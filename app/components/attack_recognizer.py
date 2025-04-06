import re
import time
import threading
from typing import Dict, List, Any, Optional, Callable, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, Counter

from app.utils.logger import get_logger
from app.utils.database import get_database

# Module logger
logger = get_logger('components.attack_recognizer')

class AttackPattern:
    """Base class for attack pattern definitions."""
    
    def __init__(self, name: str, description: str, severity: str = "medium"):
        """Initialize the attack pattern.
        
        Args:
            name: Name of the attack pattern
            description: Description of the attack
            severity: Severity level (low, medium, high, critical)
        """
        self.name = name
        self.description = description
        self.severity = severity
        
    def analyze(self, packets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Analyze packets for the attack pattern.
        
        Args:
            packets: List of packet dictionaries
            
        Returns:
            None if no attack detected, or a dict with attack details
        """
        # To be implemented by subclasses
        return None
        
    def get_details(self) -> Dict[str, str]:
        """Get basic details about this attack pattern.
        
        Returns:
            Dictionary with pattern details
        """
        return {
            'name': self.name,
            'description': self.description,
            'severity': self.severity
        }


class ARPSpoofPattern(AttackPattern):
    """Detects ARP spoofing attacks."""
    
    def __init__(self):
        """Initialize the ARP spoof pattern recognizer."""
        super().__init__(
            name="ARP Spoofing",
            description="Detects ARP poisoning attacks where an attacker associates their MAC address with another host's IP",
            severity="high"
        )
        
    def analyze(self, packets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Analyze packets for ARP spoofing patterns.
        
        Args:
            packets: List of packet dictionaries
            
        Returns:
            None if no attack detected, or a dict with attack details
        """
        # Group ARP responses by IP to see if multiple MACs claim the same IP
        ip_to_macs = defaultdict(set)
        
        # Track timestamps for the first and last occurrence
        first_seen = None
        last_seen = None
        evidence_packets = []
        
        for packet in packets:
            # Only look at ARP packets
            if packet['protocol'] != 'ARP':
                continue
                
            # ARP responses (is-at)
            if 'is-at' in packet['info']:
                # Parse IP and MAC from packet info
                match = re.search(r"([0-9.]+) is-at ([0-9a-f:]+)", packet['info'], re.IGNORECASE)
                if match:
                    ip = match.group(1)
                    mac = match.group(2)
                    
                    # Save first and last timestamps
                    if first_seen is None:
                        first_seen = packet['timestamp']
                    last_seen = packet['timestamp']
                    
                    # Add the MAC for this IP
                    ip_to_macs[ip].add(mac)
                    
                    # If we've seen multiple MACs for this IP, save as evidence
                    if len(ip_to_macs[ip]) > 1:
                        evidence_packets.append(packet)
        
        # Check for IPs with multiple MAC addresses
        suspicious_ips = []
        for ip, macs in ip_to_macs.items():
            if len(macs) > 1:
                suspicious_ips.append({
                    'ip': ip,
                    'macs': list(macs)
                })
        
        # No suspicious activity found
        if not suspicious_ips:
            return None
            
        # Return attack details
        return {
            'type': 'arp_spoofing',
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'first_seen': first_seen,
            'last_seen': last_seen,
            'suspicious_ips': suspicious_ips,
            'evidence_count': len(evidence_packets),
            'evidence_ids': [p['id'] for p in evidence_packets][:10]  # First 10 evidence packets
        }


class PortScanPattern(AttackPattern):
    """Detects port scanning attacks."""
    
    def __init__(self):
        """Initialize the port scan pattern recognizer."""
        super().__init__(
            name="Port Scanning",
            description="Detects port scanning activity targeting multiple ports on a system",
            severity="medium"
        )
        # Configuration
        self.min_ports = 10  # Minimum number of ports scanned to trigger detection
        self.time_window = 60  # Time window in seconds to consider a port scan
        
    def analyze(self, packets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Analyze packets for port scanning patterns.
        
        Args:
            packets: List of packet dictionaries
            
        Returns:
            None if no attack detected, or a dict with attack details
        """
        # Track connections (src_ip, dst_ip, dst_port) within time windows
        scanner_profiles = defaultdict(lambda: defaultdict(set))  # src_ip -> dst_ip -> set(ports)
        scanner_packet_counts = defaultdict(int)  # src_ip -> packet_count
        scanner_first_seen = {}  # src_ip -> first_timestamp
        scanner_last_seen = {}  # src_ip -> last_timestamp
        scanner_evidence = defaultdict(list)  # src_ip -> list of evidence packet IDs
        
        # Only consider SYN packets (for TCP) or initial UDP packets
        for packet in packets:
            if packet['protocol'] not in ('TCP', 'UDP'):
                continue
                
            # For TCP, only count SYN packets (scan attempts)
            if packet['protocol'] == 'TCP' and 'SYN' not in packet.get('flags', ''):
                continue
                
            src_ip = packet.get('src_ip')
            dst_ip = packet.get('dst_ip')
            dst_port = packet.get('dst_port')
            
            if not all([src_ip, dst_ip, dst_port]):
                continue
                
            # Update scanner profile
            scanner_profiles[src_ip][dst_ip].add(dst_port)
            scanner_packet_counts[src_ip] += 1
            
            # Track timestamps
            if src_ip not in scanner_first_seen:
                scanner_first_seen[src_ip] = packet['timestamp']
            scanner_last_seen[src_ip] = packet['timestamp']
            
            # Save packet ID as evidence
            if len(scanner_evidence[src_ip]) < 20:  # Limit to 20 packets
                scanner_evidence[src_ip].append(packet['id'])
        
        # Identify port scanning behavior
        scanners = []
        
        for src_ip, dst_profiles in scanner_profiles.items():
            # Get time frame for this potential scanner
            first_seen = scanner_first_seen[src_ip]
            last_seen = scanner_last_seen[src_ip]
            
            # Skip if time window is too large
            time_diff = (last_seen - first_seen).total_seconds()
            if time_diff > self.time_window and len(scanner_profiles[src_ip]) < 5:
                continue
                
            # Calculate total unique ports scanned across all destinations
            total_unique_ports = sum(len(ports) for ports in dst_profiles.values())
            
            # Check if enough ports were scanned
            if total_unique_ports >= self.min_ports:
                scanners.append({
                    'src_ip': src_ip,
                    'targets': [
                        {'ip': dst_ip, 'port_count': len(ports)} 
                        for dst_ip, ports in dst_profiles.items()
                    ],
                    'unique_port_count': total_unique_ports,
                    'packet_count': scanner_packet_counts[src_ip],
                    'first_seen': first_seen,
                    'last_seen': last_seen,
                    'duration_seconds': time_diff,
                    'evidence_ids': scanner_evidence[src_ip]
                })
        
        # No port scanning activity detected
        if not scanners:
            return None
            
        # Return attack details - focus on the most significant scanner
        most_active_scanner = max(scanners, key=lambda x: x['unique_port_count'])
        
        return {
            'type': 'port_scanning',
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'scanners': scanners,
            'most_active': most_active_scanner,
            'first_seen': min(s['first_seen'] for s in scanners),
            'last_seen': max(s['last_seen'] for s in scanners),
            'evidence_count': sum(len(s['evidence_ids']) for s in scanners),
        }


class DDoSPattern(AttackPattern):
    """Detects distributed denial of service attacks."""
    
    def __init__(self):
        """Initialize the DDoS pattern recognizer."""
        super().__init__(
            name="DDoS Attack",
            description="Detects distributed denial of service attack patterns with high traffic volume",
            severity="critical"
        )
        # Configuration
        self.threshold_packets_per_second = 100  # Packets per second threshold
        self.min_unique_sources = 3  # Minimum unique source IPs to consider DDoS
        
    def analyze(self, packets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Analyze packets for DDoS patterns.
        
        Args:
            packets: List of packet dictionaries
            
        Returns:
            None if no attack detected, or a dict with attack details
        """
        # Group packets by destination IP
        dest_packets = defaultdict(list)
        
        for packet in packets:
            dst_ip = packet.get('dst_ip')
            if dst_ip:
                dest_packets[dst_ip].append(packet)
                
        # Analyze traffic patterns for each destination
        ddos_targets = []
        
        for dst_ip, target_packets in dest_packets.items():
            # Skip if too few packets
            if len(target_packets) < 50:
                continue
                
            # Get time frame
            timestamps = [p['timestamp'] for p in target_packets]
            first_seen = min(timestamps)
            last_seen = max(timestamps)
            
            # Calculate duration in seconds
            duration = (last_seen - first_seen).total_seconds()
            if duration < 1:
                duration = 1  # Avoid division by zero
                
            # Calculate packets per second
            pps = len(target_packets) / duration
            
            # Count unique source IPs
            src_ips = set(p.get('src_ip') for p in target_packets if p.get('src_ip'))
            
            # Check if traffic exceeds threshold and has multiple sources
            if pps >= self.threshold_packets_per_second and len(src_ips) >= self.min_unique_sources:
                # Calculate protocol distribution
                protocols = Counter(p.get('protocol') for p in target_packets)
                
                # Identify most common source ports (potential reflection attack indicators)
                src_ports = Counter(p.get('src_port') for p in target_packets if p.get('src_port'))
                common_ports = src_ports.most_common(5)
                
                ddos_targets.append({
                    'dst_ip': dst_ip,
                    'packet_count': len(target_packets),
                    'unique_sources': len(src_ips),
                    'duration_seconds': duration,
                    'packets_per_second': pps,
                    'first_seen': first_seen,
                    'last_seen': last_seen,
                    'protocols': dict(protocols),
                    'common_src_ports': common_ports,
                    'evidence_ids': [p['id'] for p in target_packets[:10]]  # First 10 packets as evidence
                })
                
        # No DDoS targets identified
        if not ddos_targets:
            return None
            
        # Sort targets by packets per second (most severe first)
        ddos_targets.sort(key=lambda x: x['packets_per_second'], reverse=True)
        
        # Return attack details
        return {
            'type': 'ddos',
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'targets': ddos_targets,
            'first_seen': min(t['first_seen'] for t in ddos_targets),
            'last_seen': max(t['last_seen'] for t in ddos_targets),
            'total_packet_count': sum(t['packet_count'] for t in ddos_targets),
        }


class DNSPoisoningPattern(AttackPattern):
    """Detects DNS poisoning attacks."""
    
    def __init__(self):
        """Initialize the DNS poisoning pattern recognizer."""
        super().__init__(
            name="DNS Poisoning",
            description="Detects potential DNS poisoning attempts with conflicting DNS responses",
            severity="high"
        )
        
    def analyze(self, packets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Analyze packets for DNS poisoning patterns.
        
        Args:
            packets: List of packet dictionaries
            
        Returns:
            None if no attack detected, or a dict with attack details
        """
        # Track DNS responses by domain name
        dns_responses = defaultdict(list)  # domain -> list of (ip, response_packet)
        dns_servers = defaultdict(set)  # domain -> set of dns_server_ips
        
        for packet in packets:
            # Only interested in DNS responses
            if packet.get('protocol') != 'DNS' or 'response' not in packet.get('info', '').lower():
                continue
                
            # Try to extract domain and response IP from info
            info = packet.get('info', '')
            
            # Parse domain and IP from known formats
            domain = None
            response_ip = None
            
            # Extract domain from DNS query info (e.g., "Standard query response A example.com")
            domain_match = re.search(r"query response [A|AAAA]+ ([a-zA-Z0-9.-]+)", info)
            if domain_match:
                domain = domain_match.group(1)
                
            # Extract IP from DNS response (e.g., "A 192.168.1.1")
            ip_match = re.search(r"A ([0-9.]+)", info)
            if ip_match:
                response_ip = ip_match.group(1)
                
            # Skip if we couldn't extract the necessary info
            if not domain or not response_ip:
                continue
                
            # Record DNS server IP
            dns_server_ip = packet.get('src_ip')
            if dns_server_ip:
                dns_servers[domain].add(dns_server_ip)
                
            # Add response to our tracking
            dns_responses[domain].append({
                'ip': response_ip,
                'packet_id': packet['id'],
                'timestamp': packet['timestamp'],
                'dns_server': dns_server_ip
            })
        
        # Look for domains with conflicting responses
        suspicious_domains = []
        
        for domain, responses in dns_responses.items():
            # Skip if only one response
            if len(responses) <= 1:
                continue
                
            # Get unique IPs for this domain
            unique_ips = set(r['ip'] for r in responses)
            
            # If multiple different IPs were returned for the same domain
            if len(unique_ips) > 1:
                suspicious_domains.append({
                    'domain': domain,
                    'responses': responses,
                    'unique_ips': list(unique_ips),
                    'dns_servers': list(dns_servers[domain]),
                    'first_seen': min(r['timestamp'] for r in responses),
                    'last_seen': max(r['timestamp'] for r in responses),
                    'evidence_ids': [r['packet_id'] for r in responses]
                })
                
        # No suspicious DNS activity found
        if not suspicious_domains:
            return None
            
        # Return attack details
        return {
            'type': 'dns_poisoning',
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'suspicious_domains': suspicious_domains,
            'first_seen': min(d['first_seen'] for d in suspicious_domains),
            'last_seen': max(d['last_seen'] for d in suspicious_domains),
            'evidence_count': sum(len(d['evidence_ids']) for d in suspicious_domains),
        }


class MitMPattern(AttackPattern):
    """Detects Man-in-the-Middle attacks based on network traffic patterns."""
    
    def __init__(self):
        """Initialize the MitM pattern recognizer."""
        super().__init__(
            name="Man-in-the-Middle",
            description="Detects potential Man-in-the-Middle attacks through traffic redirection patterns",
            severity="critical"
        )
        
    def analyze(self, packets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Analyze packets for MitM attack indicators.
        
        Args:
            packets: List of packet dictionaries
            
        Returns:
            None if no attack detected, or a dict with attack details
        """
        # Track normal traffic flows
        flows = defaultdict(list)  # (src_ip, dst_ip) -> list of packets
        
        # Track redirected traffic anomalies
        redirected_flows = []
        evidence_packets = []
        first_seen = None
        last_seen = None
        
        # Identify traffic flow patterns
        for packet in packets:
            if 'src_ip' not in packet or 'dst_ip' not in packet:
                continue
                
            src_ip = packet['src_ip']
            dst_ip = packet['dst_ip']
            
            # Update timestamp tracking
            if first_seen is None:
                first_seen = packet['timestamp']
            last_seen = packet['timestamp']
            
            # Only consider TCP and UDP
            if packet['protocol'] not in ('TCP', 'UDP'):
                continue
                
            # Add to flow tracking
            flows[(src_ip, dst_ip)].append(packet)
            
            # Look for TTL anomalies that might indicate redirection
            if 'ttl' in packet and packet['ttl'] < 5:  # Very low TTL can indicate redirection
                evidence_packets.append(packet)
        
        # Look for asymmetric routing (sign of potential MitM)
        for (src_ip, dst_ip), packets_in_flow in flows.items():
            # Check if there's a reverse flow
            if (dst_ip, src_ip) in flows:
                forward_path = {p.get('src_mac', '') for p in packets_in_flow}
                reverse_path = {p.get('dst_mac', '') for p in flows[(dst_ip, src_ip)]}
                
                # If the MAC addresses in the path don't match expectations, it could be MitM
                if len(forward_path) > 1 or len(reverse_path) > 1:
                    redirected_flows.append({
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'forward_macs': list(forward_path),
                        'reverse_macs': list(reverse_path),
                        'packet_count': len(packets_in_flow)
                    })
                    evidence_packets.extend(packets_in_flow[:5])  # Add some evidence
        
        # Check for ICMP redirects (another MitM technique)
        icmp_redirects = [p for p in packets if p['protocol'] == 'ICMP' and 'redirect' in p.get('info', '').lower()]
        if icmp_redirects:
            redirected_flows.append({
                'type': 'icmp_redirect',
                'count': len(icmp_redirects),
                'sources': list(set(p.get('src_ip', '') for p in icmp_redirects))
            })
            evidence_packets.extend(icmp_redirects[:5])
            
        # SSL/TLS issues that might indicate MitM
        ssl_issues = []
        for packet in packets:
            info = packet.get('info', '').lower()
            if 'protocol' in packet and packet['protocol'] == 'TLS':
                if 'alert' in info or 'error' in info or 'warning' in info:
                    ssl_issues.append(packet)
                    evidence_packets.append(packet)
        
        # If we found any indicators, report the attack
        if redirected_flows or len(ssl_issues) > 3:
            return {
                'type': 'mitm_attack',
                'name': self.name,
                'description': self.description,
                'severity': self.severity,
                'first_seen': first_seen,
                'last_seen': last_seen,
                'evidence_count': len(evidence_packets),
                'evidence_ids': [p['id'] for p in evidence_packets[:10]],
                'redirected_flows': redirected_flows,
                'ssl_issues': len(ssl_issues),
                'confidence': 'medium'
            }
            
        return None


class SYNFloodPattern(AttackPattern):
    """Detects TCP SYN flood attacks."""
    
    def __init__(self):
        """Initialize the SYN flood pattern recognizer."""
        super().__init__(
            name="TCP SYN Flood",
            description="Detects TCP SYN flood attacks that exhaust server connection resources",
            severity="high"
        )
        # Configuration
        self.threshold_rate = 100  # SYN packets per second to trigger detection
        self.min_syn_count = 200   # Minimum SYN packets to consider an attack
        self.time_window = 10      # Time window in seconds to calculate rate
        
    def analyze(self, packets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Analyze packets for SYN flood patterns.
        
        Args:
            packets: List of packet dictionaries
            
        Returns:
            None if no attack detected, or a dict with attack details
        """
        # Track SYN packets by target (dst_ip, dst_port)
        syn_packets = defaultdict(list)
        first_seen = None
        last_seen = None
        
        # Collect all SYN packets
        for packet in packets:
            if packet['protocol'] != 'TCP':
                continue
                
            flags = packet.get('flags', '')
            if 'SYN' not in flags or 'ACK' in flags:  # Only pure SYN packets
                continue
                
            dst_ip = packet.get('dst_ip')
            dst_port = packet.get('dst_port')
            if not dst_ip or not dst_port:
                continue
                
            # Update timestamp tracking
            if first_seen is None:
                first_seen = packet['timestamp']
            last_seen = packet['timestamp']
            
            # Group by target
            target = (dst_ip, dst_port)
            syn_packets[target].append(packet)
        
        # No SYN packets found
        if not syn_packets:
            return None
            
        # Calculate SYN flood metrics
        flood_targets = []
        
        for target, packets_to_target in syn_packets.items():
            dst_ip, dst_port = target
            
            # Skip if not enough SYN packets
            if len(packets_to_target) < self.min_syn_count:
                continue
                
            # Calculate time span and rate
            target_first = min(p['timestamp'] for p in packets_to_target)
            target_last = max(p['timestamp'] for p in packets_to_target)
            time_span = (target_last - target_first).total_seconds()
            
            # Skip if time span is too small to calculate rate
            if time_span < 1:
                continue
                
            rate = len(packets_to_target) / time_span
            
            # Count unique source IPs
            source_ips = set(p.get('src_ip', '') for p in packets_to_target)
            
            # If rate exceeds threshold, consider it a flood
            if rate > self.threshold_rate:
                flood_targets.append({
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'service': self._get_service_name(dst_port),
                    'syn_count': len(packets_to_target),
                    'rate_per_second': rate,
                    'source_ip_count': len(source_ips),
                    'first_seen': target_first,
                    'last_seen': target_last,
                    'duration_seconds': time_span,
                    'evidence_ids': [p['id'] for p in packets_to_target[:10]]
                })
        
        # No flood targets identified
        if not flood_targets:
            return None
            
        # Sort targets by severity (rate)
        flood_targets.sort(key=lambda x: x['rate_per_second'], reverse=True)
        
        return {
            'type': 'syn_flood',
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'first_seen': first_seen,
            'last_seen': last_seen,
            'targets': flood_targets,
            'total_targets': len(flood_targets),
            'evidence_count': sum(t['syn_count'] for t in flood_targets),
            'max_rate': max(t['rate_per_second'] for t in flood_targets),
            'distributed': any(t['source_ip_count'] > 3 for t in flood_targets)
        }
        
    def _get_service_name(self, port: int) -> str:
        """Get service name for common ports.
        
        Args:
            port: Port number
            
        Returns:
            Service name or "unknown"
        """
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            465: "SMTPS",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP-ALT"
        }
        return common_ports.get(port, "unknown")


class SMBExploitPattern(AttackPattern):
    """Detects SMB-related attacks such as EternalBlue and brute force attempts."""
    
    def __init__(self):
        """Initialize the SMB exploit pattern recognizer."""
        super().__init__(
            name="SMB Exploit/Brute Force",
            description="Detects attempts to exploit SMB vulnerabilities or brute force SMB authentication",
            severity="critical"
        )
        # Configuration
        self.smb_ports = {139, 445}  # Common SMB ports
        self.threshold_attempts = 10  # Number of attempts to consider as brute force
        self.suspicious_smb_signatures = [
            b'\x00\x00\x00\x45',  # EternalBlue signature in Trans2 request
            b'\x00\x00\x00\x54', 
            b'\x00\x00\x00\xc8', 
            b'\x00\x00\xfb\x91',  # DoublePulsar backdoor signature
            b'\xff\x53\x4d\x42'   # Common in MS17-010 exploits
        ]
        
    def analyze(self, packets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Analyze packets for SMB-related attack patterns.
        
        Args:
            packets: List of packet dictionaries
            
        Returns:
            None if no attack detected, or a dict with attack details
        """
        # Track SMB traffic per source
        smb_sources = defaultdict(list)  # src_ip -> list of packets
        smb_failed_auth = defaultdict(int)  # src_ip -> count of failed auth attempts
        
        # Track exploit attempts
        exploit_attempts = []
        suspicious_packets = []
        
        first_seen = None
        last_seen = None
        
        for packet in packets:
            if 'src_ip' not in packet or 'dst_ip' not in packet:
                continue
                
            # Update timestamp tracking
            if first_seen is None:
                first_seen = packet['timestamp']
            last_seen = packet['timestamp']
            
            # Check if it's SMB traffic
            dst_port = packet.get('dst_port')
            if not dst_port or dst_port not in self.smb_ports:
                continue
                
            src_ip = packet.get('src_ip')
            smb_sources[src_ip].append(packet)
            
            # Look for authentication failures
            if 'info' in packet and ('status: ACCESS_DENIED' in packet['info'] or 
                                     'authentication failed' in packet['info'].lower()):
                smb_failed_auth[src_ip] += 1
                suspicious_packets.append(packet)
            
            # Look for suspicious hex signatures in packet data
            if 'raw_data' in packet:
                for signature in self.suspicious_smb_signatures:
                    if signature in packet.get('raw_data', b''):
                        exploit_attempts.append({
                            'src_ip': src_ip,
                            'dst_ip': packet.get('dst_ip'),
                            'timestamp': packet['timestamp'],
                            'signature': signature.hex(),
                            'packet_id': packet['id']
                        })
                        suspicious_packets.append(packet)
                        break
        
        # Check for brute force attempts
        brute_force_sources = []
        for src_ip, fail_count in smb_failed_auth.items():
            if fail_count >= self.threshold_attempts:
                brute_force_sources.append({
                    'src_ip': src_ip,
                    'failed_attempts': fail_count,
                    'packet_count': len(smb_sources[src_ip])
                })
        
        # If either exploit attempts or brute force is detected, report
        if exploit_attempts or brute_force_sources:
            attack_type = None
            if exploit_attempts:
                attack_type = "smb_exploit"
            elif brute_force_sources:
                attack_type = "smb_brute_force"
            else:
                attack_type = "smb_suspicious"
                
            # Determine severity based on the type of attack
            severity = self.severity
            if attack_type == "smb_exploit":
                severity = "critical"  # Exploits are always critical
            elif attack_type == "smb_brute_force":
                severity = "high"
                
            return {
                'type': attack_type,
                'name': self.name,
                'description': self.description,
                'severity': severity,
                'first_seen': first_seen,
                'last_seen': last_seen,
                'exploit_attempts': exploit_attempts,
                'brute_force_sources': brute_force_sources,
                'evidence_count': len(suspicious_packets),
                'evidence_ids': [p['id'] for p in suspicious_packets[:10]],
                'exploitation_risk': "High" if exploit_attempts else "Medium"
            }
            
        return None


class SSHBruteForcePattern(AttackPattern):
    """Detects SSH brute force login attempts and related attacks."""
    
    def __init__(self):
        """Initialize the SSH brute force pattern recognizer."""
        super().__init__(
            name="SSH Brute Force",
            description="Detects attempts to brute force SSH login credentials",
            severity="high"
        )
        # Configuration
        self.ssh_ports = {22, 2222}  # Common SSH ports
        self.threshold_attempts = 5   # Number of connection attempts to trigger detection
        self.time_window = 60         # Time window in seconds to consider for brute force
        self.max_normal_failures = 3  # Max failed attempts considered normal
        
    def analyze(self, packets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Analyze packets for SSH brute force patterns.
        
        Args:
            packets: List of packet dictionaries
            
        Returns:
            None if no attack detected, or a dict with attack details
        """
        # Group SSH traffic by source
        ssh_connections = defaultdict(list)  # src_ip -> list of packets
        ssh_connection_attempts = defaultdict(int)  # src_ip -> count of connection attempts
        
        # Track session information
        ssh_sessions = defaultdict(set)  # src_ip -> set of dst_ips
        first_seen = None
        last_seen = None
        evidence_packets = []
        
        # Track SSH-specific error messages that suggest brute force
        auth_failure_indicators = [
            'authentication failure',
            'failed password',
            'invalid user',
            'connection closed by remote host',
            'too many authentication failures'
        ]
        
        for packet in packets:
            if 'src_ip' not in packet or 'dst_ip' not in packet:
                continue
                
            # Update timestamp tracking
            packet_time = packet['timestamp']
            if first_seen is None:
                first_seen = packet_time
            last_seen = packet_time
            
            # Check if it's SSH traffic
            dst_port = packet.get('dst_port')
            if not dst_port or dst_port not in self.ssh_ports:
                continue
                
            src_ip = packet.get('src_ip')
            dst_ip = packet.get('dst_ip')
            
            # Track SSH sessions
            ssh_sessions[src_ip].add(dst_ip)
            
            # Look for TCP SYN packets (connection attempts)
            if packet['protocol'] == 'TCP' and 'SYN' in packet.get('flags', ''):
                ssh_connection_attempts[src_ip] += 1
                ssh_connections[src_ip].append(packet)
            
            # Look for authentication failures in packet info
            info = packet.get('info', '').lower()
            for indicator in auth_failure_indicators:
                if indicator in info:
                    evidence_packets.append(packet)
                    break
        
        # Identify brute force attempts
        brute_force_sources = []
        
        for src_ip, attempts in ssh_connection_attempts.items():
            # Skip if not enough connection attempts
            if attempts < self.threshold_attempts:
                continue
                
            # Calculate time frame for this source
            src_packets = ssh_connections[src_ip]
            src_first = min(p['timestamp'] for p in src_packets)
            src_last = max(p['timestamp'] for p in src_packets)
            time_span = (src_last - src_first).total_seconds()
            
            # Skip if time span is too large (not concentrated enough)
            if time_span > self.time_window and attempts < self.threshold_attempts * 2:
                continue
                
            # Calculate rate of attempts
            rate = attempts / max(1, time_span)
            
            # Number of unique targets
            targets_count = len(ssh_sessions[src_ip])
            
            # If attempts are concentrated or target multiple hosts, consider it brute force
            if rate >= 1 or targets_count > 1:
                brute_force_sources.append({
                    'src_ip': src_ip,
                    'connection_attempts': attempts,
                    'unique_targets': targets_count,
                    'target_ips': list(ssh_sessions[src_ip]),
                    'rate_per_second': rate,
                    'first_seen': src_first,
                    'last_seen': src_last,
                    'duration_seconds': time_span
                })
                evidence_packets.extend(src_packets[:5])  # Add some evidence
        
        # No brute force detected
        if not brute_force_sources:
            return None
            
        # Sort by severity (number of attempts)
        brute_force_sources.sort(key=lambda x: x['connection_attempts'], reverse=True)
        
        # Return attack details
        return {
            'type': 'ssh_brute_force',
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'first_seen': first_seen,
            'last_seen': last_seen,
            'sources': brute_force_sources,
            'total_sources': len(brute_force_sources),
            'evidence_count': len(evidence_packets),
            'evidence_ids': [p['id'] for p in evidence_packets[:10]],
            'max_attempts': max(s['connection_attempts'] for s in brute_force_sources)
        }


class WebAttackPattern(AttackPattern):
    """Detects HTTP/HTTPS-based attacks including SQL injection, XSS, and other web app attacks."""
    
    def __init__(self):
        """Initialize the web attack pattern recognizer."""
        super().__init__(
            name="Web Application Attack",
            description="Detects attempts to exploit web applications via SQL injection, XSS, directory traversal, etc.",
            severity="high"
        )
        # Configuration
        self.web_ports = {80, 443, 8080, 8443}  # Common web ports
        
        # Attack signatures for different attack types
        self.sql_injection_patterns = [
            r"'--", r"';", r"OR 1=1", r"' OR '1'='1", r" OR 1=1", 
            r"DROP TABLE", r"UNION SELECT", r"' UNION SELECT", 
            r"/*", r"*/", r"@@version", r"admin'--", r"' or 0=0 --",
            r"INFORMATION_SCHEMA", r"sysobjects", r"xp_cmdshell", r"sp_password"
        ]
        
        self.xss_patterns = [
            r"<script>", r"</script>", r"<img src=", r"onerror=",
            r"javascript:", r"onload=", r"alert\(", r"String.fromCharCode",
            r"eval\(", r"document.cookie", r"document.location"
        ]
        
        self.path_traversal_patterns = [
            r"\.\.\/", r"\.\.\\", r"%2e%2e%2f", r"%252e%252e%255c",
            r"\.\.%2f", r"\.\.%5c", r"/etc/passwd", r"C:\\Windows\\system32",
            r"boot.ini", r"win.ini", r"/proc/self/", r"/var/www/"
        ]
        
        self.command_injection_patterns = [
            r";\s*\w+", r"\|\s*\w+", r"`\w+`", r"\$\(\w+\)",
            r"ping ", r"wget ", r"curl ", r"nc ", r"bash ", r"cmd ",
            r"cat /", r"rm -", r"chmod ", r"; ls", r"& dir"
        ]
        
        self.file_inclusion_patterns = [
            r"include=http", r"file=http", r"page=http", r"data=http",
            r"include=ftp", r"php://input", r"zip://", r"phar://",
            r"expect://", r"php://filter", r"/proc/self/environ"
        ]
        
    def analyze(self, packets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Analyze packets for web attack patterns.
        
        Args:
            packets: List of packet dictionaries
            
        Returns:
            None if no attack detected, or a dict with attack details
        """
        # Group by source and track attack types
        attack_sources = defaultdict(lambda: defaultdict(list))  # src_ip -> attack_type -> list of packets
        evidence_packets = []
        
        first_seen = None
        last_seen = None
        
        for packet in packets:
            if 'src_ip' not in packet or 'dst_ip' not in packet:
                continue
                
            # Update timestamp tracking
            packet_time = packet['timestamp']
            if first_seen is None:
                first_seen = packet_time
            last_seen = packet_time
            
            # Check if it's web traffic
            dst_port = packet.get('dst_port')
            if not dst_port or dst_port not in self.web_ports:
                continue
                
            src_ip = packet.get('src_ip')
            dst_ip = packet.get('dst_ip')
            
            # Get HTTP request information (if available)
            info = packet.get('info', '').lower()
            http_request = packet.get('http_request', '')
            payload = ''
            
            # Try to extract the HTTP payload from different fields
            if http_request:
                payload = http_request
            elif 'raw_data' in packet:
                # Try to decode raw data to string if it's HTTP
                try:
                    raw_data = packet['raw_data']
                    if isinstance(raw_data, bytes):
                        raw_str = raw_data.decode('utf-8', errors='ignore')
                        if 'HTTP/' in raw_str or 'GET ' in raw_str or 'POST ' in raw_str:
                            payload = raw_str
                except:
                    pass
            
            # URL decode the payload to catch encoded attacks
            try:
                from urllib.parse import unquote
                payload = unquote(payload)
            except:
                pass
                
            # Check for attack signatures
            self._check_attack_patterns(src_ip, dst_ip, packet, payload, 'sql_injection', 
                                      self.sql_injection_patterns, attack_sources)
            self._check_attack_patterns(src_ip, dst_ip, packet, payload, 'xss', 
                                      self.xss_patterns, attack_sources)
            self._check_attack_patterns(src_ip, dst_ip, packet, payload, 'path_traversal', 
                                      self.path_traversal_patterns, attack_sources)
            self._check_attack_patterns(src_ip, dst_ip, packet, payload, 'command_injection', 
                                      self.command_injection_patterns, attack_sources)
            self._check_attack_patterns(src_ip, dst_ip, packet, payload, 'file_inclusion', 
                                      self.file_inclusion_patterns, attack_sources)
        
        # Process the collected attacks
        if not attack_sources:
            return None
            
        # Compile attack statistics
        attack_stats = []
        total_evidence = 0
        
        for src_ip, attack_types in attack_sources.items():
            source_stats = {
                'src_ip': src_ip,
                'attack_types': [],
                'total_attempts': 0
            }
            
            for attack_type, packets_list in attack_types.items():
                source_stats['attack_types'].append({
                    'type': attack_type,
                    'count': len(packets_list),
                    'evidence_ids': [p['id'] for p in packets_list[:5]]
                })
                source_stats['total_attempts'] += len(packets_list)
                total_evidence += len(packets_list)
                evidence_packets.extend(packets_list[:5])
            
            attack_stats.append(source_stats)
            
        # Sort by total attempts
        attack_stats.sort(key=lambda x: x['total_attempts'], reverse=True)
        
        # Determine most common attack type
        all_attack_types = []
        for source in attack_stats:
            for attack_type in source['attack_types']:
                all_attack_types.append(attack_type['type'])
                
        if all_attack_types:
            from collections import Counter
            most_common = Counter(all_attack_types).most_common(1)[0][0]
        else:
            most_common = 'unknown'
        
        # Return attack details
        return {
            'type': f'web_{most_common}',
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'first_seen': first_seen,
            'last_seen': last_seen,
            'sources': attack_stats,
            'total_sources': len(attack_stats),
            'most_common_attack': most_common,
            'evidence_count': min(total_evidence, 50),  # Cap at 50 packets
            'evidence_ids': [p['id'] for p in evidence_packets[:10]],
            'attack_types_found': list(set(all_attack_types))
        }
        
    def _check_attack_patterns(self, src_ip, dst_ip, packet, payload, attack_type, 
                              patterns, attack_sources):
        """Check payload against attack patterns and update attack_sources if match found.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            packet: Packet dictionary
            payload: String payload to check for patterns
            attack_type: Type of attack (e.g., 'sql_injection')
            patterns: List of regex patterns to check
            attack_sources: Dictionary to update with matches
        """
        import re
        for pattern in patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                attack_sources[src_ip][attack_type].append(packet)
                return  # One match is enough for this packet


class AttackRecognizer:
    """Monitors network traffic for attack patterns."""
    
    def __init__(self):
        """Initialize the attack recognizer."""
        self.running = False
        self.detection_thread = None
        self.callback = None
        self.database = get_database()
        
        # Initialize attack patterns
        self.patterns = [
            ARPSpoofPattern(),
            PortScanPattern(),
            DDoSPattern(),
            DNSPoisoningPattern(),
            MitMPattern(),
            SYNFloodPattern(),
            SMBExploitPattern(),
            SSHBruteForcePattern(),
            WebAttackPattern()
        ]
        
        # Store detections
        self.detected_attacks = []
        
    def start_detection(self, callback: Optional[Callable[[bool, str, Dict[str, Any]], None]] = None) -> bool:
        """Start attack pattern detection.
        
        Args:
            callback: Function to call when an attack is detected
                     callback(success, message, details)
            
        Returns:
            bool: True if detection started successfully
        """
        if self.running:
            logger.warning("Attack pattern detection already running")
            return False
            
        self.callback = callback
        self.running = True
        
        # Start detection in a separate thread
        self.detection_thread = threading.Thread(
            target=self._detection_loop,
            daemon=True
        )
        self.detection_thread.start()
        
        logger.info("Attack pattern detection started")
        return True
        
    def stop_detection(self) -> bool:
        """Stop attack pattern detection.
        
        Returns:
            bool: True if detection was stopped
        """
        if not self.running:
            logger.warning("Attack pattern detection not running")
            return False
            
        self.running = False
        if self.detection_thread:
            self.detection_thread.join(timeout=2)
            
        logger.info("Attack pattern detection stopped")
        return True
        
    def _detection_loop(self):
        """Main detection loop running in separate thread."""
        while self.running:
            try:
                # Get active session data (most recent session)
                active_session = self.database.get_active_session()
                
                if active_session:
                    # Get packets from the active session (last 5 minutes)
                    end_time = datetime.now()
                    start_time = end_time - timedelta(minutes=5)
                    
                    packets = self.database.get_packets_by_timerange(
                        active_session['id'],
                        start_time,
                        end_time
                    )
                    
                    if packets:
                        # Analyze packets with each pattern detector
                        self._analyze_patterns(packets)
                
                # Sleep before next analysis
                for _ in range(10):  # Check every second if we should stop
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Error in attack detection loop: {e}")
                if self.callback:
                    self.callback(False, f"Detection error: {e}", None)
                time.sleep(5)  # Wait a bit before trying again
                
    def _analyze_patterns(self, packets: List[Dict[str, Any]]):
        """Analyze packets using all pattern detectors.
        
        Args:
            packets: List of packet dictionaries
        """
        for pattern in self.patterns:
            try:
                # Apply the pattern detector
                result = pattern.analyze(packets)
                
                # If attack was detected
                if result:
                    # Check if we've already detected this attack recently
                    if not self._is_duplicate_detection(result):
                        # Add to detected attacks
                        result['detection_time'] = datetime.now()
                        self.detected_attacks.append(result)
                        
                        # Create an appropriate message
                        message = self._format_detection_message(result)
                        
                        # Notify via callback
                        if self.callback:
                            self.callback(True, message, result)
                            
                        # Log the detection
                        logger.warning(f"Attack detected: {result['name']} - {message}")
                        
            except Exception as e:
                logger.error(f"Error analyzing with pattern {pattern.name}: {e}")
                
    def _is_duplicate_detection(self, result: Dict[str, Any]) -> bool:
        """Check if this attack was recently detected.
        
        Args:
            result: Attack detection result
            
        Returns:
            bool: True if this is a duplicate detection
        """
        # Keep only detections from the last 5 minutes
        cutoff_time = datetime.now() - timedelta(minutes=5)
        self.detected_attacks = [
            a for a in self.detected_attacks 
            if a['detection_time'] > cutoff_time
        ]
        
        # Check for duplicates based on attack type
        attack_type = result.get('type')
        
        for existing in self.detected_attacks:
            if existing.get('type') != attack_type:
                continue
                
            # Type-specific duplicate detection
            if attack_type == 'arp_spoofing':
                # Check for overlap in suspicious IPs
                existing_ips = {ip['ip'] for ip in existing.get('suspicious_ips', [])}
                new_ips = {ip['ip'] for ip in result.get('suspicious_ips', [])}
                if existing_ips.intersection(new_ips):
                    return True
                    
            elif attack_type == 'port_scanning':
                # Check for same scanner IPs
                existing_scanners = {s['src_ip'] for s in existing.get('scanners', [])}
                new_scanners = {s['src_ip'] for s in result.get('scanners', [])}
                if existing_scanners.intersection(new_scanners):
                    return True
                    
            elif attack_type == 'ddos':
                # Check for same target IPs
                existing_targets = {t['dst_ip'] for t in existing.get('targets', [])}
                new_targets = {t['dst_ip'] for t in result.get('targets', [])}
                if existing_targets.intersection(new_targets):
                    return True
                    
            elif attack_type == 'dns_poisoning':
                # Check for same domains
                existing_domains = {d['domain'] for d in existing.get('suspicious_domains', [])}
                new_domains = {d['domain'] for d in result.get('suspicious_domains', [])}
                if existing_domains.intersection(new_domains):
                    return True
                    
        return False
        
    def _format_detection_message(self, result: Dict[str, Any]) -> str:
        """Format a human-readable message about the detected attack.
        
        Args:
            result: Attack detection result
            
        Returns:
            str: Formatted message
        """
        attack_type = result.get('type')
        severity = result.get('severity', 'medium').upper()
        
        if attack_type == 'arp_spoofing':
            ips = [ip['ip'] for ip in result.get('suspicious_ips', [])]
            return f"{severity}: ARP Spoofing detected for {len(ips)} IP addresses: {', '.join(ips[:3])}" + \
                   (f"... and {len(ips)-3} more" if len(ips) > 3 else "")
                   
        elif attack_type == 'port_scanning':
            scanners = result.get('scanners', [])
            most_active = result.get('most_active', {})
            if most_active:
                return f"{severity}: Port Scan detected from {most_active.get('src_ip', 'unknown')} - " + \
                       f"{most_active.get('unique_port_count', 0)} ports scanned across " + \
                       f"{len(most_active.get('targets', []))} targets"
            else:
                return f"{severity}: Port Scanning detected from {len(scanners)} sources"
                
        elif attack_type == 'ddos':
            targets = result.get('targets', [])
            if targets:
                main_target = targets[0]
                return f"{severity}: Potential DDoS Attack targeting {main_target.get('dst_ip', 'unknown')} - " + \
                       f"{main_target.get('packets_per_second', 0):.1f} packets/sec from " + \
                       f"{main_target.get('unique_sources', 0)} sources"
            else:
                return f"{severity}: DDoS Attack detected"
                
        elif attack_type == 'dns_poisoning':
            domains = [d['domain'] for d in result.get('suspicious_domains', [])]
            return f"{severity}: DNS Poisoning detected for {len(domains)} domains: {', '.join(domains[:3])}" + \
                   (f"... and {len(domains)-3} more" if len(domains) > 3 else "")
                   
        else:
            return f"{severity}: {result.get('name', 'Unknown attack')} detected"
            
    def get_attack_history(self) -> List[Dict[str, Any]]:
        """Get history of detected attacks.
        
        Returns:
            List of attack detection results
        """
        return sorted(self.detected_attacks, key=lambda x: x.get('detection_time', datetime.now()), reverse=True)
        
    def get_available_patterns(self) -> List[Dict[str, str]]:
        """Get list of available attack patterns.
        
        Returns:
            List of pattern details (name, description, severity)
        """
        return [pattern.get_details() for pattern in self.patterns] 