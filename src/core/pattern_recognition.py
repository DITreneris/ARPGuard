"""
Pattern Recognition Module for Advanced ARP Spoofing Detection

This module implements sophisticated pattern recognition algorithms
to detect complex ARP spoofing patterns and attack vectors.
"""

import time
import logging
import numpy as np
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict, Counter, deque
from datetime import datetime

# Configure logging
logger = logging.getLogger("arpguard.pattern")

# Constants
MAX_HISTORY_SIZE = 1000  # Maximum number of entries to keep in history
PATTERN_CHECK_INTERVAL = 5  # Seconds between pattern analysis runs
TIME_WINDOW_SMALL = 30  # 30 second window for rapid pattern detection
TIME_WINDOW_MEDIUM = 300  # 5 minute window for medium-term patterns
TIME_WINDOW_LARGE = 3600  # 1 hour window for long-term patterns
CONFIDENCE_THRESHOLD_LOW = 0.65
CONFIDENCE_THRESHOLD_MEDIUM = 0.80
CONFIDENCE_THRESHOLD_HIGH = 0.95


class PatternRecognizer:
    """
    Advanced pattern recognition for ARP spoofing detection.
    
    This class implements multiple algorithms to detect sophisticated
    ARP spoofing attacks based on temporal and spatial patterns in
    network traffic.
    """
    
    def __init__(self, gateway_detector=None):
        """
        Initialize the pattern recognizer with optional gateway detector.
        
        Args:
            gateway_detector: Optional reference to gateway detection module
        """
        self.gateway_detector = gateway_detector
        self.arp_history = deque(maxlen=MAX_HISTORY_SIZE)
        self.mac_ip_bindings = defaultdict(set)  # MAC → set of IPs
        self.ip_mac_bindings = defaultdict(set)  # IP → set of MACs
        self.mac_activity = defaultdict(list)  # MAC → list of (timestamp, activity_type)
        self.ip_activity = defaultdict(list)  # IP → list of (timestamp, activity_type)
        
        # Statistical counters
        self.packet_count = 0
        self.anomaly_count = 0
        self.last_analysis_time = time.time()
        
        # Detected patterns
        self.detected_patterns = []
        
        # Thread safety
        self.lock = None  # Initialize if running in multi-threaded environment
        
        logger.info("Pattern recognition module initialized")
    
    def process_packet(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process an ARP packet and update pattern recognition data.
        
        Args:
            packet: Dictionary containing packet information
                Required fields:
                - src_mac: Source MAC address
                - src_ip: Source IP address
                - dst_ip: Destination IP address
                - timestamp: Packet timestamp
                - op_code: ARP operation code (1=request, 2=reply)
                
        Returns:
            Dictionary with detection results if a suspicious pattern is found,
            None otherwise
        """
        # Extract key packet information
        src_mac = packet.get("src_mac")
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        timestamp = packet.get("timestamp", time.time())
        op_code = packet.get("op_code")
        
        if not src_mac or not src_ip:
            return None
            
        # Update statistics
        self.packet_count += 1
        
        # Update binding history
        self.mac_ip_bindings[src_mac].add(src_ip)
        self.ip_mac_bindings[src_ip].add(src_mac)
        
        # Record activity
        activity_type = "reply" if op_code == 2 else "request"
        self.mac_activity[src_mac].append((timestamp, activity_type))
        self.ip_activity[src_ip].append((timestamp, activity_type))
        
        # Add to history
        self.arp_history.append({
            "timestamp": timestamp,
            "src_mac": src_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "op_code": op_code
        })
        
        # Check if it's time to run pattern analysis
        if time.time() - self.last_analysis_time > PATTERN_CHECK_INTERVAL:
            return self.analyze_patterns()
            
        # Quick check for immediate red flags
        if len(self.ip_mac_bindings[src_ip]) > 1:
            # Multiple MACs for same IP - potential spoofing
            return self._check_mac_ip_conflict(src_ip, src_mac, timestamp)
            
        return None
    
    def analyze_patterns(self) -> Optional[Dict[str, Any]]:
        """
        Run comprehensive pattern analysis on collected data.
        
        Returns:
            Dictionary with highest-confidence detection results if a
            suspicious pattern is found, None otherwise
        """
        self.last_analysis_time = time.time()
        detection_results = []
        
        # Run all pattern detection algorithms
        detection_results.extend(self._detect_ip_mac_flapping())
        detection_results.extend(self._detect_gateway_impersonation())
        detection_results.extend(self._detect_arp_storm())
        detection_results.extend(self._detect_unsolicited_replies())
        detection_results.extend(self._detect_mitm_pattern())
        detection_results.extend(self._detect_subnet_scan())
        
        # If no patterns detected, return None
        if not detection_results:
            return None
            
        # Sort by confidence score and return highest
        detection_results.sort(key=lambda x: x["confidence"], reverse=True)
        highest_confidence = detection_results[0]
        
        # Add to detected patterns list
        self.detected_patterns.append(highest_confidence)
        
        # Increment anomaly counter
        self.anomaly_count += 1
        
        return highest_confidence
    
    def _detect_ip_mac_flapping(self) -> List[Dict[str, Any]]:
        """
        Detect IP-MAC binding changes that indicate possible spoofing.
        
        This algorithm detects when an IP address is associated with
        multiple MAC addresses in a short time window, which is a
        strong indicator of ARP spoofing.
        
        Returns:
            List of detection results
        """
        results = []
        current_time = time.time()
        
        # Check each IP with multiple MAC bindings
        for ip, mac_set in self.ip_mac_bindings.items():
            if len(mac_set) <= 1:
                continue
                
            # Get recent history for this IP
            recent_entries = [
                entry for entry in self.arp_history
                if entry["src_ip"] == ip and current_time - entry["timestamp"] < TIME_WINDOW_MEDIUM
            ]
            
            if len(recent_entries) < 3:
                continue
                
            # Sort by timestamp
            recent_entries.sort(key=lambda x: x["timestamp"])
            
            # Look for changes in MAC address
            mac_changes = []
            previous_mac = recent_entries[0]["src_mac"]
            
            for entry in recent_entries[1:]:
                if entry["src_mac"] != previous_mac:
                    mac_changes.append({
                        "timestamp": entry["timestamp"],
                        "old_mac": previous_mac,
                        "new_mac": entry["src_mac"]
                    })
                    previous_mac = entry["src_mac"]
            
            # If we found MAC changes, report them
            if mac_changes:
                # Calculate confidence based on number and frequency of changes
                confidence = min(0.95, 0.65 + (len(mac_changes) * 0.05))
                
                # Increase confidence if gateway IP is involved
                if self.gateway_detector and ip in self.gateway_detector._get_gateway_ips():
                    confidence = min(0.99, confidence + 0.2)
                
                # Create detection result
                results.append({
                    "type": "ip_mac_flapping",
                    "description": f"IP {ip} is using multiple MAC addresses",
                    "ip": ip,
                    "mac_addresses": list(mac_set),
                    "confidence": confidence,
                    "changes": mac_changes,
                    "timestamp": current_time,
                    "timespan": current_time - recent_entries[0]["timestamp"]
                })
        
        return results
    
    def _detect_gateway_impersonation(self) -> List[Dict[str, Any]]:
        """
        Detect attempts to impersonate the network gateway.
        
        This algorithm specifically looks for packets that claim to be from
        the gateway but use an incorrect MAC address.
        
        Returns:
            List of detection results
        """
        results = []
        current_time = time.time()
        
        # Skip if no gateway detector available
        if not self.gateway_detector:
            return results
            
        # Get gateway information
        gateway_ips = self.gateway_detector._get_gateway_ips()
        gateway_macs = self.gateway_detector._get_gateway_macs()
        
        if not gateway_ips or not gateway_macs:
            return results
            
        # Check for gateway impersonation in recent packets
        recent_entries = [
            entry for entry in self.arp_history
            if current_time - entry["timestamp"] < TIME_WINDOW_MEDIUM
        ]
        
        # Group suspicious entries by MAC address
        suspicious_macs = defaultdict(list)
        
        for entry in recent_entries:
            # Check if packet claims to be from a gateway IP
            if entry["src_ip"] in gateway_ips:
                # Check if MAC doesn't match known gateway MACs
                if entry["src_mac"] not in gateway_macs:
                    suspicious_macs[entry["src_mac"]].append(entry)
        
        # Analyze suspicious MAC addresses
        for mac, entries in suspicious_macs.items():
            if len(entries) < 2:
                continue
                
            # Calculate confidence based on number of suspicious packets
            base_confidence = 0.75  # Gateway impersonation is serious
            num_packets_factor = min(0.2, len(entries) * 0.01)  # Up to 0.2 more confidence
            time_factor = min(0.1, (entries[-1]["timestamp"] - entries[0]["timestamp"]) / 300)  # Up to 0.1 more for persistent attacks
            
            confidence = base_confidence + num_packets_factor + time_factor
            
            # Create detection result
            results.append({
                "type": "gateway_impersonation",
                "description": f"Potential gateway impersonation by MAC {mac}",
                "gateway_ip": entries[0]["src_ip"],
                "legitimate_macs": gateway_macs,
                "impersonating_mac": mac,
                "confidence": confidence,
                "packet_count": len(entries),
                "first_seen": entries[0]["timestamp"],
                "last_seen": entries[-1]["timestamp"],
                "timestamp": current_time
            })
        
        return results
    
    def _detect_arp_storm(self) -> List[Dict[str, Any]]:
        """
        Detect ARP storms that may indicate flooding attacks.
        
        This algorithm identifies abnormally high rates of ARP traffic,
        particularly from a single source.
        
        Returns:
            List of detection results
        """
        results = []
        current_time = time.time()
        
        # Get recent history
        recent_entries = [
            entry for entry in self.arp_history
            if current_time - entry["timestamp"] < TIME_WINDOW_SMALL
        ]
        
        if len(recent_entries) < 10:
            return results
            
        # Count packets by source MAC
        mac_counts = Counter([entry["src_mac"] for entry in recent_entries])
        
        # Calculate average packets per MAC
        total_macs = len(mac_counts)
        if total_macs == 0:
            return results
            
        avg_packets_per_mac = len(recent_entries) / total_macs
        
        # Check for MACs with abnormally high packet counts
        for mac, count in mac_counts.items():
            # If this MAC has sent significantly more packets than average
            if count > max(10, avg_packets_per_mac * 3):
                # Calculate confidence based on how much this exceeds normal
                ratio = count / avg_packets_per_mac
                confidence = min(0.95, 0.6 + (ratio / 20))
                
                # Get the specific entries for this MAC
                mac_entries = [entry for entry in recent_entries if entry["src_mac"] == mac]
                
                # Check unique IPs claimed by this MAC
                claimed_ips = set(entry["src_ip"] for entry in mac_entries)
                
                # If multiple IPs are claimed, increase confidence
                if len(claimed_ips) > 1:
                    confidence = min(0.99, confidence + 0.1)
                
                # Create detection result
                results.append({
                    "type": "arp_storm",
                    "description": f"Abnormally high ARP traffic from MAC {mac}",
                    "mac": mac,
                    "packet_count": count,
                    "claimed_ips": list(claimed_ips),
                    "average_packets_per_mac": avg_packets_per_mac,
                    "ratio_above_average": ratio,
                    "confidence": confidence,
                    "timespan": TIME_WINDOW_SMALL,
                    "timestamp": current_time
                })
        
        return results
    
    def _detect_unsolicited_replies(self) -> List[Dict[str, Any]]:
        """
        Detect unsolicited ARP replies which may indicate poisoning attempts.
        
        This algorithm looks for ARP replies that weren't preceded by 
        corresponding requests.
        
        Returns:
            List of detection results
        """
        results = []
        current_time = time.time()
        
        # Get recent history, focusing on replies (op_code == 2)
        recent_replies = [
            entry for entry in self.arp_history
            if entry["op_code"] == 2 and current_time - entry["timestamp"] < TIME_WINDOW_MEDIUM
        ]
        
        # Skip if not enough data
        if len(recent_replies) < 5:
            return results
            
        # Group replies by source
        mac_replies = defaultdict(list)
        for entry in recent_replies:
            mac_replies[entry["src_mac"]].append(entry)
        
        # For each source, check for unsolicited replies
        for mac, replies in mac_replies.items():
            if len(replies) < 3:
                continue
                
            # Count potentially unsolicited replies
            unsolicited_count = 0
            unsolicited_details = []
            
            for reply in replies:
                # Look for a matching request in the recent history
                found_request = False
                
                # A request should be for this IP and slightly earlier
                for entry in self.arp_history:
                    if (entry["op_code"] == 1 and 
                        entry["dst_ip"] == reply["src_ip"] and
                        entry["timestamp"] < reply["timestamp"] and
                        reply["timestamp"] - entry["timestamp"] < 2):  # Within 2 seconds
                        found_request = True
                        break
                
                if not found_request:
                    unsolicited_count += 1
                    unsolicited_details.append({
                        "timestamp": reply["timestamp"],
                        "ip": reply["src_ip"],
                        "mac": reply["src_mac"]
                    })
            
            # If we found unsolicited replies
            if unsolicited_count >= 3 and unsolicited_count / len(replies) > 0.5:
                # Calculate confidence
                ratio = unsolicited_count / len(replies)
                confidence = min(0.9, 0.7 + (ratio * 0.2))
                
                # Create detection result
                results.append({
                    "type": "unsolicited_replies",
                    "description": f"Unsolicited ARP replies from MAC {mac}",
                    "mac": mac,
                    "total_replies": len(replies),
                    "unsolicited_count": unsolicited_count,
                    "unsolicited_ratio": ratio,
                    "confidence": confidence,
                    "details": unsolicited_details,
                    "timestamp": current_time
                })
        
        return results
    
    def _detect_mitm_pattern(self) -> List[Dict[str, Any]]:
        """
        Detect Man-in-the-Middle attack patterns.
        
        This algorithm identifies classic MITM patterns where one device
        claims to be both the gateway and another host.
        
        Returns:
            List of detection results
        """
        results = []
        current_time = time.time()
        
        # Skip if no gateway detector available
        if not self.gateway_detector:
            return results
            
        # Get gateway information
        gateway_ips = self.gateway_detector._get_gateway_ips()
        
        if not gateway_ips:
            return results
            
        # Look for MACs claiming to be both the gateway and other hosts
        for mac, ip_set in self.mac_ip_bindings.items():
            if len(ip_set) < 2:
                continue
                
            # Check if this MAC claims to be the gateway
            claims_gateway = any(ip in gateway_ips for ip in ip_set)
            
            if claims_gateway:
                # Get the non-gateway IPs this MAC claims to be
                other_ips = [ip for ip in ip_set if ip not in gateway_ips]
                
                if other_ips:
                    # This is a potential MITM attack
                    # Calculate confidence based on number of claimed IPs
                    confidence = min(0.98, 0.85 + (len(other_ips) * 0.02))
                    
                    # Get recent entries for this MAC
                    mac_entries = [
                        entry for entry in self.arp_history
                        if entry["src_mac"] == mac and current_time - entry["timestamp"] < TIME_WINDOW_MEDIUM
                    ]
                    
                    # Create detection result
                    results.append({
                        "type": "mitm_pattern",
                        "description": f"Potential MITM attack from MAC {mac}",
                        "mac": mac,
                        "gateway_ips": [ip for ip in ip_set if ip in gateway_ips],
                        "other_ips": other_ips,
                        "confidence": confidence,
                        "packet_count": len(mac_entries),
                        "timestamp": current_time
                    })
        
        return results
    
    def _detect_subnet_scan(self) -> List[Dict[str, Any]]:
        """
        Detect subnet scanning activity that may precede attacks.
        
        This algorithm identifies patterns of ARP requests that systematically
        scan through IP ranges.
        
        Returns:
            List of detection results
        """
        results = []
        current_time = time.time()
        
        # Get recent ARP requests
        recent_requests = [
            entry for entry in self.arp_history
            if entry["op_code"] == 1 and current_time - entry["timestamp"] < TIME_WINDOW_MEDIUM
        ]
        
        if len(recent_requests) < 10:
            return results
            
        # Group requests by source MAC
        mac_requests = defaultdict(list)
        for entry in recent_requests:
            mac_requests[entry["src_mac"]].append(entry)
        
        # Analyze each source's request patterns
        for mac, requests in mac_requests.items():
            if len(requests) < 10:
                continue
                
            # Extract target IPs
            target_ips = [request["dst_ip"] for request in requests]
            
            # Simple check: are there many unique IPs?
            unique_ips = set(target_ips)
            if len(unique_ips) < 8:
                continue
                
            # Try to detect sequential scanning
            ip_octets = []
            for ip in unique_ips:
                try:
                    octets = [int(o) for o in ip.split('.')]
                    if len(octets) == 4:
                        ip_octets.append(octets)
                except:
                    continue
            
            # Skip if parsing failed
            if len(ip_octets) < 8:
                continue
                
            # Check for sequential patterns in the last octet
            sequential_count = 0
            for i in range(len(ip_octets) - 1):
                for j in range(i + 1, len(ip_octets)):
                    # If first 3 octets match and last differs by 1
                    if (ip_octets[i][0] == ip_octets[j][0] and
                        ip_octets[i][1] == ip_octets[j][1] and
                        ip_octets[i][2] == ip_octets[j][2] and
                        abs(ip_octets[i][3] - ip_octets[j][3]) == 1):
                        sequential_count += 1
            
            # Calculate scan coverage (how much of a subnet is scanned)
            subnet_ips = defaultdict(set)
            for octets in ip_octets:
                subnet = f"{octets[0]}.{octets[1]}.{octets[2]}"
                subnet_ips[subnet].add(octets[3])
            
            # Find subnet with most IPs
            most_scanned_subnet = max(subnet_ips.items(), key=lambda x: len(x[1]))
            subnet_coverage = len(most_scanned_subnet[1]) / 254  # Approximate coverage
            
            # If we found sequential patterns or high subnet coverage
            if sequential_count >= 5 or subnet_coverage > 0.2:
                # Calculate confidence
                confidence = min(0.85, 0.6 + (sequential_count * 0.01) + (subnet_coverage * 0.5))
                
                # Create detection result
                results.append({
                    "type": "subnet_scan",
                    "description": f"Potential subnet scanning from MAC {mac}",
                    "mac": mac,
                    "request_count": len(requests),
                    "unique_targets": len(unique_ips),
                    "sequential_pairs": sequential_count,
                    "most_scanned_subnet": most_scanned_subnet[0],
                    "subnet_coverage": subnet_coverage,
                    "confidence": confidence,
                    "timestamp": current_time
                })
        
        return results
    
    def _check_mac_ip_conflict(self, ip: str, new_mac: str, timestamp: float) -> Optional[Dict[str, Any]]:
        """
        Perform a quick check for MAC-IP conflicts when a new binding is observed.
        
        Args:
            ip: IP address
            new_mac: Newly observed MAC for this IP
            timestamp: When this binding was observed
            
        Returns:
            Detection result if conflict detected, None otherwise
        """
        # Get previous MAC addresses for this IP
        previous_macs = self.ip_mac_bindings[ip].copy()
        previous_macs.discard(new_mac)
        
        if not previous_macs:
            return None
            
        # This is a potential conflict
        confidence = 0.7  # Base confidence
        
        # Increase confidence if gateway IP is involved
        if self.gateway_detector and ip in self.gateway_detector._get_gateway_ips():
            confidence = min(0.95, confidence + 0.2)
        
        # Create detection result
        return {
            "type": "mac_ip_conflict",
            "description": f"IP {ip} changed from MAC {next(iter(previous_macs))} to {new_mac}",
            "ip": ip,
            "new_mac": new_mac,
            "previous_macs": list(previous_macs),
            "confidence": confidence,
            "timestamp": timestamp
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about pattern recognition.
        
        Returns:
            Dictionary with statistics
        """
        return {
            "packet_count": self.packet_count,
            "anomaly_count": self.anomaly_count,
            "mac_ip_bindings": len(self.mac_ip_bindings),
            "ip_mac_bindings": len(self.ip_mac_bindings),
            "unique_macs": len(self.mac_activity),
            "unique_ips": len(self.ip_activity),
            "detected_patterns": len(self.detected_patterns)
        }
    
    def get_recent_detections(self, count: int = 10) -> List[Dict[str, Any]]:
        """
        Get most recent detection results.
        
        Args:
            count: Maximum number of results to return
            
        Returns:
            List of recent detection results
        """
        # Sort by timestamp (newest first) and return requested count
        sorted_detections = sorted(
            self.detected_patterns,
            key=lambda x: x["timestamp"],
            reverse=True
        )
        return sorted_detections[:count]
    
    def reset(self) -> None:
        """Reset all pattern recognition data."""
        self.arp_history.clear()
        self.mac_ip_bindings.clear()
        self.ip_mac_bindings.clear()
        self.mac_activity.clear()
        self.ip_activity.clear()
        self.packet_count = 0
        self.anomaly_count = 0
        self.detected_patterns.clear()
        self.last_analysis_time = time.time()
        logger.info("Pattern recognition data reset")


# Helper functions for pattern analysis
def calculate_packet_rate(packets: List[Dict[str, Any]], window_size: float) -> float:
    """Calculate packet rate over the specified time window."""
    if not packets:
        return 0.0
        
    # Sort by timestamp
    sorted_packets = sorted(packets, key=lambda x: x["timestamp"])
    
    # Calculate timespan
    timespan = sorted_packets[-1]["timestamp"] - sorted_packets[0]["timestamp"]
    
    # Avoid division by zero
    if timespan <= 0:
        return float(len(packets))
        
    return len(packets) / timespan


def is_sequential_ip_range(ips: List[str]) -> bool:
    """Check if a list of IPs represents a sequential range."""
    if len(ips) < 3:
        return False
        
    # Parse IPs and sort by last octet
    octets = []
    for ip in ips:
        try:
            parts = [int(p) for p in ip.split('.')]
            if len(parts) == 4:
                octets.append(parts)
        except:
            return False
            
    # Sort by last octet
    octets.sort(key=lambda x: x[3])
    
    # Check if first 3 octets are the same for all IPs
    base_network = octets[0][:3]
    if not all(ip[:3] == base_network for ip in octets):
        return False
        
    # Check for sequential last octets
    for i in range(len(octets) - 1):
        if octets[i+1][3] - octets[i][3] != 1:
            return False
            
    return True 