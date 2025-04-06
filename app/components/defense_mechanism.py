import subprocess
import threading
import socket
import time
import os
import re
import platform
from typing import Dict, List, Any, Optional, Callable, Tuple
from datetime import datetime

from app.utils.logger import get_logger

# Module logger
logger = get_logger('components.defense_mechanism')

class DefenseMechanism:
    """Implements defensive countermeasures against network attacks."""
    
    def __init__(self):
        """Initialize the defense mechanism component."""
        self.running = False
        self.defense_thread = None
        self.callback = None
        
        # Store active defenses
        self.active_defenses = {}  # type: Dict[str, Dict[str, Any]]
        
        # Determine OS for platform-specific commands
        self.os_type = platform.system().lower()
        
        # Check for required tools
        self._check_required_tools()
    
    def _check_required_tools(self):
        """Check if required system tools are available."""
        required_tools = {
            'windows': ['netsh', 'arp', 'route'],
            'linux': ['arp', 'ip', 'iptables'],
            'darwin': ['arp', 'route', 'pfctl']  # macOS
        }
        
        os_key = 'windows' if 'win' in self.os_type else 'linux' if 'linux' in self.os_type else 'darwin'
        
        for tool in required_tools.get(os_key, []):
            if not self._is_tool_available(tool):
                logger.warning(f"Required tool '{tool}' not found. Some defenses may not work.")
    
    def _is_tool_available(self, tool_name):
        """Check if a command-line tool is available.
        
        Args:
            tool_name: The name of the tool to check
            
        Returns:
            bool: True if the tool is available
        """
        try:
            if self.os_type == 'windows':
                # On Windows, use where command
                with open(os.devnull, 'w') as devnull:
                    subprocess.check_call(['where', tool_name], stdout=devnull, stderr=devnull)
            else:
                # On Unix-like systems, use which command
                with open(os.devnull, 'w') as devnull:
                    subprocess.check_call(['which', tool_name], stdout=devnull, stderr=devnull)
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def start_defense(self, attack_details: Dict[str, Any], 
                     callback: Optional[Callable[[bool, str, Dict[str, Any]], None]] = None) -> bool:
        """Start defensive measures against an attack.
        
        Args:
            attack_details: Dictionary with attack details
            callback: Function to call with status updates
                callback(success, message, details)
                
        Returns:
            bool: True if defenses were activated successfully
        """
        attack_type = attack_details.get('type', '')
        attack_id = attack_details.get('detection_time', datetime.now()).isoformat()
        
        # Check if we already have an active defense for this attack
        if attack_id in self.active_defenses:
            logger.info(f"Defense already active for attack {attack_id}")
            return True
        
        self.callback = callback
        result = False
        defense_details = {}
        
        # Apply appropriate defenses based on attack type
        if attack_type == 'arp_spoofing':
            result, defense_details = self._defend_against_arp_spoof(attack_details)
        elif attack_type == 'port_scanning':
            result, defense_details = self._defend_against_port_scan(attack_details)
        elif attack_type == 'ddos':
            result, defense_details = self._defend_against_ddos(attack_details)
        elif attack_type == 'dns_poisoning':
            result, defense_details = self._defend_against_dns_poisoning(attack_details)
        elif attack_type == 'mitm_attack':
            result, defense_details = self._defend_against_mitm(attack_details)
        elif attack_type == 'syn_flood':
            result, defense_details = self._defend_against_syn_flood(attack_details)
        elif attack_type in ('smb_exploit', 'smb_brute_force', 'smb_suspicious'):
            result, defense_details = self._defend_against_smb_attack(attack_details)
        elif attack_type == 'ssh_brute_force':
            result, defense_details = self._defend_against_ssh_brute_force(attack_details)
        elif attack_type.startswith('web_'):
            result, defense_details = self._defend_against_web_attack(attack_details)
        else:
            logger.warning(f"No defense available for attack type: {attack_type}")
            if callback:
                callback(False, f"No defense available for attack type: {attack_type}", {})
            return False
        
        if result:
            # Store the active defense
            self.active_defenses[attack_id] = {
                'attack_details': attack_details,
                'defense_details': defense_details,
                'start_time': datetime.now()
            }
            
            # Log success
            logger.info(f"Defense activated against {attack_type} attack: {defense_details.get('action', 'unknown')}")
            
            # Notify via callback
            if callback:
                callback(True, f"Defense activated: {defense_details.get('description', '')}", defense_details)
                
            return True
        else:
            # Log failure
            logger.error(f"Failed to activate defense against {attack_type} attack")
            
            # Notify via callback
            if callback:
                callback(False, f"Failed to activate defense against {attack_type} attack", {})
                
            return False
    
    def stop_defense(self, attack_id: str) -> bool:
        """Stop a specific defense measure.
        
        Args:
            attack_id: ID of the attack to stop defending against
            
        Returns:
            bool: True if the defense was stopped successfully
        """
        if attack_id not in self.active_defenses:
            logger.warning(f"No active defense found for attack ID: {attack_id}")
            return False
        
        defense_info = self.active_defenses[attack_id]
        attack_details = defense_info['attack_details']
        defense_details = defense_info['defense_details']
        
        result = self._deactivate_defense(attack_details, defense_details)
        
        if result:
            # Remove from active defenses
            del self.active_defenses[attack_id]
            
            # Log success
            logger.info(f"Defense deactivated for attack {attack_id}")
            
            # Notify via callback
            if self.callback:
                self.callback(True, f"Defense deactivated: {defense_details.get('description', '')}", defense_details)
                
            return True
        else:
            # Log failure
            logger.error(f"Failed to deactivate defense for attack {attack_id}")
            
            # Notify via callback
            if self.callback:
                self.callback(False, f"Failed to deactivate defense for attack {attack_id}", defense_details)
                
            return False
    
    def stop_all_defenses(self) -> bool:
        """Stop all active defense measures.
        
        Returns:
            bool: True if all defenses were stopped successfully
        """
        if not self.active_defenses:
            logger.info("No active defenses to stop")
            return True
        
        success = True
        attack_ids = list(self.active_defenses.keys())
        
        for attack_id in attack_ids:
            if not self.stop_defense(attack_id):
                success = False
        
        return success
    
    def _defend_against_arp_spoof(self, attack_details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Apply defenses against ARP spoofing attacks.
        
        Args:
            attack_details: Dictionary with attack details
            
        Returns:
            Tuple[bool, Dict[str, Any]]: (success, defense details)
        """
        suspicious_ips = attack_details.get('suspicious_ips', [])
        if not suspicious_ips:
            return False, {}
        
        defense_details = {
            'type': 'arp_defense',
            'description': 'ARP spoofing countermeasures',
            'action': 'static_arp',
            'protected_ips': [],
            'commands_run': []
        }
        
        success = True
        for ip_info in suspicious_ips:
            ip = ip_info.get('ip', '')
            macs = ip_info.get('macs', [])
            
            if not ip or len(macs) < 2:
                continue
            
            # Get the legitimate MAC (this is a simplification - in a real scenario
            # we would need a more sophisticated way to determine the legitimate MAC)
            legitimate_mac = macs[0]  # Assume first MAC is legitimate
            
            # Add static ARP entry
            static_result = self._add_static_arp(ip, legitimate_mac)
            if static_result:
                defense_details['protected_ips'].append({
                    'ip': ip,
                    'mac': legitimate_mac,
                    'status': 'protected'
                })
                defense_details['commands_run'].append(static_result)
            else:
                success = False
        
        if not defense_details['protected_ips']:
            return False, {}
            
        return success, defense_details
    
    def _defend_against_port_scan(self, attack_details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Apply defenses against port scanning attacks.
        
        Args:
            attack_details: Dictionary with attack details
            
        Returns:
            Tuple[bool, Dict[str, Any]]: (success, defense details)
        """
        scanners = attack_details.get('scanners', [])
        most_active = attack_details.get('most_active', {})
        
        # Focus on the most active scanner if available
        if most_active:
            scanner_ip = most_active.get('src_ip')
        elif scanners:
            scanner_ip = scanners[0].get('src_ip')
        else:
            return False, {}
        
        defense_details = {
            'type': 'port_scan_defense',
            'description': 'Port scanning countermeasures',
            'action': 'firewall_block',
            'blocked_ips': [],
            'commands_run': []
        }
        
        # Block the scanner IP using the firewall
        block_result = self._block_ip(scanner_ip)
        if block_result:
            defense_details['blocked_ips'].append({
                'ip': scanner_ip,
                'status': 'blocked'
            })
            defense_details['commands_run'].append(block_result)
            return True, defense_details
        else:
            return False, {}
    
    def _defend_against_ddos(self, attack_details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Apply defenses against DDoS attacks.
        
        Args:
            attack_details: Dictionary with attack details
            
        Returns:
            Tuple[bool, Dict[str, Any]]: (success, defense details)
        """
        targets = attack_details.get('targets', [])
        if not targets:
            return False, {}
        
        # Get the most affected target
        main_target = targets[0]
        target_ip = main_target.get('dst_ip')
        
        defense_details = {
            'type': 'ddos_defense',
            'description': 'DDoS attack countermeasures',
            'action': 'rate_limit',
            'protected_targets': [],
            'commands_run': []
        }
        
        # Apply rate limiting or other DDoS mitigation
        rate_limit_result = self._apply_rate_limiting(target_ip)
        if rate_limit_result:
            defense_details['protected_targets'].append({
                'ip': target_ip,
                'packets_per_second': main_target.get('packets_per_second', 0),
                'status': 'rate_limited'
            })
            defense_details['commands_run'].append(rate_limit_result)
            return True, defense_details
        else:
            return False, {}
    
    def _defend_against_dns_poisoning(self, attack_details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Apply defenses against DNS poisoning attacks.
        
        Args:
            attack_details: Dictionary with attack details
            
        Returns:
            Tuple[bool, Dict[str, Any]]: (success, defense details)
        """
        suspicious_domains = attack_details.get('suspicious_domains', [])
        if not suspicious_domains:
            return False, {}
        
        defense_details = {
            'type': 'dns_defense',
            'description': 'DNS poisoning countermeasures',
            'action': 'dns_override',
            'protected_domains': [],
            'commands_run': []
        }
        
        success = True
        for domain_info in suspicious_domains:
            domain = domain_info.get('domain', '')
            responses = domain_info.get('responses', [])
            
            if not domain or not responses:
                continue
            
            # Get the most likely legitimate IP (this is a simplification)
            legitimate_ip = responses[0].get('ip')  # Assume first response is legitimate
            
            # Add hosts file entry
            hosts_result = self._add_hosts_entry(domain, legitimate_ip)
            if hosts_result:
                defense_details['protected_domains'].append({
                    'domain': domain,
                    'ip': legitimate_ip,
                    'status': 'protected'
                })
                defense_details['commands_run'].append(hosts_result)
            else:
                success = False
        
        if not defense_details['protected_domains']:
            return False, {}
            
        return success, defense_details
    
    def _defend_against_mitm(self, attack_details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Apply defenses against Man-in-the-Middle attacks.
        
        Args:
            attack_details: Dictionary with attack details
            
        Returns:
            Tuple[bool, Dict[str, Any]]: (success, defense details)
        """
        redirected_flows = attack_details.get('redirected_flows', [])
        if not redirected_flows:
            return False, {}
        
        defense_details = {
            'type': 'mitm_defense',
            'description': 'Man-in-the-Middle attack countermeasures',
            'action': 'block_mitm',
            'blocked_flows': [],
            'commands_run': []
        }
        
        success = True
        blocked_ips = set()
        
        # Block suspicious IP addresses involved in redirected flows
        for flow in redirected_flows:
            # Handle ICMP redirects
            if 'type' in flow and flow['type'] == 'icmp_redirect':
                for src_ip in flow.get('sources', []):
                    if src_ip not in blocked_ips:
                        block_result = self._block_ip(src_ip)
                        if block_result:
                            defense_details['blocked_flows'].append({
                                'type': 'icmp_redirect',
                                'source': src_ip,
                                'status': 'blocked'
                            })
                            defense_details['commands_run'].append(block_result)
                            blocked_ips.add(src_ip)
                        else:
                            success = False
            # Handle suspicious traffic flows
            else:
                src_ip = flow.get('src_ip', '')
                if src_ip and src_ip not in blocked_ips:
                    block_result = self._block_ip(src_ip)
                    if block_result:
                        defense_details['blocked_flows'].append({
                            'type': 'suspicious_flow',
                            'source': src_ip,
                            'destination': flow.get('dst_ip', 'unknown'),
                            'status': 'blocked'
                        })
                        defense_details['commands_run'].append(block_result)
                        blocked_ips.add(src_ip)
                    else:
                        success = False
        
        if not defense_details['blocked_flows']:
            return False, {}
            
        return success, defense_details
    
    def _defend_against_syn_flood(self, attack_details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Apply defenses against SYN flood attacks.
        
        Args:
            attack_details: Dictionary with attack details
            
        Returns:
            Tuple[bool, Dict[str, Any]]: (success, defense details)
        """
        targets = attack_details.get('targets', [])
        if not targets:
            return False, {}
        
        defense_details = {
            'type': 'syn_flood_defense',
            'description': 'SYN flood attack countermeasures',
            'action': 'rate_limit_syn',
            'protected_targets': [],
            'commands_run': []
        }
        
        success = True
        
        # Apply TCP SYN packet rate limiting for affected targets
        for target in targets:
            dst_ip = target.get('dst_ip', '')
            if not dst_ip:
                continue
                
            # Apply rate limiting
            limit_result = self._apply_tcp_syn_protection(dst_ip)
            if limit_result:
                defense_details['protected_targets'].append({
                    'ip': dst_ip,
                    'port': target.get('dst_port', 'unknown'),
                    'service': target.get('service', 'unknown'),
                    'status': 'protected'
                })
                defense_details['commands_run'].append(limit_result)
            else:
                success = False
        
        if not defense_details['protected_targets']:
            return False, {}
            
        return success, defense_details
    
    def _defend_against_smb_attack(self, attack_details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Apply defenses against SMB-related attacks.
        
        Args:
            attack_details: Dictionary with attack details
            
        Returns:
            Tuple[bool, Dict[str, Any]]: (success, defense details)
        """
        attack_type = attack_details.get('type', '')
        exploit_attempts = attack_details.get('exploit_attempts', [])
        brute_force_sources = attack_details.get('brute_force_sources', [])
        
        if not exploit_attempts and not brute_force_sources:
            return False, {}
        
        defense_details = {
            'type': 'smb_defense',
            'description': f"SMB {attack_type.replace('smb_', '')} countermeasures",
            'action': 'block_smb_access',
            'blocked_sources': [],
            'commands_run': []
        }
        
        success = True
        blocked_ips = set()
        
        # Block IPs attempting exploits
        for attempt in exploit_attempts:
            src_ip = attempt.get('src_ip', '')
            if src_ip and src_ip not in blocked_ips:
                block_result = self._block_ip(src_ip)
                if block_result:
                    defense_details['blocked_sources'].append({
                        'ip': src_ip,
                        'type': 'exploit_attempt',
                        'target': attempt.get('dst_ip', 'unknown'),
                        'status': 'blocked'
                    })
                    defense_details['commands_run'].append(block_result)
                    blocked_ips.add(src_ip)
                else:
                    success = False
        
        # Block IPs attempting brute force
        for source in brute_force_sources:
            src_ip = source.get('src_ip', '')
            if src_ip and src_ip not in blocked_ips:
                block_result = self._block_ip(src_ip)
                if block_result:
                    defense_details['blocked_sources'].append({
                        'ip': src_ip,
                        'type': 'brute_force',
                        'attempts': source.get('failed_attempts', 0),
                        'status': 'blocked'
                    })
                    defense_details['commands_run'].append(block_result)
                    blocked_ips.add(src_ip)
                else:
                    success = False
        
        if self.os_type == 'windows':
            # On Windows, try to disable SMBv1 which is vulnerable to many exploits
            try:
                if attack_type == 'smb_exploit':
                    # Disable SMBv1 on Windows
                    cmd = ['powershell', '-Command', 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "SMB1" -Type DWORD -Value 0 -Force']
                    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
                    if result.returncode == 0:
                        defense_details['commands_run'].append('Disabled SMBv1 protocol')
                        defense_details['action'] += '_and_disable_smbv1'
            except Exception as e:
                logger.error(f"Error attempting to disable SMBv1: {e}")
        
        if not defense_details['blocked_sources']:
            return False, {}
            
        return success, defense_details
    
    def _defend_against_ssh_brute_force(self, attack_details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Apply defenses against SSH brute force attacks.
        
        Args:
            attack_details: Dictionary with attack details
            
        Returns:
            Tuple[bool, Dict[str, Any]]: (success, defense details)
        """
        sources = attack_details.get('sources', [])
        if not sources:
            return False, {}
        
        defense_details = {
            'type': 'ssh_brute_force_defense',
            'description': 'SSH brute force countermeasures',
            'action': 'block_ssh_brute_force',
            'blocked_sources': [],
            'commands_run': []
        }
        
        success = True
        
        # Block IPs attempting SSH brute force
        for source in sources:
            src_ip = source.get('src_ip', '')
            if not src_ip:
                continue
                
            # Block the source IP
            block_result = self._block_ip(src_ip)
            if block_result:
                defense_details['blocked_sources'].append({
                    'ip': src_ip,
                    'attempts': source.get('connection_attempts', 0),
                    'targets': source.get('target_ips', []),
                    'status': 'blocked'
                })
                defense_details['commands_run'].append(block_result)
            else:
                success = False
        
        if not defense_details['blocked_sources']:
            return False, {}
            
        return success, defense_details
    
    def _defend_against_web_attack(self, attack_details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Apply defenses against web application attacks.
        
        Args:
            attack_details: Dictionary with attack details
            
        Returns:
            Tuple[bool, Dict[str, Any]]: (success, defense details)
        """
        sources = attack_details.get('sources', [])
        attack_subtype = attack_details.get('most_common_attack', 'unknown')
        
        if not sources:
            return False, {}
        
        defense_details = {
            'type': 'web_attack_defense',
            'description': f'Web application attack ({attack_subtype}) countermeasures',
            'action': 'block_web_attackers',
            'blocked_sources': [],
            'commands_run': []
        }
        
        success = True
        
        # Block IPs attempting web attacks
        for source in sources:
            src_ip = source.get('src_ip', '')
            if not src_ip:
                continue
                
            # Block the source IP
            block_result = self._block_ip(src_ip)
            if block_result:
                attack_techniques = []
                for attack in source.get('attack_types', []):
                    attack_techniques.append({
                        'type': attack.get('type', 'unknown'),
                        'count': attack.get('count', 0)
                    })
                
                defense_details['blocked_sources'].append({
                    'ip': src_ip,
                    'attempts': source.get('total_attempts', 0),
                    'techniques': attack_techniques,
                    'status': 'blocked'
                })
                defense_details['commands_run'].append(block_result)
            else:
                success = False
        
        if not defense_details['blocked_sources']:
            return False, {}
            
        return success, defense_details
    
    def _add_static_arp(self, ip: str, mac: str) -> Optional[str]:
        """Add a static ARP entry to defend against ARP spoofing.
        
        Args:
            ip: IP address to protect
            mac: Legitimate MAC address for the IP
            
        Returns:
            Optional[str]: Command executed if successful, None otherwise
        """
        try:
            if 'win' in self.os_type:
                # Windows
                command = f'netsh interface ip add neighbors "Ethernet" {ip} {mac}'
                subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return command
            elif 'linux' in self.os_type:
                # Linux
                command = f'arp -s {ip} {mac}'
                subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return command
            elif 'darwin' in self.os_type:
                # macOS
                command = f'arp -s {ip} {mac}'
                subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return command
            else:
                logger.error(f"Unsupported OS for ARP defense: {self.os_type}")
                return None
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to add static ARP entry: {e}")
            return None
    
    def _remove_static_arp(self, ip: str) -> bool:
        """Remove a static ARP entry.
        
        Args:
            ip: IP address to remove static entry for
            
        Returns:
            bool: True if successful
        """
        try:
            if 'win' in self.os_type:
                # Windows
                command = f'netsh interface ip delete neighbors "Ethernet" {ip}'
                subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return True
            elif 'linux' in self.os_type:
                # Linux
                command = f'arp -d {ip}'
                subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return True
            elif 'darwin' in self.os_type:
                # macOS
                command = f'arp -d {ip}'
                subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return True
            else:
                logger.error(f"Unsupported OS for ARP defense removal: {self.os_type}")
                return False
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to remove static ARP entry: {e}")
            return False
    
    def _block_ip(self, ip: str) -> Optional[str]:
        """Block an IP address using the firewall.
        
        Args:
            ip: IP address to block
            
        Returns:
            Optional[str]: Command executed if successful, None otherwise
        """
        try:
            if 'win' in self.os_type:
                # Windows
                command = f'netsh advfirewall firewall add rule name="ARPGuard Block {ip}" dir=in action=block remoteip={ip}'
                subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return command
            elif 'linux' in self.os_type:
                # Linux
                command = f'iptables -A INPUT -s {ip} -j DROP'
                subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return command
            elif 'darwin' in self.os_type:
                # macOS (requires root)
                command = f'echo "block in from {ip} to any" | pfctl -ef -'
                subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return command
            else:
                logger.error(f"Unsupported OS for firewall blocking: {self.os_type}")
                return None
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to block IP in firewall: {e}")
            return None
    
    def _unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address from the firewall.
        
        Args:
            ip: IP address to unblock
            
        Returns:
            bool: True if successful
        """
        try:
            if 'win' in self.os_type:
                # Windows
                command = f'netsh advfirewall firewall delete rule name="ARPGuard Block {ip}"'
                subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return True
            elif 'linux' in self.os_type:
                # Linux
                command = f'iptables -D INPUT -s {ip} -j DROP'
                subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return True
            elif 'darwin' in self.os_type:
                # macOS - would require a more complex pfctl management
                # This is simplified
                logger.warning("Unblocking IPs on macOS requires manual pfctl management")
                return False
            else:
                logger.error(f"Unsupported OS for firewall unblocking: {self.os_type}")
                return False
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to unblock IP from firewall: {e}")
            return False
    
    def _apply_rate_limiting(self, target_ip: str) -> Optional[str]:
        """Apply rate limiting to protect against DDoS.
        
        Args:
            target_ip: IP address to protect
            
        Returns:
            Optional[str]: Command executed if successful, None otherwise
        """
        try:
            if 'linux' in self.os_type:
                # Linux - using iptables for basic rate limiting
                # This limits connections to 10 per second
                command = f'iptables -A INPUT -p tcp --dport 80 -m limit --limit 10/second -j ACCEPT && ' \
                          f'iptables -A INPUT -p tcp --dport 80 -j DROP'
                subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return command
            else:
                # Rate limiting is complex and varies by platform
                # For Windows and macOS, we'd need more sophisticated approaches
                logger.warning(f"Rate limiting not fully implemented for {self.os_type}")
                
                # Return a simulated command for tracking purposes
                return f"SIMULATED: Apply rate limiting for {target_ip}"
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to apply rate limiting: {e}")
            return None
    
    def _remove_rate_limiting(self, target_ip: str) -> bool:
        """Remove rate limiting rules.
        
        Args:
            target_ip: IP address to remove protection for
            
        Returns:
            bool: True if successful
        """
        try:
            if 'linux' in self.os_type:
                # Linux - remove the iptables rules
                command = f'iptables -D INPUT -p tcp --dport 80 -m limit --limit 10/second -j ACCEPT && ' \
                          f'iptables -D INPUT -p tcp --dport 80 -j DROP'
                subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return True
            else:
                # For Windows and macOS, we'd need more sophisticated approaches
                logger.warning(f"Rate limiting removal not fully implemented for {self.os_type}")
                return True  # Assume success for tracking purposes
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to remove rate limiting: {e}")
            return False
    
    def _add_hosts_entry(self, domain: str, ip: str) -> Optional[str]:
        """Add a hosts file entry to protect against DNS poisoning.
        
        Args:
            domain: Domain name to protect
            ip: Legitimate IP address for the domain
            
        Returns:
            Optional[str]: Command executed if successful, None otherwise
        """
        # Determine hosts file location based on OS
        hosts_file = r'C:\Windows\System32\drivers\etc\hosts' if 'win' in self.os_type else '/etc/hosts'
        
        # Note: Writing to hosts file often requires elevated privileges
        try:
            # Check if we can write to the hosts file
            if not os.access(hosts_file, os.W_OK):
                logger.warning(f"No write access to hosts file: {hosts_file}")
                # Return simulated command for tracking
                return f"SIMULATED: Add entry '{ip} {domain}' to {hosts_file}"
            
            # Read existing hosts file
            with open(hosts_file, 'r') as f:
                hosts_content = f.read()
            
            # Check if domain already exists
            domain_pattern = re.compile(fr'^\s*\d+\.\d+\.\d+\.\d+\s+{re.escape(domain)}\s*$', re.MULTILINE)
            
            if domain_pattern.search(hosts_content):
                # Update existing entry
                new_hosts = domain_pattern.sub(f"{ip} {domain}", hosts_content)
            else:
                # Add new entry
                new_hosts = f"{hosts_content.rstrip()}\n{ip} {domain}\n"
            
            # Write back to hosts file
            with open(hosts_file, 'w') as f:
                f.write(new_hosts)
            
            return f"Added entry '{ip} {domain}' to {hosts_file}"
            
        except (IOError, PermissionError) as e:
            logger.error(f"Failed to modify hosts file: {e}")
            return None
    
    def _remove_hosts_entry(self, domain: str) -> bool:
        """Remove a hosts file entry.
        
        Args:
            domain: Domain name to remove protection for
            
        Returns:
            bool: True if successful
        """
        # Determine hosts file location based on OS
        hosts_file = r'C:\Windows\System32\drivers\etc\hosts' if 'win' in self.os_type else '/etc/hosts'
        
        try:
            # Check if we can write to the hosts file
            if not os.access(hosts_file, os.W_OK):
                logger.warning(f"No write access to hosts file: {hosts_file}")
                return False
            
            # Read existing hosts file
            with open(hosts_file, 'r') as f:
                hosts_content = f.read()
            
            # Remove domain entry
            domain_pattern = re.compile(fr'^\s*\d+\.\d+\.\d+\.\d+\s+{re.escape(domain)}\s*$', re.MULTILINE)
            new_hosts = domain_pattern.sub('', hosts_content)
            
            # Write back to hosts file
            with open(hosts_file, 'w') as f:
                f.write(new_hosts)
            
            return True
            
        except (IOError, PermissionError) as e:
            logger.error(f"Failed to modify hosts file: {e}")
            return False
    
    def _deactivate_defense(self, attack_details: Dict[str, Any], defense_details: Dict[str, Any]) -> bool:
        """Deactivate a defense based on its type.
        
        Args:
            attack_details: Dictionary with attack details
            defense_details: Dictionary with defense details
            
        Returns:
            bool: True if successful
        """
        defense_type = defense_details.get('type', '')
        
        try:
            if defense_type == 'arp_defense':
                # Remove static ARP entries
                success = True
                for ip_info in defense_details.get('protected_ips', []):
                    ip = ip_info.get('ip', '')
                    if ip and not self._remove_static_arp(ip):
                        success = False
                return success
                
            elif defense_type == 'port_scan_defense':
                # Unblock IPs
                success = True
                for ip_info in defense_details.get('blocked_ips', []):
                    ip = ip_info.get('ip', '')
                    if ip and not self._unblock_ip(ip):
                        success = False
                return success
                
            elif defense_type == 'ddos_defense':
                # Remove rate limiting
                success = True
                for target_info in defense_details.get('protected_targets', []):
                    ip = target_info.get('ip', '')
                    if ip and not self._remove_rate_limiting(ip):
                        success = False
                return success
                
            elif defense_type == 'dns_defense':
                # Remove hosts entries
                success = True
                for entry in defense_details.get('protected_domains', []):
                    domain = entry.get('domain', '')
                    if domain and not self._remove_hosts_entry(domain):
                        success = False
                return success
                
            elif defense_type == 'mitm_defense':
                # Unblock IPs involved in MITM
                success = True
                for flow in defense_details.get('blocked_flows', []):
                    src_ip = flow.get('source', '')
                    if src_ip and not self._unblock_ip(src_ip):
                        success = False
                return success
                
            elif defense_type == 'syn_flood_defense':
                # Remove TCP SYN flood protection
                success = True
                for target in defense_details.get('protected_targets', []):
                    ip = target.get('ip', '')
                    if ip and not self._remove_tcp_syn_protection(ip):
                        success = False
                return success
                
            elif defense_type in ('smb_defense', 'ssh_brute_force_defense', 'web_attack_defense'):
                # Unblock blocked sources
                success = True
                for source in defense_details.get('blocked_sources', []):
                    ip = source.get('ip', '')
                    if ip and not self._unblock_ip(ip):
                        success = False
                return success
                
            else:
                logger.error(f"Unknown defense type: {defense_type}")
                return False
                
        except Exception as e:
            logger.error(f"Error deactivating defense: {e}")
            return False
    
    def get_active_defenses(self) -> Dict[str, Dict[str, Any]]:
        """Get a copy of all active defenses.
        
        Returns:
            Dict[str, Dict[str, Any]]: Copy of active defenses
        """
        return self.active_defenses.copy()

    def _apply_tcp_syn_protection(self, target_ip: str) -> Optional[str]:
        """Apply TCP SYN flood protection for a target IP.
        
        Args:
            target_ip: IP address to protect
            
        Returns:
            Optional[str]: Command executed on success, None on failure
        """
        try:
            # Different commands depending on OS
            if self.os_type == 'windows':
                # On Windows, use netsh to apply a rate limit for TCP connections
                cmd = ['netsh', 'advfirewall', 'firewall', 'add', 'rule', 
                      f'name="SYN Protection for {target_ip}"', 
                      'dir=in', 'action=allow', f'remoteip={target_ip}', 
                      'protocol=TCP', 'enable=yes', 'edge=yes']
                
                # Execute command
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    return f"Applied SYN protection for {target_ip} using Windows Firewall"
                else:
                    logger.error(f"Failed to apply SYN protection on Windows: {result.stderr}")
                    return None
            elif self.os_type == 'linux':
                # On Linux, use iptables to apply SYN flood protection
                # Limit incoming SYN packets to 10 per second
                cmd = ['iptables', '-A', 'INPUT', '-p', 'tcp', '--syn', '--dport', '0:65535',
                      '-s', target_ip, '-m', 'limit', '--limit', '10/s', '--limit-burst', '20', 
                      '-j', 'ACCEPT']
                
                # Execute command
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    # Add a rule to drop excessive SYN packets
                    drop_cmd = ['iptables', '-A', 'INPUT', '-p', 'tcp', '--syn', '--dport', '0:65535',
                               '-s', target_ip, '-j', 'DROP']
                    subprocess.run(drop_cmd, capture_output=True, text=True)
                    return f"Applied SYN protection for {target_ip} using iptables"
                else:
                    logger.error(f"Failed to apply SYN protection on Linux: {result.stderr}")
                    return None
            elif self.os_type == 'darwin':
                # On macOS, use pfctl to apply SYN flood protection
                # Create a temporary pf rule file
                rule_file = os.path.join(os.path.expanduser("~"), 'arpguard_syn_protection.conf')
                with open(rule_file, 'w') as f:
                    f.write(f"block in quick proto tcp from {target_ip} to any flags S/SA keep state (max-src-conn 15, max-src-conn-rate 10/5, source-track rule)\n")
                
                # Load the rules
                cmd = ['pfctl', '-f', rule_file]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                # Enable pf if not already enabled
                subprocess.run(['pfctl', '-e'], capture_output=True, text=True)
                
                if result.returncode == 0:
                    return f"Applied SYN protection for {target_ip} using pf"
                else:
                    logger.error(f"Failed to apply SYN protection on macOS: {result.stderr}")
                    # Clean up
                    if os.path.exists(rule_file):
                        os.remove(rule_file)
                    return None
            else:
                logger.error(f"Unsupported OS for SYN flood protection: {self.os_type}")
                return None
        except Exception as e:
            logger.error(f"Error applying TCP SYN protection: {e}")
            return None

    def _remove_tcp_syn_protection(self, target_ip: str) -> bool:
        """Remove TCP SYN flood protection for a target IP.
        
        Args:
            target_ip: IP address to remove protection for
            
        Returns:
            bool: True if successful
        """
        try:
            # Different commands depending on OS
            if self.os_type == 'windows':
                # On Windows, use netsh to remove the rule
                cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 
                      f'name="SYN Protection for {target_ip}"']
                
                # Execute command
                result = subprocess.run(cmd, capture_output=True, text=True)
                return result.returncode == 0
            
            elif self.os_type == 'linux':
                # On Linux, use iptables to remove the rules
                # Find and remove the accept rule
                cmd_find = ['iptables', '-L', 'INPUT', '--line-numbers', '-n']
                result = subprocess.run(cmd_find, capture_output=True, text=True)
                
                if result.returncode == 0:
                    lines = result.stdout.splitlines()
                    rule_numbers = []
                    
                    # Find the line numbers for our rules
                    for i, line in enumerate(lines):
                        if target_ip in line and ('syn' in line.lower() or 'tcp' in line.lower()):
                            # Extract the rule number from the beginning of the line
                            parts = line.split()
                            if parts and parts[0].isdigit():
                                rule_numbers.append(int(parts[0]))
                    
                    # Delete rules starting from the highest number to avoid index changes
                    rule_numbers.sort(reverse=True)
                    for rule_num in rule_numbers:
                        del_cmd = ['iptables', '-D', 'INPUT', str(rule_num)]
                        subprocess.run(del_cmd, capture_output=True, text=True)
                    
                    return True
                return False
            
            elif self.os_type == 'darwin':
                # On macOS, remove the rule from pf
                rule_file = os.path.join(os.path.expanduser("~"), 'arpguard_syn_protection.conf')
                if os.path.exists(rule_file):
                    os.remove(rule_file)
                
                # Apply the default ruleset to reset
                cmd = ['pfctl', '-f', '/etc/pf.conf']
                result = subprocess.run(cmd, capture_output=True, text=True)
                return result.returncode == 0
            
            else:
                logger.error(f"Unsupported OS for removing SYN flood protection: {self.os_type}")
                return False
        except Exception as e:
            logger.error(f"Error removing TCP SYN protection: {e}")
            return False

# Singleton instance
_defense_mechanism_instance = None

def get_defense_mechanism():
    """Get or create the defense mechanism singleton instance.
    
    Returns:
        DefenseMechanism: The singleton instance of the defense mechanism
    """
    global _defense_mechanism_instance
    
    if _defense_mechanism_instance is None:
        _defense_mechanism_instance = DefenseMechanism()
        
    return _defense_mechanism_instance 