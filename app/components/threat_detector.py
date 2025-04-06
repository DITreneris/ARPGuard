import threading
import time
from typing import Dict, List, Set, Callable, Optional, Any
from datetime import datetime

from scapy.all import sniff, ARP, Ether
import netifaces

from app.utils.logger import get_logger
from app.utils.config import get_config
from app.utils.mac_vendor import get_vendor_for_mac

# Module logger
logger = get_logger('components.threat_detector')

class ThreatDetector:
    """Detects ARP poisoning and other network threats.
    
    This class analyzes network packets to detect malicious activities,
    including ARP spoofing, MAC flooding, and other attacks.
    """
    
    def __init__(self):
        """Initialize the threat detector."""
        self.running = False
        self.detector_thread = None
        self.threats = {}  # IP -> {'macs': set(), 'first_seen': datetime, 'last_seen': datetime}
        self.ip_mac_mappings = {}  # IP -> MAC (known good mappings)
        self.mac_ip_mappings = {}  # MAC -> set(IPs) (known good mappings)
        self.gateway_ip = None
        self.gateway_mac = None
        self.config = get_config()
        
        # Initialize signal handler flag and callback
        self.callback = None
        
        # ML Controller reference - will be set by MainWindow
        self.ml_controller = None
        
    def start_detection(self, callback: Optional[Callable] = None):
        """Start detecting network threats.
        
        Args:
            callback: Function to call with detection updates
            
        Returns:
            bool: True if detection started, False otherwise
        """
        if self.running:
            logger.warning("Threat detection already running")
            return False
            
        logger.info("Starting threat detection")
        self.running = True
        self.callback = callback
        
        # Start detection in a separate thread
        self.detector_thread = threading.Thread(target=self._detection_thread)
        self.detector_thread.daemon = True
        self.detector_thread.start()
        
        return True
        
    def stop_detection(self):
        """Stop detecting network threats.
        
        Returns:
            bool: True if stopped, False if not running
        """
        if not self.running:
            logger.warning("Threat detection not running")
            return False
            
        logger.info("Stopping threat detection")
        self.running = False
        
        # Wait for the thread to terminate
        if self.detector_thread:
            self.detector_thread.join(timeout=2.0)
            
        return True
        
    def get_threats(self) -> List[Dict[str, Any]]:
        """Get the current list of detected threats.
        
        Returns:
            list: List of threat information dictionaries
        """
        result = []
        for ip, data in self.threats.items():
            result.append({
                'ip': ip,
                'macs': list(data['macs']),
                'first_seen': data['first_seen'],
                'last_seen': data['last_seen'],
                'is_gateway': ip == self.gateway_ip,
                'vendors': [get_vendor_for_mac(mac) for mac in data['macs']]
            })
        return result
        
    def _detection_thread(self):
        """Background thread for ARP packet monitoring."""
        try:
            # Discover the default gateway
            self._discover_gateway()
            
            # Capture ARP packets
            logger.info("Starting ARP packet capture")
            while self.running:
                # Use non-blocking sniff with timeout to allow checking running flag
                packets = sniff(
                    filter="arp",
                    count=10,  # Capture in small batches
                    timeout=1,  # Short timeout to check running flag
                    store=True
                )
                
                for packet in packets:
                    if not self.running:
                        break
                    self._process_arp_packet(packet)
                    
        except Exception as e:
            logger.error(f"Error in threat detection: {e}")
            if self.callback:
                self.callback(False, f"Detection error: {str(e)}")
        finally:
            self.running = False
            
    def _discover_gateway(self):
        """Discover the default gateway IP and MAC address."""
        try:
            # Get default gateway IP
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            self.gateway_ip = default_gateway
            
            # Try to get the gateway MAC address
            # We'll update this when processing ARP packets
            logger.info(f"Default gateway identified: {default_gateway}")
            
            # Report via callback
            if self.callback:
                self.callback(True, f"Monitoring traffic for gateway {default_gateway}")
                
        except Exception as e:
            logger.error(f"Error discovering gateway: {e}")
            if self.callback:
                self.callback(False, f"Gateway discovery error: {str(e)}")
                
    def _process_arp_packet(self, packet):
        """Process an ARP packet for threat detection.
        
        Args:
            packet: The Scapy ARP packet
        """
        if not packet.haslayer(ARP):
            return
            
        arp_layer = packet[ARP]
        
        # Get source and destination IP/MAC addresses
        src_ip = arp_layer.psrc
        src_mac = arp_layer.hwsrc
        dst_ip = arp_layer.pdst
        
        # Skip packets with invalid IPs or MACs
        if not self._is_valid_ip(src_ip) or not self._is_valid_mac(src_mac):
            return
            
        # Learn gateway MAC if this is the gateway
        if src_ip == self.gateway_ip and not self.gateway_mac:
            self.gateway_mac = src_mac
            logger.info(f"Learned gateway MAC: {self.gateway_mac}")
            
        # Check for ARP spoofing based on previously seen mappings
        current_time = datetime.now()
        
        # 1. Check if we've seen a different MAC for this IP before
        if src_ip in self.ip_mac_mappings and self.ip_mac_mappings[src_ip] != src_mac:
            self._register_threat(src_ip, src_mac, current_time)
            
        # 2. Check if this MAC is claiming to be multiple IPs (possible, but suspicious)
        elif src_mac in self.mac_ip_mappings and len(self.mac_ip_mappings[src_mac]) > 1:
            # Only register if this MAC is now associated with more than a few IPs
            # (some legitimate devices might have multiple IPs)
            if len(self.mac_ip_mappings[src_mac]) > self.config.get("detector.mac_ip_threshold", 3):
                for ip in self.mac_ip_mappings[src_mac]:
                    self._register_threat(ip, src_mac, current_time)
                    
        # 3. Special check for the gateway
        elif src_ip == self.gateway_ip and self.gateway_mac and src_mac != self.gateway_mac:
            self._register_threat(src_ip, src_mac, current_time, is_gateway=True)
            
        # 4. Check for ARP responses that weren't requested (ARP spoofing technique)
        # This would require tracking ARP requests, which is more complex
            
        # Update our known mappings
        self._update_mappings(src_ip, src_mac)
        
    def _register_threat(self, ip: str, mac: str, timestamp: datetime, is_gateway: bool = False):
        """Register a potential threat.
        
        Args:
            ip: The IP address involved
            mac: The MAC address involved
            timestamp: When the threat was detected
            is_gateway: Whether this involves the gateway
        """
        # Initialize threat data if needed
        if ip not in self.threats:
            self.threats[ip] = {
                'macs': set(),
                'first_seen': timestamp,
                'last_seen': timestamp
            }
        
        # Update threat data
        self.threats[ip]['macs'].add(mac)
        self.threats[ip]['last_seen'] = timestamp
        
        # Determine threat severity
        severity = "CRITICAL" if is_gateway else "WARNING"
        
        # Log the threat
        if is_gateway:
            message = f"{severity}: Possible gateway ARP poisoning detected! {ip} is claimed by multiple MAC addresses: {', '.join(self.threats[ip]['macs'])}"
        else:
            message = f"{severity}: Possible ARP poisoning detected! {ip} is claimed by multiple MAC addresses: {', '.join(self.threats[ip]['macs'])}"
        
        logger.warning(message)
        
        # Notify via callback
        if self.callback:
            self.callback(True, message)
        
    def _update_mappings(self, ip: str, mac: str):
        """Update our known IP to MAC mappings.
        
        Args:
            ip: The IP address
            mac: The MAC address
        """
        # Update IP -> MAC mapping
        self.ip_mac_mappings[ip] = mac
        
        # Update MAC -> IPs mapping
        if mac not in self.mac_ip_mappings:
            self.mac_ip_mappings[mac] = set()
        self.mac_ip_mappings[mac].add(ip)
        
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if an IP address is valid for our purposes.
        
        Args:
            ip: The IP address to check
            
        Returns:
            bool: True if valid, False otherwise
        """
        # Basic validation - could be expanded
        return ip and ip != "0.0.0.0" and not ip.startswith("169.254.")  # Exclude APIPA addresses
        
    def _is_valid_mac(self, mac: str) -> bool:
        """Check if a MAC address is valid for our purposes.
        
        Args:
            mac: The MAC address to check
            
        Returns:
            bool: True if valid, False otherwise
        """
        # Basic validation - could be expanded
        return mac and mac != "00:00:00:00:00:00" and mac.count(":") == 5 

    def set_ml_controller(self, ml_controller):
        """Set the ML controller reference for enhanced detection.
        
        Args:
            ml_controller: MLController instance
        """
        self.ml_controller = ml_controller
        logger.info("ML controller integrated with threat detector")
    
    def analyze_packet(self, packet):
        """Analyze a packet for potential threats.
        
        Args:
            packet: The packet data to analyze
            
        Returns:
            Dictionary with analysis results
        """
        # Run traditional threat detection
        result = self._traditional_analysis(packet)
        
        # If ML controller is available, enhance detection with ML
        if self.ml_controller:
            try:
                ml_result = self.ml_controller.process_packet(packet)
                
                # Combine traditional and ML results
                combined_threat = max(
                    result.get('threat_probability', 0), 
                    ml_result.get('threat_probability', 0)
                )
                
                # Update result with ML data
                result['threat_probability'] = combined_threat
                result['ml_enhanced'] = True
                
                # If ML detected an anomaly, add that to the result
                if ml_result.get('is_anomaly', False):
                    result['is_anomaly'] = True
                    result['anomaly_explanation'] = ml_result.get('anomaly_explanation', {})
                
                # Update recommended action based on combined threat level
                if combined_threat > 0.8:
                    result['recommended_action'] = 'block'
                elif combined_threat > 0.6:
                    result['recommended_action'] = 'alert'
                elif combined_threat > 0.4:
                    result['recommended_action'] = 'monitor'
                else:
                    result['recommended_action'] = 'allow'
                    
            except Exception as e:
                logger.error(f"Error integrating ML results: {e}")
        
        return result
    
    def _traditional_analysis(self, packet):
        """Perform traditional (rule-based) packet analysis.
        
        Args:
            packet: The packet data to analyze
            
        Returns:
            Dictionary with analysis results
        """
        # This is the original analyze_packet logic, moved to a helper method
        # ... existing analysis code ...
        
        # This is a placeholder implementation
        result = {
            'threat_probability': 0.0,
            'threat_type': None,
            'recommended_action': 'allow'
        }
        
        # Check for ARP spoofing
        if self._check_arp_spoofing(packet):
            result['threat_probability'] = 0.9
            result['threat_type'] = 'arp_spoofing'
            result['recommended_action'] = 'block'
        
        # Check for MAC flooding
        elif self._check_mac_flooding(packet):
            result['threat_probability'] = 0.8
            result['threat_type'] = 'mac_flooding'
            result['recommended_action'] = 'block'
        
        # Check for suspicious port scanning
        elif self._check_port_scanning(packet):
            result['threat_probability'] = 0.7
            result['threat_type'] = 'port_scanning'
            result['recommended_action'] = 'monitor'
        
        return result 