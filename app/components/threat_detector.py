import threading
import time
from typing import Dict, List, Set, Callable, Optional, Any
from datetime import datetime

from scapy.all import sniff, ARP, Ether
import netifaces

from app.utils.logger import get_logger
from app.utils.config import get_config
from app.utils.mac_vendor import get_vendor_for_mac
from app.ml.packet_converter import convert_arp_packet

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
                    
                    # Also analyze the packet with rule-based and ML detection
                    self.analyze_packet(packet)
                    
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
            
        # Update our IP-MAC and MAC-IP mappings
        self.ip_mac_mappings[src_ip] = src_mac
        
        # Update MAC -> IPs mapping
        if src_mac not in self.mac_ip_mappings:
            self.mac_ip_mappings[src_mac] = set()
        self.mac_ip_mappings[src_mac].add(src_ip)
        
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if an IP address is valid.
        
        Args:
            ip: The IP address to check
            
        Returns:
            bool: True if valid, False otherwise
        """
        # Minimum validation - could be more comprehensive
        return ip and "." in ip and len(ip.split(".")) == 4
        
    def _is_valid_mac(self, mac: str) -> bool:
        """Check if a MAC address is valid.
        
        Args:
            mac: The MAC address to check
            
        Returns:
            bool: True if valid, False otherwise
        """
        # Minimum validation - could be more comprehensive
        return mac and ":" in mac and len(mac.split(":")) == 6
        
    def set_ml_controller(self, ml_controller):
        """Set the ML controller for advanced detection.
        
        Args:
            ml_controller: The ML controller instance
        """
        self.ml_controller = ml_controller
        
        # Set gateway information in the ML controller's context tracker
        if self.ml_controller and self.gateway_ip:
            self.ml_controller.context_tracker.gateway_ip = self.gateway_ip
            if self.gateway_mac:
                self.ml_controller.context_tracker.gateway_mac = self.gateway_mac
                
        logger.info("ML controller set for threat detection")
        
    def analyze_packet(self, packet):
        """Analyze a packet using rule-based and ML detection.
        
        This method integrates traditional detection, rule-based detection,
        and ML-based detection to provide comprehensive threat analysis.
        
        Args:
            packet: The Scapy packet to analyze
            
        Returns:
            List of detection results
        """
        # Skip if no ML controller is available
        if not self.ml_controller:
            return []
            
        # Skip non-ARP packets for now
        if not packet.haslayer(ARP):
            return []
            
        try:
            # Convert Scapy packet to dictionary format for ML processing
            packet_dict = self.ml_controller.convert_scapy_packet_to_dict(packet)
            
            # Process with ML controller
            results = self.ml_controller.process_packet(packet_dict)
            
            # Handle detections
            if results.get('is_threat', False):
                self._handle_ml_detection(results)
                
            return results
                
        except Exception as e:
            logger.error(f"Error in packet analysis: {e}")
            return []
            
    def _handle_ml_detection(self, detection_result: Dict[str, Any]):
        """Handle a detection from the ML system.
        
        Args:
            detection_result: The detection result dictionary
        """
        # Handle rule-based detections
        if 'rule_detections' in detection_result and detection_result['rule_detections']:
            for detection in detection_result['rule_detections']:
                self._handle_rule_detection(detection)
                
        # Handle ML-based detection
        if detection_result.get('ml_detection', False) and 'ml_detection_result' in detection_result:
            ml_detection = detection_result['ml_detection_result']
            self._handle_rule_detection(ml_detection)  # Reuse same handler
        elif detection_result.get('is_threat', False) and not detection_result.get('rule_detection', False):
            # Create a standard format detection for legacy compatibility
            ml_detection = {
                "type": "ml_based",
                "description": "ML-detected threat",
                "severity": "MEDIUM",
                "confidence": detection_result.get('threat_probability', 0.0),
                "timestamp": datetime.now(),
                "evidence": {
                    "src_ip": detection_result.get('source_ip', 'Unknown'),
                    "src_mac": detection_result.get('source_mac', 'Unknown'),
                    "probability": detection_result.get('threat_probability', 0.0)
                }
            }
            self._handle_rule_detection(ml_detection)
            
    def _handle_rule_detection(self, detection: Dict[str, Any]):
        """Handle a detection from the rule-based system.
        
        Args:
            detection: The detection dictionary
        """
        # Extract information from the detection
        detection_type = detection["type"]
        rule_id = detection.get("rule_id", "UNKNOWN")
        severity = detection["severity"]
        confidence = detection["confidence"]
        evidence = detection["evidence"]
        description = detection.get("description", "Unknown detection")
        
        # Determine if this is a serious threat
        is_serious = severity in ["HIGH", "CRITICAL"]
        
        # Log the detection
        log_message = f"{severity} threat detected by {detection_type} "
        if rule_id != "UNKNOWN":
            log_message += f"({rule_id}): "
        log_message += f"{description} (Confidence: {confidence:.2f})"
        
        if is_serious:
            logger.warning(log_message)
        else:
            logger.info(log_message)
            
        # Notify via callback if it's serious
        if is_serious and self.callback:
            detailed_message = f"{severity} threat: {description}\n"
            detailed_message += f"Confidence: {confidence:.2f}, Type: {detection_type}"
            if rule_id != "UNKNOWN":
                detailed_message += f", Rule: {rule_id}"
            detailed_message += f"\nEvidence: {evidence}"
            self.callback(True, detailed_message)
            
        # Register threats in the traditional system if applicable
        src_ip = evidence.get("src_ip")
        src_mac = evidence.get("src_mac")
        if src_ip and src_mac:
            self._register_threat(
                src_ip, 
                src_mac, 
                detection["timestamp"],
                is_gateway=(evidence.get("gateway_ip") == self.gateway_ip)
            )
    
    def _register_threat(self, ip: str, mac: str, timestamp: datetime, is_gateway: bool = False):
        """Register a threat in the threat database.
        
        Args:
            ip: The source IP address
            mac: The source MAC address
            timestamp: When the threat was detected
            is_gateway: Whether this involves the gateway
        """
        # Create threat entry if it doesn't exist
        if ip not in self.threats:
            self.threats[ip] = {
                'macs': set(),
                'first_seen': timestamp,
                'last_seen': timestamp
            }
            
        # Update threat entry
        self.threats[ip]['macs'].add(mac)
        self.threats[ip]['last_seen'] = timestamp
        
        # Log the threat
        gateway_str = " (GATEWAY)" if is_gateway else ""
        log_message = f"Potential ARP spoofing detected{gateway_str}: {ip} -> {mac}"
        
        if is_gateway:
            logger.warning(log_message)
        else:
            logger.info(log_message)
            
        # Notify via callback
        if self.callback:
            if is_gateway:
                message = f"CRITICAL: Gateway impersonation detected! {ip} is now claiming to be {mac}"
            else:
                message = f"WARNING: Potential ARP spoofing detected. {ip} is now claiming to be {mac}"
                
            self.callback(True, message) 