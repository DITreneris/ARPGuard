# ARPGuard API Documentation

## Overview

This document provides detailed information about ARPGuard's internal APIs and components. It is intended for developers who want to extend, customize, or integrate ARPGuard functionality into their own applications.

## Core Modules

### NetworkScanner

The `NetworkScanner` class provides functionality for discovering devices on a local network.

#### Class Definition
```python
class NetworkScanner:
    def __init__(self):
        """Initialize the network scanner with default configuration."""
        
    def get_default_gateway(self) -> Tuple[Optional[str], Optional[str]]:
        """Get the default gateway IP and interface.
        
        Returns:
            Tuple containing (gateway_ip, interface) or (None, None) if not found.
        """
        
    def get_network_range(self) -> Optional[str]:
        """Get the network range based on the default gateway.
        
        Returns:
            Network range in CIDR notation or None if not determined.
        """
        
    def start_scan(self, callback: Optional[Callable] = None) -> bool:
        """Start scanning the network for devices.
        
        Args:
            callback: Optional callback function that is called with scan results
            
        Returns:
            True if scan started successfully, False otherwise
        """
        
    def stop_scan(self) -> bool:
        """Stop an ongoing scan.
        
        Returns:
            True if stopping the scan succeeded, False otherwise
        """
        
    def get_last_scan_results(self) -> List[Dict[str, Any]]:
        """Get the results of the last scan.
        
        Returns:
            List of device dictionaries from the last scan
        """
        
    def clear_cache(self):
        """Clear the device cache."""
        
    def get_estimated_scan_time(self, network_range: str = None) -> float:
        """Get an estimate of how long a scan will take.
        
        Args:
            network_range: Optional network range, will use default if None
            
        Returns:
            Estimated time in seconds for the scan
        """
```

#### Usage Example
```python
from app.components.network_scanner import NetworkScanner

# Create scanner instance
scanner = NetworkScanner()

# Define callback function
def handle_scan_results(devices, message):
    print(f"Scan status: {message}")
    print(f"Found {len(devices)} devices")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}")

# Start scanning
scanner.start_scan(callback=handle_scan_results)

# Get scan results later
devices = scanner.get_last_scan_results()
```

#### Configuration Options
The NetworkScanner can be configured via the global configuration object:
- `scanner.timeout`: Scan timeout in seconds (default: 3)
- `scanner.batch_size`: Number of IPs to scan in each batch (default: 64)
- `scanner.cache_timeout`: Cache expiration time in seconds (default: 1800)
- `scanner.save_results`: Whether to save scan results (default: True)
- `scanner.max_saved_scans`: Maximum number of scan result files to keep (default: 5)

### ARPSpoofer

The `ARPSpoofer` class provides functionality to simulate and detect ARP spoofing attacks.

#### Class Definition
```python
class ARPSpoofer:
    def __init__(self):
        """Initialize the ARP spoofer with default configuration."""
        
    def simulate_attack(self, target_ip: str, gateway_ip: str, 
                       callback: Optional[Callable] = None) -> bool:
        """Simulate an ARP spoofing attack.
        
        Args:
            target_ip: The IP address of the target device
            gateway_ip: The IP address of the gateway
            callback: Optional callback function for progress updates
            
        Returns:
            True if attack simulation started successfully, False otherwise
        """
        
    def stop_simulation(self) -> bool:
        """Stop an ongoing attack simulation.
        
        Returns:
            True if stopping succeeded, False otherwise
        """
        
    def detect_arp_spoofing(self, callback: Optional[Callable] = None) -> bool:
        """Start detection of ARP spoofing attacks.
        
        Args:
            callback: Optional callback function for detection events
            
        Returns:
            True if detection started successfully, False otherwise
        """
        
    def stop_detection(self) -> bool:
        """Stop ARP spoofing detection.
        
        Returns:
            True if stopping succeeded, False otherwise
        """
        
    def get_arp_cache(self) -> List[Dict[str, Any]]:
        """Get the current ARP cache.
        
        Returns:
            List of ARP cache entries
        """
```

#### Usage Example
```python
from app.components.arp_spoofer import ARPSpoofer

# Create spoofer instance
spoofer = ARPSpoofer()

# Define callback function for detection
def handle_spoofing_detection(success, message, details=None):
    if success:
        print(f"Detected ARP spoofing: {message}")
        if details:
            print(f"Attacker MAC: {details.get('attacker_mac')}")
            print(f"Victim IP: {details.get('victim_ip')}")
    else:
        print(f"Detection error: {message}")

# Start detection
spoofer.detect_arp_spoofing(callback=handle_spoofing_detection)

# Later, stop detection
spoofer.stop_detection()
```

### ThreatDetector

The `ThreatDetector` class provides comprehensive threat detection capabilities.

#### Class Definition
```python
class ThreatDetector:
    def __init__(self):
        """Initialize the threat detector with default configuration."""
        
    def start_detection(self, callback: Optional[Callable] = None) -> bool:
        """Start threat detection.
        
        Args:
            callback: Optional callback function for detection events
            
        Returns:
            True if detection started successfully, False otherwise
        """
        
    def stop_detection(self) -> bool:
        """Stop threat detection.
        
        Returns:
            True if stopping succeeded, False otherwise
        """
        
    def analyze_packet(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single packet for threats.
        
        Args:
            packet_data: Dictionary containing packet information
            
        Returns:
            Dictionary with analysis results
        """
        
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get statistics about detection activities.
        
        Returns:
            Dictionary with detection statistics
        """
        
    def get_detected_threats(self) -> List[Dict[str, Any]]:
        """Get the list of detected threats.
        
        Returns:
            List of threat dictionaries
        """
```

#### Usage Example
```python
from app.components.threat_detector import ThreatDetector

# Create detector instance
detector = ThreatDetector()

# Define callback function
def handle_threat_detection(success, message, details=None):
    if success:
        print(f"Detected threat: {message}")
        if details:
            print(f"Severity: {details.get('severity', 'unknown')}")
            print(f"Source: {details.get('source_ip', 'unknown')}")
    else:
        print(f"Detection error: {message}")

# Start detection
detector.start_detection(callback=handle_threat_detection)

# Get detected threats later
threats = detector.get_detected_threats()
```

### PacketAnalyzer

The `PacketAnalyzer` class provides network packet capture and analysis capabilities.

#### Class Definition
```python
class PacketAnalyzer:
    def __init__(self):
        """Initialize the packet analyzer with default configuration."""
        
    def start_capture(self, interface: Optional[str] = None, 
                     filter_str: Optional[str] = None,
                     callback: Optional[Callable] = None) -> bool:
        """Start packet capture.
        
        Args:
            interface: Network interface to capture on (None for default)
            filter_str: BPF filter string to apply (None for no filter)
            callback: Optional callback function for captured packets
            
        Returns:
            True if capture started successfully, False otherwise
        """
        
    def stop_capture(self) -> bool:
        """Stop packet capture.
        
        Returns:
            True if stopping succeeded, False otherwise
        """
        
    def analyze_packet(self, packet) -> Dict[str, Any]:
        """Analyze a single packet.
        
        Args:
            packet: Raw packet data
            
        Returns:
            Dictionary with analysis results
        """
        
    def get_capture_statistics(self) -> Dict[str, Any]:
        """Get statistics about the current capture.
        
        Returns:
            Dictionary with capture statistics
        """
        
    def get_captured_packets(self, 
                            count: Optional[int] = None, 
                            filter_func: Optional[Callable] = None) -> List[Dict[str, Any]]:
        """Get captured packets.
        
        Args:
            count: Maximum number of packets to return (None for all)
            filter_func: Optional filter function
            
        Returns:
            List of packet dictionaries
        """
```

#### Usage Example
```python
from app.components.packet_analyzer import PacketAnalyzer

# Create analyzer instance
analyzer = PacketAnalyzer()

# Define callback function
def handle_packet(packet_info):
    print(f"Captured packet: {packet_info['protocol']} {packet_info['source']} -> {packet_info['destination']}")

# Start capture with TCP filter
analyzer.start_capture(filter_str="tcp", callback=handle_packet)

# Later, get capture statistics
stats = analyzer.get_capture_statistics()
print(f"Captured {stats['packet_count']} packets, {stats['bytes']} bytes")

# Get the first 10 HTTP packets
http_packets = analyzer.get_captured_packets(
    count=10,
    filter_func=lambda p: p.get('protocol') == 'HTTP'
)
```

### AttackRecognizer

The `AttackRecognizer` class provides advanced attack pattern recognition.

#### Class Definition
```python
class AttackRecognizer:
    def __init__(self):
        """Initialize the attack recognizer with default configuration."""
        
    def start_detection(self, patterns: Optional[List[str]] = None,
                       callback: Optional[Callable] = None) -> bool:
        """Start attack pattern detection.
        
        Args:
            patterns: List of pattern names to detect (None for all)
            callback: Optional callback function for detection events
            
        Returns:
            True if detection started successfully, False otherwise
        """
        
    def stop_detection(self) -> bool:
        """Stop attack pattern detection.
        
        Returns:
            True if stopping succeeded, False otherwise
        """
        
    def get_available_patterns(self) -> List[Dict[str, Any]]:
        """Get the list of available attack patterns.
        
        Returns:
            List of pattern dictionaries
        """
        
    def get_detected_attacks(self) -> List[Dict[str, Any]]:
        """Get the list of detected attacks.
        
        Returns:
            List of attack dictionaries
        """
```

#### Usage Example
```python
from app.components.attack_recognizer import AttackRecognizer

# Create recognizer instance
recognizer = AttackRecognizer()

# Define callback function
def handle_attack_detection(success, message, details=None):
    if success:
        print(f"Detected attack: {message}")
        if details:
            print(f"Attack type: {details.get('type', 'unknown')}")
            print(f"Severity: {details.get('severity', 'unknown')}")
    else:
        print(f"Detection error: {message}")

# Get available patterns
patterns = recognizer.get_available_patterns()
print(f"Available patterns: {[p['name'] for p in patterns]}")

# Start detection with specific patterns
recognizer.start_detection(
    patterns=["arp_spoofing", "port_scanning"],
    callback=handle_attack_detection
)

# Later, get detected attacks
attacks = recognizer.get_detected_attacks()
```

### ThreatIntelligence

The `ThreatIntelligence` class provides cloud-based threat intelligence integration.

#### Class Definition
```python
class ThreatIntelligence:
    def __init__(self):
        """Initialize the threat intelligence component."""
        
    def update_data(self, callback: Optional[Callable] = None) -> bool:
        """Update threat intelligence data from sources.
        
        Args:
            callback: Optional callback function for update events
            
        Returns:
            True if update started successfully, False otherwise
        """
        
    def get_malicious_ips(self, min_score: int = 0) -> List[Dict[str, Any]]:
        """Get known malicious IP addresses.
        
        Args:
            min_score: Minimum threat score (0-100)
            
        Returns:
            List of malicious IP dictionaries
        """
        
    def get_malicious_domains(self, min_score: int = 0) -> List[Dict[str, Any]]:
        """Get known malicious domains.
        
        Args:
            min_score: Minimum threat score (0-100)
            
        Returns:
            List of malicious domain dictionaries
        """
        
    def get_attack_signatures(self, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get attack signatures.
        
        Args:
            severity: Optional severity filter (None for all)
            
        Returns:
            List of signature dictionaries
        """
        
    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """Check if an IP address is known to be malicious.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Dictionary with threat information
        """
        
    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check if a domain is known to be malicious.
        
        Args:
            domain: Domain to check
            
        Returns:
            Dictionary with threat information
        """
```

#### Usage Example
```python
from app.components.threat_intelligence import get_threat_intelligence

# Get the threat intelligence singleton
threat_intel = get_threat_intelligence()

# Define callback function
def handle_update(success, message, details=None):
    if success:
        print(f"Update completed: {message}")
    else:
        print(f"Update error: {message}")

# Update threat data
threat_intel.update_data(callback=handle_update)

# Get malicious IPs with high score
malicious_ips = threat_intel.get_malicious_ips(min_score=80)
print(f"Found {len(malicious_ips)} malicious IPs with high threat score")

# Check a specific IP
ip_check = threat_intel.check_ip("1.2.3.4")
if ip_check.get('is_malicious'):
    print(f"IP is malicious: {ip_check.get('score')} score, {ip_check.get('categories')}")
else:
    print("IP is not known to be malicious")
```

### VulnerabilityScanner

The `VulnerabilityScanner` class provides network vulnerability scanning.

#### Class Definition
```python
class VulnerabilityScanner:
    def __init__(self):
        """Initialize the vulnerability scanner with default configuration."""
        
    def start_scan(self, targets: List[str], 
                  intensity: str = "normal",
                  callback: Optional[Callable] = None) -> bool:
        """Start vulnerability scan.
        
        Args:
            targets: List of target IP addresses
            intensity: Scan intensity ("low", "normal", "high")
            callback: Optional callback function for scan events
            
        Returns:
            True if scan started successfully, False otherwise
        """
        
    def stop_scan(self) -> bool:
        """Stop vulnerability scan.
        
        Returns:
            True if stopping succeeded, False otherwise
        """
        
    def get_scan_results(self) -> List[Dict[str, Any]]:
        """Get the results of vulnerability scans.
        
        Returns:
            List of vulnerability dictionaries
        """
        
    def get_vulnerability_database_info(self) -> Dict[str, Any]:
        """Get information about the vulnerability database.
        
        Returns:
            Dictionary with database information
        """
```

#### Usage Example
```python
from app.components.vulnerability_scanner import VulnerabilityScanner

# Create scanner instance
scanner = VulnerabilityScanner()

# Define callback function
def handle_vulnerability_scan(success, message, details=None):
    if success:
        print(f"Scan update: {message}")
        if details and 'vulnerabilities' in details:
            print(f"Found {len(details['vulnerabilities'])} vulnerabilities")
    else:
        print(f"Scan error: {message}")

# Start scan with medium intensity
scanner.start_scan(
    targets=["192.168.1.1", "192.168.1.100"],
    intensity="normal",
    callback=handle_vulnerability_scan
)

# Later, get scan results
vulnerabilities = scanner.get_scan_results()
```

### DefenseMechanism

The `DefenseMechanism` class provides network defense capabilities.

#### Class Definition
```python
class DefenseMechanism:
    def __init__(self):
        """Initialize the defense mechanism component."""
        
    def activate_defense(self, defense_type: str, 
                        target: Dict[str, Any],
                        callback: Optional[Callable] = None) -> bool:
        """Activate a defense mechanism.
        
        Args:
            defense_type: Type of defense to activate
            target: Target information (depends on defense type)
            callback: Optional callback function for defense events
            
        Returns:
            True if defense activated successfully, False otherwise
        """
        
    def deactivate_defense(self, defense_id: str) -> bool:
        """Deactivate a defense mechanism.
        
        Args:
            defense_id: ID of the defense to deactivate
            
        Returns:
            True if deactivation succeeded, False otherwise
        """
        
    def get_available_defenses(self) -> List[Dict[str, Any]]:
        """Get available defense mechanisms.
        
        Returns:
            List of defense mechanism dictionaries
        """
        
    def get_active_defenses(self) -> List[Dict[str, Any]]:
        """Get currently active defenses.
        
        Returns:
            List of active defense dictionaries
        """
```

#### Usage Example
```python
from app.components.defense_mechanism import DefenseMechanism

# Create defense mechanism instance
defense = DefenseMechanism()

# Define callback function
def handle_defense_activation(success, message, details=None):
    if success:
        print(f"Defense activated: {message}")
        if details:
            print(f"Defense ID: {details.get('defense_id')}")
    else:
        print(f"Defense activation error: {message}")

# Get available defenses
available_defenses = defense.get_available_defenses()
print(f"Available defenses: {[d['name'] for d in available_defenses]}")

# Activate ARP spoof protection
defense.activate_defense(
    defense_type="arp_protection",
    target={"gateway_ip": "192.168.1.1"},
    callback=handle_defense_activation
)

# Get active defenses
active = defense.get_active_defenses()
```

## Utility Modules

### Config

The `Config` module provides configuration management.

#### Functions
```python
def get_config() -> Dict[str, Any]:
    """Get the global configuration object.
    
    Returns:
        Dictionary with configuration values
    """
    
def save_config(config: Dict[str, Any]) -> bool:
    """Save the configuration to disk.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        True if save succeeded, False otherwise
    """
    
def get_default_config() -> Dict[str, Any]:
    """Get the default configuration.
    
    Returns:
        Dictionary with default configuration values
    """
```

#### Usage Example
```python
from app.utils.config import get_config, save_config

# Get current configuration
config = get_config()

# Modify configuration
config["scanner.timeout"] = 5
config["ui.theme"] = "dark"

# Save changes
save_config(config)
```

### Logger

The `Logger` module provides logging functionality.

#### Functions
```python
def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for a module.
    
    Args:
        name: Module name
        
    Returns:
        Logger instance
    """
    
def set_log_level(level: int) -> None:
    """Set the global log level.
    
    Args:
        level: Log level (e.g., logging.DEBUG)
    """
    
def enable_file_logging(path: Optional[str] = None) -> bool:
    """Enable logging to file.
    
    Args:
        path: Optional log file path
        
    Returns:
        True if enabling succeeded, False otherwise
    """
```

#### Usage Example
```python
import logging
from app.utils.logger import get_logger, set_log_level, enable_file_logging

# Enable debug logging
set_log_level(logging.DEBUG)

# Enable file logging
enable_file_logging()

# Get a logger for your module
logger = get_logger('my_module')

# Use the logger
logger.info("Application started")
logger.debug("Detailed debug information")
logger.warning("Warning message")
```

### MacVendor

The `MacVendor` module provides MAC address vendor lookup.

#### Functions
```python
def get_vendor_name(mac_address: str) -> str:
    """Get the vendor name for a MAC address.
    
    Args:
        mac_address: MAC address
        
    Returns:
        Vendor name or "Unknown"
    """
    
def update_vendor_database() -> bool:
    """Update the MAC vendor database.
    
    Returns:
        True if update succeeded, False otherwise
    """
```

#### Usage Example
```python
from app.utils.mac_vendor import get_vendor_name, update_vendor_database

# Get vendor for a MAC address
vendor = get_vendor_name("00:11:22:33:44:55")
print(f"MAC address belongs to: {vendor}")

# Update the vendor database
update_vendor_database()
```

## UI Components

ARPGuard UI components are based on PyQt5 and follow a consistent pattern:

### Usage Pattern
```python
from app.components.network_topology import NetworkTopologyView

# Create the view
topology_view = NetworkTopologyView()

# Connect to signals
topology_view.node_selected.connect(handle_node_selected)
topology_view.node_double_clicked.connect(handle_node_double_clicked)

# Update with data
topology_view.update_topology(devices)

# Add to your layout
layout.addWidget(topology_view)
```

### Available UI Components

- `MainWindow`: Main application window
- `PacketView`: Packet capture and display
- `AttackView`: Attack pattern display
- `ThreatIntelligenceView`: Threat intelligence display
- `NetworkTopologyView`: Network visualization
- `VulnerabilityView`: Vulnerability display
- `DefenseView`: Defense mechanism interface
- `ReportViewer`: Report generation and viewing
- `SessionHistoryView`: Historical session management

## Integration Examples

### Extending ARPGuard with a Custom Component

```python
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton
from app.components.network_scanner import NetworkScanner
from app.utils.logger import get_logger

class CustomScannerWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = get_logger('custom_scanner')
        self.scanner = NetworkScanner()
        
        # Set up UI
        layout = QVBoxLayout(self)
        self.scan_button = QPushButton("Quick Scan")
        self.scan_button.clicked.connect(self.start_quick_scan)
        layout.addWidget(self.scan_button)
        
    def start_quick_scan(self):
        self.logger.info("Starting quick scan")
        self.scanner.start_scan(callback=self.handle_scan_results)
        
    def handle_scan_results(self, devices, message):
        self.logger.info(f"Scan complete: {message}")
        # Process the results
        for device in devices:
            self.logger.debug(f"Found device: {device['ip']} ({device['mac']})")
```

### Creating a Custom Attack Detector

```python
from app.components.attack_recognizer import AttackRecognizer
from app.components.packet_analyzer import PacketAnalyzer
from app.utils.logger import get_logger

class CustomAttackDetector:
    def __init__(self):
        self.logger = get_logger('custom_detector')
        self.recognizer = AttackRecognizer()
        self.analyzer = PacketAnalyzer()
        
        # Register with existing components
        self.analyzer.start_capture(callback=self.analyze_packet)
        
    def analyze_packet(self, packet_info):
        # Custom analysis logic
        if self.is_suspicious_packet(packet_info):
            self.logger.warning("Suspicious packet detected")
            # Report as an attack
            attack_details = {
                "type": "custom_attack",
                "severity": "medium",
                "source_ip": packet_info.get("source"),
                "evidence": [packet_info]
            }
            # You could pass this to the main application or handle internally
        
    def is_suspicious_packet(self, packet_info):
        # Implement your custom detection logic
        return False
```

### Command-Line Scanning Tool

```python
import sys
import time
import json
from app.components.network_scanner import NetworkScanner

def main():
    scanner = NetworkScanner()
    results = []
    
    def collect_results(devices, message):
        nonlocal results
        results = devices
        print(f"Scan status: {message}")
    
    print("Starting network scan...")
    scanner.start_scan(callback=collect_results)
    
    # Wait for scan to complete
    while scanner.scanning:
        time.sleep(0.5)
        sys.stdout.write(".")
        sys.stdout.flush()
    
    print("\nScan complete!")
    
    # Export results
    if len(sys.argv) > 1:
        output_file = sys.argv[1]
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {output_file}")
    else:
        # Print to console
        for device in results:
            print(f"{device['ip']} | {device['mac']} | {device['vendor']}")
    
if __name__ == "__main__":
    main() 