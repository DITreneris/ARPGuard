import logging
from typing import Dict, Any, Optional, List
from .alert import AlertManager, AlertType, AlertPriority
from .alert_config import AlertConfig

class AlertSource:
    """Base class for alert sources that can generate alerts."""
    
    def __init__(self, name: str, alert_manager: AlertManager):
        """
        Initialize the alert source.
        
        Args:
            name: Name of the alert source
            alert_manager: The alert manager to send alerts to
        """
        self.name = name
        self.alert_manager = alert_manager
        self.logger = logging.getLogger(f'alert_source.{name}')
        
    def create_alert(self, 
                    alert_type: AlertType,
                    priority: AlertPriority,
                    message: str,
                    details: Dict[str, Any]) -> None:
        """
        Create an alert from this source.
        
        Args:
            alert_type: Type of alert
            priority: Alert priority
            message: Alert message
            details: Additional alert details
        """
        self.alert_manager.create_alert(
            alert_type=alert_type,
            priority=priority,
            message=message,
            source=self.name,
            details=details
        )
        self.logger.info(f"Created {alert_type.value} alert: {message}")


class ArpSpoofingDetector(AlertSource):
    """Detects ARP spoofing attacks and generates alerts."""
    
    def __init__(self, alert_manager: AlertManager):
        """Initialize the ARP spoofing detector."""
        super().__init__("arp_spoofing_detector", alert_manager)
        self.mac_ip_mappings: Dict[str, str] = {}  # MAC -> IP
        
    def analyze_packet(self, mac: str, ip: str) -> None:
        """
        Analyze an ARP packet for potential spoofing.
        
        Args:
            mac: MAC address
            ip: IP address
        """
        # Check if we've seen this MAC before with a different IP
        if mac in self.mac_ip_mappings and self.mac_ip_mappings[mac] != ip:
            old_ip = self.mac_ip_mappings[mac]
            details = {
                "mac_address": mac,
                "original_ip": old_ip,
                "new_ip": ip
            }
            
            self.create_alert(
                alert_type=AlertType.ARP_SPOOFING,
                priority=AlertPriority.HIGH,
                message=f"Possible ARP spoofing detected: MAC {mac} changed from IP {old_ip} to {ip}",
                details=details
            )
        
        # Update our mapping
        self.mac_ip_mappings[mac] = ip


class RateAnomalyDetector(AlertSource):
    """Detects anomalies in packet rates and generates alerts."""
    
    def __init__(self, alert_manager: AlertManager, alert_config: AlertConfig):
        """
        Initialize the rate anomaly detector.
        
        Args:
            alert_manager: Alert manager instance
            alert_config: Alert configuration instance
        """
        super().__init__("rate_anomaly_detector", alert_manager)
        self.alert_config = alert_config
        self.samples = []
        self.last_rate = 0
        
        # Load thresholds from config
        threshold_config = alert_config.get_threshold("rate_anomaly")
        self.packets_per_second_threshold = threshold_config.get("packets_per_second", 1000)
        self.window_size = threshold_config.get("window_size", 60)
        
    def add_sample(self, timestamp: float, packet_count: int) -> None:
        """
        Add a packet rate sample.
        
        Args:
            timestamp: Timestamp of the sample
            packet_count: Number of packets in the sample
        """
        # Add sample and keep only the last window_size samples
        self.samples.append((timestamp, packet_count))
        if len(self.samples) > self.window_size:
            self.samples.pop(0)
            
        # Calculate current rate
        if len(self.samples) >= 2:
            first_ts, first_count = self.samples[0]
            last_ts, last_count = self.samples[-1]
            
            time_delta = last_ts - first_ts
            if time_delta > 0:
                packet_delta = last_count - first_count
                current_rate = packet_delta / time_delta
                
                # Check if rate exceeds threshold
                if current_rate > self.packets_per_second_threshold:
                    details = {
                        "current_rate": current_rate,
                        "threshold": self.packets_per_second_threshold,
                        "window_size": self.window_size,
                        "first_timestamp": first_ts,
                        "last_timestamp": last_ts
                    }
                    
                    # Determine priority based on how much threshold is exceeded
                    if current_rate > self.packets_per_second_threshold * 3:
                        priority = AlertPriority.CRITICAL
                    elif current_rate > self.packets_per_second_threshold * 2:
                        priority = AlertPriority.HIGH
                    else:
                        priority = AlertPriority.MEDIUM
                    
                    self.create_alert(
                        alert_type=AlertType.RATE_ANOMALY,
                        priority=priority,
                        message=f"Packet rate anomaly detected: {current_rate:.2f} packets/sec exceeds threshold of {self.packets_per_second_threshold}",
                        details=details
                    )
                
                self.last_rate = current_rate


class PatternMatcher(AlertSource):
    """Detects specific patterns in network traffic and generates alerts."""
    
    def __init__(self, alert_manager: AlertManager):
        """Initialize the pattern matcher."""
        super().__init__("pattern_matcher", alert_manager)
        self.patterns: List[Dict[str, Any]] = []
        
    def add_pattern(self, pattern_id: str, pattern_type: str, 
                  pattern_data: Dict[str, Any], priority: AlertPriority) -> None:
        """
        Add a pattern to match against.
        
        Args:
            pattern_id: Unique ID for the pattern
            pattern_type: Type of pattern (e.g., "mac_sequence", "protocol_behavior")
            pattern_data: Pattern-specific data
            priority: Alert priority if pattern is matched
        """
        self.patterns.append({
            "id": pattern_id,
            "type": pattern_type,
            "data": pattern_data,
            "priority": priority
        })
        
    def check_pattern(self, data: Dict[str, Any]) -> None:
        """
        Check if data matches any defined patterns.
        
        Args:
            data: Data to check against patterns
        """
        for pattern in self.patterns:
            if self._match_pattern(pattern, data):
                details = {
                    "pattern_id": pattern["id"],
                    "pattern_type": pattern["type"],
                    "matched_data": data
                }
                
                self.create_alert(
                    alert_type=AlertType.PATTERN_MATCH,
                    priority=pattern["priority"],
                    message=f"Pattern match detected: {pattern['id']}",
                    details=details
                )
                
    def _match_pattern(self, pattern: Dict[str, Any], data: Dict[str, Any]) -> bool:
        """
        Match data against a specific pattern.
        
        Args:
            pattern: Pattern to match against
            data: Data to check
            
        Returns:
            True if data matches pattern, False otherwise
        """
        # Implementation depends on pattern types
        pattern_type = pattern["type"]
        pattern_data = pattern["data"]
        
        if pattern_type == "mac_sequence":
            # Check for sequence of MAC addresses
            if "mac_sequence" in data and "sequence" in pattern_data:
                return data["mac_sequence"] == pattern_data["sequence"]
                
        elif pattern_type == "protocol_behavior":
            # Check for specific protocol behavior
            if "protocol" in data and "behavior" in data:
                return (data["protocol"] == pattern_data.get("protocol") and
                       data["behavior"] == pattern_data.get("behavior"))
                
        return False


class AlertIntegration:
    """Integrates alert sources with the alert manager."""
    
    def __init__(self, config_path: str = "config/alert_config.json"):
        """
        Initialize alert integration.
        
        Args:
            config_path: Path to alert configuration file
        """
        self.logger = logging.getLogger('alert_integration')
        
        # Initialize configuration
        self.config = AlertConfig(config_path)
        
        # Initialize alert manager
        self.alert_manager = AlertManager()
        
        # Set up notification channels from config
        channels = self.config.create_channels()
        for channel in channels:
            self.alert_manager.add_channel(channel)
            
        # Initialize alert sources
        self.arp_detector = ArpSpoofingDetector(self.alert_manager)
        self.rate_detector = RateAnomalyDetector(self.alert_manager, self.config)
        self.pattern_matcher = PatternMatcher(self.alert_manager)
        
        self.logger.info("Alert integration initialized")
        
    def analyze_arp(self, mac: str, ip: str) -> None:
        """
        Analyze ARP packet for potential spoofing.
        
        Args:
            mac: MAC address
            ip: IP address
        """
        self.arp_detector.analyze_packet(mac, ip)
        
    def update_rate(self, timestamp: float, packet_count: int) -> None:
        """
        Update packet rate statistics.
        
        Args:
            timestamp: Current timestamp
            packet_count: Total packet count
        """
        self.rate_detector.add_sample(timestamp, packet_count)
        
    def check_pattern(self, data: Dict[str, Any]) -> None:
        """
        Check if data matches any patterns.
        
        Args:
            data: Data to check
        """
        self.pattern_matcher.check_pattern(data)
        
    def add_pattern(self, pattern_id: str, pattern_type: str, 
                  pattern_data: Dict[str, Any], priority: AlertPriority) -> None:
        """
        Add a pattern to the pattern matcher.
        
        Args:
            pattern_id: Unique ID for the pattern
            pattern_type: Type of pattern
            pattern_data: Pattern-specific data
            priority: Alert priority if pattern is matched
        """
        self.pattern_matcher.add_pattern(pattern_id, pattern_type, pattern_data, priority)
        
    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """
        Get an alert by ID.
        
        Args:
            alert_id: ID of the alert
            
        Returns:
            Alert as dictionary if found, None otherwise
        """
        alert = self.alert_manager.get_alert(alert_id)
        if alert:
            return alert.to_dict()
        return None
        
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """
        Get all active alerts.
        
        Returns:
            List of active alerts as dictionaries
        """
        return [alert.to_dict() for alert in self.alert_manager.get_active_alerts()]
        
    def acknowledge_alert(self, alert_id: str) -> None:
        """
        Acknowledge an alert.
        
        Args:
            alert_id: ID of the alert to acknowledge
        """
        self.alert_manager.acknowledge_alert(alert_id) 