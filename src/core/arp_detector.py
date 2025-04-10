"""
ARP Spoofing Detector Module
Identifies potential ARP spoofing attacks based on packet analysis
"""

import os
import time
import json
import logging
import threading
from typing import Dict, List, Set, Optional, Callable, Tuple, Any
from enum import Enum
from datetime import datetime, timedelta
from dataclasses import dataclass, field

from src.core.packet_analyzer import ARPPacket, PacketType, PacketAnalyzer, SCAPY_AVAILABLE

logger = logging.getLogger(__name__)


class DetectionRule(Enum):
    """Types of ARP attack detection rules"""
    MAC_IP_BINDING_CHANGE = "mac_ip_binding_change"
    GATEWAY_IMPERSONATION = "gateway_impersonation"
    MULTIPLE_MAC_FOR_IP = "multiple_mac_for_ip"
    PACKET_RATE_THRESHOLD = "packet_rate_threshold"
    IP_IN_WRONG_SUBNET = "ip_in_wrong_subnet"
    UNAUTHORIZED_ARP_ANNOUNCEMENT = "unauthorized_arp_announcement"
    MITM_PATTERN = "mitm_pattern"


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ARPAlert:
    """Class representing an ARP spoofing alert"""
    timestamp: float
    rule: DetectionRule
    severity: AlertSeverity
    src_mac: str
    src_ip: str
    affected_ip: Optional[str] = None
    affected_mac: Optional[str] = None
    description: str = ""
    packet: Optional[ARPPacket] = None
    alert_id: str = field(default_factory=lambda: f"alert_{int(time.time() * 1000)}")
    acknowledged: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp).isoformat(),
            "rule": self.rule.value,
            "severity": self.severity.value,
            "src_mac": self.src_mac,
            "src_ip": self.src_ip,
            "affected_ip": self.affected_ip,
            "affected_mac": self.affected_mac,
            "description": self.description,
            "acknowledged": self.acknowledged
        }


class DetectorConfig:
    """Configuration for ARP spoofing detector"""
    
    def __init__(self,
                trusted_hosts_file: str = "data/trusted_hosts.json",
                gateway_file: str = "data/gateways.json",
                packet_rate_threshold: int = 20,
                detection_interval: int = 10,
                alert_timeout: int = 300,
                enable_all_rules: bool = True,
                enabled_rules: Optional[List[DetectionRule]] = None):
        """
        Initialize detector configuration
        
        Args:
            trusted_hosts_file: Path to trusted hosts file
            gateway_file: Path to gateways file
            packet_rate_threshold: Max packets per second before alerting
            detection_interval: Interval in seconds for running detection
            alert_timeout: Time in seconds before similar alerts are repeated
            enable_all_rules: Whether to enable all detection rules
            enabled_rules: List of specific rules to enable if enable_all_rules is False
        """
        self.trusted_hosts_file = trusted_hosts_file
        self.gateway_file = gateway_file
        self.packet_rate_threshold = packet_rate_threshold
        self.detection_interval = detection_interval
        self.alert_timeout = alert_timeout
        self.enable_all_rules = enable_all_rules
        self.enabled_rules = enabled_rules or []
        
        # Loaded data
        self.trusted_hosts: Dict[str, str] = {}  # IP -> MAC
        self.gateways: Dict[str, str] = {}  # IP -> MAC
        
        # Load data if files exist
        self._load_trusted_hosts()
        self._load_gateways()
        
    def _load_trusted_hosts(self) -> None:
        """Load trusted hosts if file exists"""
        if os.path.exists(self.trusted_hosts_file):
            try:
                with open(self.trusted_hosts_file, 'r') as f:
                    self.trusted_hosts = json.load(f)
                logger.info(f"Loaded {len(self.trusted_hosts)} trusted hosts from {self.trusted_hosts_file}")
            except Exception as e:
                logger.error(f"Failed to load trusted hosts: {e}")
        else:
            logger.warning(f"Trusted hosts file not found: {self.trusted_hosts_file}")
            
    def _load_gateways(self) -> None:
        """Load gateways if file exists"""
        if os.path.exists(self.gateway_file):
            try:
                with open(self.gateway_file, 'r') as f:
                    self.gateways = json.load(f)
                logger.info(f"Loaded {len(self.gateways)} gateways from {self.gateway_file}")
            except Exception as e:
                logger.error(f"Failed to load gateways: {e}")
        else:
            logger.warning(f"Gateways file not found: {self.gateway_file}")
    
    def is_rule_enabled(self, rule: DetectionRule) -> bool:
        """Check if a detection rule is enabled"""
        if self.enable_all_rules:
            return True
        return rule in self.enabled_rules
    
    def is_trusted_host(self, ip: str, mac: str) -> bool:
        """Check if a host is trusted"""
        if ip in self.trusted_hosts:
            return self.trusted_hosts[ip].lower() == mac.lower()
        return False
    
    def is_gateway(self, ip: str) -> bool:
        """Check if an IP belongs to a known gateway"""
        return ip in self.gateways
    
    def get_gateway_mac(self, ip: str) -> Optional[str]:
        """Get MAC address for a gateway IP"""
        return self.gateways.get(ip)


class ARPSpoofDetector:
    """
    Detects potential ARP spoofing attacks by analyzing ARP packets
    """
    
    def __init__(self, analyzer: PacketAnalyzer, config: Optional[DetectorConfig] = None):
        """
        Initialize ARP spoofing detector
        
        Args:
            analyzer: Packet analyzer instance to get packets from
            config: Detector configuration
        """
        self.analyzer = analyzer
        self.config = config or DetectorConfig()
        self.alerts: List[ARPAlert] = []
        self.ip_mac_history: Dict[str, List[Tuple[str, float]]] = {}  # IP -> List of (MAC, timestamp)
        self.recent_alert_keys: Dict[str, float] = {}  # Alert key -> timestamp
        self.is_running = False
        self.detection_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.alert_callbacks: List[Callable[[ARPAlert], None]] = []
        
        # Register packet callback with analyzer
        if analyzer:
            analyzer.register_callback(self._on_packet_received)
    
    def start_detection(self) -> bool:
        """
        Start ARP spoofing detection in a separate thread
        
        Returns:
            bool: True if started successfully
        """
        if self.is_running:
            logger.warning("Detection already running")
            return True
        
        if not SCAPY_AVAILABLE:
            logger.error("Cannot start detection: Scapy library not available")
            return False
        
        self.is_running = True
        self.stop_event.clear()
        
        # Start detection thread
        self.detection_thread = threading.Thread(
            target=self._detection_loop,
            daemon=True
        )
        self.detection_thread.start()
        
        logger.info("Started ARP spoofing detection")
        return True
    
    def stop_detection(self) -> None:
        """Stop ARP spoofing detection"""
        if not self.is_running:
            return
        
        logger.info("Stopping ARP spoofing detection...")
        self.stop_event.set()
        
        if self.detection_thread and self.detection_thread.is_alive():
            self.detection_thread.join(timeout=2.0)
        
        self.is_running = False
        logger.info("ARP spoofing detection stopped")
    
    def register_alert_callback(self, callback: Callable[[ARPAlert], None]) -> None:
        """
        Register a callback function to be called for each alert
        
        Args:
            callback: Function to call with each new alert
        """
        self.alert_callbacks.append(callback)
    
    def _detection_loop(self) -> None:
        """Internal method for detection thread"""
        while not self.stop_event.is_set():
            try:
                # Run detection rules
                self._run_detection_rules()
                
                # Wait for next detection interval
                time.sleep(self.config.detection_interval)
            except Exception as e:
                logger.error(f"Error in detection loop: {e}")
    
    def _on_packet_received(self, packet: ARPPacket) -> None:
        """
        Handle packet from analyzer's callback
        
        Args:
            packet: The ARP packet
        """
        # Update IP-MAC history
        self._update_ip_mac_history(packet)
        
        # Check rate-based rules (these run per-packet)
        if self.config.is_rule_enabled(DetectionRule.PACKET_RATE_THRESHOLD):
            self._check_packet_rate(packet)
    
    def _update_ip_mac_history(self, packet: ARPPacket) -> None:
        """Update the IP-MAC history for tracking changes"""
        if not packet.source_ip or not packet.source_mac:
            return
        
        ip = packet.source_ip
        mac = packet.source_mac
        
        if ip not in self.ip_mac_history:
            self.ip_mac_history[ip] = []
        
        # Add the new MAC-timestamp pair
        self.ip_mac_history[ip].append((mac, packet.timestamp))
        
        # Limit history size to avoid memory growth
        if len(self.ip_mac_history[ip]) > 10:
            self.ip_mac_history[ip] = self.ip_mac_history[ip][-10:]
    
    def _run_detection_rules(self) -> None:
        """Run all enabled detection rules"""
        if not self.analyzer or not self.analyzer.packets:
            return
        
        # Check for MAC-IP binding changes
        if self.config.is_rule_enabled(DetectionRule.MAC_IP_BINDING_CHANGE):
            self._check_mac_ip_binding_changes()
        
        # Check for multiple MACs for an IP
        if self.config.is_rule_enabled(DetectionRule.MULTIPLE_MAC_FOR_IP):
            self._check_multiple_mac_for_ip()
        
        # Check for gateway impersonation
        if self.config.is_rule_enabled(DetectionRule.GATEWAY_IMPERSONATION):
            self._check_gateway_impersonation()
        
        # Check for unauthorized ARP announcements
        if self.config.is_rule_enabled(DetectionRule.UNAUTHORIZED_ARP_ANNOUNCEMENT):
            self._check_unauthorized_announcements()
        
        # Check for MITM patterns
        if self.config.is_rule_enabled(DetectionRule.MITM_PATTERN):
            self._check_mitm_patterns()
    
    def _check_mac_ip_binding_changes(self) -> None:
        """Detect rapid changes in MAC-IP bindings"""
        for ip, history in self.ip_mac_history.items():
            if len(history) < 2:
                continue
            
            # Get unique MACs in the recent history
            recent_window = 120  # seconds
            current_time = time.time()
            recent_history = [(mac, ts) for mac, ts in history if current_time - ts <= recent_window]
            
            if not recent_history:
                continue
            
            unique_macs = set(mac for mac, _ in recent_history)
            
            # If there have been multiple MACs for this IP recently
            if len(unique_macs) > 1 and not self._is_trusted_ip_mac_change(ip, unique_macs):
                # Only alert if the change happened recently
                newest_mac = max(recent_history, key=lambda x: x[1])[0]
                previous_macs = [m for m in unique_macs if m != newest_mac]
                
                for prev_mac in previous_macs:
                    alert_key = f"mac_change_{ip}_{prev_mac}_{newest_mac}"
                    if self._should_create_alert(alert_key):
                        self._create_alert(
                            rule=DetectionRule.MAC_IP_BINDING_CHANGE,
                            severity=AlertSeverity.HIGH,
                            src_mac=newest_mac,
                            src_ip=ip,
                            affected_mac=prev_mac,
                            affected_ip=ip,
                            description=f"MAC address for IP {ip} changed from {prev_mac} to {newest_mac}"
                        )
    
    def _check_multiple_mac_for_ip(self) -> None:
        """Detect multiple MAC addresses associated with a single IP"""
        for ip, mac_set in self.analyzer.ip_mac_mapping.items():
            if len(mac_set) > 1 and not self._is_trusted_ip_mac_change(ip, mac_set):
                mac_list = list(mac_set)
                alert_key = f"multiple_mac_{ip}_{'-'.join(sorted(mac_list))}"
                
                if self._should_create_alert(alert_key):
                    self._create_alert(
                        rule=DetectionRule.MULTIPLE_MAC_FOR_IP,
                        severity=AlertSeverity.MEDIUM,
                        src_mac=mac_list[0],  # Using first MAC as source
                        src_ip=ip,
                        affected_ip=ip,
                        description=f"Multiple MAC addresses ({', '.join(mac_list)}) for IP {ip}"
                    )
    
    def _check_gateway_impersonation(self) -> None:
        """Detect potential gateway impersonation"""
        for ip in self.config.gateways:
            expected_mac = self.config.get_gateway_mac(ip)
            if not expected_mac:
                continue
                
            current_macs = self.analyzer.get_mac_for_ip(ip)
            
            if not current_macs:
                continue
                
            for mac in current_macs:
                if mac.lower() != expected_mac.lower():
                    alert_key = f"gateway_impersonation_{ip}_{mac}"
                    
                    if self._should_create_alert(alert_key):
                        self._create_alert(
                            rule=DetectionRule.GATEWAY_IMPERSONATION,
                            severity=AlertSeverity.CRITICAL,
                            src_mac=mac,
                            src_ip=ip,
                            affected_ip=ip,
                            affected_mac=expected_mac,
                            description=f"Potential gateway impersonation: MAC {mac} is claiming to be gateway IP {ip} (expected MAC: {expected_mac})"
                        )
    
    def _check_packet_rate(self, packet: ARPPacket) -> None:
        """Detect abnormal ARP packet rates (rate-based detection)"""
        # This is called per-packet, so we need to be efficient
        # Get packets in the last few seconds for this source
        current_time = time.time()
        time_window = 5  # seconds
        
        # Count packets in the last window
        recent_packets = [p for p in self.analyzer.packets 
                         if p.source_mac == packet.source_mac and 
                         current_time - p.timestamp <= time_window]
        
        packet_rate = len(recent_packets) / time_window
        
        if packet_rate > self.config.packet_rate_threshold:
            alert_key = f"high_rate_{packet.source_mac}_{int(current_time/60)}"  # Group by minute
            
            if self._should_create_alert(alert_key):
                self._create_alert(
                    rule=DetectionRule.PACKET_RATE_THRESHOLD,
                    severity=AlertSeverity.MEDIUM,
                    src_mac=packet.source_mac,
                    src_ip=packet.source_ip,
                    packet=packet,
                    description=f"High ARP packet rate ({packet_rate:.1f}/sec) detected from {packet.source_mac} ({packet.source_ip})"
                )
    
    def _check_unauthorized_announcements(self) -> None:
        """Detect unauthorized ARP announcements"""
        # Get recent announcements
        current_time = time.time()
        time_window = 60  # seconds
        
        recent_announcements = [p for p in self.analyzer.packets 
                              if p.packet_type == PacketType.ARP_ANNOUNCEMENT and 
                              current_time - p.timestamp <= time_window]
        
        for packet in recent_announcements:
            ip = packet.source_ip
            mac = packet.source_mac
            
            # Skip trusted hosts
            if self.config.is_trusted_host(ip, mac):
                continue
                
            # If this is a gateway IP, but wrong MAC
            if self.config.is_gateway(ip):
                expected_mac = self.config.get_gateway_mac(ip)
                if expected_mac and mac.lower() != expected_mac.lower():
                    alert_key = f"unauthorized_announcement_{ip}_{mac}"
                    
                    if self._should_create_alert(alert_key):
                        self._create_alert(
                            rule=DetectionRule.UNAUTHORIZED_ARP_ANNOUNCEMENT,
                            severity=AlertSeverity.HIGH,
                            src_mac=mac,
                            src_ip=ip,
                            affected_ip=ip,
                            affected_mac=expected_mac,
                            packet=packet,
                            description=f"Unauthorized ARP announcement for gateway IP {ip} from MAC {mac}"
                        )
    
    def _check_mitm_patterns(self) -> None:
        """Detect patterns indicative of Man-in-the-Middle attacks"""
        # Get hosts forwarding ARP traffic between other hosts
        all_macs = self.analyzer.mac_ip_mapping.keys()
        
        for mac in all_macs:
            ips = self.analyzer.get_ip_for_mac(mac)
            if len(ips) <= 1:
                continue
                
            # Check if this host is responding for multiple different hosts including a gateway
            gateway_ips = [ip for ip in ips if self.config.is_gateway(ip)]
            if not gateway_ips:
                continue
                
            # This host claims to be both a gateway and other IPs - possible MITM
            other_ips = [ip for ip in ips if not self.config.is_gateway(ip)]
            
            if other_ips:
                # Get packets where this host answers for other hosts
                mitm_packets = []
                for packet in self.analyzer.get_packets_for_mac(mac):
                    if (packet.packet_type == PacketType.ARP_REPLY and 
                        packet.source_mac == mac and 
                        packet.source_ip in gateway_ips):
                        mitm_packets.append(packet)
                
                if mitm_packets:
                    alert_key = f"mitm_{mac}_{'-'.join(sorted(gateway_ips))}"
                    
                    if self._should_create_alert(alert_key):
                        self._create_alert(
                            rule=DetectionRule.MITM_PATTERN,
                            severity=AlertSeverity.CRITICAL,
                            src_mac=mac,
                            src_ip=gateway_ips[0],  # Using first gateway IP as source
                            packet=mitm_packets[0],
                            description=f"Potential MITM attack: Host {mac} claims to be both gateway ({', '.join(gateway_ips)}) and other hosts ({', '.join(other_ips)})"
                        )
    
    def _is_trusted_ip_mac_change(self, ip: str, mac_set: Set[str]) -> bool:
        """Check if the IP-MAC changes are from trusted hosts"""
        # If this IP is a gateway, only the registered MAC is allowed
        if self.config.is_gateway(ip):
            gateway_mac = self.config.get_gateway_mac(ip)
            # If we have one MAC and it matches the gateway, that's fine
            if len(mac_set) == 1 and gateway_mac and list(mac_set)[0].lower() == gateway_mac.lower():
                return True
            # Otherwise, any MAC change for a gateway IP is suspicious
            return False
        
        # Check if all MACs are trusted for this IP
        return all(self.config.is_trusted_host(ip, mac) for mac in mac_set)
    
    def _should_create_alert(self, alert_key: str) -> bool:
        """Determine if we should create a new alert based on recency"""
        current_time = time.time()
        
        if alert_key in self.recent_alert_keys:
            last_time = self.recent_alert_keys[alert_key]
            if current_time - last_time < self.config.alert_timeout:
                return False
        
        # Update the last alert time for this key
        self.recent_alert_keys[alert_key] = current_time
        return True
    
    def _create_alert(self, rule: DetectionRule, severity: AlertSeverity, 
                     src_mac: str, src_ip: str, description: str,
                     affected_ip: Optional[str] = None, 
                     affected_mac: Optional[str] = None,
                     packet: Optional[ARPPacket] = None) -> None:
        """Create and process a new ARP alert"""
        alert = ARPAlert(
            timestamp=time.time(),
            rule=rule,
            severity=severity,
            src_mac=src_mac,
            src_ip=src_ip,
            affected_ip=affected_ip,
            affected_mac=affected_mac,
            description=description,
            packet=packet
        )
        
        # Add to alerts list
        self.alerts.append(alert)
        
        # Log the alert
        log_msg = f"ARP Alert ({severity.value}): {description}"
        if severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
            logger.warning(log_msg)
        else:
            logger.info(log_msg)
        
        # Call alert callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """
        Mark an alert as acknowledged
        
        Args:
            alert_id: ID of the alert to acknowledge
            
        Returns:
            bool: True if the alert was found and acknowledged
        """
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                return True
        return False
    
    def get_alerts(self, 
                  min_severity: Optional[AlertSeverity] = None,
                  include_acknowledged: bool = False,
                  limit: int = 100,
                  start_time: Optional[float] = None,
                  end_time: Optional[float] = None) -> List[ARPAlert]:
        """
        Get filtered alerts
        
        Args:
            min_severity: Minimum severity level to include
            include_acknowledged: Whether to include acknowledged alerts
            limit: Maximum number of alerts to return
            start_time: Start time for filtering alerts
            end_time: End time for filtering alerts
            
        Returns:
            List of matching alerts
        """
        filtered_alerts = self.alerts
        
        # Filter by time range
        if start_time is not None:
            filtered_alerts = [a for a in filtered_alerts if a.timestamp >= start_time]
        if end_time is not None:
            filtered_alerts = [a for a in filtered_alerts if a.timestamp <= end_time]
        
        # Filter by severity
        if min_severity is not None:
            filtered_alerts = [a for a in filtered_alerts 
                             if AlertSeverity[a.severity.name].value >= AlertSeverity[min_severity.name].value]
        
        # Filter by acknowledgement status
        if not include_acknowledged:
            filtered_alerts = [a for a in filtered_alerts if not a.acknowledged]
        
        # Sort by timestamp (newest first) and apply limit
        return sorted(filtered_alerts, key=lambda x: x.timestamp, reverse=True)[:limit]
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about alerts
        
        Returns:
            Dictionary with statistics
        """
        stats = {
            "total_alerts": len(self.alerts),
            "alerts_by_severity": {},
            "alerts_by_rule": {},
            "active_alerts": len([a for a in self.alerts if not a.acknowledged]),
            "top_sources": []
        }
        
        # Count alerts by severity
        for severity in AlertSeverity:
            count = len([a for a in self.alerts if a.severity == severity])
            stats["alerts_by_severity"][severity.value] = count
        
        # Count alerts by rule
        for rule in DetectionRule:
            count = len([a for a in self.alerts if a.rule == rule])
            stats["alerts_by_rule"][rule.value] = count
        
        # Get top alert sources
        source_counts = {}
        for alert in self.alerts:
            src = f"{alert.src_ip} ({alert.src_mac})"
            source_counts[src] = source_counts.get(src, 0) + 1
        
        top_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        stats["top_sources"] = [{"source": src, "count": count} for src, count in top_sources]
        
        return stats
    
    def export_alerts(self, filename: str) -> bool:
        """
        Export alerts to a JSON file
        
        Args:
            filename: Output filename
            
        Returns:
            True if successful
        """
        try:
            data = [a.to_dict() for a in self.alerts]
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
                
            logger.info(f"Exported {len(data)} alerts to {filename}")
            return True
        except Exception as e:
            logger.error(f"Error exporting alerts: {e}")
            return False
    
    def clear_alerts(self, include_acknowledged: bool = True) -> int:
        """
        Clear alerts from memory
        
        Args:
            include_acknowledged: Whether to include acknowledged alerts
            
        Returns:
            Number of alerts cleared
        """
        count_before = len(self.alerts)
        
        if include_acknowledged:
            self.alerts.clear()
        else:
            self.alerts = [a for a in self.alerts if a.acknowledged]
            
        return count_before - len(self.alerts) 