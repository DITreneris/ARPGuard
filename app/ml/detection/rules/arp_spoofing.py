from typing import Dict, List, Any, Optional
from datetime import datetime
import time
from collections import defaultdict, deque

from ..rule_based import Rule, RuleResult

class ARPSpoofingRule(Rule):
    """Detect ARP spoofing attempts"""
    def __init__(self):
        super().__init__(
            rule_id="ARP_SPOOFING_001",
            description="Detects ARP spoofing attempts by monitoring ARP responses",
            severity="HIGH"
        )
        # Known legitimate IP-MAC mappings
        self.known_mappings = {}
        # Track when IP-MAC mappings were last seen
        self.last_seen = {}
        
    def evaluate(self, packet_data: Dict[str, Any]) -> Optional[RuleResult]:
        if packet_data.get("protocol") != "ARP":
            return None
            
        # Check for suspicious ARP responses
        if self._is_suspicious_arp_response(packet_data):
            return RuleResult(
                rule_id=self.rule_id,
                confidence=0.9,
                evidence={
                    "source_mac": packet_data.get("source_mac"),
                    "source_ip": packet_data.get("source_ip"),
                    "target_ip": packet_data.get("target_ip"),
                    "packet_type": packet_data.get("packet_type"),
                    "previous_mac": self.known_mappings.get(packet_data.get("source_ip"))
                },
                timestamp=datetime.now(),
                severity=self.severity
            )
        return None
        
    def _is_suspicious_arp_response(self, packet_data: Dict[str, Any]) -> bool:
        # Extract packet information
        source_mac = packet_data.get("source_mac")
        source_ip = packet_data.get("source_ip")
        packet_type = packet_data.get("packet_type")
        
        # Only interested in ARP replies
        if packet_type != "reply":
            return False
            
        # If this IP is seen for the first time, record it
        if source_ip not in self.known_mappings:
            self.known_mappings[source_ip] = source_mac
            self.last_seen[source_ip] = time.time()
            return False
            
        # If the IP-MAC mapping has changed, it's suspicious
        if self.known_mappings[source_ip] != source_mac:
            # Update the mapping
            self.known_mappings[source_ip] = source_mac
            self.last_seen[source_ip] = time.time()
            return True
            
        # Update last seen time
        self.last_seen[source_ip] = time.time()
        return False


class ARPGratuitousRule(Rule):
    """Detect gratuitous ARP packets"""
    def __init__(self):
        super().__init__(
            rule_id="ARP_GRATUITOUS_001",
            description="Detects suspicious gratuitous ARP packets",
            severity="MEDIUM"
        )
        # Track gratuitous ARP packet counts per source
        self.packet_counts = defaultdict(int)
        # Track when we last reset counts
        self.last_reset = time.time()
        # Rate threshold for gratuitous ARPs (packets per minute)
        self.rate_threshold = 10
        
    def evaluate(self, packet_data: Dict[str, Any]) -> Optional[RuleResult]:
        if packet_data.get("protocol") != "ARP":
            return None
            
        # Reset counts if it's been more than a minute
        current_time = time.time()
        if current_time - self.last_reset > 60:
            self.packet_counts = defaultdict(int)
            self.last_reset = current_time
            
        if self._is_suspicious_gratuitous(packet_data):
            source_mac = packet_data.get("source_mac")
            return RuleResult(
                rule_id=self.rule_id,
                confidence=0.7,
                evidence={
                    "source_mac": source_mac,
                    "source_ip": packet_data.get("source_ip"),
                    "packet_type": "gratuitous",
                    "count": self.packet_counts[source_mac]
                },
                timestamp=datetime.now(),
                severity=self.severity
            )
        return None
        
    def _is_suspicious_gratuitous(self, packet_data: Dict[str, Any]) -> bool:
        # Check if this is a gratuitous ARP
        if not self._is_gratuitous_arp(packet_data):
            return False
            
        # Increment the count for this source
        source_mac = packet_data.get("source_mac")
        self.packet_counts[source_mac] += 1
        
        # Check if the rate exceeds the threshold
        return self.packet_counts[source_mac] > self.rate_threshold
    
    def _is_gratuitous_arp(self, packet_data: Dict[str, Any]) -> bool:
        # A gratuitous ARP is a packet where source and target IP are the same
        # or target IP is broadcast
        source_ip = packet_data.get("source_ip")
        target_ip = packet_data.get("target_ip")
        
        return source_ip == target_ip or target_ip == "255.255.255.255"


class ARPFloodRule(Rule):
    """Detect ARP flooding attempts"""
    def __init__(self):
        super().__init__(
            rule_id="ARP_FLOOD_001",
            description="Detects ARP flooding attempts",
            severity="HIGH"
        )
        # Track packets per source MAC in the last second
        self.time_windows = defaultdict(lambda: deque(maxlen=100))
        # Threshold for ARP packets per second
        self.threshold = 20
        
    def evaluate(self, packet_data: Dict[str, Any]) -> Optional[RuleResult]:
        if packet_data.get("protocol") != "ARP":
            return None
            
        if self._is_arp_flood(packet_data):
            source_mac = packet_data.get("source_mac")
            packet_count = len(self.time_windows[source_mac])
            return RuleResult(
                rule_id=self.rule_id,
                confidence=0.8,
                evidence={
                    "source_mac": source_mac,
                    "packet_count": packet_count,
                    "time_window": "1 second",
                    "threshold": self.threshold
                },
                timestamp=datetime.now(),
                severity=self.severity
            )
        return None
        
    def _is_arp_flood(self, packet_data: Dict[str, Any]) -> bool:
        current_time = time.time()
        source_mac = packet_data.get("source_mac")
        
        # Add current packet timestamp to the window
        self.time_windows[source_mac].append(current_time)
        
        # Remove packets older than 1 second
        while (self.time_windows[source_mac] and 
               current_time - self.time_windows[source_mac][0] > 1.0):
            self.time_windows[source_mac].popleft()
            
        # Check if the number of packets exceeds the threshold
        return len(self.time_windows[source_mac]) > self.threshold 