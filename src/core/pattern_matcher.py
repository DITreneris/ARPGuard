import logging
import time
from typing import Dict, List, Optional, Set, Any, Tuple, Callable
from dataclasses import dataclass, field
import re

from src.core.pattern_database import Pattern, PatternDatabase, PatternFeature, PatternMatchType

logger = logging.getLogger(__name__)

@dataclass
class MatchResult:
    """Result of a pattern match"""
    pattern_id: str
    pattern_name: str
    score: float
    matched_features: List[str]
    total_features: int
    timestamp: float = field(default_factory=time.time)
    details: Dict[str, Any] = field(default_factory=dict)


class FeatureExtractor:
    """Extracts features from ARP packets for pattern matching"""
    
    def __init__(self):
        """Initialize feature extractor"""
        # Map of feature name to extractor function
        self.extractors: Dict[str, Callable] = {
            # Basic packet features
            "is_at_request": self._extract_is_at_request,
            "is_gratuitous": self._extract_is_gratuitous,
            "sender_is_gateway_ip": self._extract_sender_is_gateway_ip,
            "target_is_gateway": self._extract_target_is_gateway,
            "gateway_mac_changed": self._extract_gateway_mac_changed,
            
            # Rate-based features
            "packet_rate_high": self._extract_packet_rate_high,
            "multiple_targets": self._extract_multiple_targets,
            "random_mac_addresses": self._extract_random_mac_addresses,
            "rapid_changes": self._extract_rapid_changes
        }
    
    def extract_features(self, packet_data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract features from packet data and context.
        
        Args:
            packet_data: Packet data dictionary
            context: Context information
            
        Returns:
            Dictionary of extracted features
        """
        features = {}
        
        # Extract each feature
        for feature_name, extractor in self.extractors.items():
            try:
                features[feature_name] = extractor(packet_data, context)
            except Exception as e:
                logger.warning(f"Error extracting feature {feature_name}: {e}")
                features[feature_name] = None
        
        return features
    
    # Feature extractor methods
    
    def _extract_is_at_request(self, packet: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Check if packet is an ARP 'who-has' request"""
        return packet.get("arp_operation", 0) == 1  # ARP request
    
    def _extract_is_gratuitous(self, packet: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Check if packet is a gratuitous ARP"""
        # Gratuitous ARP is typically a broadcast where sender IP = target IP
        return (
            packet.get("arp_operation", 0) == 2 and  # ARP reply
            packet.get("sender_ip") == packet.get("target_ip")
        )
    
    def _extract_sender_is_gateway_ip(self, packet: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Check if sender IP is gateway IP"""
        gateway_ip = context.get("gateway_ip")
        if not gateway_ip:
            return False
        
        return packet.get("sender_ip") == gateway_ip
    
    def _extract_target_is_gateway(self, packet: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Check if target is gateway"""
        gateway_ip = context.get("gateway_ip")
        gateway_mac = context.get("gateway_mac")
        
        if not gateway_ip or not gateway_mac:
            return False
        
        return (
            packet.get("target_ip") == gateway_ip or
            packet.get("target_mac") == gateway_mac
        )
    
    def _extract_gateway_mac_changed(self, packet: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Check if gateway MAC has changed"""
        gateway_ip = context.get("gateway_ip")
        gateway_mac = context.get("gateway_mac")
        
        if not gateway_ip or not gateway_mac:
            return False
        
        # Check if this is an announcement for gateway IP with different MAC
        return (
            packet.get("arp_operation", 0) == 2 and  # ARP reply
            packet.get("sender_ip") == gateway_ip and
            packet.get("sender_mac") != gateway_mac
        )
    
    def _extract_packet_rate_high(self, packet: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Check if packet rate is high"""
        # Get packet rate from context
        packet_rate = context.get("packet_rate", 0)
        threshold = context.get("high_rate_threshold", 100)  # Default 100 pps
        
        return packet_rate > threshold
    
    def _extract_multiple_targets(self, packet: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Check if multiple targets are being addressed"""
        # Get unique targets from recent packets
        recent_targets = context.get("recent_targets", set())
        threshold = context.get("multiple_targets_threshold", 5)
        
        return len(recent_targets) > threshold
    
    def _extract_random_mac_addresses(self, packet: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Check if random MAC addresses are being used"""
        # Get list of MAC prefixes (OUIs) from recent packets
        recent_ouis = context.get("recent_ouis", set())
        threshold = context.get("random_mac_threshold", 3)
        
        return len(recent_ouis) > threshold
    
    def _extract_rapid_changes(self, packet: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Check if MAC-IP mappings are changing rapidly"""
        # Get count of MAC-IP mapping changes
        mapping_changes = context.get("mapping_changes", 0)
        threshold = context.get("rapid_changes_threshold", 3)
        
        return mapping_changes > threshold


class PatternMatcher:
    """
    Matches packet sequences against known attack patterns.
    """
    
    def __init__(self, pattern_database: PatternDatabase):
        """
        Initialize pattern matcher.
        
        Args:
            pattern_database: Pattern database to use for matching
        """
        self.pattern_database = pattern_database
        self.feature_extractor = FeatureExtractor()
        self.context: Dict[str, Any] = {
            "gateway_ip": None,
            "gateway_mac": None,
            "recent_packets": [],
            "recent_targets": set(),
            "recent_ouis": set(),
            "mapping_changes": 0,
            "packet_rate": 0,
            "high_rate_threshold": 100,
            "multiple_targets_threshold": 5,
            "random_mac_threshold": 3,
            "rapid_changes_threshold": 3
        }
    
    def update_context(self, key: str, value: Any) -> None:
        """
        Update context with new value.
        
        Args:
            key: Context key
            value: Context value
        """
        self.context[key] = value
    
    def process_packet(self, packet_data: Dict[str, Any]) -> List[MatchResult]:
        """
        Process a packet and check for pattern matches.
        
        Args:
            packet_data: Packet data dictionary
            
        Returns:
            List of MatchResult objects for matching patterns
        """
        # Update context with packet information
        self._update_context_from_packet(packet_data)
        
        # Extract features
        features = self.feature_extractor.extract_features(packet_data, self.context)
        
        # Match against patterns
        match_results = self._match_features(features)
        
        return match_results
    
    def process_packet_sequence(self, packet_sequence: List[Dict[str, Any]]) -> List[MatchResult]:
        """
        Process a sequence of packets and check for pattern matches.
        
        Args:
            packet_sequence: List of packet data dictionaries
            
        Returns:
            List of MatchResult objects for matching patterns
        """
        match_results = []
        
        # Process each packet
        for packet_data in packet_sequence:
            results = self.process_packet(packet_data)
            match_results.extend(results)
        
        return match_results
    
    def _update_context_from_packet(self, packet_data: Dict[str, Any]) -> None:
        """
        Update context information based on packet data.
        
        Args:
            packet_data: Packet data dictionary
        """
        # Add to recent packets (keep last 100)
        self.context["recent_packets"] = (
            self.context["recent_packets"][-99:] + [packet_data]
            if "recent_packets" in self.context
            else [packet_data]
        )
        
        # Update recent targets
        if "target_ip" in packet_data:
            if "recent_targets" not in self.context:
                self.context["recent_targets"] = set()
            self.context["recent_targets"].add(packet_data["target_ip"])
            
            # Keep set size manageable
            if len(self.context["recent_targets"]) > 100:
                self.context["recent_targets"] = set(list(self.context["recent_targets"])[-100:])
        
        # Update recent OUIs (first 6 chars of MAC)
        if "sender_mac" in packet_data:
            sender_mac = packet_data["sender_mac"]
            if sender_mac and len(sender_mac) >= 8:  # xx:xx:xx format
                oui = sender_mac[:8]
                if "recent_ouis" not in self.context:
                    self.context["recent_ouis"] = set()
                self.context["recent_ouis"].add(oui)
                
                # Keep set size manageable
                if len(self.context["recent_ouis"]) > 50:
                    self.context["recent_ouis"] = set(list(self.context["recent_ouis"])[-50:])
        
        # Track MAC-IP mapping changes
        if "sender_ip" in packet_data and "sender_mac" in packet_data:
            ip = packet_data["sender_ip"]
            mac = packet_data["sender_mac"]
            
            # Initialize the mapping dict if it doesn't exist
            if "ip_to_mac" not in self.context:
                self.context["ip_to_mac"] = {}
            
            # Check if mapping has changed
            if ip in self.context["ip_to_mac"] and self.context["ip_to_mac"][ip] != mac:
                mapping_changes = self.context.get("mapping_changes", 0)
                self.context["mapping_changes"] = mapping_changes + 1
            
            # Update mapping
            self.context["ip_to_mac"][ip] = mac
    
    def _match_features(self, features: Dict[str, Any]) -> List[MatchResult]:
        """
        Match features against patterns.
        
        Args:
            features: Dictionary of extracted features
            
        Returns:
            List of MatchResult objects for matching patterns
        """
        match_results = []
        
        # Get all patterns
        patterns = self.pattern_database.get_all_patterns()
        
        # Match each pattern
        for pattern in patterns:
            match_result = self._match_pattern(pattern, features)
            if match_result:
                match_results.append(match_result)
        
        return match_results
    
    def _match_pattern(self, pattern: Pattern, features: Dict[str, Any]) -> Optional[MatchResult]:
        """
        Match a pattern against features.
        
        Args:
            pattern: Pattern to match
            features: Dictionary of extracted features
            
        Returns:
            MatchResult if pattern matches, None otherwise
        """
        matched_features = []
        total_weight = 0
        matched_weight = 0
        
        # Check each pattern feature
        for pattern_feature in pattern.features:
            feature_name = pattern_feature.name
            expected_value = pattern_feature.value
            match_type = pattern_feature.match_type
            weight = pattern_feature.weight
            
            # Skip if feature not extracted
            if feature_name not in features or features[feature_name] is None:
                continue
            
            actual_value = features[feature_name]
            total_weight += weight
            
            # Check if feature matches based on match type
            if self._match_feature_value(actual_value, expected_value, match_type):
                matched_features.append(feature_name)
                matched_weight += weight
        
        # Calculate match score
        score = matched_weight / total_weight if total_weight > 0 else 0
        
        # Check if score exceeds confidence threshold
        if score >= pattern.confidence:
            return MatchResult(
                pattern_id=pattern.id,
                pattern_name=pattern.name,
                score=score,
                matched_features=matched_features,
                total_features=len(pattern.features),
                details={
                    "category": pattern.category.name,
                    "severity": pattern.severity,
                    "confidence_threshold": pattern.confidence
                }
            )
        
        return None
    
    def _match_feature_value(self, actual_value: Any, expected_value: Any, match_type: PatternMatchType) -> bool:
        """
        Match a feature value based on match type.
        
        Args:
            actual_value: Actual feature value
            expected_value: Expected feature value
            match_type: Type of match to perform
            
        Returns:
            True if values match according to match type, False otherwise
        """
        if match_type == PatternMatchType.EXACT:
            return actual_value == expected_value
            
        elif match_type == PatternMatchType.PARTIAL:
            # For lists, sets, dicts - check if expected is subset of actual
            if isinstance(expected_value, (list, set)):
                actual_set = set(actual_value) if isinstance(actual_value, (list, set)) else {actual_value}
                expected_set = set(expected_value)
                return expected_set.issubset(actual_set)
                
            elif isinstance(expected_value, dict):
                return all(k in actual_value and actual_value[k] == v for k, v in expected_value.items())
                
            # For strings, check if expected is substring of actual
            elif isinstance(expected_value, str) and isinstance(actual_value, str):
                return expected_value in actual_value
                
            # Default to exact match for other types
            return actual_value == expected_value
            
        elif match_type == PatternMatchType.FUZZY:
            # For numeric values, check if within 10% of expected
            if isinstance(actual_value, (int, float)) and isinstance(expected_value, (int, float)):
                return abs(actual_value - expected_value) <= 0.1 * abs(expected_value)
                
            # For strings, check if similarity ratio > 0.8
            elif isinstance(actual_value, str) and isinstance(expected_value, str):
                # Simple similarity: shared / total chars (could use more advanced methods)
                longer = actual_value if len(actual_value) > len(expected_value) else expected_value
                shorter = actual_value if len(actual_value) <= len(expected_value) else expected_value
                
                if len(longer) == 0:
                    return True  # Both empty strings
                    
                # Count shared characters (case insensitive)
                actual_lower = actual_value.lower()
                expected_lower = expected_value.lower()
                
                shared_chars = sum(min(actual_lower.count(c), expected_lower.count(c)) for c in set(shorter.lower()))
                
                similarity = shared_chars / len(longer)
                return similarity >= 0.8
                
            # Default to exact match for other types
            return actual_value == expected_value
            
        elif match_type == PatternMatchType.REGEX:
            # For strings, apply regex pattern
            if isinstance(expected_value, str) and isinstance(actual_value, str):
                try:
                    return bool(re.match(expected_value, actual_value))
                except re.error:
                    logger.warning(f"Invalid regex pattern: {expected_value}")
                    return False
                    
            # Default to exact match for other types
            return actual_value == expected_value
            
        # Default to exact match for unknown match type
        return actual_value == expected_value 