"""
Rule-based detection engine for ARPGuard.

This module implements a rule engine for detecting ARP-based attacks
using predefined rules and thresholds.
"""

import re
import yaml
import json
import os
from datetime import datetime
from threading import Lock
from typing import Dict, List, Any, Optional, Tuple, Union, Callable

from app.utils.logger import get_logger
from app.utils.config import get_config

# Setup module logger
logger = get_logger("ml.rule_engine")

class Rule:
    """Represents a detection rule."""
    
    def __init__(
        self, 
        rule_id: str, 
        description: str,
        condition: str,
        severity: str = "MEDIUM",
        enabled: bool = True,
        threshold: float = 0.7,
        cooldown: int = 60,
        tags: List[str] = None
    ):
        """Initialize a new rule.
        
        Args:
            rule_id: Unique identifier for the rule
            description: Description of what the rule detects
            condition: String representation of the rule condition
            severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
            enabled: Whether the rule is enabled
            threshold: Confidence threshold for triggering the rule
            cooldown: Cooldown period in seconds before rule can trigger again
            tags: List of tags for categorizing rules
        """
        self.rule_id = rule_id
        self.description = description
        self.condition = condition
        self.severity = severity
        self.enabled = enabled
        self.threshold = threshold
        self.cooldown = cooldown
        self.tags = tags or []
        self.last_triggered = None
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary.
        
        Returns:
            Dictionary representation of the rule
        """
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "condition": self.condition,
            "severity": self.severity,
            "enabled": self.enabled,
            "threshold": self.threshold,
            "cooldown": self.cooldown,
            "tags": self.tags,
            "last_triggered": self.last_triggered.isoformat() if self.last_triggered else None
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Rule':
        """Create a rule from dictionary data.
        
        Args:
            data: Dictionary containing rule data
            
        Returns:
            New Rule instance
        """
        rule = cls(
            rule_id=data["rule_id"],
            description=data["description"],
            condition=data["condition"],
            severity=data.get("severity", "MEDIUM"),
            enabled=data.get("enabled", True),
            threshold=data.get("threshold", 0.7),
            cooldown=data.get("cooldown", 60),
            tags=data.get("tags", [])
        )
        
        if data.get("last_triggered"):
            rule.last_triggered = datetime.fromisoformat(data["last_triggered"])
            
        return rule


class RuleEngine:
    """Engine for rule-based threat detection."""
    
    def __init__(self):
        """Initialize the rule engine."""
        self.rules = {}  # Maps rule_id to Rule instance
        self.lock = Lock()
        self.config = get_config()
        self.stats = {
            "rule_hits": {},
            "total_evaluations": 0,
            "total_detections": 0
        }
        
        # Load default rules
        self._load_default_rules()
        
    def _load_default_rules(self):
        """Load default rules from configuration."""
        try:
            # Define path to rules configuration
            config_path = self.config.get(
                "rules.config_path", 
                os.path.join("data", "rules_config.yaml")
            )
            
            if os.path.exists(config_path):
                logger.info(f"Loading rules from {config_path}")
                with open(config_path, 'r') as f:
                    rules_config = yaml.safe_load(f)
                
                for rule_id, rule_data in rules_config.get("rules", {}).items():
                    rule = Rule(
                        rule_id=rule_id,
                        description=rule_data.get("description", "No description"),
                        condition=rule_data.get("condition", ""),
                        severity=rule_data.get("severity", "MEDIUM"),
                        enabled=rule_data.get("enabled", True),
                        threshold=rule_data.get("threshold", 0.7),
                        cooldown=rule_data.get("cooldown", 60),
                        tags=rule_data.get("tags", [])
                    )
                    self.add_rule(rule)
                    
                logger.info(f"Loaded {len(self.rules)} rules from configuration")
            else:
                logger.warning(f"Rules configuration file not found at {config_path}")
                # Create some default rules
                self._create_default_rules()
        except Exception as e:
            logger.error(f"Error loading rules: {e}")
            # Create default rules on error
            self._create_default_rules()
    
    def _create_default_rules(self):
        """Create default detection rules."""
        # ARP spoofing detection
        self.add_rule(Rule(
            rule_id="ARP_SPOOFING_001",
            description="ARP spoofing - MAC address changed for existing IP",
            condition="packet.op == 2 and check_mac_change(packet.src_ip, packet.src_mac)",
            severity="HIGH",
            threshold=0.8
        ))
        
        # Gratuitous ARP detection
        self.add_rule(Rule(
            rule_id="ARP_GRATUITOUS_001",
            description="Suspicious gratuitous ARP packet",
            condition="packet.op == 2 and packet.src_ip == packet.dst_ip",
            severity="MEDIUM",
            threshold=0.7
        ))
        
        # ARP flood detection
        self.add_rule(Rule(
            rule_id="ARP_FLOOD_001",
            description="ARP request flood from single source",
            condition="packet.op == 1 and count_packets(packet.src_mac, window=5) > 20",
            severity="CRITICAL",
            threshold=0.9
        ))
        
        # ARP poisoning detection
        self.add_rule(Rule(
            rule_id="ARP_POISONING_001",
            description="ARP cache poisoning attempt",
            condition="packet.op == 2 and is_gateway(packet.src_ip) and not is_valid_gateway_mac(packet.src_mac)",
            severity="CRITICAL",
            threshold=0.9
        ))
        
        # Man in the middle detection
        self.add_rule(Rule(
            rule_id="ARP_MITM_001",
            description="Potential Man-in-the-Middle attack",
            condition="packet.op == 2 and has_multiple_ips_same_mac(packet.src_mac)",
            severity="HIGH",
            threshold=0.85
        ))
        
        logger.info(f"Created {len(self.rules)} default rules")
        
    def add_rule(self, rule: Rule) -> bool:
        """Add a new rule to the engine.
        
        Args:
            rule: Rule instance to add
            
        Returns:
            True if rule was added, False otherwise
        """
        with self.lock:
            if rule.rule_id in self.rules:
                logger.warning(f"Rule {rule.rule_id} already exists")
                return False
                
            self.rules[rule.rule_id] = rule
            logger.info(f"Added rule {rule.rule_id}")
            return True
            
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule from the engine.
        
        Args:
            rule_id: ID of the rule to remove
            
        Returns:
            True if rule was removed, False otherwise
        """
        with self.lock:
            if rule_id not in self.rules:
                logger.warning(f"Rule {rule_id} does not exist")
                return False
                
            del self.rules[rule_id]
            logger.info(f"Removed rule {rule_id}")
            return True
            
    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule.
        
        Args:
            rule_id: ID of the rule to enable
            
        Returns:
            True if rule was enabled, False otherwise
        """
        with self.lock:
            if rule_id not in self.rules:
                logger.warning(f"Rule {rule_id} does not exist")
                return False
                
            self.rules[rule_id].enabled = True
            logger.info(f"Enabled rule {rule_id}")
            return True
            
    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule.
        
        Args:
            rule_id: ID of the rule to disable
            
        Returns:
            True if rule was disabled, False otherwise
        """
        with self.lock:
            if rule_id not in self.rules:
                logger.warning(f"Rule {rule_id} does not exist")
                return False
                
            self.rules[rule_id].enabled = False
            logger.info(f"Disabled rule {rule_id}")
            return True
            
    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """Get a rule by ID.
        
        Args:
            rule_id: ID of the rule to get
            
        Returns:
            Rule instance or None if not found
        """
        with self.lock:
            return self.rules.get(rule_id)
            
    def evaluate_packet(self, packet: Dict[str, Any], context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate a packet against all enabled rules.
        
        Args:
            packet: Packet data
            context: Additional context data for rule evaluation
            
        Returns:
            List of detection results
        """
        results = []
        
        with self.lock:
            # Update stats
            self.stats["total_evaluations"] += 1
            
            # Evaluate each enabled rule
            for rule_id, rule in self.rules.items():
                if not rule.enabled:
                    continue
                    
                # Check cooldown
                if rule.last_triggered and (datetime.now() - rule.last_triggered).total_seconds() < rule.cooldown:
                    continue
                    
                # Evaluate rule condition
                try:
                    detection, confidence, evidence = self._evaluate_condition(rule.condition, packet, context)
                    
                    if detection and confidence >= rule.threshold:
                        # Update rule stats
                        self.stats["rule_hits"][rule_id] = self.stats["rule_hits"].get(rule_id, 0) + 1
                        self.stats["total_detections"] += 1
                        
                        # Update last triggered time
                        rule.last_triggered = datetime.now()
                        
                        # Create detection result
                        result = {
                            "type": "rule_based",
                            "rule_id": rule_id,
                            "description": rule.description,
                            "severity": rule.severity,
                            "confidence": confidence,
                            "timestamp": datetime.now(),
                            "evidence": evidence
                        }
                        
                        results.append(result)
                        logger.info(f"Rule {rule_id} triggered with confidence {confidence:.2f}")
                except Exception as e:
                    logger.error(f"Error evaluating rule {rule_id}: {e}")
                    
        return results
        
    def _evaluate_condition(
        self, 
        condition: str, 
        packet: Dict[str, Any], 
        context: Dict[str, Any]
    ) -> Tuple[bool, float, Dict[str, Any]]:
        """Evaluate a rule condition.
        
        Args:
            condition: Rule condition string
            packet: Packet data
            context: Additional context data
            
        Returns:
            Tuple of (detection_result, confidence, evidence)
        """
        # For simple implementation, we'll use a pattern matching approach
        evidence = {}
        confidence = 0.0
        detection = False
        
        # Check for ARP spoofing
        if "check_mac_change" in condition and "packet.op == 2" in condition:
            if packet.get("op") == 2:  # ARP reply
                ip = packet.get("src_ip")
                mac = packet.get("src_mac")
                
                # Get previous MAC for this IP if it exists
                prev_mac = context.get("ip_mac_map", {}).get(ip)
                
                if prev_mac and prev_mac != mac:
                    detection = True
                    confidence = 0.9
                    evidence = {
                        "src_ip": ip,
                        "new_mac": mac,
                        "old_mac": prev_mac,
                        "reason": "MAC address changed for existing IP"
                    }
        
        # Check for gratuitous ARP
        elif "packet.op == 2 and packet.src_ip == packet.dst_ip" in condition:
            if packet.get("op") == 2 and packet.get("src_ip") == packet.get("dst_ip"):
                detection = True
                confidence = 0.8
                evidence = {
                    "src_ip": packet.get("src_ip"),
                    "src_mac": packet.get("src_mac"),
                    "reason": "Gratuitous ARP packet detected"
                }
                
        # Check for ARP flood
        elif "count_packets" in condition and "packet.op == 1" in condition:
            if packet.get("op") == 1:  # ARP request
                mac = packet.get("src_mac")
                
                # Get packet count for this MAC
                packet_counts = context.get("packet_counts", {})
                mac_count = packet_counts.get(mac, 0)
                
                if mac_count > 20:
                    detection = True
                    confidence = 0.85
                    evidence = {
                        "src_mac": mac,
                        "packet_count": mac_count,
                        "reason": "High number of ARP requests from single source"
                    }
                    
        # Check for ARP poisoning
        elif "is_gateway" in condition and "is_valid_gateway_mac" in condition:
            ip = packet.get("src_ip")
            mac = packet.get("src_mac")
            
            # Check if IP is gateway
            gateway_ip = context.get("gateway_ip")
            known_gateway_mac = context.get("gateway_mac")
            
            if gateway_ip and ip == gateway_ip and known_gateway_mac and mac != known_gateway_mac:
                detection = True
                confidence = 0.95
                evidence = {
                    "gateway_ip": gateway_ip,
                    "expected_mac": known_gateway_mac,
                    "received_mac": mac,
                    "reason": "Gateway impersonation detected"
                }
                
        # Check for MITM
        elif "has_multiple_ips_same_mac" in condition:
            mac = packet.get("src_mac")
            ip = packet.get("src_ip")
            
            # Get IP count for this MAC
            mac_ip_map = context.get("mac_ip_map", {})
            ips_for_mac = mac_ip_map.get(mac, [])
            
            if len(ips_for_mac) > 1 and ip in ips_for_mac:
                detection = True
                confidence = 0.85
                evidence = {
                    "src_mac": mac,
                    "src_ip": ip,
                    "all_ips": ips_for_mac,
                    "reason": "MAC address associated with multiple IPs"
                }
                
        return detection, confidence, evidence
        
    def get_active_rules_count(self) -> int:
        """Get count of active rules.
        
        Returns:
            Number of active rules
        """
        with self.lock:
            return sum(1 for rule in self.rules.values() if rule.enabled)
            
    def get_statistics(self) -> Dict[str, Any]:
        """Get rule engine statistics.
        
        Returns:
            Dictionary of statistics
        """
        with self.lock:
            return {
                "rules_active": self.get_active_rules_count(),
                "rules_total": len(self.rules),
                "rule_hits": dict(self.stats["rule_hits"]),
                "total_evaluations": self.stats["total_evaluations"],
                "total_detections": self.stats["total_detections"]
            }
            
    def save_rules(self, filepath: str) -> bool:
        """Save rules to a file.
        
        Args:
            filepath: Path to save rules to
            
        Returns:
            True if rules were saved, False otherwise
        """
        try:
            rules_dict = {
                "rules": {
                    rule_id: rule.to_dict() 
                    for rule_id, rule in self.rules.items()
                }
            }
            
            # Make directory if it doesn't exist
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            # Save as YAML
            with open(filepath, 'w') as f:
                yaml.dump(rules_dict, f, default_flow_style=False)
                
            logger.info(f"Saved {len(self.rules)} rules to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Error saving rules: {e}")
            return False
            
    def load_rules(self, filepath: str) -> bool:
        """Load rules from a file.
        
        Args:
            filepath: Path to load rules from
            
        Returns:
            True if rules were loaded, False otherwise
        """
        try:
            if not os.path.exists(filepath):
                logger.warning(f"Rules file not found: {filepath}")
                return False
                
            with open(filepath, 'r') as f:
                rules_dict = yaml.safe_load(f)
                
            with self.lock:
                self.rules = {}
                
                for rule_id, rule_data in rules_dict.get("rules", {}).items():
                    rule = Rule.from_dict(rule_data)
                    self.rules[rule_id] = rule
                    
            logger.info(f"Loaded {len(self.rules)} rules from {filepath}")
            return True
        except Exception as e:
            logger.error(f"Error loading rules: {e}")
            return False 