"""
Test cases for the rule-based detection system.
"""

import unittest
from unittest.mock import MagicMock, patch
import sys
import os
import time
from datetime import datetime
from typing import Dict, Any, List

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ml.rule_engine import Rule, RuleEngine
from app.ml.context_tracker import ContextTracker
from app.ml.packet_converter import convert_arp_packet


class TestRule(unittest.TestCase):
    """Test cases for the Rule class."""
    
    def test_rule_initialization(self):
        """Test Rule initialization."""
        rule = Rule(
            rule_id="TEST_RULE_001",
            description="Test rule",
            condition="packet.op == 2 and packet.src_ip == packet.dst_ip",
            severity="HIGH",
            enabled=True,
            threshold=0.8,
            cooldown=60,
            tags=["test", "rule"]
        )
        
        self.assertEqual(rule.rule_id, "TEST_RULE_001")
        self.assertEqual(rule.description, "Test rule")
        self.assertEqual(rule.condition, "packet.op == 2 and packet.src_ip == packet.dst_ip")
        self.assertEqual(rule.severity, "HIGH")
        self.assertTrue(rule.enabled)
        self.assertEqual(rule.threshold, 0.8)
        self.assertEqual(rule.cooldown, 60)
        self.assertEqual(rule.tags, ["test", "rule"])
        self.assertIsNone(rule.last_triggered)
        
    def test_rule_to_dict(self):
        """Test converting Rule to dictionary."""
        rule = Rule(
            rule_id="TEST_RULE_001",
            description="Test rule",
            condition="packet.op == 2 and packet.src_ip == packet.dst_ip",
            severity="HIGH",
            enabled=True,
            threshold=0.8,
            cooldown=60,
            tags=["test", "rule"]
        )
        
        rule_dict = rule.to_dict()
        
        self.assertEqual(rule_dict["rule_id"], "TEST_RULE_001")
        self.assertEqual(rule_dict["description"], "Test rule")
        self.assertEqual(rule_dict["condition"], "packet.op == 2 and packet.src_ip == packet.dst_ip")
        self.assertEqual(rule_dict["severity"], "HIGH")
        self.assertTrue(rule_dict["enabled"])
        self.assertEqual(rule_dict["threshold"], 0.8)
        self.assertEqual(rule_dict["cooldown"], 60)
        self.assertEqual(rule_dict["tags"], ["test", "rule"])
        self.assertIsNone(rule_dict["last_triggered"])
        
    def test_rule_from_dict(self):
        """Test creating Rule from dictionary."""
        rule_dict = {
            "rule_id": "TEST_RULE_001",
            "description": "Test rule",
            "condition": "packet.op == 2 and packet.src_ip == packet.dst_ip",
            "severity": "HIGH",
            "enabled": True,
            "threshold": 0.8,
            "cooldown": 60,
            "tags": ["test", "rule"]
        }
        
        rule = Rule.from_dict(rule_dict)
        
        self.assertEqual(rule.rule_id, "TEST_RULE_001")
        self.assertEqual(rule.description, "Test rule")
        self.assertEqual(rule.condition, "packet.op == 2 and packet.src_ip == packet.dst_ip")
        self.assertEqual(rule.severity, "HIGH")
        self.assertTrue(rule.enabled)
        self.assertEqual(rule.threshold, 0.8)
        self.assertEqual(rule.cooldown, 60)
        self.assertEqual(rule.tags, ["test", "rule"])
        self.assertIsNone(rule.last_triggered)


class TestRuleEngine(unittest.TestCase):
    """Test cases for the RuleEngine class."""
    
    def setUp(self):
        """Set up test environment."""
        # Create a RuleEngine with mocked config
        with patch("app.ml.rule_engine.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_get_config.return_value = mock_config
            self.rule_engine = RuleEngine()
            
        # Clear existing rules and add test rules
        self.rule_engine.rules = {}
        
        # Add test rules
        self.rule_engine.add_rule(Rule(
            rule_id="TEST_GRATUITOUS_ARP",
            description="Test gratuitous ARP detection",
            condition="packet.op == 2 and packet.src_ip == packet.dst_ip",
            severity="MEDIUM",
            enabled=True,
            threshold=0.7
        ))
        
        self.rule_engine.add_rule(Rule(
            rule_id="TEST_ARP_SPOOF",
            description="Test ARP spoofing detection",
            condition="packet.op == 2 and check_mac_change(packet.src_ip, packet.src_mac)",
            severity="HIGH",
            enabled=True,
            threshold=0.8
        ))
        
    def test_add_rule(self):
        """Test adding a rule."""
        # Add a new rule
        result = self.rule_engine.add_rule(Rule(
            rule_id="TEST_NEW_RULE",
            description="Test new rule",
            condition="packet.op == 1",
            severity="LOW"
        ))
        
        self.assertTrue(result)
        self.assertIn("TEST_NEW_RULE", self.rule_engine.rules)
        
        # Try adding a rule with existing ID
        result = self.rule_engine.add_rule(Rule(
            rule_id="TEST_NEW_RULE",
            description="Duplicate rule",
            condition="packet.op == 1",
            severity="LOW"
        ))
        
        self.assertFalse(result)
        
    def test_remove_rule(self):
        """Test removing a rule."""
        # Remove an existing rule
        result = self.rule_engine.remove_rule("TEST_GRATUITOUS_ARP")
        
        self.assertTrue(result)
        self.assertNotIn("TEST_GRATUITOUS_ARP", self.rule_engine.rules)
        
        # Try removing a non-existent rule
        result = self.rule_engine.remove_rule("NON_EXISTENT_RULE")
        
        self.assertFalse(result)
        
    def test_enable_disable_rule(self):
        """Test enabling and disabling a rule."""
        # Disable a rule
        result = self.rule_engine.disable_rule("TEST_GRATUITOUS_ARP")
        
        self.assertTrue(result)
        self.assertFalse(self.rule_engine.rules["TEST_GRATUITOUS_ARP"].enabled)
        
        # Enable a rule
        result = self.rule_engine.enable_rule("TEST_GRATUITOUS_ARP")
        
        self.assertTrue(result)
        self.assertTrue(self.rule_engine.rules["TEST_GRATUITOUS_ARP"].enabled)
        
        # Try enabling a non-existent rule
        result = self.rule_engine.enable_rule("NON_EXISTENT_RULE")
        
        self.assertFalse(result)
        
    def test_get_rule(self):
        """Test getting a rule by ID."""
        # Get an existing rule
        rule = self.rule_engine.get_rule("TEST_GRATUITOUS_ARP")
        
        self.assertIsNotNone(rule)
        self.assertEqual(rule.rule_id, "TEST_GRATUITOUS_ARP")
        
        # Try getting a non-existent rule
        rule = self.rule_engine.get_rule("NON_EXISTENT_RULE")
        
        self.assertIsNone(rule)
        
    def test_evaluate_packet_gratuitous_arp(self):
        """Test evaluating a packet that matches the gratuitous ARP rule."""
        # Create a packet that matches the gratuitous ARP rule
        packet = {
            "type": "arp",
            "op": 2,  # ARP reply
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.1",  # Same as src_ip (gratuitous)
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "ff:ff:ff:ff:ff:ff"
        }
        
        # Create context
        context = {
            "ip_mac_map": {},
            "mac_ip_map": {},
            "packet_counts": {}
        }
        
        # Evaluate packet
        results = self.rule_engine.evaluate_packet(packet, context)
        
        # Check results
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["rule_id"], "TEST_GRATUITOUS_ARP")
        self.assertEqual(results[0]["type"], "rule_based")
        self.assertEqual(results[0]["severity"], "MEDIUM")
        self.assertGreaterEqual(results[0]["confidence"], 0.7)
        
    def test_evaluate_packet_arp_spoof(self):
        """Test evaluating a packet that matches the ARP spoofing rule."""
        # Create context with existing IP-MAC mapping
        context = {
            "ip_mac_map": {
                "192.168.1.1": "00:11:22:33:44:55"
            },
            "mac_ip_map": {
                "00:11:22:33:44:55": ["192.168.1.1"]
            },
            "packet_counts": {}
        }
        
        # Create a packet with different MAC for same IP
        packet = {
            "type": "arp",
            "op": 2,  # ARP reply
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.100",
            "src_mac": "aa:bb:cc:dd:ee:ff",  # Different from stored MAC
            "dst_mac": "00:00:00:00:00:00"
        }
        
        # Evaluate packet
        results = self.rule_engine.evaluate_packet(packet, context)
        
        # Check results
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["rule_id"], "TEST_ARP_SPOOF")
        self.assertEqual(results[0]["type"], "rule_based")
        self.assertEqual(results[0]["severity"], "HIGH")
        self.assertGreaterEqual(results[0]["confidence"], 0.8)
        
    def test_evaluate_packet_no_match(self):
        """Test evaluating a packet that doesn't match any rules."""
        # Create a packet that doesn't match any rules
        packet = {
            "type": "arp",
            "op": 1,  # ARP request
            "src_ip": "192.168.1.100",
            "dst_ip": "192.168.1.1",
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "ff:ff:ff:ff:ff:ff"
        }
        
        # Create context
        context = {
            "ip_mac_map": {},
            "mac_ip_map": {},
            "packet_counts": {}
        }
        
        # Evaluate packet
        results = self.rule_engine.evaluate_packet(packet, context)
        
        # Check results
        self.assertEqual(len(results), 0)
        
    def test_get_statistics(self):
        """Test getting statistics from the rule engine."""
        # Set up initial stats
        self.rule_engine.stats = {
            "rule_hits": {"TEST_GRATUITOUS_ARP": 5, "TEST_ARP_SPOOF": 2},
            "total_evaluations": 100,
            "total_detections": 7
        }
        
        # Get statistics
        stats = self.rule_engine.get_statistics()
        
        # Check stats
        self.assertEqual(stats["rules_active"], 2)
        self.assertEqual(stats["rules_total"], 2)
        self.assertEqual(stats["rule_hits"]["TEST_GRATUITOUS_ARP"], 5)
        self.assertEqual(stats["rule_hits"]["TEST_ARP_SPOOF"], 2)
        self.assertEqual(stats["total_evaluations"], 100)
        self.assertEqual(stats["total_detections"], 7)


class TestContextTracker(unittest.TestCase):
    """Test cases for the ContextTracker class."""
    
    def setUp(self):
        """Set up test environment."""
        self.context_tracker = ContextTracker(history_window=60)
        
    def test_update_and_get_context(self):
        """Test updating context and getting it back."""
        # Create a packet
        packet = {
            "type": "arp",
            "op": 2,
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.100",
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "aa:bb:cc:dd:ee:ff",
            "timestamp": datetime.now()
        }
        
        # Update context with packet
        self.context_tracker.update(packet)
        
        # Get context
        context = self.context_tracker.get_context()
        
        # Check context
        self.assertEqual(context["ip_mac_map"]["192.168.1.1"], "00:11:22:33:44:55")
        self.assertIn("192.168.1.1", context["mac_ip_map"]["00:11:22:33:44:55"])
        
    def test_multiple_ips_same_mac(self):
        """Test detecting multiple IPs associated with the same MAC."""
        # Create packets with same MAC but different IPs
        packet1 = {
            "type": "arp",
            "op": 2,
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.100",
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "aa:bb:cc:dd:ee:ff",
            "timestamp": datetime.now()
        }
        
        packet2 = {
            "type": "arp",
            "op": 2,
            "src_ip": "192.168.1.2",
            "dst_ip": "192.168.1.100",
            "src_mac": "00:11:22:33:44:55",  # Same MAC
            "dst_mac": "aa:bb:cc:dd:ee:ff",
            "timestamp": datetime.now()
        }
        
        # Update context with packets
        self.context_tracker.update(packet1)
        self.context_tracker.update(packet2)
        
        # Get context
        context = self.context_tracker.get_context()
        
        # Check context
        self.assertEqual(len(context["mac_ip_map"]["00:11:22:33:44:55"]), 2)
        self.assertIn("192.168.1.1", context["mac_ip_map"]["00:11:22:33:44:55"])
        self.assertIn("192.168.1.2", context["mac_ip_map"]["00:11:22:33:44:55"])
        
    def test_mac_change_for_ip(self):
        """Test detecting MAC address changes for an IP."""
        # Create packets with same IP but different MACs
        packet1 = {
            "type": "arp",
            "op": 2,
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.100",
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "aa:bb:cc:dd:ee:ff",
            "timestamp": datetime.now()
        }
        
        packet2 = {
            "type": "arp",
            "op": 2,
            "src_ip": "192.168.1.1",  # Same IP
            "dst_ip": "192.168.1.100",
            "src_mac": "aa:bb:cc:dd:ee:ff",  # Different MAC
            "dst_mac": "00:11:22:33:44:55",
            "timestamp": datetime.now()
        }
        
        # Update context with packets
        self.context_tracker.update(packet1)
        
        # Check suspicious activities before second packet
        context = self.context_tracker.get_context()
        self.assertEqual(len(context["suspicious_activities"]), 0)
        
        # Update with second packet
        self.context_tracker.update(packet2)
        
        # Get updated context
        context = self.context_tracker.get_context()
        
        # Check suspicious activities
        self.assertEqual(len(context["suspicious_activities"]), 1)
        self.assertEqual(context["suspicious_activities"][0]["type"], "mac_change")
        self.assertEqual(context["suspicious_activities"][0]["details"]["src_ip"], "192.168.1.1")
        self.assertEqual(context["suspicious_activities"][0]["details"]["old_mac"], "00:11:22:33:44:55")
        self.assertEqual(context["suspicious_activities"][0]["details"]["new_mac"], "aa:bb:cc:dd:ee:ff")
        
    def test_packet_counting(self):
        """Test packet counting for detecting floods."""
        # Create a packet
        packet = {
            "type": "arp",
            "op": 1,
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.100",
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "timestamp": datetime.now()
        }
        
        # Send multiple packets
        for _ in range(10):
            self.context_tracker.update(packet)
            
        # Get context
        context = self.context_tracker.get_context()
        
        # Check packet count
        self.assertGreaterEqual(context["packet_counts"]["00:11:22:33:44:55"], 10)


if __name__ == "__main__":
    unittest.main() 