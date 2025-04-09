import pytest
from datetime import datetime
import time
from app.ml.detection.rule_based import Rule, RuleEngine, RuleResult
from app.ml.detection.rules.arp_spoofing import ARPSpoofingRule, ARPGratuitousRule, ARPFloodRule
from app.ml.detection.validation import RuleValidator

class TestRule:
    """Tests for the base Rule class"""
    
    def test_rule_creation(self):
        """Test that a rule can be created with the correct attributes"""
        rule = Rule(rule_id="TEST_001", description="Test rule", severity="MEDIUM")
        assert rule.rule_id == "TEST_001"
        assert rule.description == "Test rule"
        assert rule.severity == "MEDIUM"
        
    def test_get_metadata(self):
        """Test that a rule returns the correct metadata"""
        rule = Rule(rule_id="TEST_001", description="Test rule", severity="MEDIUM")
        metadata = rule.get_metadata()
        assert metadata["rule_id"] == "TEST_001"
        assert metadata["description"] == "Test rule"
        assert metadata["severity"] == "MEDIUM"


class TestRuleEngine:
    """Tests for the RuleEngine class"""
    
    def test_add_rule(self):
        """Test adding a rule to the engine"""
        engine = RuleEngine()
        rule = ARPSpoofingRule()
        engine.add_rule(rule)
        assert rule.rule_id in engine.rules
        assert engine.rules[rule.rule_id] == rule
        
    def test_empty_engine_returns_empty_list(self):
        """Test that an empty engine returns an empty list of results"""
        engine = RuleEngine()
        packet_data = {"protocol": "ARP"}
        results = engine.evaluate_packet(packet_data)
        assert isinstance(results, list)
        assert len(results) == 0
        
    def test_evaluate_packet_with_no_match(self):
        """Test that a packet that doesn't match any rules returns no results"""
        engine = RuleEngine()
        rule = ARPSpoofingRule()
        engine.add_rule(rule)
        
        # Non-ARP packet should not match
        packet_data = {"protocol": "TCP"}
        results = engine.evaluate_packet(packet_data)
        assert len(results) == 0
        
    def test_evaluate_packet_with_match(self):
        """Test that a packet that matches a rule returns the correct result"""
        engine = RuleEngine()
        rule = ARPSpoofingRule()
        engine.add_rule(rule)
        
        # First packet - establish baseline
        packet_data1 = {
            "protocol": "ARP",
            "source_mac": "00:11:22:33:44:55",
            "source_ip": "192.168.1.100",
            "target_ip": "192.168.1.1",
            "packet_type": "reply"
        }
        results1 = engine.evaluate_packet(packet_data1)
        assert len(results1) == 0  # First packet should not trigger
        
        # Second packet - same IP, different MAC - should trigger
        packet_data2 = {
            "protocol": "ARP",
            "source_mac": "AA:BB:CC:DD:EE:FF",  # Different MAC
            "source_ip": "192.168.1.100",       # Same IP
            "target_ip": "192.168.1.1",
            "packet_type": "reply"
        }
        results2 = engine.evaluate_packet(packet_data2)
        assert len(results2) == 1
        assert isinstance(results2[0], RuleResult)
        assert results2[0].rule_id == "ARP_SPOOFING_001"
        assert results2[0].confidence == 0.9
        assert results2[0].severity == "HIGH"


class TestARPSpoofingRule:
    """Tests for the ARPSpoofingRule class"""
    
    def test_rule_attributes(self):
        """Test that the rule has the correct attributes"""
        rule = ARPSpoofingRule()
        assert rule.rule_id == "ARP_SPOOFING_001"
        assert "ARP spoofing" in rule.description.lower()
        assert rule.severity == "HIGH"
        
    def test_non_arp_packet(self):
        """Test that non-ARP packets are ignored"""
        rule = ARPSpoofingRule()
        packet_data = {"protocol": "TCP"}
        result = rule.evaluate(packet_data)
        assert result is None
        
    def test_first_seen_ip(self):
        """Test that the first packet for an IP doesn't trigger"""
        rule = ARPSpoofingRule()
        packet_data = {
            "protocol": "ARP",
            "source_mac": "00:11:22:33:44:55",
            "source_ip": "192.168.1.100",
            "packet_type": "reply"
        }
        result = rule.evaluate(packet_data)
        assert result is None
        
    def test_ip_mac_change(self):
        """Test that a change in IP-MAC mapping triggers"""
        rule = ARPSpoofingRule()
        
        # First packet - establish baseline
        packet_data1 = {
            "protocol": "ARP",
            "source_mac": "00:11:22:33:44:55",
            "source_ip": "192.168.1.100",
            "packet_type": "reply"
        }
        rule.evaluate(packet_data1)
        
        # Second packet - same IP, different MAC - should trigger
        packet_data2 = {
            "protocol": "ARP",
            "source_mac": "AA:BB:CC:DD:EE:FF",
            "source_ip": "192.168.1.100",
            "packet_type": "reply"
        }
        result = rule.evaluate(packet_data2)
        assert result is not None
        assert result.rule_id == "ARP_SPOOFING_001"
        assert "00:11:22:33:44:55" in str(result.evidence["previous_mac"])


class TestARPGratuitousRule:
    """Tests for the ARPGratuitousRule class"""
    
    def test_rule_attributes(self):
        """Test that the rule has the correct attributes"""
        rule = ARPGratuitousRule()
        assert rule.rule_id == "ARP_GRATUITOUS_001"
        assert "gratuitous" in rule.description.lower()
        assert rule.severity == "MEDIUM"
        
    def test_non_arp_packet(self):
        """Test that non-ARP packets are ignored"""
        rule = ARPGratuitousRule()
        packet_data = {"protocol": "TCP"}
        result = rule.evaluate(packet_data)
        assert result is None
        
    def test_non_gratuitous_packet(self):
        """Test that non-gratuitous ARP packets are ignored"""
        rule = ARPGratuitousRule()
        packet_data = {
            "protocol": "ARP",
            "source_mac": "00:11:22:33:44:55",
            "source_ip": "192.168.1.100",
            "target_ip": "192.168.1.2",  # Different target IP
            "packet_type": "reply"
        }
        result = rule.evaluate(packet_data)
        assert result is None
        
    def test_normal_rate_gratuitous(self):
        """Test that gratuitous ARP packets at normal rate don't trigger"""
        rule = ARPGratuitousRule()
        packet_data = {
            "protocol": "ARP",
            "source_mac": "00:11:22:33:44:55",
            "source_ip": "192.168.1.100",
            "target_ip": "192.168.1.100",  # Same as source IP - gratuitous
            "packet_type": "reply"
        }
        
        # Send a few packets (below threshold)
        for _ in range(5):
            result = rule.evaluate(packet_data)
            assert result is None
            
    def test_high_rate_gratuitous(self):
        """Test that gratuitous ARP packets at high rate trigger"""
        rule = ARPGratuitousRule()
        packet_data = {
            "protocol": "ARP",
            "source_mac": "00:11:22:33:44:55",
            "source_ip": "192.168.1.100",
            "target_ip": "192.168.1.100",  # Same as source IP - gratuitous
            "packet_type": "reply"
        }
        
        # Send many packets (above threshold)
        for _ in range(rule.rate_threshold + 1):
            result = rule.evaluate(packet_data)
            
        # The last packet should trigger
        assert result is not None
        assert result.rule_id == "ARP_GRATUITOUS_001"
        assert result.evidence["count"] > rule.rate_threshold


class TestARPFloodRule:
    """Tests for the ARPFloodRule class"""
    
    def test_rule_attributes(self):
        """Test that the rule has the correct attributes"""
        rule = ARPFloodRule()
        assert rule.rule_id == "ARP_FLOOD_001"
        assert "flood" in rule.description.lower()
        assert rule.severity == "HIGH"
        
    def test_non_arp_packet(self):
        """Test that non-ARP packets are ignored"""
        rule = ARPFloodRule()
        packet_data = {"protocol": "TCP"}
        result = rule.evaluate(packet_data)
        assert result is None
        
    def test_normal_rate(self):
        """Test that ARP packets at normal rate don't trigger"""
        rule = ARPFloodRule()
        packet_data = {
            "protocol": "ARP",
            "source_mac": "00:11:22:33:44:55",
            "packet_type": "reply"
        }
        
        # Send a few packets (below threshold)
        for _ in range(5):
            result = rule.evaluate(packet_data)
            assert result is None
            
    def test_high_rate(self):
        """Test that ARP packets at high rate trigger"""
        rule = ARPFloodRule()
        rule.threshold = 10  # Lower threshold for testing
        
        packet_data = {
            "protocol": "ARP",
            "source_mac": "00:11:22:33:44:55",
            "packet_type": "reply"
        }
        
        # Send many packets (above threshold)
        for _ in range(rule.threshold + 1):
            result = rule.evaluate(packet_data)
            
        # The last packet should trigger
        assert result is not None
        assert result.rule_id == "ARP_FLOOD_001"
        assert result.evidence["packet_count"] > rule.threshold


class TestRuleValidator:
    """Tests for the RuleValidator class"""
    
    def test_validate_valid_rule(self):
        """Test that a valid rule passes validation"""
        validator = RuleValidator()
        rule = ARPSpoofingRule()
        errors = validator.validate_rule(rule)
        assert len(errors) == 0
        
    def test_validate_rule_missing_field(self):
        """Test that a rule with missing fields fails validation"""
        validator = RuleValidator()
        rule = Rule(rule_id="", description="Test", severity="HIGH")
        errors = validator.validate_rule(rule)
        assert len(errors) > 0
        assert any("rule_id" in err.lower() for err in errors)
        
    def test_validate_rule_invalid_severity(self):
        """Test that a rule with invalid severity fails validation"""
        validator = RuleValidator()
        rule = Rule(rule_id="TEST_001", description="Test", severity="INVALID")
        errors = validator.validate_rule(rule)
        assert len(errors) > 0
        assert any("severity" in err.lower() for err in errors)
        
    def test_validate_rule_invalid_id_format(self):
        """Test that a rule with invalid ID format fails validation"""
        validator = RuleValidator()
        rule = Rule(rule_id="INVALID", description="Test", severity="HIGH")
        errors = validator.validate_rule(rule)
        assert len(errors) > 0
        assert any("rule_id" in err.lower() for err in errors) 