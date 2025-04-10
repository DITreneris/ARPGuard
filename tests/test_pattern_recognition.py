import unittest
import time
import os
import tempfile
import json
import sys
from unittest.mock import MagicMock, patch
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

# Add src directory to path
sys.path.append(str(Path(__file__).parent.parent))

from src.core.pattern_database import (
    PatternDatabase, Pattern, PatternFeature, PatternCategory, PatternMatchType
)
from src.core.pattern_matcher import (
    PatternMatcher, FeatureExtractor, MatchResult
)
from src.core.pattern_recognizer import PatternRecognizer
from src.core.alert import AlertManager, AlertType, AlertPriority
from src.core.pattern_recognition import PatternRecognizer
from src.core.detection_module import DetectionModule, DetectionModuleConfig

class TestPatternDatabase(unittest.TestCase):
    """Test the pattern database."""
    
    def setUp(self):
        """Set up test environment."""
        # Create a temporary directory for pattern database
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(self.temp_dir.name, "patterns.json")
        
        # Create pattern database
        self.pattern_database = PatternDatabase(self.database_path)
    
    def tearDown(self):
        """Clean up after tests."""
        # Clean up temporary directory
        if hasattr(self, 'temp_dir'):
            self.temp_dir.cleanup()
    
    def test_add_pattern(self):
        """Test adding a pattern to the database."""
        # Create a test pattern
        pattern = Pattern(
            id="TEST-001",
            name="Test Pattern",
            description="A test pattern",
            category=PatternCategory.ARP_SPOOFING,
            features=[
                PatternFeature("is_at_request", False),
                PatternFeature("is_gratuitous", True)
            ],
            confidence=0.8,
            severity=7,
            tags=["test", "arp"]
        )
        
        # Add pattern to database
        self.pattern_database.add_pattern(pattern)
        
        # Check if pattern was added
        patterns = self.pattern_database.get_all_patterns()
        self.assertEqual(len(patterns), 4)  # 3 default patterns + 1 new
        
        # Check if pattern is retrievable
        retrieved = self.pattern_database.get_pattern("TEST-001")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.id, "TEST-001")
        self.assertEqual(retrieved.name, "Test Pattern")
        
        # Check tag indexing
        patterns_by_tag = self.pattern_database.get_patterns_by_tag("test")
        self.assertEqual(len(patterns_by_tag), 1)
        self.assertEqual(patterns_by_tag[0].id, "TEST-001")
        
        # Check category indexing
        patterns_by_category = self.pattern_database.get_patterns_by_category(PatternCategory.ARP_SPOOFING)
        self.assertTrue(any(p.id == "TEST-001" for p in patterns_by_category))
    
    def test_remove_pattern(self):
        """Test removing a pattern from the database."""
        # Create and add a test pattern
        pattern = Pattern(
            id="TEST-002",
            name="Test Pattern 2",
            description="Another test pattern",
            category=PatternCategory.ARP_MITM,
            features=[PatternFeature("test_feature", True)],
            tags=["test", "mitm"]
        )
        self.pattern_database.add_pattern(pattern)
        
        # Check if pattern was added
        self.assertIsNotNone(self.pattern_database.get_pattern("TEST-002"))
        
        # Remove pattern
        self.assertTrue(self.pattern_database.remove_pattern("TEST-002"))
        
        # Check if pattern was removed
        self.assertIsNone(self.pattern_database.get_pattern("TEST-002"))
        
        # Check if tag indexing was updated
        patterns_by_tag = self.pattern_database.get_patterns_by_tag("mitm")
        self.assertEqual(len(patterns_by_tag), 0)
    
    def test_save_load(self):
        """Test saving and loading the pattern database."""
        # Add a test pattern
        pattern = Pattern(
            id="TEST-003",
            name="Test Pattern 3",
            description="A pattern to test saving/loading",
            category=PatternCategory.CUSTOM,
            features=[
                PatternFeature("feature1", True, PatternMatchType.EXACT),
                PatternFeature("feature2", "value", PatternMatchType.REGEX)
            ],
            confidence=0.9,
            severity=8,
            tags=["save", "load", "test"]
        )
        self.pattern_database.add_pattern(pattern)
        
        # Save database
        self.assertTrue(self.pattern_database.save())
        
        # Create a new database instance and load from file
        new_database = PatternDatabase(self.database_path)
        
        # Check if pattern was loaded
        loaded_pattern = new_database.get_pattern("TEST-003")
        self.assertIsNotNone(loaded_pattern)
        self.assertEqual(loaded_pattern.id, "TEST-003")
        self.assertEqual(loaded_pattern.name, "Test Pattern 3")
        self.assertEqual(loaded_pattern.category, PatternCategory.CUSTOM)
        self.assertEqual(len(loaded_pattern.features), 2)
        self.assertEqual(loaded_pattern.features[0].name, "feature1")
        self.assertEqual(loaded_pattern.features[0].value, True)
        self.assertEqual(loaded_pattern.features[0].match_type, PatternMatchType.EXACT)
        self.assertEqual(loaded_pattern.features[1].name, "feature2")
        self.assertEqual(loaded_pattern.features[1].value, "value")
        self.assertEqual(loaded_pattern.features[1].match_type, PatternMatchType.REGEX)


class TestFeatureExtractor(unittest.TestCase):
    """Test the feature extractor."""
    
    def setUp(self):
        """Set up test environment."""
        self.feature_extractor = FeatureExtractor()
    
    def test_extract_is_at_request(self):
        """Test extracting the is_at_request feature."""
        # ARP request
        packet1 = {"arp_operation": 1}
        self.assertTrue(self.feature_extractor._extract_is_at_request(packet1, {}))
        
        # ARP reply
        packet2 = {"arp_operation": 2}
        self.assertFalse(self.feature_extractor._extract_is_at_request(packet2, {}))
    
    def test_extract_is_gratuitous(self):
        """Test extracting the is_gratuitous feature."""
        # Gratuitous ARP (sender IP = target IP)
        packet1 = {
            "arp_operation": 2,
            "sender_ip": "192.168.1.1",
            "target_ip": "192.168.1.1"
        }
        self.assertTrue(self.feature_extractor._extract_is_gratuitous(packet1, {}))
        
        # Normal ARP reply
        packet2 = {
            "arp_operation": 2,
            "sender_ip": "192.168.1.1",
            "target_ip": "192.168.1.2"
        }
        self.assertFalse(self.feature_extractor._extract_is_gratuitous(packet2, {}))
    
    def test_extract_gateway_mac_changed(self):
        """Test extracting the gateway_mac_changed feature."""
        # Context with gateway info
        context = {
            "gateway_ip": "192.168.1.1",
            "gateway_mac": "00:11:22:33:44:55"
        }
        
        # Different MAC for gateway IP
        packet1 = {
            "arp_operation": 2,
            "sender_ip": "192.168.1.1",
            "sender_mac": "aa:bb:cc:dd:ee:ff"
        }
        self.assertTrue(self.feature_extractor._extract_gateway_mac_changed(packet1, context))
        
        # Same MAC for gateway IP
        packet2 = {
            "arp_operation": 2,
            "sender_ip": "192.168.1.1",
            "sender_mac": "00:11:22:33:44:55"
        }
        self.assertFalse(self.feature_extractor._extract_gateway_mac_changed(packet2, context))
    
    def test_extract_features(self):
        """Test extracting all features from a packet."""
        # Create test packet
        packet = {
            "arp_operation": 2,
            "sender_ip": "192.168.1.1",
            "sender_mac": "aa:bb:cc:dd:ee:ff",
            "target_ip": "192.168.1.1",
            "target_mac": "00:11:22:33:44:55"
        }
        
        # Create test context
        context = {
            "gateway_ip": "192.168.1.1",
            "gateway_mac": "00:11:22:33:44:55",
            "packet_rate": 150,
            "high_rate_threshold": 100,
            "mapping_changes": 5,
            "rapid_changes_threshold": 3
        }
        
        # Extract features
        features = self.feature_extractor.extract_features(packet, context)
        
        # Check a few key features
        self.assertFalse(features["is_at_request"])
        self.assertTrue(features["is_gratuitous"])
        self.assertTrue(features["sender_is_gateway_ip"])
        self.assertTrue(features["gateway_mac_changed"])
        self.assertTrue(features["packet_rate_high"])
        self.assertTrue(features["rapid_changes"])


class TestPatternMatcher(unittest.TestCase):
    """Test the pattern matcher."""
    
    def setUp(self):
        """Set up test environment."""
        # Create pattern database
        self.pattern_database = PatternDatabase(None)  # In-memory database
        
        # Create pattern matcher
        self.pattern_matcher = PatternMatcher(self.pattern_database)
        
        # Set up gateway info in context
        self.pattern_matcher.update_context("gateway_ip", "192.168.1.1")
        self.pattern_matcher.update_context("gateway_mac", "00:11:22:33:44:55")
    
    def test_match_feature_value(self):
        """Test matching feature values using different match types."""
        # Test exact matching
        self.assertTrue(self.pattern_matcher._match_feature_value(True, True, PatternMatchType.EXACT))
        self.assertFalse(self.pattern_matcher._match_feature_value(True, False, PatternMatchType.EXACT))
        
        # Test partial matching
        self.assertTrue(self.pattern_matcher._match_feature_value(
            ["a", "b", "c"], ["a", "c"], PatternMatchType.PARTIAL
        ))
        self.assertTrue(self.pattern_matcher._match_feature_value(
            {"a": 1, "b": 2, "c": 3}, {"a": 1, "c": 3}, PatternMatchType.PARTIAL
        ))
        self.assertTrue(self.pattern_matcher._match_feature_value(
            "abcdef", "cde", PatternMatchType.PARTIAL
        ))
        
        # Test fuzzy matching
        self.assertTrue(self.pattern_matcher._match_feature_value(105, 100, PatternMatchType.FUZZY))
        self.assertFalse(self.pattern_matcher._match_feature_value(150, 100, PatternMatchType.FUZZY))
        self.assertTrue(self.pattern_matcher._match_feature_value("hello world", "helo world", PatternMatchType.FUZZY))
        
        # Test regex matching
        self.assertTrue(self.pattern_matcher._match_feature_value("abc123", r"abc\d+", PatternMatchType.REGEX))
        self.assertFalse(self.pattern_matcher._match_feature_value("abcxyz", r"abc\d+", PatternMatchType.REGEX))
    
    def test_match_pattern(self):
        """Test matching a pattern against features."""
        # Create test pattern
        pattern = Pattern(
            id="TEST-MATCHER-001",
            name="ARP Spoofing Test",
            description="Test pattern for matching",
            category=PatternCategory.ARP_SPOOFING,
            features=[
                PatternFeature("is_at_request", False),
                PatternFeature("is_gratuitous", True),
                PatternFeature("gateway_mac_changed", True)
            ],
            confidence=0.66  # Must match 2 of 3 features
        )
        
        # Create features that match 2 of 3 features
        features = {
            "is_at_request": False,
            "is_gratuitous": True,
            "gateway_mac_changed": False
        }
        
        # Match pattern
        result = self.pattern_matcher._match_pattern(pattern, features)
        
        # Check result
        self.assertIsNotNone(result)
        self.assertEqual(result.pattern_id, "TEST-MATCHER-001")
        self.assertEqual(result.score, 2/3)
        self.assertEqual(set(result.matched_features), {"is_at_request", "is_gratuitous"})
        
        # Create features that match only 1 of 3 features (below confidence threshold)
        features = {
            "is_at_request": True,  # Not matching
            "is_gratuitous": True,  # Matching
            "gateway_mac_changed": False  # Not matching
        }
        
        # Match pattern
        result = self.pattern_matcher._match_pattern(pattern, features)
        
        # Check result - should not match
        self.assertIsNone(result)
    
    def test_process_packet(self):
        """Test processing a packet through the pattern matcher."""
        # Add a test pattern to the database
        pattern = Pattern(
            id="TEST-PROCESS-001",
            name="Gateway Impersonation",
            description="Test pattern for packet processing",
            category=PatternCategory.GATEWAY_IMPERSONATION,
            features=[
                PatternFeature("is_at_request", False),
                PatternFeature("gateway_mac_changed", True)
            ],
            confidence=0.5
        )
        self.pattern_database.add_pattern(pattern)
        
        # Create a packet that matches the pattern
        packet = {
            "arp_operation": 2,
            "sender_ip": "192.168.1.1",  # Gateway IP
            "sender_mac": "aa:bb:cc:dd:ee:ff",  # Different from gateway MAC
            "target_ip": "192.168.1.2",
            "target_mac": "ff:ff:ff:ff:ff:ff"
        }
        
        # Process packet
        results = self.pattern_matcher.process_packet(packet)
        
        # Check results
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].pattern_id, "TEST-PROCESS-001")
        self.assertEqual(results[0].pattern_name, "Gateway Impersonation")
        
        # Check context updates
        self.assertIn(packet, self.pattern_matcher.context["recent_packets"])
        self.assertIn("192.168.1.2", self.pattern_matcher.context["recent_targets"])
        self.assertIn("aa:bb:cc", self.pattern_matcher.context["recent_ouis"])
        self.assertEqual(self.pattern_matcher.context["ip_to_mac"]["192.168.1.1"], "aa:bb:cc:dd:ee:ff")


class TestPatternRecognizer(unittest.TestCase):
    """Test the pattern recognizer."""
    
    def setUp(self):
        """Set up test environment."""
        # Create mock alert manager
        self.alert_manager = MagicMock(spec=AlertManager)
        
        # Create temporary directory for pattern database
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(self.temp_dir.name, "patterns.json")
        
        # Create pattern recognizer
        self.recognizer = PatternRecognizer(
            alert_manager=self.alert_manager,
            database_path=self.database_path,
            min_confidence=0.6,
            alert_cooldown=0.1,  # Short cooldown for testing
            context_update_interval=0.1  # Short interval for testing
        )
        
        # Add a custom pattern for testing
        pattern = Pattern(
            id="TEST-RECOG-001",
            name="Test Pattern for Recognizer",
            description="A test pattern for recognizer",
            category=PatternCategory.ARP_SPOOFING,
            features=[
                PatternFeature("is_at_request", False),
                PatternFeature("is_gratuitous", True),
                PatternFeature("gateway_mac_changed", True)
            ],
            confidence=0.66,
            severity=8,
            tags=["test", "recognizer"]
        )
        self.recognizer.pattern_database.add_pattern(pattern)
    
    def tearDown(self):
        """Clean up after tests."""
        # Stop recognizer if running
        if self.recognizer.running:
            self.recognizer.stop_monitoring()
        
        # Clean up temporary directory
        if hasattr(self, 'temp_dir'):
            self.temp_dir.cleanup()
    
    def test_process_packet(self):
        """Test processing a packet through the recognizer."""
        # Create a packet that matches the pattern
        packet = {
            "arp_operation": 2,
            "sender_ip": "192.168.1.1",
            "sender_mac": "aa:bb:cc:dd:ee:ff",
            "target_ip": "192.168.1.1",
            "target_mac": "ff:ff:ff:ff:ff:ff"
        }
        
        # Setup context values
        self.recognizer.set_context_value("gateway_ip", "192.168.1.1")
        self.recognizer.set_context_value("gateway_mac", "00:11:22:33:44:55")
        
        # Process packet
        results = self.recognizer.process_packet(packet)
        
        # Check results
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].pattern_id, "TEST-RECOG-001")
        
        # Check if alert was generated
        self.alert_manager.create_alert.assert_called_once()
        args = self.alert_manager.create_alert.call_args[0]
        self.assertEqual(args[0], AlertType.PATTERN_MATCH)
        self.assertEqual(args[1], AlertPriority.HIGH)  # Based on score (0.66) * severity (8) = 5.28
        self.assertIn("ARP attack pattern detected", args[2])
    
    def test_alert_cooldown(self):
        """Test alert cooldown mechanism."""
        # Create a packet that matches the pattern
        packet = {
            "arp_operation": 2,
            "sender_ip": "192.168.1.1",
            "sender_mac": "aa:bb:cc:dd:ee:ff",
            "target_ip": "192.168.1.1",
            "target_mac": "ff:ff:ff:ff:ff:ff"
        }
        
        # Setup context values
        self.recognizer.set_context_value("gateway_ip", "192.168.1.1")
        self.recognizer.set_context_value("gateway_mac", "00:11:22:33:44:55")
        
        # Process packet first time
        self.recognizer.process_packet(packet)
        
        # Reset mock
        self.alert_manager.create_alert.reset_mock()
        
        # Process packet again immediately (should be in cooldown)
        self.recognizer.process_packet(packet)
        
        # Check that no alert was generated
        self.alert_manager.create_alert.assert_not_called()
        
        # Wait for cooldown to expire
        time.sleep(0.2)
        
        # Process packet again after cooldown
        self.recognizer.process_packet(packet)
        
        # Check that alert was generated
        self.alert_manager.create_alert.assert_called_once()
    
    def test_network_stats_callback(self):
        """Test network stats callback mechanism."""
        # Define mock callback
        def mock_network_stats():
            return {
                "packet_rate": 200,
                "high_rate_threshold": 100,
                "gateway_ip": "192.168.1.1",
                "gateway_mac": "00:11:22:33:44:55"
            }
        
        # Set callback
        self.recognizer.set_network_stats_callback(mock_network_stats)
        
        # Trigger context update
        self.recognizer._update_context()
        
        # Check if context was updated
        self.assertEqual(self.recognizer.pattern_matcher.context["packet_rate"], 200)
        self.assertEqual(self.recognizer.pattern_matcher.context["high_rate_threshold"], 100)
    
    def test_start_stop_monitoring(self):
        """Test starting and stopping the monitoring thread."""
        # Start monitoring
        self.recognizer.start_monitoring()
        
        # Check if running
        self.assertTrue(self.recognizer.running)
        self.assertIsNotNone(self.recognizer.thread)
        
        # Stop monitoring
        self.recognizer.stop_monitoring()
        
        # Check if stopped
        self.assertFalse(self.recognizer.running)
        self.assertIsNone(self.recognizer.thread)
    
    def test_get_status(self):
        """Test getting status information."""
        # Process a few packets to generate stats
        packet1 = {
            "arp_operation": 2,
            "sender_ip": "192.168.1.1",
            "sender_mac": "aa:bb:cc:dd:ee:ff",
            "target_ip": "192.168.1.1",
            "target_mac": "ff:ff:ff:ff:ff:ff"
        }
        
        # Setup context values
        self.recognizer.set_context_value("gateway_ip", "192.168.1.1")
        self.recognizer.set_context_value("gateway_mac", "00:11:22:33:44:55")
        
        # Process packet
        self.recognizer.process_packet(packet1)
        self.recognizer.process_packet(packet1)
        
        # Wait for cooldown to expire
        time.sleep(0.2)
        
        # Process packet again after cooldown
        self.recognizer.process_packet(packet1)
        
        # Get status
        status = self.recognizer.get_status()
        
        # Check status fields
        self.assertEqual(status["total_packets_processed"], 3)
        self.assertEqual(status["total_matches"], 3)
        self.assertEqual(status["alerting_patterns_count"], 1)
        self.assertEqual(len(status["top_alerting_patterns"]), 1)
        self.assertEqual(status["top_alerting_patterns"][0]["pattern_id"], "TEST-RECOG-001")
        self.assertEqual(status["top_alerting_patterns"][0]["count"], 2)  # 2 alerts due to cooldown


class MockGatewayDetector:
    """Mock gateway detector for testing."""
    
    def __init__(self, gateway_ip="192.168.1.1", gateway_mac="00:11:22:33:44:55"):
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
    
    def _get_gateway_ips(self):
        return [self.gateway_ip]
    
    def _get_gateway_macs(self):
        return [self.gateway_mac]


class TestPatternRecognition(unittest.TestCase):
    def setUp(self):
        """Set up before each test."""
        self.gateway_detector = MockGatewayDetector()
        self.pattern_recognizer = PatternRecognizer(gateway_detector=self.gateway_detector)
    
    def test_initialization(self):
        """Test that the pattern recognizer initializes correctly."""
        self.assertIsNotNone(self.pattern_recognizer)
        self.assertEqual(self.pattern_recognizer.packet_count, 0)
        self.assertEqual(self.pattern_recognizer.anomaly_count, 0)
        self.assertEqual(len(self.pattern_recognizer.arp_history), 0)
    
    def test_process_packet(self):
        """Test that the pattern recognizer correctly processes packets."""
        # Create a basic ARP packet
        packet = {
            "src_mac": "aa:bb:cc:dd:ee:ff",
            "src_ip": "192.168.1.100",
            "dst_ip": "192.168.1.1",
            "op_code": 1,  # ARP request
            "timestamp": time.time()
        }
        
        # Process the packet
        result = self.pattern_recognizer.process_packet(packet)
        
        # No anomaly should be detected for a single packet
        self.assertIsNone(result)
        
        # Check that the packet was recorded
        self.assertEqual(self.pattern_recognizer.packet_count, 1)
        self.assertEqual(len(self.pattern_recognizer.arp_history), 1)
        self.assertEqual(len(self.pattern_recognizer.mac_ip_bindings), 1)
        self.assertEqual(len(self.pattern_recognizer.ip_mac_bindings), 1)
        
        # Check the MAC-IP bindings
        self.assertIn("aa:bb:cc:dd:ee:ff", self.pattern_recognizer.mac_ip_bindings)
        self.assertIn("192.168.1.100", self.pattern_recognizer.ip_mac_bindings)
        self.assertEqual(self.pattern_recognizer.mac_ip_bindings["aa:bb:cc:dd:ee:ff"], {"192.168.1.100"})
    
    def test_ip_mac_flapping(self):
        """Test detection of IP-MAC flapping (IP address using multiple MACs)."""
        # First packet - establish baseline
        packet1 = {
            "src_mac": "aa:bb:cc:dd:ee:ff",
            "src_ip": "192.168.1.100",
            "dst_ip": "192.168.1.1",
            "op_code": 1,
            "timestamp": time.time()
        }
        self.pattern_recognizer.process_packet(packet1)
        
        # Second packet - same IP, different MAC (potential spoofing)
        packet2 = {
            "src_mac": "11:22:33:44:55:66",
            "src_ip": "192.168.1.100",
            "dst_ip": "192.168.1.1",
            "op_code": 1,
            "timestamp": time.time() + 1
        }
        result = self.pattern_recognizer.process_packet(packet2)
        
        # Should detect a MAC-IP conflict
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "mac_ip_conflict")
        self.assertGreaterEqual(result["confidence"], 0.7)
        
        # Force pattern analysis
        self.pattern_recognizer.last_analysis_time = 0
        advanced_results = self.pattern_recognizer.analyze_patterns()
        
        # Should detect IP-MAC flapping
        self.assertIsNotNone(advanced_results)
        self.assertEqual(advanced_results["type"], "ip_mac_flapping")
        
        # Check that statistics were updated
        self.assertEqual(self.pattern_recognizer.packet_count, 2)
        self.assertEqual(self.pattern_recognizer.anomaly_count, 1)
    
    def test_gateway_impersonation(self):
        """Test detection of gateway impersonation."""
        # First packet - legitimate gateway
        packet1 = {
            "src_mac": self.gateway_detector.gateway_mac,
            "src_ip": self.gateway_detector.gateway_ip,
            "dst_ip": "192.168.1.100",
            "op_code": 2,  # ARP reply
            "timestamp": time.time()
        }
        self.pattern_recognizer.process_packet(packet1)
        
        # Second packet - different MAC claiming to be gateway
        packet2 = {
            "src_mac": "aa:bb:cc:dd:ee:ff",  # Different from legitimate gateway
            "src_ip": self.gateway_detector.gateway_ip,
            "dst_ip": "192.168.1.100",
            "op_code": 2,
            "timestamp": time.time() + 1
        }
        
        # Process multiple times to increase confidence
        for _ in range(5):
            self.pattern_recognizer.process_packet(packet2)
        
        # Force pattern analysis
        self.pattern_recognizer.last_analysis_time = 0
        result = self.pattern_recognizer.analyze_patterns()
        
        # Should detect gateway impersonation
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "gateway_impersonation")
        self.assertGreaterEqual(result["confidence"], 0.75)
    
    def test_arp_storm(self):
        """Test detection of ARP storm (high rate of ARP packets)."""
        base_time = time.time()
        mac_address = "aa:bb:cc:dd:ee:ff"
        
        # Generate a burst of ARP packets from the same MAC
        for i in range(50):
            packet = {
                "src_mac": mac_address,
                "src_ip": f"192.168.1.{100 + (i % 5)}",  # Cycle through a few IPs
                "dst_ip": f"192.168.1.{200 + (i % 10)}",
                "op_code": 1,
                "timestamp": base_time + (i * 0.1)  # 10 packets per second
            }
            self.pattern_recognizer.process_packet(packet)
        
        # Force pattern analysis
        self.pattern_recognizer.last_analysis_time = 0
        result = self.pattern_recognizer.analyze_patterns()
        
        # Should detect ARP storm
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "arp_storm")
        self.assertGreaterEqual(result["confidence"], 0.6)
        self.assertEqual(result["mac"], mac_address)
    
    def test_unsolicited_replies(self):
        """Test detection of unsolicited ARP replies."""
        base_time = time.time()
        mac_address = "aa:bb:cc:dd:ee:ff"
        
        # Generate a series of ARP replies without corresponding requests
        for i in range(10):
            packet = {
                "src_mac": mac_address,
                "src_ip": f"192.168.1.{100 + i}",
                "dst_ip": "192.168.1.1",
                "op_code": 2,  # ARP reply
                "timestamp": base_time + (i * 0.5)
            }
            self.pattern_recognizer.process_packet(packet)
        
        # Force pattern analysis
        self.pattern_recognizer.last_analysis_time = 0
        result = self.pattern_recognizer.analyze_patterns()
        
        # Should detect unsolicited replies
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "unsolicited_replies")
        self.assertGreaterEqual(result["confidence"], 0.7)
        self.assertEqual(result["mac"], mac_address)
    
    def test_mitm_pattern(self):
        """Test detection of Man-in-the-Middle attack pattern."""
        base_time = time.time()
        attacker_mac = "aa:bb:cc:dd:ee:ff"
        
        # First, the attacker claims to be the gateway
        packet1 = {
            "src_mac": attacker_mac,
            "src_ip": self.gateway_detector.gateway_ip,
            "dst_ip": "192.168.1.100",
            "op_code": 2,
            "timestamp": base_time
        }
        self.pattern_recognizer.process_packet(packet1)
        
        # Then, the attacker claims to be another host
        packet2 = {
            "src_mac": attacker_mac,
            "src_ip": "192.168.1.100",
            "dst_ip": self.gateway_detector.gateway_ip,
            "op_code": 2,
            "timestamp": base_time + 0.5
        }
        self.pattern_recognizer.process_packet(packet2)
        
        # Send a few more packets to increase confidence
        for i in range(3):
            self.pattern_recognizer.process_packet(packet1)
            self.pattern_recognizer.process_packet(packet2)
        
        # Force pattern analysis
        self.pattern_recognizer.last_analysis_time = 0
        result = self.pattern_recognizer.analyze_patterns()
        
        # Should detect MITM pattern
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "mitm_pattern")
        self.assertGreaterEqual(result["confidence"], 0.85)
        self.assertEqual(result["mac"], attacker_mac)
    
    def test_subnet_scan(self):
        """Test detection of subnet scanning."""
        base_time = time.time()
        scanner_mac = "aa:bb:cc:dd:ee:ff"
        
        # Generate a sequence of ARP requests scanning through a subnet
        for i in range(20):
            packet = {
                "src_mac": scanner_mac,
                "src_ip": "192.168.1.100",
                "dst_ip": f"192.168.1.{10 + i}",  # Sequential scan
                "op_code": 1,  # ARP request
                "timestamp": base_time + (i * 0.2)
            }
            self.pattern_recognizer.process_packet(packet)
        
        # Force pattern analysis
        self.pattern_recognizer.last_analysis_time = 0
        result = self.pattern_recognizer.analyze_patterns()
        
        # Should detect subnet scan
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "subnet_scan")
        self.assertGreaterEqual(result["confidence"], 0.6)
        self.assertEqual(result["mac"], scanner_mac)
    
    def test_get_stats(self):
        """Test retrieving statistics from the pattern recognizer."""
        # Process a few packets
        for i in range(5):
            packet = {
                "src_mac": f"aa:bb:cc:dd:ee:{i:02x}",
                "src_ip": f"192.168.1.{100 + i}",
                "dst_ip": "192.168.1.1",
                "op_code": 1,
                "timestamp": time.time() + i
            }
            self.pattern_recognizer.process_packet(packet)
        
        # Get stats
        stats = self.pattern_recognizer.get_stats()
        
        # Check statistics
        self.assertEqual(stats["packet_count"], 5)
        self.assertEqual(stats["mac_ip_bindings"], 5)
        self.assertEqual(stats["ip_mac_bindings"], 5)
        self.assertEqual(stats["unique_macs"], 5)
        self.assertEqual(stats["unique_ips"], 5)
    
    def test_reset(self):
        """Test resetting the pattern recognizer."""
        # Process a few packets
        for i in range(5):
            packet = {
                "src_mac": f"aa:bb:cc:dd:ee:{i:02x}",
                "src_ip": f"192.168.1.{100 + i}",
                "dst_ip": "192.168.1.1",
                "op_code": 1,
                "timestamp": time.time() + i
            }
            self.pattern_recognizer.process_packet(packet)
        
        # Reset
        self.pattern_recognizer.reset()
        
        # Check that all data was reset
        self.assertEqual(self.pattern_recognizer.packet_count, 0)
        self.assertEqual(self.pattern_recognizer.anomaly_count, 0)
        self.assertEqual(len(self.pattern_recognizer.arp_history), 0)
        self.assertEqual(len(self.pattern_recognizer.mac_ip_bindings), 0)
        self.assertEqual(len(self.pattern_recognizer.ip_mac_bindings), 0)
        self.assertEqual(len(self.pattern_recognizer.detected_patterns), 0)
    
    def test_integration_with_detection_module(self):
        """Test integration with the detection module."""
        # Create detection module with pattern recognition
        config = DetectionModuleConfig(
            storage_path="./test_data",
            default_gateway_ip="192.168.1.1",
            default_gateway_mac="00:11:22:33:44:55"
        )
        detection_module = DetectionModule(config)
        
        # Check that pattern recognizer was initialized
        self.assertIsNotNone(detection_module.pattern_recognizer)
        
        # Create a mock ARP packet with a spoofing signature
        packet_time = time.time()
        for i in range(5):
            # Using different MAC addresses for the same IP
            mock_packet = type('MockPacket', (), {})()
            mock_packet.haslayer = lambda x: True
            mock_packet.getlayer = lambda x: type('MockARP', (), {
                'psrc': '192.168.1.100',
                'hwsrc': f'00:11:22:33:44:{60+i:02x}',  # Different MACs
                'pdst': '192.168.1.1',
                'hwdst': 'ff:ff:ff:ff:ff:ff',
                'op': 2  # ARP reply
            })()
            
            # Set the last packet to impersonate the gateway
            if i == 4:
                mock_packet.getlayer = lambda x: type('MockARP', (), {
                    'psrc': '192.168.1.1',  # Gateway IP
                    'hwsrc': '00:11:22:33:44:65',  # Not the gateway MAC
                    'pdst': '192.168.1.100',
                    'hwdst': '00:11:22:33:44:60',
                    'op': 2
                })()
            
            # Process the packet
            result = detection_module._analyze_packet(
                mock_packet, 
                priority=1, 
                timestamp=packet_time + i
            )
            
            # We expect pattern detections by the end
            if i >= 1:
                self.assertIsNotNone(result)
                self.assertIn("pattern_type", result)
        
        # Check that pattern recognition hits were recorded
        stats = detection_module.get_stats()
        self.assertIn("pattern_recognition_hits", stats)
        self.assertGreater(stats["pattern_recognition_hits"], 0)


if __name__ == '__main__':
    unittest.main() 