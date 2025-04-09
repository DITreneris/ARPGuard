import unittest
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from app.ml.feature_extraction import FeatureExtractor

class TestFeatureExtractor(unittest.TestCase):
    """Test class for the FeatureExtractor component."""
    
    def setUp(self):
        """Set up the test environment before each test."""
        self.feature_extractor = FeatureExtractor()
        
        # Sample benign ARP request
        self.benign_request = {
            "op": 1,  # Request
            "src_mac": "aa:bb:cc:dd:ee:ff",
            "dst_mac": "ff:ff:ff:ff:ff:ff",  # Broadcast
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "hw_type": 1,
            "proto_type": 0x0800,
            "hw_len": 6,
            "proto_len": 4,
            "timestamp": datetime.now()
        }
        
        # Sample benign ARP reply
        self.benign_reply = {
            "op": 2,  # Reply
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "aa:bb:cc:dd:ee:ff",
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.10",
            "hw_type": 1,
            "proto_type": 0x0800,
            "hw_len": 6,
            "proto_len": 4,
            "timestamp": datetime.now()
        }
        
        # Sample suspicious ARP packet (gratuitous)
        self.gratuitous_arp = {
            "op": 1,
            "src_mac": "aa:bb:cc:dd:ee:ff",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_ip": "192.168.1.1",  # Same as dst_ip
            "dst_ip": "192.168.1.1",  # Same as src_ip
            "hw_type": 1,
            "proto_type": 0x0800,
            "hw_len": 6,
            "proto_len": 4,
            "timestamp": datetime.now()
        }
        
        # Sample suspicious ARP packet (invalid operation)
        self.invalid_op_arp = {
            "op": 3,  # Invalid operation
            "src_mac": "aa:bb:cc:dd:ee:ff",
            "dst_mac": "00:11:22:33:44:55",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "hw_type": 1,
            "proto_type": 0x0800,
            "hw_len": 6,
            "proto_len": 4,
            "timestamp": datetime.now()
        }
        
        # Sample incomplete ARP packet
        self.incomplete_arp = {
            "op": 1,
            "src_mac": "aa:bb:cc:dd:ee:ff",
            # Missing dst_mac
            "src_ip": "192.168.1.10",
            # Missing dst_ip
            "hw_type": 1,
            "proto_type": 0x0800,
            "hw_len": 6,
            "proto_len": 4,
            "timestamp": datetime.now()
        }
    
    def test_basic_feature_extraction(self):
        """Test extraction of basic features from ARP packets."""
        # Test benign request
        features = self.feature_extractor._extract_basic_features(self.benign_request)
        
        self.assertEqual(features["operation"], 1.0)
        self.assertEqual(features["is_valid_operation"], 1.0)
        self.assertEqual(features["is_broadcast"], 1.0)
        self.assertEqual(features["is_reply_to_broadcast"], 0.0)
        self.assertEqual(features["src_dst_mac_same"], 0.0)
        self.assertEqual(features["src_dst_ip_same"], 0.0)
        self.assertEqual(features["is_gratuitous"], 0.0)
        self.assertEqual(features["is_valid_hw_type"], 1.0)
        self.assertEqual(features["is_valid_proto_type"], 1.0)
        self.assertEqual(features["is_complete"], 1.0)
        
        # Test benign reply
        features = self.feature_extractor._extract_basic_features(self.benign_reply)
        self.assertEqual(features["operation"], 2.0)
        self.assertEqual(features["is_broadcast"], 0.0)
        
        # Test gratuitous ARP
        features = self.feature_extractor._extract_basic_features(self.gratuitous_arp)
        self.assertEqual(features["src_dst_ip_same"], 1.0)
        self.assertEqual(features["is_gratuitous"], 1.0)
        
        # Test invalid operation
        features = self.feature_extractor._extract_basic_features(self.invalid_op_arp)
        self.assertEqual(features["is_valid_operation"], 0.0)
        
        # Test incomplete packet
        features = self.feature_extractor._extract_basic_features(self.incomplete_arp)
        self.assertEqual(features["is_complete"], 0.0)
    
    def test_temporal_features(self):
        """Test extraction of temporal features from packet history."""
        # Start with empty history
        self.feature_extractor.recent_packets = []
        features = self.feature_extractor._extract_temporal_features(self.benign_request)
        
        # Verify default values with no history
        self.assertEqual(features["packet_rate"], 0.0)
        self.assertEqual(features["request_rate"], 0.0)
        self.assertEqual(features["reply_rate"], 0.0)
        self.assertEqual(features["request_reply_ratio"], 0.5)
        
        # Add packets to history
        now = datetime.now()
        for i in range(5):
            request = self.benign_request.copy()
            request["timestamp"] = now - timedelta(seconds=i)
            self.feature_extractor._update_recent_packets(request)
            
        for i in range(5):
            reply = self.benign_reply.copy()
            reply["timestamp"] = now - timedelta(seconds=i)
            self.feature_extractor._update_recent_packets(reply)
        
        # Test with history
        features = self.feature_extractor._extract_temporal_features(self.benign_request)
        
        # Verify temporal features with history
        self.assertGreater(features["packet_rate"], 0.0)
        self.assertGreater(features["request_rate"], 0.0)
        self.assertGreater(features["reply_rate"], 0.0)
        self.assertAlmostEqual(features["request_reply_ratio"], 0.5, delta=0.1)
        self.assertGreater(features["src_mac_freq"], 0.0)
        self.assertLess(features["unique_ip_count"], 1.0)
        self.assertLess(features["unique_mac_count"], 1.0)
    
    def test_relationship_features(self):
        """Test extraction of relationship features between IPs and MACs."""
        # Start with empty mappings
        self.feature_extractor.ip_mac_mappings = {}
        self.feature_extractor.mac_ip_mappings = {}
        
        # First packet should be marked as new mapping
        self.feature_extractor._update_ip_mac_mappings(self.benign_request)
        features = self.feature_extractor._extract_relationship_features(self.benign_request)
        
        self.assertEqual(features["ip_mac_count"], 0.1)  # 1 normalized to 0-1 scale (max 10)
        self.assertEqual(features["mac_ip_count"], 0.1)  # 1 normalized to 0-1 scale (max 10)
        self.assertEqual(features["is_new_mapping"], 0.0)  # Already added in _update_ip_mac_mappings
        
        # New MAC for existing IP
        new_packet = self.benign_request.copy()
        new_packet["src_mac"] = "11:22:33:44:55:66"
        
        # Should be a new mapping
        features = self.feature_extractor._extract_relationship_features(new_packet)
        self.assertEqual(features["is_new_mapping"], 1.0)
        
        self.feature_extractor._update_ip_mac_mappings(new_packet)
        
        # After update, the IP should have 2 MACs
        features = self.feature_extractor._extract_relationship_features(new_packet)
        self.assertEqual(features["ip_mac_count"], 0.2)  # 2 normalized to 0-1 scale
    
    def test_network_features(self):
        """Test extraction of network-related features."""
        # Test regular IP addresses
        features = self.feature_extractor._extract_network_features(self.benign_request)
        
        # 192.168.1.x is a private network
        self.assertEqual(features["src_is_special"], 1.0)
        self.assertEqual(features["dst_is_special"], 1.0)
        self.assertEqual(features["src_dst_same_subnet"], 1.0)  # Same subnet
        
        # Test different subnets
        different_subnet = self.benign_request.copy()
        different_subnet["dst_ip"] = "10.0.0.1"
        
        features = self.feature_extractor._extract_network_features(different_subnet)
        self.assertEqual(features["src_dst_same_subnet"], 0.0)  # Different subnet
        
        # Test invalid IP
        invalid_ip = self.benign_request.copy()
        invalid_ip["src_ip"] = "invalid_ip"
        
        features = self.feature_extractor._extract_network_features(invalid_ip)
        self.assertEqual(features["src_is_special"], 0.0)  # Default because of error
    
    def test_complete_feature_extraction(self):
        """Test the complete feature extraction pipeline."""
        # Test with a benign request
        features = self.feature_extractor.extract_features(self.benign_request)
        
        # Verify the result contains all feature types
        # Basic features
        self.assertIn("operation", features)
        self.assertIn("is_valid_operation", features)
        
        # Temporal features
        self.assertIn("packet_rate", features)
        self.assertIn("request_rate", features)
        
        # Relationship features
        self.assertIn("ip_mac_count", features)
        self.assertIn("mac_ip_count", features)
        
        # Network features
        self.assertIn("src_is_special", features)
        self.assertIn("src_dst_same_subnet", features)
        
        # Verify feature values are all floats
        for key, value in features.items():
            self.assertIsInstance(value, float)
    
    def test_feature_extraction_with_errors(self):
        """Test feature extraction with errors or exceptions."""
        # Create a problematic packet that would cause an exception
        problematic_packet = {
            "op": "invalid",  # Should be an integer
            "src_mac": "aa:bb:cc:dd:ee:ff",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
        }
        
        # Should not raise an exception, but return empty features
        features = self.feature_extractor.extract_features(problematic_packet)
        self.assertIsInstance(features, dict)
    
    def test_packet_window_management(self):
        """Test the management of the packet window for temporal features."""
        # Create packets with timestamps over a 60-second period
        now = datetime.now()
        
        # Add packets at different times
        for i in range(0, 40, 2):  # 20 packets over 40 seconds
            packet = self.benign_request.copy()
            packet["timestamp"] = now - timedelta(seconds=i)
            self.feature_extractor._update_recent_packets(packet)
            
        # All should be within the window (default 30 seconds)
        self.assertLessEqual(len(self.feature_extractor.recent_packets), 20)
        
        # Add more packets with older timestamps (outside window)
        for i in range(40, 100, 2):  # 30 packets over 60 seconds (older)
            packet = self.benign_request.copy()
            packet["timestamp"] = now - timedelta(seconds=i)
            self.feature_extractor._update_recent_packets(packet)
            
        # Check that older packets were removed (outside 30s window)
        self.assertLess(len(self.feature_extractor.recent_packets), 50)
        
        # Test max limit
        self.feature_extractor.max_recent_packets = 10
        for i in range(20):
            packet = self.benign_request.copy()
            packet["timestamp"] = now
            self.feature_extractor._update_recent_packets(packet)
            
        # Should be limited to max_recent_packets
        self.assertEqual(len(self.feature_extractor.recent_packets), 10)
        
if __name__ == "__main__":
    unittest.main() 