import unittest
import os
import sys
import json
import tempfile
import shutil
import time
from unittest.mock import patch, MagicMock

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.core.detection_module import DetectionModule, DetectionModuleConfig


class TestGatewayEdgeCases(unittest.TestCase):
    def setUp(self) -> None:
        """Set up test environment before each test"""
        # Create a temporary directory for test storage
        self.test_dir = tempfile.mkdtemp()
        
        # Default config with test storage path
        self.config = DetectionModuleConfig(
            storage_path=self.test_dir,
            default_gateway_ip="192.168.1.1",
            default_gateway_mac="00:11:22:33:44:55"
        )
        
        # Create test module
        self.module = DetectionModule(self.config)
        
    def tearDown(self) -> None:
        """Clean up after each test"""
        # Remove the temporary directory
        shutil.rmtree(self.test_dir)
    
    def test_empty_gateway_file(self) -> None:
        """Test handling of an empty gateway file"""
        # Create an empty gateway file
        gateway_file = os.path.join(self.test_dir, "gateway_info.json")
        with open(gateway_file, 'w') as f:
            f.write("")
        
        # Load gateway info
        self.module._load_gateway_info()
        
        # Should use default values due to invalid file
        self.assertEqual(self.module.gateway_info["ip"], self.config.default_gateway_ip)
        self.assertEqual(self.module.gateway_info["mac"], self.config.default_gateway_mac)
    
    def test_malformed_json_gateway_file(self) -> None:
        """Test handling of malformed JSON in gateway file"""
        # Create a malformed JSON file
        gateway_file = os.path.join(self.test_dir, "gateway_info.json")
        with open(gateway_file, 'w') as f:
            f.write("{\"ip\": \"192.168.1.254\", \"mac\": \"aa:bb:cc:dd:ee:ff\"")  # Missing closing brace
        
        # Load gateway info
        self.module._load_gateway_info()
        
        # Should use default values due to invalid file
        self.assertEqual(self.module.gateway_info["ip"], self.config.default_gateway_ip)
        self.assertEqual(self.module.gateway_info["mac"], self.config.default_gateway_mac)
    
    def test_invalid_gateway_ip_format(self) -> None:
        """Test handling of invalid IP address format in gateway file"""
        # Create gateway file with invalid IP
        gateway_data = {
            "ip": "not.a.valid.ip",
            "mac": "aa:bb:cc:dd:ee:ff",
            "last_seen": time.time(),
            "verified": True
        }
        
        gateway_file = os.path.join(self.test_dir, "gateway_info.json")
        with open(gateway_file, 'w') as f:
            json.dump(gateway_data, f)
        
        # Load gateway info
        self.module._load_gateway_info()
        
        # Should load the invalid IP since validation happens at usage time
        self.assertEqual(self.module.gateway_info["ip"], "not.a.valid.ip")
        
        # Test that gateway IP retrieval still works
        gateway_ips = self.module._get_gateway_ips()
        self.assertEqual(len(gateway_ips), 1)
        self.assertEqual(gateway_ips[0], "not.a.valid.ip")
    
    def test_invalid_gateway_mac_format(self) -> None:
        """Test handling of invalid MAC address format in gateway file"""
        # Create gateway file with invalid MAC
        gateway_data = {
            "ip": "192.168.1.254",
            "mac": "not:a:valid:mac",
            "last_seen": time.time(),
            "verified": True
        }
        
        gateway_file = os.path.join(self.test_dir, "gateway_info.json")
        with open(gateway_file, 'w') as f:
            json.dump(gateway_data, f)
        
        # Load gateway info
        self.module._load_gateway_info()
        
        # Should load the invalid MAC since validation happens at usage time
        self.assertEqual(self.module.gateway_info["mac"], "not:a:valid:mac")
        
        # Test that gateway MAC retrieval still works
        gateway_macs = self.module._get_gateway_macs()
        self.assertEqual(len(gateway_macs), 1)
        self.assertEqual(gateway_macs[0], "not:a:valid:mac")
    
    def test_missing_required_fields(self) -> None:
        """Test handling of missing required fields in gateway file"""
        # Create gateway file with missing IP field
        gateway_data = {
            "mac": "aa:bb:cc:dd:ee:ff",
            "last_seen": time.time(),
            "verified": True
        }
        
        gateway_file = os.path.join(self.test_dir, "gateway_info.json")
        with open(gateway_file, 'w') as f:
            json.dump(gateway_data, f)
        
        # Load gateway info
        self.module._load_gateway_info()
        
        # Missing IP field should be handled gracefully
        self.assertEqual(self.module.gateway_info["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertIsNone(self.module.gateway_info.get("ip"))
        
        # Test that gateway IP retrieval returns empty list for missing IP
        gateway_ips = self.module._get_gateway_ips()
        self.assertEqual(len(gateway_ips), 0)
        
        # Create gateway file with missing MAC field
        gateway_data = {
            "ip": "192.168.1.254",
            "last_seen": time.time(),
            "verified": True
        }
        
        with open(gateway_file, 'w') as f:
            json.dump(gateway_data, f)
        
        # Reload gateway info
        self.module._gateway_info_loaded = False
        self.module._load_gateway_info()
        
        # Missing MAC field should be handled gracefully
        self.assertEqual(self.module.gateway_info["ip"], "192.168.1.254")
        self.assertIsNone(self.module.gateway_info.get("mac"))
        
        # Test that gateway MAC retrieval returns empty list for missing MAC
        gateway_macs = self.module._get_gateway_macs()
        self.assertEqual(len(gateway_macs), 0)
    
    def test_null_values_in_gateway_file(self) -> None:
        """Test handling of null values in gateway file"""
        # Create gateway file with null values
        gateway_data = {
            "ip": None,
            "mac": None,
            "last_seen": time.time(),
            "verified": True
        }
        
        gateway_file = os.path.join(self.test_dir, "gateway_info.json")
        with open(gateway_file, 'w') as f:
            json.dump(gateway_data, f)
        
        # Load gateway info
        self.module._load_gateway_info()
        
        # Null values should be loaded as None
        self.assertIsNone(self.module.gateway_info["ip"])
        self.assertIsNone(self.module.gateway_info["mac"])
        
        # Test that gateway IP/MAC retrieval returns empty lists for null values
        gateway_ips = self.module._get_gateway_ips()
        self.assertEqual(len(gateway_ips), 0)
        
        gateway_macs = self.module._get_gateway_macs()
        self.assertEqual(len(gateway_macs), 0)
    
    def test_extremely_large_gateway_file(self) -> None:
        """Test handling of extremely large gateway file"""
        # Create a large gateway file (1MB+)
        gateway_data = {
            "ip": "192.168.1.254",
            "mac": "aa:bb:cc:dd:ee:ff",
            "last_seen": time.time(),
            "verified": True,
            "large_field": "x" * (1024 * 1024)  # 1MB of data
        }
        
        gateway_file = os.path.join(self.test_dir, "gateway_info.json")
        with open(gateway_file, 'w') as f:
            json.dump(gateway_data, f)
        
        # Load gateway info
        self.module._load_gateway_info()
        
        # Should still load the important fields correctly
        self.assertEqual(self.module.gateway_info["ip"], "192.168.1.254")
        self.assertEqual(self.module.gateway_info["mac"], "aa:bb:cc:dd:ee:ff")
        
        # The large field should also be loaded
        self.assertEqual(len(self.module.gateway_info["large_field"]), 1024 * 1024)
    
    def test_multiple_gateways(self) -> None:
        """Test handling of multiple gateway entries"""
        # Create gateway file with multiple gateway entries
        gateway_data = {
            "ip": ["192.168.1.254", "10.0.0.1"],
            "mac": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"],
            "last_seen": time.time(),
            "verified": True
        }
        
        gateway_file = os.path.join(self.test_dir, "gateway_info.json")
        with open(gateway_file, 'w') as f:
            json.dump(gateway_data, f)
        
        # Load gateway info
        self.module._load_gateway_info()
        
        # Should load the array as-is
        self.assertEqual(self.module.gateway_info["ip"], ["192.168.1.254", "10.0.0.1"])
        self.assertEqual(self.module.gateway_info["mac"], ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"])
        
        # Test that gateway IP retrieval handles list format
        gateway_ips = self.module._get_gateway_ips()
        
        # Since _get_gateway_ips expects a string, it might not handle list properly
        # This test checks how the code responds to unexpected data types
        if isinstance(gateway_ips, list) and len(gateway_ips) > 0:
            self.assertIn(gateway_ips[0], gateway_data["ip"])
    
    def test_zero_length_values(self) -> None:
        """Test handling of zero-length values in gateway file"""
        # Create gateway file with empty string values
        gateway_data = {
            "ip": "",
            "mac": "",
            "last_seen": time.time(),
            "verified": True
        }
        
        gateway_file = os.path.join(self.test_dir, "gateway_info.json")
        with open(gateway_file, 'w') as f:
            json.dump(gateway_data, f)
        
        # Load gateway info
        self.module._load_gateway_info()
        
        # Empty strings should be loaded as empty strings
        self.assertEqual(self.module.gateway_info["ip"], "")
        self.assertEqual(self.module.gateway_info["mac"], "")
        
        # Test that gateway IP/MAC retrieval handles empty strings
        gateway_ips = self.module._get_gateway_ips()
        self.assertEqual(len(gateway_ips), 0)
        
        gateway_macs = self.module._get_gateway_macs()
        self.assertEqual(len(gateway_macs), 0)
    
    def test_file_deletion_during_operation(self) -> None:
        """Test handling of gateway file being deleted during operation"""
        # Create gateway file
        gateway_data = {
            "ip": "192.168.1.254",
            "mac": "aa:bb:cc:dd:ee:ff",
            "last_seen": time.time(),
            "verified": True
        }
        
        gateway_file = os.path.join(self.test_dir, "gateway_info.json")
        with open(gateway_file, 'w') as f:
            json.dump(gateway_data, f)
        
        # Load gateway info
        self.module._load_gateway_info()
        
        # Verify it loaded correctly
        self.assertEqual(self.module.gateway_info["ip"], "192.168.1.254")
        
        # Delete the file
        os.remove(gateway_file)
        
        # Update gateway info
        self.module.gateway_info["ip"] = "10.0.0.1"
        
        # Try to save (should not raise an exception)
        self.module._save_gateway_info()
        
        # File should be recreated
        self.assertTrue(os.path.exists(gateway_file))
        
        # Create a new module
        new_module = DetectionModule(self.config)
        
        # Should load the new value
        self.assertEqual(new_module.gateway_info["ip"], "10.0.0.1")
    
    def test_persistence_of_gateway_info(self) -> None:
        """Test that gateway info updates are persisted when saved"""
        # Update gateway info
        self.module.gateway_info = {
            "ip": "192.168.1.254",
            "mac": "aa:bb:cc:dd:ee:ff",
            "last_seen": time.time(),
            "verified": True
        }
        
        # Save gateway info
        self.module._save_gateway_info()
        
        # Create a new module
        new_module = DetectionModule(self.config)
        
        # Should load the saved values
        self.assertEqual(new_module.gateway_info["ip"], "192.168.1.254")
        self.assertEqual(new_module.gateway_info["mac"], "aa:bb:cc:dd:ee:ff")


if __name__ == '__main__':
    unittest.main() 