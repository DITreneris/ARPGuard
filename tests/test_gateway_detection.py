import unittest
import os
import json
import tempfile
import shutil
from unittest.mock import patch, MagicMock, mock_open
import sys
import time
from typing import Dict, List, Any

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.core.detection_module import DetectionModule, DetectionModuleConfig
from src.core.lite_detection_module import LiteDetectionModule


class TestGatewayDetection(unittest.TestCase):
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
        
        # Sample gateway data
        self.sample_gateway = {
            "ip": "192.168.1.254",
            "mac": "aa:bb:cc:dd:ee:ff",
            "last_seen": time.time(),
            "verified": True
        }
        
    def tearDown(self) -> None:
        """Clean up after each test"""
        # Remove the temporary directory
        shutil.rmtree(self.test_dir)
        
    def test_gateway_file_creation(self) -> None:
        """Test that gateway info file is created when saving"""
        # Create detection module
        module = DetectionModule(self.config)
        
        # Update gateway info
        module.gateway_info = self.sample_gateway
        
        # Save gateway info
        module._save_gateway_info()
        
        # Check if file exists
        gateway_file = os.path.join(self.test_dir, "gateway_info.json")
        self.assertTrue(os.path.exists(gateway_file))
        
        # Check file contents
        with open(gateway_file, 'r') as f:
            loaded_data = json.load(f)
            
        self.assertEqual(loaded_data["ip"], self.sample_gateway["ip"])
        self.assertEqual(loaded_data["mac"], self.sample_gateway["mac"])
        
    def test_gateway_file_loading(self) -> None:
        """Test loading gateway info from file"""
        # Create gateway file
        gateway_file = os.path.join(self.test_dir, "gateway_info.json")
        with open(gateway_file, 'w') as f:
            json.dump(self.sample_gateway, f)
            
        # Create detection module
        module = DetectionModule(self.config)
        
        # Load gateway info
        module._load_gateway_info()
        
        # Check if gateway info was loaded correctly
        self.assertEqual(module.gateway_info["ip"], self.sample_gateway["ip"])
        self.assertEqual(module.gateway_info["mac"], self.sample_gateway["mac"])
        self.assertTrue(module._gateway_info_loaded)
        
    def test_gateway_default_values(self) -> None:
        """Test that default gateway values are used when file doesn't exist"""
        # Create detection module without creating gateway file
        module = DetectionModule(self.config)
        
        # Load gateway info
        module._load_gateway_info()
        
        # Check if default values were used
        self.assertEqual(module.gateway_info["ip"], self.config.default_gateway_ip)
        self.assertEqual(module.gateway_info["mac"], self.config.default_gateway_mac)
        self.assertTrue(module._gateway_info_loaded)
        
    def test_gateway_file_error_handling(self) -> None:
        """Test error handling when loading gateway file"""
        # Create detection module
        module = DetectionModule(self.config)
        
        # Mock open to raise exception
        with patch('builtins.open', side_effect=Exception("Test error")):
            # Load gateway info
            module._load_gateway_info()
            
            # Check if default values were used
            self.assertEqual(module.gateway_info["ip"], self.config.default_gateway_ip)
            self.assertEqual(module.gateway_info["mac"], self.config.default_gateway_mac)
            self.assertTrue(module._gateway_info_loaded)
            
    def test_get_gateway_ips(self) -> None:
        """Test retrieving gateway IPs"""
        # Create detection module
        module = DetectionModule(self.config)
        
        # Set gateway info without loading from file
        module.gateway_info = self.sample_gateway
        module._gateway_info_loaded = True
        
        # Get gateway IPs
        gateway_ips = module._get_gateway_ips()
        
        # Check result
        self.assertEqual(len(gateway_ips), 1)
        self.assertEqual(gateway_ips[0], self.sample_gateway["ip"])
        
    def test_get_gateway_macs(self) -> None:
        """Test retrieving gateway MACs"""
        # Create detection module
        module = DetectionModule(self.config)
        
        # Set gateway info without loading from file
        module.gateway_info = self.sample_gateway
        module._gateway_info_loaded = True
        
        # Get gateway MACs
        gateway_macs = module._get_gateway_macs()
        
        # Check result
        self.assertEqual(len(gateway_macs), 1)
        self.assertEqual(gateway_macs[0], self.sample_gateway["mac"])
        
    def test_missing_gateway_ip(self) -> None:
        """Test handling of missing gateway IP"""
        # Create detection module
        module = DetectionModule(self.config)
        
        # Set gateway info with missing IP
        module.gateway_info = {"mac": "aa:bb:cc:dd:ee:ff"}
        module._gateway_info_loaded = True
        
        # Get gateway IPs
        gateway_ips = module._get_gateway_ips()
        
        # Check result
        self.assertEqual(len(gateway_ips), 0)
        
    def test_lite_module_gateway_loading(self) -> None:
        """Test gateway loading in lite detection module"""
        # Create gateway file
        gateway_file = os.path.join(self.test_dir, "gateway_info.json")
        with open(gateway_file, 'w') as f:
            json.dump(self.sample_gateway, f)
            
        # Create lite detection module
        module = LiteDetectionModule(self.config)
        
        # Check if gateway info was loaded correctly
        self.assertEqual(module.gateway_info["ip"], self.sample_gateway["ip"])
        self.assertEqual(module.gateway_info["mac"], self.sample_gateway["mac"])
        
    def test_cross_module_gateway_consistency(self) -> None:
        """Test that both modules use the same gateway information"""
        # Create detection module and save gateway info
        full_module = DetectionModule(self.config)
        full_module.gateway_info = self.sample_gateway
        full_module._save_gateway_info()
        
        # Create lite detection module (should load the same gateway info)
        lite_module = LiteDetectionModule(self.config)
        
        # Check gateway consistency
        self.assertEqual(lite_module.gateway_info["ip"], full_module.gateway_info["ip"])
        self.assertEqual(lite_module.gateway_info["mac"], full_module.gateway_info["mac"])
        
    @patch('os.path.exists')
    @patch('builtins.open')
    def test_gateway_file_validation(self, mock_open_func, mock_exists):
        """Test validation of gateway file contents"""
        # Set up mocks
        mock_exists.return_value = True
        
        # Test with valid data
        valid_data = json.dumps(self.sample_gateway)
        mock_open_func.return_value = mock_open(read_data=valid_data).return_value
        
        # Create module
        module = DetectionModule(self.config)
        module._load_gateway_info()
        
        # Check if valid data was loaded
        self.assertEqual(module.gateway_info["ip"], self.sample_gateway["ip"])
        
        # Test with invalid data (missing required fields)
        invalid_data = json.dumps({"last_seen": time.time()})
        mock_open_func.return_value = mock_open(read_data=invalid_data).return_value
        
        # Create new module
        module = DetectionModule(self.config)
        module._load_gateway_info()
        
        # Check if default values were used due to invalid data
        self.assertEqual(module.gateway_info["ip"], self.config.default_gateway_ip)


if __name__ == '__main__':
    unittest.main() 