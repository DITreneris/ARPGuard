import unittest
import os
import sys
import json
import tempfile
import shutil
import platform
from unittest.mock import patch, MagicMock, mock_open

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.core.detection_module import DetectionModule, DetectionModuleConfig


class TestCrossPlatformCompatibility(unittest.TestCase):
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
            "last_seen": 1634567890.123,
            "verified": True
        }
        
        # Create test module
        self.module = DetectionModule(self.config)
        
    def tearDown(self) -> None:
        """Clean up after each test"""
        # Remove the temporary directory
        shutil.rmtree(self.test_dir)
    
    def test_platform_info(self) -> None:
        """Log platform information for the test environment"""
        platform_info = {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation()
        }
        
        print("\nRunning cross-platform tests on:")
        for key, value in platform_info.items():
            print(f"  {key}: {value}")
    
    @patch('platform.system')
    def test_windows_path_handling(self, mock_system):
        """Test path handling on Windows systems"""
        # Mock Windows environment
        mock_system.return_value = "Windows"
        
        # Create gateway info with Windows paths
        gateway_file = os.path.join(self.test_dir, "gateway_info.json")
        with open(gateway_file, 'w') as f:
            json.dump(self.sample_gateway, f)
        
        # Test loading gateway info
        self.module._load_gateway_info()
        
        # Verify data loaded correctly
        self.assertEqual(self.module.gateway_info["ip"], self.sample_gateway["ip"])
        self.assertEqual(self.module.gateway_info["mac"], self.sample_gateway["mac"])
    
    @patch('platform.system')
    def test_linux_path_handling(self, mock_system):
        """Test path handling on Linux systems"""
        # Mock Linux environment
        mock_system.return_value = "Linux"
        
        # Create gateway info with Linux paths
        gateway_file = os.path.join(self.test_dir, "gateway_info.json")
        with open(gateway_file, 'w') as f:
            json.dump(self.sample_gateway, f)
        
        # Test loading gateway info
        self.module._load_gateway_info()
        
        # Verify data loaded correctly
        self.assertEqual(self.module.gateway_info["ip"], self.sample_gateway["ip"])
        self.assertEqual(self.module.gateway_info["mac"], self.sample_gateway["mac"])
    
    @patch('platform.system')
    def test_mac_path_handling(self, mock_system):
        """Test path handling on macOS systems"""
        # Mock macOS environment
        mock_system.return_value = "Darwin"
        
        # Create gateway info with macOS paths
        gateway_file = os.path.join(self.test_dir, "gateway_info.json")
        with open(gateway_file, 'w') as f:
            json.dump(self.sample_gateway, f)
        
        # Test loading gateway info
        self.module._load_gateway_info()
        
        # Verify data loaded correctly
        self.assertEqual(self.module.gateway_info["ip"], self.sample_gateway["ip"])
        self.assertEqual(self.module.gateway_info["mac"], self.sample_gateway["mac"])
    
    def test_file_path_normalization(self):
        """Test path normalization across platforms"""
        # Create different path formats
        paths = [
            os.path.join(self.test_dir, "gateway_info.json"),  # Normal path
            os.path.join(self.test_dir, "..", os.path.basename(self.test_dir), "gateway_info.json"),  # Path with ..
            os.path.abspath(os.path.join(self.test_dir, "gateway_info.json")),  # Absolute path
        ]
        
        # Write sample data to the first path
        with open(paths[0], 'w') as f:
            json.dump(self.sample_gateway, f)
        
        # Test loading from each path format
        for i, path in enumerate(paths):
            # Create a new module with the test path
            test_config = DetectionModuleConfig(
                storage_path=os.path.dirname(path),
                default_gateway_ip="192.168.1.1",
                default_gateway_mac="00:11:22:33:44:55"
            )
            test_module = DetectionModule(test_config)
            
            # Attempt to load gateway info
            test_module._load_gateway_info()
            
            # For the first path, data should be loaded correctly
            if i == 0:
                self.assertEqual(test_module.gateway_info["ip"], self.sample_gateway["ip"])
                self.assertEqual(test_module.gateway_info["mac"], self.sample_gateway["mac"])
    
    def test_mac_address_format_compatibility(self):
        """Test compatibility with different MAC address formats"""
        # Test MAC address formats
        mac_formats = [
            "aa:bb:cc:dd:ee:ff",  # Colon-separated (standard)
            "aa-bb-cc-dd-ee-ff",  # Hyphen-separated
            "aabb.ccdd.eeff",      # Cisco format
            "aabbccddeeff"         # No separators
        ]
        
        for mac_format in mac_formats:
            # Create gateway info with the test MAC format
            gateway_data = self.sample_gateway.copy()
            gateway_data["mac"] = mac_format
            
            gateway_file = os.path.join(self.test_dir, "gateway_info.json")
            with open(gateway_file, 'w') as f:
                json.dump(gateway_data, f)
            
            # Load the gateway info
            test_module = DetectionModule(self.config)
            test_module._load_gateway_info()
            
            # Gateway MAC should be loaded correctly regardless of format
            self.assertEqual(test_module.gateway_info["mac"], mac_format)
            
            # Get gateway MACs should return a list with the MAC
            gateway_macs = test_module._get_gateway_macs()
            self.assertEqual(len(gateway_macs), 1)
            self.assertEqual(gateway_macs[0], mac_format)
    
    def test_ip_format_compatibility(self):
        """Test compatibility with different IP address formats"""
        # Test IP address formats
        ip_formats = [
            "192.168.1.1",        # IPv4 standard
            "::1",                # IPv6 localhost
            "fe80::1234:5678:9abc:def0",  # IPv6 link-local
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"  # IPv6 standard
        ]
        
        for ip_format in ip_formats:
            # Create gateway info with the test IP format
            gateway_data = self.sample_gateway.copy()
            gateway_data["ip"] = ip_format
            
            gateway_file = os.path.join(self.test_dir, "gateway_info.json")
            with open(gateway_file, 'w') as f:
                json.dump(gateway_data, f)
            
            # Load the gateway info
            test_module = DetectionModule(self.config)
            test_module._load_gateway_info()
            
            # Gateway IP should be loaded correctly regardless of format
            self.assertEqual(test_module.gateway_info["ip"], ip_format)
            
            # Get gateway IPs should return a list with the IP
            gateway_ips = test_module._get_gateway_ips()
            self.assertEqual(len(gateway_ips), 1)
            self.assertEqual(gateway_ips[0], ip_format)
    
    def test_unicode_handling(self):
        """Test handling of Unicode characters in file paths and data"""
        # Test with Unicode characters in path and data
        unicode_dir = os.path.join(self.test_dir, "测试路径")
        os.makedirs(unicode_dir, exist_ok=True)
        
        # Create gateway data with Unicode
        gateway_data = self.sample_gateway.copy()
        gateway_data["description"] = "网关设备"  # Chinese: "Gateway device"
        
        gateway_file = os.path.join(unicode_dir, "gateway_info.json")
        with open(gateway_file, 'w', encoding='utf-8') as f:
            json.dump(gateway_data, f, ensure_ascii=False)
        
        # Create config with Unicode path
        unicode_config = DetectionModuleConfig(
            storage_path=unicode_dir,
            default_gateway_ip="192.168.1.1",
            default_gateway_mac="00:11:22:33:44:55"
        )
        
        # Test loading gateway info from Unicode path
        test_module = DetectionModule(unicode_config)
        test_module._load_gateway_info()
        
        # Verify data loaded correctly
        self.assertEqual(test_module.gateway_info["ip"], gateway_data["ip"])
        self.assertEqual(test_module.gateway_info["mac"], gateway_data["mac"])
        self.assertEqual(test_module.gateway_info["description"], gateway_data["description"])
    
    @patch('os.makedirs')
    def test_directory_creation_error_handling(self, mock_makedirs):
        """Test error handling for directory creation issues"""
        # Mock os.makedirs to raise an exception
        mock_makedirs.side_effect = PermissionError("Permission denied")
        
        # Create module with storage path
        try:
            test_module = DetectionModule(self.config)
            # Should not raise an exception
            test_module._load_gateway_info()
            
            # Should fall back to default values
            self.assertEqual(test_module.gateway_info["ip"], self.config.default_gateway_ip)
            self.assertEqual(test_module.gateway_info["mac"], self.config.default_gateway_mac)
        except Exception as e:
            self.fail(f"Module initialization raised exception: {e}")


if __name__ == '__main__':
    unittest.main() 