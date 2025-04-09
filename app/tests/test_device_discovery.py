import unittest
from unittest.mock import patch, MagicMock, call
import os
import json
from datetime import datetime

from app.components.device_discovery import DeviceDiscovery

class TestDeviceDiscovery(unittest.TestCase):
    def setUp(self):
        self.discovery = DeviceDiscovery()
        
        # Mock the network scanner
        self.discovery.network_scanner = MagicMock()
        
        # Sample test devices
        self.test_devices = [
            {
                'ip_address': '192.168.1.1',
                'mac_address': '00:11:22:33:44:55',
                'hostname': 'gateway.local',
                'vendor': 'ACME Router Inc.',
                'is_gateway': True
            },
            {
                'ip_address': '192.168.1.100',
                'mac_address': 'aa:bb:cc:dd:ee:ff',
                'hostname': 'desktop-1',
                'vendor': 'Dell Inc.',
                'is_gateway': False
            },
            {
                'ip_address': '192.168.1.101',
                'mac_address': '11:22:33:44:55:66',
                'hostname': 'laptop-1',
                'vendor': 'Apple Inc.',
                'is_gateway': False
            }
        ]
        
    def test_initialization(self):
        """Test that the discovery module initializes correctly."""
        self.assertFalse(self.discovery.discovery_in_progress)
        self.assertIsNone(self.discovery.current_scan_id)
        self.assertEqual(self.discovery.devices, [])
        
    def test_discover_devices_success(self):
        """Test successful device discovery."""
        # Mock network scanner methods
        self.discovery.network_scanner.timeout = 5
        self.discovery.network_scanner.get_network_range.return_value = "192.168.1.0/24"
        self.discovery.network_scanner.start_scan.return_value = True
        self.discovery.network_scanner.scanning = False
        
        # Mock saving results
        self.discovery._save_discovery_results = MagicMock()
        
        # Create a callback to simulate discovery process
        def fake_start_scan(callback=None):
            """Simulate a network scan."""
            if callback:
                callback(self.test_devices, "Scan completed")
            return True
        
        self.discovery.network_scanner.start_scan.side_effect = fake_start_scan
        
        # Mock the scan progress callback
        mock_callback = MagicMock()
        
        # Call discover_devices with a subnet
        scan_id, devices = self.discovery.discover_devices(
            subnet="192.168.1.0/24",
            timeout=10,
            progress_callback=mock_callback
        )
        
        # Verify the results
        self.assertIsNotNone(scan_id)
        self.assertEqual(len(devices), 3)
        self.assertEqual(devices, self.test_devices)
        self.assertEqual(self.discovery.devices, self.test_devices)
        self.assertFalse(self.discovery.discovery_in_progress)
        
        # Verify network scanner methods were called correctly
        self.discovery.network_scanner.start_scan.assert_called_once()
        self.discovery._save_discovery_results.assert_called_once_with(scan_id, self.test_devices)
        
        # Original timeout should be restored
        self.assertEqual(self.discovery.network_scanner.timeout, 5)
        
    def test_discover_devices_auto_subnet(self):
        """Test device discovery with auto subnet detection."""
        # Mock network scanner methods
        self.discovery.network_scanner.timeout = 5
        self.discovery.network_scanner.get_network_range.return_value = "192.168.1.0/24"
        self.discovery.network_scanner.start_scan.return_value = True
        self.discovery.network_scanner.scanning = False
        
        # Mock saving results
        self.discovery._save_discovery_results = MagicMock()
        
        # Create a callback to simulate discovery process
        def fake_start_scan(callback=None):
            """Simulate a network scan."""
            if callback:
                callback(self.test_devices, "Scan completed")
            return True
        
        self.discovery.network_scanner.start_scan.side_effect = fake_start_scan
        
        # Call discover_devices without specifying subnet
        scan_id, devices = self.discovery.discover_devices(timeout=10)
        
        # Verify the results
        self.assertIsNotNone(scan_id)
        self.assertEqual(len(devices), 3)
        self.assertEqual(devices, self.test_devices)
        self.assertEqual(self.discovery.devices, self.test_devices)
        
        # Verify network scanner methods were called correctly
        self.discovery.network_scanner.get_network_range.assert_called_once()
        self.discovery.network_scanner.start_scan.assert_called_once()
        
    def test_discover_devices_invalid_subnet(self):
        """Test device discovery with an invalid subnet."""
        # Call discover_devices with an invalid subnet
        scan_id, devices = self.discovery.discover_devices(subnet="invalid_subnet")
        
        # Verify the results
        self.assertIsNone(scan_id)
        self.assertEqual(devices, [])
        self.assertFalse(self.discovery.discovery_in_progress)
        
        # Network scanner methods should not have been called
        self.discovery.network_scanner.start_scan.assert_not_called()
        
    def test_discover_devices_failed_scan(self):
        """Test device discovery when the network scan fails to start."""
        # Mock network scanner methods
        self.discovery.network_scanner.get_network_range.return_value = "192.168.1.0/24"
        self.discovery.network_scanner.start_scan.return_value = False
        
        # Call discover_devices
        scan_id, devices = self.discovery.discover_devices()
        
        # Verify the results
        self.assertIsNone(scan_id)
        self.assertEqual(devices, [])
        self.assertFalse(self.discovery.discovery_in_progress)
        
    def test_discover_devices_already_in_progress(self):
        """Test device discovery when a scan is already in progress."""
        # Set discovery in progress
        self.discovery.discovery_in_progress = True
        
        # Call discover_devices
        scan_id, devices = self.discovery.discover_devices()
        
        # Verify the results
        self.assertIsNone(scan_id)
        self.assertEqual(devices, [])
        
        # Network scanner methods should not have been called
        self.discovery.network_scanner.start_scan.assert_not_called()
        
    def test_stop_discovery_success(self):
        """Test stopping device discovery successfully."""
        # Set up discovery in progress
        self.discovery.discovery_in_progress = True
        self.discovery.network_scanner.stop_scan.return_value = True
        
        # Call stop_discovery
        result = self.discovery.stop_discovery()
        
        # Verify the results
        self.assertTrue(result)
        self.assertFalse(self.discovery.discovery_in_progress)
        self.discovery.network_scanner.stop_scan.assert_called_once()
        
    def test_stop_discovery_not_in_progress(self):
        """Test stopping device discovery when no scan is in progress."""
        # Set up discovery not in progress
        self.discovery.discovery_in_progress = False
        
        # Call stop_discovery
        result = self.discovery.stop_discovery()
        
        # Verify the results
        self.assertFalse(result)
        self.discovery.network_scanner.stop_scan.assert_not_called()
        
    def test_get_discovery_details_current_scan(self):
        """Test getting details for the current scan."""
        # Set up current scan
        self.discovery.current_scan_id = "scan_20250406_120000"
        self.discovery.devices = self.test_devices
        self.discovery.last_scan_timestamp = datetime.now()
        
        # Call get_discovery_details
        details = self.discovery.get_discovery_details("scan_20250406_120000")
        
        # Verify the results
        self.assertEqual(details['scan_id'], "scan_20250406_120000")
        self.assertEqual(details['device_count'], 3)
        self.assertEqual(details['devices'], self.test_devices)
        
    @patch('os.path.exists')
    @patch('json.load')
    @patch('builtins.open')
    def test_get_discovery_details_saved_scan(self, mock_open, mock_json_load, mock_path_exists):
        """Test getting details for a saved scan."""
        # Set up mocks
        mock_path_exists.return_value = True
        mock_json_load.return_value = {
            'scan_id': 'scan_20250405_120000',
            'timestamp': '2025-04-05T12:00:00',
            'device_count': 3,
            'devices': self.test_devices
        }
        
        # Mock the _get_results_dir method
        self.discovery._get_results_dir = MagicMock(return_value="/path/to/results")
        
        # Call get_discovery_details for a different scan
        details = self.discovery.get_discovery_details("scan_20250405_120000")
        
        # Verify the results
        self.assertEqual(details['scan_id'], "scan_20250405_120000")
        self.assertEqual(details['device_count'], 3)
        self.assertEqual(details['devices'], self.test_devices)
        
        # Verify file operations
        mock_path_exists.assert_called_once()
        mock_open.assert_called_once()
        mock_json_load.assert_called_once()
        
    def test_get_discovery_details_scan_not_found(self):
        """Test getting details for a scan that doesn't exist."""
        # Set up current scan different from requested
        self.discovery.current_scan_id = "scan_20250406_120000"
        
        # Mock the _get_results_dir method and os.path.exists
        self.discovery._get_results_dir = MagicMock(return_value="/path/to/results")
        with patch('os.path.exists', return_value=False):
            # Call get_discovery_details for a non-existent scan
            details = self.discovery.get_discovery_details("nonexistent_scan")
            
            # Verify the results
            self.assertIn('error', details)
            self.assertEqual(details['error'], "Scan nonexistent_scan not found")
        
    def test_classify_devices(self):
        """Test device classification."""
        # Create test devices with various vendors
        devices = [
            # Gateway
            {
                'ip_address': '192.168.1.1',
                'mac_address': '00:11:22:33:44:55',
                'vendor': 'ACME Router Inc.',
                'is_gateway': True
            },
            # Router
            {
                'ip_address': '192.168.1.2',
                'mac_address': 'aa:bb:cc:dd:ee:ff',
                'vendor': 'Cisco Systems',
                'is_gateway': False
            },
            # Server
            {
                'ip_address': '192.168.1.3',
                'mac_address': '11:22:33:44:55:66',
                'vendor': 'VMware, Inc.',
                'is_gateway': False
            },
            # Mobile
            {
                'ip_address': '192.168.1.4',
                'mac_address': '22:33:44:55:66:77',
                'vendor': 'Apple, Inc.',
                'is_gateway': False
            },
            # Desktop
            {
                'ip_address': '192.168.1.5',
                'mac_address': '33:44:55:66:77:88',
                'vendor': 'Dell Inc.',
                'is_gateway': False
            },
            # IoT
            {
                'ip_address': '192.168.1.6',
                'mac_address': '44:55:66:77:88:99',
                'vendor': 'Nest Labs Inc.',
                'is_gateway': False
            },
            # Unknown
            {
                'ip_address': '192.168.1.7',
                'mac_address': '55:66:77:88:99:aa',
                'vendor': 'Unknown Vendor',
                'is_gateway': False
            }
        ]
        
        # Call classify_devices
        categories = self.discovery.classify_devices(devices)
        
        # Verify the results
        self.assertEqual(len(categories['gateway']), 1)
        self.assertEqual(len(categories['router']), 1)
        self.assertEqual(len(categories['server']), 1)
        self.assertEqual(len(categories['mobile']), 1)
        self.assertEqual(len(categories['desktop']), 1)
        self.assertEqual(len(categories['iot']), 1)
        self.assertEqual(len(categories['unknown']), 1)
        
        # Check specific classifications
        self.assertEqual(categories['gateway'][0]['ip_address'], '192.168.1.1')
        self.assertEqual(categories['router'][0]['ip_address'], '192.168.1.2')
        self.assertEqual(categories['server'][0]['ip_address'], '192.168.1.3')
        self.assertEqual(categories['mobile'][0]['ip_address'], '192.168.1.4')
        self.assertEqual(categories['desktop'][0]['ip_address'], '192.168.1.5')
        self.assertEqual(categories['iot'][0]['ip_address'], '192.168.1.6')
        self.assertEqual(categories['unknown'][0]['ip_address'], '192.168.1.7')
        
    def test_get_last_discovery(self):
        """Test getting the results of the last discovery scan."""
        # Case 1: Devices are already in memory
        self.discovery.devices = self.test_devices
        
        # Call get_last_discovery
        devices = self.discovery.get_last_discovery()
        
        # Verify the results
        self.assertEqual(devices, self.test_devices)
        self.discovery.network_scanner.get_last_scan_results.assert_not_called()
        
        # Case 2: No devices in memory, fall back to network scanner
        self.discovery.devices = []
        self.discovery.network_scanner.get_last_scan_results.return_value = self.test_devices
        
        # Call get_last_discovery
        devices = self.discovery.get_last_discovery()
        
        # Verify the results
        self.assertEqual(devices, self.test_devices)
        self.discovery.network_scanner.get_last_scan_results.assert_called_once()
        
    @patch('os.makedirs')
    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    @patch('json.dump')
    def test_save_discovery_results(self, mock_json_dump, mock_open, mock_makedirs):
        """Test saving discovery results to a file."""
        # Mock the _get_results_dir method
        self.discovery._get_results_dir = MagicMock(return_value="/path/to/results")
        
        # Mock config to enable saving results
        self.discovery.config = {
            "scanner.save_results": True
        }
        
        # Call _save_discovery_results
        self.discovery._save_discovery_results("test_scan", self.test_devices)
        
        # Verify the results
        mock_makedirs.assert_called_once()
        mock_open.assert_called_once_with('/path/to/results/test_scan.json', 'w')
        mock_json_dump.assert_called_once()
        
        # Verify the data being saved
        saved_data = mock_json_dump.call_args[0][0]
        self.assertEqual(saved_data['scan_id'], "test_scan")
        self.assertEqual(saved_data['device_count'], 3)
        self.assertEqual(saved_data['devices'], self.test_devices)
        
    def test_save_discovery_results_disabled(self):
        """Test that results are not saved when saving is disabled."""
        # Mock the _get_results_dir method
        self.discovery._get_results_dir = MagicMock()
        
        # Mock config to disable saving results
        self.discovery.config = {
            "scanner.save_results": False
        }
        
        # Call _save_discovery_results
        self.discovery._save_discovery_results("test_scan", self.test_devices)
        
        # Verify the results
        self.discovery._get_results_dir.assert_not_called()
        
    @patch('os.path.expanduser')
    @patch('os.makedirs')
    def test_get_results_dir(self, mock_makedirs, mock_expanduser):
        """Test getting or creating the results directory."""
        # Mock expanduser to return a fixed path
        mock_expanduser.return_value = "/home/user"
        
        # Call _get_results_dir
        results_dir = self.discovery._get_results_dir()
        
        # Verify the results
        self.assertEqual(results_dir, "/home/user/.arpguard/scan_results")
        mock_makedirs.assert_called_once_with("/home/user/.arpguard/scan_results", exist_ok=True)

if __name__ == '__main__':
    unittest.main() 