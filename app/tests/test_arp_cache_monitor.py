import unittest
from unittest.mock import patch, MagicMock, call
import time
from datetime import datetime, timedelta
import platform

from app.components.arp_cache_monitor import ARPCacheMonitor

class TestARPCacheMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = ARPCacheMonitor()
        
        # Mock the network scanner's get_default_gateway method
        self.monitor.network_scanner.get_default_gateway = MagicMock(
            return_value=('192.168.1.1', 'eth0')
        )
        
        # Initialize mock data
        self.mock_gateway_ip = '192.168.1.1'
        self.mock_gateway_mac = '00:11:22:33:44:55'
        self.mock_devices = [
            {
                'ip_address': '192.168.1.1',
                'mac_address': self.mock_gateway_mac,
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
        
        # Mock the network scanner's start_scan method
        self.monitor.network_scanner.start_scan = MagicMock()
        self.monitor.network_scanner.start_scan.side_effect = self._mock_scan_callback
        
        # Mock the network scanner's scanning property
        self.monitor.network_scanner.scanning = False
        
    def _mock_scan_callback(self, callback):
        """Simulate a network scan by calling the callback with mock data."""
        callback(self.mock_devices, "Mock scan completed")
        return True
        
    def test_initialization(self):
        """Test that the monitor initializes correctly."""
        self.assertFalse(self.monitor.monitoring)
        self.assertEqual(self.monitor.gateway_ip, '192.168.1.1')
        self.assertEqual(self.monitor.gateway_interface, 'eth0')
        
    def test_set_alert_thresholds(self):
        """Test that alert thresholds are set correctly based on level."""
        # Test low level
        self.monitor.set_alert_thresholds('low')
        self.assertEqual(self.monitor.mac_change_threshold, 3)
        self.assertEqual(self.monitor.gateway_impersonation_score, 7)
        self.assertEqual(self.monitor.check_interval, 10)
        
        # Test high level
        self.monitor.set_alert_thresholds('high')
        self.assertEqual(self.monitor.mac_change_threshold, 1)
        self.assertEqual(self.monitor.gateway_impersonation_score, 3)
        self.assertEqual(self.monitor.check_interval, 2)
        
        # Test medium level (default)
        self.monitor.set_alert_thresholds('medium')
        self.assertEqual(self.monitor.mac_change_threshold, 2)
        self.assertEqual(self.monitor.gateway_impersonation_score, 5)
        self.assertEqual(self.monitor.check_interval, 5)
        
    def test_initialize_known_devices(self):
        """Test initializing known devices from network scan."""
        # Call the method
        self.monitor._initialize_known_devices()
        
        # Check the known_devices dict is populated
        self.assertEqual(len(self.monitor.known_devices), 3)
        self.assertEqual(self.monitor.known_devices['192.168.1.1'], self.mock_gateway_mac)
        self.assertEqual(self.monitor.known_devices['192.168.1.100'], 'aa:bb:cc:dd:ee:ff')
        self.assertEqual(self.monitor.known_devices['192.168.1.101'], '11:22:33:44:55:66')
        
    @patch('subprocess.check_output')
    def test_read_arp_cache_windows(self, mock_subprocess):
        """Test reading the ARP cache on Windows."""
        # Mock platform.system to return 'Windows'
        with patch('platform.system', return_value='Windows'):
            # Mock subprocess output for Windows arp -a command
            mock_subprocess.return_value = b'''
Interface: 192.168.1.100 --- 0x4
  Internet Address      Physical Address      Type
  192.168.1.1           00-11-22-33-44-55     dynamic
  192.168.1.101         11-22-33-44-55-66     dynamic
  192.168.1.102         aa-bb-cc-dd-ee-ff     static
'''
            
            # Call the method
            arp_entries = self.monitor._read_arp_cache()
            
            # Verify the results
            self.assertEqual(len(arp_entries), 3)
            self.assertEqual(arp_entries[0]['ip_address'], '192.168.1.1')
            self.assertEqual(arp_entries[0]['mac_address'], '00:11:22:33:44:55')
            self.assertEqual(arp_entries[0]['type'], 'dynamic')
            
            self.assertEqual(arp_entries[2]['ip_address'], '192.168.1.102')
            self.assertEqual(arp_entries[2]['mac_address'], 'aa:bb:cc:dd:ee:ff')
            self.assertEqual(arp_entries[2]['type'], 'static')
            
    @patch('subprocess.check_output')
    def test_read_arp_cache_linux(self, mock_subprocess):
        """Test reading the ARP cache on Linux."""
        # Mock platform.system to return 'Linux'
        with patch('platform.system', return_value='Linux'):
            # Mock subprocess output for Linux 'ip neigh' command
            mock_subprocess.return_value = b'''
192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
192.168.1.101 dev eth0 lladdr 11:22:33:44:55:66 STALE
192.168.1.102 dev eth0 lladdr aa:bb:cc:dd:ee:ff PERMANENT
'''
            
            # Call the method
            arp_entries = self.monitor._read_arp_cache()
            
            # Verify the results
            self.assertEqual(len(arp_entries), 3)
            self.assertEqual(arp_entries[0]['ip_address'], '192.168.1.1')
            self.assertEqual(arp_entries[0]['mac_address'], '00:11:22:33:44:55')
            self.assertEqual(arp_entries[0]['type'], 'reachable')
            self.assertEqual(arp_entries[0]['interface'], 'eth0')
            
            self.assertEqual(arp_entries[2]['ip_address'], '192.168.1.102')
            self.assertEqual(arp_entries[2]['mac_address'], 'aa:bb:cc:dd:ee:ff')
            self.assertEqual(arp_entries[2]['type'], 'permanent')
            self.assertEqual(arp_entries[2]['interface'], 'eth0')
            
    def test_analyze_arp_cache_normal(self):
        """Test ARP cache analysis with normal entries."""
        # Prep the monitor with known devices
        self.monitor._initialize_known_devices()
        
        # Create mock current cache with normal entries
        current_cache = [
            {
                'ip_address': '192.168.1.1',
                'mac_address': self.mock_gateway_mac,
                'type': 'dynamic',
                'interface': 'eth0',
                'time': datetime.now()
            },
            {
                'ip_address': '192.168.1.100',
                'mac_address': 'aa:bb:cc:dd:ee:ff',
                'type': 'dynamic',
                'interface': 'eth0',
                'time': datetime.now()
            }
        ]
        
        # Call the method
        anomalies = self.monitor._analyze_arp_cache(current_cache)
        
        # Verify no anomalies with normal cache
        self.assertEqual(len(anomalies), 0)
        
    def test_analyze_arp_cache_gateway_impersonation(self):
        """Test ARP cache analysis with gateway impersonation."""
        # Prep the monitor with known devices
        self.monitor._initialize_known_devices()
        
        # Mock gateway MAC
        self.monitor._get_gateway_mac = MagicMock(return_value=self.mock_gateway_mac)
        
        # Create mock current cache with gateway impersonation
        current_cache = [
            {
                'ip_address': '192.168.1.1',
                'mac_address': self.mock_gateway_mac,
                'type': 'dynamic',
                'interface': 'eth0',
                'time': datetime.now()
            },
            {
                'ip_address': '192.168.1.100',
                'mac_address': 'aa:bb:cc:dd:ee:ff',
                'type': 'dynamic',
                'interface': 'eth0',
                'time': datetime.now()
            },
            {
                'ip_address': '192.168.1.200',
                'mac_address': self.mock_gateway_mac,  # Same MAC as gateway!
                'type': 'dynamic',
                'interface': 'eth0',
                'time': datetime.now()
            }
        ]
        
        # Call the method
        anomalies = self.monitor._analyze_arp_cache(current_cache)
        
        # Verify gateway impersonation is detected
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]['type'], 'gateway_impersonation')
        self.assertEqual(anomalies[0]['severity'], 'high')
        self.assertEqual(anomalies[0]['ip_address'], '192.168.1.200')
        self.assertEqual(anomalies[0]['mac_address'], self.mock_gateway_mac)
        
    def test_analyze_arp_cache_mac_address_conflict(self):
        """Test ARP cache analysis with MAC address conflict."""
        # Prep the monitor with known devices
        self.monitor._initialize_known_devices()
        
        # Create mock current cache with MAC conflict
        current_cache = [
            {
                'ip_address': '192.168.1.100',  # This IP should have mac aa:bb:cc:dd:ee:ff
                'mac_address': 'ff:ee:dd:cc:bb:aa',  # Different MAC!
                'type': 'dynamic',
                'interface': 'eth0',
                'time': datetime.now()
            }
        ]
        
        # Call the method
        anomalies = self.monitor._analyze_arp_cache(current_cache)
        
        # Verify MAC conflict is detected
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]['type'], 'mac_address_conflict')
        self.assertEqual(anomalies[0]['severity'], 'medium')
        self.assertEqual(anomalies[0]['ip_address'], '192.168.1.100')
        self.assertEqual(anomalies[0]['mac_address'], 'ff:ee:dd:cc:bb:aa')
        
    def test_analyze_arp_cache_gateway_mac_change(self):
        """Test ARP cache analysis with gateway MAC change."""
        # Prep the monitor with known devices
        self.monitor._initialize_known_devices()
        
        # Create mock current cache with gateway MAC change
        current_cache = [
            {
                'ip_address': '192.168.1.1',  # Gateway IP
                'mac_address': 'ff:ee:dd:cc:bb:aa',  # Different MAC than expected!
                'type': 'dynamic',
                'interface': 'eth0',
                'time': datetime.now()
            }
        ]
        
        # Call the method
        anomalies = self.monitor._analyze_arp_cache(current_cache)
        
        # Verify gateway MAC change is detected
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]['type'], 'gateway_mac_change')
        self.assertEqual(anomalies[0]['severity'], 'high')
        self.assertEqual(anomalies[0]['ip_address'], '192.168.1.1')
        self.assertEqual(anomalies[0]['mac_address'], 'ff:ee:dd:cc:bb:aa')
        
    def test_start_stop_monitoring(self):
        """Test starting and stopping the monitoring thread."""
        # Mock the monitor thread to avoid actually running it
        with patch('threading.Thread') as mock_thread:
            # Mock thread instance
            mock_thread_instance = MagicMock()
            mock_thread.return_value = mock_thread_instance
            
            # Start monitoring
            result = self.monitor.start_monitoring(
                interface='eth0',
                alert_level='medium',
                duration=60
            )
            
            # Check monitoring started correctly
            self.assertTrue(result)
            self.assertTrue(self.monitor.monitoring)
            mock_thread.assert_called_once()
            mock_thread_instance.start.assert_called_once()
            
            # Stop monitoring
            stop_result = self.monitor.stop_monitoring()
            
            # Check monitoring stopped correctly
            self.assertTrue(stop_result)
            self.assertFalse(self.monitor.monitoring)
            mock_thread_instance.join.assert_called_once()
            
    def test_process_anomaly(self):
        """Test processing an anomaly and raising an alert."""
        # Create a mock callback
        mock_callback = MagicMock()
        self.monitor.alert_callback = mock_callback
        
        # Create a mock anomaly
        anomaly = {
            'type': 'gateway_impersonation',
            'severity': 'high',
            'ip_address': '192.168.1.200',
            'mac_address': self.mock_gateway_mac,
            'time': datetime.now(),
            'details': 'Mock anomaly details'
        }
        
        # Process the anomaly
        self.monitor._process_anomaly(anomaly)
        
        # Verify alert was added and callback was called
        self.assertEqual(len(self.monitor.alerts), 1)
        self.assertEqual(self.monitor.alerts[0], anomaly)
        mock_callback.assert_called_once_with(anomaly)
        
    def test_monitor_thread(self):
        """Test the monitoring thread function with simulated ARP cache."""
        # Mock dependencies
        self.monitor._read_arp_cache = MagicMock()
        self.monitor._analyze_arp_cache = MagicMock()
        mock_callback = MagicMock()
        
        # Setup mock returns
        mock_cache = [{'ip_address': '192.168.1.100', 'mac_address': 'aa:bb:cc:dd:ee:ff'}]
        mock_anomalies = [{'type': 'test_anomaly', 'severity': 'medium'}]
        self.monitor._read_arp_cache.return_value = mock_cache
        self.monitor._analyze_arp_cache.return_value = mock_anomalies
        
        # Mock processing
        self.monitor._process_anomaly = MagicMock()
        
        # Start monitoring thread with a short duration
        self.monitor.monitoring = True
        
        # Run the monitoring thread function directly with a finite duration
        self.monitor._monitor_thread('eth0', 1, mock_callback)
        
        # Verify the thread completed its tasks
        self.monitor._read_arp_cache.assert_called()
        self.monitor._analyze_arp_cache.assert_called_with(mock_cache)
        self.monitor._process_anomaly.assert_called_with(mock_anomalies[0])
        mock_callback.assert_called()
        
if __name__ == '__main__':
    unittest.main() 