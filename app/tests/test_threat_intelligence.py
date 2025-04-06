import unittest
from unittest.mock import patch, MagicMock, Mock
import os
import json
import threading
from datetime import datetime, timedelta

from app.components.threat_intelligence import ThreatIntelligence, get_threat_intelligence

class TestThreatIntelligence(unittest.TestCase):
    """Test suite for the ThreatIntelligence module."""

    def setUp(self):
        """Set up test environment before each test."""
        # Clear any existing singleton instance
        if hasattr(get_threat_intelligence, '_instance'):
            get_threat_intelligence._instance = None
        
        # Create a fresh instance for each test
        self.threat_intel = ThreatIntelligence()
        
        # Mock API keys for testing
        self.threat_intel.api_keys = {
            'abuseipdb': 'test_abuseipdb_key',
            'virustotal': 'test_virustotal_key',
            'otx': 'test_otx_key'
        }
        
        # Sample test data
        self.sample_ip = '192.168.1.100'
        self.sample_domain = 'malicious-example.com'
        self.sample_signature_id = 'ET-1000'

    def tearDown(self):
        """Clean up after each test."""
        # Stop any running update threads
        if self.threat_intel.running:
            self.threat_intel.stop_updates()
    
    def test_singleton_pattern(self):
        """Test that get_threat_intelligence returns the same instance each time."""
        instance1 = get_threat_intelligence()
        instance2 = get_threat_intelligence()
        self.assertIs(instance1, instance2)
    
    @patch('os.environ.get')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=unittest.mock.mock_open, read_data='{"abuseipdb": "test_key"}')
    def test_load_api_keys_from_env(self, mock_open, mock_exists, mock_environ_get):
        """Test loading API keys from environment variables."""
        # Set up environment variable mocks
        mock_environ_get.side_effect = lambda key, default: {
            'ABUSEIPDB_API_KEY': 'env_abuseipdb_key',
            'VIRUSTOTAL_API_KEY': 'env_virustotal_key',
            'OTX_API_KEY': 'env_otx_key'
        }.get(key, default)
        
        # Reset API keys
        self.threat_intel.api_keys = {}
        
        # Test loading keys
        self.threat_intel.load_api_keys()
        
        # Check keys were loaded from environment
        self.assertEqual(self.threat_intel.api_keys['abuseipdb'], 'env_abuseipdb_key')
        self.assertEqual(self.threat_intel.api_keys['virustotal'], 'env_virustotal_key')
        self.assertEqual(self.threat_intel.api_keys['otx'], 'env_otx_key')
        
        # Verify open was not called (as env vars were found)
        mock_open.assert_not_called()
    
    @patch('os.environ.get', return_value='')
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=unittest.mock.mock_open, 
           read_data='{"abuseipdb": "file_key", "virustotal": "file_key2", "otx": "file_key3"}')
    def test_load_api_keys_from_file(self, mock_open, mock_exists, mock_environ_get):
        """Test loading API keys from config file when env vars are not set."""
        # Reset API keys
        self.threat_intel.api_keys = {}
        
        # Test loading keys
        self.threat_intel.load_api_keys()
        
        # Check keys were loaded from file
        self.assertEqual(self.threat_intel.api_keys['abuseipdb'], 'file_key')
        self.assertEqual(self.threat_intel.api_keys['virustotal'], 'file_key2')
        self.assertEqual(self.threat_intel.api_keys['otx'], 'file_key3')
    
    def test_start_and_stop_updates(self):
        """Test starting and stopping the update thread."""
        # Test starting updates
        callback_mock = Mock()
        result = self.threat_intel.start_updates(callback_mock)
        self.assertTrue(result)
        self.assertTrue(self.threat_intel.running)
        self.assertIsNotNone(self.threat_intel.update_thread)
        self.assertTrue(self.threat_intel.update_thread.is_alive())
        self.assertEqual(self.threat_intel.callback, callback_mock)
        
        # Test stopping updates
        result = self.threat_intel.stop_updates()
        self.assertTrue(result)
        self.assertFalse(self.threat_intel.running)
        
        # Verify thread is terminated or wait for it
        self.threat_intel.update_thread.join(timeout=1.0)
        self.assertFalse(self.threat_intel.update_thread.is_alive())
    
    def test_start_updates_already_running(self):
        """Test that start_updates returns False if updates are already running."""
        # Start updates first time
        self.threat_intel.start_updates()
        
        # Try to start again
        result = self.threat_intel.start_updates()
        self.assertFalse(result)
    
    def test_stop_updates_not_running(self):
        """Test that stop_updates returns False if updates are not running."""
        # Ensure updates are not running
        self.threat_intel.running = False
        self.threat_intel.update_thread = None
        
        # Try to stop
        result = self.threat_intel.stop_updates()
        self.assertFalse(result)
    
    @patch('app.components.threat_intelligence.ThreatIntelligence.update_all')
    def test_update_loop_callback(self, mock_update_all):
        """Test that the update loop calls the callback with the update results."""
        # Set up mock update_all
        mock_update_all.return_value = (True, "Test message", {"key": "value"})
        
        # Set up callback mock
        callback_mock = Mock()
        
        # Start with short update interval for testing
        self.threat_intel.update_interval = 1
        self.threat_intel.start_updates(callback_mock)
        
        # Let it run for a moment
        import time
        time.sleep(0.5)
        
        # Stop updates
        self.threat_intel.stop_updates()
        
        # Verify callback was called with correct arguments
        callback_mock.assert_called_with(True, "Test message", {"key": "value"})
    
    @patch('requests.get')
    def test_update_from_abuseipdb(self, mock_get):
        """Test updating threat data from AbuseIPDB."""
        # Set up mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "ipAddress": "192.168.1.100",
                    "abuseConfidenceScore": 90,
                    "categories": [3, 4, 5]
                },
                {
                    "ipAddress": "192.168.1.101",
                    "abuseConfidenceScore": 95,
                    "categories": [1, 2]
                }
            ]
        }
        mock_get.return_value = mock_response
        
        # Call the update method
        success, stats = self.threat_intel._update_from_abuseipdb()
        
        # Verify the results
        self.assertTrue(success)
        self.assertEqual(stats['malicious_ips_updated'], 2)
        self.assertIn("192.168.1.100", self.threat_intel.malicious_ips)
        self.assertIn("192.168.1.101", self.threat_intel.malicious_ips)
        self.assertEqual(self.threat_intel.malicious_ips["192.168.1.100"]["score"], 90)
    
    def test_update_from_abuseipdb_no_api_key(self):
        """Test that update_from_abuseipdb returns False if no API key is available."""
        # Remove API key
        self.threat_intel.api_keys['abuseipdb'] = ''
        
        # Call the update method
        success, stats = self.threat_intel._update_from_abuseipdb()
        
        # Verify the results
        self.assertFalse(success)
        self.assertEqual(stats, {})
    
    @patch('app.components.threat_intelligence.ThreatIntelligence._update_from_abuseipdb')
    @patch('app.components.threat_intelligence.ThreatIntelligence._update_from_virustotal')
    @patch('app.components.threat_intelligence.ThreatIntelligence._update_from_otx')
    @patch('app.components.threat_intelligence.ThreatIntelligence._update_from_emerging_threats')
    def test_update_all(self, mock_emerging, mock_otx, mock_vt, mock_abuseipdb):
        """Test the update_all method that coordinates updates from all sources."""
        # Set up mock returns
        mock_abuseipdb.return_value = (True, {'malicious_ips_updated': 10})
        mock_vt.return_value = (True, {'malicious_ips_updated': 5, 'malicious_domains_updated': 15})
        mock_otx.return_value = (True, {'malicious_ips_updated': 8, 'attack_signatures_updated': 20})
        mock_emerging.return_value = (False, {})
        
        # Call update_all
        success, message, stats = self.threat_intel.update_all()
        
        # Verify results
        self.assertTrue(success)
        self.assertIn("Updated threat intelligence data", message)
        self.assertEqual(stats['malicious_ips_updated'], 23)  # 10 + 5 + 8
        self.assertEqual(stats['malicious_domains_updated'], 15)
        self.assertEqual(stats['attack_signatures_updated'], 20)
        self.assertEqual(len(stats['sources_successful']), 3)
        self.assertEqual(len(stats['sources_failed']), 1)
        self.assertIn('abuseipdb', stats['sources_successful'])
        self.assertIn('virustotal', stats['sources_successful'])
        self.assertIn('otx', stats['sources_successful'])
        self.assertIn('emergingthreats', stats['sources_failed'])
    
    def test_is_ip_malicious(self):
        """Test checking if an IP is malicious."""
        # Set up some test data
        self.threat_intel.malicious_ips = {
            "192.168.1.100": {
                "score": 90,
                "categories": [3, 4, 5],
                "source": "abuseipdb",
                "last_updated": datetime.now()
            }
        }
        
        # Test with malicious IP
        result, details = self.threat_intel.get_ip_threat_info("192.168.1.100")
        self.assertTrue(result)
        self.assertEqual(details["score"], 90)
        
        # Test with non-malicious IP
        result, details = self.threat_intel.get_ip_threat_info("192.168.1.200")
        self.assertFalse(result)
        self.assertEqual(details, {})
    
    def test_is_domain_malicious(self):
        """Test checking if a domain is malicious."""
        # Set up some test data
        self.threat_intel.malicious_domains = {
            "malicious-example.com": {
                "score": 85,
                "categories": ["phishing", "malware"],
                "source": "virustotal",
                "last_updated": datetime.now()
            }
        }
        
        # Test with malicious domain
        result, details = self.threat_intel.get_domain_threat_info("malicious-example.com")
        self.assertTrue(result)
        self.assertEqual(details["score"], 85)
        
        # Test with non-malicious domain
        result, details = self.threat_intel.get_domain_threat_info("example.com")
        self.assertFalse(result)
        self.assertEqual(details, {})
    
    def test_get_attack_signatures(self):
        """Test retrieving attack signatures."""
        # Set up test data
        self.threat_intel.attack_signatures = {
            "ET-1000": {
                "pattern": "test pattern",
                "description": "Test signature",
                "severity": "high",
                "source": "emerging_threats"
            },
            "ET-1001": {
                "pattern": "another pattern",
                "description": "Another test",
                "severity": "medium",
                "source": "emerging_threats"
            }
        }
        
        # Test retrieving all signatures
        signatures = self.threat_intel.get_attack_signatures()
        self.assertEqual(len(signatures), 2)
        
        # Test filtering by severity
        signatures = self.threat_intel.get_attack_signatures(severity="high")
        self.assertEqual(len(signatures), 1)
        self.assertEqual(signatures["ET-1000"]["description"], "Test signature")

if __name__ == '__main__':
    unittest.main() 