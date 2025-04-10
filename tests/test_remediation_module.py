import unittest
from unittest.mock import patch, MagicMock
import os
import tempfile
import json
from datetime import datetime, timedelta
import time

from src.core.remediation_module import RemediationModule, RemediationConfig

class TestRemediationModule(unittest.TestCase):
    """Test cases for the RemediationModule class."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.temp_dir.name, "remediation_config.json")
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        
        # Create test config
        self.test_config = {
            "auto_block": True,
            "block_duration": 1800,
            "notify_admin": True,
            "notification_email": "test@example.com",
            "notification_threshold": 3,
            "whitelist": ["00:11:22:33:44:55:192.168.1.100"],
            "blocked_hosts": {}
        }
        
        with open(self.config_path, 'w') as f:
            json.dump(self.test_config, f)
            
        # Create module instance
        self.module = RemediationModule()
        
    def tearDown(self):
        """Clean up test environment."""
        self.temp_dir.cleanup()
        
    @patch('platform.system')
    def test_initialization(self, mock_system):
        """Test module initialization."""
        mock_system.return_value = 'Linux'
        module = RemediationModule()
        self.assertTrue(module.initialize())
        
    def test_whitelist_check(self):
        """Test whitelist checking."""
        # Test whitelisted host
        self.assertTrue(self.module.is_whitelisted("00:11:22:33:44:55", "192.168.1.100"))
        
        # Test non-whitelisted host
        self.assertFalse(self.module.is_whitelisted("AA:BB:CC:DD:EE:FF", "192.168.1.200"))
        
    @patch('subprocess.run')
    def test_block_host_linux(self, mock_run):
        """Test host blocking on Linux."""
        mock_run.return_value = MagicMock(returncode=0)
        
        # Test successful block
        self.assertTrue(self.module._block_host_linux("00:11:22:33:44:55", "192.168.1.100"))
        
        # Test failed block
        mock_run.side_effect = Exception("Failed")
        self.assertFalse(self.module._block_host_linux("00:11:22:33:44:55", "192.168.1.100"))
        
    @patch('subprocess.run')
    def test_block_host_windows(self, mock_run):
        """Test host blocking on Windows."""
        mock_run.return_value = MagicMock(returncode=0)
        
        # Test successful block
        self.assertTrue(self.module._block_host_windows("00:11:22:33:44:55", "192.168.1.100"))
        
        # Test failed block
        mock_run.side_effect = Exception("Failed")
        self.assertFalse(self.module._block_host_windows("00:11:22:33:44:55", "192.168.1.100"))
        
    def test_handle_detection(self):
        """Test detection handling."""
        # Test high threat with auto-block
        self.module.config.auto_block = True
        self.assertTrue(self.module.handle_detection(
            "AA:BB:CC:DD:EE:FF",
            "192.168.1.200",
            "high",
            {"reason": "Test detection"}
        ))
        
        # Test whitelisted host
        self.assertFalse(self.module.handle_detection(
            "00:11:22:33:44:55",
            "192.168.1.100",
            "high",
            {"reason": "Test detection"}
        ))
        
    @patch('smtplib.SMTP')
    def test_send_notification(self, mock_smtp):
        """Test notification sending."""
        # Test with valid email
        self.module.config.notification_email = "test@example.com"
        self.module._send_notification(
            "AA:BB:CC:DD:EE:FF",
            "192.168.1.200",
            "high",
            {"reason": "Test detection"}
        )
        mock_smtp.return_value.send_message.assert_called_once()
        
        # Test without email
        self.module.config.notification_email = ""
        self.module._send_notification(
            "AA:BB:CC:DD:EE:FF",
            "192.168.1.200",
            "high",
            {"reason": "Test detection"}
        )
        mock_smtp.return_value.send_message.assert_called_once()  # No new call
        
    def test_get_status(self):
        """Test status retrieval."""
        status = self.module.get_status()
        self.assertEqual(status['auto_block'], True)
        self.assertEqual(status['block_duration'], 1800)
        self.assertEqual(status['notify_admin'], True)
        self.assertEqual(status['notification_email'], "test@example.com")
        
    def test_get_blocked_hosts(self):
        """Test blocked hosts retrieval."""
        # Add a blocked host
        self.module.config.blocked_hosts = {
            "AA:BB:CC:DD:EE:FF": {
                "ip_address": "192.168.1.200",
                "reason": "Test block",
                "timestamp": time.time()
            }
        }
        
        blocked_hosts = self.module.get_blocked_hosts()
        self.assertEqual(len(blocked_hosts), 1)
        self.assertEqual(blocked_hosts[0]['mac_address'], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(blocked_hosts[0]['ip_address'], "192.168.1.200")
        
if __name__ == '__main__':
    unittest.main() 