import unittest
from unittest.mock import patch, MagicMock, call
import threading
from datetime import datetime

from app.components.arp_spoofer import ARPSpoofer

class TestARPSpoofer(unittest.TestCase):
    """Tests for the ARPSpoofer component"""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Create a mock config for testing
        self.config_patcher = patch('app.components.arp_spoofer.get_config')
        self.mock_config = self.config_patcher.start()
        self.mock_config.return_value = {
            "spoofer.packet_interval": 0.1,  # Fast interval for testing
            "spoofer.max_packets": 5  # Small history size for testing
        }
        
        # Create the ARPSpoofer instance for testing
        self.spoofer = ARPSpoofer()
        
    def tearDown(self):
        """Tear down test fixtures after each test method."""
        self.config_patcher.stop()
        
        # Ensure spoofing is stopped
        if hasattr(self, 'spoofer') and self.spoofer.running:
            self.spoofer.stop_spoofing(restore=False)
    
    @patch('app.components.arp_spoofer.getmacbyip')
    @patch('app.components.arp_spoofer.send')
    def test_start_spoofing_success(self, mock_send, mock_getmacbyip):
        """Test successful start of ARP spoofing."""
        # Mock the MAC address lookup
        mock_getmacbyip.return_value = "00:11:22:33:44:55"
        
        # Mock callback function
        callback = MagicMock()
        packet_callback = MagicMock()
        
        # Start spoofing
        result = self.spoofer.start_spoofing(
            "192.168.1.100", 
            "192.168.1.1", 
            interval=0.01,  # Very short interval for testing
            callback=callback,
            packet_callback=packet_callback
        )
        
        # Verify result
        self.assertTrue(result)
        self.assertTrue(self.spoofer.running)
        
        # Allow some time for packets to be sent
        threading.Event().wait(0.05)
        
        # Stop spoofing
        self.spoofer.stop_spoofing(restore=False)
        
        # Verify that packets were sent
        self.assertGreater(self.spoofer.packets_sent, 0)
        
        # Verify that callbacks were called
        callback.assert_called()
        packet_callback.assert_called()
        
        # Verify that send was called
        mock_send.assert_called()
    
    @patch('app.components.arp_spoofer.getmacbyip')
    def test_start_spoofing_already_running(self, mock_getmacbyip):
        """Test starting spoofing when already running."""
        # Mock the MAC address lookup
        mock_getmacbyip.return_value = "00:11:22:33:44:55"
        
        # Start spoofing once
        self.spoofer.start_spoofing("192.168.1.100", "192.168.1.1", interval=0.01)
        
        # Try to start again
        result = self.spoofer.start_spoofing("192.168.1.101", "192.168.1.1", interval=0.01)
        
        # Verify that the second attempt fails
        self.assertFalse(result)
        
        # Clean up
        self.spoofer.stop_spoofing(restore=False)
    
    @patch('app.components.arp_spoofer.getmacbyip')
    def test_start_spoofing_mac_lookup_failure(self, mock_getmacbyip):
        """Test MAC address lookup failure during spoofing start."""
        # Mock the MAC address lookup to fail
        mock_getmacbyip.return_value = None
        
        # Mock callback function
        callback = MagicMock()
        
        # Start spoofing
        result = self.spoofer.start_spoofing("192.168.1.100", "192.168.1.1", callback=callback)
        
        # Verify initial result
        self.assertTrue(result)
        
        # Allow some time for the thread to run and fail
        threading.Event().wait(0.1)
        
        # Verify that callback was called with failure
        callback.assert_called_with(False, "Failed to get MAC address for 192.168.1.100")
    
    def test_stop_spoofing_not_running(self):
        """Test stopping spoofing when not running."""
        # Try to stop when not running
        result = self.spoofer.stop_spoofing()
        
        # Verify that the attempt fails
        self.assertFalse(result)
    
    @patch('app.components.arp_spoofer.getmacbyip')
    @patch('app.components.arp_spoofer.send')
    def test_stop_spoofing_with_restore(self, mock_send, mock_getmacbyip):
        """Test stopping spoofing with ARP table restoration."""
        # Mock the MAC address lookup
        mock_getmacbyip.return_value = "00:11:22:33:44:55"
        
        # Start spoofing
        self.spoofer.start_spoofing("192.168.1.100", "192.168.1.1", interval=0.01)
        
        # Allow some time for packets to be sent
        threading.Event().wait(0.05)
        
        # Reset the send mock to check restoration calls
        mock_send.reset_mock()
        
        # Stop spoofing with restore
        result = self.spoofer.stop_spoofing(restore=True)
        
        # Verify result
        self.assertTrue(result)
        self.assertFalse(self.spoofer.running)
        
        # Verify that send was called multiple times for restoration
        self.assertGreaterEqual(mock_send.call_count, 5)
    
    @patch('app.components.arp_spoofer.getmacbyip')
    @patch('app.components.arp_spoofer.send')
    def test_packet_history_management(self, mock_send, mock_getmacbyip):
        """Test packet history management."""
        # Mock the MAC address lookup
        mock_getmacbyip.return_value = "00:11:22:33:44:55"
        
        # Start spoofing
        self.spoofer.start_spoofing("192.168.1.100", "192.168.1.1", interval=0.01)
        
        # Allow time for multiple packets to be sent
        threading.Event().wait(0.1)
        
        # Stop spoofing
        self.spoofer.stop_spoofing(restore=False)
        
        # Get packet history
        history = self.spoofer.get_packet_history()
        
        # Verify that history was recorded
        self.assertGreater(len(history), 0)
        
        # Verify that history was limited to max_history
        self.assertLessEqual(len(history), self.spoofer.max_history)
        
        # Verify packet structure
        packet = history[0]
        self.assertIsInstance(packet['time'], datetime)
        self.assertEqual(packet['src'], "192.168.1.1")
        self.assertEqual(packet['dst'], "192.168.1.100")
        self.assertEqual(packet['type'], "ARP")
        self.assertEqual(packet['direction'], "sent")

if __name__ == '__main__':
    unittest.main() 