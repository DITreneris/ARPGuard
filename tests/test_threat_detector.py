import unittest
from unittest.mock import patch, MagicMock, Mock, call
import threading
from datetime import datetime

from scapy.all import ARP

from app.components.threat_detector import ThreatDetector

class TestThreatDetector(unittest.TestCase):
    """Tests for the ThreatDetector component."""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Create a mock config for testing
        self.config_patcher = patch('app.components.threat_detector.get_config')
        self.mock_config = self.config_patcher.start()
        self.mock_config.return_value = {
            "detector.mac_ip_threshold": 2  # Set low threshold for testing
        }
        
        # Mock the vendor lookup
        self.vendor_patcher = patch('app.components.threat_detector.get_vendor_for_mac')
        self.mock_vendor = self.vendor_patcher.start()
        self.mock_vendor.return_value = "Test Vendor"
        
        # Create the ThreatDetector instance for testing
        self.detector = ThreatDetector()
        
    def tearDown(self):
        """Tear down test fixtures after each test method."""
        self.config_patcher.stop()
        self.vendor_patcher.stop()
        
        # Ensure detection is stopped
        if hasattr(self, 'detector') and self.detector.running:
            self.detector.stop_detection()
    
    def test_start_detection_success(self):
        """Test successful start of threat detection."""
        with patch('app.components.threat_detector.sniff'):
            with patch('app.components.threat_detector.netifaces.gateways') as mock_gateways:
                # Mock the gateway discovery
                mock_gateways.return_value = {
                    'default': {2: ('192.168.1.1', 'eth0')}
                }
                
                # Mock callback function
                callback = MagicMock()
                
                # Start detection
                result = self.detector.start_detection(callback=callback)
                
                # Verify result
                self.assertTrue(result)
                self.assertTrue(self.detector.running)
                
                # Allow thread to start
                threading.Event().wait(0.1)
                
                # Stop detection
                self.detector.stop_detection()
    
    def test_start_detection_already_running(self):
        """Test starting detection when already running."""
        with patch('app.components.threat_detector.sniff'):
            with patch('app.components.threat_detector.netifaces.gateways') as mock_gateways:
                # Mock the gateway discovery
                mock_gateways.return_value = {
                    'default': {2: ('192.168.1.1', 'eth0')}
                }
                
                # Start detection once
                self.detector.start_detection()
                
                # Try to start again
                result = self.detector.start_detection()
                
                # Verify that the second attempt fails
                self.assertFalse(result)
                
                # Cleanup
                self.detector.stop_detection()
    
    def test_stop_detection_not_running(self):
        """Test stopping detection when not running."""
        # Try to stop when not running
        result = self.detector.stop_detection()
        
        # Verify that the attempt fails
        self.assertFalse(result)
    
    def test_process_arp_packet_normal(self):
        """Test processing a normal ARP packet."""
        # Create a mock ARP packet
        mock_packet = Mock()
        mock_packet.haslayer.return_value = True
        
        mock_arp = Mock()
        mock_arp.psrc = "192.168.1.100"
        mock_arp.hwsrc = "00:11:22:33:44:55"
        mock_arp.pdst = "192.168.1.1"
        
        mock_packet.__getitem__.return_value = mock_arp
        
        # Process the packet
        self.detector._process_arp_packet(mock_packet)
        
        # Verify mappings were updated correctly
        self.assertEqual(self.detector.ip_mac_mappings["192.168.1.100"], "00:11:22:33:44:55")
        self.assertIn("192.168.1.100", self.detector.mac_ip_mappings["00:11:22:33:44:55"])
        
        # Verify no threats were registered
        self.assertEqual(len(self.detector.threats), 0)
    
    def test_process_arp_packet_invalid(self):
        """Test processing an invalid ARP packet."""
        # Create a mock ARP packet with invalid data
        mock_packet = Mock()
        mock_packet.haslayer.return_value = True
        
        mock_arp = Mock()
        mock_arp.psrc = "0.0.0.0"
        mock_arp.hwsrc = "00:00:00:00:00:00"
        mock_arp.pdst = "192.168.1.1"
        
        mock_packet.__getitem__.return_value = mock_arp
        
        # Process the packet
        self.detector._process_arp_packet(mock_packet)
        
        # Verify no mappings were updated
        self.assertEqual(len(self.detector.ip_mac_mappings), 0)
        self.assertEqual(len(self.detector.mac_ip_mappings), 0)
    
    def test_detect_ip_with_multiple_macs(self):
        """Test detection of an IP address claimed by multiple MAC addresses."""
        # Create mock packets
        mock_packet1 = Mock()
        mock_packet1.haslayer.return_value = True
        
        mock_arp1 = Mock()
        mock_arp1.psrc = "192.168.1.100"
        mock_arp1.hwsrc = "00:11:22:33:44:55"
        mock_arp1.pdst = "192.168.1.1"
        
        mock_packet1.__getitem__.return_value = mock_arp1
        
        mock_packet2 = Mock()
        mock_packet2.haslayer.return_value = True
        
        mock_arp2 = Mock()
        mock_arp2.psrc = "192.168.1.100"
        mock_arp2.hwsrc = "AA:BB:CC:DD:EE:FF"  # Different MAC for same IP
        mock_arp2.pdst = "192.168.1.1"
        
        mock_packet2.__getitem__.return_value = mock_arp2
        
        # Mock callback for threat notification
        callback = MagicMock()
        self.detector.callback = callback
        
        # Process the first packet (establishes baseline)
        self.detector._process_arp_packet(mock_packet1)
        
        # Process the second packet (should trigger threat detection)
        self.detector._process_arp_packet(mock_packet2)
        
        # Verify threat was registered
        self.assertIn("192.168.1.100", self.detector.threats)
        self.assertEqual(len(self.detector.threats["192.168.1.100"]["macs"]), 2)
        self.assertIn("00:11:22:33:44:55", self.detector.threats["192.168.1.100"]["macs"])
        self.assertIn("AA:BB:CC:DD:EE:FF", self.detector.threats["192.168.1.100"]["macs"])
        
        # Verify callback was called
        callback.assert_called()
    
    def test_detect_mac_with_many_ips(self):
        """Test detection of a MAC address claiming many IP addresses."""
        # Create 3 mock packets with different IPs but same MAC
        for i, ip in enumerate(["192.168.1.100", "192.168.1.101", "192.168.1.102"]):
            mock_packet = Mock()
            mock_packet.haslayer.return_value = True
            
            mock_arp = Mock()
            mock_arp.psrc = ip
            mock_arp.hwsrc = "00:11:22:33:44:55"  # Same MAC for all IPs
            mock_arp.pdst = "192.168.1.1"
            
            mock_packet.__getitem__.return_value = mock_arp
            
            # Process the packet
            self.detector._process_arp_packet(mock_packet)
        
        # Verify threats were registered (threshold is 2)
        self.assertEqual(len(self.detector.threats), 3)  # All IPs should be flagged
    
    def test_detect_gateway_spoofing(self):
        """Test detection of gateway ARP spoofing."""
        # Set up gateway information
        self.detector.gateway_ip = "192.168.1.1"
        self.detector.gateway_mac = "00:11:22:33:44:55"
        
        # Create a mock packet spoofing the gateway
        mock_packet = Mock()
        mock_packet.haslayer.return_value = True
        
        mock_arp = Mock()
        mock_arp.psrc = "192.168.1.1"  # Gateway IP
        mock_arp.hwsrc = "AA:BB:CC:DD:EE:FF"  # Different MAC for gateway
        mock_arp.pdst = "192.168.1.100"
        
        mock_packet.__getitem__.return_value = mock_arp
        
        # Mock callback for threat notification
        callback = MagicMock()
        self.detector.callback = callback
        
        # Process the packet
        self.detector._process_arp_packet(mock_packet)
        
        # Verify threat was registered as gateway-related
        self.assertIn("192.168.1.1", self.detector.threats)
        self.assertIn("AA:BB:CC:DD:EE:FF", self.detector.threats["192.168.1.1"]["macs"])
        
        # Verify callback was called with a critical message
        callback.assert_called()
        call_args = callback.call_args[0]
        self.assertTrue(call_args[0])  # Success flag
        self.assertIn("CRITICAL", call_args[1])  # Critical severity
        self.assertIn("gateway", call_args[1].lower())  # Mentions gateway
    
    def test_get_threats(self):
        """Test retrieving the list of threats."""
        # Add some threats manually
        current_time = datetime.now()
        
        self.detector.threats = {
            "192.168.1.100": {
                "macs": {"00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"},
                "first_seen": current_time,
                "last_seen": current_time
            },
            "192.168.1.1": {
                "macs": {"00:11:22:33:44:55", "FF:EE:DD:CC:BB:AA"},
                "first_seen": current_time,
                "last_seen": current_time
            }
        }
        
        self.detector.gateway_ip = "192.168.1.1"
        
        # Get threats
        threats = self.detector.get_threats()
        
        # Verify structure and content
        self.assertEqual(len(threats), 2)
        
        # Check first threat
        threat1 = next(t for t in threats if t["ip"] == "192.168.1.100")
        self.assertEqual(len(threat1["macs"]), 2)
        self.assertEqual(len(threat1["vendors"]), 2)
        self.assertFalse(threat1["is_gateway"])
        
        # Check gateway threat
        threat2 = next(t for t in threats if t["ip"] == "192.168.1.1")
        self.assertEqual(len(threat2["macs"]), 2)
        self.assertEqual(len(threat2["vendors"]), 2)
        self.assertTrue(threat2["is_gateway"])

if __name__ == "__main__":
    unittest.main() 