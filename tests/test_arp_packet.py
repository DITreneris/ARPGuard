import unittest
import socket
import struct
from datetime import datetime
from src.core.arp_packet import ARPPacket, ARPPacketAnalyzer
from src.core.packet_validator import ARPPacketValidator
from src.core.packet_logger import ARPPacketLogger

class TestARPPacket(unittest.TestCase):
    """Test cases for ARP packet functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = ARPPacketAnalyzer()
        self.validator = ARPPacketValidator()
        self.logger = ARPPacketLogger('test_logs')
        
    def test_parse_arp_packet(self):
        """Test ARP packet parsing."""
        # Create a sample ARP packet
        eth_header = struct.pack('!6s6sH', 
                               b'\x00'*6,  # Destination MAC
                               b'\x00'*6,  # Source MAC
                               0x0806)     # ARP protocol
        
        arp_packet = struct.pack('!HHBBH6s4s6s4s',
                                1,          # Hardware type (Ethernet)
                                0x0800,     # Protocol type (IPv4)
                                6,          # Hardware size
                                4,          # Protocol size
                                1,          # Opcode (Request)
                                b'\x00'*6,  # Sender MAC
                                socket.inet_aton('192.168.1.1'),  # Sender IP
                                b'\x00'*6,  # Target MAC
                                socket.inet_aton('192.168.1.2'))  # Target IP
        
        packet = eth_header + arp_packet
        parsed = self.analyzer.parse_arp_packet(packet)
        
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.hardware_type, 1)
        self.assertEqual(parsed.protocol_type, 0x0800)
        self.assertEqual(parsed.hardware_size, 6)
        self.assertEqual(parsed.protocol_size, 4)
        self.assertEqual(parsed.opcode, 1)
        self.assertEqual(parsed.sender_mac, '00:00:00:00:00:00')
        self.assertEqual(parsed.sender_ip, '192.168.1.1')
        self.assertEqual(parsed.target_mac, '00:00:00:00:00:00')
        self.assertEqual(parsed.target_ip, '192.168.1.2')
        
    def test_packet_validation(self):
        """Test ARP packet validation."""
        # Create a valid packet
        valid_packet = ARPPacket(
            hardware_type=1,
            protocol_type=0x0800,
            hardware_size=6,
            protocol_size=4,
            opcode=1,
            sender_mac='00:11:22:33:44:55',
            sender_ip='192.168.1.1',
            target_mac='00:00:00:00:00:00',
            target_ip='192.168.1.2',
            timestamp=datetime.now()
        )
        
        # First packet should be valid
        self.assertTrue(self.validator.validate_packet(valid_packet))
        
        # Create a spoofed packet with same MAC but different IP
        spoofed_packet = ARPPacket(
            hardware_type=1,
            protocol_type=0x0800,
            hardware_size=6,
            protocol_size=4,
            opcode=1,
            sender_mac='00:11:22:33:44:55',  # Same MAC
            sender_ip='192.168.1.3',         # Different IP
            target_mac='00:00:00:00:00:00',
            target_ip='192.168.1.2',
            timestamp=datetime.now()
        )
        
        # Spoofed packet should be invalid
        self.assertFalse(self.validator.validate_packet(spoofed_packet))
        
    def test_packet_logging(self):
        """Test ARP packet logging."""
        # Create a test packet
        packet = ARPPacket(
            hardware_type=1,
            protocol_type=0x0800,
            hardware_size=6,
            protocol_size=4,
            opcode=1,
            sender_mac='00:11:22:33:44:55',
            sender_ip='192.168.1.1',
            target_mac='00:00:00:00:00:00',
            target_ip='192.168.1.2',
            timestamp=datetime.now()
        )
        
        # Log the packet
        self.logger.log_packet(packet, True)
        
        # Log an alert
        self.logger.log_alert(packet, "Potential ARP spoofing detected")
        
        # Check recent packets and alerts
        recent_packets = self.logger.get_recent_packets()
        recent_alerts = self.logger.get_recent_alerts()
        
        self.assertEqual(len(recent_packets), 1)
        self.assertEqual(len(recent_alerts), 1)
        self.assertEqual(recent_packets[0]['sender_mac'], '00:11:22:33:44:55')
        self.assertEqual(recent_alerts[0]['reason'], "Potential ARP spoofing detected")
        
    def tearDown(self):
        """Clean up test fixtures."""
        # Clean up log files
        import shutil
        shutil.rmtree('test_logs', ignore_errors=True)

if __name__ == '__main__':
    unittest.main() 