import unittest
import sys
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
import netifaces

from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt

from app.components.network_monitor import NetworkMonitor

class TestNetworkMonitor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        # Mock the interfaces functionality
        self.mock_interfaces = ["eth0", "wlan0"]
        with patch('netifaces.interfaces', return_value=self.mock_interfaces):
            with patch('psutil.net_if_stats', return_value={
                "eth0": MagicMock(isup=True),
                "wlan0": MagicMock(isup=True)
            }):
                self.network_monitor = NetworkMonitor()
                
        # Mock packet capture library
        self.network_monitor.packet_capture = Mock()
        
    def tearDown(self):
        self.network_monitor.stop_monitoring()
        self.network_monitor.close()
        self.network_monitor.deleteLater()
        
    def test_initialization(self):
        """Test if network monitor initializes correctly"""
        self.assertIsNotNone(self.network_monitor)
        self.assertIsNotNone(self.network_monitor.interface_selector)
        self.assertIsNotNone(self.network_monitor.start_button)
        self.assertIsNotNone(self.network_monitor.stop_button)
        self.assertIsNotNone(self.network_monitor.packet_table)
        
        # Check that interfaces are populated
        self.assertEqual(self.network_monitor.interface_selector.count(), 2)
        self.assertEqual(self.network_monitor.interface_selector.itemText(0), "eth0")
        self.assertEqual(self.network_monitor.interface_selector.itemText(1), "wlan0")
    
    def test_interface_selection(self):
        """Test interface selection functionality"""
        # Select second interface
        self.network_monitor.interface_selector.setCurrentIndex(1)
        
        # Verify selection
        self.assertEqual(self.network_monitor.interface_selector.currentText(), "wlan0")
        self.assertEqual(self.network_monitor.current_interface, "wlan0")
    
    def test_start_monitoring(self):
        """Test starting network monitoring"""
        # Set up mock for packet capture
        self.network_monitor.packet_capture.start_capture.return_value = True
        
        # Start monitoring
        self.network_monitor.start_monitoring()
        
        # Verify monitoring started
        self.network_monitor.packet_capture.start_capture.assert_called_once_with(
            self.network_monitor.current_interface
        )
        self.assertTrue(self.network_monitor.is_monitoring)
        self.assertFalse(self.network_monitor.start_button.isEnabled())
        self.assertTrue(self.network_monitor.stop_button.isEnabled())
    
    def test_stop_monitoring(self):
        """Test stopping network monitoring"""
        # Set up mocks
        self.network_monitor.packet_capture.start_capture.return_value = True
        self.network_monitor.packet_capture.stop_capture.return_value = True
        
        # Start then stop monitoring
        self.network_monitor.start_monitoring()
        self.network_monitor.stop_monitoring()
        
        # Verify monitoring stopped
        self.network_monitor.packet_capture.stop_capture.assert_called_once()
        self.assertFalse(self.network_monitor.is_monitoring)
        self.assertTrue(self.network_monitor.start_button.isEnabled())
        self.assertFalse(self.network_monitor.stop_button.isEnabled())
    
    def test_packet_handling(self):
        """Test packet handling functionality"""
        # Create test packet
        test_packet = {
            "timestamp": datetime.now(),
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "AA:BB:CC:DD:EE:FF",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "protocol": "ARP",
            "length": 64,
            "info": "Who has 192.168.1.1? Tell 192.168.1.10"
        }
        
        # Process packet
        self.network_monitor.process_packet(test_packet)
        
        # Verify packet was added to table
        self.assertEqual(self.network_monitor.packet_table.rowCount(), 1)
        self.assertEqual(
            self.network_monitor.packet_table.item(0, 1).text(), 
            test_packet["protocol"]
        )
        self.assertEqual(
            self.network_monitor.packet_table.item(0, 2).text(), 
            test_packet["src_mac"]
        )
        self.assertEqual(
            self.network_monitor.packet_table.item(0, 3).text(), 
            test_packet["dst_mac"]
        )
    
    def test_packet_filtering(self):
        """Test packet filtering functionality"""
        # Create test packets
        test_packets = [
            {
                "timestamp": datetime.now(),
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "AA:BB:CC:DD:EE:FF",
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.1",
                "protocol": "ARP",
                "length": 64,
                "info": "Who has 192.168.1.1? Tell 192.168.1.10"
            },
            {
                "timestamp": datetime.now(),
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "AA:BB:CC:DD:EE:FF",
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.1",
                "protocol": "TCP",
                "length": 128,
                "info": "TCP Packet"
            }
        ]
        
        # Process packets
        for packet in test_packets:
            self.network_monitor.process_packet(packet)
            
        # Set filter to show only ARP packets
        self.network_monitor.protocol_filter.setCurrentText("ARP")
        self.network_monitor.apply_filters()
        
        # Verify filter
        visible_rows = sum(1 for i in range(self.network_monitor.packet_table.rowCount())
                         if not self.network_monitor.packet_table.isRowHidden(i))
        self.assertEqual(visible_rows, 1)
    
    def test_statistics_update(self):
        """Test network statistics updating"""
        # Create test packets with different protocols
        protocols = ["ARP", "TCP", "UDP", "ICMP", "DNS"]
        for i, protocol in enumerate(protocols):
            packet = {
                "timestamp": datetime.now(),
                "src_mac": f"00:11:22:33:44:{i:02}",
                "dst_mac": f"AA:BB:CC:DD:EE:{i:02}",
                "src_ip": f"192.168.1.{10+i}",
                "dst_ip": f"192.168.1.{1+i}",
                "protocol": protocol,
                "length": 64 + i*32,
                "info": f"{protocol} Packet"
            }
            self.network_monitor.process_packet(packet)
            
        # Update statistics
        self.network_monitor.update_statistics()
        
        # Verify statistics updated
        self.assertEqual(self.network_monitor.total_packets, 5)
        self.assertEqual(len(self.network_monitor.protocol_counts), 5)
        self.assertEqual(self.network_monitor.protocol_counts["ARP"], 1)
        self.assertEqual(self.network_monitor.protocol_counts["TCP"], 1)
    
    def test_arp_detection(self):
        """Test ARP packet detection"""
        # Create ARP packets simulating an attack
        arp_packets = [
            {
                "timestamp": datetime.now(),
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "FF:FF:FF:FF:FF:FF",  # Broadcast
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.1",
                "protocol": "ARP",
                "length": 64,
                "info": "Who has 192.168.1.1? Tell 192.168.1.10",
                "arp_operation": "request"
            },
            {
                "timestamp": datetime.now(),
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "AA:BB:CC:DD:EE:FF",
                "src_ip": "192.168.1.1",  # Gateway IP
                "dst_ip": "192.168.1.10",
                "protocol": "ARP",
                "length": 64,
                "info": "192.168.1.1 is at 00:11:22:33:44:55",  # Spoofed reply
                "arp_operation": "reply"
            }
        ]
        
        # Set up mock for arp detection signal
        self.network_monitor.arp_attack_detected = Mock()
        
        # Process packets
        for packet in arp_packets:
            self.network_monitor.process_arp_packet(packet)
            
        # Verify ARP attack detection
        self.network_monitor.arp_attack_detected.emit.assert_called()
    
    def test_packet_export(self):
        """Test packet export functionality"""
        # Create test packets
        test_packets = [
            {
                "timestamp": datetime.now(),
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "AA:BB:CC:DD:EE:FF",
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.1",
                "protocol": "ARP",
                "length": 64,
                "info": "ARP Packet"
            },
            {
                "timestamp": datetime.now(),
                "src_mac": "66:77:88:99:AA:BB",
                "dst_mac": "CC:DD:EE:FF:00:11",
                "src_ip": "192.168.1.20",
                "dst_ip": "192.168.1.1",
                "protocol": "TCP",
                "length": 128,
                "info": "TCP Packet"
            }
        ]
        
        # Process packets
        for packet in test_packets:
            self.network_monitor.process_packet(packet)
        
        # Test CSV export
        with patch('builtins.open', unittest.mock.mock_open()) as mock_file:
            self.network_monitor.export_packets_to_csv("test_export.csv")
            mock_file.assert_called_once_with("test_export.csv", "w", newline='')
            
        # Test PCAP export
        with patch('app.utils.packet_writer.write_pcap') as mock_write:
            self.network_monitor.export_packets_to_pcap("test_export.pcap")
            mock_write.assert_called_once()
            self.assertEqual(len(mock_write.call_args[0][1]), 2)  # 2 packets

    def test_error_handling(self):
        """Test error handling during monitoring"""
        # Setup mock to raise exception
        self.network_monitor.packet_capture.start_capture.side_effect = Exception("Network error")
        
        # Mock error signal
        self.network_monitor.error_occurred = Mock()
        
        # Attempt to start monitoring
        self.network_monitor.start_monitoring()
        
        # Verify error handling
        self.network_monitor.error_occurred.emit.assert_called_once()
        self.assertFalse(self.network_monitor.is_monitoring)
        
if __name__ == '__main__':
    unittest.main() 