import sys
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QGroupBox, QFormLayout, QTextEdit, QComboBox, QCheckBox,
    QTabWidget, QMessageBox, QListWidget, QListWidgetItem, QLineEdit
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QBrush, QFont

# Mock packet class
class MockPacket:
    def __init__(self, timestamp, src_ip, dst_ip, protocol, length, payload=None):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.length = length
        self.payload = payload or b""
        
        # Format hex data with spaces between bytes
        self.hex_data = ' '.join(f'{b:02x}' for b in self.payload)
        
        # Format ASCII data, replacing non-printable characters with dots
        self.ascii_data = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in self.payload)
        
        self.summary = f"{protocol} {src_ip} -> {dst_ip}"

# Create PacketView class
class PacketView(QWidget):
    packet_selected = pyqtSignal(MockPacket)
    filter_applied = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.packets = []
        self.setup_ui()
        
    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        
        # Control panel
        control_panel = QWidget()
        control_layout = QHBoxLayout(control_panel)
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter packets...")
        self.clear_button = QPushButton("Clear")
        self.export_button = QPushButton("Export")
        
        control_layout.addWidget(QLabel("Filter:"))
        control_layout.addWidget(self.filter_input)
        control_layout.addStretch()
        control_layout.addWidget(self.clear_button)
        control_layout.addWidget(self.export_button)
        
        # Packet list
        self.packet_table = QTableWidget(0, 5)
        self.packet_table.setHorizontalHeaderLabels(
            ["Time", "Source", "Destination", "Protocol", "Length"]
        )
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        # Packet details
        details_group = QGroupBox("Packet Details")
        details_layout = QVBoxLayout(details_group)
        
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.ascii_view = QTextEdit()
        self.ascii_view.setReadOnly(True)
        
        details_layout.addWidget(QLabel("Hex View:"))
        details_layout.addWidget(self.hex_view)
        details_layout.addWidget(QLabel("ASCII View:"))
        details_layout.addWidget(self.ascii_view)
        
        # Add to main layout
        main_layout.addWidget(control_panel)
        main_layout.addWidget(self.packet_table)
        main_layout.addWidget(details_group)
        
    def add_packet(self, packet):
        """Add a packet to the view"""
        self.packets.append(packet)
        self.update_packet_list()
        
    def update_packet_list(self):
        """Update the packet list display"""
        self.packet_table.setRowCount(0)
        for packet in self.packets:
            row = self.packet_table.rowCount()
            self.packet_table.insertRow(row)
            
            self.packet_table.setItem(row, 0, QTableWidgetItem(
                packet.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")
            ))
            self.packet_table.setItem(row, 1, QTableWidgetItem(packet.src_ip))
            self.packet_table.setItem(row, 2, QTableWidgetItem(packet.dst_ip))
            self.packet_table.setItem(row, 3, QTableWidgetItem(packet.protocol))
            self.packet_table.setItem(row, 4, QTableWidgetItem(str(packet.length)))
            
    def show_packet_details(self, packet):
        """Show detailed packet information"""
        self.hex_view.setText(packet.hex_data)
        self.ascii_view.setText(packet.ascii_data)

    def apply_filter(self):
        """Apply the current filter to the packet list"""
        filter_text = self.filter_input.text().lower()
        for row in range(self.packet_table.rowCount()):
            show_row = False
            for col in range(self.packet_table.columnCount()):
                item = self.packet_table.item(row, col)
                if item and filter_text in item.text().lower():
                    show_row = True
                    break
            self.packet_table.setRowHidden(row, not show_row)
            
    def export_to_csv(self, filename):
        """Export packets to CSV file"""
        import csv
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Time", "Source", "Destination", "Protocol", "Length"])
            for packet in self.packets:
                writer.writerow([
                    packet.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f"),
                    packet.src_ip,
                    packet.dst_ip,
                    packet.protocol,
                    str(packet.length)
                ])
                
    def export_to_pcap(self, filename):
        """Export packets to PCAP file"""
        # This is a mock implementation since we don't have actual PCAP writing
        with open(filename, 'wb') as pcapfile:
            pcapfile.write(b"PCAP")  # Mock PCAP header
            for packet in self.packets:
                pcapfile.write(packet.payload)

class TestPacketView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        self.packet_view = PacketView()
        
    def tearDown(self):
        self.packet_view.close()
        self.packet_view.deleteLater()
        
    def test_initialization(self):
        """Test if packet view initializes correctly"""
        self.assertIsNotNone(self.packet_view)
        self.assertIsNotNone(self.packet_view.packet_table)
        self.assertIsNotNone(self.packet_view.hex_view)
        self.assertIsNotNone(self.packet_view.ascii_view)
        self.assertIsNotNone(self.packet_view.filter_input)
        
    def test_packet_display(self):
        """Test packet display functionality"""
        # Create test packets
        packet1 = MockPacket(
            datetime.now(),
            "192.168.1.1",
            "192.168.1.2",
            "TCP",
            100,
            b"Test packet 1"
        )
        
        packet2 = MockPacket(
            datetime.now(),
            "192.168.1.2",
            "192.168.1.1",
            "UDP",
            200,
            b"Test packet 2"
        )
        
        self.packet_view.add_packet(packet1)
        self.packet_view.add_packet(packet2)
        
        # Verify packet list
        self.assertEqual(self.packet_view.packet_table.rowCount(), 2)
        self.assertEqual(self.packet_view.packet_table.item(0, 1).text(), "192.168.1.1")
        self.assertEqual(self.packet_view.packet_table.item(1, 1).text(), "192.168.1.2")
        
    def test_packet_filtering(self):
        """Test packet filtering functionality"""
        # Add packets with different protocols
        packets = [
            MockPacket(datetime.now(), "192.168.1.1", "192.168.1.2", "TCP", 100),
            MockPacket(datetime.now(), "192.168.1.2", "192.168.1.3", "UDP", 200),
            MockPacket(datetime.now(), "192.168.1.3", "192.168.1.4", "ICMP", 50)
        ]
        
        for packet in packets:
            self.packet_view.add_packet(packet)
            
        # Test protocol filtering
        self.packet_view.filter_input.setText("TCP")
        self.packet_view.apply_filter()
        visible_rows = sum(1 for i in range(self.packet_view.packet_table.rowCount())
                         if not self.packet_view.packet_table.isRowHidden(i))
        self.assertEqual(visible_rows, 1)
        
        # Test IP filtering
        self.packet_view.filter_input.setText("192.168.1.2")
        self.packet_view.apply_filter()
        visible_rows = sum(1 for i in range(self.packet_view.packet_table.rowCount())
                         if not self.packet_view.packet_table.isRowHidden(i))
        self.assertEqual(visible_rows, 2)
        
    def test_packet_details(self):
        """Test packet details display"""
        # Create a packet with specific payload
        packet = MockPacket(
            datetime.now(),
            "192.168.1.1",
            "192.168.1.2",
            "TCP",
            100,
            b"Test\x00\x01\x02\x03\x04\x05"
        )
        
        self.packet_view.add_packet(packet)
        self.packet_view.show_packet_details(packet)
        
        # Verify hex view - check for hex representation
        hex_text = self.packet_view.hex_view.toPlainText()
        self.assertIn("54 65 73 74", hex_text)  # "Test" in hex
        self.assertIn("00 01 02 03 04 05", hex_text)  # Control characters in hex
        
        # Verify ASCII view - check for ASCII representation
        ascii_text = self.packet_view.ascii_view.toPlainText()
        self.assertIn("Test", ascii_text)  # Printable characters
        self.assertIn("....", ascii_text)  # Non-printable characters replaced with dots
        
    def test_packet_export(self):
        """Test packet export functionality"""
        # Add test packets
        packets = [
            MockPacket(datetime.now(), "192.168.1.1", "192.168.1.2", "TCP", 100),
            MockPacket(datetime.now(), "192.168.1.2", "192.168.1.3", "UDP", 200)
        ]
        
        for packet in packets:
            self.packet_view.add_packet(packet)
            
        # Test CSV export
        with patch('builtins.open', unittest.mock.mock_open()) as mock_file:
            self.packet_view.export_to_csv("test_export.csv")
            mock_file.assert_called_once_with("test_export.csv", "w", newline='')
            
        # Test PCAP export
        with patch('builtins.open', unittest.mock.mock_open()) as mock_file:
            self.packet_view.export_to_pcap("test_export.pcap")
            mock_file.assert_called_once_with("test_export.pcap", "wb")
            
    def test_performance(self):
        """Test performance with large packet captures"""
        # Add many packets to test performance
        for i in range(1000):
            packet = MockPacket(
                datetime.now(),
                f"192.168.1.{i % 256}",
                f"192.168.1.{(i + 1) % 256}",
                "TCP",
                100 + (i % 900)
            )
            self.packet_view.add_packet(packet)
            
        # Test update performance
        import time
        start_time = time.time()
        self.packet_view.update_packet_list()
        end_time = time.time()
        
        # Update should complete within 1 second
        self.assertLessEqual(end_time - start_time, 1.0)

if __name__ == '__main__':
    unittest.main() 