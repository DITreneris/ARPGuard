from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, 
    QHeaderView, QLabel, QPushButton, QHBoxLayout
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QBrush

from datetime import datetime
from typing import List, Dict, Any

from app.utils.logger import get_logger

# Module logger
logger = get_logger('components.packet_display')

class PacketDisplay(QWidget):
    """Widget for visualizing packet flow."""
    
    # Signal emitted when packet count changes
    packet_count_changed = pyqtSignal(int)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.packets = []
        self.max_displayed_packets = 50
        
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        self.title_label = QLabel("<b>Packet Flow Visualization</b>")
        self.packet_count_label = QLabel("0 packets")
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_packets)
        
        header_layout.addWidget(self.title_label)
        header_layout.addStretch()
        header_layout.addWidget(self.packet_count_label)
        header_layout.addWidget(self.clear_button)
        
        # Packet table
        self.packet_table = QTableWidget(0, 5)
        self.packet_table.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Type", "Info"])
        
        # Set column widths
        self.packet_table.setColumnWidth(0, 100)  # Time
        self.packet_table.setColumnWidth(1, 120)  # Source
        self.packet_table.setColumnWidth(2, 120)  # Destination
        self.packet_table.setColumnWidth(3, 80)   # Type
        self.packet_table.setColumnWidth(4, 200)  # Info
        
        # Configure table
        self.packet_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        # Add widgets to layout
        layout.addLayout(header_layout)
        layout.addWidget(self.packet_table)
        
    def add_packet(self, packet: Dict[str, Any]):
        """Add a packet to the display.
        
        Args:
            packet: Dictionary containing packet details:
                   - time: Timestamp
                   - src: Source address
                   - dst: Destination address
                   - type: Packet type (e.g., 'ARP')
                   - info: Additional information
                   - direction: 'sent' or 'received'
        """
        # Add to our packet list
        self.packets.append(packet)
        
        # Limit the number of stored packets
        if len(self.packets) > self.max_displayed_packets * 2:
            self.packets = self.packets[-self.max_displayed_packets:]
        
        # Add to the table
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        
        # Format timestamp
        if isinstance(packet.get('time'), datetime):
            time_str = packet['time'].strftime('%H:%M:%S.%f')[:-3]
        else:
            time_str = str(packet.get('time', 'Unknown'))
            
        # Create table items
        time_item = QTableWidgetItem(time_str)
        src_item = QTableWidgetItem(packet.get('src', 'Unknown'))
        dst_item = QTableWidgetItem(packet.get('dst', 'Unknown'))
        type_item = QTableWidgetItem(packet.get('type', 'Unknown'))
        info_item = QTableWidgetItem(packet.get('info', ''))
        
        # Set colors based on direction
        color = None
        if packet.get('direction') == 'sent':
            color = QColor(200, 230, 200)  # Light green for sent packets
        elif packet.get('direction') == 'received':
            color = QColor(230, 200, 200)  # Light red for received packets
            
        if color:
            brush = QBrush(color)
            time_item.setBackground(brush)
            src_item.setBackground(brush)
            dst_item.setBackground(brush)
            type_item.setBackground(brush)
            info_item.setBackground(brush)
        
        # Add items to the table
        self.packet_table.setItem(row, 0, time_item)
        self.packet_table.setItem(row, 1, src_item)
        self.packet_table.setItem(row, 2, dst_item)
        self.packet_table.setItem(row, 3, type_item)
        self.packet_table.setItem(row, 4, info_item)
        
        # Keep only most recent packets visible in the table
        if self.packet_table.rowCount() > self.max_displayed_packets:
            self.packet_table.removeRow(0)
            
        # Scroll to the bottom
        self.packet_table.scrollToBottom()
        
        # Update packet count
        self.update_packet_count()
        
    def add_packets(self, packets: List[Dict[str, Any]]):
        """Add multiple packets to the display.
        
        Args:
            packets: List of packet dictionaries
        """
        for packet in packets:
            self.add_packet(packet)
    
    def clear_packets(self):
        """Clear all packets from the display."""
        self.packets = []
        self.packet_table.setRowCount(0)
        self.update_packet_count()
        
    def update_packet_count(self):
        """Update the packet count label."""
        count = len(self.packets)
        self.packet_count_label.setText(f"{count} packet{'s' if count != 1 else ''}")
        self.packet_count_changed.emit(count)
        
    def set_max_displayed_packets(self, count: int):
        """Set the maximum number of displayed packets.
        
        Args:
            count: Maximum number of packets to display
        """
        self.max_displayed_packets = max(1, count)
        
        # Trim the table if needed
        while self.packet_table.rowCount() > self.max_displayed_packets:
            self.packet_table.removeRow(0) 