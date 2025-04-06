from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QComboBox, QFrame, QSplitter, QTreeWidget,
    QTreeWidgetItem, QCheckBox, QLineEdit, QFormLayout, QGroupBox,
    QTabWidget, QProgressBar, QToolBar, QAction, QMenu, QHeaderView,
    QMessageBox
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QIcon, QColor, QBrush, QFont

import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import json

from app.components.packet_analyzer import PacketAnalyzer
from app.utils.logger import get_logger

# Module logger
logger = get_logger('components.packet_view')

class PacketDisplay(QTableWidget):
    """Custom table widget for displaying packet information."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(7)
        self.setHorizontalHeaderLabels([
            "Time", "Source", "Destination", "Protocol", "Length", "Info", "Status"
        ])
        
        # Memory optimization settings
        self.max_displayed_packets = 1000  # Maximum packets to display
        self.packet_buffer = []  # Buffer for new packets
        self.buffer_size = 50  # Process packets in batches of 50
        self.memory_threshold = 0.8  # Memory usage threshold (80%)
        
        # Performance optimization
        self.setSortingEnabled(True)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        
        # Configure columns
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Time
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Source
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Destination
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Protocol
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Length
        header.setSectionResizeMode(5, QHeaderView.Stretch)  # Info
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)  # Status
        
        # Memory monitoring
        self.last_memory_check = time.time()
        self.memory_check_interval = 30  # Check memory every 30 seconds
        
    def _check_memory_usage(self):
        """Check system memory usage and adjust display accordingly."""
        current_time = time.time()
        if current_time - self.last_memory_check < self.memory_check_interval:
            return
            
        self.last_memory_check = current_time
        
        try:
            import psutil
            memory = psutil.virtual_memory()
            memory_usage = memory.percent / 100.0
            
            if memory_usage > self.memory_threshold:
                # Reduce displayed packets when memory usage is high
                new_max = int(self.max_displayed_packets * (1 - (memory_usage - self.memory_threshold)))
                if new_max < 100:  # Keep at least 100 packets
                    new_max = 100
                    
                if new_max < self.rowCount():
                    # Remove oldest packets
                    self.setRowCount(new_max)
                    logger.info(f"Reduced displayed packets to {new_max} due to high memory usage")
                    
        except ImportError:
            logger.warning("psutil not available for memory monitoring")
            
    def _process_packet_buffer(self):
        """Process buffered packets in batches to reduce memory pressure."""
        if not self.packet_buffer:
            return
            
        # Process packets in batches
        for packet in self.packet_buffer:
            # Add new row
            row = self.rowCount()
            self.insertRow(row)
            
            # Set packet data
            self.setItem(row, 0, QTableWidgetItem(packet.get('timestamp', '')))
            self.setItem(row, 1, QTableWidgetItem(packet.get('src_ip', '')))
            self.setItem(row, 2, QTableWidgetItem(packet.get('dst_ip', '')))
            self.setItem(row, 3, QTableWidgetItem(packet.get('protocol', '')))
            self.setItem(row, 4, QTableWidgetItem(str(packet.get('length', 0))))
            self.setItem(row, 5, QTableWidgetItem(packet.get('info', '')))
            self.setItem(row, 6, QTableWidgetItem(packet.get('status', '')))
            
            # Apply color based on status
            if packet.get('status') == 'Suspicious':
                for col in range(self.columnCount()):
                    self.item(row, col).setBackground(QColor(255, 200, 200))
            elif packet.get('status') == 'Malicious':
                for col in range(self.columnCount()):
                    self.item(row, col).setBackground(QColor(255, 150, 150))
                    
        # Clear buffer
        self.packet_buffer = []
        
        # Limit total rows
        while self.rowCount() > self.max_displayed_packets:
            self.removeRow(0)
            
    def add_packet(self, packet):
        """Add a new packet to the display.
        
        Args:
            packet (dict): Packet information
        """
        # Add to buffer
        self.packet_buffer.append(packet)
        
        # Process buffer if it's full
        if len(self.packet_buffer) >= self.buffer_size:
            self._process_packet_buffer()
            
        # Check memory usage periodically
        self._check_memory_usage()
        
    def clear(self):
        """Clear all packets from the display."""
        super().clear()
        self.setRowCount(0)
        self.packet_buffer = []
        
    def get_selected_packet(self):
        """Get the currently selected packet.
        
        Returns:
            dict: Packet information or None if no packet selected
        """
        selected = self.selectedItems()
        if not selected:
            return None
            
        row = selected[0].row()
        return {
            'timestamp': self.item(row, 0).text(),
            'src_ip': self.item(row, 1).text(),
            'dst_ip': self.item(row, 2).text(),
            'protocol': self.item(row, 3).text(),
            'length': int(self.item(row, 4).text()),
            'info': self.item(row, 5).text(),
            'status': self.item(row, 6).text()
        }

class PacketView(QWidget):
    """User interface component for displaying packet capture and analysis."""
    
    # Signals
    capture_started = pyqtSignal(bool)  # emitted when capture starts/stops
    status_changed = pyqtSignal(str)    # emitted when status changes
    
    def __init__(self, parent=None):
        """Initialize the packet view component.
        
        Args:
            parent: Parent widget
        """
        super().__init__(parent)
        
        # Initialize packet analyzer
        self.analyzer = PacketAnalyzer()
        
        # Setup UI
        self.setup_ui()
        
        # Connect timer for periodic updates
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_statistics)
        
        # Apply initial state
        self.update_ui_state(False)  # Not capturing initially
        
    def setup_ui(self):
        """Set up the user interface."""
        main_layout = QVBoxLayout(self)
        
        # Control panel
        control_panel = self.create_control_panel()
        main_layout.addWidget(control_panel)
        
        # Main content - split between packets and details
        splitter = QSplitter(Qt.Vertical)
        
        # Upper part - packet table
        self.packet_table = PacketDisplay()
        self.packet_table.itemSelectionChanged.connect(self.show_packet_details)
        
        # Lower part - tabs for details, statistics, etc.
        detail_tabs = QTabWidget()
        
        # Tab 1: Packet details
        self.packet_detail_tree = QTreeWidget()
        self.packet_detail_tree.setHeaderLabels(["Field", "Value"])
        detail_tabs.addTab(self.packet_detail_tree, "Packet Details")
        
        # Tab 2: Hex view
        self.hex_view = QTableWidget()
        self.hex_view.setColumnCount(18)  # Offset + 16 bytes + ASCII
        header_labels = ["Offset"] + [f"{i:02X}" for i in range(16)] + ["ASCII"]
        self.hex_view.setHorizontalHeaderLabels(header_labels)
        detail_tabs.addTab(self.hex_view, "Hex View")
        
        # Tab 3: Statistics
        statistics_widget = self.create_statistics_widget()
        detail_tabs.addTab(statistics_widget, "Statistics")
        
        # Add widgets to splitter
        splitter.addWidget(self.packet_table)
        splitter.addWidget(detail_tabs)
        
        # Set initial sizes (70% top, 30% bottom)
        splitter.setSizes([700, 300])
        
        main_layout.addWidget(splitter, 1)  # Give the splitter stretch factor
        
        # Status bar
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Ready")
        self.packet_count_label = QLabel("0 packets")
        status_layout.addWidget(self.status_label, 1)
        status_layout.addWidget(self.packet_count_label)
        
        main_layout.addLayout(status_layout)
        
    def create_control_panel(self) -> QWidget:
        """Create the control panel for capture settings.
        
        Returns:
            QWidget: The control panel widget
        """
        control_widget = QWidget()
        control_layout = QHBoxLayout(control_widget)
        control_layout.setContentsMargins(0, 0, 0, 0)
        
        # Left side - capture controls
        capture_group = QGroupBox("Capture")
        capture_layout = QHBoxLayout(capture_group)
        
        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.toggle_capture)
        
        self.interface_combo = QComboBox()
        self.interface_combo.addItem("Default")  # Will be replaced with actual interfaces
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("BPF Filter (e.g., 'tcp port 80')")
        
        capture_layout.addWidget(self.start_button)
        capture_layout.addWidget(QLabel("Interface:"))
        capture_layout.addWidget(self.interface_combo)
        capture_layout.addWidget(QLabel("Filter:"))
        capture_layout.addWidget(self.filter_input, 1)  # Give stretch
        
        # Right side - display filters
        filter_group = QGroupBox("Display Filter")
        filter_layout = QHBoxLayout(filter_group)
        
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["All Protocols", "TCP", "UDP", "HTTP", "DNS", "ARP", "ICMP"])
        self.protocol_combo.currentTextChanged.connect(self.apply_display_filter)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search in packets...")
        self.search_input.textChanged.connect(self.apply_display_filter)
        
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_packets)
        
        filter_layout.addWidget(QLabel("Protocol:"))
        filter_layout.addWidget(self.protocol_combo)
        filter_layout.addWidget(QLabel("Search:"))
        filter_layout.addWidget(self.search_input, 1)  # Give stretch
        filter_layout.addWidget(self.clear_button)
        
        # Add groups to control layout
        control_layout.addWidget(capture_group)
        control_layout.addWidget(filter_group)
        
        return control_widget
        
    def create_statistics_widget(self) -> QWidget:
        """Create the statistics display widget.
        
        Returns:
            QWidget: The statistics widget
        """
        stats_widget = QWidget()
        stats_layout = QVBoxLayout(stats_widget)
        
        # Summary statistics
        summary_group = QGroupBox("Summary")
        summary_layout = QFormLayout(summary_group)
        
        self.packets_label = QLabel("0")
        self.bytes_label = QLabel("0")
        self.duration_label = QLabel("0 seconds")
        self.rate_label = QLabel("0 packets/s")
        
        summary_layout.addRow("Packets:", self.packets_label)
        summary_layout.addRow("Bytes:", self.bytes_label)
        summary_layout.addRow("Duration:", self.duration_label)
        summary_layout.addRow("Rate:", self.rate_label)
        
        # Protocol distribution
        protocol_group = QGroupBox("Protocol Distribution")
        protocol_layout = QVBoxLayout(protocol_group)
        
        self.protocol_table = QTableWidget()
        self.protocol_table.setColumnCount(3)
        self.protocol_table.setHorizontalHeaderLabels(["Protocol", "Count", "Percentage"])
        self.protocol_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        protocol_layout.addWidget(self.protocol_table)
        
        # Top talkers
        talkers_group = QGroupBox("Top Talkers")
        talkers_layout = QVBoxLayout(talkers_group)
        
        self.talkers_table = QTableWidget()
        self.talkers_table.setColumnCount(2)
        self.talkers_table.setHorizontalHeaderLabels(["IP Address", "Packet Count"])
        self.talkers_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        talkers_layout.addWidget(self.talkers_table)
        
        # Add all groups to the main layout
        stats_layout.addWidget(summary_group)
        stats_layout.addWidget(protocol_group)
        stats_layout.addWidget(talkers_group)
        
        return stats_widget
        
    def toggle_capture(self):
        """Start or stop packet capture."""
        if self.analyzer.running:
            # Stop capture
            self.analyzer.stop_capture()
            self.update_ui_state(False)
        else:
            # Start capture
            interface = None
            if self.interface_combo.currentText() != "Default":
                interface = self.interface_combo.currentText()
                
            packet_filter = self.filter_input.text() if self.filter_input.text() else None
            
            success = self.analyzer.start_capture(
                interface=interface,
                packet_filter=packet_filter,
                packet_callback=self.handle_new_packet,
                status_callback=self.handle_status_update
            )
            
            if success:
                self.update_ui_state(True)
                self.update_timer.start(1000)  # Update stats every second
            else:
                QMessageBox.critical(
                    self,
                    "Capture Error",
                    "Failed to start packet capture. Check interface and filter."
                )
                
    def update_ui_state(self, capturing):
        """Update UI elements based on capturing state.
        
        Args:
            capturing: Whether packet capture is active
        """
        self.start_button.setText("Stop Capture" if capturing else "Start Capture")
        self.interface_combo.setEnabled(not capturing)
        self.filter_input.setEnabled(not capturing)
        
        if capturing:
            self.status_label.setText("Capturing packets...")
        else:
            self.status_label.setText("Ready")
            self.update_timer.stop()
            
        # Emit signal to notify parent
        self.capture_started.emit(capturing)
        
    def handle_new_packet(self, packet_info):
        """Process a new packet from the analyzer.
        
        Args:
            packet_info: Dictionary with packet information
        """
        # Add to packet table
        self.packet_table.add_packet(packet_info)
        
        # Update packet count
        self.packet_count_label.setText(f"{self.packet_table.rowCount()} packets")
        
        # Auto-scroll to bottom if the last row was visible
        if self.packet_table.rowCount() > 0 and self.packet_table.isRowVisible(self.packet_table.rowCount() - 1):
            self.packet_table.scrollToBottom()
            
    def handle_status_update(self, success, message):
        """Handle status updates from the packet analyzer.
        
        Args:
            success: Whether the operation was successful
            message: Status message
        """
        if success:
            self.status_label.setText(message)
        else:
            self.status_label.setText(f"Error: {message}")
            
        # Emit signal to notify parent
        self.status_changed.emit(message)
        
    def update_statistics(self):
        """Update the statistics display."""
        if not self.analyzer.running:
            return
            
        # Get current statistics
        stats = self.analyzer.get_statistics()
        
        # Update summary labels
        self.packets_label.setText(str(stats['packets_analyzed']))
        self.bytes_label.setText(f"{stats['bytes_analyzed']} ({self.format_bytes(stats['bytes_analyzed'])})")
        self.duration_label.setText(f"{stats['duration_seconds']:.1f} seconds")
        self.rate_label.setText(f"{stats['packets_per_second']:.1f} packets/s ({self.format_bytes(stats['bytes_per_second'])}/s)")
        
        # Update protocol distribution
        self.protocol_table.setRowCount(0)
        total_packets = max(1, stats['packets_analyzed'])
        
        for i, (proto, count) in enumerate(stats['protocol_distribution'].items()):
            self.protocol_table.insertRow(i)
            self.protocol_table.setItem(i, 0, QTableWidgetItem(proto))
            self.protocol_table.setItem(i, 1, QTableWidgetItem(str(count)))
            
            percentage = (count / total_packets) * 100
            self.protocol_table.setItem(i, 2, QTableWidgetItem(f"{percentage:.1f}%"))
            
        # Update top talkers
        self.talkers_table.setRowCount(0)
        
        for i, (ip, count) in enumerate(stats['top_source_ips'].items()):
            self.talkers_table.insertRow(i)
            self.talkers_table.setItem(i, 0, QTableWidgetItem(ip))
            self.talkers_table.setItem(i, 1, QTableWidgetItem(str(count)))
            
    def show_packet_details(self):
        """Display details for the selected packet."""
        selected_packet = self.packet_table.get_selected_packet()
        if not selected_packet:
            return
            
        # Clear previous details
        self.packet_detail_tree.clear()
        
        # Add packet summary
        summary = QTreeWidgetItem(self.packet_detail_tree, ["Packet", ""])
        
        # Add general info
        time_str = selected_packet['timestamp']
        QTreeWidgetItem(summary, ["Time", time_str])
        
        if 'length' in selected_packet:
            QTreeWidgetItem(summary, ["Length", str(selected_packet['length'])])
            
        # Add protocol-specific details
        protocol = selected_packet.get('protocol', 'UNKNOWN')
        proto_item = QTreeWidgetItem(self.packet_detail_tree, [protocol, ""])
        
        if protocol in ('IP', 'TCP', 'UDP', 'HTTP', 'DNS'):
            # Common IP fields
            if 'src_ip' in selected_packet:
                QTreeWidgetItem(proto_item, ["Source IP", selected_packet['src_ip']])
            if 'dst_ip' in selected_packet:
                QTreeWidgetItem(proto_item, ["Destination IP", selected_packet['dst_ip']])
            if 'ttl' in selected_packet:
                QTreeWidgetItem(proto_item, ["TTL", str(selected_packet['ttl'])])
                
            # TCP/UDP fields
            if protocol in ('TCP', 'UDP', 'HTTP'):
                if 'src_port' in selected_packet:
                    QTreeWidgetItem(proto_item, ["Source Port", str(selected_packet['src_port'])])
                if 'dst_port' in selected_packet:
                    QTreeWidgetItem(proto_item, ["Destination Port", str(selected_packet['dst_port'])])
                    
            # TCP-specific fields
            if protocol == 'TCP' and 'flags' in selected_packet:
                QTreeWidgetItem(proto_item, ["Flags", selected_packet['flags']])
                
            # HTTP-specific fields
            if protocol == 'HTTP' and 'http_data' in selected_packet:
                http_item = QTreeWidgetItem(proto_item, ["HTTP", ""])
                http_data = selected_packet['http_data']
                
                for key, value in http_data.items():
                    if key == 'headers' and isinstance(value, dict):
                        headers_item = QTreeWidgetItem(http_item, ["Headers", ""])
                        for header_key, header_value in value.items():
                            QTreeWidgetItem(headers_item, [header_key, header_value])
                    else:
                        QTreeWidgetItem(http_item, [key, str(value)])
                
        # ARP-specific fields
        elif protocol == 'ARP':
            if 'arp_op' in selected_packet:
                QTreeWidgetItem(proto_item, ["Operation", selected_packet['arp_op']])
            if 'src_ip' in selected_packet:
                QTreeWidgetItem(proto_item, ["Sender IP", selected_packet['src_ip']])
            if 'src_mac' in selected_packet:
                QTreeWidgetItem(proto_item, ["Sender MAC", selected_packet['src_mac']])
            if 'dst_ip' in selected_packet:
                QTreeWidgetItem(proto_item, ["Target IP", selected_packet['dst_ip']])
            if 'dst_mac' in selected_packet:
                QTreeWidgetItem(proto_item, ["Target MAC", selected_packet['dst_mac']])
                
        # ICMP-specific fields
        elif protocol == 'ICMP':
            if 'icmp_type' in selected_packet:
                icmp_type = selected_packet['icmp_type']
                type_str = str(icmp_type)
                
                # Add human-readable type
                if icmp_type == 0:
                    type_str += " (Echo Reply)"
                elif icmp_type == 8:
                    type_str += " (Echo Request)"
                    
                QTreeWidgetItem(proto_item, ["Type", type_str])
                
            if 'icmp_code' in selected_packet:
                QTreeWidgetItem(proto_item, ["Code", str(selected_packet['icmp_code'])])
                
        # Expand all items by default
        self.packet_detail_tree.expandAll()
        
        # Update hex view if raw packet is available
        self.update_hex_view(selected_packet)
        
    def update_hex_view(self, packet_info):
        """Update the hex view with the selected packet's data.
        
        Args:
            packet_info: Dictionary with packet information
        """
        self.hex_view.clearContents()
        self.hex_view.setRowCount(0)
        
        # Check if raw packet is available
        if 'raw_packet' not in packet_info:
            return
            
        # Get raw bytes from packet
        raw_packet = packet_info['raw_packet']
        
        try:
            # Convert Scapy packet to bytes
            packet_bytes = bytes(raw_packet)
            
            # Calculate number of rows needed (16 bytes per row)
            num_rows = (len(packet_bytes) + 15) // 16
            self.hex_view.setRowCount(num_rows)
            
            for row in range(num_rows):
                # Offset
                offset_item = QTableWidgetItem(f"{row * 16:04X}")
                self.hex_view.setItem(row, 0, offset_item)
                
                # ASCII representation
                ascii_chars = []
                
                # Process 16 bytes per row
                for col in range(16):
                    byte_index = row * 16 + col
                    
                    if byte_index < len(packet_bytes):
                        byte_value = packet_bytes[byte_index]
                        
                        # Hex value
                        hex_item = QTableWidgetItem(f"{byte_value:02X}")
                        self.hex_view.setItem(row, col + 1, hex_item)
                        
                        # ASCII character
                        if 32 <= byte_value <= 126:  # Printable ASCII
                            ascii_chars.append(chr(byte_value))
                        else:
                            ascii_chars.append('.')
                    else:
                        # Fill empty cells
                        self.hex_view.setItem(row, col + 1, QTableWidgetItem(""))
                        ascii_chars.append(' ')
                        
                # Add ASCII column
                ascii_item = QTableWidgetItem(''.join(ascii_chars))
                self.hex_view.setItem(row, 17, ascii_item)
                
        except Exception as e:
            logger.error(f"Error updating hex view: {e}")
            
    def apply_protocol_color(self, row, protocol):
        """Apply color to a row based on the protocol.
        
        Args:
            row: Row index
            protocol: Protocol name
        """
        color = None
        
        if protocol == 'TCP':
            color = QColor(240, 248, 255)  # Light blue
        elif protocol == 'UDP':
            color = QColor(255, 250, 240)  # Light yellow
        elif protocol == 'HTTP':
            color = QColor(255, 240, 245)  # Light pink
        elif protocol == 'DNS':
            color = QColor(240, 255, 240)  # Light green
        elif protocol == 'ARP':
            color = QColor(255, 228, 225)  # Misty rose
        elif protocol == 'ICMP':
            color = QColor(224, 255, 255)  # Light cyan
            
        if color:
            brush = QBrush(color)
            for col in range(self.packet_table.columnCount()):
                item = self.packet_table.item(row, col)
                if item:
                    item.setBackground(brush)
                    
    def apply_display_filter(self):
        """Apply display filters to the packet table."""
        protocol_filter = self.protocol_combo.currentText()
        search_text = self.search_input.text().lower()
        
        # Show all rows first
        for row in range(self.packet_table.rowCount()):
            self.packet_table.setRowHidden(row, False)
            
        # If no filters, we're done
        if protocol_filter == "All Protocols" and not search_text:
            return
            
        # Apply filters
        for row in range(self.packet_table.rowCount()):
            # Get packet info for this row
            time_item = self.packet_table.item(row, 0)
            packet_info = time_item.data(Qt.UserRole) if time_item else None
            
            if not packet_info:
                continue
                
            # Filter by protocol if needed
            show_row = True
            if protocol_filter != "All Protocols":
                if packet_info.get('protocol', '') != protocol_filter:
                    show_row = False
                    
            # Filter by search text if provided
            if show_row and search_text:
                # Search in multiple fields
                search_fields = [
                    packet_info.get('src_ip', ''),
                    packet_info.get('dst_ip', ''),
                    packet_info.get('info', ''),
                    str(packet_info.get('src_port', '')),
                    str(packet_info.get('dst_port', ''))
                ]
                
                found = False
                for field in search_fields:
                    if search_text in field.lower():
                        found = True
                        break
                        
                if not found:
                    show_row = False
                    
            # Apply visibility
            self.packet_table.setRowHidden(row, not show_row)
            
        # Update the packet count
        visible_count = sum(1 for row in range(self.packet_table.rowCount()) 
                          if not self.packet_table.isRowHidden(row))
                          
        self.packet_count_label.setText(f"{visible_count} of {self.packet_table.rowCount()} packets")
        
    def clear_packets(self):
        """Clear all packets from the display."""
        self.packet_table.clear()
        self.packet_detail_tree.clear()
        self.hex_view.clearContents()
        self.hex_view.setRowCount(0)
        self.packet_count_label.setText("0 packets")
        
        # Reset statistics displays
        self.packets_label.setText("0")
        self.bytes_label.setText("0")
        self.duration_label.setText("0 seconds")
        self.rate_label.setText("0 packets/s")
        
        self.protocol_table.setRowCount(0)
        self.talkers_table.setRowCount(0)
        
    def format_bytes(self, byte_count):
        """Format byte count into a human-readable string.
        
        Args:
            byte_count: Number of bytes
            
        Returns:
            str: Formatted byte string
        """
        if byte_count < 1024:
            return f"{byte_count} B"
        elif byte_count < 1024 * 1024:
            return f"{byte_count / 1024:.1f} KB"
        elif byte_count < 1024 * 1024 * 1024:
            return f"{byte_count / (1024 * 1024):.1f} MB"
        else:
            return f"{byte_count / (1024 * 1024 * 1024):.1f} GB" 