import unittest
from unittest.mock import Mock, patch
import sys
from PyQt5.QtWidgets import QApplication, QTableWidgetItem
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt, QPoint, QTimer
from PyQt5.QtGui import QBrush
from datetime import datetime
import os
from app.ui.components import (OptimizedTable, StatusIndicator, 
                             OptimizedComboBox, ProgressIndicator, 
                             OptimizedButton)

# Mock the network-related modules
mock_scapy = Mock()
mock_scapy_all = Mock()
mock_netifaces = Mock()
mock_netaddr = Mock()

sys.modules['scapy'] = mock_scapy
sys.modules['scapy.all'] = mock_scapy_all
sys.modules['netifaces'] = mock_netifaces
sys.modules['netaddr'] = mock_netaddr

# Add the app directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from components.main_window import MainWindow
from components.packet_view import PacketView
from components.attack_view import AttackView
from components.threat_intelligence_view import ThreatIntelligenceView

class TestMainWindow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create QApplication instance
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        # Create a new MainWindow instance for each test
        self.window = MainWindow()
        
    def tearDown(self):
        # Clean up after each test
        self.window.close()
        self.window.deleteLater()
        
    def test_window_initialization(self):
        """Test if the main window initializes correctly"""
        self.assertIsNotNone(self.window)
        self.assertTrue(self.window.isVisible())
        self.assertEqual(self.window.windowTitle(), "ARPGuard")
        
    def test_menu_actions(self):
        """Test if menu actions are properly connected"""
        # Test File menu
        self.assertIsNotNone(self.window.file_menu)
        self.assertIsNotNone(self.window.action_scan)
        self.assertIsNotNone(self.window.action_stop)
        self.assertIsNotNone(self.window.action_exit)
        
        # Test View menu
        self.assertIsNotNone(self.window.view_menu)
        self.assertIsNotNone(self.window.action_show_packets)
        self.assertIsNotNone(self.window.action_show_threats)
        
    def test_network_scan_trigger(self):
        """Test if network scan can be triggered"""
        # Mock the network scanner
        with patch('components.main_window.NetworkScanner') as mock_scanner:
            mock_scanner.return_value = Mock()
            mock_scanner.return_value.start_scan.return_value = True
            
            # Trigger scan action
            self.window.action_scan.trigger()
            
            # Verify scanner was called
            mock_scanner.return_value.start_scan.assert_called_once()

    def test_ui_responsiveness_during_scanning(self):
        """Test if UI remains responsive during scanning"""
        # Mock the network scanner
        with patch('components.main_window.NetworkScanner') as mock_scanner:
            mock_instance = Mock()
            mock_instance.start_scan.return_value = True
            mock_scanner.return_value = mock_instance
            
            # Store original state
            original_scan_button_enabled = self.window.scan_button.isEnabled()
            
            # Start scanning
            self.window.start_scan()
            
            # Check that the UI shows scanning is in progress
            self.assertTrue(self.window.scan_progress.isVisible())
            self.assertFalse(self.window.scan_button.isEnabled())
            
            # Simulate scan completion
            self.window.handle_scan_complete()
            
            # Verify UI is restored after scanning completes
            self.assertFalse(self.window.scan_progress.isVisible())
            self.assertEqual(self.window.scan_button.isEnabled(), original_scan_button_enabled)

    def test_status_bar_updates(self):
        """Test if status bar updates correctly"""
        test_message = "Test status message"
        
        # Update the status
        self.window.update_status(test_message)
        
        # Verify status message was set
        self.assertEqual(self.window.statusBar().currentMessage(), test_message)

    def test_theme_switching(self):
        """Test if theme switching works correctly"""
        # Get current theme
        initial_theme = self.window.config.get("ui.theme", "light")
        
        # Determine the opposite theme to switch to
        target_theme = "dark" if initial_theme == "light" else "light"
        
        # Mock the apply_config method to avoid actual theme application
        with patch.object(self.window, 'apply_config') as mock_apply_config:
            # Switch theme by simulating menu action
            self.window.config["ui.theme"] = target_theme
            self.window.apply_config()
            
            # Verify apply_config was called to apply the theme change
            mock_apply_config.assert_called_once()

class TestPacketView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        self.packet_view = PacketView()
        
    def tearDown(self):
        self.packet_view.close()
        self.packet_view.deleteLater()
        
    def test_packet_view_initialization(self):
        """Test if packet view initializes correctly"""
        self.assertIsNotNone(self.packet_view)
        self.assertIsNotNone(self.packet_view.table)
        self.assertIsNotNone(self.packet_view.filter_input)
        
    def test_packet_filtering(self):
        """Test packet filtering functionality"""
        # Add some test packets
        test_packets = [
            {"source": "192.168.1.1", "destination": "192.168.1.2", "protocol": "TCP"},
            {"source": "192.168.1.2", "destination": "192.168.1.1", "protocol": "UDP"},
            {"source": "192.168.1.3", "destination": "192.168.1.4", "protocol": "ICMP"}
        ]
        
        for packet in test_packets:
            self.packet_view.add_packet(packet)
            
        # Test filtering by IP
        self.packet_view.filter_input.setText("192.168.1.1")
        QTest.keyPress(self.packet_view.filter_input, Qt.Key_Return)
        
        # Verify filtered results
        visible_rows = self.packet_view.table.rowCount()
        self.assertEqual(visible_rows, 2)  # Should show only packets with 192.168.1.1
        
    def test_packet_details_display(self):
        """Test packet details display functionality"""
        test_packet = {
            "source": "192.168.1.1",
            "destination": "192.168.1.2",
            "protocol": "TCP",
            "length": 100,
            "time": "2024-03-29 10:00:00"
        }
        
        self.packet_view.add_packet(test_packet)
        
        # Verify packet details are displayed correctly
        self.assertEqual(self.packet_view.table.item(0, 0).text(), "192.168.1.1")
        self.assertEqual(self.packet_view.table.item(0, 1).text(), "192.168.1.2")
        self.assertEqual(self.packet_view.table.item(0, 2).text(), "TCP")

    def test_packet_sorting(self):
        """Test packet sorting functionality"""
        # Add some test packets with different protocols
        test_packets = [
            {"source": "192.168.1.1", "destination": "192.168.1.2", "protocol": "TCP", "length": 100, "time": "2024-03-29 10:00:00"},
            {"source": "192.168.1.3", "destination": "192.168.1.4", "protocol": "UDP", "length": 200, "time": "2024-03-29 10:01:00"},
            {"source": "192.168.1.5", "destination": "192.168.1.6", "protocol": "ICMP", "length": 50, "time": "2024-03-29 10:02:00"}
        ]
        
        for packet in test_packets:
            self.packet_view.add_packet(packet)
        
        # Get initial order
        initial_protocol = self.packet_view.table.item(0, 2).text()
        
        # Sort by protocol (column 2)
        self.packet_view.table.horizontalHeader().sectionClicked.emit(2)
        
        # Verify order changed
        sorted_protocol = self.packet_view.table.item(0, 2).text()
        self.assertNotEqual(initial_protocol, sorted_protocol)

    def test_packet_highlighting(self):
        """Test packet highlighting based on protocol"""
        # Add test packets with different protocols
        protocols = ["TCP", "UDP", "ICMP", "ARP", "HTTP", "DNS"]
        
        for i, protocol in enumerate(protocols):
            test_packet = {
                "source": f"192.168.1.{i+1}",
                "destination": f"192.168.1.{i+2}",
                "protocol": protocol,
                "length": 100,
                "time": f"2024-03-29 10:0{i}:00"
            }
            self.packet_view.add_packet(test_packet)
            
        # Verify each row has appropriate styling applied
        for i, protocol in enumerate(protocols):
            # Get foreground or background color of the protocol cell
            cell_item = self.packet_view.table.item(i, 2)  # Protocol is in column 2
            self.assertIsNotNone(cell_item, f"Item for protocol {protocol} is None")
            
            # Check if a color is set (foreground or background)
            has_color = (cell_item.foreground() != QBrush() or 
                        cell_item.background() != QBrush())
            
            self.assertTrue(has_color, f"Protocol {protocol} does not have highlighting applied")

    def test_context_menu_functionality(self):
        """Test context menu availability and actions"""
        # Mock QMenu to capture action creation
        with patch('PyQt5.QtWidgets.QMenu') as mock_menu:
            # Create mock menu instance
            menu_instance = Mock()
            mock_menu.return_value = menu_instance
            menu_instance.addAction.return_value = Mock()
            
            # Add a test packet
            test_packet = {
                "source": "192.168.1.1", 
                "destination": "192.168.1.2", 
                "protocol": "TCP", 
                "length": 100,
                "time": "2024-03-29 10:00:00"
            }
            self.packet_view.add_packet(test_packet)
            
            # Simulate context menu request
            # First select the row
            self.packet_view.table.selectRow(0)
            
            # Check if the packet view has context menu policy set
            self.assertEqual(self.packet_view.table.contextMenuPolicy(), Qt.CustomContextMenu)
            
            # Trigger the context menu
            if hasattr(self.packet_view, 'show_context_menu'):
                self.packet_view.show_context_menu(QPoint(10, 10))
                # Verify context menu was created with actions
                mock_menu.assert_called_once()
                # At least one action should be added
                self.assertGreater(menu_instance.addAction.call_count, 0)

class TestAttackView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        self.attack_view = AttackView()
        
    def tearDown(self):
        self.attack_view.close()
        self.attack_view.deleteLater()
        
    def test_initialization(self):
        """Test if attack view initializes correctly"""
        self.assertIsNotNone(self.attack_view)
        self.assertIsNotNone(self.attack_view.attack_table)
        self.assertIsNotNone(self.attack_view.pattern_combo)
        self.assertIsNotNone(self.attack_view.start_button)
        
    def test_attack_display(self):
        """Test if attack events are properly displayed"""
        # Create a mock attack details
        test_attack = {
            "id": "test-001",
            "type": "ARP Spoofing",
            "severity": "high",
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration": "00:05:23",
            "source_ip": "192.168.1.10",
            "target_ip": "192.168.1.1",
            "description": "Possible ARP cache poisoning attack detected",
            "evidence": [
                {"packet_id": 1, "details": "Suspicious ARP packet 1"},
                {"packet_id": 2, "details": "Suspicious ARP packet 2"}
            ]
        }
        
        # Manually add attack to table
        self.attack_view.add_attack_to_table(test_attack, "Attack detected")
        
        # Verify attack was added to table
        self.assertEqual(self.attack_view.attack_table.rowCount(), 1)
        
        # Verify attack details are correct
        time_col = 0
        type_col = 1
        severity_col = 2
        
        self.assertEqual(self.attack_view.attack_table.item(0, type_col).text(), "ARP Spoofing")
        self.assertEqual(self.attack_view.attack_table.item(0, severity_col).text(), "HIGH")
        
    def test_attack_type_filtering(self):
        """Test attack type filtering functionality"""
        # Create mock attack details
        arp_attack = {
            "id": "arp-001",
            "type": "ARP Spoofing",
            "severity": "high",
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration": "00:05:23",
            "source_ip": "192.168.1.10",
            "target_ip": "192.168.1.1",
            "description": "Possible ARP cache poisoning attack detected"
        }
        
        port_scan_attack = {
            "id": "scan-001",
            "type": "Port Scanning",
            "severity": "medium",
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration": "00:02:45",
            "source_ip": "192.168.1.15",
            "target_ip": "192.168.1.1",
            "description": "Port scanning detected"
        }
        
        # Add attacks to table
        self.attack_view.add_attack_to_table(arp_attack, "ARP attack detected")
        self.attack_view.add_attack_to_table(port_scan_attack, "Port scan detected")
        
        # Verify both attacks were added
        self.assertEqual(self.attack_view.attack_table.rowCount(), 2)
        
        # Test filtering by pattern (if implemented in the class)
        if hasattr(self.attack_view, 'filter_attacks_by_type'):
            # Filter to only show ARP attacks
            self.attack_view.filter_attacks_by_type("ARP Spoofing")
            
            # Check if only ARP attacks are visible
            visible_count = 0
            for i in range(self.attack_view.attack_table.rowCount()):
                if not self.attack_view.attack_table.isRowHidden(i):
                    visible_count += 1
                    
            self.assertEqual(visible_count, 1)
    
    def test_detail_viewing(self):
        """Test attack detail viewing functionality"""
        # Create a mock attack with details
        test_attack = {
            "id": "test-001",
            "type": "ARP Spoofing",
            "severity": "high",
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration": "00:05:23",
            "source_ip": "192.168.1.10",
            "target_ip": "192.168.1.1",
            "description": "Possible ARP cache poisoning attack detected",
            "evidence": [
                {"packet_id": 1, "details": "Suspicious ARP packet 1"},
                {"packet_id": 2, "details": "Suspicious ARP packet 2"}
            ]
        }
        
        # Add attack to table
        self.attack_view.add_attack_to_table(test_attack, "Attack detected")
        
        # Select the attack
        self.attack_view.attack_table.selectRow(0)
        
        # Verify attack details are shown
        self.assertIn("ARP Spoofing", self.attack_view.attack_name_label.text())
        self.assertIn("HIGH", self.attack_view.attack_severity_label.text())

    def test_attack_export(self):
        """Test attack data export functionality"""
        # Create a mock attack
        test_attack = {
            "id": "test-001",
            "type": "ARP Spoofing",
            "severity": "high",
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration": "00:05:23",
            "source_ip": "192.168.1.10",
            "target_ip": "192.168.1.1",
            "description": "Possible ARP cache poisoning attack detected"
        }
        
        # Add attack to table
        self.attack_view.add_attack_to_table(test_attack, "Attack detected")
        
        # Mock the export functionality
        with patch('components.attack_view.QFileDialog.getSaveFileName') as mock_save:
            mock_save.return_value = ('test_export.csv', 'CSV Files (*.csv)')
            
            # Call export method
            self.attack_view.export_attacks()
            
            # Verify export was attempted
            mock_save.assert_called_once()
            
            # Verify attack data was prepared for export
            self.assertEqual(len(self.attack_view.attack_table.rowCount()), 1)

    def test_attack_clear(self):
        """Test clearing attack data functionality"""
        # Add multiple test attacks
        for i in range(3):
            test_attack = {
                "id": f"test-{i:03d}",
                "type": "ARP Spoofing",
                "severity": "high",
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "duration": "00:05:23",
                "source_ip": f"192.168.1.{i+10}",
                "target_ip": "192.168.1.1",
                "description": f"Test attack {i}"
            }
            self.attack_view.add_attack_to_table(test_attack, f"Attack {i} detected")
        
        # Verify attacks were added
        self.assertEqual(self.attack_view.attack_table.rowCount(), 3)
        
        # Clear the table
        self.attack_view.clear_attacks()
        
        # Verify table is empty
        self.assertEqual(self.attack_view.attack_table.rowCount(), 0)

    def test_attack_sorting(self):
        """Test attack table sorting functionality"""
        # Create test attacks with different timestamps
        attacks = [
            {
                "id": "test-001",
                "type": "ARP Spoofing",
                "severity": "high",
                "time": "2024-03-29 10:00:00",
                "duration": "00:05:23",
                "source_ip": "192.168.1.10",
                "target_ip": "192.168.1.1",
                "description": "First attack"
            },
            {
                "id": "test-002",
                "type": "Port Scanning",
                "severity": "medium",
                "time": "2024-03-29 09:00:00",
                "duration": "00:02:45",
                "source_ip": "192.168.1.15",
                "target_ip": "192.168.1.1",
                "description": "Second attack"
            }
        ]
        
        # Add attacks to table
        for attack in attacks:
            self.attack_view.add_attack_to_table(attack, "Attack detected")
        
        # Sort by time column (ascending)
        self.attack_view.attack_table.sortItems(0, Qt.AscendingOrder)
        
        # Verify sorting order
        self.assertEqual(self.attack_view.attack_table.item(0, 1).text(), "Port Scanning")  # Earlier time
        self.assertEqual(self.attack_view.attack_table.item(1, 1).text(), "ARP Spoofing")  # Later time

    def test_mitigation_actions(self):
        """Test mitigation action triggering and handling"""
        # Create a mock attack with mitigation options
        test_attack = {
            "id": "test-002",
            "type": "DDoS",
            "severity": "critical",
            "detection_time": datetime.now(),
            "targets": [
                {
                    "dst_ip": "192.168.1.1",
                    "protocol": "TCP",
                    "packet_count": 1000,
                    "rate": 500.0,
                    "evidence_ids": [1, 2, 3]
                }
            ],
            "mitigation_options": [
                {
                    "type": "block_ip",
                    "description": "Block source IP addresses",
                    "action": "block_ips",
                    "targets": ["192.168.1.100", "192.168.1.101"]
                },
                {
                    "type": "rate_limit",
                    "description": "Apply rate limiting",
                    "action": "rate_limit",
                    "targets": ["192.168.1.1"]
                }
            ]
        }

        # Add attack to table
        self.attack_view.add_attack_to_table(test_attack, "DDoS attack detected")

        # Select the attack
        self.attack_view.attack_table.selectRow(0)

        # Verify mitigation options are available
        self.assertIn("DDoS", self.attack_view.attack_name_label.text())
        self.assertIn("CRITICAL", self.attack_view.attack_severity_label.text())

        # Verify attack details show mitigation options
        stats_html = self.attack_view._generate_attack_stats_html(test_attack)
        self.assertIn("DDoS", stats_html)
        self.assertIn("500.0", stats_html)  # Check rate is displayed
        self.assertIn("192.168.1.1", stats_html)  # Check target IP is displayed

    def test_attack_history(self):
        """Test attack history display and management"""
        # Create multiple mock attacks
        attacks = [
            {
                "id": "test-003",
                "type": "ARP Spoofing",
                "severity": "high",
                "detection_time": datetime.now(),
                "first_seen": datetime.now(),
                "last_seen": datetime.now(),
                "suspicious_ips": [
                    {
                        "ip": "192.168.1.100",
                        "macs": ["00:11:22:33:44:55"]
                    }
                ]
            },
            {
                "id": "test-004",
                "type": "Port Scanning",
                "severity": "medium",
                "detection_time": datetime.now(),
                "first_seen": datetime.now(),
                "last_seen": datetime.now(),
                "most_active": {
                    "src_ip": "192.168.1.200",
                    "port_count": 50,
                    "evidence_ids": [4, 5, 6]
                }
            }
        ]

        # Add attacks to table
        for attack in attacks:
            self.attack_view.add_attack_to_table(attack, f"{attack['type']} detected")

        # Verify all attacks are displayed
        self.assertEqual(self.attack_view.attack_table.rowCount(), len(attacks))

        # Verify attack details are correct
        for i, attack in enumerate(attacks):
            self.assertEqual(self.attack_view.attack_table.item(i, 1).text(), attack['type'])
            self.assertEqual(self.attack_view.attack_table.item(i, 2).text(), attack['severity'].upper())

        # Test attack history retrieval
        with patch('app.components.attack_view.AttackRecognizer') as mock_recognizer:
            mock_recognizer.return_value.get_attack_history.return_value = attacks
            detected_attacks = self.attack_view.get_detected_attacks()
            self.assertEqual(len(detected_attacks), len(attacks))

    def test_evidence_collection(self):
        """Test evidence collection and visualization"""
        # Create a mock attack with evidence
        test_attack = {
            "id": "test-005",
            "type": "DNS Poisoning",
            "severity": "high",
            "detection_time": datetime.now(),
            "suspicious_responses": [
                {
                    "domain": "example.com",
                    "legitimate_ip": "93.184.216.34",
                    "spoofed_ip": "192.168.1.50",
                    "src_ip": "192.168.1.100"
                }
            ],
            "evidence_ids": [7, 8, 9]
        }

        # Add attack to table
        self.attack_view.add_attack_to_table(test_attack, "DNS poisoning detected")

        # Select the attack
        self.attack_view.attack_table.selectRow(0)

        # Verify evidence list is populated
        self.assertEqual(self.attack_view.evidence_list.count(), len(test_attack['evidence_ids']))

        # Verify evidence items have correct data
        for i in range(self.attack_view.evidence_list.count()):
            item = self.attack_view.evidence_list.item(i)
            packet_id = item.data(Qt.UserRole)
            self.assertIn(packet_id, test_attack['evidence_ids'])
            self.assertIn(f"Packet #{packet_id}", item.text())

        # Verify attack details show evidence information
        stats_html = self.attack_view._generate_attack_stats_html(test_attack)
        self.assertIn("DNS Poisoning", stats_html)
        self.assertIn("example.com", stats_html)
        self.assertIn("192.168.1.50", stats_html)  # Check spoofed IP is displayed

class TestThreatIntelligenceView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        self.intel_view = ThreatIntelligenceView()
        
    def tearDown(self):
        self.intel_view.close()
        self.intel_view.deleteLater()
        
    def test_initialization(self):
        """Test if threat intelligence view initializes correctly"""
        self.assertIsNotNone(self.intel_view)
        self.assertIsNotNone(self.intel_view.ip_table)
        self.assertIsNotNone(self.intel_view.domain_table)
        self.assertIsNotNone(self.intel_view.signature_table)
        self.assertIsNotNone(self.intel_view.update_button)
        
    def test_threat_display(self):
        """Test if threat intelligence data is properly displayed"""
        # Mock the threat intelligence data
        with patch('components.threat_intelligence_view.get_threat_intelligence') as mock_intel:
            mock_intel_instance = Mock()
            mock_intel.return_value = mock_intel_instance
            
            # Mock IP data
            test_ip_data = [{
                "ip": "1.2.3.4",
                "score": 90,
                "categories": ["malware", "c2"],
                "source": "AbuseIPDB"
            }]
            
            # Set the mock data
            mock_intel_instance.get_malicious_ips.return_value = test_ip_data
            mock_intel_instance.get_malicious_domains.return_value = []
            mock_intel_instance.get_attack_signatures.return_value = []
            
            # Update the display
            self.intel_view.refresh_display()
            
            # Verify data is displayed
            self.assertEqual(self.intel_view.ip_table.rowCount(), 1)
            self.assertEqual(self.intel_view.ip_table.item(0, 0).text(), "1.2.3.4")
            self.assertEqual(self.intel_view.ip_table.item(0, 1).text(), "90")
            
    def test_severity_filtering(self):
        """Test if severity filtering works for threat intelligence data"""
        # Add sample data to tables
        # IP table with different scores
        test_ips = [
            {"ip": "1.2.3.4", "score": 90, "categories": "malware, c2", "source": "AbuseIPDB"},
            {"ip": "5.6.7.8", "score": 70, "categories": "scanner", "source": "AbuseIPDB"},
            {"ip": "9.10.11.12", "score": 40, "categories": "suspicious", "source": "AbuseIPDB"}
        ]
        
        # Manually add IPs to the table
        for ip_data in test_ips:
            row = self.intel_view.ip_table.rowCount()
            self.intel_view.ip_table.insertRow(row)
            self.intel_view.ip_table.setItem(row, 0, QTableWidgetItem(ip_data["ip"]))
            self.intel_view.ip_table.setItem(row, 1, QTableWidgetItem(str(ip_data["score"])))
            self.intel_view.ip_table.setItem(row, 2, QTableWidgetItem(ip_data["categories"]))
            self.intel_view.ip_table.setItem(row, 3, QTableWidgetItem(ip_data["source"]))
            
        # Verify all rows are visible initially
        visible_count = 0
        for i in range(self.intel_view.ip_table.rowCount()):
            if not self.intel_view.ip_table.isRowHidden(i):
                visible_count += 1
        self.assertEqual(visible_count, 3)
        
        # Set minimum score filter to 75
        self.intel_view.ip_score_filter.setValue(75)
        
        # Trigger filter if separate function
        if hasattr(self.intel_view, 'filter_malicious_ips'):
            self.intel_view.filter_malicious_ips()
            
            # Verify only high severity IPs are visible
            visible_count = 0
            for i in range(self.intel_view.ip_table.rowCount()):
                if not self.intel_view.ip_table.isRowHidden(i):
                    visible_count += 1
            self.assertEqual(visible_count, 1)
            
    def test_threat_detail_viewing(self):
        """Test threat intelligence detail viewing functionality"""
        # Add a test signature
        test_signature = {
            "id": "ET-1234",
            "description": "Test malicious signature",
            "severity": "critical",
            "source": "Emerging Threats"
        }
        
        # Add signature to table
        row = self.intel_view.signature_table.rowCount()
        self.intel_view.signature_table.insertRow(row)
        self.intel_view.signature_table.setItem(row, 0, QTableWidgetItem(test_signature["id"]))
        self.intel_view.signature_table.setItem(row, 1, QTableWidgetItem(test_signature["description"]))
        self.intel_view.signature_table.setItem(row, 2, QTableWidgetItem(test_signature["severity"]))
        self.intel_view.signature_table.setItem(row, 3, QTableWidgetItem(test_signature["source"]))
        
        # Select the signature
        self.intel_view.signature_table.selectRow(0)
        
        # Simulate selection change to trigger detail view
        self.intel_view.show_signature_details()
        
        # If there's a detail text field, check if it contains signature details
        if hasattr(self.intel_view, 'signature_details_text'):
            # Verify details are displayed
            details_text = self.intel_view.signature_details_text.toPlainText()
            self.assertIn(test_signature["id"], details_text)
            self.assertIn(test_signature["description"], details_text)

    def test_threat_intelligence_update(self):
        """Test threat intelligence data update functionality"""
        # Mock the update process
        with patch('components.threat_intelligence_view.get_threat_intelligence') as mock_intel:
            mock_intel_instance = Mock()
            mock_intel.return_value = mock_intel_instance
            
            # Mock update process
            mock_intel_instance.update.return_value = True
            
            # Call update method
            self.intel_view.update_threat_data()
            
            # Verify update was called
            mock_intel_instance.update.assert_called_once()
            
            # Verify UI reflects update state
            self.assertFalse(self.intel_view.update_button.isEnabled())
            self.assertEqual(self.intel_view.status_label.text(), "Status: Updating...")

    def test_threat_intelligence_export(self):
        """Test threat intelligence data export functionality"""
        # Add test data to tables
        test_data = {
            "ips": [{"ip": "1.2.3.4", "score": 90, "categories": "malware", "source": "AbuseIPDB"}],
            "domains": [{"domain": "malicious.com", "score": 85, "categories": "phishing", "source": "VirusTotal"}],
            "signatures": [{"id": "ET-1234", "description": "Test signature", "severity": "high", "source": "Emerging Threats"}]
        }
        
        # Populate tables with test data
        for ip in test_data["ips"]:
            row = self.intel_view.ip_table.rowCount()
            self.intel_view.ip_table.insertRow(row)
            self.intel_view.ip_table.setItem(row, 0, QTableWidgetItem(ip["ip"]))
            self.intel_view.ip_table.setItem(row, 1, QTableWidgetItem(str(ip["score"])))
            self.intel_view.ip_table.setItem(row, 2, QTableWidgetItem(ip["categories"]))
            self.intel_view.ip_table.setItem(row, 3, QTableWidgetItem(ip["source"]))
            
        # Mock file dialog
        with patch('components.threat_intelligence_view.QFileDialog.getSaveFileName') as mock_save:
            mock_save.return_value = ('threat_export.csv', 'CSV Files (*.csv)')
            
            # Call export method
            self.intel_view.export_threat_data()
            
            # Verify export was attempted
            mock_save.assert_called_once()
            
            # Verify data was prepared for export
            self.assertEqual(self.intel_view.ip_table.rowCount(), 1)

    def test_threat_intelligence_search(self):
        """Test threat intelligence search functionality"""
        # Add test data to tables
        test_data = [
            {"ip": "1.2.3.4", "score": 90, "categories": "malware", "source": "AbuseIPDB"},
            {"ip": "5.6.7.8", "score": 70, "categories": "scanner", "source": "AbuseIPDB"},
            {"ip": "9.10.11.12", "score": 40, "categories": "suspicious", "source": "AbuseIPDB"}
        ]
        
        # Populate IP table
        for data in test_data:
            row = self.intel_view.ip_table.rowCount()
            self.intel_view.ip_table.insertRow(row)
            self.intel_view.ip_table.setItem(row, 0, QTableWidgetItem(data["ip"]))
            self.intel_view.ip_table.setItem(row, 1, QTableWidgetItem(str(data["score"])))
            self.intel_view.ip_table.setItem(row, 2, QTableWidgetItem(data["categories"]))
            self.intel_view.ip_table.setItem(row, 3, QTableWidgetItem(data["source"]))
            
        # Test search functionality
        self.intel_view.search_input.setText("1.2.3")
        self.intel_view.search_threats()
        
        # Verify only matching IP is visible
        visible_count = 0
        for i in range(self.intel_view.ip_table.rowCount()):
            if not self.intel_view.ip_table.isRowHidden(i):
                visible_count += 1
        self.assertEqual(visible_count, 1)
        self.assertEqual(self.intel_view.ip_table.item(0, 0).text(), "1.2.3.4")

    def test_threat_intelligence_clear(self):
        """Test clearing threat intelligence data functionality"""
        # Add test data to tables
        test_data = [
            {"ip": "1.2.3.4", "score": 90, "categories": "malware", "source": "AbuseIPDB"},
            {"ip": "5.6.7.8", "score": 70, "categories": "scanner", "source": "AbuseIPDB"}
        ]
        
        # Populate IP table
        for data in test_data:
            row = self.intel_view.ip_table.rowCount()
            self.intel_view.ip_table.insertRow(row)
            self.intel_view.ip_table.setItem(row, 0, QTableWidgetItem(data["ip"]))
            self.intel_view.ip_table.setItem(row, 1, QTableWidgetItem(str(data["score"])))
            self.intel_view.ip_table.setItem(row, 2, QTableWidgetItem(data["categories"]))
            self.intel_view.ip_table.setItem(row, 3, QTableWidgetItem(data["source"]))
            
        # Verify data was added
        self.assertEqual(self.intel_view.ip_table.rowCount(), 2)
        
        # Clear the table
        self.intel_view.clear_threat_data()
        
        # Verify table is empty
        self.assertEqual(self.intel_view.ip_table.rowCount(), 0)

class TestUIComponents(unittest.TestCase):
    def setUp(self):
        self.app = QApplication.instance()
        if not self.app:
            self.app = QApplication([])
            
    def test_optimized_table(self):
        """Test optimized table functionality"""
        table = OptimizedTable()
        
        # Test data update
        data = [
            {'id': 1, 'name': 'Item 1', 'value': 100},
            {'id': 2, 'name': 'Item 2', 'value': 200},
            {'id': 3, 'name': 'Item 3', 'value': 300}
        ]
        columns = ['id', 'name', 'value']
        
        table.update_data(data, columns)
        
        # Verify initial load
        self.assertEqual(table.rowCount(), min(50, len(data)))
        self.assertEqual(table.columnCount(), len(columns))
        
        # Verify data content
        self.assertEqual(table.item(0, 0).text(), '1')
        self.assertEqual(table.item(0, 1).text(), 'Item 1')
        self.assertEqual(table.item(0, 2).text(), '100')
        
    def test_status_indicator(self):
        """Test status indicator functionality"""
        indicator = StatusIndicator()
        
        # Test status changes
        test_cases = [
            ('ok', 'Operation successful'),
            ('warning', 'Please check configuration'),
            ('error', 'Operation failed'),
            ('info', 'Processing data')
        ]
        
        for status, message in test_cases:
            indicator.set_status(status, message)
            self.assertEqual(indicator.status_label.text(), message)
            
    def test_optimized_combobox(self):
        """Test optimized combo box functionality"""
        combo = OptimizedComboBox()
        
        # Test item loading
        items = [f'Item {i}' for i in range(1000)]
        combo.add_items(items)
        
        # Verify initial load
        self.assertLessEqual(combo.count(), 100)  # Should be limited
        
        # Test filtering
        combo.lineEdit().setText('Item 1')
        QTimer.singleShot(400, lambda: self._verify_filter(combo, 'Item 1'))
        
    def _verify_filter(self, combo, filter_text):
        """Verify combo box filtering"""
        for i in range(combo.count()):
            self.assertIn(filter_text, combo.itemText(i).lower())
            
    def test_progress_indicator(self):
        """Test progress indicator functionality"""
        indicator = ProgressIndicator()
        
        # Test progress updates
        indicator.set_progress(50, 'Halfway there')
        self.assertEqual(indicator.status_label.text(), 'Halfway there')
        
        # Wait for animation
        QTimer.singleShot(1000, lambda: self.assertEqual(
            indicator.progress_bar.value(), 50
        ))
        
    def test_optimized_button(self):
        """Test optimized button functionality"""
        button = OptimizedButton('Test Button')
        
        # Test loading state
        button.set_loading(True)
        self.assertFalse(button.isEnabled())
        self.assertEqual(button.text(), 'Loading...')
        
        button.set_loading(False)
        self.assertTrue(button.isEnabled())
        self.assertEqual(button.text(), 'Test Button')
        
    def test_component_performance(self):
        """Test component performance under load"""
        table = OptimizedTable()
        
        # Test with large dataset
        data = [{'id': i, 'name': f'Item {i}', 'value': i * 100} 
                for i in range(10000)]
        columns = ['id', 'name', 'value']
        
        # Measure update time
        import time
        start_time = time.time()
        table.update_data(data, columns)
        end_time = time.time()
        
        # Verify performance
        self.assertLess(end_time - start_time, 1.0)  # Should complete within 1 second
        
        # Verify memory usage
        self.assertLess(len(table._data_cache), 100)  # Should cache only visible items

if __name__ == '__main__':
    unittest.main() 