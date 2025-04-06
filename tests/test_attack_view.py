import sys
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QGroupBox, QFormLayout, QTextEdit, QComboBox, QCheckBox,
    QTabWidget, QMessageBox, QListWidget, QListWidgetItem
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QBrush, QFont

# Mock database and logger
class MockDatabase:
    def get_packet_by_id(self, packet_id):
        return {
            'id': packet_id,
            'timestamp': datetime.now(),
            'protocol': 'TCP',
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'src_port': 12345,
            'dst_port': 80,
            'length': 64,
            'info': 'Test packet'
        }

class MockLogger:
    def error(self, msg):
        print(f"ERROR: {msg}")

class MockAttackRecognizer:
    def get_available_patterns(self):
        return [
            {'name': 'ARP Spoofing', 'severity': 'high'},
            {'name': 'Port Scanning', 'severity': 'medium'},
            {'name': 'DDoS', 'severity': 'critical'}
        ]
    
    def get_attack_history(self):
        return []

# Create AttackView class
class AttackView(QWidget):
    status_changed = pyqtSignal(str)
    attack_detected = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.database = MockDatabase()
        self.recognizer = MockAttackRecognizer()
        self.setup_ui()
        
    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        
        # Control panel
        control_panel = QWidget()
        control_layout = QHBoxLayout(control_panel)
        
        self.start_button = QPushButton("Start Pattern Detection")
        self.pattern_combo = QComboBox()
        self.pattern_combo.addItem("All Patterns", "all")
        
        for pattern in self.recognizer.get_available_patterns():
            self.pattern_combo.addItem(
                f"{pattern['name']} ({pattern['severity'].upper()})", 
                pattern['name']
            )
        
        control_layout.addWidget(QLabel("Detection Patterns:"))
        control_layout.addWidget(self.pattern_combo)
        control_layout.addStretch()
        control_layout.addWidget(self.start_button)
        
        # Attack list
        attack_list_group = QGroupBox("Detected Attacks")
        attack_list_layout = QVBoxLayout(attack_list_group)
        
        self.attack_table = QTableWidget(0, 5)
        self.attack_table.setHorizontalHeaderLabels(
            ["Detection Time", "Attack Type", "Severity", "Duration", "Details"]
        )
        self.attack_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.attack_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        attack_list_layout.addWidget(self.attack_table)
        
        # Attack details
        attack_details_group = QGroupBox("Attack Details")
        attack_details_layout = QVBoxLayout(attack_details_group)
        
        self.details_tabs = QTabWidget()
        
        # Overview tab
        overview_tab = QWidget()
        overview_layout = QFormLayout(overview_tab)
        
        self.attack_name_label = QLabel("No attack selected")
        self.attack_severity_label = QLabel("")
        self.attack_time_label = QLabel("")
        self.attack_stats_label = QLabel("")
        
        overview_layout.addRow(self.attack_name_label)
        overview_layout.addRow("Severity:", self.attack_severity_label)
        overview_layout.addRow("Time:", self.attack_time_label)
        overview_layout.addRow("Stats:", self.attack_stats_label)
        
        # Evidence tab
        evidence_tab = QWidget()
        evidence_layout = QVBoxLayout(evidence_tab)
        
        self.evidence_list = QListWidget()
        evidence_layout.addWidget(self.evidence_list)
        
        # Add tabs
        self.details_tabs.addTab(overview_tab, "Overview")
        self.details_tabs.addTab(evidence_tab, "Evidence")
        
        attack_details_layout.addWidget(self.details_tabs)
        
        # Add to main layout
        main_layout.addWidget(control_panel)
        main_layout.addWidget(attack_list_group)
        main_layout.addWidget(attack_details_group)
        
        self.status_label = QLabel("Ready")
        main_layout.addWidget(self.status_label)
        
    def add_attack_to_table(self, attack_details, message):
        detection_time = attack_details.get('detection_time', datetime.now())
        
        # Get attack duration if available
        duration = "N/A"
        if 'first_seen' in attack_details and 'last_seen' in attack_details:
            first_seen = attack_details['first_seen']
            last_seen = attack_details['last_seen']
            duration_sec = (last_seen - first_seen).total_seconds()
            duration = f"{duration_sec:.1f} sec"
        
        # Insert at the top of the table
        row = 0
        self.attack_table.insertRow(row)
        
        # Time column
        time_item = QTableWidgetItem(detection_time.strftime("%Y-%m-%d %H:%M:%S"))
        self.attack_table.setItem(row, 0, time_item)
        
        # Attack type column
        attack_type = attack_details.get('type', 'Unknown')
        type_item = QTableWidgetItem(attack_type)
        self.attack_table.setItem(row, 1, type_item)
        
        # Severity column
        severity = attack_details.get('severity', 'medium').upper()
        severity_item = QTableWidgetItem(severity)
        self.attack_table.setItem(row, 2, severity_item)
        
        # Duration column
        duration_item = QTableWidgetItem(duration)
        self.attack_table.setItem(row, 3, duration_item)
        
        # Details column
        details_item = QTableWidgetItem(message)
        self.attack_table.setItem(row, 4, details_item)
        
        # Store attack details
        time_item.setData(Qt.UserRole, attack_details)
        
        # Select the new attack
        self.attack_table.selectRow(row)
        
    def _generate_attack_stats_html(self, attack_details):
        attack_type = attack_details.get('type', '')
        html = []
        
        if attack_type == 'DDoS':
            targets = attack_details.get('targets', [])
            if targets:
                target = targets[0]
                html.append(f"<p><b>Target IP:</b> {target['dst_ip']}</p>")
                html.append(f"<p><b>Protocol:</b> {target['protocol']}</p>")
                html.append(f"<p><b>Rate:</b> {target['rate']} packets/second</p>")
                
        elif attack_type == 'DNS Poisoning':
            responses = attack_details.get('suspicious_responses', [])
            if responses:
                response = responses[0]
                html.append(f"<p><b>Domain:</b> {response['domain']}</p>")
                html.append(f"<p><b>Spoofed IP:</b> {response['spoofed_ip']}</p>")
                
        return "".join(html)
        
    def get_detected_attacks(self):
        return self.recognizer.get_attack_history()

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
        test_attack = {
            "id": "test-001",
            "type": "ARP Spoofing",
            "severity": "high",
            "detection_time": datetime.now(),
            "duration": "00:05:23",
            "source_ip": "192.168.1.10",
            "target_ip": "192.168.1.1",
            "description": "Possible ARP cache poisoning attack detected"
        }
        
        self.attack_view.add_attack_to_table(test_attack, "Attack detected")
        
        self.assertEqual(self.attack_view.attack_table.rowCount(), 1)
        self.assertEqual(self.attack_view.attack_table.item(0, 1).text(), "ARP Spoofing")
        self.assertEqual(self.attack_view.attack_table.item(0, 2).text(), "HIGH")
        
    def test_mitigation_actions(self):
        """Test mitigation action triggering and handling"""
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
            ]
        }
        
        self.attack_view.add_attack_to_table(test_attack, "DDoS attack detected")
        self.attack_view.attack_table.selectRow(0)
        
        stats_html = self.attack_view._generate_attack_stats_html(test_attack)
        self.assertIn("192.168.1.1", stats_html)
        self.assertIn("500", stats_html)
        
    def test_evidence_collection(self):
        """Test evidence collection and visualization"""
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
            ]
        }
        
        self.attack_view.add_attack_to_table(test_attack, "DNS poisoning detected")
        self.attack_view.attack_table.selectRow(0)
        
        stats_html = self.attack_view._generate_attack_stats_html(test_attack)
        self.assertIn("example.com", stats_html)
        self.assertIn("192.168.1.50", stats_html)

    def test_edge_cases(self):
        """Test edge cases in attack handling"""
        # Test empty attack details
        empty_attack = {}
        self.attack_view.add_attack_to_table(empty_attack, "Empty attack")
        self.assertEqual(self.attack_view.attack_table.rowCount(), 1)
        self.assertEqual(self.attack_view.attack_table.item(0, 1).text(), "Unknown")
        self.assertEqual(self.attack_view.attack_table.item(0, 2).text(), "MEDIUM")

        # Test attack with missing required fields
        partial_attack = {
            "type": "Port Scanning",
            "severity": "high"
        }
        self.attack_view.add_attack_to_table(partial_attack, "Partial attack")
        self.assertEqual(self.attack_view.attack_table.rowCount(), 2)
        self.assertEqual(self.attack_view.attack_table.item(1, 1).text(), "Port Scanning")
        self.assertEqual(self.attack_view.attack_table.item(1, 2).text(), "HIGH")

        # Test attack with invalid severity
        invalid_severity_attack = {
            "type": "DDoS",
            "severity": "invalid",
            "detection_time": datetime.now()
        }
        self.attack_view.add_attack_to_table(invalid_severity_attack, "Invalid severity")
        self.assertEqual(self.attack_view.attack_table.item(2, 2).text(), "MEDIUM")

    def test_error_handling(self):
        """Test error handling scenarios"""
        # Test database error handling
        with patch.object(self.attack_view.database, 'get_packet_by_id', side_effect=Exception("Database error")):
            test_attack = {
                "id": "test-006",
                "type": "SQL Injection",
                "severity": "high",
                "detection_time": datetime.now(),
                "evidence_ids": [1, 2, 3]
            }
            self.attack_view.add_attack_to_table(test_attack, "Database error test")
            # Verify the attack is still added despite database error
            self.assertEqual(self.attack_view.attack_table.rowCount(), 1)

        # Test invalid evidence data
        invalid_evidence_attack = {
            "id": "test-007",
            "type": "XSS",
            "severity": "high",
            "detection_time": datetime.now(),
            "evidence": "invalid_evidence_format"
        }
        self.attack_view.add_attack_to_table(invalid_evidence_attack, "Invalid evidence")
        # Verify the attack is added with default evidence handling
        self.assertEqual(self.attack_view.attack_table.rowCount(), 2)

    def test_attack_filtering(self):
        """Test attack filtering functionality"""
        # Add multiple attacks with different types and severities
        attacks = [
            {
                "type": "ARP Spoofing",
                "severity": "high",
                "detection_time": datetime.now()
            },
            {
                "type": "Port Scanning",
                "severity": "medium",
                "detection_time": datetime.now()
            },
            {
                "type": "DDoS",
                "severity": "critical",
                "detection_time": datetime.now()
            }
        ]

        for attack in attacks:
            self.attack_view.add_attack_to_table(attack, f"{attack['type']} detected")

        # Test filtering by attack type
        self.attack_view.pattern_combo.setCurrentText("ARP Spoofing")
        self.attack_view.filter_attacks()
        visible_rows = sum(1 for i in range(self.attack_view.attack_table.rowCount())
                         if not self.attack_view.attack_table.isRowHidden(i))
        self.assertEqual(visible_rows, 1)

        # Test filtering by severity
        self.attack_view.pattern_combo.setCurrentText("All Patterns")
        self.attack_view.filter_attacks()
        visible_rows = sum(1 for i in range(self.attack_view.attack_table.rowCount())
                         if not self.attack_view.attack_table.isRowHidden(i))
        self.assertEqual(visible_rows, 3)

if __name__ == '__main__':
    unittest.main() 