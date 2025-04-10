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
from PyQt5.QtTest import QTest

# Mock threat intelligence service
class MockThreatIntelligence:
    def get_malicious_ips(self):
        return [
            {
                "ip": "1.2.3.4",
                "score": 90,
                "categories": ["malware", "c2"],
                "source": "AbuseIPDB",
                "last_seen": datetime.now()
            },
            {
                "ip": "5.6.7.8",
                "score": 70,
                "categories": ["scanner"],
                "source": "VirusTotal",
                "last_seen": datetime.now()
            }
        ]

    def get_malicious_domains(self):
        return [
            {
                "domain": "malicious.com",
                "score": 85,
                "categories": ["phishing"],
                "source": "VirusTotal",
                "last_seen": datetime.now()
            }
        ]

    def get_attack_signatures(self):
        return [
            {
                "id": "ET-1234",
                "description": "Test malicious signature",
                "severity": "critical",
                "source": "Emerging Threats",
                "last_updated": datetime.now()
            }
        ]

# Create ThreatIntelligenceView class
class ThreatIntelligenceView(QWidget):
    status_changed = pyqtSignal(str)
    threat_data_updated = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.threat_intel = MockThreatIntelligence()
        self.setup_ui()
        
    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        
        # Control panel
        control_panel = QWidget()
        control_layout = QHBoxLayout(control_panel)
        
        self.update_button = QPushButton("Update Threat Data")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search threats...")
        
        control_layout.addWidget(self.search_input)
        control_layout.addStretch()
        control_layout.addWidget(self.update_button)
        
        # Threat data tables
        tables_group = QGroupBox("Threat Intelligence")
        tables_layout = QVBoxLayout(tables_group)
        
        # IP table
        self.ip_table = QTableWidget(0, 5)
        self.ip_table.setHorizontalHeaderLabels(
            ["IP Address", "Score", "Categories", "Source", "Last Seen"]
        )
        self.ip_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.ip_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        # Domain table
        self.domain_table = QTableWidget(0, 5)
        self.domain_table.setHorizontalHeaderLabels(
            ["Domain", "Score", "Categories", "Source", "Last Seen"]
        )
        self.domain_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.domain_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        # Signature table
        self.signature_table = QTableWidget(0, 4)
        self.signature_table.setHorizontalHeaderLabels(
            ["ID", "Description", "Severity", "Source"]
        )
        self.signature_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.signature_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        tables_layout.addWidget(QLabel("Malicious IPs:"))
        tables_layout.addWidget(self.ip_table)
        tables_layout.addWidget(QLabel("Malicious Domains:"))
        tables_layout.addWidget(self.domain_table)
        tables_layout.addWidget(QLabel("Attack Signatures:"))
        tables_layout.addWidget(self.signature_table)
        
        # Add to main layout
        main_layout.addWidget(control_panel)
        main_layout.addWidget(tables_group)
        
        self.status_label = QLabel("Ready")
        main_layout.addWidget(self.status_label)
        
    def refresh_display(self):
        """Refresh all threat data tables"""
        self.update_ip_table()
        self.update_domain_table()
        self.update_signature_table()
        
    def update_ip_table(self):
        """Update malicious IP table"""
        self.ip_table.setRowCount(0)
        for ip_data in self.threat_intel.get_malicious_ips():
            row = self.ip_table.rowCount()
            self.ip_table.insertRow(row)
            
            self.ip_table.setItem(row, 0, QTableWidgetItem(ip_data["ip"]))
            self.ip_table.setItem(row, 1, QTableWidgetItem(str(ip_data["score"])))
            self.ip_table.setItem(row, 2, QTableWidgetItem(", ".join(ip_data["categories"])))
            self.ip_table.setItem(row, 3, QTableWidgetItem(ip_data["source"]))
            self.ip_table.setItem(row, 4, QTableWidgetItem(
                ip_data["last_seen"].strftime("%Y-%m-%d %H:%M:%S")
            ))
            
    def update_domain_table(self):
        """Update malicious domain table"""
        self.domain_table.setRowCount(0)
        for domain_data in self.threat_intel.get_malicious_domains():
            row = self.domain_table.rowCount()
            self.domain_table.insertRow(row)
            
            self.domain_table.setItem(row, 0, QTableWidgetItem(domain_data["domain"]))
            self.domain_table.setItem(row, 1, QTableWidgetItem(str(domain_data["score"])))
            self.domain_table.setItem(row, 2, QTableWidgetItem(", ".join(domain_data["categories"])))
            self.domain_table.setItem(row, 3, QTableWidgetItem(domain_data["source"]))
            self.domain_table.setItem(row, 4, QTableWidgetItem(
                domain_data["last_seen"].strftime("%Y-%m-%d %H:%M:%S")
            ))
            
    def update_signature_table(self):
        """Update attack signature table"""
        self.signature_table.setRowCount(0)
        for sig_data in self.threat_intel.get_attack_signatures():
            row = self.signature_table.rowCount()
            self.signature_table.insertRow(row)
            
            self.signature_table.setItem(row, 0, QTableWidgetItem(sig_data["id"]))
            self.signature_table.setItem(row, 1, QTableWidgetItem(sig_data["description"]))
            self.signature_table.setItem(row, 2, QTableWidgetItem(sig_data["severity"]))
            self.signature_table.setItem(row, 3, QTableWidgetItem(sig_data["source"]))

class TestThreatIntelligenceView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        self.threat_view = ThreatIntelligenceView()
        self.mock_intelligence = MagicMock()
        self.threat_view.intelligence = self.mock_intelligence
        
    def tearDown(self):
        self.threat_view.close()
        self.threat_view.deleteLater()
        
    def test_initialization(self):
        """Test if threat intelligence view initializes correctly"""
        self.assertIsNotNone(self.threat_view)
        self.assertIsNotNone(self.threat_view.ip_table)
        self.assertIsNotNone(self.threat_view.domain_table)
        self.assertIsNotNone(self.threat_view.signature_table)
        self.assertIsNotNone(self.threat_view.update_button)
        self.assertIsNotNone(self.threat_view.search_input)
        
    def test_threat_data_display(self):
        """Test threat data display functionality"""
        # Mock threat data
        test_threat = {
            "id": "threat-001",
            "type": "Malware",
            "severity": "high",
            "source": "External",
            "detection_time": datetime.now(),
            "description": "New malware variant detected",
            "affected_systems": ["192.168.1.10", "192.168.1.15"],
            "recommendations": ["Update antivirus", "Scan affected systems"]
        }
        
        # Add threat to view
        self.threat_view.add_threat(test_threat)
        
        # Verify threat was added
        self.assertEqual(self.threat_view.threat_table.rowCount(), 1)
        self.assertEqual(self.threat_view.threat_table.item(0, 1).text(), "Malware")
        
    def test_threat_filtering(self):
        """Test threat filtering functionality"""
        # Add multiple threats
        test_threats = [
            {
                "id": "threat-001",
                "type": "Malware",
                "severity": "high",
                "source": "External",
                "detection_time": datetime.now(),
                "description": "Malware threat",
                "affected_systems": ["192.168.1.10"],
                "recommendations": ["Update antivirus"]
            },
            {
                "id": "threat-002",
                "type": "Phishing",
                "severity": "medium",
                "source": "Email",
                "detection_time": datetime.now(),
                "description": "Phishing attempt",
                "affected_systems": ["192.168.1.15"],
                "recommendations": ["User training"]
            }
        ]
        
        for threat in test_threats:
            self.threat_view.add_threat(threat)
            
        # Set filter to show only high severity threats
        self.threat_view.severity_combo.setCurrentText("High")
        self.threat_view.filter_threats()
        
        # Verify filter
        visible_rows = sum(1 for i in range(self.threat_view.threat_table.rowCount())
                         if not self.threat_view.threat_table.isRowHidden(i))
        self.assertEqual(visible_rows, 1)
        
    def test_threat_details(self):
        """Test threat details display"""
        # Mock threat data
        test_threat = {
            "id": "threat-001",
            "type": "Malware",
            "severity": "high",
            "source": "External",
            "detection_time": datetime.now(),
            "description": "Detailed malware description",
            "affected_systems": ["192.168.1.10", "192.168.1.15"],
            "recommendations": ["Update antivirus", "Scan systems", "Isolate affected machines"]
        }
        
        # Add threat and select it
        self.threat_view.add_threat(test_threat)
        self.threat_view.threat_table.selectRow(0)
        
        # Verify details are displayed
        self.assertEqual(self.threat_view.description_label.text(), "Detailed malware description")
        self.assertEqual(len(self.threat_view.recommendations_list), 3)
        
    def test_threat_update(self):
        """Test real-time threat updates"""
        # Initial threat
        test_threat = {
            "id": "threat-001",
            "type": "Malware",
            "severity": "high",
            "source": "External",
            "detection_time": datetime.now(),
            "description": "Initial threat",
            "affected_systems": ["192.168.1.10"],
            "recommendations": ["Initial action"]
        }
        
        self.threat_view.add_threat(test_threat)
        
        # Updated threat
        updated_threat = {
            "id": "threat-001",
            "type": "Malware",
            "severity": "critical",
            "source": "External",
            "detection_time": datetime.now(),
            "description": "Updated threat",
            "affected_systems": ["192.168.1.10", "192.168.1.15"],
            "recommendations": ["Updated action 1", "Updated action 2"]
        }
        
        # Update threat
        self.threat_view.update_threat(updated_threat)
        
        # Verify update
        self.assertEqual(self.threat_view.threat_table.item(0, 2).text(), "Critical")
        self.assertEqual(self.threat_view.description_label.text(), "Updated threat")
        self.assertEqual(len(self.threat_view.recommendations_list), 2)
        
    def test_performance(self):
        """Test performance with multiple threats"""
        # Generate 100 test threats
        test_threats = [
            {
                "id": f"threat-{i}",
                "type": "Malware",
                "severity": "high",
                "source": "External",
                "detection_time": datetime.now(),
                "description": f"Threat {i}",
                "affected_systems": [f"192.168.1.{i+10}"],
                "recommendations": ["Action 1", "Action 2"]
            } for i in range(100)
        ]
        
        # Add threats and measure time
        start_time = datetime.now()
        for threat in test_threats:
            self.threat_view.add_threat(threat)
        end_time = datetime.now()
        
        # Calculate processing time
        processing_time = (end_time - start_time).total_seconds()
        
        # Verify all threats were added
        self.assertEqual(self.threat_view.threat_table.rowCount(), 100)
        
        # Verify performance (should process 100 threats in less than 1 second)
        self.assertLess(processing_time, 1.0)
        
    def test_export_functionality(self):
        """Test the export functionality for threat data"""
        # Add test threats
        test_threats = [
            {
                "id": "threat-001",
                "type": "Malware",
                "severity": "high",
                "source": "External",
                "detection_time": datetime.now(),
                "description": "Test malware",
                "affected_systems": ["192.168.1.10"],
                "recommendations": ["Update antivirus"]
            }
        ]
        
        for threat in test_threats:
            self.threat_view.add_threat(threat)
            
        # Test CSV export
        with patch('builtins.open', unittest.mock.mock_open()) as mock_file:
            self.threat_view.export_to_csv("test_export.csv")
            mock_file.assert_called_once_with("test_export.csv", "w", newline='')
            
        # Test JSON export
        with patch('builtins.open', unittest.mock.mock_open()) as mock_file:
            self.threat_view.export_to_json("test_export.json")
            mock_file.assert_called_once_with("test_export.json", "w")
            
    def test_threat_history(self):
        """Test the threat history functionality"""
        # Add initial threat
        test_threat = {
            "id": "threat-001",
            "type": "Malware",
            "severity": "medium",
            "source": "External",
            "detection_time": datetime.now(),
            "description": "Initial detection",
            "affected_systems": ["192.168.1.10"],
            "recommendations": ["Initial action"]
        }
        
        self.threat_view.add_threat(test_threat)
        
        # Get history before updates
        initial_history = self.threat_view.get_threat_history("threat-001")
        self.assertEqual(len(initial_history), 1)
        
        # Update threat multiple times
        for i in range(3):
            updated_threat = test_threat.copy()
            updated_threat["severity"] = ["medium", "high", "critical"][i]
            updated_threat["description"] = f"Update {i+1}"
            self.threat_view.update_threat(updated_threat)
            
        # Get history after updates
        final_history = self.threat_view.get_threat_history("threat-001")
        self.assertEqual(len(final_history), 4)  # Initial + 3 updates
        self.assertEqual(final_history[-1]["severity"], "critical")
        
    def test_threat_correlation(self):
        """Test threat correlation functionality"""
        # Add multiple related threats
        test_threats = [
            {
                "id": "threat-001",
                "type": "Malware",
                "severity": "high",
                "source": "External",
                "detection_time": datetime.now(),
                "description": "Malware on system 1",
                "affected_systems": ["192.168.1.10"],
                "recommendations": ["Update antivirus"]
            },
            {
                "id": "threat-002",
                "type": "Exfiltration",
                "severity": "critical",
                "source": "Internal",
                "detection_time": datetime.now(),
                "description": "Data exfiltration from system 1",
                "affected_systems": ["192.168.1.10"],
                "recommendations": ["Isolate system"]
            }
        ]
        
        for threat in test_threats:
            self.threat_view.add_threat(threat)
            
        # Run correlation
        with patch.object(self.threat_view, 'threat_correlated') as mock_signal:
            correlated = self.threat_view.correlate_threats()
            self.assertTrue(correlated)
            self.assertEqual(mock_signal.emit.call_count, 1)
            
        # Check correlation results
        correlation_results = self.threat_view.get_correlation_results()
        self.assertEqual(len(correlation_results), 1)
        self.assertIn("threat-001", correlation_results[0]["related_threats"])
        self.assertIn("threat-002", correlation_results[0]["related_threats"])
        
    def test_search_functionality(self):
        """Test the search functionality for threats"""
        # Add multiple threats
        test_threats = [
            {
                "id": "threat-001",
                "type": "Malware",
                "severity": "high",
                "source": "External",
                "detection_time": datetime.now(),
                "description": "Ransomware attack",
                "affected_systems": ["192.168.1.10"],
                "recommendations": ["Update antivirus"]
            },
            {
                "id": "threat-002",
                "type": "Phishing",
                "severity": "medium",
                "source": "Email",
                "detection_time": datetime.now(),
                "description": "Credential phishing campaign",
                "affected_systems": ["192.168.1.15"],
                "recommendations": ["User training"]
            }
        ]
        
        for threat in test_threats:
            self.threat_view.add_threat(threat)
            
        # Test search by description
        self.threat_view.search_input.setText("Ransomware")
        self.threat_view.search_threats()
        
        # Verify search results
        visible_rows = sum(1 for i in range(self.threat_view.threat_table.rowCount())
                         if not self.threat_view.threat_table.isRowHidden(i))
        self.assertEqual(visible_rows, 1)
        
        # Clear search
        self.threat_view.search_input.clear()
        self.threat_view.search_threats()
        
        # Verify all threats visible again
        visible_rows = sum(1 for i in range(self.threat_view.threat_table.rowCount())
                         if not self.threat_view.threat_table.isRowHidden(i))
        self.assertEqual(visible_rows, 2)
        
    def test_threat_scoring(self):
        """Test threat scoring and prioritization"""
        # Add threats with different severities
        test_threats = [
            {
                "id": "threat-001",
                "type": "Malware",
                "severity": "low",
                "source": "External",
                "detection_time": datetime.now(),
                "description": "Low severity threat",
                "affected_systems": ["192.168.1.10"],
                "recommendations": ["Monitor"]
            },
            {
                "id": "threat-002",
                "type": "Phishing",
                "severity": "medium",
                "source": "Email",
                "detection_time": datetime.now(),
                "description": "Medium severity threat",
                "affected_systems": ["192.168.1.15"],
                "recommendations": ["User training"]
            },
            {
                "id": "threat-003",
                "type": "Ransomware",
                "severity": "critical",
                "source": "External",
                "detection_time": datetime.now(),
                "description": "Critical severity threat",
                "affected_systems": ["192.168.1.20"],
                "recommendations": ["Isolate system"]
            }
        ]
        
        for threat in test_threats:
            self.threat_view.add_threat(threat)
            
        # Test prioritization functionality
        self.threat_view.prioritize_threats()
        
        # Verify threats are sorted by severity
        self.assertEqual(self.threat_view.threat_table.item(0, 0).text(), "threat-003")  # Critical first
        self.assertEqual(self.threat_view.threat_table.item(1, 0).text(), "threat-002")  # Medium second
        self.assertEqual(self.threat_view.threat_table.item(2, 0).text(), "threat-001")  # Low last
        
        # Calculate threat score
        threat_scores = self.threat_view.calculate_threat_scores()
        self.assertGreater(threat_scores["threat-003"], threat_scores["threat-002"])
        self.assertGreater(threat_scores["threat-002"], threat_scores["threat-001"])

if __name__ == '__main__':
    unittest.main() 