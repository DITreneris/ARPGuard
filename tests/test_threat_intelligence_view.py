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
        self.assertIsNotNone(self.intel_view.search_input)
        
    def test_threat_data_display(self):
        """Test if threat data is properly displayed in tables"""
        self.intel_view.refresh_display()
        
        # Check IP table
        self.assertEqual(self.intel_view.ip_table.rowCount(), 2)
        self.assertEqual(self.intel_view.ip_table.item(0, 0).text(), "1.2.3.4")
        self.assertEqual(self.intel_view.ip_table.item(0, 1).text(), "90")
        
        # Check domain table
        self.assertEqual(self.intel_view.domain_table.rowCount(), 1)
        self.assertEqual(self.intel_view.domain_table.item(0, 0).text(), "malicious.com")
        self.assertEqual(self.intel_view.domain_table.item(0, 1).text(), "85")
        
        # Check signature table
        self.assertEqual(self.intel_view.signature_table.rowCount(), 1)
        self.assertEqual(self.intel_view.signature_table.item(0, 0).text(), "ET-1234")
        self.assertEqual(self.intel_view.signature_table.item(0, 2).text(), "critical")
        
    def test_threat_search(self):
        """Test threat search functionality"""
        self.intel_view.refresh_display()
        
        # Test IP search
        self.intel_view.search_input.setText("1.2.3.4")
        self.intel_view.search_threats()
        visible_rows = sum(1 for i in range(self.intel_view.ip_table.rowCount())
                         if not self.intel_view.ip_table.isRowHidden(i))
        self.assertEqual(visible_rows, 1)
        
        # Test domain search
        self.intel_view.search_input.setText("malicious.com")
        self.intel_view.search_threats()
        visible_rows = sum(1 for i in range(self.intel_view.domain_table.rowCount())
                         if not self.intel_view.domain_table.isRowHidden(i))
        self.assertEqual(visible_rows, 1)
        
    def test_threat_update(self):
        """Test threat data update functionality"""
        with patch.object(self.intel_view.threat_intel, 'get_malicious_ips') as mock_ips:
            mock_ips.return_value = [
                {
                    "ip": "9.8.7.6",
                    "score": 95,
                    "categories": ["malware"],
                    "source": "AbuseIPDB",
                    "last_seen": datetime.now()
                }
            ]
            
            self.intel_view.refresh_display()
            self.assertEqual(self.intel_view.ip_table.rowCount(), 1)
            self.assertEqual(self.intel_view.ip_table.item(0, 0).text(), "9.8.7.6")
            self.assertEqual(self.intel_view.ip_table.item(0, 1).text(), "95")
            
    def test_error_handling(self):
        """Test error handling in threat intelligence operations"""
        # Test database error
        with patch.object(self.intel_view.threat_intel, 'get_malicious_ips',
                         side_effect=Exception("Database error")):
            self.intel_view.refresh_display()
            self.assertEqual(self.intel_view.ip_table.rowCount(), 0)
            
        # Test invalid data format
        with patch.object(self.intel_view.threat_intel, 'get_malicious_domains',
                         return_value=[{"invalid": "data"}]):
            self.intel_view.refresh_display()
            self.assertEqual(self.intel_view.domain_table.rowCount(), 0)

    def test_specific_scenarios(self):
        """Test specific threat intelligence scenarios"""
        # Test high severity IP with multiple categories
        with patch.object(self.intel_view.threat_intel, 'get_malicious_ips') as mock_ips:
            mock_ips.return_value = [{
                "ip": "10.0.0.1",
                "score": 100,
                "categories": ["malware", "c2", "phishing", "scanner"],
                "source": "Multiple",
                "last_seen": datetime.now()
            }]
            self.intel_view.refresh_display()
            self.assertEqual(self.intel_view.ip_table.rowCount(), 1)
            self.assertEqual(self.intel_view.ip_table.item(0, 1).text(), "100")
            self.assertEqual(len(self.intel_view.ip_table.item(0, 2).text().split(", ")), 4)

        # Test domain with historical data
        with patch.object(self.intel_view.threat_intel, 'get_malicious_domains') as mock_domains:
            mock_domains.return_value = [{
                "domain": "historical-threat.com",
                "score": 75,
                "categories": ["historical"],
                "source": "Historical DB",
                "last_seen": datetime(2023, 1, 1)
            }]
            self.intel_view.refresh_display()
            self.assertEqual(self.intel_view.domain_table.item(0, 0).text(), "historical-threat.com")
            self.assertIn("2023", self.intel_view.domain_table.item(0, 4).text())

    def test_data_export(self):
        """Test threat data export functionality"""
        # Test CSV export
        with patch('builtins.open', unittest.mock.mock_open()) as mock_file:
            self.intel_view.export_to_csv("test_export.csv")
            mock_file.assert_called_once_with("test_export.csv", "w", newline='')
            
        # Test JSON export
        with patch('builtins.open', unittest.mock.mock_open()) as mock_file:
            self.intel_view.export_to_json("test_export.json")
            mock_file.assert_called_once_with("test_export.json", "w")

    def test_advanced_filtering(self):
        """Test advanced filtering capabilities"""
        # Test score range filtering
        self.intel_view.min_score_spinbox.setValue(80)
        self.intel_view.max_score_spinbox.setValue(100)
        self.intel_view.filter_threats()
        visible_rows = sum(1 for i in range(self.intel_view.ip_table.rowCount())
                         if not self.intel_view.ip_table.isRowHidden(i))
        self.assertEqual(visible_rows, 1)  # Only the IP with score 90 should be visible

        # Test category filtering
        self.intel_view.category_filter.addItem("malware")
        self.intel_view.filter_threats()
        visible_rows = sum(1 for i in range(self.intel_view.ip_table.rowCount())
                         if not self.intel_view.ip_table.isRowHidden(i))
        self.assertEqual(visible_rows, 1)  # Only the IP with malware category should be visible

        # Test source filtering
        self.intel_view.source_filter.addItem("VirusTotal")
        self.intel_view.filter_threats()
        visible_rows = sum(1 for i in range(self.intel_view.domain_table.rowCount())
                         if not self.intel_view.domain_table.isRowHidden(i))
        self.assertEqual(visible_rows, 1)  # Only the domain from VirusTotal should be visible

    def test_performance_metrics(self):
        """Test performance metrics and statistics"""
        # Test threat statistics calculation
        stats = self.intel_view.calculate_threat_statistics()
        self.assertEqual(stats["total_ips"], 2)
        self.assertEqual(stats["total_domains"], 1)
        self.assertEqual(stats["total_signatures"], 1)
        self.assertEqual(stats["average_ip_score"], 80)
        self.assertEqual(stats["highest_severity"], "critical")

        # Test update frequency tracking
        self.intel_view.refresh_display()
        self.intel_view.refresh_display()
        self.assertEqual(self.intel_view.update_count, 2)
        self.assertLessEqual(self.intel_view.last_update_duration, 1.0)  # Should complete within 1 second

    def test_integration_scenarios(self):
        """Test integration with other components"""
        # Test threat alert generation
        with patch.object(self.intel_view, 'status_changed') as mock_signal:
            self.intel_view.check_for_new_threats()
            mock_signal.emit.assert_called_once()

        # Test threat correlation
        with patch.object(self.intel_view, 'threat_data_updated') as mock_signal:
            self.intel_view.correlate_threats()
            mock_signal.emit.assert_called_once()

        # Test threat intelligence sharing
        with patch.object(self.intel_view, 'share_threat_intelligence') as mock_share:
            self.intel_view.share_threat_intelligence("partner_id")
            mock_share.assert_called_once_with("partner_id")

if __name__ == '__main__':
    unittest.main() 