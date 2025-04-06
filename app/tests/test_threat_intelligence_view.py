import unittest
from unittest.mock import patch, MagicMock, Mock
import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt, QTimer

from app.components.threat_intelligence_view import ThreatIntelligenceView

# Global QApplication instance for all tests
app = QApplication.instance()
if not app:
    app = QApplication(sys.argv)

class TestThreatIntelligenceView(unittest.TestCase):
    """Test suite for the ThreatIntelligenceView component."""

    @patch('app.components.threat_intelligence_view.get_threat_intelligence')
    def setUp(self, mock_get_threat_intel):
        """Set up test environment before each test."""
        # Create mock threat intelligence backend
        self.mock_threat_intel = MagicMock()
        mock_get_threat_intel.return_value = self.mock_threat_intel
        
        # Mock threat intel is_running method
        self.mock_threat_intel.is_running.return_value = False
        
        # Create view component
        self.view = ThreatIntelligenceView()

    def tearDown(self):
        """Clean up after each test."""
        self.view.deleteLater()

    def test_ui_initialization(self):
        """Test that the UI components are initialized correctly."""
        # Check that the main UI components exist
        self.assertIsNotNone(self.view.update_button)
        self.assertIsNotNone(self.view.status_label)
        self.assertIsNotNone(self.view.tabs)
        self.assertIsNotNone(self.view.ip_table)
        self.assertIsNotNone(self.view.domain_table)
        self.assertIsNotNone(self.view.signature_table)
        
        # Check tab initialization
        self.assertEqual(self.view.tabs.count(), 3)
        self.assertEqual(self.view.tabs.tabText(0), "Malicious IPs")
        self.assertEqual(self.view.tabs.tabText(1), "Malicious Domains")
        self.assertEqual(self.view.tabs.tabText(2), "Attack Signatures")
        
        # Check table headers
        ip_headers = [self.view.ip_table.horizontalHeaderItem(i).text() 
                      for i in range(self.view.ip_table.columnCount())]
        self.assertEqual(ip_headers, ["IP Address", "Score", "Categories", "Source"])
        
        domain_headers = [self.view.domain_table.horizontalHeaderItem(i).text() 
                          for i in range(self.view.domain_table.columnCount())]
        self.assertEqual(domain_headers, ["Domain", "Score", "Categories", "Source"])
        
        signature_headers = [self.view.signature_table.horizontalHeaderItem(i).text() 
                             for i in range(self.view.signature_table.columnCount())]
        self.assertEqual(signature_headers, ["ID", "Description", "Severity", "Source"])

    def test_update_button_action(self):
        """Test that the update button triggers threat data update."""
        # Mock the update_threat_data method
        self.view.update_threat_data = Mock()
        
        # Click the update button
        self.view.update_button.click()
        
        # Check if the method was called
        self.view.update_threat_data.assert_called_once()

    @patch('app.components.threat_intelligence_view.threading.Thread')
    def test_update_threat_data(self, mock_thread):
        """Test the update_threat_data method."""
        # Setup mock thread
        mock_thread_instance = Mock()
        mock_thread.return_value = mock_thread_instance
        
        # Call update_threat_data
        self.view.update_threat_data()
        
        # Check UI state changes
        self.assertFalse(self.view.update_button.isEnabled())
        self.assertEqual(self.view.status_label.text(), "Status: Updating...")
        self.assertTrue(self.view.progress_bar.isVisible())
        self.assertEqual(self.view.progress_bar.value(), 10)
        
        # Check thread creation and start
        mock_thread.assert_called_once()
        mock_thread_instance.start.assert_called_once()

    def test_update_complete_success(self):
        """Test handling of successful update completion."""
        # Call _update_complete with success
        details = {
            'malicious_ips_updated': 50,
            'malicious_domains_updated': 30,
            'attack_signatures_updated': 20,
            'sources_successful': ['abuseipdb', 'virustotal'],
            'update_duration': 5.2
        }
        self.view._update_complete(True, "Update successful", details)
        
        # Check UI updates
        self.assertTrue(self.view.update_button.isEnabled())
        self.assertEqual(self.view.status_label.text(), "Status: Update successful")
        self.assertFalse(self.view.progress_bar.isVisible())
        
        # Check that last_update_label was updated
        self.assertIn("Last update:", self.view.last_update_label.text())

    def test_update_complete_failure(self):
        """Test handling of failed update completion."""
        # Call _update_complete with failure
        self.view._update_complete(False, "Update failed", {})
        
        # Check UI updates
        self.assertTrue(self.view.update_button.isEnabled())
        self.assertEqual(self.view.status_label.text(), "Status: Update failed")
        self.assertFalse(self.view.progress_bar.isVisible())

    def test_populate_ip_table(self):
        """Test populating the malicious IPs table."""
        # Create test data
        malicious_ips = {
            "192.168.1.100": {
                "score": 90,
                "categories": [3, 4, 5],
                "source": "abuseipdb",
                "last_updated": "2023-03-15 12:00:00"
            },
            "10.0.0.1": {
                "score": 95,
                "categories": ["phishing", "malware"],
                "source": "virustotal",
                "last_updated": "2023-03-16 14:30:00"
            }
        }
        
        # Mock the get_malicious_ips method
        self.mock_threat_intel.get_malicious_ips.return_value = malicious_ips
        
        # Call the method
        self.view.populate_ip_table()
        
        # Check that table was populated
        self.assertEqual(self.view.ip_table.rowCount(), 2)
        
        # Check contents of first row
        self.assertEqual(self.view.ip_table.item(0, 0).text(), "192.168.1.100")
        self.assertEqual(self.view.ip_table.item(0, 1).text(), "90")
        # Categories might be joined as string
        self.assertTrue("3" in self.view.ip_table.item(0, 2).text())
        self.assertTrue("4" in self.view.ip_table.item(0, 2).text())
        self.assertTrue("5" in self.view.ip_table.item(0, 2).text())
        self.assertEqual(self.view.ip_table.item(0, 3).text(), "abuseipdb")

    def test_populate_domain_table(self):
        """Test populating the malicious domains table."""
        # Create test data
        malicious_domains = {
            "malicious-example.com": {
                "score": 85,
                "categories": ["phishing", "malware"],
                "source": "virustotal",
                "last_updated": "2023-03-15 12:00:00"
            },
            "bad-domain.org": {
                "score": 75,
                "categories": ["spam"],
                "source": "otx",
                "last_updated": "2023-03-16 14:30:00"
            }
        }
        
        # Mock the get_malicious_domains method
        self.mock_threat_intel.get_malicious_domains.return_value = malicious_domains
        
        # Call the method
        self.view.populate_domain_table()
        
        # Check that table was populated
        self.assertEqual(self.view.domain_table.rowCount(), 2)
        
        # Check contents of first row
        self.assertEqual(self.view.domain_table.item(0, 0).text(), "malicious-example.com")
        self.assertEqual(self.view.domain_table.item(0, 1).text(), "85")
        self.assertTrue("phishing" in self.view.domain_table.item(0, 2).text())
        self.assertTrue("malware" in self.view.domain_table.item(0, 2).text())
        self.assertEqual(self.view.domain_table.item(0, 3).text(), "virustotal")

    def test_populate_signature_table(self):
        """Test populating the attack signatures table."""
        # Create test data
        attack_signatures = {
            "ET-1000": {
                "pattern": "test pattern",
                "description": "Test signature",
                "severity": "high",
                "source": "emerging_threats"
            },
            "ET-1001": {
                "pattern": "another pattern",
                "description": "Another test",
                "severity": "medium",
                "source": "otx"
            }
        }
        
        # Mock the get_attack_signatures method
        self.mock_threat_intel.get_attack_signatures.return_value = attack_signatures
        
        # Call the method
        self.view.populate_signature_table()
        
        # Check that table was populated
        self.assertEqual(self.view.signature_table.rowCount(), 2)
        
        # Check contents of first row
        self.assertEqual(self.view.signature_table.item(0, 0).text(), "ET-1000")
        self.assertEqual(self.view.signature_table.item(0, 1).text(), "Test signature")
        self.assertEqual(self.view.signature_table.item(0, 2).text(), "high")
        self.assertEqual(self.view.signature_table.item(0, 3).text(), "emerging_threats")

    def test_filter_malicious_ips(self):
        """Test filtering of malicious IPs based on score and search text."""
        # Create test data
        malicious_ips = {
            "192.168.1.100": {
                "score": 90,
                "categories": [3, 4, 5],
                "source": "abuseipdb",
                "last_updated": "2023-03-15 12:00:00"
            },
            "10.0.0.1": {
                "score": 60,
                "categories": ["phishing", "malware"],
                "source": "virustotal",
                "last_updated": "2023-03-16 14:30:00"
            }
        }
        
        # Mock the get_malicious_ips method
        self.mock_threat_intel.get_malicious_ips.return_value = malicious_ips
        
        # Populate the table first
        self.view.populate_ip_table()
        
        # Set filter threshold to 80
        self.view.ip_score_filter.setValue(80)
        self.view.filter_malicious_ips()
        
        # Should show only the 90-score IP
        self.assertEqual(self.view.ip_table.rowCount(), 1)
        self.assertEqual(self.view.ip_table.item(0, 0).text(), "192.168.1.100")
        
        # Set filter to match by IP text
        self.view.ip_score_filter.setValue(0)  # Show all scores
        self.view.ip_search.setText("10.0")
        self.view.filter_malicious_ips()
        
        # Should show only the 10.0.0.1 IP
        self.assertEqual(self.view.ip_table.rowCount(), 1)
        self.assertEqual(self.view.ip_table.item(0, 0).text(), "10.0.0.1")

    def test_show_signature_details(self):
        """Test displaying attack signature details when selected."""
        # Create test data
        attack_signatures = {
            "ET-1000": {
                "pattern": "test pattern",
                "description": "Test signature",
                "severity": "high",
                "source": "emerging_threats",
                "details": "This is a test signature with additional details."
            }
        }
        
        # Mock the get_attack_signatures method
        self.mock_threat_intel.get_attack_signatures.return_value = attack_signatures
        self.mock_threat_intel.get_signature_details.return_value = attack_signatures["ET-1000"]
        
        # Populate the table
        self.view.populate_signature_table()
        
        # Select the first row
        self.view.signature_table.selectRow(0)
        
        # Should trigger show_signature_details through signal
        self.view.show_signature_details()
        
        # Check that details text was updated
        details_text = self.view.signature_details_text.toPlainText()
        self.assertIn("Test signature", details_text)
        self.assertIn("high", details_text)
        self.assertIn("test pattern", details_text)
        self.assertIn("This is a test signature with additional details", details_text)

    def test_check_for_updates(self):
        """Test auto-update check functionality."""
        # Mock is_running to return False 
        self.mock_threat_intel.is_running.return_value = False
        
        # Mock a last_update time that's older than update_interval
        self.mock_threat_intel.last_update = None
        
        # Mock update_threat_data
        self.view.update_threat_data = Mock()
        
        # Call check_for_updates
        self.view.check_for_updates()
        
        # Should trigger update because last_update is None
        self.view.update_threat_data.assert_called_once()
        
        # Reset mock
        self.view.update_threat_data.reset_mock()
        
        # Set last_update time to recent
        from datetime import datetime
        self.mock_threat_intel.last_update = datetime.now()
        
        # Call check_for_updates again
        self.view.check_for_updates()
        
        # Should not trigger update because last_update is recent
        self.view.update_threat_data.assert_not_called()

if __name__ == '__main__':
    unittest.main() 