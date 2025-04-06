import unittest
from unittest.mock import patch, MagicMock, Mock
import sys
from PyQt5.QtWidgets import QApplication, QTabWidget
from PyQt5.QtCore import Qt, QTimer

from app.components.main_window import MainWindow
from app.components.threat_intelligence_view import ThreatIntelligenceView

# Global QApplication instance for all tests
app = QApplication.instance()
if not app:
    app = QApplication(sys.argv)

class TestMainWindowThreatIntegration(unittest.TestCase):
    """Test suite for the integration of threat intelligence with the main window."""

    @patch('app.components.main_window.NetworkScanner')
    @patch('app.components.main_window.ARPSpoofer')
    @patch('app.components.main_window.ThreatDetector')
    @patch('app.components.main_window.get_threat_intelligence')
    @patch('app.components.main_window.ThreatIntelligenceView')
    @patch('app.components.main_window.get_config')
    @patch('app.components.main_window.get_app_icon')
    def setUp(self, mock_get_icon, mock_get_config, mock_threat_intel_view, 
              mock_get_threat_intel, mock_detector, mock_spoofer, mock_scanner):
        """Set up test environment before each test."""
        # Configure mocks
        mock_get_config.return_value = {
            "app_name": "ARPGuard Test",
            "scanner.auto_scan_on_start": False,
            "detector.start_on_launch": False
        }
        
        # Create mock threat intelligence
        self.mock_threat_intel = MagicMock()
        mock_get_threat_intel.return_value = self.mock_threat_intel
        
        # Create mock threat detector
        self.mock_detector = mock_detector.return_value
        
        # Create main window instance
        self.main_window = MainWindow()
        
        # Replace show_onboarding with a stub to avoid UI prompts
        self.main_window.show_onboarding = lambda: None
        
        # For tab-related tests
        self.threat_intel_tab_index = self.find_tab_index("Threat Intelligence")
        
    def tearDown(self):
        """Clean up after each test."""
        self.main_window.deleteLater()
    
    def find_tab_index(self, tab_name):
        """Helper to find tab index by name."""
        for i in range(self.main_window.tab_widget.count()):
            if self.main_window.tab_widget.tabText(i) == tab_name:
                return i
        return -1
    
    def test_threat_intelligence_tab_exists(self):
        """Test that the threat intelligence tab exists in the main window."""
        self.assertGreaterEqual(self.threat_intel_tab_index, 0)
    
    def test_threat_intelligence_view_initialized(self):
        """Test that the threat intelligence view is properly initialized."""
        self.assertIsNotNone(self.main_window.threat_intel_view)
    
    def test_threat_intel_view_signals_connected(self):
        """Test that the threat intelligence view signals are connected to handlers."""
        # Get the threat intel view from the main window
        threat_intel_view = self.main_window.threat_intel_view
        
        # Check if the signals are connected
        # Using a timeout to avoid blocking if signal is not received
        timer = QTimer()
        timer.setSingleShot(True)
        
        # Test status_changed signal
        status_received = [False]
        
        def on_status_change(status):
            status_received[0] = True
            timer.stop()
        
        # Connect our test slot to the signal
        threat_intel_view.status_changed.connect(on_status_change)
        
        # Emit the signal
        threat_intel_view.status_changed.emit("Test Status")
        
        # Wait for signal processing
        timer.start(100)
        app.processEvents()
        
        # Check that our slot was called
        self.assertTrue(status_received[0])
        
        # Clean up
        threat_intel_view.status_changed.disconnect(on_status_change)
    
    def test_handle_threat_intelligence_update(self):
        """Test that the main window handles threat intelligence updates correctly."""
        # Create a mock for the _integrate_threat_intelligence method
        self.main_window._integrate_threat_intelligence = Mock()
        
        # Create test update data
        update_data = {
            'malicious_ips_updated': 50,
            'malicious_domains_updated': 30,
            'attack_signatures_updated': 20
        }
        
        # Call the handler
        self.main_window.handle_threat_intelligence_update(update_data)
        
        # Check that _integrate_threat_intelligence was called
        self.main_window._integrate_threat_intelligence.assert_called_once()
    
    @patch('app.components.main_window.QMessageBox')
    def test_handle_threat_intelligence_update_with_notification(self, mock_messagebox):
        """Test that the main window shows a notification for significant updates."""
        # Create a mock for the _integrate_threat_intelligence method
        self.main_window._integrate_threat_intelligence = Mock()
        
        # Create test update data with significant changes
        update_data = {
            'malicious_ips_updated': 100,  # Large number of updates
            'malicious_domains_updated': 30,
            'attack_signatures_updated': 20
        }
        
        # Call the handler
        self.main_window.handle_threat_intelligence_update(update_data)
        
        # Check that a notification was shown
        mock_messagebox.information.assert_called_once()
    
    def test_integrate_threat_intelligence(self):
        """Test that threat intelligence data is integrated with the threat detector."""
        # Setup mock data
        malicious_ips = {
            "192.168.1.100": {"score": 90},
            "10.0.0.1": {"score": 95}
        }
        attack_signatures = {
            "ET-1000": {"pattern": "test pattern"},
            "ET-1001": {"pattern": "another pattern"}
        }
        
        # Configure mock threat_intel methods
        self.mock_threat_intel.get_malicious_ips.return_value = malicious_ips
        self.mock_threat_intel.get_attack_signatures.return_value = attack_signatures
        
        # Create copy of original data for comparison
        original_watchlist = self.mock_detector.get_ip_watchlist().copy() if hasattr(self.mock_detector, 'get_ip_watchlist') else []
        
        # Call the method to test
        self.main_window._integrate_threat_intelligence()
        
        # Check that watchlist was updated with malicious IPs
        self.mock_detector.add_ip_to_watchlist.assert_any_call("192.168.1.100")
        self.mock_detector.add_ip_to_watchlist.assert_any_call("10.0.0.1")
        
        # Check that attack patterns were added
        self.mock_detector.add_attack_pattern.assert_any_call("ET-1000", "test pattern")
        self.mock_detector.add_attack_pattern.assert_any_call("ET-1001", "another pattern")
    
    def test_start_threat_intelligence_updates(self):
        """Test that threat intelligence updates can be started from the main window."""
        # Call the method
        self.main_window.start_threat_intelligence_updates()
        
        # Check that threat intelligence updates were started
        self.mock_threat_intel.start_updates.assert_called_once()
        
        # Check that the status message was updated
        self.assertIn("threat intelligence", self.main_window.statusBar().currentMessage().lower())

if __name__ == '__main__':
    unittest.main() 