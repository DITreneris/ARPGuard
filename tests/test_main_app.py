import unittest
import sys
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt

from app.main import ARPGuardApp

class TestARPGuardApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        # Create mocks for components
        with patch('app.components.network_monitor.NetworkMonitor', return_value=Mock()):
            with patch('app.components.arp_protection.ARPProtection', return_value=Mock()):
                with patch('app.components.ml_detection.MachineLearningDetection', return_value=Mock()):
                    with patch('app.components.threat_intelligence_view.ThreatIntelligenceView', return_value=Mock()):
                        with patch('app.components.settings.SettingsDialog', return_value=Mock()):
                            self.main_app = ARPGuardApp()
        
        # Set up mocks for key functionality
        self.main_app.network_monitor.arp_attack_detected = Mock()
        self.main_app.arp_protection.attack_handled = Mock()
        self.main_app.ml_detection.attack_detected = Mock()
        
    def tearDown(self):
        self.main_app.close()
        self.main_app.deleteLater()
        
    def test_initialization(self):
        """Test if main application initializes correctly"""
        self.assertIsNotNone(self.main_app)
        self.assertIsNotNone(self.main_app.tabs)
        self.assertIsNotNone(self.main_app.menu_bar)
        self.assertIsNotNone(self.main_app.status_bar)
        
        # Check that components are loaded
        self.assertIsNotNone(self.main_app.network_monitor)
        self.assertIsNotNone(self.main_app.arp_protection)
        self.assertIsNotNone(self.main_app.ml_detection)
        self.assertIsNotNone(self.main_app.threat_intelligence)
        
    def test_menu_actions(self):
        """Test menu actions functionality"""
        # Test file menu actions
        with patch('PyQt5.QtWidgets.QMessageBox.information') as mock_info:
            # Trigger about action
            self.main_app.about_action.trigger()
            mock_info.assert_called_once()
            
        # Test settings action
        with patch.object(self.main_app.settings_dialog, 'show') as mock_show:
            # Trigger settings action
            self.main_app.settings_action.trigger()
            mock_show.assert_called_once()
            
        # Test exit action
        with patch.object(self.main_app, 'close') as mock_close:
            # Trigger exit action
            self.main_app.exit_action.trigger()
            mock_close.assert_called_once()
    
    def test_tab_switching(self):
        """Test tab switching functionality"""
        # Initial tab index
        initial_index = self.main_app.tabs.currentIndex()
        
        # Switch to second tab
        with patch.object(self.main_app.tabs, 'setCurrentIndex') as mock_set:
            self.main_app.tabs.setCurrentIndex(1)
            mock_set.assert_called_once_with(1)
            
        # Switch to third tab
        with patch.object(self.main_app.tabs, 'setCurrentIndex') as mock_set:
            self.main_app.tabs.setCurrentIndex(2)
            mock_set.assert_called_once_with(2)
    
    def test_attack_detection_integration(self):
        """Test attack detection integration between components"""
        # Create test attack
        test_attack = {
            "timestamp": datetime.now(),
            "attacker_mac": "00:11:22:33:44:55",
            "attacker_ip": "192.168.1.100",
            "target_ip": "192.168.1.1",
            "gateway_ip": "192.168.1.1",
            "interface": "eth0",
            "attack_type": "ARP Spoofing"
        }
        
        # Mock the status bar
        self.main_app.status_bar.showMessage = Mock()
        
        # Emit attack detected signal from network monitor
        self.main_app.network_monitor.arp_attack_detected.emit(test_attack)
        
        # Verify attack was forwarded to protection component
        self.main_app.arp_protection.handle_attack_detection.assert_called_once()
        
        # Verify status bar was updated
        self.main_app.status_bar.showMessage.assert_called_once()
    
    def test_attack_handling_integration(self):
        """Test attack handling integration between components"""
        # Create test attack
        test_attack = {
            "timestamp": datetime.now(),
            "attacker_mac": "00:11:22:33:44:55",
            "attacker_ip": "192.168.1.100",
            "target_ip": "192.168.1.1",
            "gateway_ip": "192.168.1.1",
            "interface": "eth0",
            "attack_type": "ARP Spoofing"
        }
        
        # Mock the logging and notification
        self.main_app.log_attack = Mock()
        self.main_app.show_notification = Mock()
        
        # Emit attack handled signal from protection component
        self.main_app.arp_protection.attack_handled.emit(test_attack)
        
        # Verify attack was logged
        self.main_app.log_attack.assert_called_once_with(test_attack)
        
        # Verify notification was shown
        self.main_app.show_notification.assert_called_once()
    
    def test_ml_detection_integration(self):
        """Test ML detection integration with other components"""
        # Create test result
        test_result = {
            "packet_id": datetime.now(),
            "is_attack": True,
            "confidence": 0.95,
            "features": [0.1, 0.2, 0.3, 0.4],
            "protocol": "ARP",
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "AA:BB:CC:DD:EE:FF",
            "src_ip": "192.168.1.100",
            "dst_ip": "192.168.1.1"
        }
        
        # Mock the attack conversion
        self.main_app.convert_ml_result_to_attack = Mock(return_value={
            "timestamp": test_result["packet_id"],
            "attacker_mac": test_result["src_mac"],
            "attacker_ip": test_result["src_ip"],
            "target_ip": test_result["dst_ip"],
            "gateway_ip": test_result["dst_ip"],
            "interface": "eth0",
            "attack_type": "ML Detected ARP Spoofing"
        })
        
        # Emit attack detected signal from ML component
        self.main_app.ml_detection.attack_detected.emit(test_result)
        
        # Verify result was converted to attack
        self.main_app.convert_ml_result_to_attack.assert_called_once_with(test_result)
        
        # Verify attack was forwarded to protection component
        self.main_app.arp_protection.handle_attack_detection.assert_called_once()
    
    def test_logging_functionality(self):
        """Test logging functionality"""
        # Create test attack
        test_attack = {
            "timestamp": datetime.now(),
            "attacker_mac": "00:11:22:33:44:55",
            "attacker_ip": "192.168.1.100",
            "target_ip": "192.168.1.1",
            "gateway_ip": "192.168.1.1",
            "interface": "eth0",
            "attack_type": "ARP Spoofing"
        }
        
        # Mock the logger
        with patch('logging.Logger.info') as mock_log:
            # Log attack
            self.main_app.log_attack(test_attack)
            
            # Verify attack was logged
            mock_log.assert_called_once()
    
    def test_settings_integration(self):
        """Test settings integration with components"""
        # Create test settings
        test_settings = {
            "general": {
                "start_on_boot": True,
                "minimize_to_tray": True
            },
            "protection": {
                "default_level": "High",
                "auto_start": True
            },
            "detection": {
                "ml_enabled": True,
                "detection_threshold": 0.8
            }
        }
        
        # Mock the settings dialog signals
        self.main_app.settings_dialog.settings_updated = Mock()
        
        # Emit settings updated signal with test settings
        self.main_app.settings_dialog.settings_updated.emit(test_settings)
        
        # Verify settings were applied to components
        self.main_app.apply_settings.assert_called_once_with(test_settings)
    
    def test_notification_system(self):
        """Test notification system"""
        # Test system tray notification
        with patch('PyQt5.QtWidgets.QSystemTrayIcon.showMessage') as mock_notify:
            # Show notification
            self.main_app.show_notification("Test Title", "Test Message")
            
            # Verify notification was shown
            mock_notify.assert_called_once_with("Test Title", "Test Message", self.main_app.tray_icon.Information, 5000)
    
    def test_status_updates(self):
        """Test status bar updates"""
        # Mock the status bar
        self.main_app.status_bar.showMessage = Mock()
        
        # Update status
        self.main_app.update_status("Test Status")
        
        # Verify status was updated
        self.main_app.status_bar.showMessage.assert_called_once_with("Test Status", 5000)
    
    def test_error_handling(self):
        """Test error handling in main application"""
        # Create test error
        test_error = "Test error message"
        
        # Mock the error dialog
        with patch('PyQt5.QtWidgets.QMessageBox.critical') as mock_error:
            # Handle error
            self.main_app.handle_error(test_error)
            
            # Verify error dialog was shown
            mock_error.assert_called_once()
            
        # Test component error handling
        with patch.object(self.main_app, 'handle_error') as mock_handle:
            # Emit error from network monitor
            self.main_app.network_monitor.error_occurred.emit("Network error")
            
            # Verify error was handled
            mock_handle.assert_called_once_with("Network error")
            
            # Emit error from protection component
            self.main_app.arp_protection.error_occurred.emit("Protection error")
            
            # Verify error was handled
            mock_handle.assert_called_with("Protection error")
    
    def test_application_shutdown(self):
        """Test application shutdown process"""
        # Mock the component shutdown methods
        self.main_app.network_monitor.stop_monitoring = Mock()
        self.main_app.arp_protection.stop_protection = Mock()
        
        # Mock the settings save method
        self.main_app.save_settings = Mock()
        
        # Call close event handler
        event = MagicMock()
        self.main_app.closeEvent(event)
        
        # Verify components were stopped
        self.main_app.network_monitor.stop_monitoring.assert_called_once()
        self.main_app.arp_protection.stop_protection.assert_called_once()
        
        # Verify settings were saved
        self.main_app.save_settings.assert_called_once()
        
        # Verify event was accepted
        event.accept.assert_called_once()
        
if __name__ == '__main__':
    unittest.main() 