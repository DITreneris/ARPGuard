import unittest
import sys
import json
from unittest.mock import Mock, patch, mock_open

from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt

from app.components.settings import SettingsDialog

class TestSettingsDialog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        # Mock config file
        mock_config = {
            "general": {
                "start_on_boot": True,
                "minimize_to_tray": True,
                "check_updates": True
            },
            "protection": {
                "default_level": "Medium",
                "auto_start": False,
                "block_attackers": True,
                "restore_cache": True
            },
            "detection": {
                "ml_enabled": True,
                "detection_threshold": 0.7,
                "use_default_model": True,
                "custom_model_path": ""
            },
            "logging": {
                "log_level": "INFO",
                "max_log_size": 10,
                "log_retention": 30,
                "log_to_syslog": False
            },
            "network": {
                "default_interface": "eth0",
                "monitor_mode": False,
                "packet_buffer_size": 1000
            }
        }
        
        # Mock the config file loading
        with patch('builtins.open', mock_open(read_data=json.dumps(mock_config))):
            with patch('os.path.exists', return_value=True):
                self.settings_dialog = SettingsDialog()
                
        # Mock signals
        self.settings_dialog.settings_updated = Mock()
        
    def tearDown(self):
        self.settings_dialog.close()
        self.settings_dialog.deleteLater()
        
    def test_initialization(self):
        """Test if settings dialog initializes correctly"""
        self.assertIsNotNone(self.settings_dialog)
        self.assertIsNotNone(self.settings_dialog.tabs)
        
        # Check tabs
        self.assertIsNotNone(self.settings_dialog.general_tab)
        self.assertIsNotNone(self.settings_dialog.protection_tab)
        self.assertIsNotNone(self.settings_dialog.detection_tab)
        self.assertIsNotNone(self.settings_dialog.logging_tab)
        self.assertIsNotNone(self.settings_dialog.network_tab)
        
        # Check buttons
        self.assertIsNotNone(self.settings_dialog.save_button)
        self.assertIsNotNone(self.settings_dialog.cancel_button)
        self.assertIsNotNone(self.settings_dialog.defaults_button)
    
    def test_loading_settings(self):
        """Test loading settings from config"""
        # Verify settings were loaded correctly
        self.assertTrue(self.settings_dialog.start_on_boot_checkbox.isChecked())
        self.assertTrue(self.settings_dialog.minimize_to_tray_checkbox.isChecked())
        self.assertTrue(self.settings_dialog.check_updates_checkbox.isChecked())
        
        # Protection settings
        self.assertEqual(self.settings_dialog.protection_level_combo.currentText(), "Medium")
        self.assertFalse(self.settings_dialog.auto_start_protection_checkbox.isChecked())
        self.assertTrue(self.settings_dialog.block_attackers_checkbox.isChecked())
        
        # Detection settings
        self.assertTrue(self.settings_dialog.ml_enabled_checkbox.isChecked())
        self.assertEqual(self.settings_dialog.threshold_slider.value(), 70)  # 0.7 * 100
    
    def test_saving_settings(self):
        """Test saving settings to config"""
        # Modify some settings
        self.settings_dialog.start_on_boot_checkbox.setChecked(False)
        self.settings_dialog.protection_level_combo.setCurrentText("High")
        self.settings_dialog.threshold_slider.setValue(80)  # 0.8
        
        # Mock file writing
        with patch('builtins.open', mock_open()) as mock_file:
            # Save settings
            self.settings_dialog.save_settings()
            
            # Verify file was written
            mock_file.assert_called_once()
            
            # Check that settings_updated signal was emitted
            self.settings_dialog.settings_updated.emit.assert_called_once()
    
    def test_restoring_defaults(self):
        """Test restoring default settings"""
        # First change some settings
        self.settings_dialog.start_on_boot_checkbox.setChecked(False)
        self.settings_dialog.protection_level_combo.setCurrentText("High")
        self.settings_dialog.threshold_slider.setValue(80)
        
        # Restore defaults
        with patch.object(self.settings_dialog, 'load_default_settings') as mock_load:
            self.settings_dialog.restore_defaults()
            mock_load.assert_called_once()
    
    def test_cancel_operation(self):
        """Test cancel operation"""
        # First change some settings
        original_boot = self.settings_dialog.start_on_boot_checkbox.isChecked()
        self.settings_dialog.start_on_boot_checkbox.setChecked(not original_boot)
        
        # Mock close method
        with patch.object(self.settings_dialog, 'close') as mock_close:
            # Cancel settings
            self.settings_dialog.cancel_changes()
            
            # Verify dialog was closed
            mock_close.assert_called_once()
            
            # Verify settings were not saved (no signal emitted)
            self.settings_dialog.settings_updated.emit.assert_not_called()
    
    def test_protection_level_settings(self):
        """Test protection level settings changes"""
        # Test different protection levels
        protection_levels = ["Low", "Medium", "High", "Custom"]
        
        for level in protection_levels:
            # Select protection level
            self.settings_dialog.protection_level_combo.setCurrentText(level)
            
            # Trigger currentTextChanged signal
            self.settings_dialog.protection_level_combo.currentTextChanged.emit(level)
            
            # Verify protection settings updated
            if level == "Low":
                self.assertFalse(self.settings_dialog.block_attackers_checkbox.isChecked())
                self.assertTrue(self.settings_dialog.log_attacks_checkbox.isChecked())
            elif level == "Medium":
                self.assertTrue(self.settings_dialog.block_attackers_checkbox.isChecked())
                self.assertTrue(self.settings_dialog.log_attacks_checkbox.isChecked())
            elif level == "High":
                self.assertTrue(self.settings_dialog.block_attackers_checkbox.isChecked())
                self.assertTrue(self.settings_dialog.log_attacks_checkbox.isChecked())
                self.assertTrue(self.settings_dialog.monitor_all_traffic_checkbox.isChecked())
    
    def test_threshold_slider_updates(self):
        """Test threshold slider updates"""
        # Initial value
        initial_value = self.settings_dialog.threshold_value_label.text()
        
        # Change slider value
        self.settings_dialog.threshold_slider.setValue(90)
        
        # Trigger valueChanged signal
        self.settings_dialog.threshold_slider.valueChanged.emit(90)
        
        # Verify label was updated
        self.assertEqual(self.settings_dialog.threshold_value_label.text(), "0.90")
        self.assertNotEqual(self.settings_dialog.threshold_value_label.text(), initial_value)
    
    def test_model_selection(self):
        """Test model selection functionality"""
        # Mock file dialog
        with patch('PyQt5.QtWidgets.QFileDialog.getOpenFileName', return_value=("/path/to/model.pkl", "")):
            # Initial state
            self.assertTrue(self.settings_dialog.use_default_model_radio.isChecked())
            self.assertFalse(self.settings_dialog.use_custom_model_radio.isChecked())
            
            # Change to custom model
            self.settings_dialog.use_custom_model_radio.setChecked(True)
            
            # Browse for model
            self.settings_dialog.browse_model()
            
            # Verify path was updated
            self.assertEqual(self.settings_dialog.custom_model_path_edit.text(), "/path/to/model.pkl")
            
            # Verify model selection was updated
            self.assertFalse(self.settings_dialog.use_default_model_radio.isChecked())
            self.assertTrue(self.settings_dialog.use_custom_model_radio.isChecked())
    
    def test_log_level_selection(self):
        """Test log level selection"""
        # Test different log levels
        log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        
        for level in log_levels:
            # Select log level
            self.settings_dialog.log_level_combo.setCurrentText(level)
            
            # Verify log level was selected
            self.assertEqual(self.settings_dialog.log_level_combo.currentText(), level)
    
    def test_network_interface_selection(self):
        """Test network interface selection"""
        # Mock available interfaces
        with patch('app.utils.network.get_interfaces', return_value=["eth0", "wlan0", "lo"]):
            # Refresh interfaces
            self.settings_dialog.refresh_interfaces()
            
            # Verify interfaces were loaded
            self.assertEqual(self.settings_dialog.interface_combo.count(), 3)
            
            # Select interface
            self.settings_dialog.interface_combo.setCurrentText("wlan0")
            
            # Verify interface was selected
            self.assertEqual(self.settings_dialog.interface_combo.currentText(), "wlan0")
    
    def test_validation(self):
        """Test settings validation"""
        # Valid settings should return True
        self.assertTrue(self.settings_dialog.validate_settings())
        
        # Test invalid log size
        self.settings_dialog.max_log_size_edit.setText("invalid")
        self.assertFalse(self.settings_dialog.validate_settings())
        
        # Reset to valid
        self.settings_dialog.max_log_size_edit.setText("10")
        
        # Test invalid retention period
        self.settings_dialog.log_retention_edit.setText("invalid")
        self.assertFalse(self.settings_dialog.validate_settings())
        
        # Reset to valid
        self.settings_dialog.log_retention_edit.setText("30")
        
        # Test missing custom model path
        self.settings_dialog.use_custom_model_radio.setChecked(True)
        self.settings_dialog.custom_model_path_edit.setText("")
        self.assertFalse(self.settings_dialog.validate_settings())
    
    def test_get_current_settings(self):
        """Test getting current settings"""
        # Get settings
        settings = self.settings_dialog.get_current_settings()
        
        # Verify settings structure
        self.assertIn("general", settings)
        self.assertIn("protection", settings)
        self.assertIn("detection", settings)
        self.assertIn("logging", settings)
        self.assertIn("network", settings)
        
        # Verify some specific settings
        self.assertIn("start_on_boot", settings["general"])
        self.assertIn("default_level", settings["protection"])
        self.assertIn("detection_threshold", settings["detection"])
        self.assertIn("log_level", settings["logging"])
        self.assertIn("default_interface", settings["network"])
        
if __name__ == '__main__':
    unittest.main() 