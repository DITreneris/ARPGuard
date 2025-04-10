import unittest
import sys
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt

from app.components.arp_protection import ARPProtection

class TestARPProtection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        # Create mock for network interface and ARP cache
        with patch('app.utils.network.get_interfaces', return_value=["eth0", "wlan0"]):
            with patch('app.utils.arp.get_arp_cache', return_value=[
                {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "interface": "eth0"},
                {"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:FF", "interface": "eth0"}
            ]):
                self.arp_protection = ARPProtection()
                
        # Mock the protection engine
        self.arp_protection.protection_engine = Mock()
        
    def tearDown(self):
        self.arp_protection.stop_protection()
        self.arp_protection.close()
        self.arp_protection.deleteLater()
        
    def test_initialization(self):
        """Test if ARP protection initializes correctly"""
        self.assertIsNotNone(self.arp_protection)
        self.assertIsNotNone(self.arp_protection.interface_selector)
        self.assertIsNotNone(self.arp_protection.trusted_devices_table)
        self.assertIsNotNone(self.arp_protection.start_button)
        self.assertIsNotNone(self.arp_protection.stop_button)
        
        # Check interface population
        self.assertEqual(self.arp_protection.interface_selector.count(), 2)
        self.assertEqual(self.arp_protection.interface_selector.itemText(0), "eth0")
        self.assertEqual(self.arp_protection.interface_selector.itemText(1), "wlan0")
        
        # Check trusted devices
        self.assertEqual(self.arp_protection.trusted_devices_table.rowCount(), 2)
    
    def test_interface_selection(self):
        """Test interface selection functionality"""
        # Select second interface
        self.arp_protection.interface_selector.setCurrentIndex(1)
        
        # Verify selection
        self.assertEqual(self.arp_protection.interface_selector.currentText(), "wlan0")
        self.assertEqual(self.arp_protection.current_interface, "wlan0")
    
    def test_start_protection(self):
        """Test starting ARP protection"""
        # Set up mock for protection engine
        self.arp_protection.protection_engine.start_protection.return_value = True
        
        # Start protection
        self.arp_protection.start_protection()
        
        # Verify protection started
        self.arp_protection.protection_engine.start_protection.assert_called_once_with(
            self.arp_protection.current_interface, 
            self.arp_protection.trusted_devices
        )
        self.assertTrue(self.arp_protection.is_protecting)
        self.assertFalse(self.arp_protection.start_button.isEnabled())
        self.assertTrue(self.arp_protection.stop_button.isEnabled())
    
    def test_stop_protection(self):
        """Test stopping ARP protection"""
        # Set up mocks
        self.arp_protection.protection_engine.start_protection.return_value = True
        self.arp_protection.protection_engine.stop_protection.return_value = True
        
        # Start then stop protection
        self.arp_protection.start_protection()
        self.arp_protection.stop_protection()
        
        # Verify protection stopped
        self.arp_protection.protection_engine.stop_protection.assert_called_once()
        self.assertFalse(self.arp_protection.is_protecting)
        self.assertTrue(self.arp_protection.start_button.isEnabled())
        self.assertFalse(self.arp_protection.stop_button.isEnabled())
    
    def test_add_trusted_device(self):
        """Test adding a trusted device"""
        # Initial count
        initial_count = self.arp_protection.trusted_devices_table.rowCount()
        
        # Add new trusted device
        new_device = {
            "ip": "192.168.1.3", 
            "mac": "11:22:33:44:55:66", 
            "interface": "eth0",
            "description": "Test Device"
        }
        self.arp_protection.add_trusted_device(new_device)
        
        # Verify device was added
        self.assertEqual(self.arp_protection.trusted_devices_table.rowCount(), initial_count + 1)
        self.assertEqual(self.arp_protection.trusted_devices_table.item(initial_count, 0).text(), new_device["ip"])
        self.assertEqual(self.arp_protection.trusted_devices_table.item(initial_count, 1).text(), new_device["mac"])
        
        # Verify trusted devices list was updated
        self.assertIn(new_device, self.arp_protection.trusted_devices)
    
    def test_remove_trusted_device(self):
        """Test removing a trusted device"""
        # Initial count
        initial_count = self.arp_protection.trusted_devices_table.rowCount()
        
        # Select the first device
        self.arp_protection.trusted_devices_table.selectRow(0)
        
        # Get the device details to compare later
        removed_ip = self.arp_protection.trusted_devices_table.item(0, 0).text()
        
        # Remove the device
        self.arp_protection.remove_trusted_device()
        
        # Verify device was removed
        self.assertEqual(self.arp_protection.trusted_devices_table.rowCount(), initial_count - 1)
        
        # Verify trusted devices list was updated
        removed_devices = [d for d in self.arp_protection.trusted_devices if d["ip"] == removed_ip]
        self.assertEqual(len(removed_devices), 0)
    
    def test_import_trusted_devices(self):
        """Test importing trusted devices from file"""
        # Mock file data
        mock_file_data = """
        {
            "trusted_devices": [
                {"ip": "192.168.1.10", "mac": "AA:AA:AA:AA:AA:AA", "interface": "eth0", "description": "Device 1"},
                {"ip": "192.168.1.11", "mac": "BB:BB:BB:BB:BB:BB", "interface": "eth0", "description": "Device 2"},
                {"ip": "192.168.1.12", "mac": "CC:CC:CC:CC:CC:CC", "interface": "eth0", "description": "Device 3"}
            ]
        }
        """
        
        # Mock open and file dialog
        with patch('builtins.open', unittest.mock.mock_open(read_data=mock_file_data)):
            with patch('PyQt5.QtWidgets.QFileDialog.getOpenFileName', return_value=("test_file.json", "")):
                # Import devices
                self.arp_protection.import_trusted_devices()
                
                # Verify devices were imported
                self.assertEqual(self.arp_protection.trusted_devices_table.rowCount(), 5)  # 2 initial + 3 imported
                
                # Check the imported devices
                imported_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
                for ip in imported_ips:
                    matching_devices = [d for d in self.arp_protection.trusted_devices if d["ip"] == ip]
                    self.assertEqual(len(matching_devices), 1)
    
    def test_export_trusted_devices(self):
        """Test exporting trusted devices to file"""
        # Mock file dialog
        with patch('PyQt5.QtWidgets.QFileDialog.getSaveFileName', return_value=("test_file.json", "")):
            with patch('builtins.open', unittest.mock.mock_open()) as mock_file:
                # Export devices
                self.arp_protection.export_trusted_devices()
                
                # Verify file was written
                mock_file.assert_called_once_with("test_file.json", "w")
                
                # Verify content was written
                write_calls = mock_file().write.call_args_list
                self.assertTrue(len(write_calls) > 0)
    
    def test_handle_attack(self):
        """Test handling an ARP attack"""
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
        
        # Set up mock for response actions
        self.arp_protection.block_attacker = Mock()
        self.arp_protection.restore_arp_cache = Mock()
        
        # Process attack
        self.arp_protection.handle_attack_detection(test_attack)
        
        # Verify attack was handled
        self.arp_protection.block_attacker.assert_called_once_with(test_attack["attacker_mac"], test_attack["attacker_ip"])
        self.arp_protection.restore_arp_cache.assert_called_once()
        
        # Verify attack was added to attack log
        self.assertEqual(self.arp_protection.attack_log_table.rowCount(), 1)
        self.assertEqual(
            self.arp_protection.attack_log_table.item(0, 1).text(), 
            test_attack["attacker_mac"]
        )
    
    def test_protection_levels(self):
        """Test different protection levels"""
        # Test setting protection level
        protection_levels = ["Low", "Medium", "High", "Custom"]
        
        for level in protection_levels:
            # Set protection level
            self.arp_protection.protection_level_selector.setCurrentText(level)
            self.arp_protection.update_protection_settings()
            
            # Verify protection settings updated
            if level == "Low":
                self.assertFalse(self.arp_protection.block_attackers_checkbox.isChecked())
                self.assertTrue(self.arp_protection.log_attacks_checkbox.isChecked())
            elif level == "Medium":
                self.assertTrue(self.arp_protection.block_attackers_checkbox.isChecked())
                self.assertTrue(self.arp_protection.log_attacks_checkbox.isChecked())
            elif level == "High":
                self.assertTrue(self.arp_protection.block_attackers_checkbox.isChecked())
                self.assertTrue(self.arp_protection.log_attacks_checkbox.isChecked())
                self.assertTrue(self.arp_protection.monitor_all_traffic_checkbox.isChecked())
    
    def test_restore_arp_cache(self):
        """Test ARP cache restoration"""
        # Set up mock for ARP cache operations
        with patch('app.utils.arp.restore_arp_entry') as mock_restore:
            # Call restore method
            self.arp_protection.restore_arp_cache()
            
            # Verify all trusted devices were restored
            self.assertEqual(mock_restore.call_count, len(self.arp_protection.trusted_devices))
            
    def test_error_handling(self):
        """Test error handling during protection"""
        # Setup mock to raise exception
        self.arp_protection.protection_engine.start_protection.side_effect = Exception("Protection error")
        
        # Mock error signal
        self.arp_protection.error_occurred = Mock()
        
        # Attempt to start protection
        self.arp_protection.start_protection()
        
        # Verify error handling
        self.arp_protection.error_occurred.emit.assert_called_once()
        self.assertFalse(self.arp_protection.is_protecting)
        
if __name__ == '__main__':
    unittest.main() 