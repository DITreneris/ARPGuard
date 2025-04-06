import unittest
from unittest.mock import Mock, patch
import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt

# Add the app directory to the Python path
sys.path.append('app')

from components.defense_view import DefenseView
from components.defense_mechanism import DefenseMechanism

class TestDefenseView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up the QApplication instance once for all tests"""
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        """Create a fresh DefenseView instance for each test"""
        # Mock the DefenseMechanism dependency
        self.mock_defense_mechanism = Mock(spec=DefenseMechanism)
        with patch('components.defense_view.DefenseMechanism', return_value=self.mock_defense_mechanism):
            self.view = DefenseView()
        
    def tearDown(self):
        """Clean up after each test"""
        self.view.close()
        self.view.deleteLater()
        
    def test_view_initialization(self):
        """Test if defense view initializes correctly with all UI components"""
        # Check if main components are initialized
        self.assertIsNotNone(self.view)
        self.assertIsNotNone(self.view.defense_table)
        self.assertIsNotNone(self.view.status_filter)
        self.assertIsNotNone(self.view.attack_type_filter)
        
        # Check if the main layout is set
        self.assertIsNotNone(self.view.layout())
        
        # Check if the window title is set correctly
        self.assertEqual(self.view.windowTitle(), "Defense Mechanisms")
        
    def test_defense_display(self):
        """Test defense mechanisms display functionality"""
        # Create a test defense item
        test_defense = {
            "attack_type": "ARP Spoofing",
            "target_ip": "192.168.1.1",
            "status": "Active",
            "timestamp": "2024-03-29 10:00:00",
            "details": "Gateway protection enabled"
        }
        
        # Add the defense item to the view
        self.view.add_defense(test_defense)
        
        # Verify the defense item is displayed correctly
        self.assertEqual(self.view.defense_table.rowCount(), 1)
        self.assertEqual(self.view.defense_table.item(0, 0).text(), "ARP Spoofing")
        self.assertEqual(self.view.defense_table.item(0, 1).text(), "192.168.1.1")
        self.assertEqual(self.view.defense_table.item(0, 2).text(), "Active")
        
    def test_status_filtering(self):
        """Test defense filtering by status"""
        # Add test defense items with different statuses
        test_defenses = [
            {"attack_type": "ARP Spoofing", "target_ip": "192.168.1.1", "status": "Active"},
            {"attack_type": "Port Scan", "target_ip": "192.168.1.2", "status": "Inactive"},
            {"attack_type": "DNS Spoofing", "target_ip": "192.168.1.3", "status": "Failed"}
        ]
        
        for defense in test_defenses:
            self.view.add_defense(defense)
            
        # Verify all defenses are initially displayed
        self.assertEqual(self.view.defense_table.rowCount(), 3)
        
        # Set filter to "Active"
        self.view.status_filter.setCurrentText("Active")
        QTest.keyPress(self.view.status_filter, Qt.Key_Return)
        
        # Verify only Active defenses are shown
        visible_rows = 0
        for row in range(self.view.defense_table.rowCount()):
            if not self.view.defense_table.isRowHidden(row):
                visible_rows += 1
                self.assertEqual(self.view.defense_table.item(row, 2).text(), "Active")
        
        self.assertEqual(visible_rows, 1)
        
    def test_attack_type_filtering(self):
        """Test defense filtering by attack type"""
        # Add test defense items with different attack types
        test_defenses = [
            {"attack_type": "ARP Spoofing", "target_ip": "192.168.1.1", "status": "Active"},
            {"attack_type": "Port Scan", "target_ip": "192.168.1.2", "status": "Active"},
            {"attack_type": "DNS Spoofing", "target_ip": "192.168.1.3", "status": "Active"}
        ]
        
        for defense in test_defenses:
            self.view.add_defense(defense)
            
        # Set filter to "Port Scan"
        self.view.attack_type_filter.setCurrentText("Port Scan")
        QTest.keyPress(self.view.attack_type_filter, Qt.Key_Return)
        
        # Verify only Port Scan defenses are shown
        visible_rows = 0
        for row in range(self.view.defense_table.rowCount()):
            if not self.view.defense_table.isRowHidden(row):
                visible_rows += 1
                self.assertEqual(self.view.defense_table.item(row, 0).text(), "Port Scan")
        
        self.assertEqual(visible_rows, 1)
        
    def test_activate_defense(self):
        """Test activating a defense mechanism"""
        # Add a test defense
        test_defense = {
            "attack_type": "ARP Spoofing",
            "target_ip": "192.168.1.1",
            "status": "Inactive"
        }
        
        self.view.add_defense(test_defense)
        
        # Mock the activate_defense method
        self.view.activate_defense = Mock()
        
        # Select the defense row
        self.view.defense_table.selectRow(0)
        
        # Trigger the activate action
        self.view.activate_action.trigger()
        
        # Verify the activate_defense method was called with the correct parameters
        self.view.activate_defense.assert_called_once_with(0)
        
    def test_defense_selection(self):
        """Test defense selection functionality"""
        # Add test defenses
        test_defenses = [
            {"attack_type": "ARP Spoofing", "target_ip": "192.168.1.1", "status": "Active"},
            {"attack_type": "Port Scan", "target_ip": "192.168.1.2", "status": "Inactive"}
        ]
        
        for defense in test_defenses:
            self.view.add_defense(defense)
        
        # Create a mock for the slot that should be called when selection changes
        self.view.on_defense_selected = Mock()
        self.view.defense_table.itemSelectionChanged.connect(self.view.on_defense_selected)
        
        # Select a row
        self.view.defense_table.selectRow(1)
        
        # Verify the signal was emitted and the slot was called
        self.view.on_defense_selected.assert_called_once()

if __name__ == '__main__':
    unittest.main() 