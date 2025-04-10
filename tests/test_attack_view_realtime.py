import unittest
import sys
from datetime import datetime
from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt, QTimer
from unittest.mock import Mock, patch
from app.components.attack_view import AttackView

class TestAttackViewRealtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        self.attack_view = AttackView()
        self.mock_recognizer = Mock()
        self.attack_view.recognizer = self.mock_recognizer
        
    def tearDown(self):
        self.attack_view.close()
        self.attack_view.deleteLater()
        
    def test_real_time_updates(self):
        """Test real-time attack updates"""
        # Mock attack data
        test_attack = {
            "id": "test-001",
            "type": "ARP Spoofing",
            "severity": "high",
            "detection_time": datetime.now(),
            "source_ip": "192.168.1.10",
            "target_ip": "192.168.1.1",
            "description": "Real-time attack detected"
        }
        
        # Mock the attack detection signal
        self.mock_recognizer.attack_detected = Mock()
        self.mock_recognizer.attack_detected.emit = Mock()
        
        # Add attack to table
        self.attack_view.add_attack_to_table(test_attack, "Attack detected")
        
        # Verify initial state
        self.assertEqual(self.attack_view.attack_table.rowCount(), 1)
        self.assertEqual(self.attack_view.attack_table.item(0, 1).text(), "ARP Spoofing")
        
        # Simulate real-time update
        new_attack = {
            "id": "test-002",
            "type": "Port Scanning",
            "severity": "medium",
            "detection_time": datetime.now(),
            "source_ip": "192.168.1.15",
            "target_ip": "192.168.1.1",
            "description": "New attack detected"
        }
        
        # Trigger attack detection signal
        self.attack_view.attack_detected.emit(new_attack)
        
        # Process events to handle the signal
        QTest.qWait(100)
        
        # Verify new attack was added
        self.assertEqual(self.attack_view.attack_table.rowCount(), 2)
        self.assertEqual(self.attack_view.attack_table.item(1, 1).text(), "Port Scanning")
        
    def test_update_frequency(self):
        """Test attack update frequency"""
        # Mock attack data
        test_attacks = [
            {
                "id": f"test-{i}",
                "type": "ARP Spoofing",
                "severity": "high",
                "detection_time": datetime.now(),
                "source_ip": f"192.168.1.{i+10}",
                "target_ip": "192.168.1.1",
                "description": f"Attack {i} detected"
            } for i in range(5)
        ]
        
        # Add attacks with small delay
        for attack in test_attacks:
            self.attack_view.add_attack_to_table(attack, "Attack detected")
            QTest.qWait(50)  # 50ms delay between updates
            
        # Verify all attacks were added
        self.assertEqual(self.attack_view.attack_table.rowCount(), 5)
        
    def test_performance_under_load(self):
        """Test performance under high update frequency"""
        # Mock attack data
        test_attacks = [
            {
                "id": f"test-{i}",
                "type": "ARP Spoofing",
                "severity": "high",
                "detection_time": datetime.now(),
                "source_ip": f"192.168.1.{i+10}",
                "target_ip": "192.168.1.1",
                "description": f"Attack {i} detected"
            } for i in range(100)
        ]
        
        # Add attacks rapidly
        start_time = datetime.now()
        for attack in test_attacks:
            self.attack_view.add_attack_to_table(attack, "Attack detected")
        end_time = datetime.now()
        
        # Calculate processing time
        processing_time = (end_time - start_time).total_seconds()
        
        # Verify all attacks were added
        self.assertEqual(self.attack_view.attack_table.rowCount(), 100)
        
        # Verify performance (should process 100 attacks in less than 1 second)
        self.assertLess(processing_time, 1.0)
        
    def test_filter_updates(self):
        """Test filtering with real-time updates"""
        # Add initial attacks
        test_attacks = [
            {
                "id": "test-001",
                "type": "ARP Spoofing",
                "severity": "high",
                "detection_time": datetime.now(),
                "source_ip": "192.168.1.10",
                "target_ip": "192.168.1.1",
                "description": "ARP attack detected"
            },
            {
                "id": "test-002",
                "type": "Port Scanning",
                "severity": "medium",
                "detection_time": datetime.now(),
                "source_ip": "192.168.1.15",
                "target_ip": "192.168.1.1",
                "description": "Port scan detected"
            }
        ]
        
        for attack in test_attacks:
            self.attack_view.add_attack_to_table(attack, "Attack detected")
            
        # Set filter to show only ARP attacks
        self.attack_view.pattern_combo.setCurrentText("ARP Spoofing")
        self.attack_view.filter_attacks()
        
        # Verify initial filter
        visible_rows = sum(1 for i in range(self.attack_view.attack_table.rowCount())
                         if not self.attack_view.attack_table.isRowHidden(i))
        self.assertEqual(visible_rows, 1)
        
        # Add new attack of different type
        new_attack = {
            "id": "test-003",
            "type": "DDoS",
            "severity": "critical",
            "detection_time": datetime.now(),
            "source_ip": "192.168.1.20",
            "target_ip": "192.168.1.1",
            "description": "DDoS attack detected"
        }
        
        self.attack_view.add_attack_to_table(new_attack, "Attack detected")
        
        # Verify filter is maintained
        visible_rows = sum(1 for i in range(self.attack_view.attack_table.rowCount())
                         if not self.attack_view.attack_table.isRowHidden(i))
        self.assertEqual(visible_rows, 1)  # Still only showing ARP attacks
        
if __name__ == '__main__':
    unittest.main() 