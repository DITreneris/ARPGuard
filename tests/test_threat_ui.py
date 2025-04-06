import unittest
from unittest.mock import Mock, patch
import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt

# Add the app directory to the Python path
sys.path.append('app')

from components.threat_detector import ThreatDetector
from components.threat_intelligence_view import ThreatIntelligenceView
from components.network_scanner import NetworkScanner
from components.attack_view import AttackView

class TestThreatIntelligenceView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        self.view = ThreatIntelligenceView()
        
    def tearDown(self):
        self.view.close()
        self.view.deleteLater()
        
    def test_view_initialization(self):
        """Test if threat intelligence view initializes correctly"""
        self.assertIsNotNone(self.view)
        self.assertIsNotNone(self.view.threat_table)
        self.assertIsNotNone(self.view.severity_filter)
        
    def test_threat_display(self):
        """Test threat display functionality"""
        test_threat = {
            "ip": "192.168.1.100",
            "type": "ARP Spoofing",
            "severity": "High",
            "timestamp": "2024-03-29 10:00:00",
            "details": "Suspicious ARP activity detected"
        }
        
        self.view.add_threat(test_threat)
        
        # Verify threat details are displayed correctly
        self.assertEqual(self.view.threat_table.item(0, 0).text(), "192.168.1.100")
        self.assertEqual(self.view.threat_table.item(0, 1).text(), "ARP Spoofing")
        self.assertEqual(self.view.threat_table.item(0, 2).text(), "High")
        
    def test_severity_filtering(self):
        """Test threat filtering by severity"""
        test_threats = [
            {"ip": "192.168.1.100", "type": "ARP Spoofing", "severity": "High"},
            {"ip": "192.168.1.101", "type": "Port Scan", "severity": "Medium"},
            {"ip": "192.168.1.102", "type": "DNS Spoofing", "severity": "Low"}
        ]
        
        for threat in test_threats:
            self.view.add_threat(threat)
            
        # Test filtering by High severity
        self.view.severity_filter.setCurrentText("High")
        QTest.keyPress(self.view.severity_filter, Qt.Key_Return)
        
        # Verify filtered results
        visible_rows = self.view.threat_table.rowCount()
        self.assertEqual(visible_rows, 1)  # Should show only High severity threats

class TestAttackView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        self.view = AttackView()
        
    def tearDown(self):
        self.view.close()
        self.view.deleteLater()
        
    def test_view_initialization(self):
        """Test if attack view initializes correctly"""
        self.assertIsNotNone(self.view)
        self.assertIsNotNone(self.view.attack_table)
        self.assertIsNotNone(self.view.attack_type_filter)
        
    def test_attack_display(self):
        """Test attack display functionality"""
        test_attack = {
            "source_ip": "192.168.1.100",
            "target_ip": "192.168.1.1",
            "attack_type": "Man-in-the-Middle",
            "status": "Detected",
            "timestamp": "2024-03-29 10:00:00"
        }
        
        self.view.add_attack(test_attack)
        
        # Verify attack details are displayed correctly
        self.assertEqual(self.view.attack_table.item(0, 0).text(), "192.168.1.100")
        self.assertEqual(self.view.attack_table.item(0, 1).text(), "192.168.1.1")
        self.assertEqual(self.view.attack_table.item(0, 2).text(), "Man-in-the-Middle")
        
    def test_attack_type_filtering(self):
        """Test attack filtering by type"""
        test_attacks = [
            {"source_ip": "192.168.1.100", "target_ip": "192.168.1.1", "attack_type": "Man-in-the-Middle"},
            {"source_ip": "192.168.1.101", "target_ip": "192.168.1.2", "attack_type": "Port Scan"},
            {"source_ip": "192.168.1.102", "target_ip": "192.168.1.3", "attack_type": "DDoS"}
        ]
        
        for attack in test_attacks:
            self.view.add_attack(attack)
            
        # Test filtering by Man-in-the-Middle attacks
        self.view.attack_type_filter.setCurrentText("Man-in-the-Middle")
        QTest.keyPress(self.view.attack_type_filter, Qt.Key_Return)
        
        # Verify filtered results
        visible_rows = self.view.attack_table.rowCount()
        self.assertEqual(visible_rows, 1)  # Should show only Man-in-the-Middle attacks

if __name__ == '__main__':
    unittest.main() 