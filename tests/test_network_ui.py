import unittest
from unittest.mock import Mock, patch
import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt

# Add the app directory to the Python path
sys.path.append('app')

from components.network_topology import NetworkTopology
from components.vulnerability_view import VulnerabilityView
from components.vulnerability_scanner import VulnerabilityScanner

class TestNetworkTopology(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        self.topology = NetworkTopology()
        
    def tearDown(self):
        self.topology.close()
        self.topology.deleteLater()
        
    def test_view_initialization(self):
        """Test if network topology view initializes correctly"""
        self.assertIsNotNone(self.topology)
        self.assertIsNotNone(self.topology.scene)
        self.assertIsNotNone(self.topology.view)
        
    def test_device_addition(self):
        """Test adding devices to the topology"""
        test_device = {
            "ip": "192.168.1.100",
            "mac": "00:11:22:33:44:55",
            "hostname": "test-device",
            "type": "host"
        }
        
        self.topology.add_device(test_device)
        
        # Verify device was added to the scene
        items = self.topology.scene.items()
        self.assertEqual(len(items), 1)  # Should have one device node
        
    def test_connection_display(self):
        """Test displaying connections between devices"""
        devices = [
            {"ip": "192.168.1.100", "mac": "00:11:22:33:44:55", "hostname": "device1"},
            {"ip": "192.168.1.101", "mac": "00:11:22:33:44:66", "hostname": "device2"}
        ]
        
        for device in devices:
            self.topology.add_device(device)
            
        # Add connection between devices
        self.topology.add_connection("192.168.1.100", "192.168.1.101")
        
        # Verify connection was added
        items = self.topology.scene.items()
        self.assertEqual(len(items), 3)  # 2 devices + 1 connection

class TestVulnerabilityView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        self.view = VulnerabilityView()
        
    def tearDown(self):
        self.view.close()
        self.view.deleteLater()
        
    def test_view_initialization(self):
        """Test if vulnerability view initializes correctly"""
        self.assertIsNotNone(self.view)
        self.assertIsNotNone(self.view.vuln_table)
        self.assertIsNotNone(self.view.risk_filter)
        
    def test_vulnerability_display(self):
        """Test vulnerability display functionality"""
        test_vuln = {
            "ip": "192.168.1.100",
            "port": 80,
            "service": "HTTP",
            "risk_level": "High",
            "description": "SQL Injection vulnerability detected",
            "timestamp": "2024-03-29 10:00:00"
        }
        
        self.view.add_vulnerability(test_vuln)
        
        # Verify vulnerability details are displayed correctly
        self.assertEqual(self.view.vuln_table.item(0, 0).text(), "192.168.1.100")
        self.assertEqual(self.view.vuln_table.item(0, 1).text(), "80")
        self.assertEqual(self.view.vuln_table.item(0, 2).text(), "HTTP")
        self.assertEqual(self.view.vuln_table.item(0, 3).text(), "High")
        
    def test_risk_level_filtering(self):
        """Test vulnerability filtering by risk level"""
        test_vulns = [
            {"ip": "192.168.1.100", "port": 80, "service": "HTTP", "risk_level": "High"},
            {"ip": "192.168.1.101", "port": 443, "service": "HTTPS", "risk_level": "Medium"},
            {"ip": "192.168.1.102", "port": 22, "service": "SSH", "risk_level": "Low"}
        ]
        
        for vuln in test_vulns:
            self.view.add_vulnerability(vuln)
            
        # Test filtering by High risk level
        self.view.risk_filter.setCurrentText("High")
        QTest.keyPress(self.view.risk_filter, Qt.Key_Return)
        
        # Verify filtered results
        visible_rows = self.view.vuln_table.rowCount()
        self.assertEqual(visible_rows, 1)  # Should show only High risk vulnerabilities

if __name__ == '__main__':
    unittest.main() 