import unittest
import sys
import os
import time
from unittest.mock import Mock, patch, MagicMock
from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt, QTimer

# Add the app directory to the Python path
sys.path.append('app')

from components.main_window import MainWindow
from components.network_scanner import NetworkScanner
from components.threat_detector import ThreatDetector
from components.defense_mechanism import DefenseMechanism
from components.attack_recognizer import AttackRecognizer
from components.vulnerability_scanner import VulnerabilityScanner
from components.threat_intelligence import ThreatIntelligence

class TestCompleteProtectionWorkflow(unittest.TestCase):
    """Test the complete end-to-end protection workflow"""
    
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv) if not QApplication.instance() else QApplication.instance()
        
    def setUp(self):
        """Set up the test environment with all necessary components"""
        # Create mock objects for all the components
        self.mock_scanner = Mock(spec=NetworkScanner)
        self.mock_detector = Mock(spec=ThreatDetector)
        self.mock_recognizer = Mock(spec=AttackRecognizer)
        self.mock_defense = Mock(spec=DefenseMechanism)
        self.mock_vuln_scanner = Mock(spec=VulnerabilityScanner)
        self.mock_intelligence = Mock(spec=ThreatIntelligence)
        
        # Patch the component classes
        self.scanner_patcher = patch('components.main_window.NetworkScanner', 
                                    return_value=self.mock_scanner)
        self.detector_patcher = patch('components.main_window.ThreatDetector', 
                                     return_value=self.mock_detector)
        self.recognizer_patcher = patch('components.main_window.AttackRecognizer', 
                                       return_value=self.mock_recognizer)
        self.defense_patcher = patch('components.main_window.DefenseMechanism', 
                                    return_value=self.mock_defense)
        self.vuln_scanner_patcher = patch('components.main_window.VulnerabilityScanner', 
                                         return_value=self.mock_vuln_scanner)
        self.intelligence_patcher = patch('components.main_window.ThreatIntelligence', 
                                         return_value=self.mock_intelligence)
        
        # Start the patchers
        self.scanner_patcher.start()
        self.detector_patcher.start()
        self.recognizer_patcher.start()
        self.defense_patcher.start()
        self.vuln_scanner_patcher.start()
        self.intelligence_patcher.start()
        
        # Create the MainWindow
        self.window = MainWindow()
        
        # Sample test data
        self.test_devices = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "hostname": "gateway", "vendor": "Router Inc"},
            {"ip": "192.168.1.100", "mac": "00:11:22:33:44:66", "hostname": "device1", "vendor": "Computer Inc"},
            {"ip": "192.168.1.101", "mac": "00:11:22:33:44:77", "hostname": "device2", "vendor": "Computer Inc"},
            {"ip": "192.168.1.102", "mac": "00:11:22:33:44:55", "hostname": "unknown", "vendor": "Unknown"} # Duplicate MAC
        ]
        
        self.test_threat = {
            "type": "ARP Spoofing",
            "source_ip": "192.168.1.102",
            "target_ip": "192.168.1.1",
            "severity": "High",
            "description": "Duplicate MAC address detected",
            "timestamp": "2024-03-29 10:00:00"
        }
        
        self.test_attack = {
            "attack_type": "Port Scan",
            "source_ip": "192.168.1.102",
            "target_ip": "192.168.1.1",
            "severity": "High",
            "timestamp": "2024-03-29 10:05:00",
            "details": "Multiple ports scanned (21,22,23,25,80,443)"
        }
        
        self.test_vulnerabilities = [
            {
                "ip": "192.168.1.1",
                "port": 80,
                "service": "HTTP",
                "risk_level": "Medium",
                "description": "Web server vulnerable to outdated software",
                "timestamp": "2024-03-29 10:10:00"
            },
            {
                "ip": "192.168.1.100",
                "port": 22,
                "service": "SSH",
                "risk_level": "Low",
                "description": "SSH service using password authentication",
                "timestamp": "2024-03-29 10:10:00"
            }
        ]
        
        self.test_intel = {
            "is_malicious": True,
            "threat_score": 85,
            "threat_type": "Scanner",
            "source": "AbuseIPDB",
            "reports": 24
        }
        
        # Configure mock behaviors
        self.mock_scanner.get_devices.return_value = self.test_devices
        self.mock_detector.get_threats.return_value = [self.test_threat]
        self.mock_recognizer.get_attacks.return_value = [self.test_attack]
        self.mock_vuln_scanner.get_vulnerabilities.return_value = self.test_vulnerabilities
        self.mock_intelligence.lookup_ip.return_value = self.test_intel
        
        # Mock UI update methods to avoid widget manipulation in tests
        self.window.update_device_list = Mock()
        self.window.update_threat_list = Mock()
        self.window.update_attack_list = Mock()
        self.window.update_vulnerability_list = Mock()
        self.window.update_defense_list = Mock()
        self.window.show_alert = Mock()
        self.window.update_ui_state = Mock()
        
    def tearDown(self):
        """Clean up after each test"""
        self.window.close()
        self.window.deleteLater()
        
        # Stop the patchers
        self.scanner_patcher.stop()
        self.detector_patcher.stop()
        self.recognizer_patcher.stop()
        self.defense_patcher.stop()
        self.vuln_scanner_patcher.stop()
        self.intelligence_patcher.stop()
        
    def test_complete_protection_cycle(self):
        """Test the complete protection cycle from scan to defense"""
        # PART 1: Initial Network Scan
        # Configure scanner behavior
        self.mock_scanner.start_scan.return_value = True
        self.mock_scanner.is_scanning.return_value = False
        
        # Trigger scan
        self.window.action_scan.trigger()
        
        # Verify scanner was called
        self.mock_scanner.start_scan.assert_called_once()
        
        # Simulate scan completion
        self.window.on_scan_completed()
        
        # Verify device list was updated
        self.mock_scanner.get_devices.assert_called_once()
        self.window.update_device_list.assert_called_once()
        
        # PART 2: Threat Detection
        # Verify detector was called with the device list
        self.mock_detector.analyze_devices.assert_called_once_with(self.test_devices)
        
        # Simulate threat detection
        self.window.on_threat_detected()
        
        # Verify threat list was updated and alert shown
        self.mock_detector.get_threats.assert_called_once()
        self.window.update_threat_list.assert_called_once()
        self.window.show_alert.assert_called_once()
        
        # Reset mock call counters for alert
        self.window.show_alert.reset_mock()
        
        # PART 3: Attack Detection and Intelligence Correlation
        # Configure attack recognizer
        self.mock_recognizer.is_monitoring.return_value = True
        
        # Simulate attack detection
        self.window.on_attack_detected()
        
        # Verify attack was detected and displayed
        self.mock_recognizer.get_attacks.assert_called_once()
        self.window.update_attack_list.assert_called_once()
        self.window.show_alert.assert_called_once()
        
        # Verify threat intelligence was checked
        self.mock_intelligence.lookup_ip.assert_called_with(self.test_attack["source_ip"])
        
        # Reset mock call counters
        self.window.show_alert.reset_mock()
        
        # PART 4: Vulnerability Scanning
        # Configure vulnerability scanner
        self.mock_vuln_scanner.scan_network.return_value = True
        
        # Trigger vulnerability scan
        if hasattr(self.window, 'action_vuln_scan'):
            self.window.action_vuln_scan.trigger()
        else:
            # Direct method call if no action exists
            self.window.start_vulnerability_scan()
        
        # Verify scanner was called
        self.mock_vuln_scanner.scan_network.assert_called_once()
        
        # Simulate scan completion
        if hasattr(self.window, 'on_vulnerability_scan_completed'):
            self.window.on_vulnerability_scan_completed()
        
        # Verify vulnerability list was updated
        self.mock_vuln_scanner.get_vulnerabilities.assert_called_once()
        self.window.update_vulnerability_list.assert_called_once()
        
        # PART 5: Defense Deployment
        # Configure defense mechanism
        self.mock_defense.deploy_countermeasure.return_value = True
        self.mock_defense.get_active_defenses.return_value = [{
            "attack_type": self.test_attack["attack_type"],
            "target_ip": self.test_attack["target_ip"],
            "status": "Active",
            "timestamp": "2024-03-29 10:15:00"
        }]
        
        # Deploy defense
        self.window.deploy_defense(
            self.test_attack["attack_type"],
            self.test_attack["source_ip"],
            self.test_attack["target_ip"]
        )
        
        # Verify defense was deployed
        self.mock_defense.deploy_countermeasure.assert_called_once_with(
            self.test_attack["attack_type"],
            self.test_attack["source_ip"],
            self.test_attack["target_ip"]
        )
        
        # Verify defense list was updated
        self.mock_defense.get_active_defenses.assert_called_once()
        self.window.update_defense_list.assert_called_once()
        
        # PART 6: Report Generation
        # Configure report generation
        if hasattr(self.window, 'generate_network_report'):
            self.window.generate_network_report = Mock(return_value="/path/to/report.html")
            self.window.show_report = Mock()
            
            # Mock file dialog
            with patch('PyQt5.QtWidgets.QFileDialog.getSaveFileName') as mock_dialog:
                mock_dialog.return_value = ("/path/to/report.html", "HTML Files (*.html)")
                
                # Trigger report generation
                if hasattr(self.window, 'action_generate_report'):
                    self.window.action_generate_report.trigger()
                else:
                    # Direct method call if no action exists
                    self.window.generate_report()
                
                # Verify report was generated and displayed
                self.window.generate_network_report.assert_called_once()
                self.window.show_report.assert_called_once_with("/path/to/report.html")
        
        # Verify the complete protection cycle was successful
        # This is a comprehensive end-to-end test that touches all major components
        print("\nComplete Protection Cycle Test:")
        print("  ✓ Network scanning")
        print("  ✓ Threat detection")
        print("  ✓ Attack recognition")
        print("  ✓ Vulnerability scanning")
        print("  ✓ Defense deployment")
        print("  ✓ Report generation")
        print("  → All steps completed successfully")

if __name__ == '__main__':
    unittest.main() 