import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt, QTimer

# Add the app directory to the Python path
sys.path.append('app')

from components.main_window import MainWindow
from components.network_scanner import NetworkScanner
from components.threat_detector import ThreatDetector
from components.defense_mechanism import DefenseMechanism
from components.attack_recognizer import AttackRecognizer

class TestCompleteScanWorkflow(unittest.TestCase):
    """Test the complete scan, detect, alert workflow"""
    
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        # Create mock objects for the main components
        self.mock_scanner = Mock(spec=NetworkScanner)
        self.mock_detector = Mock(spec=ThreatDetector)
        
        # Patch the component classes to return our mocks
        self.scanner_patcher = patch('components.main_window.NetworkScanner', 
                                    return_value=self.mock_scanner)
        self.detector_patcher = patch('components.main_window.ThreatDetector', 
                                     return_value=self.mock_detector)
        
        # Start the patchers
        self.scanner_patcher.start()
        self.detector_patcher.start()
        
        # Create the MainWindow
        self.window = MainWindow()
        
    def tearDown(self):
        self.window.close()
        self.window.deleteLater()
        
        # Stop the patchers
        self.scanner_patcher.stop()
        self.detector_patcher.stop()
        
    def test_complete_scan_workflow(self):
        """Test the complete workflow from scan initiation to results display"""
        # Set up test devices data
        test_devices = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "hostname": "gateway", "vendor": "Router Inc"},
            {"ip": "192.168.1.100", "mac": "00:11:22:33:44:66", "hostname": "device1", "vendor": "Computer Inc"}
        ]
        
        # Set up scanner mock behavior
        self.mock_scanner.start_scan.return_value = True
        self.mock_scanner.get_devices.return_value = test_devices
        self.mock_scanner.is_scanning.return_value = False
        
        # Mock UI methods that need to be verified
        self.window.update_device_list = Mock()
        self.window.set_ui_busy = Mock()
        self.window.set_ui_ready = Mock()
        
        # 1. Trigger the scan action
        self.window.action_scan.trigger()
        
        # 2. Verify UI shows busy state
        self.window.set_ui_busy.assert_called_once()
        
        # 3. Simulate scan completion
        self.window.on_scan_completed()
        
        # 4. Verify scanner was called and results processed
        self.mock_scanner.start_scan.assert_called_once()
        self.mock_scanner.get_devices.assert_called_once()
        
        # 5. Verify UI updated with results
        self.window.update_device_list.assert_called_once()
        self.window.set_ui_ready.assert_called_once()
        
    def test_scan_with_threat_detection_workflow(self):
        """Test workflow when a scan discovers a threat"""
        # Set up test devices data with a threat
        test_devices = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "hostname": "gateway", "vendor": "Router Inc"},
            {"ip": "192.168.1.100", "mac": "00:11:22:33:44:55", "hostname": "unknown", "vendor": "Unknown"}
        ]
        
        # Set up a threat that should be detected
        test_threat = {
            "type": "ARP Spoofing",
            "source_ip": "192.168.1.100",
            "target_ip": "192.168.1.1",
            "severity": "High",
            "description": "Duplicate MAC address detected",
            "timestamp": "2024-03-29 10:00:00"
        }
        
        # Set up scanner and detector behavior
        self.mock_scanner.start_scan.return_value = True
        self.mock_scanner.get_devices.return_value = test_devices
        self.mock_scanner.is_scanning.return_value = False
        
        self.mock_detector.analyze_devices = Mock()
        self.mock_detector.get_threats.return_value = [test_threat]
        
        # Mock UI methods for verification
        self.window.update_device_list = Mock()
        self.window.update_threat_list = Mock()
        self.window.show_alert = Mock()
        
        # 1. Trigger the scan
        self.window.action_scan.trigger()
        
        # 2. Simulate scan completion
        self.window.on_scan_completed()
        
        # 3. Verify devices passed to detector for analysis
        self.mock_detector.analyze_devices.assert_called_once_with(test_devices)
        
        # 4. Simulate threat detection event
        self.window.on_threat_detected()
        
        # 5. Verify UI updated with threat information
        self.mock_detector.get_threats.assert_called_once()
        self.window.update_threat_list.assert_called_once()
        self.window.show_alert.assert_called_once()


class TestAttackResponseWorkflow(unittest.TestCase):
    """Test the attack detection, alert, and defense workflow"""
    
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        # Create mock objects for the main components
        self.mock_recognizer = Mock(spec=AttackRecognizer)
        self.mock_defense = Mock(spec=DefenseMechanism)
        
        # Patch the component classes to return our mocks
        self.recognizer_patcher = patch('components.main_window.AttackRecognizer', 
                                       return_value=self.mock_recognizer)
        self.defense_patcher = patch('components.main_window.DefenseMechanism', 
                                    return_value=self.mock_defense)
        
        # Start the patchers
        self.recognizer_patcher.start()
        self.defense_patcher.start()
        
        # Create the MainWindow
        self.window = MainWindow()
        
    def tearDown(self):
        self.window.close()
        self.window.deleteLater()
        
        # Stop the patchers
        self.recognizer_patcher.stop()
        self.defense_patcher.stop()
        
    def test_attack_detection_and_response_workflow(self):
        """Test workflow from attack detection to defense deployment"""
        # Set up a test attack
        test_attack = {
            "attack_type": "Port Scan",
            "source_ip": "192.168.1.100",
            "target_ip": "192.168.1.1",
            "severity": "High",
            "timestamp": "2024-03-29 10:00:00",
            "details": "Multiple ports scanned (21,22,23,25,80,443)"
        }
        
        # Set up recognizer behavior
        self.mock_recognizer.get_attacks.return_value = [test_attack]
        self.mock_recognizer.is_monitoring.return_value = True
        
        # Set up defense behavior
        self.mock_defense.deploy_countermeasure.return_value = True
        self.mock_defense.get_active_defenses.return_value = [{
            "attack_type": "Port Scan",
            "target_ip": "192.168.1.1",
            "status": "Active",
            "timestamp": "2024-03-29 10:00:00"
        }]
        
        # Mock UI methods for verification
        self.window.update_attack_list = Mock()
        self.window.update_defense_list = Mock()
        self.window.show_alert = Mock()
        
        # 1. Simulate attack detection event
        self.window.on_attack_detected()
        
        # 2. Verify UI updated with attack information
        self.mock_recognizer.get_attacks.assert_called_once()
        self.window.update_attack_list.assert_called_once()
        self.window.show_alert.assert_called_once()
        
        # 3. Simulate defense deployment
        # This would normally happen after user confirmation or automatically
        self.window.deploy_defense(test_attack["attack_type"], 
                                   test_attack["source_ip"], 
                                   test_attack["target_ip"])
        
        # 4. Verify defense mechanism was deployed
        self.mock_defense.deploy_countermeasure.assert_called_once_with(
            test_attack["attack_type"],
            test_attack["source_ip"],
            test_attack["target_ip"]
        )
        
        # 5. Verify UI updated with defense status
        self.mock_defense.get_active_defenses.assert_called_once()
        self.window.update_defense_list.assert_called_once()


class TestReportGenerationWorkflow(unittest.TestCase):
    """Test the report generation workflow"""
    
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        # Patch file operations to avoid actual file creation
        self.file_patcher = patch('builtins.open', MagicMock())
        self.os_patcher = patch('os.path.exists', return_value=True)
        self.dir_patcher = patch('os.makedirs')
        
        # Start the patchers
        self.file_mock = self.file_patcher.start()
        self.os_mock = self.os_patcher.start()
        self.dir_mock = self.dir_patcher.start()
        
        # Create the MainWindow
        self.window = MainWindow()
        
    def tearDown(self):
        self.window.close()
        self.window.deleteLater()
        
        # Stop the patchers
        self.file_patcher.stop()
        self.os_patcher.stop()
        self.dir_patcher.stop()
        
    def test_report_generation_workflow(self):
        """Test the complete workflow for generating and viewing a report"""
        # Mock the QFileDialog to avoid actual dialog
        with patch('PyQt5.QtWidgets.QFileDialog.getSaveFileName') as mock_dialog:
            mock_dialog.return_value = ("/path/to/report.html", "HTML Files (*.html)")
            
            # Mock the report generation methods
            self.window.generate_network_report = Mock(return_value="/path/to/report.html")
            self.window.show_report = Mock()
            
            # 1. Trigger report generation
            # Assuming there's a report_action in the MainWindow
            self.window.action_generate_report.trigger()
            
            # 2. Verify report generation was called
            self.window.generate_network_report.assert_called_once()
            
            # 3. Verify the report was displayed
            self.window.show_report.assert_called_once_with("/path/to/report.html")


class TestSystemInteractions(unittest.TestCase):
    """Test that all components interact correctly in the system"""
    
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        # Create the main window with all real components (no mocks)
        self.window = MainWindow()
        
    def tearDown(self):
        self.window.close()
        self.window.deleteLater()
        
    def test_system_initialization(self):
        """Test that the system initializes correctly with all components"""
        # Verify all required components are initialized
        self.assertIsNotNone(self.window.scanner)
        self.assertIsNotNone(self.window.detector)
        self.assertIsNotNone(self.window.spoofer)
        
        # Verify UI components are initialized
        self.assertIsNotNone(self.window.device_table)
        self.assertIsNotNone(self.window.threat_table)
        self.assertIsNotNone(self.window.status_bar)
        
    def test_system_shutdown(self):
        """Test that the system shuts down cleanly"""
        # Mock the event to simulate application exit
        close_event = MagicMock()
        
        # Call the closeEvent handler
        self.window.closeEvent(close_event)
        
        # Verify the event was accepted (not ignored)
        close_event.accept.assert_called_once()
        
        # The test passes if no exceptions are raised

if __name__ == '__main__':
    unittest.main() 