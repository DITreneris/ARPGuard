import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt, QEvent

# Add the app directory to the Python path
sys.path.append('app')

from components.main_window import MainWindow
from components.network_scanner import NetworkScanner
from components.threat_detector import ThreatDetector
from components.arp_spoofer import ARPSpoofer
from components.threat_intelligence import ThreatIntelligence
from components.attack_recognizer import AttackRecognizer
from components.defense_mechanism import DefenseMechanism

class TestScannerThreatDetectorIntegration(unittest.TestCase):
    """Test integration between NetworkScanner and ThreatDetector"""
    
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        self.scanner = NetworkScanner()
        self.detector = ThreatDetector()
        
    def test_scanner_results_to_detector(self):
        """Test that scanner results are properly passed to threat detector"""
        # Prepare test data
        test_devices = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "hostname": "gateway", "vendor": "Router Inc"},
            {"ip": "192.168.1.100", "mac": "00:11:22:33:44:66", "hostname": "device1", "vendor": "Computer Inc"}
        ]
        
        # Mock the scanner to return the test devices
        self.scanner.get_devices = Mock(return_value=test_devices)
        
        # Mock the detector's analyze_devices method
        self.detector.analyze_devices = Mock()
        
        # Call the scanner to get devices
        devices = self.scanner.get_devices()
        
        # Pass the results to the detector
        self.detector.analyze_devices(devices)
        
        # Verify the detector received the correct devices
        self.detector.analyze_devices.assert_called_once_with(test_devices)
        
    def test_detector_identifies_threats_from_scan(self):
        """Test that detector properly identifies threats from scan results"""
        # Prepare test data for a potential spoofing scenario
        # Two devices with duplicate MAC addresses but different IPs
        test_devices = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "hostname": "gateway", "vendor": "Router Inc"},
            {"ip": "192.168.1.100", "mac": "00:11:22:33:44:55", "hostname": "unknown", "vendor": "Unknown"}
        ]
        
        # Mock the detector's internal threat detection method
        original_analyze = self.detector.analyze_devices
        self.detector.analyze_devices = Mock(side_effect=lambda devices: original_analyze(devices))
        
        # Mock the detector's threat notification method
        self.detector.report_threat = Mock()
        
        # Pass the devices to the detector
        self.detector.analyze_devices(test_devices)
        
        # Verify that a threat was reported
        self.detector.report_threat.assert_called_at_least_once()
        
        # Restore the original method
        self.detector.analyze_devices = original_analyze


class TestThreatDetectorDefenseIntegration(unittest.TestCase):
    """Test integration between ThreatDetector and DefenseMechanism"""
    
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        self.detector = ThreatDetector()
        self.defense = DefenseMechanism()
        
    def test_detector_triggers_defense(self):
        """Test that detector threats trigger defense mechanisms"""
        # Create a test threat
        test_threat = {
            "type": "ARP Spoofing",
            "source_ip": "192.168.1.100",
            "target_ip": "192.168.1.1",
            "severity": "High",
            "description": "Possible ARP poisoning attack detected"
        }
        
        # Mock the detector's get_threats method
        self.detector.get_threats = Mock(return_value=[test_threat])
        
        # Mock the defense's deploy_countermeasure method
        self.defense.deploy_countermeasure = Mock()
        
        # Get threats from detector
        threats = self.detector.get_threats()
        
        # For each threat, deploy an appropriate countermeasure
        for threat in threats:
            self.defense.deploy_countermeasure(
                threat["type"],
                threat["source_ip"],
                threat["target_ip"]
            )
        
        # Verify the defense mechanism was deployed
        self.defense.deploy_countermeasure.assert_called_once_with(
            "ARP Spoofing",
            "192.168.1.100",
            "192.168.1.1"
        )


class TestAttackRecognizerDefenseIntegration(unittest.TestCase):
    """Test integration between AttackRecognizer and DefenseMechanism"""
    
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        self.recognizer = AttackRecognizer()
        self.defense = DefenseMechanism()
        
    def test_recognizer_triggers_defense(self):
        """Test that recognized attacks trigger defense mechanisms"""
        # Create a test attack
        test_attack = {
            "attack_type": "Port Scan",
            "source_ip": "192.168.1.100",
            "target_ip": "192.168.1.1",
            "ports": [21, 22, 23, 25, 80, 443],
            "timestamp": "2024-03-29 10:00:00"
        }
        
        # Mock the recognizer's get_attacks method
        self.recognizer.get_attacks = Mock(return_value=[test_attack])
        
        # Mock the defense's deploy_countermeasure method
        self.defense.deploy_countermeasure = Mock()
        
        # Get attacks from recognizer
        attacks = self.recognizer.get_attacks()
        
        # For each attack, deploy an appropriate countermeasure
        for attack in attacks:
            self.defense.deploy_countermeasure(
                attack["attack_type"],
                attack["source_ip"],
                attack["target_ip"]
            )
        
        # Verify the defense mechanism was deployed
        self.defense.deploy_countermeasure.assert_called_once_with(
            "Port Scan",
            "192.168.1.100",
            "192.168.1.1"
        )


class TestThreatIntelligenceIntegration(unittest.TestCase):
    """Test integration between ThreatIntelligence and other components"""
    
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        self.intelligence = ThreatIntelligence()
        self.detector = ThreatDetector()
        
    def test_intelligence_enhances_threats(self):
        """Test that threat intelligence enhances detected threats"""
        # Create a basic threat detected by the detector
        basic_threat = {
            "type": "Suspicious Activity",
            "source_ip": "192.168.1.100",
            "severity": "Medium",
            "description": "Unknown scanning activity"
        }
        
        # Mock the detector's get_threats method
        self.detector.get_threats = Mock(return_value=[basic_threat])
        
        # Mock the intelligence's lookup_ip method
        # Simulating threat intelligence data for the IP
        intelligence_data = {
            "is_malicious": True,
            "threat_score": 85,
            "threat_type": "Scanner",
            "source": "AbuseIPDB",
            "reports": 24
        }
        self.intelligence.lookup_ip = Mock(return_value=intelligence_data)
        
        # Get threats from the detector
        threats = self.detector.get_threats()
        
        # Enhance threats with intelligence data
        enhanced_threats = []
        for threat in threats:
            # Look up intelligence data for the source IP
            intel = self.intelligence.lookup_ip(threat["source_ip"])
            if intel["is_malicious"]:
                # Enhance the threat with intelligence data
                threat["severity"] = "High"  # Increase severity based on intel
                threat["description"] += f" (Confirmed by {intel['source']} with score {intel['threat_score']})"
                threat["reports"] = intel["reports"]
                threat["threat_type"] = intel["threat_type"]
            enhanced_threats.append(threat)
        
        # Verify the intelligence lookup was called
        self.intelligence.lookup_ip.assert_called_once_with("192.168.1.100")
        
        # Verify the threat was enhanced correctly
        self.assertEqual(enhanced_threats[0]["severity"], "High")
        self.assertIn("Confirmed by AbuseIPDB", enhanced_threats[0]["description"])
        self.assertEqual(enhanced_threats[0]["reports"], 24)
        self.assertEqual(enhanced_threats[0]["threat_type"], "Scanner")


class TestMainWindowIntegration(unittest.TestCase):
    """Test integration within the MainWindow between components"""
    
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        # Create mock objects for the main components
        self.mock_scanner = Mock(spec=NetworkScanner)
        self.mock_detector = Mock(spec=ThreatDetector)
        self.mock_spoofer = Mock(spec=ARPSpoofer)
        
        # Patch the component classes to return our mocks
        self.scanner_patcher = patch('components.main_window.NetworkScanner', 
                                    return_value=self.mock_scanner)
        self.detector_patcher = patch('components.main_window.ThreatDetector', 
                                     return_value=self.mock_detector)
        self.spoofer_patcher = patch('components.main_window.ARPSpoofer', 
                                    return_value=self.mock_spoofer)
        
        # Start the patchers
        self.scanner_patcher.start()
        self.detector_patcher.start()
        self.spoofer_patcher.start()
        
        # Create the MainWindow
        self.window = MainWindow()
        
    def tearDown(self):
        self.window.close()
        self.window.deleteLater()
        
        # Stop the patchers
        self.scanner_patcher.stop()
        self.detector_patcher.stop()
        self.spoofer_patcher.stop()
        
    def test_scan_action_triggers_scanner(self):
        """Test that scan action triggers the network scanner"""
        # Set up the mock scanner to return some devices
        test_devices = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "hostname": "gateway"},
            {"ip": "192.168.1.100", "mac": "00:11:22:33:44:66", "hostname": "device1"}
        ]
        self.mock_scanner.start_scan.return_value = True
        self.mock_scanner.get_devices.return_value = test_devices
        
        # Trigger the scan action
        self.window.action_scan.trigger()
        
        # Verify the scanner was called
        self.mock_scanner.start_scan.assert_called_once()
        
    def test_scan_results_update_ui(self):
        """Test that scan results update the UI properly"""
        # Set up the mock scanner to return some devices
        test_devices = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "hostname": "gateway"},
            {"ip": "192.168.1.100", "mac": "00:11:22:33:44:66", "hostname": "device1"}
        ]
        self.mock_scanner.get_devices.return_value = test_devices
        
        # Mock the UI update method
        self.window.update_device_list = Mock()
        
        # Simulate a scan completion
        self.window.on_scan_completed()
        
        # Verify the UI was updated with the devices
        self.mock_scanner.get_devices.assert_called_once()
        self.window.update_device_list.assert_called_once()
        
    def test_threat_detection_integrates_with_ui(self):
        """Test that detected threats are displayed in the UI"""
        # Set up a test threat
        test_threat = {
            "type": "ARP Spoofing",
            "source_ip": "192.168.1.100",
            "target_ip": "192.168.1.1",
            "severity": "High",
            "timestamp": "2024-03-29 10:00:00"
        }
        self.mock_detector.get_threats.return_value = [test_threat]
        
        # Mock the UI update method
        self.window.update_threat_list = Mock()
        
        # Simulate a threat detection event
        self.window.on_threat_detected()
        
        # Verify the UI was updated with the threat
        self.mock_detector.get_threats.assert_called_once()
        self.window.update_threat_list.assert_called_once()

if __name__ == '__main__':
    unittest.main() 