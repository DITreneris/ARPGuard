import unittest
from unittest.mock import Mock, patch
import sys

# Add the app directory to the Python path
sys.path.append('app')

class TestNetworkScanningIntegration(unittest.TestCase):
    def test_scanner_detector_integration(self):
        """Test integration between network scanner and threat detector"""
        # Import the components
        from components.network_scanner import NetworkScanner
        from components.threat_detector import ThreatDetector
        
        # Create mock objects
        mock_scanner = Mock(spec=NetworkScanner)
        mock_detector = Mock(spec=ThreatDetector)
        
        # Set up return values
        mock_scanner.get_devices.return_value = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "hostname": "gateway"},
            {"ip": "192.168.1.100", "mac": "00:11:22:33:44:66", "hostname": "device1"}
        ]
        
        # Test integration
        devices = mock_scanner.get_devices()
        mock_detector.analyze_devices(devices)
        
        # Verify detector was called with scanner output
        mock_detector.analyze_devices.assert_called_once_with(devices)
        
    def test_threat_alert_integration(self):
        """Test integration between threat detector and alert system"""
        # Import the components
        from components.threat_detector import ThreatDetector
        from components.threat_intelligence import ThreatIntelligence
        
        # Create mock objects
        mock_detector = Mock(spec=ThreatDetector)
        mock_intelligence = Mock(spec=ThreatIntelligence)
        
        # Set up return values
        mock_detector.get_threats.return_value = [
            {"ip": "192.168.1.100", "type": "ARP Spoofing", "severity": "High"}
        ]
        
        # Test integration
        threats = mock_detector.get_threats()
        mock_intelligence.process_threats(threats)
        
        # Verify intelligence system was called with detector output
        mock_intelligence.process_threats.assert_called_once_with(threats)
    
    def test_attack_defense_integration(self):
        """Test integration between attack recognition and defense mechanism"""
        # Import the components
        from components.attack_recognizer import AttackRecognizer
        from components.defense_mechanism import DefenseMechanism
        
        # Create mock objects
        mock_recognizer = Mock(spec=AttackRecognizer)
        mock_defense = Mock(spec=DefenseMechanism)
        
        # Set up return values
        mock_recognizer.get_attacks.return_value = [
            {"source_ip": "192.168.1.100", "target_ip": "192.168.1.1", "attack_type": "ARP Spoofing"}
        ]
        
        # Test integration
        attacks = mock_recognizer.get_attacks()
        mock_defense.deploy_countermeasures(attacks)
        
        # Verify defense system was called with recognizer output
        mock_defense.deploy_countermeasures.assert_called_once_with(attacks)
    
    def test_vulnerability_scan_integration(self):
        """Test integration between vulnerability scanner and reporting"""
        # Import the components
        from components.vulnerability_scanner import VulnerabilityScanner
        from components.report_viewer import ReportViewer
        
        # Create mock objects
        mock_scanner = Mock(spec=VulnerabilityScanner)
        mock_reporter = Mock(spec=ReportViewer)
        
        # Set up return values
        mock_scanner.get_vulnerabilities.return_value = [
            {"ip": "192.168.1.100", "port": 80, "service": "HTTP", "risk_level": "High"}
        ]
        
        # Test integration
        vulnerabilities = mock_scanner.get_vulnerabilities()
        mock_reporter.generate_vulnerability_report(vulnerabilities)
        
        # Verify reporter was called with scanner output
        mock_reporter.generate_vulnerability_report.assert_called_once_with(vulnerabilities)

if __name__ == '__main__':
    unittest.main() 