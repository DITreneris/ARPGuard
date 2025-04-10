#!/usr/bin/env python3
"""
ARP Guard Integration Tests
Tests that validate the integration between different modules
"""

import unittest
import os
import sys
import time
import logging
import tempfile
import shutil
import json
from unittest.mock import patch, MagicMock

# Add the parent directory to sys.path to import modules
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from src.core.detection_module import DetectionModule
from src.core.remediation_module import RemediationModule
from src.core.cli_module import CLIModule

# Disable logging during tests
logging.disable(logging.CRITICAL)

class IntegrationTestCase(unittest.TestCase):
    """Base class for integration tests."""
    
    def setUp(self):
        """Set up test environment."""
        # Create temporary directory for test data
        self.test_dir = tempfile.mkdtemp()
        os.environ['ARP_GUARD_CONFIG_DIR'] = self.test_dir
        
        # Create config directory
        self.config_dir = os.path.join(self.test_dir, 'config')
        os.makedirs(self.config_dir, exist_ok=True)
        
    def tearDown(self):
        """Clean up test environment."""
        # Remove temporary directory
        shutil.rmtree(self.test_dir)
        os.environ.pop('ARP_GUARD_CONFIG_DIR', None)

class TestDetectionRemediationIntegration(IntegrationTestCase):
    """Integration tests for Detection and Remediation modules."""
    
    @patch('scapy.sniff')
    def test_detection_remediation_integration(self, mock_sniff):
        """Test that Detection module correctly integrates with Remediation."""
        # Mock packet capture
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = True
        mock_packet.src = "00:11:22:33:44:55"
        mock_packet.dst = "66:77:88:99:AA:BB"
        
        # Mock ARP layer
        mock_arp = MagicMock()
        mock_arp.hwsrc = "00:11:22:33:44:55"
        mock_arp.psrc = "192.168.1.100"
        mock_arp.hwdst = "66:77:88:99:AA:BB"
        mock_arp.pdst = "192.168.1.1"
        mock_arp.op = 2  # ARP reply
        
        mock_packet.getlayer.return_value = mock_arp
        mock_sniff.return_value = [mock_packet]
        
        # Create instances
        detection = DetectionModule()
        remediation = RemediationModule()
        
        # Connect modules
        detection.remediation = remediation
        
        # Mock the block_host method to avoid actual network changes
        with patch.object(remediation, 'block_host') as mock_block:
            mock_block.return_value = True
            
            # Initialize modules
            detection.initialize()
            remediation.initialize()
            
            # Simulate detection with high threat level
            detection._add_detection_result(
                mac="00:11:22:33:44:55",
                ip="192.168.1.100",
                threat_level="high",
                details={"reason": "Suspicious ARP reply"}
            )
            
            # Verify that remediation was called
            mock_block.assert_called_once()
            self.assertEqual(mock_block.call_args[0][0], "00:11:22:33:44:55")
            self.assertEqual(mock_block.call_args[0][1], "192.168.1.100")
            
class TestCLIDetectionIntegration(IntegrationTestCase):
    """Integration tests for CLI and Detection modules."""
    
    def test_cli_detection_integration(self):
        """Test that CLI module can control Detection module."""
        # Create instances
        detection = DetectionModule()
        cli = CLIModule()
        
        # Mock the start_detection and stop_detection methods
        with patch.object(detection, 'start_detection') as mock_start, \
             patch.object(detection, 'stop_detection') as mock_stop:
            
            mock_start.return_value = True
            mock_stop.return_value = True
            
            # Mock command arguments
            start_args = MagicMock()
            start_args.service = 'detection'
            
            status_args = MagicMock()
            status_args.service = 'detection'
            
            stop_args = MagicMock()
            stop_args.service = 'detection'
            
            # Register detection module with CLI
            cli.detection_module = detection
            
            # Test start command
            cli._handle_start(start_args)
            mock_start.assert_called_once()
            
            # Test status command
            with patch.object(detection, 'get_status') as mock_status:
                mock_status.return_value = {'running': True, 'uptime': '00:01:00'}
                cli._handle_status(status_args)
                mock_status.assert_called_once()
            
            # Test stop command
            cli._handle_stop(stop_args)
            mock_stop.assert_called_once()

class TestFullSystemIntegration(IntegrationTestCase):
    """Integration tests for the full system."""
    
    @patch('subprocess.run')
    @patch('scapy.sniff')
    def test_full_system_operation(self, mock_sniff, mock_subprocess):
        """Test the full system operation flow."""
        # Mock packet capture with suspicious packet
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = True
        mock_packet.src = "00:11:22:33:44:55"
        mock_packet.dst = "66:77:88:99:AA:BB"
        
        # Mock ARP layer with gateway spoofing
        mock_arp = MagicMock()
        mock_arp.hwsrc = "00:11:22:33:44:55"  # Attacker MAC
        mock_arp.psrc = "192.168.1.1"  # Gateway IP
        mock_arp.hwdst = "66:77:88:99:AA:BB"
        mock_arp.pdst = "192.168.1.100"
        mock_arp.op = 2  # ARP reply
        
        mock_packet.getlayer.return_value = mock_arp
        mock_sniff.return_value = [mock_packet]
        
        # Mock subprocess calls for firewall rules
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Create instances
        detection = DetectionModule()
        remediation = RemediationModule()
        cli = CLIModule()
        
        # Connect modules
        detection.remediation = remediation
        cli.detection_module = detection
        cli.remediation_module = remediation
        
        # Initialize modules
        detection.initialize()
        remediation.initialize()
        cli.initialize()
        
        # 1. Start detection via CLI
        start_args = MagicMock()
        start_args.service = 'detection'
        with patch.object(detection, 'start_detection') as mock_start:
            mock_start.return_value = True
            cli._handle_start(start_args)
            mock_start.assert_called_once()
        
        # 2. Simulate detection process finding suspicious packet
        # Instead of calling the actual analyze_packets which would try to use scapy
        # We'll directly call the methods that would be triggered in the real flow
        with patch.object(detection, '_check_suspicious_pattern') as mock_check:
            mock_check.return_value = True
            
            # Simulate packet analysis
            arp_info = {
                'source_mac': "00:11:22:33:44:55",
                'source_ip': "192.168.1.1",
                'dest_mac': "66:77:88:99:AA:BB",
                'dest_ip': "192.168.1.100",
                'op': 2
            }
            
            # Determine threat level (should be high for suspicious gateway packet)
            threat_level = detection._determine_threat_level(
                arp_info, 
                suspicious=True, 
                ip_mac_change=True
            )
            
            self.assertEqual(threat_level, "high")
            
            # 3. Add detection result which should trigger remediation
            with patch.object(remediation, 'block_host') as mock_block:
                mock_block.return_value = True
                
                detection._add_detection_result(
                    mac="00:11:22:33:44:55",
                    ip="192.168.1.1",
                    threat_level=threat_level,
                    details={"reason": "Gateway spoofing detected"}
                )
                
                # Verify remediation was triggered
                mock_block.assert_called_once()
                self.assertEqual(mock_block.call_args[0][0], "00:11:22:33:44:55")
                self.assertEqual(mock_block.call_args[0][1], "192.168.1.1")
        
        # 4. Check status via CLI
        status_args = MagicMock()
        status_args.service = 'all'
        with patch.object(detection, 'get_status') as mock_det_status, \
             patch.object(remediation, 'get_status') as mock_rem_status:
            
            mock_det_status.return_value = {'running': True, 'detections': 1}
            mock_rem_status.return_value = {'blocked_hosts_count': 1}
            
            cli._handle_status(status_args)
            
            mock_det_status.assert_called_once()
            mock_rem_status.assert_called_once()
        
        # 5. Stop detection via CLI
        stop_args = MagicMock()
        stop_args.service = 'detection'
        with patch.object(detection, 'stop_detection') as mock_stop:
            mock_stop.return_value = True
            cli._handle_stop(stop_args)
            mock_stop.assert_called_once()

class TestConfigPersistence(IntegrationTestCase):
    """Tests for configuration persistence across module restarts."""
    
    def test_remediation_config_persistence(self):
        """Test that remediation configuration persists."""
        # Create and configure first instance
        remediation1 = RemediationModule()
        remediation1.initialize()
        
        # Modify configuration
        remediation1.config.auto_block = False
        remediation1.config.block_duration = 600
        remediation1.config.whitelist.append("00:11:22:33:44:55:192.168.1.100")
        
        # Save configuration
        remediation1._save_config()
        
        # Create second instance (should load the saved config)
        remediation2 = RemediationModule()
        remediation2.initialize()
        
        # Verify configuration was loaded
        self.assertEqual(remediation2.config.auto_block, False)
        self.assertEqual(remediation2.config.block_duration, 600)
        self.assertIn("00:11:22:33:44:55:192.168.1.100", remediation2.config.whitelist)

if __name__ == '__main__':
    unittest.main() 