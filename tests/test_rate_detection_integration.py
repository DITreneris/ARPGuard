import unittest
import time
import tempfile
import os
import sys
import json
from unittest.mock import MagicMock, patch
from pathlib import Path

# Add src directory to path
sys.path.append(str(Path(__file__).parent.parent))

from src.core.rate_detection_integration import AdaptiveRateDetection
from src.core.alert import AlertManager, AlertType, AlertPriority, Alert

class TestAdaptiveRateDetection(unittest.TestCase):
    """Test the AdaptiveRateDetection class."""
    
    def setUp(self):
        """Set up test environment."""
        # Create a mock alert manager
        self.alert_manager = MagicMock(spec=AlertManager)
        
        # Create a temporary file for threshold persistence
        self.temp_dir = tempfile.TemporaryDirectory()
        self.persistence_path = os.path.join(self.temp_dir.name, "thresholds.json")
        
        # Create the adaptive rate detection system
        self.rate_detection = AdaptiveRateDetection(
            alert_manager=self.alert_manager,
            persistence_path=self.persistence_path,
            threshold_update_interval=0.1,  # Fast updates for testing
            monitor_interval=0.1            # Fast checks for testing
        )
    
    def tearDown(self):
        """Clean up after tests."""
        # Stop the rate detection system
        if hasattr(self, 'rate_detection') and self.rate_detection:
            self.rate_detection.stop()
            
        # Clean up the temporary directory
        if hasattr(self, 'temp_dir') and self.temp_dir:
            self.temp_dir.cleanup()
    
    def test_initialization(self):
        """Test initialization of AdaptiveRateDetection."""
        self.assertEqual(self.rate_detection.alert_manager, self.alert_manager)
        self.assertEqual(self.rate_detection.persistence_path, self.persistence_path)
        self.assertEqual(self.rate_detection.threshold_update_interval, 0.1)
        self.assertEqual(self.rate_detection.monitor_interval, 0.1)
        self.assertFalse(self.rate_detection.running)
        self.assertIsNone(self.rate_detection.thread)
        
        # Verify components are initialized
        self.assertIsNotNone(self.rate_detection.rate_monitor)
        self.assertIsNotNone(self.rate_detection.threshold_manager)
    
    def test_add_interface_detector(self):
        """Test adding an interface detector."""
        # Add a detector for 'eth0'
        self.rate_detection.add_interface_detector('eth0')
        
        # Verify detector was added to rate monitor
        status = self.rate_detection.rate_monitor.get_status()
        self.assertIn('interface:eth0', status)
        
        # Verify thresholds were created
        threshold_status = self.rate_detection.threshold_manager.get_status()
        thresholds = threshold_status.get('thresholds', {})
        
        # Check for warning threshold
        warning_key = 'interface:eth0:rate:warning'
        self.assertIn(warning_key, thresholds)
        
        # Check for critical threshold
        critical_key = 'interface:eth0:rate:critical'
        self.assertIn(critical_key, thresholds)
        
        # Verify threshold values
        warning_threshold = thresholds[warning_key]
        self.assertEqual(warning_threshold['initial_value'], 500.0)
        
        critical_threshold = thresholds[critical_key]
        self.assertEqual(critical_threshold['initial_value'], 1000.0)
        self.assertTrue(critical_threshold['use_percentile'])
    
    @patch('time.time', return_value=100.0)
    def test_update_packet_count(self, mock_time):
        """Test updating packet count."""
        # Add a detector
        self.rate_detection.add_interface_detector('eth0')
        
        # Update packet count
        self.rate_detection.update_packet_count('eth0', 100)
        
        # Update again with increment
        self.rate_detection.update_packet_count('eth0', 200)
        
        # Get detector status
        status = self.rate_detection.rate_monitor.get_status()
        detector_status = status.get('interface:eth0', {})
        
        # Verify packet count was updated
        self.assertIn('detector_status', detector_status)
        self.assertEqual(detector_status['detector_status']['last_count'], 200)
    
    @patch('time.time')
    def test_check_thresholds_below_warning(self, mock_time):
        """Test checking thresholds when rate is below warning level."""
        # Set up time mock
        mock_time.return_value = 100.0
        
        # Add a detector
        self.rate_detection.add_interface_detector('eth0')
        
        # Mock the threshold values
        self.rate_detection.threshold_manager.get_threshold_value = MagicMock(
            side_effect=lambda detector, metric, name: 500.0 if name == 'warning' else 1000.0
        )
        
        # Mock the rate monitor status
        self.rate_detection.rate_monitor.get_status = MagicMock(return_value={
            'interface:eth0': {
                'detector_status': {
                    'stats': {
                        'current': 100.0  # Below warning threshold
                    }
                }
            }
        })
        
        # Check thresholds
        self.rate_detection.check_thresholds()
        
        # Verify no alerts were created
        self.alert_manager.create_alert.assert_not_called()
    
    @patch('time.time')
    def test_check_thresholds_warning_level(self, mock_time):
        """Test checking thresholds when rate is at warning level."""
        # Set up time mock
        mock_time.return_value = 100.0
        
        # Add a detector
        self.rate_detection.add_interface_detector('eth0')
        
        # Mock the threshold values
        self.rate_detection.threshold_manager.get_threshold_value = MagicMock(
            side_effect=lambda detector, metric, name: 500.0 if name == 'warning' else 1000.0
        )
        
        # Mock the rate monitor status
        self.rate_detection.rate_monitor.get_status = MagicMock(return_value={
            'interface:eth0': {
                'detector_status': {
                    'stats': {
                        'current': 600.0  # Above warning but below critical
                    }
                }
            }
        })
        
        # Check thresholds
        self.rate_detection.check_thresholds()
        
        # Verify warning alert was created
        self.alert_manager.create_alert.assert_called_once()
        call_args = self.alert_manager.create_alert.call_args[0]
        self.assertEqual(call_args[0], AlertType.RATE_ANOMALY)
        self.assertEqual(call_args[1], AlertPriority.WARNING)
        self.assertIn('High packet rate detected on eth0', call_args[2])
        
        # Reset mock
        self.alert_manager.create_alert.reset_mock()
    
    @patch('time.time')
    def test_check_thresholds_critical_level(self, mock_time):
        """Test checking thresholds when rate is at critical level."""
        # Set up time mock
        mock_time.return_value = 100.0
        
        # Add a detector
        self.rate_detection.add_interface_detector('eth0')
        
        # Mock the threshold values
        self.rate_detection.threshold_manager.get_threshold_value = MagicMock(
            side_effect=lambda detector, metric, name: 500.0 if name == 'warning' else 1000.0
        )
        
        # Mock the rate monitor status
        self.rate_detection.rate_monitor.get_status = MagicMock(return_value={
            'interface:eth0': {
                'detector_status': {
                    'stats': {
                        'current': 1500.0  # Above critical threshold
                    }
                }
            }
        })
        
        # Check thresholds
        self.rate_detection.check_thresholds()
        
        # Verify critical alert was created
        self.alert_manager.create_alert.assert_called_once()
        call_args = self.alert_manager.create_alert.call_args[0]
        self.assertEqual(call_args[0], AlertType.RATE_ANOMALY)
        self.assertEqual(call_args[1], AlertPriority.CRITICAL)
        self.assertIn('Critical packet rate detected on eth0', call_args[2])
    
    def test_start_stop(self):
        """Test starting and stopping the rate detection system."""
        # Start the system
        self.rate_detection.start()
        
        # Verify system is running
        self.assertTrue(self.rate_detection.running)
        self.assertIsNotNone(self.rate_detection.thread)
        
        # Stop the system
        self.rate_detection.stop()
        
        # Verify system is stopped
        self.assertFalse(self.rate_detection.running)
        self.assertIsNone(self.rate_detection.thread)
    
    def test_get_status(self):
        """Test getting status information."""
        # Add a detector
        self.rate_detection.add_interface_detector('eth0')
        
        # Get status
        status = self.rate_detection.get_status()
        
        # Verify status contains expected keys
        self.assertIn('running', status)
        self.assertIn('threshold_update_interval', status)
        self.assertIn('monitor_interval', status)
        self.assertIn('persistence_path', status)
        self.assertIn('thresholds', status)
        self.assertIn('rate_monitor', status)


if __name__ == '__main__':
    unittest.main() 