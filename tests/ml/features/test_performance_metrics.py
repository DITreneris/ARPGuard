import unittest
import pandas as pd
import time
from datetime import datetime
from unittest.mock import patch, MagicMock

from app.ml.features.performance_metrics import PerformanceMetrics

class TestPerformanceMetrics(unittest.TestCase):
    """Test class for the PerformanceMetrics component."""
    
    def setUp(self):
        """Set up the test environment before each test."""
        self.metrics_collector = PerformanceMetrics(window_size=10)
    
    def test_initialization(self):
        """Test initialization of the metrics collector."""
        # Default initialization
        metrics = PerformanceMetrics()
        self.assertEqual(metrics.window_size, 60)
        
        # Custom initialization
        metrics = PerformanceMetrics(window_size=30)
        self.assertEqual(metrics.window_size, 30)
        
        # Verify metrics dictionary structure
        expected_keys = [
            'timestamp', 'cpu_usage', 'memory_usage', 'network_traffic',
            'packet_processing_rate', 'response_time'
        ]
        for key in expected_keys:
            self.assertIn(key, metrics.metrics)
            self.assertEqual(metrics.metrics[key], [])
    
    @patch('psutil.cpu_percent')
    @patch('psutil.virtual_memory')
    @patch('psutil.net_io_counters')
    @patch('time.time')
    def test_collect_metrics(self, mock_time, mock_net_io, mock_memory, mock_cpu):
        """Test collecting performance metrics."""
        # Mock the psutil calls
        mock_cpu.return_value = 25.5
        
        # Mock memory object
        mock_memory_obj = MagicMock()
        mock_memory_obj.percent = 45.2
        mock_memory.return_value = mock_memory_obj
        
        # Mock network IO objects
        first_net_io = MagicMock()
        first_net_io.bytes_sent = 1000
        first_net_io.bytes_recv = 2000
        
        second_net_io = MagicMock()
        second_net_io.bytes_sent = 1500
        second_net_io.bytes_recv = 3000
        
        mock_net_io.side_effect = [first_net_io, second_net_io]
        
        # Mock time values
        mock_time.side_effect = [100.0, 101.0]
        
        # Initialize network counters
        self.metrics_collector._initialize_network_counters()
        
        # Collect metrics
        with patch.object(self.metrics_collector, '_get_packet_rate', return_value=1200.0):
            with patch.object(self.metrics_collector, '_get_response_time', return_value=15.5):
                metrics = self.metrics_collector.collect_metrics()
        
        # Verify collected metrics
        self.assertIsInstance(metrics, dict)
        self.assertIn('timestamp', metrics)
        self.assertIsInstance(metrics['timestamp'], datetime)
        self.assertEqual(metrics['cpu_usage'], 25.5)
        self.assertEqual(metrics['memory_usage'], 45.2)
        self.assertEqual(metrics['packet_processing_rate'], 1200.0)
        self.assertEqual(metrics['response_time'], 15.5)
        
        # Network traffic should be calculated as (sent_diff + recv_diff) / time_diff
        # (1500-1000) + (3000-2000) = 1500 bytes over 1 second = 1500.0
        self.assertEqual(metrics['network_traffic'], 1500.0)
    
    def test_update_metrics_history(self):
        """Test updating the metrics history."""
        # Create sample metrics
        sample_metrics = {
            'timestamp': datetime.now(),
            'cpu_usage': 30.5,
            'memory_usage': 50.2,
            'network_traffic': 1250.0,
            'packet_processing_rate': 1500.0,
            'response_time': 10.5
        }
        
        # Update history with sample metrics
        self.metrics_collector._update_metrics_history(sample_metrics)
        
        # Verify history was updated
        for key, value in sample_metrics.items():
            self.assertIn(value, self.metrics_collector.metrics[key])
            self.assertEqual(len(self.metrics_collector.metrics[key]), 1)
        
        # Add more metrics to exceed window size
        for i in range(15):  # Window size is 10
            sample_metrics = {
                'timestamp': datetime.now(),
                'cpu_usage': 30.5 + i,
                'memory_usage': 50.2 + i,
                'network_traffic': 1250.0 + i,
                'packet_processing_rate': 1500.0 + i,
                'response_time': 10.5 + i
            }
            self.metrics_collector._update_metrics_history(sample_metrics)
        
        # Verify window size is maintained
        for key in self.metrics_collector.metrics:
            self.assertEqual(len(self.metrics_collector.metrics[key]), 10)
    
    def test_get_metrics_dataframe(self):
        """Test getting metrics as a pandas DataFrame."""
        # Add some metrics
        for i in range(5):
            sample_metrics = {
                'timestamp': datetime.now(),
                'cpu_usage': 30.5 + i,
                'memory_usage': 50.2 + i,
                'network_traffic': 1250.0 + i,
                'packet_processing_rate': 1500.0 + i,
                'response_time': 10.5 + i
            }
            self.metrics_collector._update_metrics_history(sample_metrics)
        
        # Get metrics as DataFrame
        df = self.metrics_collector.get_metrics_dataframe()
        
        # Verify DataFrame structure
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(len(df), 5)
        
        # Verify all columns are present
        for key in self.metrics_collector.metrics:
            self.assertIn(key, df.columns)
    
    def test_get_metrics_window(self):
        """Test getting metrics for a specified window."""
        # Add some metrics
        for i in range(5):
            sample_metrics = {
                'timestamp': datetime.now(),
                'cpu_usage': 30.5 + i,
                'memory_usage': 50.2 + i,
                'network_traffic': 1250.0 + i,
                'packet_processing_rate': 1500.0 + i,
                'response_time': 10.5 + i
            }
            self.metrics_collector._update_metrics_history(sample_metrics)
        
        # Get all metrics (default)
        all_metrics = self.metrics_collector.get_metrics_window()
        self.assertEqual(len(all_metrics['cpu_usage']), 5)
        
        # Get specific window size
        window_metrics = self.metrics_collector.get_metrics_window(window_size=3)
        self.assertEqual(len(window_metrics['cpu_usage']), 3)
        
        # Verify we get the most recent metrics
        self.assertEqual(window_metrics['cpu_usage'][-1], 30.5 + 4)
    
    def test_clear_metrics(self):
        """Test clearing all stored metrics."""
        # Add some metrics
        for i in range(5):
            sample_metrics = {
                'timestamp': datetime.now(),
                'cpu_usage': 30.5 + i,
                'memory_usage': 50.2 + i,
                'network_traffic': 1250.0 + i,
                'packet_processing_rate': 1500.0 + i,
                'response_time': 10.5 + i
            }
            self.metrics_collector._update_metrics_history(sample_metrics)
        
        # Verify metrics were added
        self.assertEqual(len(self.metrics_collector.metrics['cpu_usage']), 5)
        
        # Clear metrics
        self.metrics_collector.clear_metrics()
        
        # Verify all metrics were cleared
        for key in self.metrics_collector.metrics:
            self.assertEqual(len(self.metrics_collector.metrics[key]), 0)
    
    def test_get_packet_rate(self):
        """Test the packet rate calculation method."""
        # This is a placeholder implementation, so it should return 0.0
        packet_rate = self.metrics_collector._get_packet_rate()
        self.assertEqual(packet_rate, 0.0)
    
    def test_get_response_time(self):
        """Test the response time calculation method."""
        # This is a placeholder implementation, so it should return 0.0
        response_time = self.metrics_collector._get_response_time()
        self.assertEqual(response_time, 0.0)
    
    @patch('psutil.net_io_counters')
    def test_initialize_network_counters(self, mock_net_io):
        """Test initializing network counters."""
        # Mock network IO object
        net_io = MagicMock()
        net_io.bytes_sent = 1000
        net_io.bytes_recv = 2000
        mock_net_io.return_value = net_io
        
        # Initialize counters
        with patch('time.time', return_value=100.0):
            self.metrics_collector._initialize_network_counters()
        
        # Verify counters were initialized
        self.assertEqual(self.metrics_collector.last_net_io.bytes_sent, 1000)
        self.assertEqual(self.metrics_collector.last_net_io.bytes_recv, 2000)
        self.assertEqual(self.metrics_collector.last_time, 100.0)
    
if __name__ == "__main__":
    unittest.main() 