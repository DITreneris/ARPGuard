import unittest
import time
from unittest.mock import MagicMock, patch
import statistics
import tempfile
import os
import json
import sys
import pathlib

# Add the src directory to the path so we can import the module
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from src.core.adaptive_threshold import (
    AdaptiveThreshold,
    AdaptiveThresholdManager,
    calculate_percentile
)


class TestCalculatePercentile(unittest.TestCase):
    """Test the calculate_percentile function."""
    
    def test_empty_data(self):
        """Test with empty data."""
        self.assertEqual(calculate_percentile([], 95.0), 0.0)
    
    def test_single_value(self):
        """Test with a single value."""
        self.assertEqual(calculate_percentile([10.0], 95.0), 10.0)
    
    def test_multiple_values(self):
        """Test with multiple values."""
        data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
        
        # Test various percentiles
        self.assertAlmostEqual(calculate_percentile(data, 0.0), 1.0)
        self.assertAlmostEqual(calculate_percentile(data, 50.0), 5.5)
        self.assertAlmostEqual(calculate_percentile(data, 90.0), 9.1)
        self.assertAlmostEqual(calculate_percentile(data, 100.0), 10.0)
    
    def test_unsorted_data(self):
        """Test with unsorted data."""
        data = [5.0, 2.0, 10.0, 1.0, 8.0, 3.0, 7.0, 4.0, 9.0, 6.0]
        
        # Should give same results as if data were sorted
        self.assertAlmostEqual(calculate_percentile(data, 50.0), 5.5)


class TestAdaptiveThreshold(unittest.TestCase):
    """Test the AdaptiveThreshold class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.threshold = AdaptiveThreshold(
            name="test_threshold",
            detector_name="test_detector",
            metric_name="test_metric",
            initial_value=100.0,
            min_value=10.0,
            max_value=500.0,
            learning_rate=0.2,
            window_size=5,
            adaptation_interval=10,
            std_dev_factor=2.0
        )
    
    def test_initialization(self):
        """Test initialization of AdaptiveThreshold."""
        self.assertEqual(self.threshold.name, "test_threshold")
        self.assertEqual(self.threshold.detector_name, "test_detector")
        self.assertEqual(self.threshold.metric_name, "test_metric")
        self.assertEqual(self.threshold.current_value, 100.0)
        self.assertEqual(self.threshold.min_value, 10.0)
        self.assertEqual(self.threshold.max_value, 500.0)
        self.assertEqual(self.threshold.learning_rate, 0.2)
        self.assertEqual(self.threshold.window_size, 5)
        self.assertEqual(self.threshold.adaptation_interval, 10)
        self.assertEqual(self.threshold.std_dev_factor, 2.0)
        self.assertEqual(self.threshold.history, [])
        self.assertEqual(self.threshold.last_adaptation_time, 0)
        self.assertEqual(self.threshold.adaptations_count, 0)
        self.assertEqual(self.threshold.total_adjustment, 0.0)
    
    def test_add_sample(self):
        """Test adding samples to the threshold."""
        # Add samples
        self.threshold.add_sample(50.0)
        self.threshold.add_sample(60.0)
        
        # Check that samples were added
        self.assertEqual(self.threshold.history, [50.0, 60.0])
        
        # Test window size limitation
        for i in range(10):
            self.threshold.add_sample(float(i))
            
        # Should only keep the most recent window_size samples
        self.assertEqual(len(self.threshold.history), 5)
        self.assertEqual(self.threshold.history, [6.0, 7.0, 8.0, 9.0, 0.0])
    
    def test_adapt_not_enough_time(self):
        """Test adaptation when not enough time has passed."""
        # Set last adaptation time to now
        current_time = time.time()
        self.threshold.last_adaptation_time = current_time
        
        # Add samples
        self.threshold.add_sample(50.0)
        self.threshold.add_sample(60.0)
        
        # Should not adapt because not enough time has passed
        self.assertFalse(self.threshold.adapt(current_time + 5))
        self.assertEqual(self.threshold.adaptations_count, 0)
    
    def test_adapt_not_enough_samples(self):
        """Test adaptation when not enough samples are available."""
        # Set last adaptation time to long ago
        self.threshold.last_adaptation_time = 0
        
        # No samples - should not adapt
        self.assertFalse(self.threshold.adapt())
        self.assertEqual(self.threshold.adaptations_count, 0)
    
    def test_adapt_with_standard_deviation(self):
        """Test adaptation using mean and standard deviation."""
        # Set last adaptation time to long ago
        self.threshold.last_adaptation_time = 0
        
        # Add samples with a known mean and std dev
        for value in [100.0, 120.0, 130.0, 140.0, 150.0]:
            self.threshold.add_sample(value)
            
        # Mean = 128, StdDev ≈ 19.24
        # New base should be around 128 + (19.24 * 2) ≈ 166.48
        # New value should be 100 * 0.8 + 166.48 * 0.2 ≈ 113.3
        
        # Adapt
        self.assertTrue(self.threshold.adapt())
        
        # Check that adaptation occurred
        self.assertEqual(self.threshold.adaptations_count, 1)
        self.assertAlmostEqual(self.threshold.current_value, 113.3, places=1)
    
    def test_adapt_with_percentile(self):
        """Test adaptation using percentile."""
        # Create a threshold with percentile configuration
        threshold = AdaptiveThreshold(
            name="percentile_threshold",
            detector_name="test_detector",
            metric_name="test_metric",
            initial_value=100.0,
            learning_rate=0.2,
            use_percentile=True,
            percentile=90.0
        )
        
        # Set last adaptation time to long ago
        threshold.last_adaptation_time = 0
        
        # Add samples
        for value in [100.0, 110.0, 120.0, 130.0, 140.0, 150.0, 160.0, 170.0, 180.0, 190.0]:
            threshold.add_sample(value)
            
        # 90th percentile should be 181.0
        # New value should be 100 * 0.8 + 181.0 * 0.2 = 116.2
        
        # Adapt
        self.assertTrue(threshold.adapt())
        
        # Check that adaptation occurred
        self.assertEqual(threshold.adaptations_count, 1)
        self.assertAlmostEqual(threshold.current_value, 116.2, places=1)
    
    def test_adapt_with_bounds(self):
        """Test adaptation with bounds applied."""
        # Set last adaptation time to long ago
        self.threshold.last_adaptation_time = 0
        
        # Add samples that would push the value below min_value
        for value in [10.0, 12.0, 14.0, 16.0, 18.0]:
            self.threshold.add_sample(value)
            
        # Mean = 14, StdDev = 3.16
        # New base should be around 14 + (3.16 * 2) ≈ 20.32
        # New value would be 100 * 0.8 + 20.32 * 0.2 ≈ 84.06
        
        # Adapt
        self.assertTrue(self.threshold.adapt())
        
        # Check that adaptation occurred and bounds were applied
        self.assertEqual(self.threshold.adaptations_count, 1)
        self.assertAlmostEqual(self.threshold.current_value, 84.06, places=1)
        
        # Now test exceeding max_value
        self.threshold.last_adaptation_time = 0
        
        # Add samples that would push the value above max_value
        for value in [1000.0, 1200.0, 1400.0, 1600.0, 1800.0]:
            self.threshold.add_sample(value)
            
        # Adapt
        self.assertTrue(self.threshold.adapt())
        
        # Check that max bound was applied
        self.assertEqual(self.threshold.adaptations_count, 2)
        self.assertEqual(self.threshold.current_value, 500.0)  # max_value
    
    def test_to_dict_and_from_dict(self):
        """Test conversion to and from dictionary."""
        # Add some samples and adapt the threshold
        self.threshold.last_adaptation_time = 0
        self.threshold.add_sample(50.0)
        self.threshold.add_sample(60.0)
        self.threshold.adapt()
        
        # Convert to dictionary
        threshold_dict = self.threshold.to_dict()
        
        # Check dictionary contents
        self.assertEqual(threshold_dict["name"], "test_threshold")
        self.assertEqual(threshold_dict["detector_name"], "test_detector")
        self.assertEqual(threshold_dict["metric_name"], "test_metric")
        self.assertEqual(threshold_dict["adaptations_count"], 1)
        
        # Create a new threshold from the dictionary
        new_threshold = AdaptiveThreshold.from_dict(threshold_dict)
        
        # Check that properties were copied correctly
        self.assertEqual(new_threshold.name, self.threshold.name)
        self.assertEqual(new_threshold.detector_name, self.threshold.detector_name)
        self.assertEqual(new_threshold.metric_name, self.threshold.metric_name)
        self.assertEqual(new_threshold.current_value, self.threshold.current_value)
        self.assertEqual(new_threshold.min_value, self.threshold.min_value)
        self.assertEqual(new_threshold.max_value, self.threshold.max_value)
        self.assertEqual(new_threshold.learning_rate, self.threshold.learning_rate)
        self.assertEqual(new_threshold.window_size, self.threshold.window_size)
        self.assertEqual(new_threshold.adaptation_interval, self.threshold.adaptation_interval)
        self.assertEqual(new_threshold.std_dev_factor, self.threshold.std_dev_factor)
        self.assertEqual(new_threshold.use_percentile, self.threshold.use_percentile)
        self.assertEqual(new_threshold.percentile, self.threshold.percentile)


class TestAdaptiveThresholdManager(unittest.TestCase):
    """Test the AdaptiveThresholdManager class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a mock rate monitor
        self.rate_monitor = MagicMock()
        
        # Configure the mock rate monitor with a detector
        self.rate_monitor.detectors = {"test_detector": MagicMock()}
        
        # Configure the mock rate monitor to return a status
        self.rate_monitor.get_status.return_value = {
            "test_detector": {
                "detector_status": {
                    "stats": {
                        "current": 50.0
                    }
                }
            }
        }
        
        # Create a temporary file for threshold persistence
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file.close()
        
        # Create the manager
        self.manager = AdaptiveThresholdManager(
            rate_monitor=self.rate_monitor,
            update_interval=1.0,
            persistence_path=self.temp_file.name
        )
    
    def tearDown(self):
        """Tear down test fixtures."""
        # Stop the manager
        self.manager.stop()
        
        # Delete the temporary file
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)
    
    def test_initialization(self):
        """Test initialization of AdaptiveThresholdManager."""
        # Check that the manager was initialized with default thresholds
        self.assertEqual(len(self.manager.thresholds), 2)
        
        # Check that the thresholds were created correctly
        high_rate = self.manager.get_threshold("test_detector", "current", "high_rate")
        self.assertIsNotNone(high_rate)
        self.assertEqual(high_rate.name, "high_rate")
        self.assertEqual(high_rate.detector_name, "test_detector")
        self.assertEqual(high_rate.metric_name, "current")
        
        critical_rate = self.manager.get_threshold("test_detector", "current", "critical_rate")
        self.assertIsNotNone(critical_rate)
        self.assertEqual(critical_rate.name, "critical_rate")
        self.assertEqual(critical_rate.detector_name, "test_detector")
        self.assertEqual(critical_rate.metric_name, "current")
    
    def test_add_and_get_threshold(self):
        """Test adding and getting thresholds."""
        # Create a new threshold
        threshold = AdaptiveThreshold(
            name="custom_threshold",
            detector_name="test_detector",
            metric_name="test_metric",
            initial_value=200.0
        )
        
        # Add the threshold
        self.manager.add_threshold(threshold)
        
        # Get the threshold
        retrieved = self.manager.get_threshold("test_detector", "test_metric", "custom_threshold")
        
        # Check that the threshold was added correctly
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.name, "custom_threshold")
        self.assertEqual(retrieved.detector_name, "test_detector")
        self.assertEqual(retrieved.metric_name, "test_metric")
        self.assertEqual(retrieved.current_value, 200.0)
    
    def test_get_threshold_value(self):
        """Test getting a threshold value."""
        # Get a threshold value
        value = self.manager.get_threshold_value("test_detector", "current", "high_rate")
        
        # Check that the value was retrieved correctly
        self.assertIsNotNone(value)
        self.assertEqual(value, 100.0)  # Default initial value
        
        # Try getting a non-existent threshold
        value = self.manager.get_threshold_value("non_existent", "metric", "threshold")
        self.assertIsNone(value)
    
    def test_update(self):
        """Test updating thresholds."""
        # Add a spy to the add_sample method
        original_add_sample = AdaptiveThreshold.add_sample
        add_sample_calls = []
        
        def spy_add_sample(self, value):
            add_sample_calls.append((self.name, value))
            return original_add_sample(self, value)
        
        with patch('src.core.adaptive_threshold.AdaptiveThreshold.add_sample', spy_add_sample):
            # Update the manager
            self.manager.update()
            
            # Check that the thresholds were updated
            self.assertEqual(len(add_sample_calls), 2)
            self.assertEqual(add_sample_calls[0][0], "high_rate")
            self.assertEqual(add_sample_calls[0][1], 50.0)
            self.assertEqual(add_sample_calls[1][0], "critical_rate")
            self.assertEqual(add_sample_calls[1][1], 50.0)
    
    def test_persistence(self):
        """Test saving and loading thresholds."""
        # Modify a threshold
        threshold = self.manager.get_threshold("test_detector", "current", "high_rate")
        threshold.current_value = 150.0
        
        # Save thresholds
        self.manager._save_thresholds()
        
        # Create a new manager to load the thresholds
        new_manager = AdaptiveThresholdManager(
            rate_monitor=self.rate_monitor,
            persistence_path=self.temp_file.name
        )
        
        # Check that the thresholds were loaded correctly
        loaded_threshold = new_manager.get_threshold("test_detector", "current", "high_rate")
        self.assertIsNotNone(loaded_threshold)
        self.assertEqual(loaded_threshold.current_value, 150.0)
    
    def test_start_and_stop(self):
        """Test starting and stopping the manager."""
        # Start the manager
        self.manager.start()
        
        # Check that the manager is running
        self.assertTrue(self.manager.running)
        self.assertIsNotNone(self.manager.thread)
        
        # Stop the manager
        self.manager.stop()
        
        # Check that the manager is stopped
        self.assertFalse(self.manager.running)
        self.assertIsNone(self.manager.thread)
    
    def test_get_status(self):
        """Test getting status information."""
        # Get status
        status = self.manager.get_status()
        
        # Check status information
        self.assertFalse(status["running"])
        self.assertEqual(status["update_interval"], 1.0)
        self.assertEqual(status["persistence_path"], self.temp_file.name)
        self.assertEqual(status["thresholds_count"], 2)
        self.assertIn("thresholds", status)


if __name__ == "__main__":
    unittest.main() 