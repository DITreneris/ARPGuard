import unittest
import time
import random
import threading
import numpy as np
from unittest.mock import MagicMock, patch

from src.core.rate_monitor import RateDetector, TrafficRateMonitor
from src.core.rate_analysis import (
    RatePattern, 
    PatternLibrary, 
    RateAnalyzer,
    AdaptiveThresholdManager
)

class TestRatePattern(unittest.TestCase):
    """Test cases for the RatePattern class."""
    
    def test_pattern_creation(self):
        """Test creating a pattern with features."""
        # Create pattern
        pattern = RatePattern("test_pattern", "Test pattern description")
        
        # Add features
        pattern.add_feature("numeric_feature", 42)
        pattern.add_feature("string_feature", "test")
        pattern.add_feature("list_feature", [1, 2, 3])
        pattern.add_feature("dict_feature", {"a": 1, "b": 2})
        
        # Check pattern attributes
        self.assertEqual(pattern.name, "test_pattern")
        self.assertEqual(pattern.description, "Test pattern description")
        self.assertEqual(len(pattern.features), 4)
        self.assertEqual(pattern.features["numeric_feature"], 42)
        self.assertEqual(pattern.features["string_feature"], "test")
        self.assertEqual(pattern.features["list_feature"], [1, 2, 3])
        self.assertEqual(pattern.features["dict_feature"], {"a": 1, "b": 2})
        
    def test_pattern_matching(self):
        """Test pattern matching with different samples."""
        # Create pattern
        pattern = RatePattern("test_pattern")
        pattern.add_feature("rate_variance", 0.2)
        pattern.add_feature("periodic", False)
        pattern.add_feature("sudden_spikes", False)
        
        # Test exact match
        sample1 = {
            "rate_variance": 0.2,
            "periodic": False,
            "sudden_spikes": False,
            "extra_feature": "ignored"
        }
        is_match, similarity = pattern.match(sample1)
        self.assertTrue(is_match)
        self.assertEqual(similarity, 1.0)
        
        # Test close but not exact match (within threshold)
        sample2 = {
            "rate_variance": 0.21,  # Slightly different
            "periodic": False,
            "sudden_spikes": False
        }
        is_match, similarity = pattern.match(sample2)
        self.assertTrue(is_match)
        self.assertGreater(similarity, 0.8)
        
        # Test non-match (below threshold)
        sample3 = {
            "rate_variance": 0.5,  # Very different
            "periodic": True,      # Different
            "sudden_spikes": False
        }
        is_match, similarity = pattern.match(sample3)
        self.assertFalse(is_match)
        self.assertLess(similarity, 0.8)
        
        # Test missing features
        sample4 = {
            "periodic": False,
            "sudden_spikes": False
        }
        is_match, similarity = pattern.match(sample4)
        self.assertFalse(is_match)
        self.assertEqual(similarity, 0.0)
        
    def test_serialization(self):
        """Test pattern serialization to/from dictionary."""
        # Create pattern
        pattern = RatePattern("test_pattern", "Test pattern description")
        pattern.add_feature("numeric_feature", 42)
        pattern.add_feature("string_feature", "test")
        
        # Convert to dictionary
        pattern_dict = pattern.to_dict()
        
        # Check dictionary
        self.assertEqual(pattern_dict["name"], "test_pattern")
        self.assertEqual(pattern_dict["description"], "Test pattern description")
        self.assertEqual(pattern_dict["features"]["numeric_feature"], 42)
        
        # Convert back to pattern
        pattern2 = RatePattern.from_dict(pattern_dict)
        
        # Check restored pattern
        self.assertEqual(pattern2.name, "test_pattern")
        self.assertEqual(pattern2.description, "Test pattern description")
        self.assertEqual(pattern2.features["numeric_feature"], 42)
        

class TestPatternLibrary(unittest.TestCase):
    """Test cases for the PatternLibrary class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.library = PatternLibrary()
        
        # Add test patterns
        self.pattern1 = RatePattern("pattern1", "Test pattern 1")
        self.pattern1.add_feature("feature1", 1)
        
        self.pattern2 = RatePattern("pattern2", "Test pattern 2")
        self.pattern2.add_feature("feature2", 2)
        
        self.library.add_pattern(self.pattern1)
        self.library.add_pattern(self.pattern2)
        
    def test_add_get_pattern(self):
        """Test adding and getting patterns."""
        # Check existing patterns
        pattern1 = self.library.get_pattern("pattern1")
        self.assertIsNotNone(pattern1)
        self.assertEqual(pattern1.name, "pattern1")
        
        # Check non-existent pattern
        pattern3 = self.library.get_pattern("non_existent")
        self.assertIsNone(pattern3)
        
        # Add new pattern
        pattern3 = RatePattern("pattern3", "Test pattern 3")
        self.library.add_pattern(pattern3)
        
        # Check new pattern
        pattern3_get = self.library.get_pattern("pattern3")
        self.assertIsNotNone(pattern3_get)
        self.assertEqual(pattern3_get.name, "pattern3")
        
    def test_remove_pattern(self):
        """Test removing patterns."""
        # Remove existing pattern
        result = self.library.remove_pattern("pattern1")
        self.assertTrue(result)
        
        # Check pattern is gone
        pattern1 = self.library.get_pattern("pattern1")
        self.assertIsNone(pattern1)
        
        # Remove non-existent pattern
        result = self.library.remove_pattern("non_existent")
        self.assertFalse(result)
        
    def test_find_matches(self):
        """Test finding pattern matches."""
        # Create sample that matches pattern1
        sample1 = {"feature1": 1, "extra": "value"}
        
        # Find matches
        matches = self.library.find_matches(sample1)
        
        # Check matches
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][0].name, "pattern1")
        
        # Create sample that matches both patterns
        sample2 = {"feature1": 1, "feature2": 2}
        
        # Create a third pattern for testing
        pattern3 = RatePattern("pattern3", "Test pattern 3")
        pattern3.add_feature("feature1", 1)
        pattern3.add_feature("feature2", 2)
        self.library.add_pattern(pattern3)
        
        # Find matches
        matches = self.library.find_matches(sample2)
        
        # Check matches (expect 3 matches, sorted by similarity)
        self.assertEqual(len(matches), 3)
        self.assertEqual(matches[0][0].name, "pattern3")  # Best match (has both features)
        
    def test_default_patterns(self):
        """Test loading default patterns."""
        library = PatternLibrary()
        library.load_default_patterns()
        
        # Check that default patterns were loaded
        self.assertIsNotNone(library.get_pattern("normal_traffic"))
        self.assertIsNotNone(library.get_pattern("dos_attack"))
        self.assertIsNotNone(library.get_pattern("network_scan"))
        self.assertIsNotNone(library.get_pattern("arp_spoofing"))
        self.assertIsNotNone(library.get_pattern("data_transfer"))
        

class TestRateAnalyzer(unittest.TestCase):
    """Test cases for the RateAnalyzer class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create mock rate monitor
        self.mock_monitor = MagicMock(spec=TrafficRateMonitor)
        
        # Initialize analyzer
        self.analyzer = RateAnalyzer(self.mock_monitor)
        
        # Register test detector
        self.analyzer.register_detector("test_detector")
        
    def test_add_sample(self):
        """Test adding samples."""
        # Add sample without timestamp
        sample1 = {"current_rate": 100}
        self.analyzer.add_sample("test_detector", sample1)
        
        # Add sample with timestamp
        sample2 = {"current_rate": 200, "timestamp": 123456}
        self.analyzer.add_sample("test_detector", sample2)
        
        # Add sample to non-existent detector (should create it)
        sample3 = {"current_rate": 300}
        self.analyzer.add_sample("new_detector", sample3)
        
        # Check samples were added
        self.assertEqual(len(self.analyzer.historical_data["test_detector"]), 2)
        self.assertEqual(len(self.analyzer.historical_data["new_detector"]), 1)
        
        # Check timestamp was added to first sample
        self.assertTrue("timestamp" in self.analyzer.historical_data["test_detector"][0])
        
    def test_analyze_detector_basic_stats(self):
        """Test analyzing basic statistics."""
        # Add samples
        for i in range(20):
            sample = {"current_rate": 100 + i * 10, "timestamp": time.time() + i}
            self.analyzer.add_sample("test_detector", sample)
            
        # Analyze detector
        results = self.analyzer.analyze_detector("test_detector")
        
        # Check basic statistics
        self.assertEqual(results["count"], 20)
        self.assertEqual(results["min"], 100)
        self.assertEqual(results["max"], 290)
        self.assertAlmostEqual(results["mean"], 195, delta=1)
        
    def test_analyze_detector_periodicity(self):
        """Test analyzing periodicity."""
        # Add periodic samples (sine wave)
        for i in range(100):
            rate = 100 + 50 * np.sin(i * 0.2 * np.pi)
            sample = {"current_rate": rate, "timestamp": time.time() + i}
            self.analyzer.add_sample("periodic_detector", sample)
            
        # Analyze detector
        results = self.analyzer.analyze_detector("periodic_detector")
        
        # Check periodicity detection
        self.assertTrue(results["periodic"])
        self.assertTrue("period" in results)
        
    def test_analyze_detector_spikes(self):
        """Test analyzing spikes."""
        # Add samples with spikes
        for i in range(50):
            rate = 100
            if i in [10, 25, 40]:  # Add spikes
                rate = 500
            sample = {"current_rate": rate, "timestamp": time.time() + i}
            self.analyzer.add_sample("spike_detector", sample)
            
        # Analyze detector
        results = self.analyzer.analyze_detector("spike_detector")
        
        # Check spike detection
        self.assertTrue(results["sudden_spikes"])
        self.assertEqual(results["spike_count"], 3)
        
    def test_auto_threshold(self):
        """Test automatic threshold calculation."""
        # Add samples
        for i in range(20):
            sample = {"current_rate": 100 + i * 10, "timestamp": time.time() + i}
            self.analyzer.add_sample("test_detector", sample)
            
        # Calculate thresholds
        thresholds = self.analyzer.auto_threshold("test_detector")
        
        # Check thresholds
        self.assertTrue("high_rate" in thresholds)
        self.assertTrue("critical_rate" in thresholds)
        self.assertTrue("low_rate" in thresholds)
        
        # Check threshold values
        self.assertGreater(thresholds["high_rate"], thresholds["low_rate"])
        self.assertGreater(thresholds["critical_rate"], thresholds["high_rate"])
        
        # Test sensitivity
        thresholds_high = self.analyzer.auto_threshold("test_detector", 2.0)
        self.assertGreater(thresholds_high["high_rate"], thresholds["high_rate"])
        
    def test_pattern_classification(self):
        """Test pattern classification."""
        # Create samples that match normal pattern
        for i in range(50):
            sample = {
                "current_rate": 100 + random.uniform(-5, 5),  # Low variance
                "timestamp": time.time() + i
            }
            self.analyzer.add_sample("normal_detector", sample)
            
        # Create samples that match DOS attack pattern
        for i in range(50):
            # High variance with spikes
            rate = 100
            if i % 10 < 3:  # Spikes every 10 samples
                rate = 500
            sample = {
                "current_rate": rate,
                "timestamp": time.time() + i
            }
            self.analyzer.add_sample("dos_detector", sample)
            
        # Analyze detectors
        normal_results = self.analyzer.analyze_detector("normal_detector")
        dos_results = self.analyzer.analyze_detector("dos_detector")
        
        # Check pattern classification
        self.assertEqual(normal_results["pattern_classification"], "normal_traffic")
        self.assertEqual(dos_results["pattern_classification"], "dos_attack")
        
    def test_update_from_monitor(self):
        """Test updating from rate monitor."""
        # Mock monitor status
        self.mock_monitor.get_status.return_value = {
            "detector1": {
                "detector_status": {
                    "stats": {
                        "current": 100,
                        "mean": 90,
                        "std": 10
                    }
                },
                "packet_counter": 1000
            },
            "detector2": {
                "detector_status": {
                    "stats": {
                        "current": 200,
                        "mean": 180,
                        "std": 20
                    }
                },
                "packet_counter": 2000
            }
        }
        
        # Update from monitor
        result = self.analyzer.update_from_monitor()
        
        # Check result
        self.assertTrue(result)
        
        # Check samples were added
        self.assertEqual(len(self.analyzer.historical_data["detector1"]), 1)
        self.assertEqual(len(self.analyzer.historical_data["detector2"]), 1)
        
        # Check sample values
        self.assertEqual(self.analyzer.historical_data["detector1"][0]["current_rate"], 100)
        self.assertEqual(self.analyzer.historical_data["detector2"][0]["current_rate"], 200)
        

class TestAdaptiveThresholdManager(unittest.TestCase):
    """Test cases for the AdaptiveThresholdManager class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create mock rate monitor
        self.mock_monitor = MagicMock(spec=TrafficRateMonitor)
        self.mock_monitor.detectors = {"detector1": MagicMock(), "detector2": MagicMock()}
        
        # Create mock rate analyzer
        self.mock_analyzer = MagicMock(spec=RateAnalyzer)
        
        # Initialize manager
        self.manager = AdaptiveThresholdManager(
            self.mock_monitor, self.mock_analyzer, update_interval=1)
        
    def test_sensitivity(self):
        """Test sensitivity settings."""
        # Check default sensitivity
        self.assertEqual(self.manager.get_sensitivity("detector1"), 1.0)
        
        # Set sensitivity
        self.manager.set_sensitivity("detector1", 2.0)
        
        # Check sensitivity
        self.assertEqual(self.manager.get_sensitivity("detector1"), 2.0)
        
        # Set extreme sensitivities (should be clamped)
        self.manager.set_sensitivity("detector2", 20.0)
        self.assertEqual(self.manager.get_sensitivity("detector2"), 10.0)
        
        self.manager.set_sensitivity("detector2", 0.05)
        self.assertEqual(self.manager.get_sensitivity("detector2"), 0.1)
        
    def test_update_now(self):
        """Test immediate threshold update."""
        # Define mock threshold values
        self.mock_analyzer.auto_threshold.return_value = {
            "high_rate": 200,
            "critical_rate": 400,
            "low_rate": 50
        }
        
        # Update thresholds
        self.manager.update_now()
        
        # Check analyzer was called
        self.mock_analyzer.update_from_monitor.assert_called_once()
        
        # Check thresholds were applied
        self.assertEqual(self.mock_analyzer.apply_auto_thresholds.call_count, 2)
        
    def test_start_stop(self):
        """Test starting and stopping the manager."""
        # Start manager
        self.manager.start()
        
        # Check thread is running
        self.assertTrue(self.manager.running)
        self.assertIsNotNone(self.manager.thread)
        
        # Stop manager
        self.manager.stop()
        
        # Check thread is stopped
        self.assertFalse(self.manager.running)
        
    def test_get_status(self):
        """Test getting manager status."""
        # Mock analyzer responses
        self.mock_analyzer.auto_threshold.return_value = {"high_rate": 200}
        self.mock_analyzer.results = {
            "detector1": {
                "mean": 100,
                "std": 10,
                "matching_patterns": [("normal_traffic", 0.9)]
            }
        }
        
        # Get status
        status = self.manager.get_status()
        
        # Check status
        self.assertFalse(status["running"])
        self.assertEqual(status["update_interval"], 1)
        self.assertEqual(status["default_sensitivity"], 1.0)
        self.assertEqual(len(status["detectors"]), 2)
        self.assertEqual(status["detectors"]["detector1"]["thresholds"]["high_rate"], 200)


if __name__ == "__main__":
    unittest.main() 