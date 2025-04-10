import unittest
import time
from app.utils.performance_monitor import PerformanceMonitor, measure_performance, ResponseTimeOptimizer

class TestPerformanceMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = PerformanceMonitor()
        
    def test_track_metric(self):
        """Test tracking of performance metrics"""
        self.monitor.track_metric('test_metric', 1.0)
        self.monitor.track_metric('test_metric', 2.0)
        
        stats = self.monitor.get_metric_stats('test_metric')
        self.assertEqual(stats['count'], 2)
        self.assertEqual(stats['min'], 1.0)
        self.assertEqual(stats['max'], 2.0)
        
    def test_metric_stats(self):
        """Test calculation of metric statistics"""
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        for value in values:
            self.monitor.track_metric('test_metric', value)
            
        stats = self.monitor.get_metric_stats('test_metric')
        self.assertEqual(stats['mean'], 3.0)
        self.assertEqual(stats['median'], 3.0)
        
    def test_reset_metric(self):
        """Test resetting of metrics"""
        self.monitor.track_metric('test_metric', 1.0)
        self.monitor.reset_metric('test_metric')
        
        stats = self.monitor.get_metric_stats('test_metric')
        self.assertEqual(stats, {})
        
    @measure_performance('test_function')
    def test_function(self):
        """Test the performance measurement decorator"""
        time.sleep(0.1)
        return True
        
    def test_performance_decorator(self):
        """Test the performance measurement decorator"""
        result = self.test_function()
        self.assertTrue(result)
        
        # Verify that the metric was tracked
        stats = self.monitor.get_metric_stats('test_function')
        self.assertGreater(stats['min'], 0.0)

class TestResponseTimeOptimizer(unittest.TestCase):
    def setUp(self):
        self.optimizer = ResponseTimeOptimizer()
        
    def test_caching(self):
        """Test result caching functionality"""
        # Cache a result
        self.optimizer.cache_result('test_key', 'test_value', ttl=1.0)
        
        # Get cached result
        result = self.optimizer.get_cached_result('test_key')
        self.assertEqual(result, 'test_value')
        
        # Wait for cache to expire
        time.sleep(1.1)
        expired_result = self.optimizer.get_cached_result('test_key')
        self.assertIsNone(expired_result)
        
    def test_data_structure_optimization(self):
        """Test data structure optimization"""
        data = [1, 2, 3, 4, 5]
        
        # Test sequential access optimization
        optimized_seq = self.optimizer.optimize_data_structure(data, 'sequential')
        self.assertEqual(optimized_seq, data)
        
        # Test random access optimization
        optimized_random = self.optimizer.optimize_data_structure(data, 'random')
        self.assertIsInstance(optimized_random, dict)
        self.assertEqual(len(optimized_random), len(data))
        
        # Test frequent updates optimization
        optimized_updates = self.optimizer.optimize_data_structure(data, 'frequent_updates')
        self.assertIsInstance(optimized_updates, type(data))
        
    def test_response_time_measurement(self):
        """Test response time measurement"""
        with self.optimizer.measure_response_time('test_operation'):
            time.sleep(0.1)
            
        stats = self.optimizer.monitor.get_metric_stats('response_time_test_operation')
        self.assertGreater(stats['min'], 0.0)
        
    def test_performance_report(self):
        """Test performance report generation"""
        # Add some metrics
        with self.optimizer.measure_response_time('operation1'):
            time.sleep(0.1)
        with self.optimizer.measure_response_time('operation2'):
            time.sleep(0.2)
            
        report = self.optimizer.get_performance_report()
        self.assertIn('response_time_operation1', report)
        self.assertIn('response_time_operation2', report)
        self.assertGreater(report['response_time_operation2']['mean'], 
                          report['response_time_operation1']['mean'])

if __name__ == '__main__':
    unittest.main() 