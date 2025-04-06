import unittest
import pandas as pd
import numpy as np
from datetime import datetime
from app.ml.features.performance_metrics import PerformanceMetrics
from app.ml.features.preprocessor import PerformancePreprocessor

class TestPerformanceMetrics(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures"""
        self.metrics = PerformanceMetrics(window_size=5)
        self.preprocessor = PerformancePreprocessor()
        
    def test_initialization(self):
        """Test initialization of PerformanceMetrics"""
        self.assertEqual(self.metrics.window_size, 5)
        self.assertTrue(all(key in self.metrics.metrics for key in [
            'timestamp', 'cpu_usage', 'memory_usage', 
            'network_traffic', 'packet_processing_rate', 'response_time'
        ]))
        
    def test_collect_metrics(self):
        """Test metrics collection"""
        metrics = self.metrics.collect_metrics()
        
        # Check all required metrics are present
        self.assertTrue(all(key in metrics for key in [
            'timestamp', 'cpu_usage', 'memory_usage',
            'network_traffic', 'packet_processing_rate', 'response_time'
        ]))
        
        # Check metric types
        self.assertIsInstance(metrics['timestamp'], datetime)
        self.assertIsInstance(metrics['cpu_usage'], float)
        self.assertIsInstance(metrics['memory_usage'], float)
        self.assertIsInstance(metrics['network_traffic'], float)
        
    def test_metrics_history(self):
        """Test metrics history maintenance"""
        # Collect metrics multiple times
        for _ in range(10):
            self.metrics.collect_metrics()
            
        # Check window size is maintained
        for values in self.metrics.metrics.values():
            self.assertLessEqual(len(values), self.metrics.window_size)
            
    def test_get_metrics_dataframe(self):
        """Test DataFrame conversion"""
        # Collect some metrics
        for _ in range(3):
            self.metrics.collect_metrics()
            
        df = self.metrics.get_metrics_dataframe()
        
        # Check DataFrame properties
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(len(df), min(3, self.metrics.window_size))
        self.assertTrue(all(col in df.columns for col in self.metrics.metrics.keys()))
        
    def test_preprocessing(self):
        """Test data preprocessing"""
        # Create sample data
        data = pd.DataFrame({
            'timestamp': pd.date_range(start='2024-01-01', periods=5, freq='H'),
            'cpu_usage': [50.0, 60.0, 55.0, 65.0, 70.0],
            'memory_usage': [40.0, 45.0, 42.0, 48.0, 50.0],
            'network_traffic': [1000.0, 1200.0, 1100.0, 1300.0, 1400.0]
        })
        
        # Preprocess data
        X, _ = self.preprocessor.preprocess(data)
        
        # Check preprocessing results
        self.assertIsInstance(X, np.ndarray)
        self.assertEqual(X.shape[0], len(data))
        self.assertLessEqual(X.shape[1], len(data.columns) - 1)  # -1 for timestamp
        
    def test_feature_importance(self):
        """Test feature importance calculation"""
        # Create sample data
        data = pd.DataFrame({
            'timestamp': pd.date_range(start='2024-01-01', periods=5, freq='H'),
            'cpu_usage': [50.0, 60.0, 55.0, 65.0, 70.0],
            'memory_usage': [40.0, 45.0, 42.0, 48.0, 50.0],
            'network_traffic': [1000.0, 1200.0, 1100.0, 1300.0, 1400.0]
        })
        
        # Preprocess data
        self.preprocessor.preprocess(data)
        
        # Get feature importance
        importance = self.preprocessor.get_feature_importance()
        
        # Check importance results
        self.assertIsInstance(importance, dict)
        self.assertTrue(all(isinstance(v, float) for v in importance.values()))
        
    def test_inverse_transform(self):
        """Test inverse transformation"""
        # Create sample data
        data = pd.DataFrame({
            'timestamp': pd.date_range(start='2024-01-01', periods=5, freq='H'),
            'cpu_usage': [50.0, 60.0, 55.0, 65.0, 70.0],
            'memory_usage': [40.0, 45.0, 42.0, 48.0, 50.0],
            'network_traffic': [1000.0, 1200.0, 1100.0, 1300.0, 1400.0]
        })
        
        # Preprocess data
        X, _ = self.preprocessor.preprocess(data)
        
        # Inverse transform
        X_original = self.preprocessor.inverse_transform(X)
        
        # Check inverse transformation
        self.assertIsInstance(X_original, np.ndarray)
        self.assertEqual(X_original.shape[0], len(data))
        
if __name__ == '__main__':
    unittest.main() 