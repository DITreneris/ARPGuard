import unittest
import numpy as np
import pandas as pd
from datetime import datetime
from unittest.mock import patch, MagicMock

from app.ml.features.preprocessor import PerformancePreprocessor

class TestPerformancePreprocessor(unittest.TestCase):
    """Test class for the PerformancePreprocessor component."""
    
    def setUp(self):
        """Set up the test environment before each test."""
        self.preprocessor = PerformancePreprocessor()
        
        # Create sample performance data
        dates = pd.date_range(start='2023-01-01', periods=100, freq='H')
        self.sample_data = pd.DataFrame({
            'timestamp': dates,
            'cpu_usage': np.random.uniform(0, 100, 100),
            'memory_usage': np.random.uniform(20, 80, 100),
            'network_traffic': np.random.uniform(0, 1000, 100),
            'packet_processing_rate': np.random.uniform(100, 5000, 100),
            'response_time': np.random.uniform(1, 100, 100)
        })
        
        # Add a target column for some tests
        self.sample_data_with_target = self.sample_data.copy()
        self.sample_data_with_target['anomaly'] = np.random.randint(0, 2, 100)
    
    def test_initialization(self):
        """Test initialization of the preprocessor."""
        # Default initialization
        preprocessor = PerformancePreprocessor()
        self.assertEqual(preprocessor.pca.n_components, 0.95)
        self.assertEqual(preprocessor.feature_names, [])
        
        # Custom initialization
        preprocessor = PerformancePreprocessor(n_components=0.8)
        self.assertEqual(preprocessor.pca.n_components, 0.8)
    
    def test_process_timestamp(self):
        """Test timestamp processing functionality."""
        # Process timestamp column
        processed_data = self.preprocessor._process_timestamp(self.sample_data)
        
        # Verify timestamp was processed into features
        self.assertNotIn('timestamp', processed_data.columns)
        self.assertIn('hour', processed_data.columns)
        self.assertIn('day_of_week', processed_data.columns)
        self.assertIn('is_weekend', processed_data.columns)
        
        # Verify values
        # Check if hours range from 0-23
        self.assertTrue((processed_data['hour'] >= 0).all() and (processed_data['hour'] <= 23).all())
        
        # Check if day_of_week ranges from 0-6
        self.assertTrue((processed_data['day_of_week'] >= 0).all() and (processed_data['day_of_week'] <= 6).all())
        
        # Check if is_weekend is boolean (0 or 1)
        self.assertTrue(set(processed_data['is_weekend'].unique()).issubset({0, 1, True, False}))
    
    def test_preprocess_without_target(self):
        """Test preprocessing without a target column."""
        # Preprocess data without target
        X_reduced, y = self.preprocessor.preprocess(self.sample_data)
        
        # Verify output shape and type
        self.assertIsInstance(X_reduced, np.ndarray)
        self.assertIsNone(y)
        
        # Verify feature names were stored
        self.assertGreater(len(self.preprocessor.feature_names), 0)
        
        # Verify dimensionality reduction was applied
        # The number of components should be less than or equal to the original features
        self.assertLessEqual(X_reduced.shape[1], len(self.sample_data.columns) + 2)  # +2 for hour, day_of_week, is_weekend
    
    def test_preprocess_with_target(self):
        """Test preprocessing with a target column."""
        # Preprocess data with target
        X_reduced, y = self.preprocessor.preprocess(self.sample_data_with_target, target_column='anomaly')
        
        # Verify output shape and type
        self.assertIsInstance(X_reduced, np.ndarray)
        self.assertIsInstance(y, np.ndarray)
        
        # Verify target column extraction
        self.assertEqual(y.shape[0], len(self.sample_data_with_target))
        
        # Verify feature names don't include target
        self.assertNotIn('anomaly', self.preprocessor.feature_names)
    
    def test_get_feature_importance(self):
        """Test feature importance calculation."""
        # First preprocess data to populate feature_names
        X_reduced, _ = self.preprocessor.preprocess(self.sample_data)
        
        # Get feature importance
        importance = self.preprocessor.get_feature_importance()
        
        # Verify structure
        self.assertIsInstance(importance, dict)
        self.assertGreater(len(importance), 0)
        
        # Verify all features have importance values
        for feature in self.preprocessor.feature_names:
            self.assertIn(feature, importance)
            self.assertIsInstance(importance[feature], float)
    
    def test_get_feature_importance_empty(self):
        """Test feature importance with empty feature names."""
        # Create a new preprocessor without processed data
        preprocessor = PerformancePreprocessor()
        
        # Get feature importance (should be empty)
        importance = preprocessor.get_feature_importance()
        self.assertEqual(importance, {})
    
    def test_inverse_transform(self):
        """Test inverse transformation of preprocessed data."""
        # Preprocess data
        X_reduced, _ = self.preprocessor.preprocess(self.sample_data)
        
        # Inverse transform
        X_original = self.preprocessor.inverse_transform(X_reduced)
        
        # Verify shape
        self.assertEqual(X_original.shape[0], X_reduced.shape[0])
        self.assertEqual(X_original.shape[1], len(self.preprocessor.feature_names))
        
        # The recovered data should be approximately similar to original
        # (we can't check exact equality due to dimensionality reduction)
        
    def test_get_explained_variance(self):
        """Test getting explained variance ratio."""
        # First preprocess data to fit PCA
        X_reduced, _ = self.preprocessor.preprocess(self.sample_data)
        
        # Get explained variance
        variance = self.preprocessor.get_explained_variance()
        
        # Verify it's a float between 0 and 1
        self.assertIsInstance(variance, float)
        self.assertGreaterEqual(variance, 0.0)
        self.assertLessEqual(variance, 1.0)
        
        # For n_components=0.95, variance should be at least 0.95
        self.assertGreaterEqual(variance, 0.95)
    
    def test_different_n_components(self):
        """Test using different n_components values."""
        # Create preprocessor with lower variance preservation
        preprocessor_low = PerformancePreprocessor(n_components=0.5)
        X_reduced_low, _ = preprocessor_low.preprocess(self.sample_data)
        
        # Create preprocessor with higher variance preservation
        preprocessor_high = PerformancePreprocessor(n_components=0.99)
        X_reduced_high, _ = preprocessor_high.preprocess(self.sample_data)
        
        # Higher preservation should result in more components
        if hasattr(preprocessor_low.pca, 'n_components_') and hasattr(preprocessor_high.pca, 'n_components_'):
            self.assertLessEqual(preprocessor_low.pca.n_components_, preprocessor_high.pca.n_components_)
    
    def test_data_without_timestamp(self):
        """Test handling data without timestamp column."""
        # Create data without timestamp
        data_no_timestamp = self.sample_data.drop(columns=['timestamp'])
        
        # Should process without errors
        X_reduced, _ = self.preprocessor.preprocess(data_no_timestamp)
        
        # Verify output
        self.assertIsInstance(X_reduced, np.ndarray)
        self.assertEqual(X_reduced.shape[0], len(data_no_timestamp))
    
if __name__ == "__main__":
    unittest.main() 