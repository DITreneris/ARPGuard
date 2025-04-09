import unittest
import numpy as np
import pandas as pd
from app.ml.feature_validation import FeatureValidator
from app.ml.feature_engineering import FeatureExtractor
from app.ml.preprocessing import DataPreprocessor

class TestFeatureValidation(unittest.TestCase):
    def setUp(self):
        """Set up test data and validator"""
        self.validator = FeatureValidator()
        self.extractor = FeatureExtractor()
        self.preprocessor = DataPreprocessor()
        
        # Create sample packet data
        self.packets = [
            {
                'src_ip': '192.168.1.1',
                'dst_ip': '192.168.1.2',
                'src_port': 5000,
                'dst_port': 80,
                'protocol': 'TCP',
                'length': 100,
                'timestamp': 1610000000.0
            },
            {
                'src_ip': '192.168.1.2',
                'dst_ip': '192.168.1.1',
                'src_port': 80,
                'dst_port': 5000,
                'protocol': 'TCP',
                'length': 200,
                'timestamp': 1610000001.0
            }
        ]
        
        # Extract features
        self.features = self.extractor.extract_features(self.packets)
        
        # Preprocess features
        self.processed_features = self.preprocessor.preprocess(self.features)
        
        # Add some missing values and outliers for testing
        self.processed_features_with_issues = self.processed_features.copy()
        self.processed_features_with_issues.iloc[0, 0] = np.nan  # Add missing value
        self.processed_features_with_issues.iloc[1, 1] = 1000   # Add outlier

    def test_data_quality_checks(self):
        """Test data quality validation"""
        # Test with clean data
        quality_report = self.validator.validate_data_quality(self.processed_features)
        self.assertTrue(quality_report['is_valid'])
        self.assertEqual(quality_report['missing_values'], 0)
        self.assertEqual(quality_report['outliers'], 0)
        
        # Test with data containing issues
        quality_report = self.validator.validate_data_quality(self.processed_features_with_issues)
        self.assertFalse(quality_report['is_valid'])
        self.assertEqual(quality_report['missing_values'], 1)
        self.assertEqual(quality_report['outliers'], 1)

    def test_feature_importance_analysis(self):
        """Test feature importance analysis"""
        # Create sample labels
        labels = np.array([0, 1])  # Binary classification
        
        # Test feature importance calculation
        importance_scores = self.validator.analyze_feature_importance(
            self.processed_features,
            labels
        )
        
        # Verify results
        self.assertIsInstance(importance_scores, dict)
        self.assertTrue(all(0 <= score <= 1 for score in importance_scores.values()))
        self.assertTrue(all(isinstance(feature, str) for feature in importance_scores.keys()))

    def test_feature_correlation_analysis(self):
        """Test feature correlation analysis"""
        # Test correlation analysis
        correlation_matrix = self.validator.analyze_feature_correlation(self.processed_features)
        
        # Verify results
        self.assertIsInstance(correlation_matrix, pd.DataFrame)
        self.assertEqual(correlation_matrix.shape[0], len(self.processed_features.columns))
        self.assertEqual(correlation_matrix.shape[1], len(self.processed_features.columns))
        self.assertTrue(all(-1 <= val <= 1 for val in correlation_matrix.values.flatten()))

    def test_feature_distribution_analysis(self):
        """Test feature distribution analysis"""
        # Test distribution analysis
        distribution_report = self.validator.analyze_feature_distributions(self.processed_features)
        
        # Verify results
        self.assertIsInstance(distribution_report, dict)
        for feature, stats in distribution_report.items():
            self.assertIn('mean', stats)
            self.assertIn('std', stats)
            self.assertIn('skew', stats)
            self.assertIn('kurtosis', stats)

    def test_feature_selection(self):
        """Test feature selection based on validation results"""
        # Create validation report
        validation_report = {
            'data_quality': self.validator.validate_data_quality(self.processed_features),
            'importance': self.validator.analyze_feature_importance(
                self.processed_features,
                np.array([0, 1])
            ),
            'correlation': self.validator.analyze_feature_correlation(self.processed_features)
        }
        
        # Test feature selection
        selected_features = self.validator.select_features(
            self.processed_features,
            validation_report
        )
        
        # Verify results
        self.assertIsInstance(selected_features, list)
        self.assertTrue(all(feature in self.processed_features.columns for feature in selected_features))
        self.assertTrue(len(selected_features) <= len(self.processed_features.columns))

if __name__ == '__main__':
    unittest.main() 