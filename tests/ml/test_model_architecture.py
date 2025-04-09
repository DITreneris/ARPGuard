import unittest
import numpy as np
import pandas as pd
from app.ml.models.ensemble import EnsembleModel
from app.ml.models.deep_learning import DeepLearningModel
from app.ml.feature_engineering import FeatureExtractor
from app.ml.preprocessing import DataPreprocessor

class TestModelArchitecture(unittest.TestCase):
    def setUp(self):
        """Set up test data and models"""
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
        
        # Extract and preprocess features
        self.features = self.extractor.extract_features(self.packets)
        self.processed_features = self.preprocessor.preprocess(self.features)
        
        # Create sample labels
        self.labels = np.array([0, 1])  # Binary classification
        
        # Initialize models
        self.ensemble_model = EnsembleModel()
        self.deep_learning_model = DeepLearningModel()

    def test_ensemble_model_initialization(self):
        """Test ensemble model initialization"""
        self.assertIsNotNone(self.ensemble_model.models)
        self.assertIsNotNone(self.ensemble_model.weights)
        self.assertEqual(len(self.ensemble_model.models), 3)  # Should have 3 base models

    def test_ensemble_model_training(self):
        """Test ensemble model training"""
        # Train the model
        self.ensemble_model.train(self.processed_features, self.labels)
        
        # Verify model weights
        self.assertTrue(all(0 <= w <= 1 for w in self.ensemble_model.weights))
        self.assertAlmostEqual(sum(self.ensemble_model.weights), 1.0)
        
        # Verify base models are trained
        for model in self.ensemble_model.models:
            self.assertTrue(hasattr(model, 'predict'))

    def test_ensemble_model_prediction(self):
        """Test ensemble model prediction"""
        # Train the model
        self.ensemble_model.train(self.processed_features, self.labels)
        
        # Make predictions
        predictions = self.ensemble_model.predict(self.processed_features)
        
        # Verify predictions
        self.assertIsInstance(predictions, np.ndarray)
        self.assertEqual(predictions.shape, self.labels.shape)
        self.assertTrue(all(pred in [0, 1] for pred in predictions))

    def test_deep_learning_model_initialization(self):
        """Test deep learning model initialization"""
        self.assertIsNotNone(self.deep_learning_model.model)
        self.assertIsNotNone(self.deep_learning_model.optimizer)
        self.assertIsNotNone(self.deep_learning_model.loss_function)

    def test_deep_learning_model_training(self):
        """Test deep learning model training"""
        # Train the model
        history = self.deep_learning_model.train(
            self.processed_features,
            self.labels,
            epochs=2,
            batch_size=1
        )
        
        # Verify training history
        self.assertIsInstance(history, dict)
        self.assertIn('loss', history)
        self.assertIn('accuracy', history)
        self.assertTrue(all(isinstance(v, list) for v in history.values()))

    def test_deep_learning_model_prediction(self):
        """Test deep learning model prediction"""
        # Train the model
        self.deep_learning_model.train(
            self.processed_features,
            self.labels,
            epochs=2,
            batch_size=1
        )
        
        # Make predictions
        predictions = self.deep_learning_model.predict(self.processed_features)
        
        # Verify predictions
        self.assertIsInstance(predictions, np.ndarray)
        self.assertEqual(predictions.shape, self.labels.shape)
        self.assertTrue(all(0 <= pred <= 1 for pred in predictions))

    def test_model_ensemble_combination(self):
        """Test combining ensemble and deep learning models"""
        # Train both models
        self.ensemble_model.train(self.processed_features, self.labels)
        self.deep_learning_model.train(
            self.processed_features,
            self.labels,
            epochs=2,
            batch_size=1
        )
        
        # Get predictions from both models
        ensemble_preds = self.ensemble_model.predict(self.processed_features)
        dl_preds = self.deep_learning_model.predict(self.processed_features)
        
        # Combine predictions
        combined_preds = (ensemble_preds + dl_preds) / 2
        
        # Verify combined predictions
        self.assertIsInstance(combined_preds, np.ndarray)
        self.assertEqual(combined_preds.shape, self.labels.shape)
        self.assertTrue(all(0 <= pred <= 1 for pred in combined_preds))

    def test_model_performance_metrics(self):
        """Test model performance metrics"""
        # Train both models
        self.ensemble_model.train(self.processed_features, self.labels)
        self.deep_learning_model.train(
            self.processed_features,
            self.labels,
            epochs=2,
            batch_size=1
        )
        
        # Get performance metrics
        ensemble_metrics = self.ensemble_model.evaluate(self.processed_features, self.labels)
        dl_metrics = self.deep_learning_model.evaluate(self.processed_features, self.labels)
        
        # Verify metrics
        for metrics in [ensemble_metrics, dl_metrics]:
            self.assertIsInstance(metrics, dict)
            self.assertIn('accuracy', metrics)
            self.assertIn('precision', metrics)
            self.assertIn('recall', metrics)
            self.assertIn('f1_score', metrics)
            self.assertTrue(all(0 <= v <= 1 for v in metrics.values()))

if __name__ == '__main__':
    unittest.main() 