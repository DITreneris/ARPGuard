import unittest
import numpy as np
import pandas as pd
from app.ml.pipeline import MLPipeline
from app.ml.data_collection import DataCollector
from app.ml.preprocessing import DataPreprocessor
from app.ml.models.ensemble import EnsembleModel
from app.ml.models.deep_learning import DeepLearningModel

class TestMLPipeline(unittest.TestCase):
    def setUp(self):
        """Set up test data and pipeline"""
        self.pipeline = MLPipeline()
        self.data_collector = DataCollector()
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

    def test_data_collection(self):
        """Test data collection component"""
        # Collect data
        collected_data = self.data_collector.collect_data(self.packets)
        
        # Verify collected data
        self.assertIsInstance(collected_data, list)
        self.assertEqual(len(collected_data), len(self.packets))
        for packet in collected_data:
            self.assertIn('src_ip', packet)
            self.assertIn('dst_ip', packet)
            self.assertIn('src_port', packet)
            self.assertIn('dst_port', packet)
            self.assertIn('protocol', packet)
            self.assertIn('length', packet)
            self.assertIn('timestamp', packet)

    def test_data_preprocessing(self):
        """Test data preprocessing component"""
        # Preprocess data
        processed_data = self.preprocessor.preprocess(self.packets)
        
        # Verify processed data
        self.assertIsInstance(processed_data, pd.DataFrame)
        self.assertEqual(len(processed_data), len(self.packets))
        self.assertTrue(all(col in processed_data.columns for col in [
            'src_ip_encoded', 'dst_ip_encoded', 'src_port', 'dst_port',
            'protocol_encoded', 'length', 'timestamp'
        ]))

    def test_pipeline_execution(self):
        """Test complete pipeline execution"""
        # Run pipeline
        results = self.pipeline.run(self.packets)
        
        # Verify results
        self.assertIsInstance(results, dict)
        self.assertIn('predictions', results)
        self.assertIn('probabilities', results)
        self.assertIn('metrics', results)
        
        # Verify predictions
        self.assertIsInstance(results['predictions'], np.ndarray)
        self.assertEqual(len(results['predictions']), len(self.packets))
        self.assertTrue(all(pred in [0, 1] for pred in results['predictions']))
        
        # Verify probabilities
        self.assertIsInstance(results['probabilities'], np.ndarray)
        self.assertEqual(len(results['probabilities']), len(self.packets))
        self.assertTrue(all(0 <= prob <= 1 for prob in results['probabilities']))
        
        # Verify metrics
        self.assertIsInstance(results['metrics'], dict)
        self.assertIn('accuracy', results['metrics'])
        self.assertIn('precision', results['metrics'])
        self.assertIn('recall', results['metrics'])
        self.assertIn('f1_score', results['metrics'])

    def test_pipeline_components(self):
        """Test individual pipeline components"""
        # Test data collection
        collected_data = self.pipeline.collect_data(self.packets)
        self.assertIsInstance(collected_data, list)
        
        # Test feature extraction
        features = self.pipeline.extract_features(collected_data)
        self.assertIsInstance(features, pd.DataFrame)
        
        # Test preprocessing
        processed_features = self.pipeline.preprocess_features(features)
        self.assertIsInstance(processed_features, np.ndarray)
        
        # Test model training
        labels = np.array([0, 1])  # Sample labels
        self.pipeline.train_models(processed_features, labels)
        self.assertTrue(self.pipeline.ensemble_model.is_trained)
        self.assertTrue(self.pipeline.deep_learning_model.is_trained)
        
        # Test prediction
        predictions = self.pipeline.predict(processed_features)
        self.assertIsInstance(predictions, np.ndarray)
        
        # Test evaluation
        metrics = self.pipeline.evaluate(processed_features, labels)
        self.assertIsInstance(metrics, dict)

    def test_pipeline_configuration(self):
        """Test pipeline configuration"""
        # Test configuration changes
        self.pipeline.configure(
            ensemble_models=['rf', 'gb', 'svm'],
            deep_learning_params={
                'input_size': 20,
                'hidden_size': 128,
                'epochs': 5,
                'batch_size': 16
            }
        )
        
        # Verify configuration
        self.assertEqual(len(self.pipeline.ensemble_model.models), 3)
        self.assertEqual(self.pipeline.deep_learning_model.model[0].in_features, 20)
        self.assertEqual(self.pipeline.deep_learning_model.model[0].out_features, 128)

    def test_pipeline_save_load(self):
        """Test pipeline model saving and loading"""
        # Train pipeline
        features = self.pipeline.extract_features(self.packets)
        processed_features = self.pipeline.preprocess_features(features)
        labels = np.array([0, 1])
        self.pipeline.train_models(processed_features, labels)
        
        # Save models
        self.pipeline.save_models('test_models')
        
        # Create new pipeline and load models
        new_pipeline = MLPipeline()
        new_pipeline.load_models('test_models')
        
        # Verify loaded models
        self.assertTrue(new_pipeline.ensemble_model.is_trained)
        self.assertTrue(new_pipeline.deep_learning_model.is_trained)
        
        # Make predictions with loaded models
        predictions = new_pipeline.predict(processed_features)
        self.assertIsInstance(predictions, np.ndarray)
        self.assertEqual(len(predictions), len(self.packets))

if __name__ == '__main__':
    unittest.main() 