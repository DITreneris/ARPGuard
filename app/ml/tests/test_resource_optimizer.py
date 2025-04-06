import unittest
import numpy as np
import pandas as pd
import os
import tempfile
import shutil
from datetime import datetime, timedelta

from app.ml.models.resource_optimizer import ResourceUsageOptimizer
from app.ml.pipeline.model_trainer import ModelTrainer
from app.ml.utils.evaluation import ModelEvaluator

class TestResourceOptimizer(unittest.TestCase):
    """Tests for the Resource Usage Optimizer model."""
    
    def setUp(self):
        """Set up test environment."""
        # Create temporary directory for test outputs
        self.test_dir = tempfile.mkdtemp()
        self.models_dir = os.path.join(self.test_dir, "models")
        self.output_dir = os.path.join(self.test_dir, "output")
        
        os.makedirs(self.models_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Create sample data for testing
        self.create_sample_data()
        
    def tearDown(self):
        """Clean up after tests."""
        # Remove temporary test directory
        shutil.rmtree(self.test_dir)
        
    def create_sample_data(self):
        """Create synthetic data for testing."""
        # Number of samples
        n_samples = 500
        
        # Generate features
        np.random.seed(42)
        
        # Create input features that might affect resource allocation
        cpu_load = np.random.uniform(10, 90, n_samples)
        memory_usage = np.random.uniform(20, 80, n_samples)
        request_rate = np.random.uniform(100, 1000, n_samples)
        active_connections = np.random.uniform(10, 200, n_samples)
        bandwidth_usage = np.random.uniform(100, 500, n_samples)
        
        # Create target variables (resource allocations)
        # CPU allocation is influenced by CPU load and request rate
        cpu_allocation = 0.2 + 0.3 * (cpu_load / 100) + 0.2 * (request_rate / 1000) + np.random.normal(0, 0.05, n_samples)
        
        # Memory allocation is influenced by memory usage and active connections
        memory_allocation = 0.3 + 0.4 * (memory_usage / 100) + 0.1 * (active_connections / 200) + np.random.normal(0, 0.05, n_samples)
        
        # Bandwidth allocation is influenced by bandwidth usage and request rate
        bandwidth_allocation = 0.2 + 0.5 * (bandwidth_usage / 500) + 0.2 * (request_rate / 1000) + np.random.normal(0, 0.05, n_samples)
        
        # Clip allocations to valid range [0, 1]
        cpu_allocation = np.clip(cpu_allocation, 0, 1)
        memory_allocation = np.clip(memory_allocation, 0, 1)
        bandwidth_allocation = np.clip(bandwidth_allocation, 0, 1)
        
        # Create DataFrames
        self.X = pd.DataFrame({
            'cpu_load': cpu_load,
            'memory_usage': memory_usage,
            'request_rate': request_rate,
            'active_connections': active_connections,
            'bandwidth_usage': bandwidth_usage
        })
        
        self.y = pd.DataFrame({
            'cpu_allocation': cpu_allocation,
            'memory_allocation': memory_allocation,
            'bandwidth_allocation': bandwidth_allocation
        })
        
    def test_rf_model(self):
        """Test Random Forest model training and prediction."""
        # Initialize model
        model = ResourceUsageOptimizer(
            mode='rf',
            n_estimators=50,
            max_depth=10,
            multi_output=True,
            model_path=os.path.join(self.models_dir, "test_rf_model")
        )
        
        # Train model
        feature_names = list(self.X.columns)
        target_names = list(self.y.columns)
        
        training_results = model.train(
            X_train=self.X.values,
            y_train=self.y.values,
            feature_names=feature_names,
            target_names=target_names
        )
        
        # Check training results
        self.assertTrue(training_results['rf_training_complete'])
        self.assertIsNotNone(model.rf_model)
        
        # Make predictions
        predictions = model.predict(self.X.values)
        
        # Check predictions
        self.assertEqual(predictions.shape, self.y.values.shape)
        
        # Evaluate model
        metrics = model.evaluate(self.X.values, self.y.values)
        
        # Check evaluation metrics
        self.assertIn('rmse', metrics)
        self.assertIn('r2', metrics)
        
        # Check feature importance
        importance = model.get_feature_importance()
        self.assertIn('rf', importance)
        self.assertEqual(len(importance['rf']), len(feature_names))
        
    def test_gb_model(self):
        """Test Gradient Boosting model training and prediction."""
        # Initialize model
        model = ResourceUsageOptimizer(
            mode='gb',
            n_estimators=50,
            max_depth=5,
            multi_output=True,
            model_path=os.path.join(self.models_dir, "test_gb_model")
        )
        
        # Train model
        feature_names = list(self.X.columns)
        target_names = list(self.y.columns)
        
        training_results = model.train(
            X_train=self.X.values,
            y_train=self.y.values,
            feature_names=feature_names,
            target_names=target_names
        )
        
        # Check training results
        self.assertTrue(training_results['gb_training_complete'])
        self.assertIsNotNone(model.gb_model)
        
        # Make predictions
        predictions = model.predict(self.X.values)
        
        # Check predictions
        self.assertEqual(predictions.shape, self.y.values.shape)
        
        # Evaluate model
        metrics = model.evaluate(self.X.values, self.y.values)
        
        # Check evaluation metrics
        self.assertIn('rmse', metrics)
        self.assertIn('r2', metrics)
        
    def test_ensemble_model(self):
        """Test ensemble model (RF + GB) training and prediction."""
        # Initialize model
        model = ResourceUsageOptimizer(
            mode='ensemble',
            n_estimators=50,
            multi_output=True,
            model_path=os.path.join(self.models_dir, "test_ensemble_model")
        )
        
        # Train model
        feature_names = list(self.X.columns)
        target_names = list(self.y.columns)
        
        training_results = model.train(
            X_train=self.X.values,
            y_train=self.y.values,
            feature_names=feature_names,
            target_names=target_names
        )
        
        # Check training results
        self.assertTrue(training_results['rf_training_complete'])
        self.assertTrue(training_results['gb_training_complete'])
        self.assertIsNotNone(model.rf_model)
        self.assertIsNotNone(model.gb_model)
        
        # Make predictions
        predictions = model.predict(self.X.values)
        
        # Check predictions
        self.assertEqual(predictions.shape, self.y.values.shape)
        
        # Test model saving and loading
        model.save()
        
        # Create a new model and load the saved model
        new_model = ResourceUsageOptimizer(
            model_path=os.path.join(self.models_dir, "test_ensemble_model")
        )
        
        # This should raise an error since the model file doesn't exist yet
        with self.assertRaises(FileNotFoundError):
            new_model.load()
            
        # Save model to the correct path
        model_path = os.path.join(self.models_dir, "test_ensemble_model")
        model.save(model_path)
        
        # Now loading should work
        new_model.load(model_path)
        
        # Check if parameters were loaded correctly
        self.assertEqual(new_model.mode, 'ensemble')
        self.assertEqual(new_model.n_estimators, 50)
        self.assertEqual(new_model.feature_names, feature_names)
        self.assertEqual(new_model.target_names, target_names)
        
        # Make predictions with loaded model
        new_predictions = new_model.predict(self.X.values)
        
        # Check predictions
        self.assertEqual(new_predictions.shape, self.y.values.shape)
        np.testing.assert_allclose(new_predictions, predictions)
        
    def test_resource_optimization(self):
        """Test resource optimization functionality."""
        # Initialize model
        model = ResourceUsageOptimizer(
            mode='rf',
            n_estimators=50,
            multi_output=True,
            model_path=os.path.join(self.models_dir, "test_optimizer_model")
        )
        
        # Train model
        feature_names = list(self.X.columns)
        target_names = list(self.y.columns)
        
        model.train(
            X_train=self.X.values,
            y_train=self.y.values,
            feature_names=feature_names,
            target_names=target_names
        )
        
        # Define constraints
        constraints = {
            'cpu_allocation': {'min': 0.2, 'max': 0.8},
            'memory_allocation': {'min': 0.3, 'max': 0.9},
            'bandwidth_allocation': {'min': 0.1, 'max': 0.7}
        }
        
        # Generate test data
        test_data = self.X.values[:5]
        
        # Make predictions
        raw_predictions = model.predict(test_data)
        
        # Optimize resources
        optimized, details = model.optimize_resources(test_data, constraints)
        
        # Check optimization results
        self.assertEqual(optimized.shape, raw_predictions.shape)
        
        # Check that constraints were applied
        for i, target in enumerate(target_names):
            if target in constraints:
                constraint = constraints[target]
                min_val = constraint.get('min', float('-inf'))
                max_val = constraint.get('max', float('inf'))
                
                # All optimized values should be within constraints
                self.assertTrue(np.all(optimized[:, i] >= min_val))
                self.assertTrue(np.all(optimized[:, i] <= max_val))
                
                # Check that adjustments were calculated correctly
                np.testing.assert_allclose(
                    details['adjustments'], 
                    details['optimized_allocations'] - details['original_predictions']
                )
        
    def test_with_model_trainer(self):
        """Test integration with ModelTrainer."""
        # Initialize model
        model = ResourceUsageOptimizer(
            mode='rf',
            n_estimators=50,
            multi_output=True,
            model_path=os.path.join(self.models_dir, "test_trainer_model")
        )
        
        # Initialize trainer
        trainer = ModelTrainer(
            model=model,
            output_dir=self.output_dir,
            test_size=0.2,
            val_size=0.2
        )
        
        # Train and evaluate
        history, metrics = trainer.train_and_evaluate(
            X=self.X.values,
            y=self.y.values
        )
        
        # Check metrics
        self.assertIn('rmse', metrics)
        self.assertIn('r2', metrics)
        
        # Check that metrics were saved
        files = os.listdir(self.output_dir)
        self.assertTrue(any(f.startswith('eval_metrics_') for f in files))

if __name__ == '__main__':
    unittest.main() 