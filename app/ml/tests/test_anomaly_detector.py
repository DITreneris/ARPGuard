import unittest
import numpy as np
import pandas as pd
import os
import tempfile
import shutil
from datetime import datetime, timedelta

from app.ml.models.anomaly_detector import AnomalyDetector
from app.ml.pipeline.model_trainer import ModelTrainer
from app.ml.utils.evaluation import ModelEvaluator

class TestAnomalyDetector(unittest.TestCase):
    """Tests for the Anomaly Detection System."""
    
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
        """Create synthetic data with anomalies for testing."""
        # Number of samples
        n_samples = 500
        n_features = 5
        
        # Generate features
        np.random.seed(42)
        
        # Create timestamps
        start_time = datetime.now() - timedelta(days=5)
        timestamps = [start_time + timedelta(minutes=15*i) for i in range(n_samples)]
        
        # Generate normal data with some correlations
        X = np.random.randn(n_samples, n_features)
        
        # Add correlations between features
        X[:, 1] = X[:, 0] * 0.7 + X[:, 1] * 0.3
        X[:, 3] = X[:, 2] * 0.5 + X[:, 3] * 0.5
        
        # Add some patterns
        hour_of_day = np.array([t.hour + t.minute/60 for t in timestamps])
        day_pattern = np.sin(hour_of_day * (2 * np.pi / 24))
        
        # Apply daily patterns to some features
        X[:, 0] += day_pattern * 0.5
        X[:, 2] += day_pattern * 0.3
        
        # Insert anomalies
        anomaly_indices = [50, 150, 250, 350, 450]
        for idx in anomaly_indices:
            # Make an obvious anomaly in a window of 5 samples
            X[idx:idx+5, 0] += 5.0  # Spike in first feature
            X[idx:idx+5, 2] -= 5.0  # Drop in third feature
            
        # Create anomaly labels
        y = np.zeros(n_samples, dtype=bool)
        for idx in anomaly_indices:
            y[idx:idx+5] = True
            
        # Create DataFrames
        self.X = pd.DataFrame(
            X,
            columns=[f'feature_{i}' for i in range(n_features)]
        )
        self.y = pd.Series(y, name='anomaly')
        self.timestamps = np.array(timestamps)
        
        # Split into train (normal data only) and test sets
        normal_indices = ~y
        self.X_train = self.X[normal_indices].copy()
        self.X_test = self.X.copy()
        self.y_test = self.y.copy()
        
    def test_basic_functionality(self):
        """Test basic functionality of anomaly detector."""
        # Initialize model
        model = AnomalyDetector(
            input_dim=self.X.shape[1],
            encoding_dims=[16, 8, 4],
            model_path=os.path.join(self.models_dir, "test_anomaly_model")
        )
        
        # Train model (using only normal data)
        feature_names = list(self.X.columns)
        
        # Use a small number of epochs for testing
        history = model.train(
            X_train=self.X_train.values,
            epochs=5,
            batch_size=32,
            verbose=0,
            feature_names=feature_names
        )
        
        # Check training results
        self.assertIn('loss', history)
        self.assertEqual(len(history['loss']), 5)
        
        # Check that threshold was set
        self.assertIsNotNone(model.threshold)
        
        # Test anomaly detection
        anomalies, scores = model.detect_anomalies(self.X_test.values)
        
        # Check results
        self.assertEqual(len(anomalies), len(self.X_test))
        self.assertEqual(len(scores), len(self.X_test))
        self.assertTrue(np.any(anomalies))  # Should detect at least some anomalies
        
        # Evaluate model
        metrics = model.evaluate(self.X_test.values, self.y_test.values)
        
        # Check evaluation metrics
        self.assertIn('reconstruction_mse', metrics)
        self.assertIn('precision', metrics)
        self.assertIn('recall', metrics)
        self.assertIn('f1', metrics)
        
    def test_save_and_load(self):
        """Test saving and loading the model."""
        # Initialize model
        model = AnomalyDetector(
            input_dim=self.X.shape[1],
            encoding_dims=[16, 8, 4],
            model_path=os.path.join(self.models_dir, "test_save_load_model")
        )
        
        # Train model
        feature_names = list(self.X.columns)
        model.train(
            X_train=self.X_train.values,
            epochs=2,  # Small value for testing
            batch_size=32,
            verbose=0,
            feature_names=feature_names
        )
        
        # Get predictions before saving
        orig_anomalies, orig_scores = model.detect_anomalies(self.X_test.values[:10])
        
        # Save model
        model_path = os.path.join(self.models_dir, "test_save_load_model")
        model.save(model_path)
        
        # Check that files were created
        self.assertTrue(os.path.exists(f"{model_path}_keras"))
        self.assertTrue(os.path.exists(f"{model_path}_params.pkl"))
        
        # Create a new model and load
        new_model = AnomalyDetector(
            input_dim=self.X.shape[1],
            model_path=model_path
        )
        new_model.load(model_path)
        
        # Check if parameters were loaded correctly
        self.assertEqual(new_model.input_dim, self.X.shape[1])
        self.assertEqual(new_model.encoding_dims, [16, 8, 4])
        self.assertEqual(new_model.feature_names, feature_names)
        self.assertIsNotNone(new_model.threshold)
        
        # Make predictions with loaded model
        new_anomalies, new_scores = new_model.detect_anomalies(self.X_test.values[:10])
        
        # Check predictions
        np.testing.assert_array_equal(new_anomalies, orig_anomalies)
        np.testing.assert_allclose(new_scores, orig_scores)
        
    def test_anomaly_explanation(self):
        """Test explaining which features contributed to anomalies."""
        # Initialize model
        model = AnomalyDetector(
            input_dim=self.X.shape[1],
            encoding_dims=[16, 8],
            model_path=os.path.join(self.models_dir, "test_explain_model")
        )
        
        # Train model
        feature_names = list(self.X.columns)
        model.train(
            X_train=self.X_train.values,
            epochs=2,  # Small value for testing
            batch_size=32,
            verbose=0,
            feature_names=feature_names
        )
        
        # Get explanations for anomalies
        explanation = model.explain_anomalies(self.X_test.values)
        
        # Check explanation
        self.assertIn('anomaly_indices', explanation)
        self.assertIn('feature_contributions', explanation)
        
        # Should have detected at least some anomalies
        self.assertTrue(len(explanation['anomaly_indices']) > 0)
        
        # Feature contributions should sum to 1 for each anomaly
        if len(explanation['feature_contributions']) > 0:
            sums = np.sum(explanation['feature_contributions'], axis=1)
            np.testing.assert_allclose(sums, np.ones_like(sums), rtol=1e-5)
            
    def test_plot_anomalies(self):
        """Test plotting anomaly detection results."""
        # Initialize model
        model = AnomalyDetector(
            input_dim=self.X.shape[1],
            encoding_dims=[8, 4],
            model_path=os.path.join(self.models_dir, "test_plot_model")
        )
        
        # Train model
        feature_names = list(self.X.columns)
        model.train(
            X_train=self.X_train.values,
            epochs=2,  # Small value for testing
            batch_size=32,
            verbose=0,
            feature_names=feature_names
        )
        
        # Plot anomalies
        plot_path = os.path.join(self.output_dir, "anomaly_plot.png")
        fig = model.plot_anomalies(
            X=self.X_test.values[:100],  # Use a subset for faster testing
            timestamps=self.timestamps[:100],
            title="Test Anomaly Plot",
            save_path=plot_path
        )
        
        # Check that plot was created
        self.assertTrue(os.path.exists(plot_path))
        
        # Check figure properties
        self.assertEqual(len(fig.axes), 2)  # Should have 2 subplots
        
    def test_with_model_trainer(self):
        """Test integration with ModelTrainer."""
        # Initialize model
        model = AnomalyDetector(
            input_dim=self.X.shape[1],
            encoding_dims=[16, 8],
            model_path=os.path.join(self.models_dir, "test_trainer_model")
        )
        
        # Need to implement a simple adapter since ModelTrainer expects y_train to be required
        # and AnomalyDetector doesn't use it for training (but for API compatibility)
        class AnomalyDetectorAdapter:
            def __init__(self, detector):
                self.detector = detector
                
            def train(self, X_train, y_train, **kwargs):
                return self.detector.train(X_train=X_train, **kwargs)
                
            def evaluate(self, X_test, y_test):
                return self.detector.evaluate(X_test, y_test)
                
            def save(self, path=None):
                return self.detector.save(path)
                
        # Wrap model in adapter
        adapter = AnomalyDetectorAdapter(model)
        
        # Initialize trainer
        trainer = ModelTrainer(
            model=adapter,
            output_dir=self.output_dir,
            test_size=0.2,
            val_size=0.2
        )
        
        # Train and evaluate
        history, metrics = trainer.train_and_evaluate(
            X=self.X.values,
            y=self.y.values,
            train_kwargs={
                'epochs': 2,
                'batch_size': 32,
                'verbose': 0,
                'feature_names': list(self.X.columns)
            }
        )
        
        # Check that metrics were calculated
        self.assertIn('reconstruction_mse', metrics)
        self.assertIn('precision', metrics)
        self.assertIn('recall', metrics)
        self.assertIn('f1', metrics)
        
        # Check that metrics were saved
        files = os.listdir(self.output_dir)
        self.assertTrue(any(f.startswith('eval_metrics_') for f in files))

if __name__ == '__main__':
    unittest.main() 