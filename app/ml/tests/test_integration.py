import unittest
import numpy as np
import pandas as pd
import os
import shutil
import tempfile
from datetime import datetime, timedelta

from app.ml.features.performance_metrics import PerformanceMetrics
from app.ml.features.preprocessor import PerformancePreprocessor
from app.ml.models.lstm_traffic_predictor import LSTMTrafficPredictor
from app.ml.pipeline.model_trainer import ModelTrainer
from app.ml.utils.evaluation import ModelEvaluator

class TestMLPipeline(unittest.TestCase):
    """Integration tests for the ML pipeline."""
    
    def setUp(self):
        """Set up test environment."""
        # Create temporary directories for test outputs
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
        # Create timestamps for a week of data with 5-minute intervals
        n_samples = 2016  # 7 days * 24 hours * 12 samples per hour
        start_time = datetime.now() - timedelta(days=7)
        timestamps = [start_time + timedelta(minutes=5*i) for i in range(n_samples)]
        
        # Generate synthetic metrics
        np.random.seed(42)
        
        # Daily and weekly patterns with some noise
        hours = np.array([(t.hour + t.minute/60) for t in timestamps])
        days = np.array([t.weekday() for t in timestamps])
        
        # Create patterns
        daily_pattern = np.sin(hours * (2 * np.pi / 24)) * 0.5 + 0.5
        weekly_pattern = 0.2 * np.sin(days * (2 * np.pi / 7))
        
        # Generate metrics with patterns and noise
        cpu_usage = 30 + 30 * daily_pattern + 10 * weekly_pattern + np.random.normal(0, 5, n_samples)
        memory_usage = 40 + 20 * daily_pattern + 5 * weekly_pattern + np.random.normal(0, 3, n_samples)
        network_traffic = 1000 + 800 * daily_pattern + 200 * weekly_pattern + np.random.normal(0, 100, n_samples)
        packet_rate = 500 + 400 * daily_pattern + 100 * weekly_pattern + np.random.normal(0, 50, n_samples)
        response_time = 20 + 10 * (1 - daily_pattern) + 5 * weekly_pattern + np.random.normal(0, 2, n_samples)
        
        # Clip values to reasonable ranges
        cpu_usage = np.clip(cpu_usage, 0, 100)
        memory_usage = np.clip(memory_usage, 0, 100)
        network_traffic = np.clip(network_traffic, 0, 3000)
        packet_rate = np.clip(packet_rate, 0, 1500)
        response_time = np.clip(response_time, 0, 100)
        
        # Create DataFrame
        self.data = pd.DataFrame({
            'timestamp': timestamps,
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'network_traffic': network_traffic,
            'packet_processing_rate': packet_rate,
            'response_time': response_time
        })
    
    def test_full_pipeline(self):
        """Test the complete ML pipeline from data to evaluation."""
        # 1. Initialize components
        preprocessor = PerformancePreprocessor()
        
        # 2. Preprocess data
        # Convert timestamps to datetime objects if they're strings
        if isinstance(self.data['timestamp'].iloc[0], str):
            self.data['timestamp'] = pd.to_datetime(self.data['timestamp'])
            
        # Process features
        features = self.data.drop(columns=['timestamp', 'network_traffic'])
        target = self.data['network_traffic']
        
        # Apply preprocessing
        X, y = preprocessor.preprocess(self.data.drop(columns=['network_traffic']), 
                                      target_column='network_traffic')
        
        # 3. Initialize model
        lstm_model = LSTMTrafficPredictor(
            input_dim=X.shape[1],
            sequence_length=24,  # 2 hours of 5-minute data
            lstm_units=[64, 32],
            model_path=os.path.join(self.models_dir, "test_lstm_model")
        )
        
        # 4. Create training pipeline
        trainer = ModelTrainer(
            model=lstm_model,
            output_dir=self.output_dir,
            test_size=0.2,
            val_size=0.2
        )
        
        # 5. Prepare sequences for LSTM
        n_seq = 24  # sequence length used in model
        X_seq, y_seq = [], []
        
        for i in range(len(X) - n_seq):
            X_seq.append(X[i:i+n_seq])
            y_seq.append(y[i+n_seq])
            
        X_seq = np.array(X_seq)
        y_seq = np.array(y_seq)
        
        # 6. Train and evaluate (with reduced epochs for testing)
        history, metrics = trainer.train_and_evaluate(
            X_seq, y_seq,
            train_kwargs={
                'epochs': 2,
                'batch_size': 32,
                'verbose': 0
            }
        )
        
        # 7. Verify outputs
        # Check if model file was created
        self.assertTrue(os.path.exists(os.path.join(self.models_dir, "test_lstm_model")))
        
        # Check if metrics were calculated
        self.assertIn('mae', metrics)
        self.assertIn('loss', metrics)
        
        # Check if training happened
        self.assertIsNotNone(history)
        self.assertIn('loss', history)
        
        # 8. Create evaluation report
        evaluator = ModelEvaluator(output_dir=os.path.join(self.output_dir, "evaluation"))
        
        # Get predictions for the test set
        X_train, X_val, X_test, y_train, y_val, y_test = trainer._prepare_data(X_seq, y_seq)
        y_pred = lstm_model.predict(X_test).flatten()
        
        # Generate report
        report_dir = evaluator.generate_evaluation_report(
            model_name="LSTM_Traffic_Predictor",
            metrics=metrics,
            y_true=y_test,
            y_pred=y_pred,
            timestamps=None,  # We don't have direct timestamps for the sequences
            is_classification=False
        )
        
        # Verify report was created
        self.assertTrue(os.path.exists(report_dir))
        self.assertTrue(os.path.exists(os.path.join(report_dir, "metrics.json")))
        self.assertTrue(os.path.exists(os.path.join(report_dir, "prediction_vs_actual.png")))
    
    def test_metrics_collection_to_model_input(self):
        """Test the flow from metrics collection to model input preparation."""
        # 1. Initialize metrics collector
        metrics_collector = PerformanceMetrics(window_size=100)
        
        # 2. Add some mock metrics (using our sample data)
        for i in range(50):  # Add 50 data points
            metrics_collector.metrics['timestamp'].append(self.data['timestamp'].iloc[i])
            metrics_collector.metrics['cpu_usage'].append(self.data['cpu_usage'].iloc[i])
            metrics_collector.metrics['memory_usage'].append(self.data['memory_usage'].iloc[i])
            metrics_collector.metrics['network_traffic'].append(self.data['network_traffic'].iloc[i])
            metrics_collector.metrics['packet_processing_rate'].append(self.data['packet_processing_rate'].iloc[i])
            metrics_collector.metrics['response_time'].append(self.data['response_time'].iloc[i])
        
        # 3. Convert to DataFrame
        df = metrics_collector.get_metrics_dataframe()
        
        # 4. Verify DataFrame structure
        self.assertEqual(len(df), 50)
        self.assertIn('cpu_usage', df.columns)
        self.assertIn('network_traffic', df.columns)
        
        # 5. Initialize preprocessor
        preprocessor = PerformancePreprocessor()
        
        # 6. Process features for the model
        X, y = preprocessor.preprocess(
            df.drop(columns=['network_traffic']), 
            target_column='network_traffic'
        )
        
        # 7. Verify preprocessed data
        self.assertEqual(len(X), 50)  # Same number of samples
        
        # 8. Prepare sequences for LSTM (if we had enough data)
        if len(X) >= 24:  # Need at least sequence_length samples
            n_seq = 24
            X_seq, y_seq = [], []
            
            for i in range(len(X) - n_seq):
                X_seq.append(X[i:i+n_seq])
                y_seq.append(y[i+n_seq])
                
            X_seq = np.array(X_seq)
            y_seq = np.array(y_seq)
            
            # Verify sequences
            self.assertEqual(len(X_seq), len(X) - n_seq)
            self.assertEqual(X_seq.shape[1], n_seq)
            
            # Check that this can be used as input to the model
            lstm_model = LSTMTrafficPredictor(
                input_dim=X.shape[1],
                sequence_length=n_seq,
                lstm_units=[64, 32],
                model_path=os.path.join(self.models_dir, "test_lstm_model2")
            )
            
            # Build model
            lstm_model.build_model()
            
            # Make sure the model accepts our preprocessed data
            if len(X_seq) > 0:
                # Take a small batch for testing
                test_batch = X_seq[:min(5, len(X_seq))]
                
                # This should not raise any errors if data is compatible
                lstm_model.model.predict(test_batch)
                
                # Basic shape check
                self.assertEqual(lstm_model.model.input_shape[1:], (n_seq, X.shape[1]))
        
        # If we didn't have enough data for the above tests, at least verify
        # that the preprocessing steps worked correctly
        self.assertIsInstance(X, np.ndarray)
        self.assertIsInstance(y, np.ndarray)

if __name__ == '__main__':
    unittest.main() 