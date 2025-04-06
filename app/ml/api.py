import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Union, Any
import os
import logging
from datetime import datetime
import matplotlib.pyplot as plt

from app.ml.models.lstm_traffic_predictor import LSTMTrafficPredictor
from app.ml.models.resource_optimizer import ResourceUsageOptimizer
from app.ml.models.anomaly_detector import AnomalyDetector
from app.ml.features.performance_metrics import PerformanceMetrics
from app.ml.features.preprocessor import PerformancePreprocessor
from app.ml.pipeline.model_trainer import ModelTrainer
from app.ml.utils.evaluation import ModelEvaluator

class ARPGuardML:
    """
    Unified API for ARPGuard Machine Learning capabilities.
    Provides simplified access to all ML models and utilities.
    """
    
    def __init__(
        self,
        base_dir: str = "app/ml/models",
        output_dir: str = "app/ml/output",
        metrics_window_size: int = 100
    ):
        """
        Initialize the ARPGuard ML API.
        
        Args:
            base_dir: Base directory for model storage
            output_dir: Directory for outputs (reports, plots)
            metrics_window_size: Size of the performance metrics window
        """
        self.base_dir = base_dir
        self.output_dir = output_dir
        
        # Create directories if they don't exist
        os.makedirs(base_dir, exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize metrics collector
        self.metrics_collector = PerformanceMetrics(window_size=metrics_window_size)
        
        # Initialize preprocessor
        self.preprocessor = PerformancePreprocessor()
        
        # Initialize evaluator
        self.evaluator = ModelEvaluator(output_dir=os.path.join(output_dir, "evaluation"))
        
        # Initialize models (but don't build them yet)
        self.traffic_predictor = None
        self.resource_optimizer = None
        self.anomaly_detector = None
        
        # Initialize logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(output_dir, "arpguard_ml.log")),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("ARPGuard ML API initialized")
        
    def collect_metrics(self, duration_seconds: int = 0) -> pd.DataFrame:
        """
        Collect performance metrics for a specified duration.
        
        Args:
            duration_seconds: How long to collect metrics (0 = collect once)
            
        Returns:
            DataFrame of collected metrics
        """
        import time
        
        self.logger.info(f"Collecting metrics for {duration_seconds} seconds")
        
        if duration_seconds <= 0:
            # Collect metrics once
            self.metrics_collector.collect_metrics()
        else:
            # Collect metrics for the specified duration
            end_time = time.time() + duration_seconds
            while time.time() < end_time:
                self.metrics_collector.collect_metrics()
                time.sleep(1)  # Collect roughly every second
                
        # Get metrics as DataFrame
        metrics_df = self.metrics_collector.get_metrics_dataframe()
        self.logger.info(f"Collected {len(metrics_df)} metrics samples")
        
        return metrics_df
    
    def initialize_traffic_predictor(
        self,
        input_dim: int = 5,
        sequence_length: int = 24,
        lstm_units: List[int] = [64, 32],
        dropout_rate: float = 0.2,
        learning_rate: float = 0.001
    ) -> LSTMTrafficPredictor:
        """
        Initialize the LSTM Traffic Predictor model.
        
        Args:
            input_dim: Number of input features
            sequence_length: Length of input sequences (time steps)
            lstm_units: List of units for each LSTM layer
            dropout_rate: Dropout rate for regularization
            learning_rate: Learning rate for optimization
            
        Returns:
            Initialized LSTMTrafficPredictor
        """
        model_path = os.path.join(self.base_dir, "lstm_traffic_model")
        
        self.traffic_predictor = LSTMTrafficPredictor(
            input_dim=input_dim,
            sequence_length=sequence_length,
            lstm_units=lstm_units,
            dropout_rate=dropout_rate,
            learning_rate=learning_rate,
            model_path=model_path
        )
        
        self.logger.info(f"Initialized LSTM Traffic Predictor with {len(lstm_units)} layers")
        return self.traffic_predictor
    
    def initialize_resource_optimizer(
        self,
        mode: str = 'ensemble',
        n_estimators: int = 100,
        max_depth: Optional[int] = None,
        multi_output: bool = True
    ) -> ResourceUsageOptimizer:
        """
        Initialize the Resource Usage Optimizer model.
        
        Args:
            mode: Model type ('rf', 'gb', or 'ensemble')
            n_estimators: Number of trees
            max_depth: Maximum tree depth
            multi_output: Whether to support multiple target variables
            
        Returns:
            Initialized ResourceUsageOptimizer
        """
        model_path = os.path.join(self.base_dir, "resource_optimizer_model")
        
        self.resource_optimizer = ResourceUsageOptimizer(
            mode=mode,
            n_estimators=n_estimators,
            max_depth=max_depth,
            multi_output=multi_output,
            model_path=model_path
        )
        
        self.logger.info(f"Initialized Resource Usage Optimizer in {mode} mode")
        return self.resource_optimizer
    
    def initialize_anomaly_detector(
        self,
        input_dim: int = 5,
        encoding_dims: List[int] = [32, 16, 8],
        threshold_multiplier: float = 3.0
    ) -> AnomalyDetector:
        """
        Initialize the Anomaly Detection System.
        
        Args:
            input_dim: Number of input features
            encoding_dims: List of dimensions for encoder layers
            threshold_multiplier: Threshold sensitivity
            
        Returns:
            Initialized AnomalyDetector
        """
        model_path = os.path.join(self.base_dir, "anomaly_detector_model")
        
        self.anomaly_detector = AnomalyDetector(
            input_dim=input_dim,
            encoding_dims=encoding_dims,
            threshold_multiplier=threshold_multiplier,
            model_path=model_path
        )
        
        self.logger.info(f"Initialized Anomaly Detector with {len(encoding_dims)} encoding layers")
        return self.anomaly_detector
    
    def prepare_data_for_traffic_prediction(
        self,
        metrics_df: pd.DataFrame,
        target_column: str = 'network_traffic',
        sequence_length: Optional[int] = None
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Prepare data for traffic prediction.
        
        Args:
            metrics_df: DataFrame of performance metrics
            target_column: Name of the target column
            sequence_length: Length of sequences (if None, uses model's default)
            
        Returns:
            Tuple of (X_sequences, y_targets)
        """
        if self.traffic_predictor is None:
            self.logger.error("Traffic predictor not initialized. Call initialize_traffic_predictor() first.")
            raise ValueError("Traffic predictor not initialized")
            
        # Use model's sequence length if not specified
        if sequence_length is None:
            sequence_length = self.traffic_predictor.sequence_length
            
        # Preprocess the data
        X, y = self.preprocessor.preprocess(
            metrics_df.drop(columns=[target_column]),
            target_column=target_column
        )
        
        # Prepare sequences
        X_seq, y_seq = [], []
        for i in range(len(X) - sequence_length):
            X_seq.append(X[i:i+sequence_length])
            y_seq.append(y[i+sequence_length])
            
        return np.array(X_seq), np.array(y_seq)
    
    def train_traffic_predictor(
        self,
        metrics_df: pd.DataFrame,
        target_column: str = 'network_traffic',
        epochs: int = 50,
        batch_size: int = 32,
        validation_split: float = 0.2,
        patience: int = 10
    ) -> Dict:
        """
        Train the LSTM Traffic Predictor model.
        
        Args:
            metrics_df: DataFrame of performance metrics
            target_column: Name of the target column
            epochs: Number of training epochs
            batch_size: Batch size
            validation_split: Proportion of data to use for validation
            patience: Early stopping patience
            
        Returns:
            Training history
        """
        if self.traffic_predictor is None:
            self.logger.error("Traffic predictor not initialized. Call initialize_traffic_predictor() first.")
            raise ValueError("Traffic predictor not initialized")
            
        # Prepare sequences
        X_seq, y_seq = self.prepare_data_for_traffic_prediction(metrics_df, target_column)
        
        # Create a trainer
        trainer = ModelTrainer(
            model=self.traffic_predictor,
            output_dir=os.path.join(self.output_dir, "traffic_predictor"),
            test_size=0.2,
            val_size=validation_split
        )
        
        # Train the model
        history, metrics = trainer.train_and_evaluate(
            X=X_seq,
            y=y_seq,
            train_kwargs={
                'epochs': epochs,
                'batch_size': batch_size,
                'patience': patience
            }
        )
        
        self.logger.info(f"Trained traffic predictor - MAE: {metrics.get('mae', 'N/A')}")
        return {'history': history, 'metrics': metrics}
    
    def predict_traffic(
        self,
        metrics_df: pd.DataFrame,
        target_column: str = 'network_traffic',
        generate_report: bool = True
    ) -> Dict:
        """
        Predict network traffic using the trained model.
        
        Args:
            metrics_df: DataFrame of performance metrics
            target_column: Name of the target column
            generate_report: Whether to generate an evaluation report
            
        Returns:
            Dictionary with predictions and evaluation results
        """
        if self.traffic_predictor is None:
            self.logger.error("Traffic predictor not initialized. Call initialize_traffic_predictor() first.")
            raise ValueError("Traffic predictor not initialized")
            
        # Prepare sequences
        X_seq, y_true = self.prepare_data_for_traffic_prediction(metrics_df, target_column)
        
        # Make predictions
        y_pred = self.traffic_predictor.predict(X_seq).flatten()
        
        # Calculate metrics
        metrics = self.traffic_predictor.evaluate(X_seq, y_true)
        
        # Generate report if requested
        report_dir = None
        if generate_report:
            report_dir = self.evaluator.generate_evaluation_report(
                model_name="LSTM_Traffic_Predictor",
                metrics=metrics,
                y_true=y_true,
                y_pred=y_pred,
                is_classification=False
            )
        
        self.logger.info(f"Traffic prediction - MAE: {metrics.get('mae', 'N/A')}")
        return {
            'predictions': y_pred,
            'true_values': y_true,
            'metrics': metrics,
            'report_dir': report_dir
        }
    
    def train_resource_optimizer(
        self,
        metrics_df: pd.DataFrame,
        target_columns: List[str] = ['cpu_usage', 'memory_usage']
    ) -> Dict:
        """
        Train the Resource Usage Optimizer model.
        
        Args:
            metrics_df: DataFrame of performance metrics
            target_columns: List of target columns to predict
            
        Returns:
            Training results
        """
        if self.resource_optimizer is None:
            self.logger.error("Resource optimizer not initialized. Call initialize_resource_optimizer() first.")
            raise ValueError("Resource optimizer not initialized")
            
        # Prepare features and targets
        feature_cols = [col for col in metrics_df.columns if col not in target_columns and col != 'timestamp']
        X = metrics_df[feature_cols].values
        y = metrics_df[target_columns].values
        
        # Create a trainer
        trainer = ModelTrainer(
            model=self.resource_optimizer,
            output_dir=os.path.join(self.output_dir, "resource_optimizer"),
            test_size=0.2,
            val_size=0.2
        )
        
        # Train the model
        history, metrics = trainer.train_and_evaluate(
            X=X,
            y=y
        )
        
        self.logger.info(f"Trained resource optimizer - RMSE: {metrics.get('rmse', 'N/A')}")
        return {'metrics': metrics, 'feature_importance': self.resource_optimizer.get_feature_importance()}
    
    def optimize_resources(
        self,
        metrics_df: pd.DataFrame,
        target_columns: List[str] = ['cpu_usage', 'memory_usage'],
        constraints: Optional[Dict[str, Dict[str, float]]] = None
    ) -> Dict:
        """
        Optimize resource allocation based on metrics.
        
        Args:
            metrics_df: DataFrame of performance metrics
            target_columns: List of target columns to predict/optimize
            constraints: Resource constraints (e.g., {'cpu_usage': {'min': 0.2, 'max': 0.8}})
            
        Returns:
            Dictionary with optimized allocations and details
        """
        if self.resource_optimizer is None:
            self.logger.error("Resource optimizer not initialized. Call initialize_resource_optimizer() first.")
            raise ValueError("Resource optimizer not initialized")
            
        # Prepare features
        feature_cols = [col for col in metrics_df.columns if col not in target_columns and col != 'timestamp']
        X = metrics_df[feature_cols].values
        
        # Optimize resources
        optimized, details = self.resource_optimizer.optimize_resources(X, constraints)
        
        # Create a DataFrame with the optimized allocations
        optimized_df = pd.DataFrame(
            optimized,
            columns=target_columns,
            index=metrics_df.index
        )
        
        self.logger.info(f"Optimized resources for {len(optimized_df)} samples")
        return {
            'optimized_allocations': optimized_df,
            'details': details
        }
    
    def train_anomaly_detector(
        self,
        normal_metrics_df: pd.DataFrame,
        epochs: int = 50,
        batch_size: int = 32,
        validation_split: float = 0.2
    ) -> Dict:
        """
        Train the Anomaly Detection System.
        
        Args:
            normal_metrics_df: DataFrame of normal (non-anomalous) metrics
            epochs: Number of training epochs
            batch_size: Batch size
            validation_split: Proportion of data to use for validation
            
        Returns:
            Training history
        """
        if self.anomaly_detector is None:
            self.logger.error("Anomaly detector not initialized. Call initialize_anomaly_detector() first.")
            raise ValueError("Anomaly detector not initialized")
            
        # Prepare features (drop timestamp if present)
        X = normal_metrics_df.drop(columns=['timestamp']) if 'timestamp' in normal_metrics_df.columns else normal_metrics_df
        feature_names = list(X.columns)
        
        # Split data for validation
        from sklearn.model_selection import train_test_split
        X_train, X_val = train_test_split(X.values, test_size=validation_split, random_state=42)
        
        # Train the model
        history = self.anomaly_detector.train(
            X_train=X_train,
            X_val=X_val,
            epochs=epochs,
            batch_size=batch_size,
            feature_names=feature_names
        )
        
        self.logger.info(f"Trained anomaly detector for {len(history['loss'])} epochs")
        return {'history': history}
    
    def detect_anomalies(
        self,
        metrics_df: pd.DataFrame,
        plot_results: bool = True,
        save_plot: bool = True
    ) -> Dict:
        """
        Detect anomalies in the metrics data.
        
        Args:
            metrics_df: DataFrame of performance metrics
            plot_results: Whether to generate and show a plot
            save_plot: Whether to save the plot to disk
            
        Returns:
            Dictionary with anomaly detection results
        """
        if self.anomaly_detector is None:
            self.logger.error("Anomaly detector not initialized. Call initialize_anomaly_detector() first.")
            raise ValueError("Anomaly detector not initialized")
            
        # Extract timestamps if present
        timestamps = None
        if 'timestamp' in metrics_df.columns:
            timestamps = metrics_df['timestamp'].values
            metrics_df = metrics_df.drop(columns=['timestamp'])
            
        # Detect anomalies
        anomalies, scores = self.anomaly_detector.detect_anomalies(metrics_df.values)
        
        # Get explanations for anomalies
        explanation = self.anomaly_detector.explain_anomalies(metrics_df.values)
        
        # Generate plot if requested
        plot_path = None
        fig = None
        if plot_results:
            plot_path = os.path.join(self.output_dir, "anomaly_detection", f"anomalies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
            fig = self.anomaly_detector.plot_anomalies(
                X=metrics_df.values,
                timestamps=timestamps,
                save_path=plot_path if save_plot else None
            )
            
        # Create a DataFrame with the results
        results_df = pd.DataFrame({
            'anomaly_score': scores,
            'is_anomaly': anomalies
        }, index=metrics_df.index)
        
        if timestamps is not None:
            results_df['timestamp'] = timestamps
            
        anomaly_count = np.sum(anomalies)
        self.logger.info(f"Detected {anomaly_count} anomalies out of {len(metrics_df)} samples")
        
        return {
            'results': results_df,
            'anomaly_count': anomaly_count,
            'threshold': self.anomaly_detector.threshold,
            'explanation': explanation,
            'plot': fig,
            'plot_path': plot_path
        }
    
    def load_models(self) -> Dict[str, bool]:
        """
        Load all trained models from disk.
        
        Returns:
            Dictionary indicating which models were loaded
        """
        results = {
            'traffic_predictor_loaded': False,
            'resource_optimizer_loaded': False,
            'anomaly_detector_loaded': False
        }
        
        # Try to load traffic predictor
        if self.traffic_predictor is not None:
            try:
                self.traffic_predictor.load()
                results['traffic_predictor_loaded'] = True
                self.logger.info("Loaded traffic predictor model")
            except Exception as e:
                self.logger.error(f"Failed to load traffic predictor: {str(e)}")
                
        # Try to load resource optimizer
        if self.resource_optimizer is not None:
            try:
                self.resource_optimizer.load()
                results['resource_optimizer_loaded'] = True
                self.logger.info("Loaded resource optimizer model")
            except Exception as e:
                self.logger.error(f"Failed to load resource optimizer: {str(e)}")
                
        # Try to load anomaly detector
        if self.anomaly_detector is not None:
            try:
                self.anomaly_detector.load()
                results['anomaly_detector_loaded'] = True
                self.logger.info("Loaded anomaly detector model")
            except Exception as e:
                self.logger.error(f"Failed to load anomaly detector: {str(e)}")
                
        return results
    
    def save_models(self) -> Dict[str, bool]:
        """
        Save all trained models to disk.
        
        Returns:
            Dictionary indicating which models were saved
        """
        results = {
            'traffic_predictor_saved': False,
            'resource_optimizer_saved': False,
            'anomaly_detector_saved': False
        }
        
        # Try to save traffic predictor
        if self.traffic_predictor is not None and self.traffic_predictor.model is not None:
            try:
                self.traffic_predictor.save()
                results['traffic_predictor_saved'] = True
                self.logger.info("Saved traffic predictor model")
            except Exception as e:
                self.logger.error(f"Failed to save traffic predictor: {str(e)}")
                
        # Try to save resource optimizer
        if self.resource_optimizer is not None and (self.resource_optimizer.rf_model is not None or self.resource_optimizer.gb_model is not None):
            try:
                self.resource_optimizer.save()
                results['resource_optimizer_saved'] = True
                self.logger.info("Saved resource optimizer model")
            except Exception as e:
                self.logger.error(f"Failed to save resource optimizer: {str(e)}")
                
        # Try to save anomaly detector
        if self.anomaly_detector is not None and self.anomaly_detector.model is not None:
            try:
                self.anomaly_detector.save()
                results['anomaly_detector_saved'] = True
                self.logger.info("Saved anomaly detector model")
            except Exception as e:
                self.logger.error(f"Failed to save anomaly detector: {str(e)}")
                
        return results 