from typing import Dict, List, Any, Optional, Tuple
import threading
import time
import os
import logging
from datetime import datetime
import pandas as pd
import numpy as np

from app.components.ml_integration import MLIntegration
from app.utils.logger import get_logger

logger = get_logger('components.ml_controller')

class MLController:
    """Controller for ML operations, managing integration between ML models and the application."""
    
    def __init__(self):
        """Initialize the ML controller."""
        self.ml_integration = MLIntegration()
        self.running = False
        self.collection_thread = None
        self.training_thread = None
        
        # Performance data collection
        self.metrics_history = []
        self.predictions_history = []
        
        # Status tracking
        self.status = "Stopped"
        self.last_collection_time = None
        self.last_training_time = None
        
        # Collection settings
        self.collection_interval = 10  # seconds
        self.automatic_training = False
        self.training_interval = 3600  # 1 hour
    
    def start(self):
        """Start the ML controller."""
        if self.running:
            return
            
        # Initialize ML models
        self.ml_integration.initialize_models()
        
        # Start collection thread
        self.running = True
        self.collection_thread = threading.Thread(target=self._collection_loop, daemon=True)
        self.collection_thread.start()
        
        # Start training thread if automatic training is enabled
        if self.automatic_training:
            self.training_thread = threading.Thread(target=self._training_loop, daemon=True)
            self.training_thread.start()
        
        self.status = "Running"
        logger.info("ML controller started")
    
    def stop(self):
        """Stop the ML controller."""
        self.running = False
        if self.collection_thread:
            self.collection_thread.join(timeout=2.0)
        if self.training_thread:
            self.training_thread.join(timeout=2.0)
        
        self.status = "Stopped"
        logger.info("ML controller stopped")
    
    def _collection_loop(self):
        """Background thread for collecting metrics."""
        while self.running:
            try:
                # Collect system performance metrics
                metrics = self._collect_system_metrics()
                self.metrics_history.append(metrics)
                
                # Keep only the last 1000 metrics
                if len(self.metrics_history) > 1000:
                    self.metrics_history = self.metrics_history[-1000:]
                
                self.last_collection_time = datetime.now()
                
            except Exception as e:
                logger.error(f"Error collecting metrics: {e}")
            
            # Sleep for collection interval
            time.sleep(self.collection_interval)
    
    def _training_loop(self):
        """Background thread for automatic model training."""
        while self.running:
            try:
                if self.automatic_training:
                    # Check if training is needed based on time interval
                    current_time = datetime.now()
                    if (self.last_training_time is None or 
                        (current_time - self.last_training_time).total_seconds() >= self.training_interval):
                        
                        logger.info("Starting automatic model training")
                        self.train_models()
                
            except Exception as e:
                logger.error(f"Error in training loop: {e}")
            
            # Sleep for a shorter interval and check again
            time.sleep(60)  # Check every minute
    
    def _collect_system_metrics(self) -> Dict[str, Any]:
        """Collect system performance metrics.
        
        Returns:
            Dictionary of metrics
        """
        # This is a placeholder - in a real implementation, you would
        # collect actual system metrics (CPU, memory, network, etc.)
        import psutil
        
        metrics = {
            'timestamp': datetime.now(),
            'cpu_usage': psutil.cpu_percent() / 100.0,
            'memory_usage': psutil.virtual_memory().percent / 100.0,
            'network_traffic': 0.0,  # Placeholder
            'packet_rate': 0.0,      # Placeholder
            'response_time': 0.0     # Placeholder
        }
        
        # Pass metrics to ML API
        try:
            self.ml_integration.ml_api.collect_metrics(metrics)
        except Exception as e:
            logger.error(f"Error passing metrics to ML API: {e}")
        
        return metrics
    
    def process_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Process a network packet through ML detection.
        
        Args:
            packet: Dictionary containing packet information
            
        Returns:
            Dictionary with detection results
        """
        # Process the packet through ML integration
        result = self.ml_integration.process_packet(packet)
        
        # Store prediction
        prediction = {
            'timestamp': datetime.now(),
            'source': packet.get('src_ip', 'Unknown'),
            'threat_probability': result.get('threat_probability', 0.0),
            'action': result.get('recommended_action', 'allow'),
            'is_anomaly': result.get('is_anomaly', False),
            'packet_info': packet
        }
        
        # Add to history
        self.predictions_history.append(prediction)
        
        # Keep only the last 1000 predictions
        if len(self.predictions_history) > 1000:
            self.predictions_history = self.predictions_history[-1000:]
        
        return result
    
    def train_models(self, force=True) -> bool:
        """Train ML models with collected data.
        
        Args:
            force: If True, force training even if minimum data requirements aren't met
            
        Returns:
            True if training was performed, False otherwise
        """
        try:
            # Train the models through ML integration
            samples_count = self.ml_integration._check_training(force=force)
            
            if samples_count > 0:
                logger.info(f"Models trained with {samples_count} samples")
                self.last_training_time = datetime.now()
                return True
            else:
                logger.info("No training performed - insufficient data")
                return False
                
        except Exception as e:
            logger.error(f"Error training models: {e}")
            return False
    
    def get_metrics_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get the history of collected metrics.
        
        Args:
            limit: Optional limit on number of entries to return
            
        Returns:
            List of metrics dictionaries
        """
        if limit is None:
            return self.metrics_history
        return self.metrics_history[-limit:]
    
    def get_predictions_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get the history of predictions.
        
        Args:
            limit: Optional limit on number of entries to return
            
        Returns:
            List of prediction dictionaries
        """
        if limit is None:
            return self.predictions_history
        return self.predictions_history[-limit:]
    
    def get_performance_metrics(self) -> Dict[str, float]:
        """Get current performance metrics for the ML models.
        
        Returns:
            Dictionary with performance metrics
        """
        return self.ml_integration.get_performance_metrics()
    
    def set_collection_interval(self, interval: int):
        """Set the metrics collection interval.
        
        Args:
            interval: Collection interval in seconds
        """
        self.collection_interval = max(1, interval)
        logger.info(f"Collection interval set to {self.collection_interval} seconds")
    
    def set_training_settings(self, automatic: bool, interval: int, min_samples: int):
        """Set training settings.
        
        Args:
            automatic: Whether to enable automatic training
            interval: Training interval in seconds
            min_samples: Minimum number of samples required for training
        """
        self.automatic_training = automatic
        self.training_interval = max(60, interval)
        self.ml_integration.min_training_samples = max(10, min_samples)
        
        logger.info(f"Training settings updated: automatic={automatic}, "
                  f"interval={self.training_interval}s, min_samples={self.ml_integration.min_training_samples}")
        
        # Start or stop training thread based on automatic setting
        if automatic and not self.training_thread and self.running:
            self.training_thread = threading.Thread(target=self._training_loop, daemon=True)
            self.training_thread.start()
    
    def predict_traffic(self, hours_ahead: int = 1) -> Optional[pd.DataFrame]:
        """Predict network traffic for the specified hours ahead.
        
        Args:
            hours_ahead: Number of hours to predict ahead
            
        Returns:
            DataFrame with predicted traffic values or None if prediction fails
        """
        try:
            # Check if ML API is initialized
            if not self.ml_integration.models_initialized:
                self.ml_integration.initialize_models()
            
            # Prepare data from metrics history
            if len(self.metrics_history) < 20:  # Need enough history for sequence
                logger.warning("Not enough metrics history for traffic prediction")
                return None
            
            # Extract network traffic from metrics history
            df = pd.DataFrame(self.metrics_history[-100:])  # Use last 100 entries
            
            # Prepare data for prediction
            input_data = self.ml_integration.ml_api.prepare_data_for_traffic_prediction(df)
            
            # Predict traffic
            predictions = self.ml_integration.ml_api.predict_traffic(
                input_data, 
                steps=hours_ahead * 6  # Assuming 10-minute intervals, 6 steps per hour
            )
            
            return predictions
            
        except Exception as e:
            logger.error(f"Error predicting traffic: {e}")
            return None
    
    def detect_anomalies(self, data: Optional[pd.DataFrame] = None) -> Tuple[List[bool], List[float], Dict[str, Any]]:
        """Detect anomalies in the provided data or recent metrics.
        
        Args:
            data: Optional DataFrame with metrics data
            
        Returns:
            Tuple of (anomaly flags, anomaly scores, explanations)
        """
        try:
            # Check if ML API is initialized
            if not self.ml_integration.models_initialized:
                self.ml_integration.initialize_models()
            
            # Use provided data or recent metrics
            if data is None:
                if len(self.metrics_history) < 10:
                    logger.warning("Not enough metrics history for anomaly detection")
                    return [], [], {}
                
                data = pd.DataFrame(self.metrics_history[-50:])  # Use last 50 entries
            
            # Convert to numpy array of features
            features = data.drop(['timestamp'], axis=1, errors='ignore').values
            
            # Detect anomalies
            is_anomaly, scores, explanations = self.ml_integration.ml_api.detect_anomalies(
                features, explain=True
            )
            
            return is_anomaly, scores, explanations
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
            return [], [], {}
    
    def optimize_resources(self, constraints: Dict[str, float]) -> Dict[str, float]:
        """Optimize resource allocation based on current metrics.
        
        Args:
            constraints: Dictionary of resource constraints
            
        Returns:
            Dictionary with optimized resource allocations
        """
        try:
            # Check if ML API is initialized
            if not self.ml_integration.models_initialized:
                self.ml_integration.initialize_models()
            
            # Use recent metrics for optimization
            if len(self.metrics_history) < 10:
                logger.warning("Not enough metrics history for resource optimization")
                return {}
            
            data = pd.DataFrame(self.metrics_history[-30:])  # Use last 30 entries
            
            # Optimize resources
            optimized = self.ml_integration.ml_api.optimize_resources(
                data, constraints
            )
            
            return optimized
            
        except Exception as e:
            logger.error(f"Error optimizing resources: {e}")
            return {} 