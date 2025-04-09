from typing import Dict, List, Any, Optional, Tuple
import threading
import time
import os
import logging
from datetime import datetime
import pandas as pd
import numpy as np
from threading import Lock

from app.components.ml_integration import MLIntegration
from app.ml.rule_engine import RuleEngine
from app.ml.context_tracker import ContextTracker
from app.utils.logger import get_logger

logger = get_logger('components.ml_controller')

class MLController:
    """Controller for ML operations, managing integration between ML models and the application."""
    
    def __init__(self):
        """Initialize the ML controller."""
        self.ml_integration = MLIntegration()
        self.rule_engine = RuleEngine()
        self.context_tracker = ContextTracker()
        
        self.running = False
        self.collection_thread = None
        self.training_thread = None
        
        # Performance data collection
        self.metrics_history = []
        self.predictions_history = []
        
        # Detection results storage
        self.detection_results = []
        self.detection_lock = Lock()
        
        # Stats tracking
        self.stats = {
            "packets_analyzed": 0,
            "threats_detected": 0,
            "rules_active": self.rule_engine.get_active_rules_count(),
            "rule_hits": {},
            "false_positives": 0,
            "false_negatives": 0
        }
        
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
                
                # Update statistics from rule engine
                self._update_rule_stats()
                
            except Exception as e:
                logger.error(f"Error collecting metrics: {e}")
            
            # Sleep for collection interval
            time.sleep(self.collection_interval)
    
    def _update_rule_stats(self):
        """Update statistics from the rule engine."""
        try:
            # Get rule engine statistics
            rule_stats = self.rule_engine.get_statistics()
            
            # Update our stats with rule engine stats
            self.stats["rules_active"] = rule_stats["rules_active"]
            self.stats["rule_hits"] = rule_stats["rule_hits"]
            
        except Exception as e:
            logger.error(f"Error updating rule stats: {e}")
    
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
        # Update statistics
        self.stats["packets_analyzed"] += 1
        
        # Update context tracker with packet information
        self.context_tracker.update(packet)
        
        # Get current context for rule evaluation
        context = self.context_tracker.get_context()
        
        # Evaluate packet against rules
        rule_results = self.rule_engine.evaluate_packet(packet, context)
        
        # Store rule-based detection results
        if rule_results:
            with self.detection_lock:
                self.detection_results.extend(rule_results)
                self.stats["threats_detected"] += len(rule_results)
                
                # Keep only the most recent 1000 detections
                if len(self.detection_results) > 1000:
                    self.detection_results = self.detection_results[-1000:]
        
        # Also process the packet through ML integration
        ml_result = self.ml_integration.process_packet(packet)
        
        # Store ML prediction
        prediction = {
            'timestamp': datetime.now(),
            'source': packet.get('src_ip', 'Unknown'),
            'threat_probability': ml_result.get('threat_probability', 0.0),
            'action': ml_result.get('recommended_action', 'allow'),
            'is_anomaly': ml_result.get('is_anomaly', False),
            'packet_info': packet
        }
        
        # Add to history
        self.predictions_history.append(prediction)
        
        # Keep only the last 1000 predictions
        if len(self.predictions_history) > 1000:
            self.predictions_history = self.predictions_history[-1000:]
        
        # If ML detected a threat, add it to our detection results
        if ml_result.get('is_threat', False):
            with self.detection_lock:
                ml_detection = {
                    "type": "ml_based",
                    "description": "ML-detected threat",
                    "severity": "MEDIUM",
                    "confidence": ml_result.get('threat_probability', 0.0),
                    "timestamp": datetime.now(),
                    "evidence": {
                        "src_ip": packet.get('src_ip', 'Unknown'),
                        "src_mac": packet.get('src_mac', 'Unknown'),
                        "probability": ml_result.get('threat_probability', 0.0),
                        "anomaly_score": ml_result.get('anomaly_score', 0.0)
                    }
                }
                self.detection_results.append(ml_detection)
                self.stats["threats_detected"] += 1
                
                # Keep only the most recent 1000 detections
                if len(self.detection_results) > 1000:
                    self.detection_results = self.detection_results[-1000:]
        
        # Combine results (prefer rule-based if both detected)
        combined_result = ml_result.copy()
        if rule_results:
            combined_result['is_threat'] = True
            combined_result['rule_detection'] = True
            combined_result['threat_probability'] = max(
                combined_result.get('threat_probability', 0.0),
                max(r['confidence'] for r in rule_results)
            )
            combined_result['rule_detections'] = rule_results
        
        return combined_result
    
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
    
    def get_recent_detections(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get recent detection results.
        
        Args:
            limit: Optional limit on number of entries to return
            
        Returns:
            List of detection dictionaries
        """
        with self.detection_lock:
            if limit is None:
                return list(self.detection_results)
            return list(self.detection_results[-limit:])
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current statistics from the ML controller.
        
        Returns:
            Dictionary with statistics
        """
        # Make a copy of the stats to avoid thread issues
        stats_copy = dict(self.stats)
        
        # Add any additional computed statistics
        stats_copy["detection_count"] = len(self.detection_results)
        
        return stats_copy
    
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
        
    def save_rule_configuration(self, filepath: Optional[str] = None) -> bool:
        """Save rule configuration to a file.
        
        Args:
            filepath: Path to save rules to, defaults to configured path
            
        Returns:
            True if rules were saved, False otherwise
        """
        if filepath is None:
            filepath = os.path.join("data", "rules_config.yaml")
            
        return self.rule_engine.save_rules(filepath)
        
    def load_rule_configuration(self, filepath: Optional[str] = None) -> bool:
        """Load rule configuration from a file.
        
        Args:
            filepath: Path to load rules from, defaults to configured path
            
        Returns:
            True if rules were loaded, False otherwise
        """
        if filepath is None:
            filepath = os.path.join("data", "rules_config.yaml")
            
        return self.rule_engine.load_rules(filepath)
        
    def predict_traffic(self, hours_ahead: int = 1) -> Optional[pd.DataFrame]:
        """Predict future traffic patterns.
        
        Args:
            hours_ahead: Number of hours to predict ahead
            
        Returns:
            DataFrame with predictions or None if not enough data
        """
        # This is a placeholder implementation
        if len(self.metrics_history) < 24:
            logger.warning("Not enough data for traffic prediction")
            return None
            
        # Create a pandas DataFrame from the metrics history
        metrics_df = pd.DataFrame(self.metrics_history)
        
        # Set timestamp as index
        metrics_df['timestamp'] = pd.to_datetime(metrics_df['timestamp'])
        metrics_df.set_index('timestamp', inplace=True)
        
        # Resample to hourly data
        hourly_df = metrics_df.resample('1H').mean()
        
        # Simple forecasting - just repeat the pattern
        if len(hourly_df) >= 24:
            # Use the last 24 hours as the forecast for the next period
            last_day = hourly_df.tail(24).reset_index(drop=True)
            
            # Create prediction DataFrame
            prediction = pd.DataFrame()
            for i in range(hours_ahead):
                # Add forecast hours
                forecast_hour = last_day.copy()
                forecast_hour['hour'] = i + 1
                prediction = pd.concat([prediction, forecast_hour])
                
            return prediction
            
        return None
        
    def detect_anomalies(self, data: Optional[pd.DataFrame] = None) -> Tuple[List[bool], List[float], Dict[str, Any]]:
        """Detect anomalies in the data.
        
        Args:
            data: Optional DataFrame with data to check, uses internal data if None
            
        Returns:
            Tuple of (anomaly_flags, anomaly_scores, metadata)
        """
        # Use internal data if none provided
        if data is None:
            if len(self.metrics_history) < 10:
                return [], [], {"error": "Not enough data for anomaly detection"}
                
            # Create DataFrame from metrics history
            data = pd.DataFrame(self.metrics_history)
            data['timestamp'] = pd.to_datetime(data['timestamp'])
            data.set_index('timestamp', inplace=True)
        
        # Extract numerical columns for anomaly detection
        numeric_data = data.select_dtypes(include=[np.number])
        
        # Simple anomaly detection - flag values > 2 std deviations from mean
        means = numeric_data.mean()
        stds = numeric_data.std()
        
        anomaly_scores = []
        anomaly_flags = []
        
        for _, row in numeric_data.iterrows():
            # Calculate how many std deviations from mean for each field
            deviations = abs(row - means) / stds
            
            # Maximum deviation is the anomaly score
            score = float(deviations.max())
            
            # Flag as anomaly if score > 2.0
            flag = score > 2.0
            
            anomaly_scores.append(score)
            anomaly_flags.append(flag)
        
        metadata = {
            "mean": means.to_dict(),
            "std": stds.to_dict(),
            "threshold": 2.0,
            "anomaly_count": sum(anomaly_flags)
        }
        
        return anomaly_flags, anomaly_scores, metadata
        
    def optimize_resources(self, constraints: Dict[str, float]) -> Dict[str, float]:
        """Optimize resource allocation based on current needs.
        
        Args:
            constraints: Dictionary with resource constraints
            
        Returns:
            Dictionary with optimized resource allocation
        """
        # This is a placeholder implementation
        # In a real system, this would use predictive models to optimize resources
        
        # Get recent metrics
        recent_metrics = self.get_metrics_history(limit=100)
        if not recent_metrics:
            return constraints
            
        # Calculate average recent usage
        avg_cpu = np.mean([m.get('cpu_usage', 0.0) for m in recent_metrics])
        avg_memory = np.mean([m.get('memory_usage', 0.0) for m in recent_metrics])
        
        # Simple optimization - allocate resources proportionally to usage
        total_resources = sum(constraints.values())
        
        # Default allocation - equal distribution
        allocation = {k: total_resources / len(constraints) for k in constraints}
        
        # Adjust CPU and memory if we have those metrics
        if 'cpu' in constraints and avg_cpu > 0:
            allocation['cpu'] = max(constraints['cpu'] * avg_cpu * 1.5, constraints['cpu'] * 0.5)
            
        if 'memory' in constraints and avg_memory > 0:
            allocation['memory'] = max(constraints['memory'] * avg_memory * 1.5, constraints['memory'] * 0.5)
        
        return allocation 