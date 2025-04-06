from typing import Dict, List, Any, Optional, Tuple
import logging
from datetime import datetime
import os

from app.utils.logger import get_logger
from app.components.ml_threat_detector import MLThreatDetector
from app.components.ml_data_collector import MLDataCollector
from app.components.threat_detector import ThreatDetector
from app.components.threat_intelligence import ThreatIntelligence
from app.ml.api import ARPGuardML

logger = get_logger('components.ml_integration')

class MLIntegration:
    """Integrates ML-based threat detection with the existing system."""
    
    def __init__(self):
        """Initialize the ML integration component."""
        # Initialize existing components for backwards compatibility
        self.ml_detector = MLThreatDetector()
        self.data_collector = MLDataCollector()
        self.threat_detector = ThreatDetector()
        self.threat_intelligence = ThreatIntelligence()
        
        # Initialize the new ARPGuardML API
        model_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data', 'ml_models')
        output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data', 'ml_output')
        
        # Create directories if they don't exist
        os.makedirs(model_dir, exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize the ML API
        self.ml_api = ARPGuardML(
            model_dir=model_dir,
            output_dir=output_dir,
            metrics_window=100  # Keep 100 metrics records
        )
        
        # Models initialized flag
        self.models_initialized = False
        
        # Training configuration
        self.min_training_samples = 1000
        self.training_interval = 3600  # 1 hour
        self.last_training_time = None
        
        # Performance tracking
        self.true_positives = 0
        self.false_positives = 0
        self.true_negatives = 0
        self.false_negatives = 0
    
    def initialize_models(self):
        """Initialize all ML models."""
        if self.models_initialized:
            return
            
        try:
            # Initialize traffic predictor
            self.ml_api.initialize_traffic_predictor(
                input_dim=10,  # Features from network traffic
                sequence_length=20,  # Use 20 time steps of history
                lstm_units=64  # Size of LSTM layers
            )
            
            # Initialize resource optimizer
            self.ml_api.initialize_resource_optimizer(
                mode='ensemble',  # Use both RF and GB
                n_estimators=100,
                multi_output=True
            )
            
            # Initialize anomaly detector
            self.ml_api.initialize_anomaly_detector(
                input_dim=10,  # Features from system metrics
                encoding_dims=[8, 4],  # Autoencoder architecture
                threshold_multiplier=3.0  # Threshold for anomaly detection
            )
            
            # Try to load previously saved models
            try:
                self.ml_api.load_models()
                logger.info("Loaded pre-trained ML models")
            except Exception as e:
                logger.info(f"No pre-trained models found, will train new ones: {e}")
            
            self.models_initialized = True
            
        except Exception as e:
            logger.error(f"Error initializing ML models: {e}")
    
    def process_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Process a network packet through the integrated detection system.
        
        Args:
            packet: Dictionary containing packet information
            
        Returns:
            Dictionary with detection results and actions
        """
        # Initialize models if needed
        if not self.models_initialized:
            self.initialize_models()
        
        # Get threat intelligence data
        threat_data = self._get_threat_intelligence(packet)
        packet.update(threat_data)
        
        # Get traditional detection results
        traditional_result = self.threat_detector.analyze_packet(packet)
        
        # Get ML-based detection results
        legacy_ml_result = self.ml_detector.analyze_packet(packet)
        
        # Collect metrics for ML API
        self._collect_metrics(packet)
        
        # Run anomaly detection if enough data is available
        ml_api_result = {}
        try:
            if self.ml_api.anomaly_detector and len(self.ml_api.collected_metrics) > 10:
                # Prepare data for anomaly detection
                features = self._extract_features_from_packet(packet)
                
                # Detect anomalies
                is_anomaly, anomaly_score, explanation = self.ml_api.detect_anomalies(
                    features, explain=True
                )
                
                ml_api_result = {
                    'threat_probability': anomaly_score,
                    'is_anomaly': is_anomaly,
                    'anomaly_explanation': explanation
                }
        except Exception as e:
            logger.error(f"Error during anomaly detection: {e}")
        
        # Combine results
        combined_result = self._combine_results(traditional_result, legacy_ml_result, ml_api_result)
        
        # Collect data for training
        self._collect_training_data(packet, combined_result)
        
        # Check if training is needed
        self._check_training()
        
        return combined_result
    
    def _extract_features_from_packet(self, packet: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from packet for the ML API.
        
        Args:
            packet: Dictionary containing packet information
            
        Returns:
            Dictionary of features suitable for ML API
        """
        # Extract basic features that might be present in a packet
        features = {
            'packet_length': float(packet.get('packet_length', 0)),
            'protocol': float(packet.get('protocol', 0)),
            'src_port': float(packet.get('src_port', 0)),
            'dst_port': float(packet.get('dst_port', 0)),
            'packets_per_second': float(packet.get('packets_per_second', 0)),
            'bytes_per_second': float(packet.get('bytes_per_second', 0)),
            'connection_attempts': float(packet.get('connection_attempts', 0)),
            'threat_score': float(packet.get('threat_score', 0)),
            'reputation_score': float(packet.get('reputation_score', 0)),
            'timestamp': datetime.now()
        }
        
        return features
    
    def _collect_metrics(self, packet: Dict[str, Any]):
        """Collect performance metrics for ML API.
        
        Args:
            packet: Dictionary containing packet information
        """
        try:
            # Extract metrics from packet
            metrics = {
                'cpu_usage': 0.5,  # Placeholder, would be collected from system
                'memory_usage': 0.3,  # Placeholder
                'network_traffic': float(packet.get('packet_length', 0)),
                'packet_rate': float(packet.get('packets_per_second', 0)),
                'response_time': 0.1,  # Placeholder
                'timestamp': datetime.now()
            }
            
            # Add to API metrics collector
            self.ml_api.collect_metrics(metrics)
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
    
    def _get_threat_intelligence(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Get threat intelligence data for a packet.
        
        Args:
            packet: Dictionary containing packet information
            
        Returns:
            Dictionary with threat intelligence data
        """
        result = {}
        
        # Check source IP
        src_ip = packet.get('src_ip')
        if src_ip:
            ip_data = self.threat_intelligence.check_ip(src_ip)
            if ip_data:
                result['threat_score'] = ip_data.get('score', 0)
                result['reputation_score'] = 100 - ip_data.get('score', 0)
        
        # Check destination domain if present
        dst_domain = packet.get('dst_domain')
        if dst_domain:
            domain_data = self.threat_intelligence.check_domain(dst_domain)
            if domain_data:
                result['domain_threat_score'] = domain_data.get('score', 0)
        
        return result
    
    def _combine_results(self, traditional: Dict[str, Any], legacy_ml: Dict[str, Any], 
                       ml_api: Dict[str, Any]) -> Dict[str, Any]:
        """Combine traditional and ML-based detection results.
        
        Args:
            traditional: Results from traditional detection
            legacy_ml: Results from legacy ML-based detection
            ml_api: Results from new ML API
            
        Returns:
            Combined results dictionary
        """
        # Weight the results (can be adjusted based on performance)
        traditional_weight = 0.3
        legacy_ml_weight = 0.3
        ml_api_weight = 0.4
        
        # Calculate combined threat probability
        traditional_prob = traditional.get('threat_probability', 0)
        legacy_ml_prob = legacy_ml.get('threat_probability', 0)
        ml_api_prob = ml_api.get('threat_probability', 0)
        
        # Default weights if ml_api is not available
        if not ml_api:
            traditional_weight = 0.4
            legacy_ml_weight = 0.6
            ml_api_weight = 0
        
        combined_prob = (traditional_prob * traditional_weight + 
                        legacy_ml_prob * legacy_ml_weight +
                        ml_api_prob * ml_api_weight)
        
        # Determine final action
        if combined_prob > 0.8:
            action = 'block'
        elif combined_prob > 0.5:
            action = 'monitor'
        else:
            action = 'allow'
        
        # Prepare combined result
        result = {
            'threat_probability': combined_prob,
            'recommended_action': action,
            'confidence': legacy_ml.get('confidence', 0.5),
            'traditional_detection': traditional,
            'legacy_ml_detection': legacy_ml
        }
        
        # Add ML API results if available
        if ml_api:
            result['ml_api_detection'] = ml_api
            
            if ml_api.get('is_anomaly', False):
                result['is_anomaly'] = True
                result['anomaly_explanation'] = ml_api.get('anomaly_explanation', {})
        
        return result
    
    def _collect_training_data(self, packet: Dict[str, Any], result: Dict[str, Any]):
        """Collect data for ML model training.
        
        Args:
            packet: Original packet data
            result: Detection results
        """
        # Determine if this was a true positive/negative or false positive/negative
        # This would typically come from feedback or ground truth data
        # For now, we'll use the combined result as a proxy
        is_threat = result['threat_probability'] > 0.5
        
        # Collect data for legacy ML model
        self.data_collector.add_packet(packet, is_threat)
        
        # Collect features for ML API
        features = self._extract_features_from_packet(packet)
        
        # TODO: Add code to collect training data for ML API
    
    def _check_training(self, force=False):
        """Check if ML models need to be retrained.
        
        Args:
            force: If True, force retraining regardless of conditions
            
        Returns:
            Number of samples used for training, or 0 if training was not performed
        """
        current_time = datetime.now()
        
        # Check if enough time has passed since last training
        if (not force and self.last_training_time is not None and 
            (current_time - self.last_training_time).total_seconds() < self.training_interval):
            return 0
        
        # Get collected training data
        X, y = self.data_collector.get_training_data()
        
        # Check if we have enough samples
        if len(X) < self.min_training_samples and not force:
            return 0
        
        # Train the legacy models first
        try:
            self.ml_detector.train(X, y)
            logger.info(f"Legacy ML models trained with {len(X)} samples")
        except Exception as e:
            logger.error(f"Error training legacy ML models: {e}")
        
        # Initialize models if needed
        if not self.models_initialized:
            self.initialize_models()
        
        # TODO: Add code to train the ML API models
        # For now, just update the last training time
        self.last_training_time = current_time
        
        # Clear collected data after training
        self.data_collector.clear_data()
        
        return len(X)
    
    def get_performance_metrics(self) -> Dict[str, float]:
        """Get current performance metrics for the ML models.
        
        Returns:
            Dictionary with performance metrics
        """
        total = self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        if total == 0:
            return {
                'accuracy': 0.0,
                'precision': 0.0,
                'recall': 0.0,
                'f1_score': 0.0
            }
        
        accuracy = (self.true_positives + self.true_negatives) / total
        precision = self.true_positives / (self.true_positives + self.false_positives) if (self.true_positives + self.false_positives) > 0 else 0
        recall = self.true_positives / (self.true_positives + self.false_negatives) if (self.true_positives + self.false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score
        }
    
    def update_performance(self, true_positive: bool, false_positive: bool, 
                         true_negative: bool, false_negative: bool):
        """Update performance tracking metrics.
        
        Args:
            true_positive: Whether this was a true positive
            false_positive: Whether this was a false positive
            true_negative: Whether this was a true negative
            false_negative: Whether this was a false negative
        """
        if true_positive:
            self.true_positives += 1
        if false_positive:
            self.false_positives += 1
        if true_negative:
            self.true_negatives += 1
        if false_negative:
            self.false_negatives += 1 