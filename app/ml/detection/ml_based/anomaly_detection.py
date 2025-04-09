"""
Anomaly-based detection for ARPGuard ML detection layer.

This module provides anomaly detection capabilities for identifying
unusual ARP traffic patterns that may indicate attacks.
"""

import os
import json
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, NamedTuple

from app.utils.logger import get_logger
from app.utils.config import get_config
from app.ml.models.anomaly_detector import AnomalyDetector
from app.ml.packet_converter import extract_packet_features

# Set up module logger
logger = get_logger("ml.detection.ml_based.anomaly_detection")

class AnomalyResult(NamedTuple):
    """Result of anomaly detection."""
    is_anomaly: bool
    score: float
    features_contribution: Dict[str, float]
    timestamp: datetime
    source_ip: Optional[str]
    source_mac: Optional[str]
    packet_info: Dict[str, Any]

class AnomalyDetectionEngine:
    """Engine for detecting anomalies in network traffic using machine learning.
    
    This class wraps the AnomalyDetector model, providing an interface for
    processing packets and detecting anomalies in their features.
    """
    
    def __init__(self, model_dir: Optional[str] = None):
        """Initialize the anomaly detection engine.
        
        Args:
            model_dir: Directory to save/load model files
        """
        self.config = get_config()
        
        # Default model directory if not provided
        if model_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
            model_dir = os.path.join(base_dir, 'data', 'ml_models')
            
        # Ensure model directory exists
        os.makedirs(model_dir, exist_ok=True)
            
        # Model path
        self.model_path = os.path.join(model_dir, "anomaly_detector")
        
        # Initialize the anomaly detector
        self.detector = self._initialize_detector()
        
        # Feature names
        self.feature_names = [
            "operation",
            "src_mac_value",
            "dst_mac_value",
            "src_ip_value",
            "dst_ip_value",
            "hw_type",
            "proto_type",
            "hw_len",
            "proto_len",
            "is_gratuitous",
            "is_broadcast"
        ]
        
        # Detection history
        self.detection_history = []
        
        # Detector ready flag
        self.detector_ready = False
        
        # Anomaly threshold
        self.anomaly_threshold = self.config.get(
            "ml.anomaly_detection.threshold", 0.8
        )
        
        # Load model if exists
        self._load_model()
        
    def _initialize_detector(self) -> AnomalyDetector:
        """Initialize the anomaly detector with appropriate configuration.
        
        Returns:
            Configured AnomalyDetector
        """
        # Get configuration values with defaults
        input_dim = 11  # Fixed dimension for our feature extraction
        encoding_dims = self.config.get(
            "ml.anomaly_detection.encoding_dims", [32, 16, 8]
        )
        threshold_multiplier = self.config.get(
            "ml.anomaly_detection.threshold_multiplier", 3.0
        )
        
        # Create anomaly detector
        detector = AnomalyDetector(
            input_dim=input_dim,
            encoding_dims=encoding_dims,
            threshold_multiplier=threshold_multiplier,
            model_path=self.model_path
        )
        
        logger.info(f"Initialized anomaly detector with input dim {input_dim}")
        return detector
        
    def _load_model(self) -> bool:
        """Load the anomaly detector model if it exists.
        
        Returns:
            Boolean indicating if model was loaded successfully
        """
        try:
            if os.path.exists(f"{self.model_path}.h5"):
                self.detector.load()
                self.detector_ready = True
                logger.info("Loaded anomaly detector model")
                return True
            else:
                logger.warning("No anomaly detector model found, model needs training")
                return False
        except Exception as e:
            logger.error(f"Error loading anomaly detector model: {e}")
            return False
            
    def detect(self, packet: Dict[str, Any]) -> Optional[AnomalyResult]:
        """Detect anomalies in a packet.
        
        Args:
            packet: Dictionary containing packet data
            
        Returns:
            AnomalyResult if anomaly detected, None otherwise
        """
        if not self.detector_ready:
            logger.warning("Anomaly detector not ready, skipping detection")
            return None
            
        try:
            # Extract features
            features = extract_packet_features(packet)
            
            # Reshape for model
            features_reshaped = features.reshape(1, -1)
            
            # Detect anomalies
            anomalies, scores = self.detector.detect_anomalies(features_reshaped)
            
            # Create result if anomaly detected
            if anomalies[0]:
                # Get feature contribution to the anomaly
                contributions = self._get_feature_contributions(features_reshaped)
                
                result = AnomalyResult(
                    is_anomaly=True,
                    score=float(scores[0]),
                    features_contribution=contributions,
                    timestamp=datetime.now(),
                    source_ip=packet.get("src_ip"),
                    source_mac=packet.get("src_mac"),
                    packet_info=packet
                )
                
                # Add to history
                self.detection_history.append({
                    "timestamp": result.timestamp,
                    "source_ip": result.source_ip,
                    "source_mac": result.source_mac,
                    "score": result.score,
                    "contributions": result.features_contribution
                })
                
                # Keep limited history
                if len(self.detection_history) > 1000:
                    self.detection_history = self.detection_history[-1000:]
                    
                logger.info(f"Anomaly detected: score={result.score:.4f}, src={result.source_ip}")
                return result
                
            return None
            
        except Exception as e:
            logger.error(f"Error during anomaly detection: {e}")
            return None
            
    def _get_feature_contributions(self, features: np.ndarray) -> Dict[str, float]:
        """Calculate feature contributions to anomaly detection.
        
        Args:
            features: Feature vector
            
        Returns:
            Dictionary mapping feature names to contribution scores
        """
        try:
            # Get reconstruction
            reconstruction = self.detector.model.predict(features)
            
            # Calculate error for each feature
            feature_errors = np.square(features - reconstruction)[0]
            
            # Create contribution dictionary
            contributions = {}
            for i, name in enumerate(self.feature_names):
                if i < len(feature_errors):
                    contributions[name] = float(feature_errors[i])
                    
            return contributions
            
        except Exception as e:
            logger.error(f"Error calculating feature contributions: {e}")
            return {name: 0.0 for name in self.feature_names}
            
    def train(self, packets: List[Dict[str, Any]], is_anomaly: Optional[List[bool]] = None) -> Dict[str, Any]:
        """Train the anomaly detection model.
        
        Args:
            packets: List of packet dictionaries
            is_anomaly: Optional list of labels (if available)
            
        Returns:
            Dictionary with training results
        """
        try:
            # Extract features
            features = np.array([extract_packet_features(packet) for packet in packets])
            
            # Train the model
            history = self.detector.train(
                X_train=features,
                y_train=is_anomaly,  # May be None, that's fine for unsupervised learning
                epochs=self.config.get("ml.anomaly_detection.epochs", 50),
                batch_size=self.config.get("ml.anomaly_detection.batch_size", 32),
                feature_names=self.feature_names
            )
            
            # Save the model
            self.detector.save()
            
            # Set detector ready
            self.detector_ready = True
            
            logger.info(f"Trained anomaly detector on {len(packets)} packets")
            
            return {
                "success": True,
                "training_loss": float(history["loss"][-1]),
                "samples": len(packets),
                "epochs": len(history["loss"])
            }
            
        except Exception as e:
            logger.error(f"Error training anomaly detector: {e}")
            return {
                "success": False,
                "error": str(e)
            }
            
    def get_recent_detections(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent anomaly detections.
        
        Args:
            limit: Maximum number of detections to return
            
        Returns:
            List of recent detection results
        """
        return self.detection_history[-limit:] if self.detection_history else []
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get detection statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            "total_detections": len(self.detection_history),
            "detector_ready": self.detector_ready,
            "last_detection": self.detection_history[-1]["timestamp"] if self.detection_history else None,
            "average_score": np.mean([d["score"] for d in self.detection_history]) if self.detection_history else 0.0
        } 