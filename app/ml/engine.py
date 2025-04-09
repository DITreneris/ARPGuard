"""
ML Engine module for ARPGuard.

This module implements the core machine learning functionality including
anomaly detection and classification of network traffic.
"""

import os
import json
import pickle
import logging
import numpy as np
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

from app.utils.logger import get_logger

# Get module logger
logger = get_logger("ml.engine")

class MLEngine:
    """Machine learning engine for ARP traffic analysis.
    
    This class provides anomaly detection and classification capabilities
    for identifying malicious ARP traffic patterns.
    """
    
    def __init__(self, model_dir: str = None):
        """Initialize the ML engine.
        
        Args:
            model_dir: Optional directory for model storage
        """
        # Model directory
        self.model_dir = model_dir or os.path.join("data", "ml_models")
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Models
        self.anomaly_detector = None
        self.classifier = None
        self.scaler = None
        
        # Configuration
        self.use_anomaly_detection = True
        self.use_classification = True
        self.anomaly_severity = "MEDIUM"
        self.min_confidence = 0.7
        
        # Feature importance
        self.feature_importance = {}
        
    def process(self, packet: Dict[str, Any], features: Dict[str, float]) -> Dict[str, Any]:
        """Process a packet through the ML pipeline.
        
        Args:
            packet: The packet to analyze
            features: Extracted features from the packet
            
        Returns:
            Dict containing detection results
        """
        result = {"detections": []}
        
        try:
            # Skip if no models are loaded
            if not self.anomaly_detector and not self.classifier:
                return result
                
            # Convert features to array format
            feature_names = sorted(features.keys())
            feature_array = np.array([features[f] for f in feature_names]).reshape(1, -1)
            
            # Scale features if scaler exists
            if self.scaler:
                feature_array = self.scaler.transform(feature_array)
                
            # Anomaly detection
            if self.use_anomaly_detection and self.anomaly_detector:
                anomaly_result = self._detect_anomaly(feature_array, features, packet)
                if anomaly_result:
                    result["detections"].append(anomaly_result)
                    
            # Classification
            if self.use_classification and self.classifier:
                classification_result = self._classify(feature_array, features, packet)
                if classification_result:
                    result["detections"].append(classification_result)
                    
        except Exception as e:
            logger.error(f"Error processing packet with ML: {e}")
            
        return result
    
    def _detect_anomaly(self, feature_array: np.ndarray, features: Dict[str, float], 
                         packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect anomalies in the packet.
        
        Args:
            feature_array: Scaled feature array
            features: Original feature dictionary
            packet: The original packet
            
        Returns:
            Detection result dict if anomaly detected, None otherwise
        """
        try:
            # Get anomaly score (-1 for anomalies, 1 for normal data in IsolationForest)
            score = self.anomaly_detector.decision_function(feature_array)[0]
            
            # Convert to anomaly score (0-1 where 1 is definitely anomalous)
            # IsolationForest returns negative scores for anomalies, so we invert
            anomaly_score = 1 - (score + 1) / 2
            
            # Skip if score is below threshold
            if anomaly_score < self.min_confidence:
                return None
                
            # Create detection
            detection = {
                "confidence": float(anomaly_score),
                "severity": self.anomaly_severity,
                "evidence": {
                    "detection_type": "anomaly",
                    "anomaly_score": float(anomaly_score),
                    "source_ip": packet.get("src_ip"),
                    "source_mac": packet.get("src_mac"),
                    "contributing_features": self._get_contributing_features(features)
                }
            }
            
            logger.info(f"Anomaly detected: score={anomaly_score:.2f}, severity={self.anomaly_severity}")
            return detection
            
        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
            return None
    
    def _classify(self, feature_array: np.ndarray, features: Dict[str, float], 
                  packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Classify the packet type.
        
        Args:
            feature_array: Scaled feature array
            features: Original feature dictionary
            packet: The original packet
            
        Returns:
            Detection result dict if attack detected, None otherwise
        """
        try:
            # Get prediction probabilities
            probs = self.classifier.predict_proba(feature_array)[0]
            
            # Get predicted class
            predicted_class = self.classifier.classes_[np.argmax(probs)]
            max_prob = np.max(probs)
            
            # Skip if benign or confidence is low
            if predicted_class == "benign" or max_prob < self.min_confidence:
                return None
                
            # Map attack type to severity
            severity_map = {
                "spoofing": "HIGH",
                "mitm": "CRITICAL",
                "dos": "MEDIUM",
                "recon": "LOW"
            }
            
            severity = severity_map.get(predicted_class, "MEDIUM")
            
            # Create detection
            detection = {
                "confidence": float(max_prob),
                "severity": severity,
                "evidence": {
                    "detection_type": "classification",
                    "attack_type": predicted_class,
                    "source_ip": packet.get("src_ip"),
                    "source_mac": packet.get("src_mac"),
                    "contributing_features": self._get_contributing_features(features)
                }
            }
            
            logger.info(f"Attack classified: type={predicted_class}, confidence={max_prob:.2f}, severity={severity}")
            return detection
            
        except Exception as e:
            logger.error(f"Error in classification: {e}")
            return None
    
    def _get_contributing_features(self, features: Dict[str, float]) -> Dict[str, float]:
        """Calculate features that most contributed to the detection.
        
        Args:
            features: Feature dictionary
            
        Returns:
            Dict mapping feature names to contribution scores
        """
        # Start with feature importance if available
        contributions = {}
        
        # If we have feature importance data from training
        if self.feature_importance:
            for feature, value in features.items():
                if feature in self.feature_importance:
                    # Combine feature importance with actual value
                    contributions[feature] = abs(value) * self.feature_importance.get(feature, 0.01)
        else:
            # Otherwise just use the feature values (normalized)
            max_val = max(abs(v) for v in features.values()) if features else 1.0
            for feature, value in features.items():
                contributions[feature] = abs(value) / max_val
        
        # Return top 5 features
        sorted_contributions = sorted(contributions.items(), key=lambda x: x[1], reverse=True)
        return dict(sorted_contributions[:5])
    
    def train(self, X: List[Dict[str, float]], y: List[str]) -> Dict[str, Any]:
        """Train the ML models.
        
        Args:
            X: List of feature dictionaries
            y: List of class labels
            
        Returns:
            Dict containing training results
        """
        result = {"success": False, "error": None}
        
        try:
            # Check if we have enough data
            if len(X) < 10 or len(y) < 10:
                result["error"] = f"Not enough training data (got {len(X)} samples)"
                return result
            
            # Convert features to array format
            feature_names = sorted(X[0].keys())
            X_array = np.array([[x[f] for f in feature_names] for x in X])
            
            # Train test split
            X_train, X_test, y_train, y_test = train_test_split(
                X_array, y, test_size=0.2, random_state=42
            )
            
            # Train scaler
            self.scaler = StandardScaler()
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train anomaly detector
            benign_indices = [i for i, label in enumerate(y_train) if label == "benign"]
            X_benign = X_train_scaled[benign_indices]
            
            if len(X_benign) > 0:
                logger.info(f"Training anomaly detector with {len(X_benign)} benign samples")
                self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
                self.anomaly_detector.fit(X_benign)
            else:
                logger.warning("No benign samples available for anomaly detector training")
                
            # Train classifier
            logger.info(f"Training classifier with {len(X_train)} samples")
            self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
            self.classifier.fit(X_train_scaled, y_train)
            
            # Calculate feature importance
            if hasattr(self.classifier, 'feature_importances_'):
                self.feature_importance = {
                    feature: importance 
                    for feature, importance in zip(feature_names, self.classifier.feature_importances_)
                }
            
            # Evaluate
            anomaly_results = {"trained": self.anomaly_detector is not None}
            
            if self.classifier:
                accuracy = self.classifier.score(X_test_scaled, y_test)
                classifier_results = {
                    "accuracy": float(accuracy),
                    "classes": self.classifier.classes_.tolist()
                }
            else:
                classifier_results = {"trained": False}
                
            # Update result
            result.update({
                "success": True,
                "anomaly_detector": anomaly_results,
                "classifier": classifier_results
            })
            
            logger.info(f"Training completed successfully: {result}")
            
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Error training ML models: {e}")
            
        return result
    
    def save_models(self):
        """Save trained models to disk."""
        try:
            # Create model directory if it doesn't exist
            os.makedirs(self.model_dir, exist_ok=True)
            
            # Save anomaly detector
            if self.anomaly_detector:
                anomaly_path = os.path.join(self.model_dir, "anomaly_detector.pkl")
                with open(anomaly_path, 'wb') as f:
                    pickle.dump(self.anomaly_detector, f)
                logger.info(f"Anomaly detector saved to {anomaly_path}")
                
            # Save classifier
            if self.classifier:
                classifier_path = os.path.join(self.model_dir, "classifier.pkl")
                with open(classifier_path, 'wb') as f:
                    pickle.dump(self.classifier, f)
                logger.info(f"Classifier saved to {classifier_path}")
                
            # Save scaler
            if self.scaler:
                scaler_path = os.path.join(self.model_dir, "scaler.pkl")
                with open(scaler_path, 'wb') as f:
                    pickle.dump(self.scaler, f)
                logger.info(f"Scaler saved to {scaler_path}")
                
            # Save feature importance
            if self.feature_importance:
                importance_path = os.path.join(self.model_dir, "feature_importance.json")
                with open(importance_path, 'w') as f:
                    json.dump(self.feature_importance, f, indent=2)
                logger.info(f"Feature importance saved to {importance_path}")
                
            # Save metadata
            metadata = {
                "timestamp": datetime.now().isoformat(),
                "anomaly_detector": self.anomaly_detector is not None,
                "classifier": self.classifier is not None,
                "scaler": self.scaler is not None,
                "feature_importance": bool(self.feature_importance)
            }
            
            metadata_path = os.path.join(self.model_dir, "models_metadata.json")
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
                
            logger.info("ML models saved successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error saving ML models: {e}")
            return False
    
    def load_models(self) -> bool:
        """Load trained models from disk.
        
        Returns:
            True if any models were loaded, False otherwise
        """
        # Check if model directory exists
        if not os.path.exists(self.model_dir):
            logger.warning(f"Model directory not found: {self.model_dir}")
            return False
            
        try:
            # Check if metadata exists
            metadata_path = os.path.join(self.model_dir, "models_metadata.json")
            if not os.path.exists(metadata_path):
                logger.warning("Models metadata not found")
                return False
                
            # Load metadata
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                
            # Load anomaly detector
            if metadata.get("anomaly_detector", False):
                anomaly_path = os.path.join(self.model_dir, "anomaly_detector.pkl")
                if os.path.exists(anomaly_path):
                    with open(anomaly_path, 'rb') as f:
                        self.anomaly_detector = pickle.load(f)
                    logger.info("Anomaly detector loaded")
                    
            # Load classifier
            if metadata.get("classifier", False):
                classifier_path = os.path.join(self.model_dir, "classifier.pkl")
                if os.path.exists(classifier_path):
                    with open(classifier_path, 'rb') as f:
                        self.classifier = pickle.load(f)
                    logger.info("Classifier loaded")
                    
            # Load scaler
            if metadata.get("scaler", False):
                scaler_path = os.path.join(self.model_dir, "scaler.pkl")
                if os.path.exists(scaler_path):
                    with open(scaler_path, 'rb') as f:
                        self.scaler = pickle.load(f)
                    logger.info("Scaler loaded")
                    
            # Load feature importance
            if metadata.get("feature_importance", False):
                importance_path = os.path.join(self.model_dir, "feature_importance.json")
                if os.path.exists(importance_path):
                    with open(importance_path, 'r') as f:
                        self.feature_importance = json.load(f)
                    logger.info("Feature importance loaded")
                    
            # Return success if any model was loaded
            return bool(self.anomaly_detector or self.classifier)
            
        except Exception as e:
            logger.error(f"Error loading ML models: {e}")
            return False 