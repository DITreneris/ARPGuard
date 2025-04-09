"""
ML-based classification for ARPGuard detection layer.

This module provides supervised machine learning classification
capabilities for detecting known classes of ARP-based attacks.
"""

import os
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, NamedTuple
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from app.utils.logger import get_logger
from app.utils.config import get_config
from app.ml.packet_converter import extract_packet_features

# Set up module logger
logger = get_logger("ml.detection.ml_based.classifier")

class ClassificationResult(NamedTuple):
    """Result of ML classification."""
    is_attack: bool
    attack_type: str
    probability: float
    confidence: float
    timestamp: datetime
    source_ip: Optional[str]
    source_mac: Optional[str]
    packet_info: Dict[str, Any]

class MLClassifier:
    """Machine learning classifier for network traffic.
    
    This class implements a supervised machine learning approach to
    classify network packets as benign or belonging to specific attack classes.
    """
    
    def __init__(self, model_dir: Optional[str] = None):
        """Initialize the ML classifier.
        
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
            
        # Model paths
        self.model_path = os.path.join(model_dir, "ml_classifier.pkl")
        self.scaler_path = os.path.join(model_dir, "ml_classifier_scaler.pkl")
        
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
        
        # Classification model
        self.model = None
        self.scaler = StandardScaler()
        
        # Class names mapping
        self.class_names = {
            0: "benign",
            1: "arp_spoofing",
            2: "arp_mitm",
            3: "arp_dos",
            4: "reconnaissance"
        }
        
        # Classifier ready flag
        self.classifier_ready = False
        
        # Classification threshold
        self.classification_threshold = self.config.get(
            "ml.classification.threshold", 0.7
        )
        
        # Load model if exists
        self._load_model()
        
    def _initialize_model(self) -> RandomForestClassifier:
        """Initialize the ML classifier model.
        
        Returns:
            Initialized classifier
        """
        # Get model type from config
        model_type = self.config.get("ml.classification.model_type", "random_forest")
        
        if model_type == "gradient_boosting":
            # Initialize Gradient Boosting Classifier
            model = GradientBoostingClassifier(
                n_estimators=self.config.get("ml.classification.n_estimators", 100),
                learning_rate=self.config.get("ml.classification.learning_rate", 0.1),
                max_depth=self.config.get("ml.classification.max_depth", 5),
                random_state=42
            )
        else:
            # Default to Random Forest
            model = RandomForestClassifier(
                n_estimators=self.config.get("ml.classification.n_estimators", 100),
                max_depth=self.config.get("ml.classification.max_depth", 10),
                min_samples_split=self.config.get("ml.classification.min_samples_split", 2),
                random_state=42
            )
            
        logger.info(f"Initialized {model_type} classifier")
        return model
        
    def _load_model(self) -> bool:
        """Load the ML classifier model if it exists.
        
        Returns:
            Boolean indicating if model was loaded successfully
        """
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
                # Load model
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                    
                # Load scaler
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                    
                self.classifier_ready = True
                logger.info("Loaded ML classifier model")
                return True
            else:
                logger.warning("No ML classifier model found, model needs training")
                return False
        except Exception as e:
            logger.error(f"Error loading ML classifier model: {e}")
            return False
            
    def _save_model(self) -> bool:
        """Save the ML classifier model.
        
        Returns:
            Boolean indicating if model was saved successfully
        """
        try:
            if self.model is not None:
                # Save model
                with open(self.model_path, 'wb') as f:
                    pickle.dump(self.model, f)
                    
                # Save scaler
                with open(self.scaler_path, 'wb') as f:
                    pickle.dump(self.scaler, f)
                    
                logger.info("Saved ML classifier model")
                return True
            else:
                logger.warning("No model to save")
                return False
        except Exception as e:
            logger.error(f"Error saving ML classifier model: {e}")
            return False
            
    def classify(self, packet: Dict[str, Any]) -> Optional[ClassificationResult]:
        """Classify a packet using the ML model.
        
        Args:
            packet: Dictionary containing packet data
            
        Returns:
            ClassificationResult if classification successful, None otherwise
        """
        if not self.classifier_ready:
            logger.warning("ML classifier not ready, skipping classification")
            return None
            
        try:
            # Extract features
            features = extract_packet_features(packet)
            
            # Scale features
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            
            # Get prediction and probabilities
            prediction = self.model.predict(features_scaled)[0]
            probabilities = self.model.predict_proba(features_scaled)[0]
            
            # Get class name
            attack_type = self.class_names.get(prediction, "unknown")
            
            # Get highest probability
            confidence = float(probabilities[prediction])
            
            # Create result
            is_attack = prediction > 0 and confidence >= self.classification_threshold
            
            if is_attack:
                result = ClassificationResult(
                    is_attack=is_attack,
                    attack_type=attack_type,
                    probability=float(probabilities[prediction]),
                    confidence=confidence,
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
                    "attack_type": result.attack_type,
                    "probability": result.probability,
                    "confidence": result.confidence
                })
                
                # Keep limited history
                if len(self.detection_history) > 1000:
                    self.detection_history = self.detection_history[-1000:]
                    
                logger.info(f"Classification: {result.attack_type} (conf={result.confidence:.4f}), src={result.source_ip}")
                return result
            
            return None
            
        except Exception as e:
            logger.error(f"Error during ML classification: {e}")
            return None
            
    def train(self, packets: List[Dict[str, Any]], labels: List[int]) -> Dict[str, Any]:
        """Train the ML classifier.
        
        Args:
            packets: List of packet dictionaries
            labels: List of class labels (0=benign, 1+=attack types)
            
        Returns:
            Dictionary with training results
        """
        try:
            # Check data
            if len(packets) != len(labels):
                raise ValueError(f"Number of packets ({len(packets)}) does not match number of labels ({len(labels)})")
                
            if len(packets) < 100:
                logger.warning(f"Training with small dataset ({len(packets)} samples)")
                
            # Extract features
            features = np.array([extract_packet_features(packet) for packet in packets])
            labels = np.array(labels)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                features, labels, test_size=0.2, random_state=42, stratify=labels
            )
            
            # Scale features
            self.scaler.fit(X_train)
            X_train_scaled = self.scaler.transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Initialize model if needed
            if self.model is None:
                self.model = self._initialize_model()
                
            # Train model
            self.model.fit(X_train_scaled, y_train)
            
            # Evaluate model
            y_pred = self.model.predict(X_test_scaled)
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
            recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
            f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
            
            # Save model
            self._save_model()
            
            # Set classifier ready
            self.classifier_ready = True
            
            logger.info(f"Trained ML classifier on {len(packets)} packets "
                       f"(Accuracy: {accuracy:.4f}, F1: {f1:.4f})")
            
            return {
                "success": True,
                "accuracy": float(accuracy),
                "precision": float(precision),
                "recall": float(recall),
                "f1_score": float(f1),
                "samples": len(packets),
                "classes": len(set(labels))
            }
            
        except Exception as e:
            logger.error(f"Error training ML classifier: {e}")
            return {
                "success": False,
                "error": str(e)
            }
            
    def get_recent_detections(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent ML classifications.
        
        Args:
            limit: Maximum number of detections to return
            
        Returns:
            List of recent detection results
        """
        return self.detection_history[-limit:] if self.detection_history else []
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get classification statistics.
        
        Returns:
            Dictionary with statistics
        """
        # Count detections by attack type
        attack_counts = {}
        for detection in self.detection_history:
            attack_type = detection["attack_type"]
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
            
        return {
            "total_detections": len(self.detection_history),
            "classifier_ready": self.classifier_ready,
            "last_detection": self.detection_history[-1]["timestamp"] if self.detection_history else None,
            "attack_distribution": attack_counts,
            "average_confidence": np.mean([d["confidence"] for d in self.detection_history]) if self.detection_history else 0.0
        }
        
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from the ML model.
        
        Returns:
            Dictionary mapping feature names to importance scores
        """
        if not self.classifier_ready or not hasattr(self.model, 'feature_importances_'):
            logger.warning("Feature importance not available")
            return {}
            
        try:
            # Get feature importance
            importance = self.model.feature_importances_
            
            # Map to feature names
            importance_dict = {}
            for i, name in enumerate(self.feature_names):
                if i < len(importance):
                    importance_dict[name] = float(importance[i])
                    
            return importance_dict
            
        except Exception as e:
            logger.error(f"Error getting feature importance: {e}")
            return {} 