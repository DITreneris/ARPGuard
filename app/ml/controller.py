"""
ML Controller module for managing machine learning operations.

This module provides a controller interface for machine learning
operations including model training, inference, and management.
"""

import os
import json
import glob
import logging
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union

from app.utils.logger import get_logger
from app.utils.config import get_config
from app.ml.engine import MLEngine
from app.ml.feature_extraction import FeatureExtractor

# Get module logger
logger = get_logger("ml.controller")

class MLController:
    """Controller for machine learning operations.
    
    This class serves as a central controller for all ML-related operations,
    including model training, inference, and management.
    """
    
    def __init__(self):
        """Initialize the ML controller."""
        self.config = get_config()
        self.ml_engine = MLEngine()
        self.feature_extractor = FeatureExtractor()
        
        # Statistics
        self.stats = {
            "packets_analyzed": 0,
            "threats_detected": 0,
            "ml_detections": 0,
            "rule_hits": {},
            "ml_engine": {
                "anomaly_stats": {
                    "detector_ready": False,
                    "total_detections": 0
                },
                "classifier_stats": {
                    "classifier_ready": False,
                    "total_detections": 0
                }
            },
            "training": {
                "training_in_progress": False,
                "collected_samples": 0,
                "last_training": None
            },
            "last_detection": None
        }
        
        # Recent detections (limited to 1000 entries)
        self.detections = []
        self.max_detections = 1000
        
        # Training lock
        self.training_lock = threading.Lock()
        
        # Load models if available
        self._load_models()
        
    def _load_models(self):
        """Load pre-trained models if available."""
        try:
            models_loaded = self.ml_engine.load_models()
            if models_loaded:
                logger.info("Pre-trained models loaded successfully")
                self.stats["ml_engine"]["anomaly_stats"]["detector_ready"] = self.ml_engine.anomaly_detector is not None
                self.stats["ml_engine"]["classifier_stats"]["classifier_ready"] = self.ml_engine.classifier is not None
            else:
                logger.info("No pre-trained models found")
        except Exception as e:
            logger.error(f"Error loading pre-trained models: {e}")
    
    def process_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Process a network packet through the ML pipeline.
        
        Args:
            packet: The packet to process
            
        Returns:
            Dict containing detection results if any
        """
        result = {"detections": []}
        
        try:
            # Extract features
            features = self.feature_extractor.extract_features(packet)
            
            # Update statistics
            self.stats["packets_analyzed"] += 1
            
            # ML analysis enabled?
            if not self.config.get("ml.detection.enabled", True):
                return result
                
            # Process with ML engine
            ml_result = self.ml_engine.process(packet, features)
            
            # If any detections, update stats and store
            if ml_result.get("detections", []):
                detections = ml_result["detections"]
                self.stats["threats_detected"] += len(detections)
                self.stats["ml_detections"] += len(detections)
                
                # Update type-specific stats
                for detection in detections:
                    evidence = detection.get("evidence", {})
                    
                    if evidence.get("detection_type") == "anomaly":
                        self.stats["ml_engine"]["anomaly_stats"]["total_detections"] += 1
                    elif evidence.get("detection_type") == "classification":
                        self.stats["ml_engine"]["classifier_stats"]["total_detections"] += 1
                
                # Store detections
                timestamp = datetime.now().isoformat()
                for detection in detections:
                    detection["timestamp"] = timestamp
                    detection["type"] = "ml_based"
                    self.detections.append(detection)
                    
                # Trim if needed
                if len(self.detections) > self.max_detections:
                    self.detections = self.detections[-self.max_detections:]
                    
                # Update last detection timestamp
                self.stats["last_detection"] = timestamp
                
                # Add to result
                result["detections"].extend(detections)
        
        except Exception as e:
            logger.error(f"Error processing packet with ML: {e}")
            
        return result
    
    def load_sample_data(self) -> Dict[str, Any]:
        """Load sample data and train models.
        
        Returns:
            Dict containing success status and error if any
        """
        result = {"success": False, "error": None}
        
        # Check if training is already in progress
        if self.stats["training"]["training_in_progress"]:
            result["error"] = "Training already in progress"
            return result
            
        # Use training lock to prevent concurrent training
        with self.training_lock:
            try:
                self.stats["training"]["training_in_progress"] = True
                
                # Sample data directories
                base_dir = os.path.join("data", "ml_samples")
                
                # Check if sample data exists
                if not os.path.exists(base_dir):
                    result["error"] = f"Sample data directory not found: {base_dir}"
                    return result
                
                # Load benign samples
                benign_samples = self._load_data_from_directory(os.path.join(base_dir, "benign"))
                
                # Load attack samples
                attack_categories = ["spoofing", "mitm", "dos", "recon"]
                attack_samples = {}
                
                for category in attack_categories:
                    category_samples = self._load_data_from_directory(os.path.join(base_dir, category))
                    if category_samples:
                        attack_samples[category] = category_samples
                
                # Check if we have enough data
                if not benign_samples:
                    result["error"] = "No benign sample data found"
                    return result
                    
                if not attack_samples:
                    result["error"] = "No attack sample data found"
                    return result
                
                # Extract features from data
                X_benign, y_benign = self._extract_features_from_samples(benign_samples, "benign")
                
                X_attack = []
                y_attack = []
                
                for category, samples in attack_samples.items():
                    X_cat, y_cat = self._extract_features_from_samples(samples, category)
                    X_attack.extend(X_cat)
                    y_attack.extend(y_cat)
                
                # Combine data
                X = X_benign + X_attack
                y = y_benign + y_attack
                
                # Train models
                logger.info(f"Training with {len(X)} samples ({len(X_benign)} benign, {len(X_attack)} attack)")
                training_result = self.ml_engine.train(X, y)
                
                if training_result.get("success", False):
                    # Update statistics
                    self.stats["ml_engine"]["anomaly_stats"]["detector_ready"] = True
                    self.stats["ml_engine"]["classifier_stats"]["classifier_ready"] = True
                    self.stats["training"]["last_training"] = datetime.now().isoformat()
                    
                    # Save models
                    self.ml_engine.save_models()
                    
                    result["success"] = True
                    logger.info("ML model training completed successfully")
                else:
                    result["error"] = training_result.get("error", "Unknown training error")
                    logger.error(f"ML model training failed: {result['error']}")
                
            except Exception as e:
                result["error"] = str(e)
                logger.error(f"Error during sample data loading and training: {e}")
            finally:
                self.stats["training"]["training_in_progress"] = False
                
        return result
    
    def _load_data_from_directory(self, directory: str) -> List[Dict[str, Any]]:
        """Load sample data from a directory.
        
        Args:
            directory: Path to the directory containing sample data
            
        Returns:
            List of sample data entries
        """
        samples = []
        
        try:
            if not os.path.exists(directory):
                logger.warning(f"Sample directory not found: {directory}")
                return samples
                
            # Find all JSON files
            json_files = glob.glob(os.path.join(directory, "*.json"))
            
            for file_path in json_files:
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        
                    if isinstance(data, list):
                        samples.extend(data)
                    else:
                        samples.append(data)
                        
                except Exception as e:
                    logger.error(f"Error loading sample file {file_path}: {e}")
                    
            logger.info(f"Loaded {len(samples)} samples from {directory}")
            
        except Exception as e:
            logger.error(f"Error loading samples from directory {directory}: {e}")
            
        return samples
    
    def _extract_features_from_samples(self, samples: List[Dict[str, Any]], label: str) -> Tuple[List[Dict[str, float]], List[str]]:
        """Extract features from sample data.
        
        Args:
            samples: List of sample data entries
            label: Class label for these samples
            
        Returns:
            Tuple of (feature vectors, labels)
        """
        X = []
        y = []
        
        for sample in samples:
            try:
                # Extract features
                features = self.feature_extractor.extract_features(sample)
                
                # Add to dataset
                X.append(features)
                y.append(label)
                
            except Exception as e:
                logger.error(f"Error extracting features from sample: {e}")
                
        return X, y
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current statistics.
        
        Returns:
            Dict containing current statistics
        """
        return self.stats
    
    def get_recent_detections(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent detections.
        
        Args:
            limit: Maximum number of detections to return
            
        Returns:
            List of recent detections
        """
        return self.detections[-limit:] if self.detections else []
    
    def clear_statistics(self):
        """Reset all statistics counters."""
        # Keep model readiness state
        anomaly_ready = self.stats["ml_engine"]["anomaly_stats"]["detector_ready"]
        classifier_ready = self.stats["ml_engine"]["classifier_stats"]["classifier_ready"]
        last_training = self.stats["training"]["last_training"]
        
        # Reset stats
        self.stats = {
            "packets_analyzed": 0,
            "threats_detected": 0,
            "ml_detections": 0,
            "rule_hits": {},
            "ml_engine": {
                "anomaly_stats": {
                    "detector_ready": anomaly_ready,
                    "total_detections": 0
                },
                "classifier_stats": {
                    "classifier_ready": classifier_ready,
                    "total_detections": 0
                }
            },
            "training": {
                "training_in_progress": False,
                "collected_samples": 0,
                "last_training": last_training
            },
            "last_detection": None
        }
        
        # Clear detections
        self.detections = []
        
        logger.info("Statistics and detections cleared")
        
    def collect_sample(self, packet: Dict[str, Any], label: Optional[str] = None):
        """Collect a sample for later training.
        
        Args:
            packet: The packet to collect
            label: Optional label for the sample
        """
        if not self.config.get("ml.training.collect_samples", True):
            return
            
        try:
            # Determine sample category
            category = label if label else "unlabeled"
            
            # Create directory if it doesn't exist
            sample_dir = os.path.join("data", "ml_samples", "collected", category)
            os.makedirs(sample_dir, exist_ok=True)
            
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            filename = f"sample_{timestamp}_{self.stats['training']['collected_samples']}.json"
            filepath = os.path.join(sample_dir, filename)
            
            # Save sample
            with open(filepath, 'w') as f:
                json.dump(packet, f, indent=2)
                
            # Update stats
            self.stats["training"]["collected_samples"] += 1
            
            logger.debug(f"Collected sample saved to {filepath}")
            
        except Exception as e:
            logger.error(f"Error collecting sample: {e}")
            
    def save_state(self):
        """Save controller state."""
        try:
            # Save models if they exist
            self.ml_engine.save_models()
            
            # Save statistics
            stats_dir = os.path.join("data", "ml_stats")
            os.makedirs(stats_dir, exist_ok=True)
            
            stats_path = os.path.join(stats_dir, "ml_controller_stats.json")
            
            with open(stats_path, 'w') as f:
                # Create a copy of stats without large detection history
                stats_copy = self.stats.copy()
                json.dump(stats_copy, f, indent=2)
                
            logger.info("ML controller state saved")
            
        except Exception as e:
            logger.error(f"Error saving ML controller state: {e}")
            
    def load_state(self):
        """Load controller state."""
        try:
            # Load statistics
            stats_path = os.path.join("data", "ml_stats", "ml_controller_stats.json")
            
            if os.path.exists(stats_path):
                with open(stats_path, 'r') as f:
                    loaded_stats = json.load(f)
                    
                # Update stats while preserving current detections
                detections = self.detections
                self.stats.update(loaded_stats)
                self.detections = detections
                
            # Load models
            self._load_models()
            
            logger.info("ML controller state loaded")
            
        except Exception as e:
            logger.error(f"Error loading ML controller state: {e}")