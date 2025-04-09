"""
ML Detection Engine for ARPGuard.

This module combines anomaly detection and classification
to provide a comprehensive ML-based detection layer.
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, NamedTuple, Set

from app.utils.logger import get_logger
from app.utils.config import get_config
from app.ml.detection.ml_based.anomaly_detection import AnomalyDetectionEngine, AnomalyResult
from app.ml.detection.ml_based.classifier import MLClassifier, ClassificationResult

# Set up module logger
logger = get_logger("ml.detection.ml_based.detection_engine")

class MLDetectionResult(NamedTuple):
    """Result of ML-based detection."""
    is_threat: bool
    timestamp: datetime
    source_ip: Optional[str]
    source_mac: Optional[str]
    detection_type: str  # 'anomaly', 'classification', or 'both'
    anomaly_result: Optional[AnomalyResult]
    classification_result: Optional[ClassificationResult]
    confidence: float
    severity: str
    evidence: Dict[str, Any]

class MLDetectionEngine:
    """Engine for the ML-based detection layer.
    
    This class combines anomaly detection and classification approaches
    to provide a comprehensive ML-based detection layer for ARPGuard.
    """
    
    def __init__(self, model_dir: Optional[str] = None):
        """Initialize the ML detection engine.
        
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
        
        # Initialize sub-engines
        self.anomaly_engine = AnomalyDetectionEngine(model_dir)
        self.classifier = MLClassifier(model_dir)
        
        # Detection history
        self.detection_history = []
        
        # Detection configuration
        self.use_anomaly_detection = self.config.get("ml.detection.use_anomaly", True)
        self.use_classification = self.config.get("ml.detection.use_classification", True)
        self.anomaly_severity = self.config.get("ml.detection.anomaly_severity", "MEDIUM")
        
        # Cache recently seen packets to avoid duplicate detections
        self.recent_detections: Dict[str, Set[str]] = {}  # source_ip -> set of MAC addresses
        self.detection_cache_ttl = self.config.get("ml.detection.cache_ttl", 60)  # seconds
        
        logger.info("Initialized ML Detection Engine")
        
    def detect(self, packet: Dict[str, Any]) -> Optional[MLDetectionResult]:
        """Detect threats using the ML detection layer.
        
        Args:
            packet: Dictionary containing packet data
            
        Returns:
            MLDetectionResult if a threat is detected, None otherwise
        """
        source_ip = packet.get("src_ip")
        source_mac = packet.get("src_mac")
        
        # Skip packet if it was recently detected as a threat
        if self._is_duplicate_detection(source_ip, source_mac):
            return None
        
        # Results from different detection methods
        anomaly_result = None
        classification_result = None
        
        # Run anomaly detection if enabled
        if self.use_anomaly_detection:
            anomaly_result = self.anomaly_engine.detect(packet)
            
        # Run classification if enabled
        if self.use_classification:
            classification_result = self.classifier.classify(packet)
            
        # If neither detected anything, return None
        if not anomaly_result and not classification_result:
            return None
            
        # Determine detection type
        detection_type = "both" if anomaly_result and classification_result else (
            "anomaly" if anomaly_result else "classification"
        )
        
        # Calculate confidence
        confidence = 0.0
        if anomaly_result and classification_result:
            # Both detected, use maximum confidence
            confidence = max(anomaly_result.score, classification_result.confidence)
        elif anomaly_result:
            confidence = anomaly_result.score
        elif classification_result:
            confidence = classification_result.confidence
        
        # Determine severity
        severity = "MEDIUM"  # Default
        if classification_result and anomaly_result:
            severity = "HIGH"  # Both methods detected something, so higher severity
        elif classification_result:
            # Based on the attack type
            attack_severities = {
                "arp_spoofing": "HIGH",
                "arp_mitm": "HIGH",
                "arp_dos": "CRITICAL",
                "reconnaissance": "MEDIUM"
            }
            severity = attack_severities.get(classification_result.attack_type, "MEDIUM")
        elif anomaly_result:
            # Use configured anomaly severity with score adjustment
            if anomaly_result.score > 0.9:
                severity = "HIGH"
            else:
                severity = self.anomaly_severity
                
        # Create evidence dictionary
        evidence = {
            "source_ip": source_ip,
            "source_mac": source_mac,
            "detection_type": detection_type,
            "confidence": confidence
        }
        
        # Add classification evidence if available
        if classification_result:
            evidence.update({
                "attack_type": classification_result.attack_type,
                "classification_confidence": classification_result.confidence
            })
            
        # Add anomaly evidence if available
        if anomaly_result:
            evidence.update({
                "anomaly_score": anomaly_result.score,
                "contributing_features": anomaly_result.features_contribution
            })
            
        # Create final result
        result = MLDetectionResult(
            is_threat=True,
            timestamp=datetime.now(),
            source_ip=source_ip,
            source_mac=source_mac,
            detection_type=detection_type,
            anomaly_result=anomaly_result,
            classification_result=classification_result,
            confidence=confidence,
            severity=severity,
            evidence=evidence
        )
        
        # Record this detection
        self._record_detection(source_ip, source_mac)
        
        # Add to history
        self.detection_history.append({
            "timestamp": result.timestamp,
            "source_ip": result.source_ip,
            "source_mac": result.source_mac,
            "detection_type": result.detection_type,
            "confidence": result.confidence,
            "severity": result.severity
        })
        
        # Keep limited history
        if len(self.detection_history) > 1000:
            self.detection_history = self.detection_history[-1000:]
            
        logger.info(f"ML detection: {result.detection_type} "
                  f"(confidence={result.confidence:.4f}, severity={result.severity}), "
                  f"src={result.source_ip}")
        
        return result
        
    def _is_duplicate_detection(self, source_ip: Optional[str], source_mac: Optional[str]) -> bool:
        """Check if this packet was recently detected as a threat.
        
        Args:
            source_ip: Source IP address
            source_mac: Source MAC address
            
        Returns:
            Boolean indicating if this is a duplicate detection
        """
        if not source_ip or not source_mac:
            return False
            
        # Clean up old entries
        self._cleanup_detection_cache()
        
        # Check if this IP+MAC combination was recently detected
        if source_ip in self.recent_detections and source_mac in self.recent_detections[source_ip]:
            return True
            
        return False
        
    def _record_detection(self, source_ip: Optional[str], source_mac: Optional[str]):
        """Record a detection in the cache.
        
        Args:
            source_ip: Source IP address
            source_mac: Source MAC address
        """
        if not source_ip or not source_mac:
            return
            
        # Add to cache
        if source_ip not in self.recent_detections:
            self.recent_detections[source_ip] = set()
        
        self.recent_detections[source_ip].add(source_mac)
        
    def _cleanup_detection_cache(self):
        """Clean up old entries in the detection cache."""
        # In a real implementation, we would track timestamps and clean up
        # based on TTL. For simplicity, we'll reset the cache when it gets too large.
        if sum(len(macs) for macs in self.recent_detections.values()) > 1000:
            self.recent_detections = {}
            
    def train_models(self, packets: List[Dict[str, Any]], labels: Optional[List[int]] = None) -> Dict[str, Any]:
        """Train all ML models.
        
        Args:
            packets: List of packet dictionaries
            labels: Optional labels for classification (0=benign, 1+=attacks)
            
        Returns:
            Dictionary with training results
        """
        results = {
            "anomaly_training": None,
            "classifier_training": None
        }
        
        # Train anomaly detector (unsupervised)
        if self.use_anomaly_detection:
            try:
                # Anomaly detection doesn't need labels
                results["anomaly_training"] = self.anomaly_engine.train(packets)
                logger.info("Trained anomaly detection model")
            except Exception as e:
                logger.error(f"Error training anomaly detection model: {e}")
                results["anomaly_training"] = {"success": False, "error": str(e)}
                
        # Train classifier (supervised)
        if self.use_classification and labels is not None:
            try:
                results["classifier_training"] = self.classifier.train(packets, labels)
                logger.info("Trained classification model")
            except Exception as e:
                logger.error(f"Error training classification model: {e}")
                results["classifier_training"] = {"success": False, "error": str(e)}
                
        return results
        
    def get_recent_detections(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent ML detections.
        
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
        # Get sub-engine statistics
        anomaly_stats = self.anomaly_engine.get_statistics() if self.use_anomaly_detection else {}
        classifier_stats = self.classifier.get_statistics() if self.use_classification else {}
        
        # Count by detection type
        detection_types = {}
        for detection in self.detection_history:
            dtype = detection["detection_type"]
            detection_types[dtype] = detection_types.get(dtype, 0) + 1
            
        # Count by severity
        severity_counts = {}
        for detection in self.detection_history:
            severity = detection["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
        return {
            "total_detections": len(self.detection_history),
            "anomaly_stats": anomaly_stats,
            "classifier_stats": classifier_stats,
            "detection_types": detection_types,
            "severity_distribution": severity_counts,
            "last_detection": self.detection_history[-1]["timestamp"] if self.detection_history else None,
            "average_confidence": sum(d["confidence"] for d in self.detection_history) / len(self.detection_history) if self.detection_history else 0.0
        } 