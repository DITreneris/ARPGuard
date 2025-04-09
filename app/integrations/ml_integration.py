"""
ML Integration module for ARPGuard.

This module provides integration between the main application and
the ML-based detection layer to enable seamless operation.
"""

import os
import threading
import time
from typing import Dict, List, Any, Optional, Callable

from app.utils.logger import get_logger
from app.utils.config import get_config
from app.ml import MLController
from app.components.ml_detection_view import MLDetectionView

# Get module logger
logger = get_logger('integrations.ml_integration')

class MLIntegration:
    """Integration handler for ML-based detection.
    
    This class handles integration between the main application and 
    the ML-based detection layer, including event handling, UI integration,
    and packet processing flow.
    """
    
    def __init__(self):
        """Initialize the ML integration handler."""
        self.config = get_config()
        self.ml_controller = MLController()
        self.ml_view = None
        
        # Detection callback for UI notification
        self.detection_callback = None
        
        # Monitoring thread for regularly checking detections
        self.monitor_thread = None
        self.monitor_running = False
        self.monitor_interval = 5.0  # Check every 5 seconds
        
        # UI status
        self.ui_status = {
            "detected_threats": 0,
            "last_detection_time": None,
            "packets_processed": 0,
            "ml_status": "Initialized"
        }
        
        logger.info("ML integration initialized")
        
    def get_ui_component(self) -> MLDetectionView:
        """Get the ML detection UI component.
        
        Returns:
            The ML detection view component
        """
        if self.ml_view is None:
            self.ml_view = MLDetectionView(self.ml_controller)
        
        return self.ml_view
    
    def set_detection_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """Set the callback for when a detection occurs.
        
        Args:
            callback: Function to call when a detection occurs
        """
        self.detection_callback = callback
        
    def process_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Process a packet through the ML detection layer.
        
        Args:
            packet: The packet to process
            
        Returns:
            Dictionary with detection results
        """
        # Skip if ML detection is disabled
        if not self.config.get("ml.detection.enabled", True):
            return {"detections": []}
            
        try:
            # Process packet through ML controller
            result = self.ml_controller.process_packet(packet)
            
            # Update UI status
            self.ui_status["packets_processed"] += 1
            
            # If any detections, update stats and notify
            if result.get("detections", []):
                self.ui_status["detected_threats"] += len(result["detections"])
                self.ui_status["last_detection_time"] = time.time()
                
                # Notify through callback if available
                if self.detection_callback:
                    for detection in result["detections"]:
                        self.detection_callback(detection)
                        
                logger.warning(f"ML detection: {len(result['detections'])} threats detected")
                
            return result
            
        except Exception as e:
            logger.error(f"Error processing packet with ML: {e}")
            return {"detections": [], "error": str(e)}
            
    def start_monitoring(self):
        """Start the background monitoring thread."""
        if self.monitor_thread and self.monitor_thread.is_alive():
            logger.warning("Monitoring thread already running")
            return
            
        self.monitor_running = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("ML monitoring thread started")
        
    def stop_monitoring(self):
        """Stop the background monitoring thread."""
        self.monitor_running = False
        
        if self.monitor_thread:
            if self.monitor_thread.is_alive():
                # Wait for thread to terminate (with timeout)
                self.monitor_thread.join(timeout=2.0)
                
            self.monitor_thread = None
            
        logger.info("ML monitoring thread stopped")
            
    def _monitoring_loop(self):
        """Background monitoring loop to check for detections periodically."""
        while self.monitor_running:
            try:
                # Check for recent detections
                recent_detections = self.ml_controller.get_recent_detections(5)
                
                # Update UI if available
                if self.ml_view:
                    # The view has its own update mechanism
                    pass
                    
                # Check training status
                stats = self.ml_controller.get_statistics()
                training_in_progress = stats.get("training", {}).get("training_in_progress", False)
                
                if training_in_progress:
                    self.ui_status["ml_status"] = "Training in progress"
                else:
                    anomaly_ready = stats.get("ml_engine", {}).get("anomaly_stats", {}).get("detector_ready", False)
                    classifier_ready = stats.get("ml_engine", {}).get("classifier_stats", {}).get("classifier_ready", False)
                    
                    if anomaly_ready and classifier_ready:
                        self.ui_status["ml_status"] = "Ready (All models loaded)"
                    elif anomaly_ready:
                        self.ui_status["ml_status"] = "Ready (Anomaly detection only)"
                    elif classifier_ready:
                        self.ui_status["ml_status"] = "Ready (Classification only)"
                    else:
                        self.ui_status["ml_status"] = "Models not trained"
                        
            except Exception as e:
                logger.error(f"Error in ML monitoring thread: {e}")
                
            # Sleep for the specified interval
            time.sleep(self.monitor_interval)
            
    def train_models(self) -> Dict[str, Any]:
        """Train ML models with sample data.
        
        Returns:
            Dictionary with training results
        """
        try:
            logger.info("Starting ML model training")
            
            # Update status
            self.ui_status["ml_status"] = "Training in progress"
            
            # Train models
            result = self.ml_controller.load_sample_data()
            
            # Update status based on result
            if result.get("success", False):
                self.ui_status["ml_status"] = "Ready (Models trained)"
                logger.info("ML model training completed successfully")
            else:
                self.ui_status["ml_status"] = f"Training failed: {result.get('error', 'Unknown error')}"
                logger.error(f"ML model training failed: {result.get('error', 'Unknown error')}")
                
            return result
            
        except Exception as e:
            error_msg = f"Error training ML models: {e}"
            logger.error(error_msg)
            self.ui_status["ml_status"] = f"Error: {str(e)}"
            return {"success": False, "error": error_msg}
            
    def get_status(self) -> Dict[str, Any]:
        """Get current ML integration status.
        
        Returns:
            Dictionary with current status
        """
        # Get ML controller statistics
        ml_stats = self.ml_controller.get_statistics()
        
        # Combine with UI status
        status = {
            **self.ui_status,
            "ml_engine_stats": ml_stats
        }
        
        return status
        
    def save_state(self):
        """Save the ML state."""
        try:
            self.ml_controller.save_state()
            logger.info("ML state saved")
        except Exception as e:
            logger.error(f"Error saving ML state: {e}")
            
    def load_state(self):
        """Load the ML state."""
        try:
            self.ml_controller.load_state()
            logger.info("ML state loaded")
        except Exception as e:
            logger.error(f"Error loading ML state: {e}")
            
    def cleanup(self):
        """Clean up resources used by ML integration."""
        self.stop_monitoring()
        self.save_state()
        logger.info("ML integration cleaned up") 