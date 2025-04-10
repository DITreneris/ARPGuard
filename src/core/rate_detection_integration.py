import logging
import time
import threading
from typing import Dict, List, Optional, Any, Callable

from src.core.adaptive_threshold import AdaptiveThreshold, AdaptiveThresholdManager
from src.core.rate_monitor import TrafficRateMonitor, RateDetector
from src.core.alert import AlertManager, Alert, AlertPriority, AlertType

logger = logging.getLogger(__name__)

class AdaptiveRateDetection:
    """
    Integrates adaptive thresholds with rate-based detection to provide
    intelligent anomaly detection capabilities.
    """
    
    def __init__(
        self,
        alert_manager: AlertManager,
        persistence_path: Optional[str] = None,
        threshold_update_interval: float = 5.0,
        monitor_interval: float = 1.0
    ):
        """
        Initialize the adaptive rate detection system.
        
        Args:
            alert_manager: The alert manager to use for sending alerts
            persistence_path: Path to save/load threshold data
            threshold_update_interval: Time in seconds between threshold updates
            monitor_interval: Time in seconds between monitoring checks
        """
        self.alert_manager = alert_manager
        self.persistence_path = persistence_path
        self.threshold_update_interval = threshold_update_interval
        self.monitor_interval = monitor_interval
        
        # Initialize the traffic rate monitor
        self.rate_monitor = TrafficRateMonitor()
        
        # Initialize the adaptive threshold manager
        self.threshold_manager = AdaptiveThresholdManager(
            self.rate_monitor,
            update_interval=threshold_update_interval,
            persistence_path=persistence_path
        )
        
        # Runtime variables
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.last_check_time = 0
        
    def add_interface_detector(self, interface_name: str) -> None:
        """
        Add a detector for a network interface.
        
        Args:
            interface_name: Name of the interface to monitor
        """
        # Add detector to the rate monitor
        self.rate_monitor.add_detector(
            name=f"interface:{interface_name}",
            window_size=60,
            check_interval=self.monitor_interval
        )
        
        # Set up adaptive thresholds for this detector
        self._setup_thresholds_for_detector(f"interface:{interface_name}")
        
        logger.info(f"Added rate detection for interface: {interface_name}")
    
    def _setup_thresholds_for_detector(self, detector_name: str) -> None:
        """
        Set up adaptive thresholds for a detector.
        
        Args:
            detector_name: Name of the detector
        """
        # Warning threshold - adapts quickly to normal traffic
        warning_threshold = AdaptiveThreshold(
            name="warning",
            detector_name=detector_name,
            metric_name="rate", 
            initial_value=500.0,  # Initial packets per second
            min_value=50.0,       # Minimum threshold
            max_value=10000.0,    # Maximum threshold 
            learning_rate=0.1,
            window_size=50,
            adaptation_interval=30,
            std_dev_factor=2.0
        )
        self.threshold_manager.add_threshold(warning_threshold)
        
        # Critical threshold - adapts more slowly, uses high percentile
        critical_threshold = AdaptiveThreshold(
            name="critical",
            detector_name=detector_name,
            metric_name="rate",
            initial_value=1000.0,  # Initial packets per second
            min_value=200.0,       # Minimum threshold
            max_value=20000.0,     # Maximum threshold
            learning_rate=0.05,
            window_size=100,
            adaptation_interval=60,
            use_percentile=True,
            percentile=99.0
        )
        self.threshold_manager.add_threshold(critical_threshold)
        
    def update_packet_count(self, interface_name: str, packet_count: int) -> None:
        """
        Update packet count for an interface.
        
        Args:
            interface_name: Name of the interface
            packet_count: Current packet count
        """
        detector_name = f"interface:{interface_name}"
        self.rate_monitor.update_packet_count(detector_name, packet_count)
    
    def check_thresholds(self) -> None:
        """Check all thresholds and generate alerts as needed."""
        current_time = time.time()
        
        # Skip if not enough time has passed
        if current_time - self.last_check_time < self.monitor_interval:
            return
            
        self.last_check_time = current_time
        
        try:
            # Get current status from rate monitor
            status = self.rate_monitor.get_status()
            
            # Process each detector
            for detector_name, detector_data in status.items():
                self._process_detector_status(detector_name, detector_data)
                
        except Exception as e:
            logger.error(f"Error checking thresholds: {e}")
    
    def _process_detector_status(self, detector_name: str, detector_data: Dict[str, Any]) -> None:
        """
        Process status data for a detector.
        
        Args:
            detector_name: Name of the detector
            detector_data: Status data for the detector
        """
        if "detector_status" not in detector_data:
            return
            
        detector_status = detector_data["detector_status"]
        
        # Get current rate from stats
        if "stats" in detector_status and "current" in detector_status["stats"]:
            current_rate = detector_status["stats"].get("current")
            if current_rate is None:
                return
                
            # Get warning threshold
            warning_threshold = self.threshold_manager.get_threshold_value(
                detector_name, "rate", "warning"
            )
            
            # Get critical threshold
            critical_threshold = self.threshold_manager.get_threshold_value(
                detector_name, "rate", "critical"
            )
            
            # Check against thresholds and generate alerts
            if warning_threshold is not None and critical_threshold is not None:
                self._check_and_alert(
                    detector_name, current_rate, warning_threshold, critical_threshold
                )
    
    def _check_and_alert(
        self, 
        detector_name: str, 
        current_rate: float,
        warning_threshold: float, 
        critical_threshold: float
    ) -> None:
        """
        Check rate against thresholds and generate alerts.
        
        Args:
            detector_name: Name of the detector
            current_rate: Current packet rate
            warning_threshold: Warning threshold value
            critical_threshold: Critical threshold value
        """
        # Extract interface name from detector name
        interface_name = detector_name.split(":", 1)[1] if ":" in detector_name else detector_name
        
        # Check against critical threshold first
        if current_rate >= critical_threshold:
            self.alert_manager.create_alert(
                AlertType.RATE_ANOMALY,
                AlertPriority.CRITICAL,
                f"Critical packet rate detected on {interface_name}: {current_rate:.2f} pps (threshold: {critical_threshold:.2f})",
                source=detector_name,
                details={
                    "interface": interface_name,
                    "current_rate": current_rate,
                    "threshold": critical_threshold,
                    "threshold_type": "critical"
                }
            )
        # Check against warning threshold
        elif current_rate >= warning_threshold:
            self.alert_manager.create_alert(
                AlertType.RATE_ANOMALY,
                AlertPriority.WARNING,
                f"High packet rate detected on {interface_name}: {current_rate:.2f} pps (threshold: {warning_threshold:.2f})",
                source=detector_name,
                details={
                    "interface": interface_name,
                    "current_rate": current_rate,
                    "threshold": warning_threshold,
                    "threshold_type": "warning"
                }
            )
    
    def start(self) -> None:
        """Start the adaptive rate detection system."""
        if self.running:
            return
            
        self.running = True
        
        # Start the threshold manager
        self.threshold_manager.start()
        
        # Start monitoring thread
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        
        logger.info("Started adaptive rate detection system")
    
    def stop(self) -> None:
        """Stop the adaptive rate detection system."""
        if not self.running:
            return
            
        self.running = False
        
        # Stop the threshold manager
        self.threshold_manager.stop()
        
        # Stop the rate monitor
        self.rate_monitor.stop_all()
        
        # Stop the monitoring thread
        if self.thread:
            try:
                self.thread.join(timeout=2)
            except Exception:
                pass
                
        self.thread = None
        
        logger.info("Stopped adaptive rate detection system")
    
    def run(self) -> None:
        """Run the monitoring loop."""
        while self.running:
            try:
                self.check_thresholds()
            except Exception as e:
                logger.error(f"Error in adaptive rate detection: {e}")
                
            # Sleep for a fraction of the monitor interval
            time.sleep(min(0.5, self.monitor_interval / 2))
    
    def get_status(self) -> Dict[str, Any]:
        """Get status information about the adaptive rate detection system."""
        threshold_status = self.threshold_manager.get_status() if self.threshold_manager else {}
        rate_monitor_status = self.rate_monitor.get_status() if self.rate_monitor else {}
        
        return {
            "running": self.running,
            "threshold_update_interval": self.threshold_update_interval,
            "monitor_interval": self.monitor_interval,
            "persistence_path": self.persistence_path,
            "last_check_time": self.last_check_time,
            "thresholds": threshold_status,
            "rate_monitor": rate_monitor_status
        } 