import time
import logging
import threading
from typing import List, Dict, Any, Optional, Tuple, Callable
import numpy as np
from collections import deque

class SampleWindow:
    """Sliding window of packet rate samples."""
    
    def __init__(self, window_size: int = 60):
        """
        Initialize sample window.
        
        Args:
            window_size: Maximum number of samples to keep
        """
        self.window_size = window_size
        self.samples = deque(maxlen=window_size)  # (timestamp, count) tuples
        self.lock = threading.Lock()
        
    def add_sample(self, timestamp: float, count: int) -> None:
        """
        Add a new sample to the window.
        
        Args:
            timestamp: Sample timestamp
            count: Packet count
        """
        with self.lock:
            self.samples.append((timestamp, count))
            
    def get_rate(self) -> Optional[float]:
        """
        Calculate current packet rate from samples.
        
        Returns:
            Packets per second or None if insufficient samples
        """
        with self.lock:
            if len(self.samples) < 2:
                return None
                
            first_ts, first_count = self.samples[0]
            last_ts, last_count = self.samples[-1]
            
            time_delta = last_ts - first_ts
            if time_delta <= 0:
                return None
                
            return (last_count - first_count) / time_delta
            
    def get_rates(self) -> List[float]:
        """
        Calculate rates for consecutive sample pairs.
        
        Returns:
            List of rate values for each consecutive pair of samples
        """
        with self.lock:
            if len(self.samples) < 2:
                return []
                
            rates = []
            samples_list = list(self.samples)
            
            for i in range(1, len(samples_list)):
                prev_ts, prev_count = samples_list[i-1]
                curr_ts, curr_count = samples_list[i]
                
                time_delta = curr_ts - prev_ts
                if time_delta > 0:
                    rate = (curr_count - prev_count) / time_delta
                    rates.append(rate)
                    
            return rates
            
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistical information about the sample window.
        
        Returns:
            Dictionary with statistics
        """
        with self.lock:
            rates = self.get_rates()
            
            if not rates:
                return {
                    "count": 0,
                    "min": None,
                    "max": None,
                    "mean": None,
                    "median": None,
                    "std": None,
                    "current": None
                }
                
            return {
                "count": len(rates),
                "min": float(min(rates)),
                "max": float(max(rates)),
                "mean": float(np.mean(rates)),
                "median": float(np.median(rates)),
                "std": float(np.std(rates)),
                "current": float(rates[-1]) if rates else None
            }
            
    def clear(self) -> None:
        """Clear all samples."""
        with self.lock:
            self.samples.clear()


class RateThreshold:
    """Defines a threshold for packet rate detection."""
    
    def __init__(self, 
                rate: float, 
                duration: int = 1,
                direction: str = "above"):
        """
        Initialize rate threshold.
        
        Args:
            rate: Packet rate threshold (packets per second)
            duration: Number of consecutive samples that must exceed the threshold
            direction: "above" or "below" to trigger when rate is above or below threshold
        """
        self.rate = float(rate)
        self.duration = int(duration)
        
        if direction not in ["above", "below"]:
            raise ValueError("Direction must be 'above' or 'below'")
        self.direction = direction
        
        # Internal state
        self.consecutive_hits = 0
        self.triggered = False
        self.last_trigger_time = 0.0
        
    def check(self, rate: float, timestamp: float) -> bool:
        """
        Check if rate exceeds threshold.
        
        Args:
            rate: Current packet rate
            timestamp: Current timestamp
            
        Returns:
            True if threshold is newly triggered, False otherwise
        """
        # Skip if rate is None
        if rate is None:
            self.consecutive_hits = 0
            return False
            
        # Check if rate exceeds threshold
        if ((self.direction == "above" and rate >= self.rate) or
            (self.direction == "below" and rate <= self.rate)):
            # Increment consecutive hits
            self.consecutive_hits += 1
            
            # Check if we've hit the duration and haven't already triggered
            if self.consecutive_hits >= self.duration and not self.triggered:
                self.triggered = True
                self.last_trigger_time = timestamp
                return True
        else:
            # Reset consecutive hits if rate doesn't exceed threshold
            self.consecutive_hits = 0
            
        return False
        
    def reset(self) -> None:
        """Reset threshold state."""
        self.consecutive_hits = 0
        self.triggered = False


class RateDetector:
    """Detects rate-based anomalies in network traffic."""
    
    def __init__(self, 
                window_size: int = 60, 
                check_interval: int = 1):
        """
        Initialize rate detector.
        
        Args:
            window_size: Number of samples to keep in sliding window
            check_interval: Interval between threshold checks (seconds)
        """
        self.logger = logging.getLogger('rate_detector')
        self.window = SampleWindow(window_size)
        self.check_interval = check_interval
        self.thresholds: Dict[str, RateThreshold] = {}
        self.callbacks: Dict[str, Callable] = {}
        self.baseline: Dict[str, float] = {
            "mean": 0.0,
            "std": 0.0,
            "last_update": 0.0
        }
        
        # Monitoring thread
        self.running = False
        self.thread = None
        self.lock = threading.Lock()
        
    def add_threshold(self, 
                     name: str, 
                     rate: float, 
                     duration: int = 1, 
                     direction: str = "above",
                     callback: Optional[Callable[[str, float, float], None]] = None) -> None:
        """
        Add a rate threshold.
        
        Args:
            name: Threshold name
            rate: Rate threshold value
            duration: Duration for consecutive samples
            direction: "above" or "below"
            callback: Optional callback function when threshold is triggered
        """
        with self.lock:
            self.thresholds[name] = RateThreshold(rate, duration, direction)
            if callback:
                self.callbacks[name] = callback
            self.logger.info(f"Added threshold '{name}': {rate} pps, {duration} samples, {direction}")
            
    def remove_threshold(self, name: str) -> bool:
        """
        Remove a threshold.
        
        Args:
            name: Threshold name
            
        Returns:
            True if threshold was removed, False if it didn't exist
        """
        with self.lock:
            if name in self.thresholds:
                del self.thresholds[name]
                if name in self.callbacks:
                    del self.callbacks[name]
                self.logger.info(f"Removed threshold '{name}'")
                return True
            return False
            
    def add_sample(self, timestamp: float, count: int) -> None:
        """
        Add a packet count sample.
        
        Args:
            timestamp: Sample timestamp
            count: Packet count
        """
        self.window.add_sample(timestamp, count)
        
        # Update baseline statistics (every 5 minutes)
        if timestamp - self.baseline["last_update"] > 300:
            self._update_baseline()
            
    def _update_baseline(self) -> None:
        """Update baseline statistics."""
        stats = self.window.get_stats()
        if stats["count"] > 0:
            self.baseline["mean"] = stats["mean"]
            self.baseline["std"] = stats["std"]
            self.baseline["last_update"] = time.time()
            self.logger.debug(f"Updated baseline: mean={self.baseline['mean']:.2f} pps, std={self.baseline['std']:.2f}")
            
    def get_anomaly_score(self) -> float:
        """
        Calculate anomaly score based on deviation from baseline.
        
        Returns:
            Anomaly score (0 = normal, higher = more anomalous)
        """
        current_rate = self.window.get_rate()
        if current_rate is None or self.baseline["std"] == 0:
            return 0.0
            
        # Z-score: how many standard deviations from the mean
        z_score = abs(current_rate - self.baseline["mean"]) / max(self.baseline["std"], 1.0)
        return float(z_score)
        
    def start(self) -> None:
        """Start the rate detector monitoring thread."""
        with self.lock:
            if self.running:
                self.logger.warning("Rate detector is already running")
                return
                
            self.running = True
            self.thread = threading.Thread(target=self._monitoring_loop)
            self.thread.daemon = True
            self.thread.start()
            self.logger.info("Started rate detector monitoring")
            
    def stop(self) -> None:
        """Stop the rate detector monitoring thread."""
        with self.lock:
            if not self.running:
                return
                
            self.running = False
            if self.thread:
                self.thread.join(timeout=2)
                self.thread = None
            self.logger.info("Stopped rate detector monitoring")
            
    def _monitoring_loop(self) -> None:
        """Monitor rates and check thresholds."""
        while self.running:
            try:
                # Get current rate
                current_rate = self.window.get_rate()
                current_time = time.time()
                
                # Check thresholds
                if current_rate is not None:
                    with self.lock:
                        for name, threshold in self.thresholds.items():
                            if threshold.check(current_rate, current_time):
                                self.logger.info(f"Threshold '{name}' triggered: {current_rate:.2f} pps")
                                
                                # Call associated callback if any
                                if name in self.callbacks:
                                    try:
                                        self.callbacks[name](name, current_rate, current_time)
                                    except Exception as e:
                                        self.logger.error(f"Error in threshold callback for '{name}': {e}")
                
            except Exception as e:
                self.logger.error(f"Error in rate monitoring loop: {e}")
                
            # Sleep until next check interval
            time.sleep(self.check_interval)
            
    def reset_all_thresholds(self) -> None:
        """Reset all thresholds."""
        with self.lock:
            for threshold in self.thresholds.values():
                threshold.reset()
                
    def get_status(self) -> Dict[str, Any]:
        """
        Get status of rate detector.
        
        Returns:
            Dictionary with status information
        """
        stats = self.window.get_stats()
        anomaly_score = self.get_anomaly_score()
        
        # Collect threshold statuses
        threshold_statuses = {}
        with self.lock:
            for name, threshold in self.thresholds.items():
                threshold_statuses[name] = {
                    "rate": threshold.rate,
                    "duration": threshold.duration,
                    "direction": threshold.direction,
                    "triggered": threshold.triggered,
                    "consecutive_hits": threshold.consecutive_hits,
                    "last_trigger_time": threshold.last_trigger_time
                }
                
        return {
            "stats": stats,
            "baseline": self.baseline,
            "anomaly_score": anomaly_score,
            "thresholds": threshold_statuses,
            "running": self.running
        }


class TrafficRateMonitor:
    """
    Monitors traffic rates for multiple interfaces or traffic types.
    """
    
    def __init__(self):
        """Initialize traffic rate monitor."""
        self.logger = logging.getLogger('traffic_rate_monitor')
        self.detectors: Dict[str, RateDetector] = {}
        self.packet_counters: Dict[str, int] = {}
        self.last_update_times: Dict[str, float] = {}
        self.lock = threading.Lock()
        
    def add_detector(self, 
                    name: str, 
                    window_size: int = 60, 
                    check_interval: int = 1) -> None:
        """
        Add a rate detector for a specific traffic type.
        
        Args:
            name: Detector name (e.g., interface name)
            window_size: Sample window size
            check_interval: Check interval in seconds
        """
        with self.lock:
            if name in self.detectors:
                self.logger.warning(f"Detector '{name}' already exists")
                return
                
            detector = RateDetector(window_size, check_interval)
            self.detectors[name] = detector
            self.packet_counters[name] = 0
            self.last_update_times[name] = time.time()
            
            # Start detector
            detector.start()
            self.logger.info(f"Added and started detector '{name}'")
            
    def remove_detector(self, name: str) -> bool:
        """
        Remove a rate detector.
        
        Args:
            name: Detector name
            
        Returns:
            True if detector was removed, False if it didn't exist
        """
        with self.lock:
            if name in self.detectors:
                detector = self.detectors[name]
                detector.stop()
                del self.detectors[name]
                
                if name in self.packet_counters:
                    del self.packet_counters[name]
                    
                if name in self.last_update_times:
                    del self.last_update_times[name]
                    
                self.logger.info(f"Removed detector '{name}'")
                return True
            return False
            
    def update_packet_count(self, name: str, count: int) -> None:
        """
        Update packet count for a detector.
        
        Args:
            name: Detector name
            count: Current total packet count
        """
        with self.lock:
            if name not in self.detectors:
                self.logger.warning(f"Detector '{name}' not found")
                return
                
            # Record timestamp
            timestamp = time.time()
            
            # Update detector with sample
            self.detectors[name].add_sample(timestamp, count)
            
            # Update last values
            self.packet_counters[name] = count
            self.last_update_times[name] = timestamp
            
    def add_packets(self, name: str, count: int) -> None:
        """
        Add packets to the counter for a detector.
        
        Args:
            name: Detector name
            count: Number of packets to add
        """
        with self.lock:
            if name not in self.packet_counters:
                self.logger.warning(f"Detector '{name}' not found")
                return
                
            # Add to counter
            self.packet_counters[name] += count
            
            # Update with new total
            self.update_packet_count(name, self.packet_counters[name])
            
    def add_threshold(self, 
                     detector_name: str, 
                     threshold_name: str, 
                     rate: float, 
                     duration: int = 1, 
                     direction: str = "above",
                     callback: Optional[Callable[[str, float, float], None]] = None) -> bool:
        """
        Add a threshold to a detector.
        
        Args:
            detector_name: Detector name
            threshold_name: Threshold name
            rate: Rate threshold
            duration: Duration for consecutive samples
            direction: "above" or "below"
            callback: Callback when threshold is triggered
            
        Returns:
            True if threshold was added, False if detector not found
        """
        with self.lock:
            if detector_name not in self.detectors:
                self.logger.warning(f"Detector '{detector_name}' not found")
                return False
                
            self.detectors[detector_name].add_threshold(
                threshold_name, rate, duration, direction, callback)
            return True
            
    def stop_all(self) -> None:
        """Stop all detectors."""
        with self.lock:
            for name, detector in self.detectors.items():
                detector.stop()
                self.logger.info(f"Stopped detector '{name}'")
                
    def get_status(self) -> Dict[str, Any]:
        """
        Get status of all detectors.
        
        Returns:
            Dictionary with detector statuses
        """
        status = {}
        with self.lock:
            for name, detector in self.detectors.items():
                status[name] = {
                    "detector_status": detector.get_status(),
                    "packet_counter": self.packet_counters.get(name, 0),
                    "last_update_time": self.last_update_times.get(name, 0)
                }
        return status 