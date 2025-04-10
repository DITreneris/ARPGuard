import time
import logging
import threading
import math
import multiprocessing
from typing import List, Dict, Any, Optional, Tuple, Callable
import numpy as np
from collections import deque, defaultdict
from .rate_monitor import RateDetector, TrafficRateMonitor

# Constants for optimization
MAX_WORKER_THREADS = min(4, multiprocessing.cpu_count())
DEFAULT_BATCH_SIZE = 100
SAMPLE_WINDOW_SIZE = 10  # Analyze over 10 data points for each sample


class RatePattern:
    """Represents a pattern of network traffic rates."""
    
    def __init__(self, name: str, description: str = ""):
        """
        Initialize rate pattern.
        
        Args:
            name: Pattern name
            description: Pattern description
        """
        self.name = name
        self.description = description
        self.features: Dict[str, Any] = {}
        
    def add_feature(self, name: str, value: Any) -> None:
        """
        Add a feature to the pattern.
        
        Args:
            name: Feature name
            value: Feature value
        """
        self.features[name] = value
        
    def match(self, sample: Dict[str, Any], threshold: float = 0.8) -> Tuple[bool, float]:
        """
        Check if a sample matches this pattern.
        
        Args:
            sample: Sample to check
            threshold: Similarity threshold for a match
            
        Returns:
            Tuple of (match_result, similarity_score)
        """
        # Check if sample has all required features
        if not all(k in sample for k in self.features):
            return False, 0.0
            
        # Calculate similarity
        matches = 0
        total = len(self.features)
        
        for name, value in self.features.items():
            if name not in sample:
                continue
                
            sample_value = sample[name]
            
            # Handle different types of features
            if isinstance(value, (int, float)) and isinstance(sample_value, (int, float)):
                # Numerical values: check if within range
                if isinstance(value, int):
                    # For integers, exact match or +/- 1
                    if abs(sample_value - value) <= 1:
                        matches += 1
                else:
                    # For floats, check if within 10%
                    if abs(sample_value - value) <= 0.1 * abs(value):
                        matches += 1
            elif isinstance(value, str) and isinstance(sample_value, str):
                # String values: exact match
                if sample_value == value:
                    matches += 1
            elif isinstance(value, list) and isinstance(sample_value, list):
                # Lists: check if at least 50% of items match
                list_matches = sum(1 for x in sample_value if x in value)
                if list_matches >= len(value) * 0.5:
                    matches += 1
            elif isinstance(value, dict) and isinstance(sample_value, dict):
                # Dictionaries: check if at least 50% of items match
                dict_matches = sum(1 for k, v in value.items() 
                                 if k in sample_value and sample_value[k] == v)
                if dict_matches >= len(value) * 0.5:
                    matches += 1
            else:
                # Other types: exact match
                if sample_value == value:
                    matches += 1
                    
        similarity = matches / total if total > 0 else 0.0
        return similarity >= threshold, similarity
        
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert pattern to dictionary.
        
        Returns:
            Pattern as dictionary
        """
        return {
            "name": self.name,
            "description": self.description,
            "features": self.features
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RatePattern':
        """
        Create pattern from dictionary.
        
        Args:
            data: Pattern data
            
        Returns:
            Rate pattern object
        """
        pattern = cls(data["name"], data.get("description", ""))
        pattern.features = data.get("features", {})
        return pattern


class PatternLibrary:
    """Manages a collection of rate patterns."""
    
    def __init__(self):
        """Initialize pattern library."""
        self.patterns: Dict[str, RatePattern] = {}
        self.lock = threading.Lock()
        
    def add_pattern(self, pattern: RatePattern) -> None:
        """
        Add a pattern to the library.
        
        Args:
            pattern: Pattern to add
        """
        with self.lock:
            self.patterns[pattern.name] = pattern
            
    def remove_pattern(self, name: str) -> bool:
        """
        Remove a pattern from the library.
        
        Args:
            name: Pattern name
            
        Returns:
            True if pattern was removed, False if it didn't exist
        """
        with self.lock:
            if name in self.patterns:
                del self.patterns[name]
                return True
            return False
            
    def get_pattern(self, name: str) -> Optional[RatePattern]:
        """
        Get a pattern by name.
        
        Args:
            name: Pattern name
            
        Returns:
            Pattern if found, None otherwise
        """
        with self.lock:
            return self.patterns.get(name)
            
    def find_matches(self, sample: Dict[str, Any], 
                   threshold: float = 0.8) -> List[Tuple[RatePattern, float]]:
        """
        Find patterns that match a sample.
        
        Args:
            sample: Sample to check
            threshold: Similarity threshold for matches
            
        Returns:
            List of (pattern, similarity) tuples for matches
        """
        matches = []
        with self.lock:
            for pattern in self.patterns.values():
                is_match, similarity = pattern.match(sample, threshold)
                if is_match:
                    matches.append((pattern, similarity))
                    
        # Sort by similarity score, highest first
        matches.sort(key=lambda x: x[1], reverse=True)
        return matches
        
    def load_default_patterns(self) -> None:
        """Load default set of known patterns."""
        # Define common rate patterns
        
        # Normal traffic pattern
        normal = RatePattern("normal_traffic", "Normal network traffic pattern")
        normal.add_feature("rate_variance", 0.2)  # Low variance
        normal.add_feature("periodic", False)
        normal.add_feature("sudden_spikes", False)
        self.add_pattern(normal)
        
        # DoS attack pattern
        dos = RatePattern("dos_attack", "Denial of Service attack pattern")
        dos.add_feature("rate_variance", 0.8)  # High variance
        dos.add_feature("periodic", False)
        dos.add_feature("sudden_spikes", True)
        dos.add_feature("sustained_high_rate", True)
        self.add_pattern(dos)
        
        # Network scan pattern
        scan = RatePattern("network_scan", "Network scanning pattern")
        scan.add_feature("rate_variance", 0.4)  # Medium variance
        scan.add_feature("periodic", True)
        scan.add_feature("burst_duration", 2)  # Short bursts
        self.add_pattern(scan)
        
        # ARP spoofing pattern
        arp_spoofing = RatePattern("arp_spoofing", "ARP spoofing pattern")
        arp_spoofing.add_feature("periodic", True)
        arp_spoofing.add_feature("arp_request_rate", "high")
        arp_spoofing.add_feature("rate_consistency", "high")
        self.add_pattern(arp_spoofing)
        
        # Backup/transfer pattern
        backup = RatePattern("data_transfer", "Large data transfer pattern")
        backup.add_feature("rate_variance", 0.1)  # Very low variance
        backup.add_feature("periodic", False)
        backup.add_feature("sustained_high_rate", True)
        backup.add_feature("gradual_increase", True)
        self.add_pattern(backup)


class RateAnalyzer:
    """Analyzes network traffic rates to detect patterns and anomalies."""
    
    def __init__(self, 
                rate_monitor: Optional[TrafficRateMonitor] = None,
                batch_size: int = DEFAULT_BATCH_SIZE,
                worker_threads: int = MAX_WORKER_THREADS):
        """
        Initialize rate analyzer.
        
        Args:
            rate_monitor: Traffic rate monitor to use
            batch_size: Number of samples to analyze per batch
            worker_threads: Number of worker threads for parallel processing
        """
        self.rate_monitor = rate_monitor
        self.pattern_library = PatternLibrary()
        self.pattern_library.load_default_patterns()
        
        # Detector storage
        self.detectors: Dict[str, Dict[str, Any]] = {}
        
        # Analysis results cache
        self.results_cache: Dict[str, Dict[str, Any]] = {}
        
        # Thread synchronization
        self.lock = threading.Lock()
        
        # Processing configuration
        self.batch_size = batch_size
        self.worker_threads = min(worker_threads, MAX_WORKER_THREADS)
        
        # Thread pool for parallel processing
        self.thread_pool = None
        if worker_threads > 1:
            try:
                from concurrent.futures import ThreadPoolExecutor
                self.thread_pool = ThreadPoolExecutor(max_workers=self.worker_threads)
            except ImportError:
                logging.warning("ThreadPoolExecutor not available, using single-threaded processing")
        
        # Performance metrics
        self.processing_times: Dict[str, deque] = {}
        self.samples_processed = 0
        self.last_processing_time = 0
        
    def register_detector(self, detector_name: str) -> None:
        """
        Register a detector for analysis.
        
        Args:
            detector_name: Detector name
        """
        with self.lock:
            if detector_name not in self.detectors:
                self.detectors[detector_name] = {
                    "samples": deque(maxlen=1000),  # Store last 1000 samples
                    "last_updated": time.time(),
                    "thresholds": {
                        "rate": 0.0,
                        "variance": 0.0
                    },
                    "analysis": {}
                }
                self.processing_times[detector_name] = deque(maxlen=100)  # Last 100 processing times
                
    def add_sample(self, detector_name: str, sample: Dict[str, Any]) -> None:
        """
        Add a sample to a detector.
        
        Args:
            detector_name: Detector name
            sample: Sample data
        """
        with self.lock:
            if detector_name not in self.detectors:
                self.register_detector(detector_name)
                
            # Add timestamp if not present
            if "timestamp" not in sample:
                sample["timestamp"] = time.time()
                
            # Add to detector samples
            self.detectors[detector_name]["samples"].append(sample)
            self.detectors[detector_name]["last_updated"] = time.time()
            
            # Invalidate results cache for this detector
            if detector_name in self.results_cache:
                del self.results_cache[detector_name]
                
            self.samples_processed += 1
    
    def _process_sample_batch(self, detector_name: str, samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process a batch of samples for a detector.
        
        Args:
            detector_name: Detector name
            samples: List of samples to process
            
        Returns:
            Batch analysis results
        """
        if not samples:
                return {}
                
        result = {}
        
        # Extract rates if present
        rates = [sample.get("rate", 0.0) for sample in samples if "rate" in sample]
        
        if rates:
            # Basic statistics
            avg_rate = sum(rates) / len(rates)
            min_rate = min(rates)
            max_rate = max(rates)
            
            # Calculate variance and standard deviation
            variance = sum((r - avg_rate) ** 2 for r in rates) / len(rates) if len(rates) > 1 else 0.0
            stddev = math.sqrt(variance)
            
            result.update({
                "avg_rate": avg_rate,
                "min_rate": min_rate,
                "max_rate": max_rate,
                "variance": variance,
                "stddev": stddev,
                "sample_count": len(rates)
            })
            
            # Detect rate changes
            if len(rates) > 1:
                changes = [abs(rates[i] - rates[i-1]) for i in range(1, len(rates))]
                avg_change = sum(changes) / len(changes)
                max_change = max(changes)
                
                result.update({
                    "avg_change": avg_change,
                    "max_change": max_change
                })
                
                # Detect patterns
                result["patterns"] = self._detect_patterns(detector_name, rates)
        
        return result
    
    def _detect_patterns(self, detector_name: str, rates: List[float]) -> Dict[str, Any]:
        """
        Detect patterns in a rate series.
        
        Args:
            detector_name: Detector name
            rates: List of rate values
            
        Returns:
            Pattern detection results
        """
        if len(rates) < SAMPLE_WINDOW_SIZE:
            return {}
        
        result = {}
        
        # Check for periodicity using autocorrelation
        try:
            # Use numpy for faster calculations
            rates_array = np.array(rates)
            rates_normalized = rates_array - np.mean(rates_array)
            autocorr = np.correlate(rates_normalized, rates_normalized, mode='full')
            autocorr = autocorr[len(autocorr)//2:]
            
            # Look for peaks in autocorrelation
            if len(autocorr) > 1:
                # Skip first value (autocorrelation with itself is always 1.0)
                peaks = []
                for i in range(1, len(autocorr) - 1):
                    if autocorr[i] > autocorr[i-1] and autocorr[i] > autocorr[i+1]:
                        peaks.append((i, autocorr[i]))
                
                if peaks:
                # Sort by correlation value
                peaks.sort(key=lambda x: x[1], reverse=True)
                    top_peak = peaks[0]
                    
                    result["periodic"] = True
                    result["period"] = top_peak[0]
                    result["correlation"] = float(top_peak[1] / autocorr[0])  # Normalize by autocorr[0]
        except (ImportError, Exception) as e:
            logging.warning(f"Error detecting periodicity: {e}")
        
        # Create sample for pattern matching
        sample = {
            "avg_rate": np.mean(rates),
            "variance": np.var(rates),
            "periodic": result.get("periodic", False),
            "period": result.get("period", 0)
        }
                    
            # Find matching patterns
        matches = self.pattern_library.find_matches(sample)
            if matches:
            result["pattern_matches"] = [
                {
                    "name": pattern.name,
                    "similarity": similarity,
                    "description": pattern.description
                }
                for pattern, similarity in matches
            ]
        
        return result
    
    def analyze_detector(self, detector_name: str) -> Dict[str, Any]:
        """
        Analyze a detector's samples.
        
        Args:
            detector_name: Detector name
            
        Returns:
            Analysis results
        """
        # Check if results are cached
        if detector_name in self.results_cache:
            return self.results_cache[detector_name]
        
        start_time = time.time()
        
        with self.lock:
            if detector_name not in self.detectors:
                return {}
                
            # Get samples
            detector = self.detectors[detector_name]
            samples = list(detector["samples"])
        
        if not samples:
                return {}
                
        result = {
            "timestamp": time.time(),
            "total_samples": len(samples)
        }
        
        # Process in batches
        batches = [samples[i:i+self.batch_size] for i in range(0, len(samples), self.batch_size)]
        
        # Use thread pool for parallel processing if available
        if self.thread_pool:
            batch_results = list(self.thread_pool.map(
                lambda batch: self._process_sample_batch(detector_name, batch),
                batches
            ))
        else:
            # Sequential processing
            batch_results = [self._process_sample_batch(detector_name, batch) for batch in batches]
        
        # Merge batch results
        merged_result = {}
        
        # Calculate statistics across all batches
        all_avg_rates = [br.get("avg_rate", 0.0) for br in batch_results if "avg_rate" in br]
        all_min_rates = [br.get("min_rate", float('inf')) for br in batch_results if "min_rate" in br]
        all_max_rates = [br.get("max_rate", 0.0) for br in batch_results if "max_rate" in br]
        all_variances = [br.get("variance", 0.0) for br in batch_results if "variance" in br]
        all_sample_counts = [br.get("sample_count", 0) for br in batch_results if "sample_count" in br]
        
        if all_avg_rates and all_sample_counts:
            # Weighted average based on sample count
            total_samples = sum(all_sample_counts)
            weighted_avg = sum(avg * count for avg, count in zip(all_avg_rates, all_sample_counts)) / total_samples
            
            merged_result["avg_rate"] = weighted_avg
            merged_result["min_rate"] = min(all_min_rates) if all_min_rates else 0.0
            merged_result["max_rate"] = max(all_max_rates) if all_max_rates else 0.0
            
            # Weighted variance
            merged_result["variance"] = sum(var * count for var, count in zip(all_variances, all_sample_counts)) / total_samples
            merged_result["stddev"] = math.sqrt(merged_result["variance"])
        
        # Merge pattern results
        pattern_matches = []
        for br in batch_results:
            if "patterns" in br and "pattern_matches" in br["patterns"]:
                pattern_matches.extend(br["patterns"]["pattern_matches"])
        
        if pattern_matches:
            # Count pattern frequencies
            pattern_counts = defaultdict(int)
            for match in pattern_matches:
                pattern_counts[match["name"]] += 1
            
            # Include most frequent patterns
            sorted_patterns = sorted(
                [(name, count) for name, count in pattern_counts.items()],
                key=lambda x: x[1],
                reverse=True
            )
            
            merged_result["patterns"] = {
                "top_patterns": [{"name": name, "count": count} for name, count in sorted_patterns[:3]]
            }
        
        result.update(merged_result)
        
        # Calculate processing time
        processing_time = time.time() - start_time
        with self.lock:
            self.processing_times[detector_name].append(processing_time)
            self.last_processing_time = processing_time
        
        # Update result with performance stats
        result["processing_time"] = processing_time
        
        # Cache results
        with self.lock:
            self.results_cache[detector_name] = result
            
            # Update detector analysis
            self.detectors[detector_name]["analysis"] = result
        
        return result
    
    def auto_threshold(self, detector_name: str, sensitivity: float = 1.0) -> Dict[str, float]:
        """
        Calculate automatic thresholds for a detector.
        
        Args:
            detector_name: Detector name
            sensitivity: Sensitivity multiplier (higher = more sensitive)
            
        Returns:
            Dictionary of threshold values
        """
        # Get analysis results
        analysis = self.analyze_detector(detector_name)
        
        if not analysis or "avg_rate" not in analysis:
            return {}
        
        thresholds = {}
        
        # Rate threshold: mean + (stddev * sensitivity)
        if "avg_rate" in analysis and "stddev" in analysis:
            rate_threshold = analysis["avg_rate"] + (analysis["stddev"] * sensitivity)
            thresholds["rate"] = rate_threshold
        
        # Variance threshold
        if "variance" in analysis:
            # Add margin based on sensitivity
            variance_threshold = analysis["variance"] * (1.0 + sensitivity)
            thresholds["variance"] = variance_threshold
        
        # Store in detector
        with self.lock:
            if detector_name in self.detectors:
                self.detectors[detector_name]["thresholds"].update(thresholds)
        
        return thresholds
        
    def analyze_all(self) -> Dict[str, Dict[str, Any]]:
        """
        Analyze all registered detectors.
        
        Returns:
            Dictionary of analysis results per detector
        """
        start_time = time.time()
        results = {}
        
        with self.lock:
            detector_names = list(self.detectors.keys())
        
        # Use thread pool for parallel processing if available
        if self.thread_pool:
            detector_results = list(self.thread_pool.map(
                self.analyze_detector,
                detector_names
            ))
            for name, result in zip(detector_names, detector_results):
                results[name] = result
        else:
            # Sequential processing
            for name in detector_names:
                results[name] = self.analyze_detector(name)
        
        # Add overall processing time
        processing_time = time.time() - start_time
        results["_meta"] = {
            "timestamp": time.time(),
            "processing_time": processing_time,
            "detector_count": len(detector_names)
        }
                
        return results
        
    def update_from_monitor(self) -> bool:
        """
        Update historical data from rate monitor.
        
        Returns:
            True if data was updated, False otherwise
        """
        if not self.rate_monitor:
            return False
            
        # Get status from monitor
        status = self.rate_monitor.get_status()
        
        # Update historical data
        current_time = time.time()
        for detector_name, detector_status in status.items():
            detector_stats = detector_status.get("detector_status", {}).get("stats", {})
            if detector_stats:
                sample = {
                    "timestamp": current_time,
                    "current_rate": detector_stats.get("current"),
                    "mean_rate": detector_stats.get("mean"),
                    "std_rate": detector_stats.get("std"),
                    "packet_count": detector_status.get("packet_counter", 0)
                }
                
                # Only add if we have a valid current rate
                if sample["current_rate"] is not None:
                    self.add_sample(detector_name, sample)
                    
        return True


class AdaptiveThresholdManager:
    """Manages adaptive thresholds that adjust based on traffic patterns."""
    
    def __init__(self, 
                rate_monitor: TrafficRateMonitor,
                rate_analyzer: RateAnalyzer,
                update_interval: int = 300):
        """
        Initialize adaptive threshold manager.
        
        Args:
            rate_monitor: Rate monitor instance
            rate_analyzer: Rate analyzer instance
            update_interval: Threshold update interval in seconds
        """
        self.logger = logging.getLogger('adaptive_threshold_manager')
        self.rate_monitor = rate_monitor
        self.rate_analyzer = rate_analyzer
        self.update_interval = update_interval
        
        # Sensitivity settings
        self.sensitivities: Dict[str, float] = {}
        self.default_sensitivity = 1.0
        
        # Update thread
        self.running = False
        self.thread = None
        self.lock = threading.Lock()
        
        # Callbacks for threshold events
        self.callbacks: Dict[str, Callable[[str, float, float], None]] = {}
        
    def set_sensitivity(self, detector_name: str, sensitivity: float) -> None:
        """
        Set sensitivity for a detector.
        
        Args:
            detector_name: Detector name
            sensitivity: Sensitivity value (higher = more sensitive)
        """
        with self.lock:
            self.sensitivities[detector_name] = max(0.1, min(10.0, sensitivity))
            
    def get_sensitivity(self, detector_name: str) -> float:
        """
        Get sensitivity for a detector.
        
        Args:
            detector_name: Detector name
            
        Returns:
            Sensitivity value
        """
        with self.lock:
            return self.sensitivities.get(detector_name, self.default_sensitivity)
            
    def set_callback(self, 
                    detector_name: str, 
                    callback: Callable[[str, float, float], None]) -> None:
        """
        Set callback for threshold events.
        
        Args:
            detector_name: Detector name
            callback: Callback function
        """
        with self.lock:
            self.callbacks[detector_name] = callback
            
    def start(self) -> None:
        """Start the adaptive threshold manager."""
        with self.lock:
            if self.running:
                self.logger.warning("Adaptive threshold manager is already running")
                return
                
            self.running = True
            self.thread = threading.Thread(target=self._update_loop)
            self.thread.daemon = True
            self.thread.start()
            self.logger.info("Started adaptive threshold manager")
            
    def stop(self) -> None:
        """Stop the adaptive threshold manager."""
        with self.lock:
            if not self.running:
                return
                
            self.running = False
            if self.thread:
                self.thread.join(timeout=2)
                self.thread = None
            self.logger.info("Stopped adaptive threshold manager")
            
    def _update_loop(self) -> None:
        """Update thresholds periodically."""
        while self.running:
            try:
                # Update analyzer data
                self.rate_analyzer.update_from_monitor()
                
                # Update thresholds for all detectors
                for detector_name in self.rate_monitor.detectors.keys():
                    # Get sensitivity
                    sensitivity = self.get_sensitivity(detector_name)
                    
                    # Get callback
                    callback = self.callbacks.get(detector_name)
                    
                    # Apply thresholds
                    self.rate_analyzer.apply_auto_thresholds(
                        detector_name, sensitivity, callback)
                    
            except Exception as e:
                self.logger.error(f"Error in threshold update loop: {e}")
                
            # Sleep until next update
            for _ in range(self.update_interval):
                if not self.running:
                    break
                time.sleep(1)
                
    def update_now(self) -> None:
        """Force an immediate threshold update."""
        try:
            # Update analyzer data
            self.rate_analyzer.update_from_monitor()
            
            # Update thresholds for all detectors
            for detector_name in self.rate_monitor.detectors.keys():
                # Get sensitivity
                sensitivity = self.get_sensitivity(detector_name)
                
                # Get callback
                callback = self.callbacks.get(detector_name)
                
                # Apply thresholds
                self.rate_analyzer.apply_auto_thresholds(
                    detector_name, sensitivity, callback)
                    
        except Exception as e:
            self.logger.error(f"Error in immediate threshold update: {e}")
            
    def get_status(self) -> Dict[str, Any]:
        """
        Get status of adaptive threshold manager.
        
        Returns:
            Dictionary with status information
        """
        status = {
            "running": self.running,
            "update_interval": self.update_interval,
            "default_sensitivity": self.default_sensitivity,
            "sensitivities": dict(self.sensitivities),
            "detectors": {}
        }
        
        # Get analysis results for each detector
        for detector_name in self.rate_monitor.detectors.keys():
            # Get thresholds
            thresholds = self.rate_analyzer.auto_threshold(
                detector_name, self.get_sensitivity(detector_name))
                
            # Get analysis results
            analysis = self.rate_analyzer.results.get(detector_name, {})
            
            status["detectors"][detector_name] = {
                "thresholds": thresholds,
                "analysis": {k: v for k, v in analysis.items() if k != "matching_patterns"}
            }
            
            # Add top pattern match if available
            if "matching_patterns" in analysis and analysis["matching_patterns"]:
                status["detectors"][detector_name]["top_pattern"] = analysis["matching_patterns"][0]
                
        return status 