#!/usr/bin/env python3
"""
Detection Module for ARP Guard
Responsible for detecting ARP spoofing attacks and other malicious ARP activities
"""

import os
import time
import json
import logging
import threading
import multiprocessing
from typing import List, Dict, Any, Optional, Tuple, TypeVar, Generic, Callable
from datetime import datetime, timedelta
import random
from collections import deque, Counter, defaultdict
import queue
import heapq
import psutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s'
)
logger = logging.getLogger(__name__)

try:
    import scapy.all as scapy
    from scapy.layers.l2 import ARP, Ether
except ImportError:
    logger.error("scapy library not found. Install with: pip install scapy")
    scapy = None

# Check for psutil
PSUTIL_AVAILABLE = True
try:
    import psutil
except ImportError:
    logger.warning("psutil library not found. Some optimizations will be disabled.")
    PSUTIL_AVAILABLE = False

# Import the base Module class
from .module import Module
from .remediation_module import RemediationModule

# Constants for optimization
MAX_WORKER_THREADS = min(4, multiprocessing.cpu_count())
PACKET_SAMPLING_RATIO = 0.5  # Sample 50% of packets in high traffic scenarios
HIGH_TRAFFIC_THRESHOLD = 1000  # Packets per second

# Constants for packet prioritization
PRIORITY_HIGH = 0
PRIORITY_MEDIUM = 1
PRIORITY_LOW = 2
PRIORITY_LEVELS = 3

# Constants for TTL values (in seconds)
DEFAULT_ARP_ENTRY_TTL = 3600  # 1 hour
DEFAULT_SUSPICIOUS_SOURCE_TTL = 1800  # 30 minutes
DEFAULT_PACKET_CACHE_TTL = 180  # 3 minutes

# Type variables for generic classes
K = TypeVar('K')
V = TypeVar('V')

# Import the pattern recognition module
from src.core.pattern_recognition import PatternRecognizer


class TTLDict(Generic[K]):
    """A dictionary with TTL (time-to-live) for entries."""
    
    def __init__(self, ttl: int = 3600):
        """
        Initialize TTLDict
        
        Args:
            ttl: Default TTL in seconds
        """
        self._data: Dict[str, Tuple[K, float]] = {}
        self._ttl = ttl
        self._last_cleanup = time.time()
        self._cleanup_interval = 60  # Clean up once per minute
        
    def __contains__(self, key: str) -> bool:
        """Check if key exists and is not expired."""
        if key not in self._data:
            return False
            
        _, expire_time = self._data[key]
        if time.time() > expire_time:
            # Expired, remove it
            del self._data[key]
            return False
            
        return True
        
    def __getitem__(self, key: str) -> K:
        """Get value if exists and not expired."""
        if key not in self:
            raise KeyError(key)
            
        value, _ = self._data[key]
        return value
        
    def get(self, key: str, default: K = None) -> K:
        """Get value with default if not exists or expired."""
        try:
            return self[key]
        except KeyError:
            return default
            
    def __setitem__(self, key: str, value: K) -> None:
        """Set value with default TTL."""
        self._data[key] = (value, time.time() + self._ttl)
        
        # Occasionally clean up expired entries
        if time.time() - self._last_cleanup > self._cleanup_interval:
            self._cleanup()
            
    def set_with_ttl(self, key: str, value: K, ttl: int) -> None:
        """Set value with custom TTL."""
        self._data[key] = (value, time.time() + ttl)
        
    def _cleanup(self) -> None:
        """Remove all expired entries."""
        now = time.time()
        self._data = {k: v for k, v in self._data.items() if v[1] > now}
        self._last_cleanup = now
        
    def items(self):
        """Get (key, value) pairs for non-expired entries."""
        self._cleanup()
        return [(k, v[0]) for k, v in self._data.items()]
        
    def keys(self):
        """Get keys for non-expired entries."""
        self._cleanup()
        return [k for k in self._data.keys() if self.__contains__(k)]
        
    def values(self):
        """Get values for non-expired entries."""
        self._cleanup()
        return [v[0] for k, v in self._data.items() if self.__contains__(k)]
        
    def __len__(self) -> int:
        """Get count of non-expired entries."""
        return len(self.keys())


class DetectionResult:
    """
    Class to store detection results for a specific host
    """
    def __init__(self, mac_address: str, ip_address: str, threat_level: str = "UNKNOWN", details: List[str] = None):
        """
        Initialize detection result
        
        Args:
            mac_address: MAC address of the host
            ip_address: IP address of the host
            threat_level: Threat level (LOW, MEDIUM, HIGH)
            details: Additional details or reasons for the threat assessment
        """
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.threat_level = threat_level
        self.details = details or []
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary
        
        Returns:
            Dictionary representation
        """
        return {
            "mac_address": self.mac_address,
            "ip_address": self.ip_address,
            "threat_level": self.threat_level,
            "details": self.details,
            "timestamp": self.timestamp.isoformat()
        }
    
    def __str__(self) -> str:
        """String representation"""
        return f"{self.mac_address} ({self.ip_address}) - Threat: {self.threat_level}"


class DetectionModuleConfig:
    """
    Configuration for the detection module
    """
    def __init__(
        self,
        detection_interval: int = 5,
        enabled_features: List[str] = None,
        storage_path: str = None,
        max_packet_cache: int = 1000,
        auto_protect: bool = False,
        history_size: int = 10,
        worker_threads: int = MAX_WORKER_THREADS,
        enable_sampling: bool = True,
        sampling_rate: float = PACKET_SAMPLING_RATIO,
        batch_size: int = 50,
        prioritize_packets: bool = True,
        high_priority_ratio: float = 0.8,
        medium_priority_ratio: float = 0.5,
        low_priority_ratio: float = 0.2
    ):
        """
        Initialize configuration
        
        Args:
            detection_interval: Interval in seconds between detection runs
            enabled_features: List of enabled detection features
            storage_path: Path to store detection results
            max_packet_cache: Maximum number of packets to cache
            auto_protect: Whether to automatically protect against attacks
            history_size: Number of entries to keep in detection history
            worker_threads: Number of worker threads for parallel processing
            enable_sampling: Whether to enable packet sampling in high traffic
            sampling_rate: Ratio of packets to sample (0.0-1.0)
            batch_size: Number of packets to process in a batch
            prioritize_packets: Whether to prioritize suspicious packets
            high_priority_ratio: Ratio of high priority packets to process
            medium_priority_ratio: Ratio of medium priority packets to process
            low_priority_ratio: Ratio of low priority packets to process
        """
        self.detection_interval = detection_interval
        self.enabled_features = enabled_features or ["basic", "fingerprint"]
        self.storage_path = storage_path or os.path.join(os.path.expanduser("~"), ".arpguard")
        self.max_packet_cache = max_packet_cache
        self.auto_protect = auto_protect
        self.history_size = history_size
        self.worker_threads = min(worker_threads, MAX_WORKER_THREADS)
        self.enable_sampling = enable_sampling
        self.sampling_rate = max(0.1, min(1.0, sampling_rate))  # Ensure between 0.1 and 1.0
        self.batch_size = batch_size
        self.prioritize_packets = prioritize_packets
        self.high_priority_ratio = max(0.1, min(1.0, high_priority_ratio))
        self.medium_priority_ratio = max(0.1, min(1.0, medium_priority_ratio))
        self.low_priority_ratio = max(0.1, min(1.0, low_priority_ratio))
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary
        
        Returns:
            Dictionary representation
        """
        return {
            "detection_interval": self.detection_interval,
            "enabled_features": self.enabled_features,
            "storage_path": self.storage_path,
            "max_packet_cache": self.max_packet_cache,
            "auto_protect": self.auto_protect,
            "history_size": self.history_size,
            "worker_threads": self.worker_threads,
            "enable_sampling": self.enable_sampling,
            "sampling_rate": self.sampling_rate,
            "batch_size": self.batch_size,
            "prioritize_packets": self.prioritize_packets,
            "high_priority_ratio": self.high_priority_ratio,
            "medium_priority_ratio": self.medium_priority_ratio,
            "low_priority_ratio": self.low_priority_ratio
        }


class PriorityQueue:
    """
    A priority queue implementation for packet processing
    with support for weighted dequeuing based on priority levels
    """
    
    def __init__(self, maxsize=100):
        """
        Initialize the priority queue
        
        Args:
            maxsize: Maximum size of the queue (default: 100)
        """
        self.queues = [[] for _ in range(PRIORITY_LEVELS)]
        self.maxsize = maxsize
        self.lock = threading.Lock()
        self.total_items = 0
        self.stats = {
            "high_priority": 0,
            "medium_priority": 0,
            "low_priority": 0,
            "total_size": 0
        }
    
    def put(self, item, priority=PRIORITY_LOW):
        """
        Add an item to the queue with given priority
        
        Args:
            item: The item to add
            priority: Priority level (0=high, 1=medium, 2=low)
        
        Raises:
            queue.Full: If the queue is full
        """
        with self.lock:
            if self.total_items >= self.maxsize:
                raise queue.Full("Priority queue is full")
            
            # Add the item to the appropriate queue
            self.queues[priority].append((item, priority))
            self.total_items += 1
            
            # Update stats
            if priority == PRIORITY_HIGH:
                self.stats["high_priority"] += 1
            elif priority == PRIORITY_MEDIUM:
                self.stats["medium_priority"] += 1
            else:
                self.stats["low_priority"] += 1
            
            self.stats["total_size"] = self.total_items
    
    def get(self, priority_ratios=None):
        """
        Get an item from the queue based on priority ratios
        
        Args:
            priority_ratios: List of ratios for each priority level [high, medium, low]
                             If None, uses [0.6, 0.3, 0.1]
        
        Returns:
            Tuple of (item, priority) or None if queue is empty
        """
        if priority_ratios is None:
            priority_ratios = [0.6, 0.3, 0.1]  # Default ratios
            
        with self.lock:
            if self.total_items == 0:
                return None
            
            # Determine which queue to pull from based on ratios and current queue state
            # Use weighted random selection based on ratios and queue sizes
            queue_weights = []
            for i, ratio in enumerate(priority_ratios):
                # Weight is ratio * queue size
                if len(self.queues[i]) > 0:
                    queue_weights.append(ratio * len(self.queues[i]))
                else:
                    queue_weights.append(0)
            
            # If all queues are empty, return None
            if sum(queue_weights) == 0:
                return None
            
            # Normalize weights
            total_weight = sum(queue_weights)
            normalized_weights = [w / total_weight for w in queue_weights]
            
            # Choose queue based on weights
            r = random.random()
            cumulative = 0
            selected_queue = len(normalized_weights) - 1  # Default to lowest priority
            
            for i, weight in enumerate(normalized_weights):
                cumulative += weight
                if r <= cumulative:
                    selected_queue = i
                    break
            
            # Get item from selected queue
            if len(self.queues[selected_queue]) > 0:
                item = self.queues[selected_queue].pop(0)
                self.total_items -= 1
                
                # Update stats
                if selected_queue == PRIORITY_HIGH:
                    self.stats["high_priority"] -= 1
                elif selected_queue == PRIORITY_MEDIUM:
                    self.stats["medium_priority"] -= 1
                else:
                    self.stats["low_priority"] -= 1
                
                self.stats["total_size"] = self.total_items
                return item
            
            # If selected queue is empty, try other queues
            for i in range(PRIORITY_LEVELS):
                if len(self.queues[i]) > 0:
                    item = self.queues[i].pop(0)
                    self.total_items -= 1
                    
                    # Update stats
                    if i == PRIORITY_HIGH:
                        self.stats["high_priority"] -= 1
                    elif i == PRIORITY_MEDIUM:
                        self.stats["medium_priority"] -= 1
                    else:
                        self.stats["low_priority"] -= 1
                    
                    self.stats["total_size"] = self.total_items
                    return item
            
            return None
    
    def get_stats(self):
        """Get statistics about the queue"""
        with self.lock:
            return self.stats.copy()
    
    def qsize(self):
        """Get the total size of the queue"""
        with self.lock:
            return self.total_items
    
    def task_done(self):
        """
        Mark a task as done (compatibility with queue.Queue)
        This is a no-op since we don't track tasks separately
        """
        pass


class DetectionModule(Module):
    """
    ARP spoofing detection module for network protection.
    
    This module analyzes network packets to detect potential ARP spoofing attacks,
    using a multi-threaded approach with priority-based packet processing.
    """
    
    def __init__(self, config: DetectionModuleConfig, remediation: Optional[RemediationModule] = None):
        """
        Initialize the detection module.
        
        Args:
            config: Configuration for the detection module
            remediation: Optional remediation module for automatic responses
        """
        super().__init__("detection", "Packet Analysis and ARP Spoofing Detection", config)
        self.config = config
        self.remediation = remediation
        
        # Core state
        self.started_at = time.time()
        self.running = False
        self.active_workers = 0
        
        # Create storage directory if it doesn't exist
        os.makedirs(self.config.storage_path, exist_ok=True)
        
        # Network state - with optimized data structures
        self.packet_cache = deque(maxlen=self.config.max_packet_cache)
        
        # Use more memory-efficient data structures with TTL support
        self.arp_table = TTLDict(ttl=3600)  # Expire entries after 1 hour
        self.mac_vendors = {}  # Lazy loaded
        self._mac_vendors_loaded = False  # Track if we've loaded MAC vendors
        self.suspicious_sources = TTLDict(ttl=86400)  # Expire after 24 hours
        self.gateway_info = {}  # Lazy loaded
        self._gateway_info_loaded = False  # Track if we've loaded gateway info
        
        # Initialize pattern recognition
        self.pattern_recognizer = PatternRecognizer(gateway_detector=self)
        
        # Cache for frequently accessed data
        self._known_safe_sources = set()  # Known safe sources that don't need constant checking
        self._known_safe_ttl = {}
        
        # Network statistics
        self.stats = {
            "packets_processed": 0,
            "arp_packets_processed": 0,
            "suspicious_packets": 0,
            "attack_alerts": 0,
            "false_positives": 0,
            "high_priority_packets": 0,
            "medium_priority_packets": 0,
            "low_priority_packets": 0,
            "dropped_packets": 0,
            "memory_usage": 0,
            "cpu_usage": 0,
            "uptime": 0,
            "last_attack_time": 0,
            "packet_rate": 0,
            "detection_latency": 0,
            "fast_path_hits": 0,
            "quick_reject_hits": 0,
            "pattern_recognition_hits": 0
        }
        
        # Recent packet rate tracking
        self.packet_count_history = deque(maxlen=self.config.history_size)
        self.last_packet_time = time.time()
        self.adaptive_sampling = False
        
        # Processing state
        self.worker_threads: List[threading.Thread] = []
        self.work_queue = PriorityQueue(maxsize=config.max_packet_cache)
        self.result_queue: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        
        # Priority thresholds and ratios
        self.priority_ratios = [
            self.config.high_priority_ratio,
            self.config.medium_priority_ratio,
            self.config.low_priority_ratio
        ]
        
        # Don't load vendor/gateway data immediately - lazy load
        # This improves startup time
        logger.info(f"Detection module initialized with {config.worker_threads} workers and pattern recognition")
    
    def start(self) -> None:
        """Start the detection module and worker threads"""
        if self.running:
            logger.warning("Detection module already running")
            return
            
        self.running = True
        self.started_at = time.time()
        self.stop_event.clear()
        
        # Start worker threads
        for i in range(self.config.worker_threads):
            worker = threading.Thread(
                target=self._worker_thread,
                name=f"detection-worker-{i}",
                daemon=True
            )
            worker.start()
            self.worker_threads.append(worker)
            self.active_workers += 1
            
        # Start result collector thread
        self.collector_thread = threading.Thread(
            target=self._collect_results,
            name="detection-collector",
            daemon=True
        )
        self.collector_thread.start()
        
        logger.info(f"Detection module started with {self.active_workers} workers")
    
    def stop(self) -> None:
        """Stop the detection module and worker threads"""
        if not self.running:
            logger.warning("Detection module not running")
            return
        
        logger.info("Stopping detection module...")
        self.running = False
        self.stop_event.set()
        
        # Wait for worker threads to finish
        for worker in self.worker_threads:
            if worker.is_alive():
                worker.join(timeout=1.0)
                
        # Clear queues
        while not self.work_queue.empty():
            try:
                self.work_queue.get(block=False)
                self.work_queue.task_done()
            except queue.Empty:
                break
                
        while not self.result_queue.empty():
            try:
                self.result_queue.get(block=False)
                self.result_queue.task_done()
            except queue.Empty:
                break
                
        self.worker_threads = []
        self.active_workers = 0
        logger.info("Detection module stopped")
        
    def process_packet(self, packet: scapy.Packet) -> None:
        """
        Process a single packet
        
        Args:
            packet: Scapy packet to process
        """
        # Update packet stats
        if "packets_received" not in self.stats:
            # Initialize missing statistics fields
            self.stats.update({
                "packets_received": 0,
                "last_rate_update": time.time(),
                "last_packet_count": 0,
                "packet_rate_samples": [],
                "avg_packet_rate": 0,
                "last_thread_adjustment": 0,
                "priority_distribution": {
                    PRIORITY_HIGH: 0,
                    PRIORITY_MEDIUM: 0,
                    PRIORITY_LOW: 0
                }
            })
            
        self.stats["packets_received"] += 1
        
        # Calculate packet rates periodically
        current_time = time.time()
        if current_time - self.stats["last_rate_update"] >= 1.0:
            # Calculate packet rate over the last second
            rate = self.stats["packets_received"] - self.stats.get("last_packet_count", 0)
            self.stats["packet_rate_samples"].append(rate)
            
            # Keep only recent samples (last minute)
            while len(self.stats["packet_rate_samples"]) > 60:
                self.stats["packet_rate_samples"].pop(0)
                
            self.stats["avg_packet_rate"] = sum(self.stats["packet_rate_samples"]) / len(self.stats["packet_rate_samples"])
            self.stats["last_packet_count"] = self.stats["packets_received"]
            self.stats["last_rate_update"] = current_time
            
            # Adjust worker threads based on load if needed
            if PSUTIL_AVAILABLE and current_time - self.stats.get("last_thread_adjustment", 0) >= 30:
                self._adjust_worker_threads()
                self.stats["last_thread_adjustment"] = current_time
        
        # Quick reject check
        if self._should_quick_reject(packet):
            return
        
        # Fast path for common packet patterns
        if self._is_fast_path_eligible(packet):
            # Update last seen timestamp but skip detailed analysis
            if packet.haslayer(scapy.ARP):
                arp = packet.getlayer(scapy.ARP)
                if arp.psrc in self.arp_table:
                    self.arp_table[arp.psrc]["last_seen"] = current_time
                    self.arp_table[arp.psrc]["count"] += 1
            return
            
        # Determine packet priority
        priority = self._determine_packet_priority(packet)
        self.stats["priority_distribution"][priority] += 1
        
        # Add packet to appropriate queue with timestamp
        if self.running:
            try:
                self.work_queue.put((packet, current_time), priority=priority)
            except queue.Full:
                logger.warning(f"Queue {priority} is full, dropping packet")
                self.stats["dropped_packets"] += 1
                
                # If high priority queue is full, this is serious - adjust worker threads
                if priority == PRIORITY_HIGH:
                    self._adjust_worker_threads(force_increase=True)
                    
    def process_packet_batch(self, packets: List[scapy.Packet]) -> None:
        """
        Process a batch of packets for more efficient handling
        
        Args:
            packets: List of packets to process
        """
        if not packets:
            return
            
        # First sort packets by estimated priority
        prioritized_packets = []
        for packet in packets:
            priority = self._determine_packet_priority(packet)
            prioritized_packets.append((packet, priority))
            
        # Sort by priority (highest/lowest number first)
        prioritized_packets.sort(key=lambda x: x[1])
        
        # Process in priority order
        for packet, priority in prioritized_packets:
            self.process_packet(packet)
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get detection module statistics and status
        
        Returns:
            Dictionary with current statistics
        """
        current_time = time.time()
        
        # Update dynamic statistics
        self.stats["uptime"] = current_time - self.started_at
        
        if PSUTIL_AVAILABLE:
            try:
                process = psutil.Process(os.getpid())
                self.stats["cpu_usage"] = process.cpu_percent()
                self.stats["memory_usage"] = process.memory_info().rss / (1024 * 1024)  # MB
            except:
                pass
        
        # Add pattern recognition stats if available
        if hasattr(self, 'pattern_recognizer'):
            pattern_stats = self.pattern_recognizer.get_stats()
            for key, value in pattern_stats.items():
                self.stats[f"pattern_{key}"] = value
        
        return self.stats.copy()
    
    def get_suspicious_sources(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all suspicious sources detected
        
        Returns:
            Dictionary of suspicious sources with metadata
        """
        return self.suspicious_sources.copy()
    
    def get_arp_table(self) -> Dict[str, Dict[str, Any]]:
        """
        Get the current ARP table
        
        Returns:
            Dictionary of IP to MAC mappings with metadata
        """
        return self.arp_table.copy()
    
    def reset_stats(self) -> None:
        """Reset all module statistics"""
        current_time = time.time()
        self.stats = {
            "packets_processed": 0,
            "arp_packets_processed": 0,
            "suspicious_packets": 0,
            "attack_alerts": 0,
            "false_positives": 0,
            "high_priority_packets": 0, 
            "medium_priority_packets": 0,
            "low_priority_packets": 0,
            "dropped_packets": 0,
            "memory_usage": 0,
            "cpu_usage": 0,
            "uptime": current_time - self.started_at,
            "last_attack_time": 0,
            "packet_rate": 0,
            "detection_latency": 0,
            "fast_path_hits": 0,
            "quick_reject_hits": 0,
            "pattern_recognition_hits": 0
        }
        self.packet_count_history.clear()
        self.last_packet_time = current_time
        
    def _load_mac_vendors(self) -> None:
        """Load MAC vendor information from file (lazy loading)"""
        # If already loaded, skip
        if self._mac_vendors_loaded:
            return
            
        vendor_file = os.path.join(self.config.storage_path, "mac_vendors.json")
        try:
            if os.path.exists(vendor_file):
                with open(vendor_file, "r") as f:
                    self.mac_vendors = json.load(f)
                logger.info(f"Loaded {len(self.mac_vendors)} MAC vendors from {vendor_file}")
            else:
                logger.warning(f"MAC vendor file not found: {vendor_file}")
                
            # Mark as loaded
            self._mac_vendors_loaded = True
        except Exception as e:
            logger.error(f"Error loading MAC vendors: {e}")
    
    def _load_gateway_info(self) -> None:
        """Load gateway information from configuration (lazy loading)"""
        # If already loaded, skip
        if self._gateway_info_loaded:
            return
            
        try:
            gateway_file = os.path.join(self.config.storage_path, "gateway_info.json")
            if os.path.exists(gateway_file):
                with open(gateway_file, "r") as f:
                    self.gateway_info = json.load(f)
                    logger.info(f"Loaded gateway info: {self.gateway_info['ip']} ({self.gateway_info['mac']})")
            else:
                # Default gateway info if file doesn't exist
                self.gateway_info = {
                    "ip": self.config.default_gateway_ip,
                    "mac": self.config.default_gateway_mac,
                    "last_seen": time.time(),
                    "verified": False
                }
                logger.warning(f"Using default gateway info: {self.gateway_info['ip']} ({self.gateway_info['mac']})")
                
            # Mark as loaded
            self._gateway_info_loaded = True
        except Exception as e:
            logger.error(f"Error loading gateway info: {e}")
            # Fallback to defaults
            self.gateway_info = {
                "ip": self.config.default_gateway_ip,
                "mac": self.config.default_gateway_mac,
                "last_seen": time.time(),
                "verified": False
            }
            
            # Still mark as loaded (with defaults)
            self._gateway_info_loaded = True
    
    def _save_gateway_info(self) -> None:
        """Save gateway information to file"""
        try:
            gateway_file = os.path.join(self.config.storage_path, "gateway_info.json")
            with open(gateway_file, "w") as f:
                json.dump(self.gateway_info, f, indent=2)
            logger.debug(f"Saved gateway info to {gateway_file}")
        except Exception as e:
            logger.error(f"Error saving gateway info: {e}")
    
    def _worker_thread(self) -> None:
        """Worker thread for processing packets from the queue"""
        logger.debug(f"Worker thread {threading.current_thread().name} started")
        
        while not self.stop_event.is_set():
            try:
                # Get work item from queue with priority weighting
                work_item = self.work_queue.get(priority_ratios=self.priority_ratios)
                if work_item is None:
                    # Sleep briefly if no work available
                    time.sleep(0.01)
                    continue
                    
                packet, timestamp = work_item[0]
                priority = work_item[1]
                
                # Process the packet
                result = self._analyze_packet(packet, priority, timestamp)
                
                # Put result in result queue if meaningful
                if result:
                    self.result_queue.put(result)
                    
            except queue.Empty:
                # Sleep briefly if no work available
                time.sleep(0.01)
                
            except Exception as e:
                logger.error(f"Error in worker thread: {e}")
    
        logger.debug(f"Worker thread {threading.current_thread().name} stopped")
        
    def _analyze_packet(self, packet: scapy.Packet, priority: int, timestamp: float) -> Optional[Dict[str, Any]]:
        """
        Analyze a packet for ARP spoofing detection
        
        Args:
            packet: Scapy packet to analyze
            priority: Priority level of the packet
            timestamp: Time when packet was received
            
        Returns:
            Detection result or None if no issue detected
        """
        # Calculate processing latency
        latency = time.time() - timestamp
        self.stats["detection_latency"] = (self.stats["detection_latency"] + latency) / 2
        
        # Quick rejection filter - bail out early for packets that are clearly not interesting
        if self._should_quick_reject(packet):
            return None
            
        # Check if packet contains ARP layer
        if not packet.haslayer(scapy.ARP):
            return None
            
        # Increment ARP packet counter
        self.stats["arp_packets_processed"] += 1
        
        # Extract ARP fields
        arp = packet.getlayer(scapy.ARP)
        src_ip = arp.psrc
        src_mac = arp.hwsrc
        dst_ip = arp.pdst
        dst_mac = arp.hwdst
        op_code = arp.op
        
        # Skip packets with empty or broadcast addresses
        if not src_ip or not src_mac or src_ip == "0.0.0.0" or src_mac == "00:00:00:00:00:00":
            return None
            
        # Check if this is a gateway (lazy-load gateway info if needed)
        if not self._gateway_info_loaded:
            self._load_gateway_info()
            
        is_gateway = (src_ip == self.gateway_info.get("ip")) or (src_mac == self.gateway_info.get("mac"))
        
        # Update ARP table
        if src_ip not in self.arp_table:
            self.arp_table[src_ip] = {
                "mac": src_mac,
                "first_seen": time.time(),
                "last_seen": time.time(),
                "count": 1,
                "is_gateway": is_gateway,
                "op_codes": Counter([op_code])
            }
        else:
            # Existing IP in table
            existing_entry = self.arp_table[src_ip]
            existing_entry["last_seen"] = time.time()
            existing_entry["count"] += 1
            existing_entry["op_codes"][op_code] += 1
            
            # Quick check for MAC change - potential spoofing
            if existing_entry["mac"] != src_mac:
                # This is suspicious - the MAC for an IP has changed
                suspicious = {
                    "timestamp": time.time(),
                    "src_ip": src_ip,
                    "old_mac": existing_entry["mac"],
                    "new_mac": src_mac,
                    "op_code": op_code,
                    "packet": packet,
                    "confidence": 0.7,  # Initial confidence
                    "priority": priority
                }
                
                # Update ARP table with new MAC
                existing_entry["mac"] = src_mac
                existing_entry["changes"] = existing_entry.get("changes", 0) + 1
                
                # Return suspicious activity
                return suspicious
        
        # Also run the packet through pattern recognition for advanced detection
        pattern_packet = {
            "src_mac": src_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_mac": dst_mac,
            "op_code": op_code,
            "timestamp": timestamp,
            "priority": priority
        }
        
        pattern_result = self.pattern_recognizer.process_packet(pattern_packet)
        
        if pattern_result:
                    # Update statistics
            self.stats["pattern_recognition_hits"] += 1
            
            # Convert to our result format
            suspicious = {
                "timestamp": pattern_result.get("timestamp", time.time()),
                "src_ip": pattern_result.get("ip", src_ip),
                "src_mac": pattern_result.get("mac", src_mac),
                "old_mac": pattern_result.get("previous_macs", [None])[0] if "previous_macs" in pattern_result else None,
                "new_mac": pattern_result.get("new_mac", src_mac),
                "pattern_type": pattern_result.get("type", "unknown"),
                "description": pattern_result.get("description", "Advanced pattern detected"),
                "confidence": pattern_result.get("confidence", 0.7),
                "priority": priority,
                "details": pattern_result
            }
            
            return suspicious
                
        return None
    
    def _should_quick_reject(self, packet: scapy.Packet) -> bool:
        """
        Quick rejection filter to bail out early for packets that are clearly not interesting.
        
        Args:
            packet: Packet to check
            
        Returns:
            True if packet should be rejected, False otherwise
        """
        # Track number of quick rejects for stats
        rejected = False
        
        # Not an ARP packet
        if not packet.haslayer(scapy.ARP):
            rejected = True
        else:
            arp = packet.getlayer(scapy.ARP)
            
            # Invalid source addresses
            if (not arp.psrc or 
                arp.psrc == "0.0.0.0" or 
                not arp.hwsrc or 
                arp.hwsrc == "00:00:00:00:00:00"):
                rejected = True
                
            # Invalid destination addresses for ARP replies
            elif (arp.op == 2 and  # ARP reply (is-at)
                  (not arp.pdst or 
                   arp.pdst == "0.0.0.0" or 
                   not arp.hwdst or 
                   arp.hwdst == "00:00:00:00:00:00" or 
                   arp.hwdst == "ff:ff:ff:ff:ff:ff")):
                rejected = True
                
            # Known safe source
            elif arp.psrc in self._known_safe_sources:
                rejected = True
        
        if rejected:
            self.stats["quick_reject_hits"] += 1
            
        return rejected
        
    def _is_fast_path_eligible(self, packet: scapy.Packet) -> bool:
        """
        Check if packet is eligible for fast path processing
        
        Args:
            packet: Packet to check
            
        Returns:
            True if packet can be processed via fast path
        """
        if not packet.haslayer(scapy.ARP):
            return False
            
        arp = packet.getlayer(scapy.ARP)
        src_ip = arp.psrc
        
        # ARP request (who-has) from non-suspicious source
        if (arp.op == 1 and 
            src_ip not in self.suspicious_sources and
            src_ip in self.arp_table and
            self.arp_table.get(src_ip, {}).get("count", 0) > 5):
            self.stats["fast_path_hits"] += 1
            return True
            
        # Recent ARP reply with consistent data
        if (arp.op == 2 and 
            src_ip in self.arp_table and
            self.arp_table[src_ip].get("mac") == arp.hwsrc and
            self.arp_table[src_ip].get("count", 0) > 10 and
            src_ip not in self.suspicious_sources):
            self.stats["fast_path_hits"] += 1
            return True
            
        return False
    
    def _collect_results(self) -> None:
        """Collect and process results from worker threads"""
        logger.debug("Result collector thread started")
        
        while not self.stop_event.is_set():
            try:
                # Get result from queue with 0.1s timeout
                result = self.result_queue.get(timeout=0.1)
                
                # Process the suspicious activity
                src_ip = result["src_ip"]
                new_mac = result["new_mac"]
                old_mac = result["old_mac"]
                confidence = result["confidence"]
                
                # Mark as suspicious
                self.stats["suspicious_packets"] += 1
                
                # Check if this is a known suspicious source
                if src_ip in self.suspicious_sources:
                    # Update existing entry
                    entry = self.suspicious_sources[src_ip]
                    entry["last_seen"] = time.time()
                    entry["count"] += 1
                    entry["confidence"] = min(0.99, entry["confidence"] + 0.1)  # Increase confidence
                    
                    # Add to MAC history if not already there
                    if new_mac not in entry["mac_history"]:
                        entry["mac_history"].append(new_mac)
                        
                    # Check alert threshold
                    if entry["count"] >= self.config.detection_threshold and not entry["alerted"]:
                        entry["alerted"] = True
                        self.stats["attack_alerts"] += 1
                        self.stats["last_attack_time"] = time.time()
                        
                        # Create alert with high confidence
                        alert = {
                            "timestamp": time.time(),
                            "src_ip": src_ip,
                            "mac_addresses": entry["mac_history"],
                            "count": entry["count"],
                            "confidence": entry["confidence"],
                            "message": f"ARP spoofing detected - IP {src_ip} using multiple MAC addresses"
                        }
                        
                        # Log alert
                        logger.warning(f"ARP SPOOF ALERT: {alert['message']} (confidence: {alert['confidence']:.2f})")
                        
                        # Send to remediation if available
                        if self.remediation:
                            self.remediation.handle_detection(alert)
                else:
                    # New suspicious source
                    self.suspicious_sources[src_ip] = {
                        "first_seen": time.time(),
                        "last_seen": time.time(),
                        "count": 1,
                        "mac_history": [old_mac, new_mac],
                        "confidence": confidence,
                        "alerted": False
                    }
                    
                    logger.info(f"New suspicious source: {src_ip} changed MAC from {old_mac} to {new_mac}")
                    
                # Mark task as done
                self.result_queue.task_done()
                
            except queue.Empty:
                # No results, sleep briefly
                time.sleep(0.01)
            except Exception as e:
                logger.error(f"Error in result collector: {e}")
                
        logger.debug("Result collector thread stopped")
    
    def _determine_packet_priority(self, packet: scapy.Packet) -> int:
        """
        Determine processing priority for a packet
        
        Args:
            packet: Packet to prioritize
            
        Returns:
            Priority level (PRIORITY_HIGH, PRIORITY_MEDIUM, PRIORITY_LOW)
        """
        if not packet.haslayer(scapy.ARP):
            return PRIORITY_LOW
            
        arp = packet.getlayer(scapy.ARP)
        
        # High priority cases
        if any([
            # ARP announcements/gratuitous ARP
            arp.op == 2 and arp.pdst == "0.0.0.0",  
            
            # Gateway IP involved
            arp.psrc in self._get_gateway_ips() or arp.pdst in self._get_gateway_ips(),
            
            # Known suspicious source
            arp.psrc in self.suspicious_sources,
            
            # IP conflict with different MAC
            arp.psrc in self.arp_table and self.arp_table[arp.psrc]["mac"] != arp.hwsrc
        ]):
            return PRIORITY_HIGH
            
        # Medium priority cases    
        if any([
            # ARP reply (is-at)
            arp.op == 2,
            
            # New IP not in ARP table
            arp.psrc not in self.arp_table,
            
            # Target is in our suspicious list
            arp.pdst in self.suspicious_sources
        ]):
            return PRIORITY_MEDIUM
            
        # All other cases (primarily normal ARP requests)
        return PRIORITY_LOW
    
    def _adjust_sampling_rate(self) -> None:
        """Dynamically adjust packet sampling rate based on traffic load"""
        current_rate = self.stats["packet_rate"]
        
        # If packet rate exceeds threshold, enable adaptive sampling
        if current_rate > self.config.high_traffic_threshold:
            if not self.adaptive_sampling:
                logger.info(f"Enabling adaptive sampling due to high traffic ({current_rate:.2f} pps)")
                self.adaptive_sampling = True
                
            # Adjust sampling rate based on load
            # Lower sampling rate as traffic increases
            traffic_ratio = min(1.0, self.config.high_traffic_threshold / current_rate)
            self.config.sampling_rate = max(0.1, traffic_ratio * self.config.sampling_rate)
            
        elif self.adaptive_sampling and current_rate < self.config.high_traffic_threshold * 0.8:
            # Return to normal sampling when traffic decreases
            logger.info(f"Disabling adaptive sampling due to reduced traffic ({current_rate:.2f} pps)")
            self.adaptive_sampling = False
            self.config.sampling_rate = 1.0  # Process all packets
    
    def _adjust_response_system(self) -> None:
        """
        Dynamically adjust response system based on traffic load and system resources
        """
        # Get current system load
        system_load = 0.5  # Default medium load
        if PSUTIL_AVAILABLE:
            try:
                # Get CPU and memory metrics
                cpu_percent = psutil.cpu_percent()
                memory_percent = psutil.virtual_memory().percent
                
                # Weighted average (CPU is more important)
                system_load = (cpu_percent * 0.7 + memory_percent * 0.3) / 100.0
            except:
                pass
                
        # Get current detection latency
        current_latency = self.stats["detection_latency"]
        
        # Adjust worker threads based on system load
        target_workers = self.config.worker_threads
        
        # If system is very loaded or latency is high, reduce resources
        if system_load > 0.8 or current_latency > 1.0:
            # Reduce by 25%
            target_workers = max(1, int(target_workers * 0.75))
            logger.info(f"High system load ({system_load:.2f}) or high latency ({current_latency:.2f}ms), reducing workers to {target_workers}")
        # If system has low load and latency is low, increase resources
        elif system_load < 0.3 and current_latency < 0.1:
            # Increase by 25% up to max
            target_workers = min(multiprocessing.cpu_count(), int(target_workers * 1.25))
            logger.info(f"Low system load ({system_load:.2f}) and low latency ({current_latency:.2f}ms), increasing workers to {target_workers}")
        
        # Adjust worker threads if needed
        current_workers = len(self.worker_threads)
        if target_workers > current_workers:
            # Add workers
            for i in range(current_workers, target_workers):
                worker = threading.Thread(
                    target=self._worker_thread,
                    name=f"detection-worker-{i}",
                    daemon=True
                )
                worker.start()
                self.worker_threads.append(worker)
                self.active_workers += 1
                logger.info(f"Added worker thread: {worker.name}")
                
        # We don't remove workers dynamically as that would be complex
        # Instead, we'll just let the system stabilize by itself 

    def _get_gateway_ips(self) -> List[str]:
        """
        Get list of gateway IPs from system
            
        Returns:
            List of gateway IP addresses
        """
        # Lazy-load gateway info if needed
        if not self._gateway_info_loaded:
            self._load_gateway_info()
            
        gw_ip = self.gateway_info.get("ip")
        return [gw_ip] if gw_ip else []
    
    def _get_gateway_macs(self) -> List[str]:
        """
        Get list of gateway MACs from system
            
        Returns:
            List of gateway MAC addresses
        """
        # Lazy-load gateway info if needed
        if not self._gateway_info_loaded:
            self._load_gateway_info()
            
        gw_mac = self.gateway_info.get("mac")
        return [gw_mac] if gw_mac else []
    
    def get_vendor_for_mac(self, mac_address: str) -> str:
        """
        Get vendor name for MAC address
        
        Args:
            mac_address: MAC address to look up
            
        Returns:
            Vendor name or "Unknown"
        """
        # Lazy load MAC vendors if not already loaded
        if not self._mac_vendors_loaded:
            self._load_mac_vendors()
            
        if not mac_address:
            return "Unknown"
            
        # Try to normalize the MAC address format
        mac_prefix = mac_address.replace(':', '').replace('-', '').upper()[0:6]
        
        # Look up the vendor
        return self.mac_vendors.get(mac_prefix, "Unknown") 

