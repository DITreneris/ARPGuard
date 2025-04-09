"""
Memory Manager module for optimizing packet capture memory usage.

This module provides utilities for monitoring system memory usage and
optimizing packet capture operations to prevent memory-related issues.
"""

import os
import sys
import time
import logging
import threading
from enum import Enum
from typing import Dict, List, Any, Optional, Callable, Tuple, Set, Union
import psutil

from app.utils.logger import get_logger
from app.utils.config import get_config

# Get module logger
logger = get_logger("utils.memory_manager")

class MemoryPressureLevel(str, Enum):
    """Enum for different memory pressure levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class MemoryManager:
    """
    Memory Manager to monitor system memory usage and adapt behavior accordingly.
    
    This class provides methods to:
    1. Monitor system memory usage and determine pressure levels
    2. Adapt capture strategies based on memory pressure
    3. Execute callbacks when memory pressure changes
    4. Track memory-related metrics for reporting
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the Memory Manager.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or get_config().get("memory", {})
        
        # Thresholds for memory pressure levels (percent of used memory)
        self.thresholds = {
            MemoryPressureLevel.LOW: self.config.get("low_threshold", 50),
            MemoryPressureLevel.MEDIUM: self.config.get("medium_threshold", 70),
            MemoryPressureLevel.HIGH: self.config.get("high_threshold", 85),
            MemoryPressureLevel.CRITICAL: self.config.get("critical_threshold", 95)
        }
        
        # Strategy parameters based on memory pressure
        self.strategies = {
            MemoryPressureLevel.LOW: {
                "sampling_rate": self.config.get("low_sampling_rate", 1.0),
                "buffer_size": self.config.get("low_buffer_size", 10000),
                "gc_interval": self.config.get("low_gc_interval", 600)  # 10 minutes
            },
            MemoryPressureLevel.MEDIUM: {
                "sampling_rate": self.config.get("medium_sampling_rate", 0.75),
                "buffer_size": self.config.get("medium_buffer_size", 5000),
                "gc_interval": self.config.get("medium_gc_interval", 300)  # 5 minutes
            },
            MemoryPressureLevel.HIGH: {
                "sampling_rate": self.config.get("high_sampling_rate", 0.5),
                "buffer_size": self.config.get("high_buffer_size", 2500),
                "gc_interval": self.config.get("high_gc_interval", 120)  # 2 minutes
            },
            MemoryPressureLevel.CRITICAL: {
                "sampling_rate": self.config.get("critical_sampling_rate", 0.25),
                "buffer_size": self.config.get("critical_buffer_size", 1000),
                "gc_interval": self.config.get("critical_gc_interval", 60)  # 1 minute
            }
        }
        
        # Current memory pressure level
        self.current_pressure_level = MemoryPressureLevel.LOW
        
        # Callbacks to be notified when memory pressure changes
        self.pressure_change_callbacks: List[Callable[[MemoryPressureLevel], None]] = []
        
        # Metrics
        self.metrics = {
            "memory_checks": 0,
            "pressure_changes": 0,
            "last_memory_usage": 0.0,
            "peak_memory_usage": 0.0,
            "gc_invocations": 0,
            "packets_dropped": 0,
            "adaptive_actions": 0
        }
        
        # Threading
        self.monitoring_interval = self.config.get("monitoring_interval", 15)  # seconds
        self.monitoring_thread = None
        self.monitoring_active = False
        self.last_gc_time = time.time()
        
        # Process information
        self.process = psutil.Process(os.getpid())
        
        logger.info(f"Memory Manager initialized with thresholds: {self.thresholds}")
    
    def start_monitoring(self):
        """Start background memory monitoring thread."""
        if self.monitoring_thread is not None and self.monitoring_thread.is_alive():
            logger.warning("Memory monitoring is already running")
            return
            
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            name="MemoryMonitoringThread",
            daemon=True
        )
        self.monitoring_thread.start()
        logger.info("Memory monitoring started")
    
    def stop_monitoring(self):
        """Stop background memory monitoring thread."""
        if self.monitoring_thread is None or not self.monitoring_thread.is_alive():
            logger.warning("Memory monitoring is not running")
            return
            
        self.monitoring_active = False
        self.monitoring_thread.join(timeout=5.0)
        logger.info("Memory monitoring stopped")
    
    def _monitoring_loop(self):
        """Background thread loop to monitor memory usage."""
        while self.monitoring_active:
            try:
                # Check memory usage and update pressure level
                self.check_memory_pressure()
                
                # Perform garbage collection if needed
                self._check_gc_needed()
                
                # Sleep for the configured interval
                time.sleep(self.monitoring_interval)
            except Exception as e:
                logger.error(f"Error in memory monitoring loop: {e}")
    
    def get_memory_usage(self) -> float:
        """
        Get current memory usage as a percentage.
        
        Returns:
            float: Memory usage percentage (0-100)
        """
        try:
            # Get system memory usage
            memory = psutil.virtual_memory()
            usage_percent = memory.percent
            
            # Update metrics
            self.metrics["memory_checks"] += 1
            self.metrics["last_memory_usage"] = usage_percent
            
            if usage_percent > self.metrics["peak_memory_usage"]:
                self.metrics["peak_memory_usage"] = usage_percent
                
            return usage_percent
        except Exception as e:
            logger.error(f"Error getting memory usage: {e}")
            return 0.0
    
    def get_process_memory(self) -> Dict[str, float]:
        """
        Get current process memory usage details.
        
        Returns:
            Dict: Process memory metrics in MB
        """
        try:
            memory_info = self.process.memory_info()
            return {
                "rss": memory_info.rss / (1024 * 1024),  # Resident Set Size in MB
                "vms": memory_info.vms / (1024 * 1024),  # Virtual Memory Size in MB
                "shared": getattr(memory_info, 'shared', 0) / (1024 * 1024),  # Shared memory in MB
                "percent": self.process.memory_percent()  # Process memory as percent of total
            }
        except Exception as e:
            logger.error(f"Error getting process memory: {e}")
            return {"rss": 0.0, "vms": 0.0, "shared": 0.0, "percent": 0.0}
    
    def check_memory_pressure(self) -> MemoryPressureLevel:
        """
        Check current memory pressure level based on usage.
        
        Returns:
            MemoryPressureLevel: Current memory pressure level
        """
        usage_percent = self.get_memory_usage()
        
        # Determine pressure level based on thresholds
        new_level = MemoryPressureLevel.LOW
        
        if usage_percent >= self.thresholds[MemoryPressureLevel.CRITICAL]:
            new_level = MemoryPressureLevel.CRITICAL
        elif usage_percent >= self.thresholds[MemoryPressureLevel.HIGH]:
            new_level = MemoryPressureLevel.HIGH
        elif usage_percent >= self.thresholds[MemoryPressureLevel.MEDIUM]:
            new_level = MemoryPressureLevel.MEDIUM
            
        # Check if pressure level changed
        if new_level != self.current_pressure_level:
            # Update metrics
            self.metrics["pressure_changes"] += 1
            
            # Log the change
            logger.info(f"Memory pressure changed from {self.current_pressure_level} to {new_level} "
                       f"(Usage: {usage_percent:.1f}%)")
            
            # Update current level
            self.current_pressure_level = new_level
            
            # Notify callbacks
            self._notify_pressure_change(new_level)
            
        return new_level
    
    def _notify_pressure_change(self, level: MemoryPressureLevel):
        """
        Notify all registered callbacks about memory pressure change.
        
        Args:
            level: New memory pressure level
        """
        for callback in self.pressure_change_callbacks:
            try:
                callback(level)
            except Exception as e:
                logger.error(f"Error in memory pressure callback: {e}")
    
    def register_pressure_callback(self, callback: Callable[[MemoryPressureLevel], None]):
        """
        Register a callback to be notified of memory pressure changes.
        
        Args:
            callback: Function to call when memory pressure changes
        """
        if callback not in self.pressure_change_callbacks:
            self.pressure_change_callbacks.append(callback)
    
    def unregister_pressure_callback(self, callback: Callable[[MemoryPressureLevel], None]):
        """
        Unregister a previously registered callback.
        
        Args:
            callback: Previously registered callback function
        """
        if callback in self.pressure_change_callbacks:
            self.pressure_change_callbacks.remove(callback)
    
    def get_current_strategy(self) -> Dict[str, Any]:
        """
        Get current memory management strategy based on pressure level.
        
        Returns:
            Dict: Strategy parameters for current pressure level
        """
        return self.strategies[self.current_pressure_level]
    
    def should_process_packet(self) -> bool:
        """
        Determine if a packet should be processed based on sampling rate.
        
        Returns:
            bool: True if packet should be processed, False otherwise
        """
        import random
        
        strategy = self.get_current_strategy()
        sampling_rate = strategy["sampling_rate"]
        
        # Always process if sampling rate is 1.0
        if sampling_rate >= 1.0:
            return True
            
        # Randomly sample based on configured rate
        should_process = random.random() < sampling_rate
        
        # Update metrics if packet is dropped
        if not should_process:
            self.metrics["packets_dropped"] += 1
            
        return should_process
    
    def get_max_buffer_size(self) -> int:
        """
        Get maximum packet buffer size based on current strategy.
        
        Returns:
            int: Maximum buffer size for packet storage
        """
        strategy = self.get_current_strategy()
        return strategy["buffer_size"]
    
    def _check_gc_needed(self):
        """Check if garbage collection should be triggered based on time interval."""
        strategy = self.get_current_strategy()
        gc_interval = strategy["gc_interval"]
        
        current_time = time.time()
        if current_time - self.last_gc_time >= gc_interval:
            self._trigger_garbage_collection()
            self.last_gc_time = current_time
    
    def _trigger_garbage_collection(self):
        """Trigger Python garbage collection."""
        import gc
        
        # Update metrics
        self.metrics["gc_invocations"] += 1
        
        # Log the event
        logger.debug(f"Triggering garbage collection (Pressure: {self.current_pressure_level})")
        
        # Collect garbage
        gc.collect()
    
    def estimate_packet_memory(self, packet_size: int) -> float:
        """
        Estimate memory usage for a packet of given size.
        
        Args:
            packet_size: Size of the packet in bytes
            
        Returns:
            float: Estimated memory usage in bytes
        """
        # Basic estimation: packet size plus overhead
        # The overhead factor accounts for Python object overhead and additional data structures
        overhead_factor = self.config.get("memory_overhead_factor", 1.5)
        return packet_size * overhead_factor
    
    def register_adaptive_action(self):
        """Register that an adaptive action was taken in response to memory pressure."""
        self.metrics["adaptive_actions"] += 1
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get memory manager metrics.
        
        Returns:
            Dict: Current metrics
        """
        # Add current memory usage information to metrics
        current_metrics = dict(self.metrics)
        current_metrics["current_pressure_level"] = self.current_pressure_level
        current_metrics["current_memory_usage"] = self.get_memory_usage()
        current_metrics["process_memory"] = self.get_process_memory()
        
        return current_metrics
    
    def reset_metrics(self):
        """Reset all metrics to initial values."""
        self.metrics = {
            "memory_checks": 0,
            "pressure_changes": 0,
            "last_memory_usage": 0.0,
            "peak_memory_usage": 0.0,
            "gc_invocations": 0,
            "packets_dropped": 0,
            "adaptive_actions": 0
        }
        logger.info("Memory metrics reset")


class PacketMemoryOptimizer:
    """
    Packet Memory Optimizer for efficient packet storage.
    
    This class provides methods to:
    1. Optimize packet storage by removing redundant information
    2. Deduplicate common packet attributes
    3. Adapt storage strategy based on memory pressure
    """
    
    def __init__(self, memory_manager: MemoryManager = None):
        """
        Initialize the Packet Memory Optimizer.
        
        Args:
            memory_manager: Optional memory manager instance
        """
        self.memory_manager = memory_manager or MemoryManager()
        
        # Register for memory pressure callbacks
        self.memory_manager.register_pressure_callback(self._on_memory_pressure_change)
        
        # Deduplication dictionaries for common values
        self.ip_cache: Dict[str, str] = {}
        self.mac_cache: Dict[str, str] = {}
        self.protocol_cache: Dict[str, str] = {}
        
        # Storage optimization flags (adjust based on memory pressure)
        self.store_raw_packet = True
        self.store_full_payload = True
        self.max_payload_size = 1500  # Bytes
        
        # Metrics
        self.metrics = {
            "packets_optimized": 0,
            "bytes_saved": 0,
            "duplicate_ips_found": 0,
            "duplicate_macs_found": 0,
            "payloads_truncated": 0
        }
        
        # Update storage flags based on initial memory pressure
        self._on_memory_pressure_change(self.memory_manager.current_pressure_level)
        
        logger.info("Packet Memory Optimizer initialized")
    
    def _on_memory_pressure_change(self, level: MemoryPressureLevel):
        """
        Adjust optimization strategies based on memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        # Adjust optimization strategies based on pressure level
        if level == MemoryPressureLevel.LOW:
            self.store_raw_packet = True
            self.store_full_payload = True
            self.max_payload_size = 1500  # Full Ethernet frame
        elif level == MemoryPressureLevel.MEDIUM:
            self.store_raw_packet = True
            self.store_full_payload = True
            self.max_payload_size = 512  # Reduced payload size
        elif level == MemoryPressureLevel.HIGH:
            self.store_raw_packet = False
            self.store_full_payload = False
            self.max_payload_size = 256  # Minimal payload
        elif level == MemoryPressureLevel.CRITICAL:
            self.store_raw_packet = False
            self.store_full_payload = False
            self.max_payload_size = 64  # Headers only
            
        # Log the changes
        logger.info(f"Packet optimization adjusted for {level} memory pressure: "
                   f"store_raw={self.store_raw_packet}, "
                   f"full_payload={self.store_full_payload}, "
                   f"max_size={self.max_payload_size}")
        
        # Register adaptive action
        self.memory_manager.register_adaptive_action()
    
    def optimize_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """
        Optimize a packet dictionary to reduce memory usage.
        
        Args:
            packet: Raw packet dictionary
            
        Returns:
            Dict: Optimized packet dictionary
        """
        if not packet:
            return packet
            
        # Create a copy that we'll optimize
        optimized = dict(packet)
        bytes_before = self._estimate_dict_size(optimized)
        
        # Apply deduplication for common values
        self._deduplicate_packet_fields(optimized)
        
        # Apply payload optimization if needed
        if 'payload' in optimized and not self.store_full_payload:
            original_len = len(optimized['payload'])
            
            if original_len > self.max_payload_size:
                optimized['payload'] = optimized['payload'][:self.max_payload_size]
                optimized['payload_truncated'] = True
                optimized['original_payload_size'] = original_len
                self.metrics["payloads_truncated"] += 1
        
        # Remove raw packet data if not storing
        if 'raw_packet' in optimized and not self.store_raw_packet:
            del optimized['raw_packet']
        
        # Calculate bytes saved
        bytes_after = self._estimate_dict_size(optimized)
        bytes_saved = bytes_before - bytes_after
        
        # Update metrics
        self.metrics["packets_optimized"] += 1
        self.metrics["bytes_saved"] += bytes_saved
        
        return optimized
    
    def _deduplicate_packet_fields(self, packet: Dict[str, Any]):
        """
        Deduplicate common packet fields to save memory.
        
        Args:
            packet: Packet dictionary to deduplicate in-place
        """
        # Deduplicate IP addresses
        if 'src_ip' in packet and isinstance(packet['src_ip'], str):
            ip = packet['src_ip']
            if ip in self.ip_cache:
                packet['src_ip'] = self.ip_cache[ip]
                self.metrics["duplicate_ips_found"] += 1
            else:
                self.ip_cache[ip] = ip
                
        if 'dst_ip' in packet and isinstance(packet['dst_ip'], str):
            ip = packet['dst_ip']
            if ip in self.ip_cache:
                packet['dst_ip'] = self.ip_cache[ip]
                self.metrics["duplicate_ips_found"] += 1
            else:
                self.ip_cache[ip] = ip
        
        # Deduplicate MAC addresses
        if 'src_mac' in packet and isinstance(packet['src_mac'], str):
            mac = packet['src_mac']
            if mac in self.mac_cache:
                packet['src_mac'] = self.mac_cache[mac]
                self.metrics["duplicate_macs_found"] += 1
            else:
                self.mac_cache[mac] = mac
                
        if 'dst_mac' in packet and isinstance(packet['dst_mac'], str):
            mac = packet['dst_mac']
            if mac in self.mac_cache:
                packet['dst_mac'] = self.mac_cache[mac]
                self.metrics["duplicate_macs_found"] += 1
            else:
                self.mac_cache[mac] = mac
        
        # Deduplicate protocol names
        if 'protocol' in packet and isinstance(packet['protocol'], str):
            proto = packet['protocol']
            if proto in self.protocol_cache:
                packet['protocol'] = self.protocol_cache[proto]
            else:
                self.protocol_cache[proto] = proto
    
    def _estimate_dict_size(self, d: Dict[str, Any]) -> int:
        """
        Estimate memory size of a dictionary.
        
        Args:
            d: Dictionary to estimate size for
            
        Returns:
            int: Estimated size in bytes
        """
        import sys
        
        # Base dictionary overhead
        size = sys.getsizeof(d)
        
        # Add size of each key-value pair
        for key, value in d.items():
            # Add key size
            size += sys.getsizeof(key)
            
            # Add value size based on type
            if isinstance(value, (str, bytes, bytearray)):
                size += sys.getsizeof(value)
            elif isinstance(value, (int, float, bool)):
                size += sys.getsizeof(value)
            elif isinstance(value, dict):
                size += self._estimate_dict_size(value)
            elif isinstance(value, (list, tuple, set)):
                size += sys.getsizeof(value)
                # Add size of elements (simplified)
                if value and len(value) > 0:
                    avg_item_size = sys.getsizeof(value[0]) if isinstance(value, (list, tuple)) and value else 8
                    size += len(value) * avg_item_size
            else:
                # For other types, use a conservative estimate
                size += sys.getsizeof(value)
                
        return size
    
    def clear_caches(self):
        """Clear all deduplication caches."""
        self.ip_cache.clear()
        self.mac_cache.clear()
        self.protocol_cache.clear()
        logger.info("Packet memory optimizer caches cleared")
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get memory optimizer metrics.
        
        Returns:
            Dict: Current metrics
        """
        current_metrics = dict(self.metrics)
        current_metrics["ip_cache_size"] = len(self.ip_cache)
        current_metrics["mac_cache_size"] = len(self.mac_cache)
        current_metrics["protocol_cache_size"] = len(self.protocol_cache)
        current_metrics["store_raw_packet"] = self.store_raw_packet
        current_metrics["store_full_payload"] = self.store_full_payload
        current_metrics["max_payload_size"] = self.max_payload_size
        
        return current_metrics
    
    def reset_metrics(self):
        """Reset all metrics to initial values."""
        self.metrics = {
            "packets_optimized": 0,
            "bytes_saved": 0,
            "duplicate_ips_found": 0,
            "duplicate_macs_found": 0,
            "payloads_truncated": 0
        }
        logger.info("Packet memory optimizer metrics reset") 