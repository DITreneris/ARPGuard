"""
Performance Configuration for ARP Guard
Manages performance optimization settings
"""

import os
import json
import logging
import multiprocessing
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Default values
DEFAULT_PACKET_SAMPLING = True
DEFAULT_SAMPLING_RATIO = 0.5  # Sample 50% of packets in high traffic
DEFAULT_HIGH_TRAFFIC_THRESHOLD = 1000  # Packets per second
DEFAULT_BATCH_SIZE = 100  # Process packets in batches
DEFAULT_PARALLEL_PROCESSING = True
DEFAULT_MAX_WORKER_THREADS = min(4, multiprocessing.cpu_count())
DEFAULT_MEMORY_LIMIT = 512  # MB
DEFAULT_CONFIG_FILE = "config/performance.json"


class PerformanceConfig:
    """Configuration for performance optimization settings"""

    def __init__(self, 
               config_file: Optional[str] = None,
               enable_packet_sampling: bool = DEFAULT_PACKET_SAMPLING,
               sampling_ratio: float = DEFAULT_SAMPLING_RATIO,
               high_traffic_threshold: int = DEFAULT_HIGH_TRAFFIC_THRESHOLD,
               enable_batch_processing: bool = True,
               batch_size: int = DEFAULT_BATCH_SIZE,
               enable_parallel_processing: bool = DEFAULT_PARALLEL_PROCESSING,
               max_worker_threads: int = DEFAULT_MAX_WORKER_THREADS,
               memory_limit_mb: int = DEFAULT_MEMORY_LIMIT):
        """
        Initialize performance configuration
        
        Args:
            config_file: Path to configuration file
            enable_packet_sampling: Whether to enable packet sampling in high traffic
            sampling_ratio: Ratio of packets to sample (0.0-1.0)
            high_traffic_threshold: Threshold for high traffic in packets per second
            enable_batch_processing: Whether to process packets in batches
            batch_size: Number of packets to process in a batch
            enable_parallel_processing: Whether to use parallel processing
            max_worker_threads: Maximum number of worker threads
            memory_limit_mb: Memory limit in MB
        """
        self.config_file = config_file or DEFAULT_CONFIG_FILE
        self.enable_packet_sampling = enable_packet_sampling
        self.sampling_ratio = max(0.1, min(1.0, sampling_ratio))  # Ensure between 0.1 and 1.0
        self.high_traffic_threshold = high_traffic_threshold
        self.enable_batch_processing = enable_batch_processing
        self.batch_size = batch_size
        self.enable_parallel_processing = enable_parallel_processing
        self.max_worker_threads = min(max_worker_threads, multiprocessing.cpu_count())
        self.memory_limit_mb = memory_limit_mb
        
        # Try to load from file if exists
        if os.path.exists(self.config_file):
            self.load_from_file()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            "enable_packet_sampling": self.enable_packet_sampling,
            "sampling_ratio": self.sampling_ratio,
            "high_traffic_threshold": self.high_traffic_threshold,
            "enable_batch_processing": self.enable_batch_processing,
            "batch_size": self.batch_size,
            "enable_parallel_processing": self.enable_parallel_processing,
            "max_worker_threads": self.max_worker_threads,
            "memory_limit_mb": self.memory_limit_mb
        }
    
    def from_dict(self, data: Dict[str, Any]) -> None:
        """
        Load configuration from dictionary
        
        Args:
            data: Configuration data
        """
        if "enable_packet_sampling" in data:
            self.enable_packet_sampling = bool(data["enable_packet_sampling"])
        
        if "sampling_ratio" in data:
            self.sampling_ratio = max(0.1, min(1.0, float(data["sampling_ratio"])))
        
        if "high_traffic_threshold" in data:
            self.high_traffic_threshold = int(data["high_traffic_threshold"])
        
        if "enable_batch_processing" in data:
            self.enable_batch_processing = bool(data["enable_batch_processing"])
        
        if "batch_size" in data:
            self.batch_size = int(data["batch_size"])
        
        if "enable_parallel_processing" in data:
            self.enable_parallel_processing = bool(data["enable_parallel_processing"])
        
        if "max_worker_threads" in data:
            self.max_worker_threads = min(int(data["max_worker_threads"]), multiprocessing.cpu_count())
        
        if "memory_limit_mb" in data:
            self.memory_limit_mb = int(data["memory_limit_mb"])
    
    def load_from_file(self) -> bool:
        """
        Load configuration from file
        
        Returns:
            True if loaded successfully, False otherwise
        """
        try:
            with open(self.config_file, 'r') as f:
                data = json.load(f)
            
            self.from_dict(data)
            logger.info(f"Loaded performance configuration from {self.config_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to load performance configuration: {e}")
            return False
    
    def save_to_file(self) -> bool:
        """
        Save configuration to file
        
        Returns:
            True if saved successfully, False otherwise
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            
            with open(self.config_file, 'w') as f:
                json.dump(self.to_dict(), f, indent=4)
            
            logger.info(f"Saved performance configuration to {self.config_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save performance configuration: {e}")
            return False
    
    def optimize_for_environment(self) -> None:
        """Automatically optimize configuration based on system resources"""
        try:
            # Get available CPU cores
            cpu_count = multiprocessing.cpu_count()
            
            # Get available memory
            import psutil
            mem = psutil.virtual_memory()
            available_mem_mb = mem.available / (1024 * 1024)
            
            logger.info(f"System has {cpu_count} CPU cores and {available_mem_mb:.0f} MB available memory")
            
            # Adjust worker threads based on available CPUs
            if cpu_count <= 2:
                self.enable_parallel_processing = False
                self.max_worker_threads = 1
            elif cpu_count <= 4:
                self.max_worker_threads = max(2, cpu_count - 1)
            else:
                self.max_worker_threads = max(4, cpu_count - 2)
            
            # Adjust memory limit and batch size based on available memory
            if available_mem_mb < 500:
                self.memory_limit_mb = 256
                self.batch_size = 50
            elif available_mem_mb < 1000:
                self.memory_limit_mb = 512
                self.batch_size = 100
            else:
                self.memory_limit_mb = 1024
                self.batch_size = 200
            
            logger.info("Optimized performance settings for current environment")
            
        except Exception as e:
            logger.warning(f"Failed to optimize for environment: {e}")
    
    def __str__(self) -> str:
        """String representation of configuration"""
        return (
            f"PerformanceConfig("
            f"packet_sampling={self.enable_packet_sampling}, "
            f"sampling_ratio={self.sampling_ratio}, "
            f"batch_processing={self.enable_batch_processing}, "
            f"batch_size={self.batch_size}, "
            f"parallel_processing={self.enable_parallel_processing}, "
            f"worker_threads={self.max_worker_threads}, "
            f"memory_limit={self.memory_limit_mb}MB)"
        ) 