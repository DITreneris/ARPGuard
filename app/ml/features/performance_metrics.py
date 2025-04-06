import psutil
import time
import numpy as np
import pandas as pd
from typing import Dict, List, Optional
from datetime import datetime

class PerformanceMetrics:
    """
    Collects and processes system performance metrics for ML models.
    Provides real-time and historical performance data.
    """
    def __init__(self, window_size: int = 60):
        """
        Initialize the performance metrics collector.
        
        Args:
            window_size (int): Number of samples to keep in memory (default: 60)
        """
        self.window_size = window_size
        self.metrics = {
            'timestamp': [],
            'cpu_usage': [],
            'memory_usage': [],
            'network_traffic': [],
            'packet_processing_rate': [],
            'response_time': []
        }
        self._initialize_network_counters()
        
    def _initialize_network_counters(self):
        """Initialize network counters for traffic measurement"""
        self.last_net_io = psutil.net_io_counters()
        self.last_time = time.time()
        
    def collect_metrics(self) -> Dict[str, float]:
        """
        Collect real-time performance metrics.
        
        Returns:
            Dict[str, float]: Dictionary of current performance metrics
        """
        current_time = time.time()
        time_diff = current_time - self.last_time
        
        # CPU Usage
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        # Memory Usage
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        
        # Network Traffic
        net_io = psutil.net_io_counters()
        bytes_sent = net_io.bytes_sent - self.last_net_io.bytes_sent
        bytes_recv = net_io.bytes_recv - self.last_net_io.bytes_recv
        network_traffic = (bytes_sent + bytes_recv) / time_diff
        
        # Update counters
        self.last_net_io = net_io
        self.last_time = current_time
        
        metrics = {
            'timestamp': datetime.now(),
            'cpu_usage': cpu_percent,
            'memory_usage': memory_percent,
            'network_traffic': network_traffic,
            'packet_processing_rate': self._get_packet_rate(),
            'response_time': self._get_response_time()
        }
        
        self._update_metrics_history(metrics)
        return metrics
    
    def _get_packet_rate(self) -> float:
        """
        Calculate current packet processing rate.
        This is a placeholder - implement based on your packet processing logic.
        """
        # TODO: Implement actual packet rate calculation
        return 0.0
    
    def _get_response_time(self) -> float:
        """
        Calculate current system response time.
        This is a placeholder - implement based on your system's response time measurement.
        """
        # TODO: Implement actual response time measurement
        return 0.0
    
    def _update_metrics_history(self, metrics: Dict[str, float]):
        """
        Update the metrics history with new values.
        
        Args:
            metrics (Dict[str, float]): New metrics to add to history
        """
        for key, value in metrics.items():
            self.metrics[key].append(value)
            
            # Maintain window size
            if len(self.metrics[key]) > self.window_size:
                self.metrics[key].pop(0)
    
    def get_metrics_dataframe(self) -> pd.DataFrame:
        """
        Get current metrics history as a pandas DataFrame.
        
        Returns:
            pd.DataFrame: DataFrame containing metrics history
        """
        return pd.DataFrame(self.metrics)
    
    def get_metrics_window(self, window_size: Optional[int] = None) -> Dict[str, List[float]]:
        """
        Get metrics for the specified window size.
        
        Args:
            window_size (Optional[int]): Number of samples to return (default: None, uses all)
            
        Returns:
            Dict[str, List[float]]: Dictionary of metrics for the specified window
        """
        if window_size is None:
            return self.metrics.copy()
            
        window_metrics = {}
        for key, values in self.metrics.items():
            window_metrics[key] = values[-window_size:]
        return window_metrics
    
    def clear_metrics(self):
        """Clear all stored metrics"""
        for key in self.metrics:
            self.metrics[key] = [] 