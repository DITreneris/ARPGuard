import time
import logging
from functools import wraps
from typing import Dict, List, Any, Callable
from collections import deque
import statistics

class PerformanceMonitor:
    def __init__(self, max_samples: int = 1000):
        self.max_samples = max_samples
        self.metrics: Dict[str, deque] = {}
        self.logger = logging.getLogger('performance')
        
    def track_metric(self, metric_name: str, value: float):
        """Track a performance metric value"""
        if metric_name not in self.metrics:
            self.metrics[metric_name] = deque(maxlen=self.max_samples)
        self.metrics[metric_name].append(value)
        
    def get_metric_stats(self, metric_name: str) -> Dict[str, float]:
        """Get statistics for a specific metric"""
        if metric_name not in self.metrics or not self.metrics[metric_name]:
            return {}
            
        values = list(self.metrics[metric_name])
        return {
            'min': min(values),
            'max': max(values),
            'mean': statistics.mean(values),
            'median': statistics.median(values),
            'p95': statistics.quantiles(values, n=20)[18],  # 95th percentile
            'count': len(values)
        }
        
    def log_metric_stats(self, metric_name: str):
        """Log statistics for a specific metric"""
        stats = self.get_metric_stats(metric_name)
        if stats:
            self.logger.info(f"Performance stats for {metric_name}: {stats}")
            
    def reset_metric(self, metric_name: str):
        """Reset a specific metric"""
        if metric_name in self.metrics:
            self.metrics[metric_name].clear()

def measure_performance(metric_name: str):
    """Decorator to measure function execution time"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            result = func(*args, **kwargs)
            end_time = time.perf_counter()
            
            execution_time = end_time - start_time
            monitor = PerformanceMonitor()
            monitor.track_metric(metric_name, execution_time)
            
            return result
        return wrapper
    return decorator

class ResponseTimeOptimizer:
    def __init__(self):
        self.monitor = PerformanceMonitor()
        self.cache: Dict[str, Any] = {}
        self.cache_ttl: Dict[str, float] = {}
        
    def cache_result(self, key: str, value: Any, ttl: float = 60.0):
        """Cache a result with time-to-live"""
        self.cache[key] = value
        self.cache_ttl[key] = time.time() + ttl
        
    def get_cached_result(self, key: str) -> Any:
        """Get a cached result if it exists and is not expired"""
        if key in self.cache and time.time() < self.cache_ttl.get(key, 0):
            return self.cache[key]
        return None
        
    def measure_response_time(self, operation_name: str):
        """Context manager to measure response time"""
        start_time = time.perf_counter()
        yield
        end_time = time.perf_counter()
        self.monitor.track_metric(f"response_time_{operation_name}", end_time - start_time)
        
    def optimize_data_structure(self, data: List[Any], access_pattern: str = 'sequential') -> List[Any]:
        """Optimize data structure based on access pattern"""
        with self.measure_response_time('optimize_data_structure'):
            if access_pattern == 'random':
                # Convert to dictionary for O(1) access
                return {str(i): item for i, item in enumerate(data)}
            elif access_pattern == 'frequent_updates':
                # Use deque for efficient updates
                return deque(data)
            return data
            
    def get_performance_report(self) -> Dict[str, Dict[str, float]]:
        """Generate a performance report"""
        report = {}
        for metric_name in self.monitor.metrics:
            report[metric_name] = self.monitor.get_metric_stats(metric_name)
        return report 