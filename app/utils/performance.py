import time
import psutil
from collections import deque
from datetime import datetime

class PerformanceMonitor:
    def __init__(self, window_size=1000):
        self.window_size = window_size
        self.metrics = {
            "packets_processed": 0,
            "processing_rate": 0,
            "average_processing_time": 0,
            "memory_usage": 0,
            "cpu_usage": 0,
            "start_time": time.time()
        }
        self.processing_times = deque(maxlen=window_size)
        self.memory_samples = deque(maxlen=window_size)
        self.cpu_samples = deque(maxlen=window_size)
        
    def reset_metrics(self):
        """Reset all performance metrics"""
        self.metrics = {
            "packets_processed": 0,
            "processing_rate": 0,
            "average_processing_time": 0,
            "memory_usage": 0,
            "cpu_usage": 0,
            "start_time": time.time()
        }
        self.processing_times.clear()
        self.memory_samples.clear()
        self.cpu_samples.clear()
        
    def record_processing_time(self, processing_time):
        """Record the time taken to process a packet"""
        self.processing_times.append(processing_time)
        self.metrics["average_processing_time"] = sum(self.processing_times) / len(self.processing_times)
        
    def record_memory_usage(self):
        """Record current memory usage"""
        memory_usage = psutil.Process().memory_info().rss
        self.memory_samples.append(memory_usage)
        self.metrics["memory_usage"] = memory_usage
        
    def record_cpu_usage(self):
        """Record current CPU usage"""
        cpu_usage = psutil.cpu_percent()
        self.cpu_samples.append(cpu_usage)
        self.metrics["cpu_usage"] = cpu_usage
        
    def increment_packet_count(self):
        """Increment the packet counter and update processing rate"""
        self.metrics["packets_processed"] += 1
        elapsed_time = time.time() - self.metrics["start_time"]
        if elapsed_time > 0:
            self.metrics["processing_rate"] = self.metrics["packets_processed"] / elapsed_time
            
    def get_metrics(self):
        """Get current performance metrics"""
        # Update current metrics
        self.record_memory_usage()
        self.record_cpu_usage()
        
        # Calculate additional metrics
        if len(self.processing_times) > 0:
            self.metrics["min_processing_time"] = min(self.processing_times)
            self.metrics["max_processing_time"] = max(self.processing_times)
            self.metrics["processing_time_std"] = self._calculate_std(self.processing_times)
            
        if len(self.memory_samples) > 0:
            self.metrics["min_memory_usage"] = min(self.memory_samples)
            self.metrics["max_memory_usage"] = max(self.memory_samples)
            self.metrics["memory_usage_std"] = self._calculate_std(self.memory_samples)
            
        if len(self.cpu_samples) > 0:
            self.metrics["min_cpu_usage"] = min(self.cpu_samples)
            self.metrics["max_cpu_usage"] = max(self.cpu_samples)
            self.metrics["cpu_usage_std"] = self._calculate_std(self.cpu_samples)
            
        return self.metrics
        
    def _calculate_std(self, values):
        """Calculate standard deviation of a list of values"""
        if len(values) < 2:
            return 0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return variance ** 0.5
        
    def get_performance_report(self):
        """Generate a detailed performance report"""
        metrics = self.get_metrics()
        report = {
            "timestamp": datetime.now().isoformat(),
            "overview": {
                "packets_processed": metrics["packets_processed"],
                "processing_rate": f"{metrics['processing_rate']:.2f} packets/second",
                "average_processing_time": f"{metrics['average_processing_time'] * 1000:.2f} ms",
                "memory_usage": f"{metrics['memory_usage'] / 1024 / 1024:.2f} MB",
                "cpu_usage": f"{metrics['cpu_usage']:.1f}%"
            },
            "processing_times": {
                "min": f"{metrics.get('min_processing_time', 0) * 1000:.2f} ms",
                "max": f"{metrics.get('max_processing_time', 0) * 1000:.2f} ms",
                "std_dev": f"{metrics.get('processing_time_std', 0) * 1000:.2f} ms"
            },
            "memory_usage": {
                "min": f"{metrics.get('min_memory_usage', 0) / 1024 / 1024:.2f} MB",
                "max": f"{metrics.get('max_memory_usage', 0) / 1024 / 1024:.2f} MB",
                "std_dev": f"{metrics.get('memory_usage_std', 0) / 1024 / 1024:.2f} MB"
            },
            "cpu_usage": {
                "min": f"{metrics.get('min_cpu_usage', 0):.1f}%",
                "max": f"{metrics.get('max_cpu_usage', 0):.1f}%",
                "std_dev": f"{metrics.get('cpu_usage_std', 0):.1f}%"
            }
        }
        return report 