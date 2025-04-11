import time
import psutil
import os
import threading
import logging
from collections import deque, defaultdict
from datetime import datetime
import sys
import tracemalloc
from typing import Dict, List, Any, Tuple, Optional, Callable

logger = logging.getLogger("arp_guard.performance")

class PerformanceMetric:
    """Represents a performance metric with statistics tracking."""
    
    def __init__(self, name: str, max_samples: int = 1000, unit: str = ""):
        self.name = name
        self.samples = deque(maxlen=max_samples)
        self.min_value = None
        self.max_value = None
        self.total = 0
        self.count = 0
        self.unit = unit
        self.last_updated = time.time()
    
    def add_sample(self, value: float):
        """Add a new sample to this metric."""
        self.samples.append(value)
        self.total += value
        self.count += 1
        
        if self.min_value is None or value < self.min_value:
            self.min_value = value
        
        if self.max_value is None or value > self.max_value:
            self.max_value = value
        
        self.last_updated = time.time()
    
    def get_average(self) -> float:
        """Get the average value for this metric."""
        if self.count == 0:
            return 0
        return self.total / self.count
    
    def get_percentile(self, percentile: float) -> Optional[float]:
        """Get the specified percentile value."""
        if not self.samples:
            return None
        
        # Sort samples for percentile calculation
        sorted_samples = sorted(self.samples)
        idx = int(len(sorted_samples) * percentile / 100)
        return sorted_samples[idx]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics for this metric."""
        if not self.samples:
            return {"count": 0}
        
        p95 = self.get_percentile(95)
        p99 = self.get_percentile(99)
        
        return {
            "min": self.min_value,
            "max": self.max_value,
            "avg": self.get_average(),
            "p95": p95,
            "p99": p99,
            "count": self.count,
            "unit": self.unit,
            "last_updated": self.last_updated
        }
    
    def reset(self):
        """Reset all statistics."""
        self.samples.clear()
        self.min_value = None
        self.max_value = None
        self.total = 0
        self.count = 0


class PerformanceMonitor:
    """Enhanced performance monitoring system with bottleneck detection and optimization recommendations."""
    
    def __init__(self, window_size=1000, enable_profiling=True):
        self.window_size = window_size
        self.metrics = {
            "packets_processed": 0,
            "processing_rate": 0,
            "average_processing_time": 0,
            "memory_usage": 0,
            "cpu_usage": 0,
            "start_time": time.time()
        }
        
        # Initialize metric tracking
        self.performance_metrics: Dict[str, PerformanceMetric] = {}
        self.create_metric("processing_time", unit="ms")
        self.create_metric("memory_usage", unit="MB")
        self.create_metric("cpu_usage", unit="%")
        self.create_metric("response_time", unit="ms")
        self.create_metric("disk_io", unit="KB/s")
        self.create_metric("network_traffic", unit="KB/s")
        
        # Traditional tracking methods (for backward compatibility)
        self.processing_times = deque(maxlen=window_size)
        self.memory_samples = deque(maxlen=window_size)
        self.cpu_samples = deque(maxlen=window_size)
        
        # Set up performance thresholds for alerting/recommendations
        self.thresholds = {
            "cpu_usage": 80.0,  # Alert when CPU usage exceeds 80%
            "memory_usage": 85.0,  # Alert when memory usage exceeds 85%
            "processing_time": 100.0,  # Alert when processing time exceeds 100ms
            "response_time": 200.0,  # Alert when response time exceeds 200ms
        }
        
        # Store bottlenecks and recommendations
        self.bottlenecks = []
        self.recommendations = []
        
        # Profiling settings
        self.enable_profiling = enable_profiling
        self.profiling_active = False
        self.profiler = None
        self.profiling_results = {}
        self.resource_usage_history = deque(maxlen=100)  # Keep last 100 resource snapshots
        
        # Monitoring thread
        self.monitoring_active = False
        self.monitoring_thread = None
        self.monitoring_interval = 1.0  # seconds
        
        # Initialize process object for monitoring
        self.process = psutil.Process(os.getpid())
        
        # Initialize tracemalloc for memory profiling if enabled
        if self.enable_profiling:
            try:
                tracemalloc.start()
                logger.info("Memory profiling enabled with tracemalloc")
            except Exception as e:
                logger.warning(f"Failed to start tracemalloc: {str(e)}")
    
    def create_metric(self, name: str, unit: str = "") -> PerformanceMetric:
        """Create and register a new performance metric."""
        metric = PerformanceMetric(name, self.window_size, unit)
        self.performance_metrics[name] = metric
        return metric
    
    def get_metric(self, name: str) -> Optional[PerformanceMetric]:
        """Get a metric by name, creating it if it doesn't exist."""
        if name not in self.performance_metrics:
            return None
        return self.performance_metrics[name]
    
    def record_metric(self, name: str, value: float):
        """Record a value for a metric, creating the metric if needed."""
        if name not in self.performance_metrics:
            self.create_metric(name)
        
        self.performance_metrics[name].add_sample(value)
        
        # Check for threshold crossings
        if name in self.thresholds and value > self.thresholds[name]:
            self._record_bottleneck(name, value, self.thresholds[name])
    
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
        
        # Reset performance metrics
        for metric in self.performance_metrics.values():
            metric.reset()
        
        # Clear bottlenecks and recommendations
        self.bottlenecks = []
        self.recommendations = []
        
        # Reset profiling if active
        if self.profiling_active:
            self.stop_profiling()
    
    def start_monitoring(self):
        """Start background monitoring thread for continuous resource tracking."""
        if self.monitoring_active:
            logger.warning("Monitoring already active")
            return
        
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_worker,
            daemon=True,
            name="PerformanceMonitoring"
        )
        self.monitoring_thread.start()
        logger.info("Performance monitoring thread started")
    
    def stop_monitoring(self):
        """Stop the background monitoring thread."""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=2.0)
        
        logger.info("Performance monitoring thread stopped")
    
    def _monitoring_worker(self):
        """Background thread for monitoring system resources."""
        logger.info("Performance monitoring worker started")
        
        while self.monitoring_active:
            try:
                # Update CPU and memory usage
                self.record_cpu_usage()
                self.record_memory_usage()
                
                # Record disk I/O
                disk_io = psutil.disk_io_counters()
                if disk_io:
                    self.record_metric("disk_io", (disk_io.read_bytes + disk_io.write_bytes) / 1024)
                
                # Record network I/O
                net_io = psutil.net_io_counters()
                if net_io:
                    self.record_metric("network_traffic", (net_io.bytes_sent + net_io.bytes_recv) / 1024)
                
                # Capture resource snapshot
                self._capture_resource_snapshot()
                
                # Check for bottlenecks and generate recommendations
                self._check_bottlenecks()
                
                # Sleep until next monitoring interval
                time.sleep(self.monitoring_interval)
            
            except Exception as e:
                logger.error(f"Error in performance monitoring worker: {str(e)}")
                time.sleep(5.0)  # Sleep longer on error
        
        logger.info("Performance monitoring worker stopped")
    
    def _capture_resource_snapshot(self):
        """Capture a snapshot of current resource usage."""
        try:
            mem_info = self.process.memory_info()
            cpu_percent = self.process.cpu_percent(interval=0.1) / psutil.cpu_count()
            
            snapshot = {
                "timestamp": time.time(),
                "cpu_percent": cpu_percent,
                "memory_rss": mem_info.rss,
                "memory_vms": mem_info.vms,
                "threads": self.process.num_threads(),
                "open_files": len(self.process.open_files()),
                "connections": len(self.process.connections()),
            }
            
            # Add system-wide stats
            snapshot.update({
                "system_cpu": psutil.cpu_percent(),
                "system_memory": psutil.virtual_memory().percent,
                "system_swap": psutil.swap_memory().percent,
                "system_disk": psutil.disk_usage('/').percent
            })
            
            self.resource_usage_history.append(snapshot)
            
        except Exception as e:
            logger.error(f"Error capturing resource snapshot: {str(e)}")
    
    def start_profiling(self, duration: int = 30):
        """Start CPU and memory profiling for a specified duration (seconds)."""
        if self.profiling_active:
            logger.warning("Profiling already active")
            return
        
        if not self.enable_profiling:
            logger.warning("Profiling is disabled")
            return
        
        logger.info(f"Starting performance profiling for {duration} seconds")
        self.profiling_active = True
        
        # Reset tracemalloc snapshots
        if tracemalloc.is_tracing():
            tracemalloc.clear_traces()
        
        # Take initial memory snapshot
        self.initial_memory_snapshot = tracemalloc.take_snapshot()
        
        # Schedule profiling to stop after duration
        threading.Timer(duration, self.stop_profiling).start()
    
    def stop_profiling(self):
        """Stop profiling and analyze results."""
        if not self.profiling_active:
            return
        
        logger.info("Stopping performance profiling")
        
        # Take final memory snapshot and compare
        if tracemalloc.is_tracing():
            final_memory_snapshot = tracemalloc.take_snapshot()
            top_stats = final_memory_snapshot.compare_to(self.initial_memory_snapshot, 'lineno')
            
            # Save memory profiling results
            self.profiling_results["memory"] = []
            for stat in top_stats[:20]:  # Save top 20 memory changes
                frame = stat.traceback[0]
                filename = os.path.basename(frame.filename)
                self.profiling_results["memory"].append({
                    "file": filename,
                    "line": frame.lineno,
                    "size": stat.size,
                    "size_diff": stat.size_diff,
                    "count": stat.count,
                    "count_diff": stat.count_diff
                })
        
        # Analyze bottlenecks
        self._analyze_profiling_results()
        
        self.profiling_active = False
        logger.info("Performance profiling completed")
    
    def _analyze_profiling_results(self):
        """Analyze profiling results and generate recommendations."""
        recommendations = []
        
        # Analyze memory usage
        if "memory" in self.profiling_results and self.profiling_results["memory"]:
            memory_items = self.profiling_results["memory"]
            total_memory_diff = sum(item["size_diff"] for item in memory_items if item["size_diff"] > 0)
            
            if total_memory_diff > 10 * 1024 * 1024:  # More than 10MB increase
                top_memory_consumers = memory_items[:3]
                recommendation = {
                    "type": "memory_optimization",
                    "severity": "high" if total_memory_diff > 50 * 1024 * 1024 else "medium",
                    "description": f"Memory usage increased by {total_memory_diff / (1024 * 1024):.2f} MB during profiling",
                    "hotspots": [f"{item['file']}:{item['line']} ({item['size_diff'] / 1024:.2f} KB)" 
                                for item in top_memory_consumers if item["size_diff"] > 0],
                    "suggestion": "Consider optimizing memory usage in these hotspots"
                }
                recommendations.append(recommendation)
        
        # Analyze CPU usage
        cpu_metric = self.get_metric("cpu_usage")
        if cpu_metric and cpu_metric.count > 0:
            avg_cpu = cpu_metric.get_average()
            max_cpu = cpu_metric.max_value
            
            if max_cpu > 80:
                recommendation = {
                    "type": "cpu_optimization",
                    "severity": "high" if max_cpu > 90 else "medium",
                    "description": f"High CPU usage detected (max: {max_cpu:.2f}%, avg: {avg_cpu:.2f}%)",
                    "suggestion": "Consider optimizing CPU-intensive operations or implementing better concurrency"
                }
                recommendations.append(recommendation)
        
        # Analyze response times
        response_metric = self.get_metric("response_time")
        if response_metric and response_metric.count > 0:
            p95_response = response_metric.get_percentile(95)
            
            if p95_response and p95_response > 200:
                recommendation = {
                    "type": "responsiveness_optimization",
                    "severity": "medium",
                    "description": f"Slow response times detected (95th percentile: {p95_response:.2f} ms)",
                    "suggestion": "Consider optimizing critical request handlers or implementing caching"
                }
                recommendations.append(recommendation)
        
        # Add recommendations for resource usage based on history
        if self.resource_usage_history:
            avg_threads = sum(s["threads"] for s in self.resource_usage_history) / len(self.resource_usage_history)
            max_connections = max(s["connections"] for s in self.resource_usage_history)
            
            if avg_threads > 100:
                recommendation = {
                    "type": "thread_optimization",
                    "severity": "medium",
                    "description": f"High thread count detected (avg: {avg_threads:.2f})",
                    "suggestion": "Consider using a more efficient threading model or thread pooling"
                }
                recommendations.append(recommendation)
            
            if max_connections > 100:
                recommendation = {
                    "type": "connection_optimization",
                    "severity": "medium",
                    "description": f"High connection count detected (max: {max_connections})",
                    "suggestion": "Implement connection pooling or more efficient connection management"
                }
                recommendations.append(recommendation)
        
        # Update global recommendations
        self.recommendations.extend(recommendations)
    
    def record_processing_time(self, processing_time):
        """Record the time taken to process a packet"""
        self.processing_times.append(processing_time)
        self.metrics["average_processing_time"] = sum(self.processing_times) / len(self.processing_times)
        
        # Update enhanced metrics
        self.record_metric("processing_time", processing_time * 1000)  # Convert to ms
    
    def record_response_time(self, response_time):
        """Record API response time in milliseconds"""
        self.record_metric("response_time", response_time)
    
    def record_memory_usage(self):
        """Record current memory usage"""
        memory_info = self.process.memory_info()
        memory_usage = memory_info.rss
        memory_usage_mb = memory_usage / (1024 * 1024)
        
        self.memory_samples.append(memory_usage)
        self.metrics["memory_usage"] = memory_usage
        
        # Update enhanced metrics
        self.record_metric("memory_usage", memory_usage_mb)
    
    def record_cpu_usage(self):
        """Record current CPU usage"""
        try:
            cpu_usage = psutil.cpu_percent()
            self.cpu_samples.append(cpu_usage)
            self.metrics["cpu_usage"] = cpu_usage
            
            # Update enhanced metrics
            self.record_metric("cpu_usage", cpu_usage)
        except Exception as e:
            logger.error(f"Error recording CPU usage: {str(e)}")
    
    def increment_packet_count(self):
        """Increment the packet counter and update processing rate"""
        self.metrics["packets_processed"] += 1
        elapsed_time = time.time() - self.metrics["start_time"]
        if elapsed_time > 0:
            self.metrics["processing_rate"] = self.metrics["packets_processed"] / elapsed_time
    
    def _record_bottleneck(self, metric_name: str, value: float, threshold: float):
        """Record a performance bottleneck."""
        bottleneck = {
            "metric": metric_name,
            "value": value,
            "threshold": threshold,
            "timestamp": time.time(),
            "stack_trace": traceback.format_stack()
        }
        
        self.bottlenecks.append(bottleneck)
        logger.warning(f"Performance bottleneck detected: {metric_name} = {value} (threshold: {threshold})")
    
    def _check_bottlenecks(self):
        """Check for bottlenecks and generate optimization recommendations."""
        if not self.bottlenecks:
            return
        
        # Look for patterns in bottlenecks
        metric_counts = defaultdict(int)
        for bottleneck in self.bottlenecks:
            metric_counts[bottleneck["metric"]] += 1
        
        # Generate recommendations for frequent bottlenecks
        for metric, count in metric_counts.items():
            if count >= 3 and not any(r["type"] == f"{metric}_optimization" for r in self.recommendations):
                if metric == "cpu_usage":
                    recommendation = {
                        "type": "cpu_usage_optimization",
                        "severity": "high" if count > 5 else "medium",
                        "description": f"High CPU usage detected {count} times",
                        "suggestion": "Consider implementing more efficient algorithms, better concurrency, or offloading computation"
                    }
                    self.recommendations.append(recommendation)
                
                elif metric == "memory_usage":
                    recommendation = {
                        "type": "memory_usage_optimization",
                        "severity": "high" if count > 5 else "medium",
                        "description": f"High memory usage detected {count} times",
                        "suggestion": "Look for memory leaks, reduce object allocations, or implement more efficient data structures"
                    }
                    self.recommendations.append(recommendation)
                
                elif metric == "processing_time":
                    recommendation = {
                        "type": "processing_time_optimization",
                        "severity": "medium",
                        "description": f"Slow processing times detected {count} times",
                        "suggestion": "Optimize the processing pipeline, implement batch processing, or use more efficient algorithms"
                    }
                    self.recommendations.append(recommendation)
                
                elif metric == "response_time":
                    recommendation = {
                        "type": "response_time_optimization",
                        "severity": "medium",
                        "description": f"Slow response times detected {count} times",
                        "suggestion": "Implement caching, optimize database queries, or use asynchronous processing"
                    }
                    self.recommendations.append(recommendation)
    
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
    
    def get_all_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get detailed statistics for all metrics."""
        result = {}
        for name, metric in self.performance_metrics.items():
            result[name] = metric.get_stats()
        return result
    
    def get_bottlenecks(self) -> List[Dict[str, Any]]:
        """Get list of detected bottlenecks."""
        return self.bottlenecks
    
    def get_recommendations(self) -> List[Dict[str, Any]]:
        """Get optimization recommendations."""
        return self.recommendations
    
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
        all_metrics = self.get_all_metrics()
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "overview": {
                "packets_processed": metrics["packets_processed"],
                "processing_rate": f"{metrics['processing_rate']:.2f} packets/second",
                "average_processing_time": f"{metrics['average_processing_time'] * 1000:.2f} ms",
                "memory_usage": f"{metrics['memory_usage'] / 1024 / 1024:.2f} MB",
                "cpu_usage": f"{metrics['cpu_usage']:.1f}%"
            },
            "detailed_metrics": all_metrics,
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
            },
            "bottlenecks": self.get_bottlenecks(),
            "recommendations": self.get_recommendations()
        }
        
        # Add system health score
        # 100 is optimal, lower values indicate problems
        cpu_health = max(0, 100 - metrics.get('cpu_usage', 0))
        memory_health = max(0, 100 - (metrics.get('memory_usage', 0) / psutil.virtual_memory().total * 100))
        processing_health = max(0, 100 - min(100, metrics.get('average_processing_time', 0) * 1000 / 2))
        
        bottleneck_penalty = min(50, len(self.bottlenecks) * 5)
        
        health_score = (cpu_health * 0.3 + memory_health * 0.3 + processing_health * 0.4) - bottleneck_penalty
        health_score = max(0, min(100, health_score))
        
        report["health_score"] = round(health_score, 1)
        
        return report


def measure_performance(metric_name: str = "function_execution_time"):
    """Decorator to measure function execution time"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            
            # Get the global performance monitor
            from app.utils.global_state import get_performance_monitor
            performance_monitor = get_performance_monitor()
            
            # Record the execution time
            performance_monitor.record_metric(metric_name, execution_time * 1000)  # Convert to ms
            
            return result
        return wrapper
    return decorator 