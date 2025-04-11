import os
import time
import uuid
import logging
import threading
import psutil
from typing import Dict, List, Optional, Any, Counter, Tuple
from datetime import datetime, timedelta
from collections import deque, defaultdict
import cProfile
import pstats
import io
from dataclasses import dataclass, field

logger = logging.getLogger("arp_guard.utils.cpu_profiler")

@dataclass
class CPUSnapshot:
    """Represents a snapshot of CPU usage at a point in time"""
    snapshot_id: str
    timestamp: datetime
    label: str
    total_cpu_percent: float
    per_cpu_percent: List[float]
    process_cpu_percent: float
    process_threads: List[Dict[str, Any]]
    top_processes: List[Dict[str, Any]]
    profiling_stats: Optional[Dict[str, Any]] = None
    system_stats: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"CPUSnapshot(id={self.snapshot_id[:8]}, label={self.label}, cpu={self.process_cpu_percent:.1f}%, time={self.timestamp})"


class CPUProfiler:
    """CPU profiler for tracking application CPU usage and identifying hotspots."""
    
    def __init__(self, 
                 enable_system_monitoring: bool = True,
                 enable_process_profiling: bool = True,
                 history_size: int = 20):
        """
        Initialize the CPU profiler.
        
        Args:
            enable_system_monitoring: If True, collect system-wide CPU metrics
            enable_process_profiling: If True, use cProfile for function-level profiling
            history_size: Number of snapshots to keep in history
        """
        self.enable_system_monitoring = enable_system_monitoring
        self.enable_process_profiling = enable_process_profiling
        self.history_size = history_size
        
        # Store CPU snapshots
        self.snapshots: Dict[str, CPUSnapshot] = {}
        
        # Track baseline for comparison
        self.baseline_snapshot_id: Optional[str] = None
        
        # Process for gathering metrics
        self.process = psutil.Process(os.getpid())
        
        # Profiling with cProfile
        self.profiler = None if not enable_process_profiling else cProfile.Profile()
        self.is_profiling = False
        self.profiling_lock = threading.Lock()
        
        # Track recent CPU history for trend analysis
        self.cpu_history = deque(maxlen=60)  # Last 60 snapshots for trend analysis
        
        # Thresholds for alerts
        self.cpu_high_threshold = 80.0  # Percentage
        self.cpu_critical_threshold = 95.0  # Percentage
        
        # Thread activity
        self.monitoring_thread = None
        self.monitoring_active = False
        self.monitoring_interval = 1.0  # seconds
        
        logger.info("CPU profiler initialized")
    
    def take_snapshot(self, label: Optional[str] = None) -> str:
        """
        Take a snapshot of current CPU usage.
        
        Args:
            label: Optional label for this snapshot
            
        Returns:
            ID of the created snapshot
        """
        snapshot_id = str(uuid.uuid4())
        timestamp = datetime.now()
        
        # Get CPU info
        try:
            total_cpu_percent = psutil.cpu_percent(interval=0.1)
            per_cpu_percent = psutil.cpu_percent(interval=0.1, percpu=True)
            process_cpu_percent = self.process.cpu_percent(interval=0.1)
        except Exception as e:
            logger.error(f"Failed to get CPU percentages: {str(e)}")
            total_cpu_percent = 0.0
            per_cpu_percent = []
            process_cpu_percent = 0.0
        
        # Get thread info for this process
        process_threads = []
        try:
            for thread in self.process.threads():
                process_threads.append({
                    "id": thread.id,
                    "user_time": thread.user_time,
                    "system_time": thread.system_time,
                })
        except Exception as e:
            logger.error(f"Failed to get thread info: {str(e)}")
        
        # Get top processes by CPU usage
        top_processes = []
        if self.enable_system_monitoring:
            try:
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                    processes.append(proc.info)
                
                # Sort by CPU percent and get top 5
                processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
                top_processes = processes[:5]
            except Exception as e:
                logger.error(f"Failed to get top processes: {str(e)}")
        
        # Get cProfile stats if profiling is active
        profiling_stats = None
        if self.enable_process_profiling and self.is_profiling:
            with self.profiling_lock:
                if self.profiler:
                    s = io.StringIO()
                    ps = pstats.Stats(self.profiler, stream=s).sort_stats('cumulative')
                    ps.print_stats(20)  # Get top 20 functions by cumulative time
                    
                    # Parse the text output
                    profiling_stats = self._parse_profiling_stats(s.getvalue())
        
        # Get system stats
        system_stats = {}
        if self.enable_system_monitoring:
            try:
                system_stats = {
                    "load_avg": psutil.getloadavg(),
                    "context_switches": psutil.cpu_stats().ctx_switches,
                    "interrupts": psutil.cpu_stats().interrupts,
                    "soft_interrupts": psutil.cpu_stats().soft_interrupts,
                    "syscalls": getattr(psutil.cpu_stats(), 'syscalls', 0),
                }
            except Exception as e:
                logger.error(f"Failed to get system stats: {str(e)}")
        
        # Create and store snapshot
        snapshot = CPUSnapshot(
            snapshot_id=snapshot_id,
            timestamp=timestamp,
            label=label or f"snapshot_{snapshot_id[:8]}",
            total_cpu_percent=total_cpu_percent,
            per_cpu_percent=per_cpu_percent,
            process_cpu_percent=process_cpu_percent,
            process_threads=process_threads,
            top_processes=top_processes,
            profiling_stats=profiling_stats,
            system_stats=system_stats
        )
        
        self.snapshots[snapshot_id] = snapshot
        
        # Add to history for trend analysis
        self.cpu_history.append((timestamp, process_cpu_percent))
        
        # Maintain history size
        if len(self.snapshots) > self.history_size:
            oldest_id = min(self.snapshots.items(), key=lambda x: x[1].timestamp)[0]
            # Don't remove baseline
            if oldest_id != self.baseline_snapshot_id:
                del self.snapshots[oldest_id]
        
        logger.debug(f"CPU snapshot taken: {snapshot}")
        return snapshot_id
    
    def _parse_profiling_stats(self, stats_text: str) -> Dict[str, Any]:
        """Parse cProfile text output into structured data"""
        result = {
            "functions": []
        }
        
        lines = stats_text.strip().split('\n')
        
        # Skip header lines
        data_lines = [line for line in lines if line.strip() and not line.startswith('ncalls')]
        
        for line in data_lines:
            if line and not line.startswith(' '):
                continue
                
            # Parse line with stats for a function
            parts = line.strip().split()
            if len(parts) >= 6:
                # Format: ncalls tottime percall cumtime percall filename:lineno(function)
                function_info = ' '.join(parts[5:])
                result["functions"].append({
                    "ncalls": parts[0],
                    "tottime": float(parts[1]),
                    "percall_tot": float(parts[2]),
                    "cumtime": float(parts[3]),
                    "percall_cum": float(parts[4]),
                    "function_info": function_info
                })
        
        return result
    
    def get_snapshot(self, snapshot_id: str) -> Optional[CPUSnapshot]:
        """
        Get a specific CPU snapshot.
        
        Args:
            snapshot_id: ID of the snapshot to retrieve
            
        Returns:
            The snapshot or None if not found
        """
        return self.snapshots.get(snapshot_id)
    
    def get_all_snapshots(self) -> Dict[str, CPUSnapshot]:
        """
        Get all stored snapshots.
        
        Returns:
            Dict mapping snapshot IDs to snapshots
        """
        return self.snapshots.copy()
    
    def set_baseline(self, snapshot_id: Optional[str] = None) -> Optional[str]:
        """
        Set a snapshot as the baseline for comparisons.
        
        Args:
            snapshot_id: ID of snapshot to use as baseline (if None, take a new snapshot)
            
        Returns:
            The baseline snapshot ID or None if failed
        """
        if snapshot_id is None:
            # Take a new snapshot for baseline
            snapshot_id = self.take_snapshot(label="baseline")
        
        if snapshot_id in self.snapshots:
            self.baseline_snapshot_id = snapshot_id
            logger.info(f"Set CPU baseline to snapshot {snapshot_id[:8]}")
            return snapshot_id
        
        logger.error(f"Failed to set baseline: snapshot {snapshot_id} not found")
        return None
    
    def clear_snapshots(self, preserve_baseline: bool = True) -> None:
        """
        Clear all snapshots.
        
        Args:
            preserve_baseline: If True, keep the baseline snapshot
        """
        if preserve_baseline and self.baseline_snapshot_id:
            baseline = self.snapshots.get(self.baseline_snapshot_id)
            self.snapshots.clear()
            if baseline:
                self.snapshots[self.baseline_snapshot_id] = baseline
        else:
            self.snapshots.clear()
            self.baseline_snapshot_id = None
        
        logger.info("CPU snapshots cleared")
    
    def start_profiling(self) -> bool:
        """
        Start CPU profiling.
        
        Returns:
            True if profiling started successfully
        """
        if not self.enable_process_profiling:
            logger.warning("Process profiling is disabled")
            return False
        
        with self.profiling_lock:
            if self.is_profiling:
                logger.warning("Profiling already active")
                return False
            
            if self.profiler is None:
                self.profiler = cProfile.Profile()
            
            try:
                self.profiler.enable()
                self.is_profiling = True
                logger.info("CPU profiling started")
                return True
            except Exception as e:
                logger.error(f"Failed to start CPU profiling: {str(e)}")
                return False
    
    def stop_profiling(self) -> bool:
        """
        Stop CPU profiling.
        
        Returns:
            True if profiling stopped successfully
        """
        if not self.enable_process_profiling:
            return False
        
        with self.profiling_lock:
            if not self.is_profiling:
                logger.warning("Profiling not active")
                return False
            
            try:
                self.profiler.disable()
                self.is_profiling = False
                logger.info("CPU profiling stopped")
                
                # Take a snapshot with profiling results
                self.take_snapshot(label="profile_results")
                
                return True
            except Exception as e:
                logger.error(f"Failed to stop CPU profiling: {str(e)}")
                return False
    
    def identify_hotspots(self, snapshot_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Identify CPU usage hotspots from profiling data.
        
        Args:
            snapshot_id: ID of snapshot to analyze (if None, use the most recent)
            
        Returns:
            List of hotspots, each a dict with function information and CPU usage
        """
        # Get the right snapshot
        snapshot = None
        if snapshot_id:
            snapshot = self.snapshots.get(snapshot_id)
        else:
            # Find the most recent snapshot with profiling data
            profiled_snapshots = [s for s in self.snapshots.values() if s.profiling_stats]
            if profiled_snapshots:
                snapshot = max(profiled_snapshots, key=lambda s: s.timestamp)
        
        if not snapshot or not snapshot.profiling_stats:
            logger.warning("No profiling data available for hotspot identification")
            return []
        
        # Extract hotspots from the profiling data
        hotspots = []
        for func in snapshot.profiling_stats.get("functions", []):
            if func.get("cumtime", 0) > 0.01:  # Focus on functions taking more than 10ms
                hotspots.append({
                    "function": func.get("function_info", "unknown"),
                    "cumulative_time": func.get("cumtime", 0),
                    "total_time": func.get("tottime", 0),
                    "calls": func.get("ncalls", "0")
                })
        
        # Sort by cumulative time
        hotspots.sort(key=lambda x: x["cumulative_time"], reverse=True)
        return hotspots[:10]  # Return top 10 hotspots
    
    def get_optimization_recommendations(self) -> List[Dict[str, Any]]:
        """
        Generate optimization recommendations based on CPU profiling.
        
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Get hotspots
        hotspots = self.identify_hotspots()
        
        if hotspots:
            recommendations.append({
                "type": "function_optimization",
                "severity": "medium",
                "description": f"CPU hotspots identified in {len(hotspots)} functions",
                "details": hotspots[:3],  # Top 3 hotspots
                "suggestion": "Consider optimizing these functions or adding caching"
            })
        
        # Check for CPU trends
        if len(self.cpu_history) >= 10:
            recent_cpu = [cpu for _, cpu in list(self.cpu_history)[-10:]]
            avg_cpu = sum(recent_cpu) / len(recent_cpu)
            
            if avg_cpu > self.cpu_high_threshold:
                recommendations.append({
                    "type": "high_cpu_usage",
                    "severity": "high" if avg_cpu > self.cpu_critical_threshold else "medium",
                    "description": f"Sustained high CPU usage: {avg_cpu:.1f}%",
                    "suggestion": "Consider adding background worker threads or optimizing processing logic"
                })
        
        # Check for CPU imbalance across cores
        latest_snapshot = max(self.snapshots.values(), key=lambda s: s.timestamp)
        if latest_snapshot.per_cpu_percent and len(latest_snapshot.per_cpu_percent) > 1:
            max_cpu = max(latest_snapshot.per_cpu_percent)
            min_cpu = min(latest_snapshot.per_cpu_percent)
            
            if max_cpu > 70 and (max_cpu - min_cpu) > 40:
                recommendations.append({
                    "type": "cpu_imbalance",
                    "severity": "medium",
                    "description": f"CPU core utilization imbalance detected (max: {max_cpu:.1f}%, min: {min_cpu:.1f}%)",
                    "suggestion": "Consider using a thread pool with better work distribution"
                })
        
        return recommendations
    
    def compare_snapshots(self, first_id: str, second_id: str) -> Dict[str, Any]:
        """
        Compare two CPU snapshots.
        
        Args:
            first_id: ID of the first snapshot
            second_id: ID of the second snapshot
            
        Returns:
            Dict with comparison results
            
        Raises:
            ValueError: If snapshots not found
        """
        first = self.snapshots.get(first_id)
        second = self.snapshots.get(second_id)
        
        if not first or not second:
            missing = first_id if not first else second_id
            raise ValueError(f"Snapshot {missing} not found")
        
        # Ensure first is the earlier snapshot
        if first.timestamp > second.timestamp:
            first, second = second, first
            first_id, second_id = second_id, first_id
        
        # Calculate time difference
        time_diff = (second.timestamp - first.timestamp).total_seconds()
        
        # Calculate CPU differences
        cpu_diff = second.process_cpu_percent - first.process_cpu_percent
        total_cpu_diff = second.total_cpu_percent - first.total_cpu_percent
        
        result = {
            "first_snapshot": {
                "id": first_id,
                "label": first.label,
                "timestamp": first.timestamp
            },
            "second_snapshot": {
                "id": second_id,
                "label": second.label,
                "timestamp": second.timestamp
            },
            "time_difference_seconds": time_diff,
            "cpu_differences": {
                "process_cpu_percent": cpu_diff,
                "total_cpu_percent": total_cpu_diff
            }
        }
        
        # Compare thread info if available
        if first.process_threads and second.process_threads:
            # Create maps of thread IDs to thread info
            first_threads = {t["id"]: t for t in first.process_threads}
            second_threads = {t["id"]: t for t in second.process_threads}
            
            # Find common threads
            common_thread_ids = set(first_threads.keys()) & set(second_threads.keys())
            
            # Calculate differences for common threads
            thread_diffs = []
            for thread_id in common_thread_ids:
                first_thread = first_threads[thread_id]
                second_thread = second_threads[thread_id]
                
                user_time_diff = second_thread["user_time"] - first_thread["user_time"]
                system_time_diff = second_thread["system_time"] - first_thread["system_time"]
                
                if user_time_diff > 0 or system_time_diff > 0:
                    thread_diffs.append({
                        "thread_id": thread_id,
                        "user_time_diff": user_time_diff,
                        "system_time_diff": system_time_diff,
                        "total_time_diff": user_time_diff + system_time_diff
                    })
            
            # Sort by total time difference
            thread_diffs.sort(key=lambda x: x["total_time_diff"], reverse=True)
            result["thread_differences"] = thread_diffs[:5]  # Top 5 threads
        
        return result
    
    def calculate_health_score(self) -> float:
        """
        Calculate a health score based on CPU usage and trends.
        
        Returns:
            Health score from 0.0 (bad) to 100.0 (excellent)
        """
        score = 100.0
        
        # Get latest CPU usage
        if not self.snapshots:
            return score
        
        latest_snapshot = max(self.snapshots.values(), key=lambda s: s.timestamp)
        cpu_percent = latest_snapshot.process_cpu_percent
        
        # Penalize for high current CPU usage
        if cpu_percent > 90:
            score -= 30
        elif cpu_percent > 80:
            score -= 20
        elif cpu_percent > 70:
            score -= 10
        elif cpu_percent > 60:
            score -= 5
        
        # Analyze CPU trend
        if len(self.cpu_history) >= 10:
            recent_cpu = [cpu for _, cpu in list(self.cpu_history)[-10:]]
            avg_cpu = sum(recent_cpu) / len(recent_cpu)
            
            # Check if trend is increasing
            if len(recent_cpu) >= 5:
                first_half = recent_cpu[:len(recent_cpu)//2]
                second_half = recent_cpu[len(recent_cpu)//2:]
                
                first_half_avg = sum(first_half) / len(first_half)
                second_half_avg = sum(second_half) / len(second_half)
                
                if second_half_avg > first_half_avg:
                    # CPU usage is increasing
                    increase_pct = ((second_half_avg - first_half_avg) / first_half_avg) * 100 if first_half_avg > 0 else 0
                    
                    if increase_pct > 50:  # More than 50% increase
                        score -= 20
                    elif increase_pct > 25:  # 25-50% increase
                        score -= 10
                    elif increase_pct > 10:  # 10-25% increase
                        score -= 5
            
            # Penalize for sustained high CPU
            if avg_cpu > 85:
                score -= 25
            elif avg_cpu > 75:
                score -= 15
            elif avg_cpu > 65:
                score -= 5
        
        # Ensure score is within bounds
        score = max(0.0, min(100.0, score))
        
        return score
    
    def start_monitoring(self, interval: float = 1.0) -> bool:
        """
        Start background monitoring of CPU usage.
        
        Args:
            interval: Monitoring interval in seconds
            
        Returns:
            True if monitoring started successfully
        """
        if self.monitoring_active:
            logger.warning("Monitoring already active")
            return False
        
        self.monitoring_interval = interval
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True,
            name="CPUMonitoringThread"
        )
        self.monitoring_thread.start()
        
        logger.info(f"CPU monitoring started with interval {interval}s")
        return True
    
    def stop_monitoring(self) -> None:
        """Stop background CPU monitoring."""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=2.0)
            logger.info("CPU monitoring thread stopped")
    
    def _monitoring_loop(self) -> None:
        """Background thread for CPU monitoring."""
        last_snapshot_time = datetime.now() - timedelta(seconds=self.monitoring_interval * 2)
        
        while self.monitoring_active:
            try:
                current_time = datetime.now()
                
                # Take snapshot at the specified interval
                if (current_time - last_snapshot_time).total_seconds() >= self.monitoring_interval:
                    self.take_snapshot(label=f"monitor_{current_time.strftime('%H:%M:%S')}")
                    last_snapshot_time = current_time
                
                # Short sleep to prevent CPU hogging
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"Error in CPU monitoring loop: {str(e)}")
                time.sleep(1.0)  # Longer sleep on error
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of CPU usage and profiling.
        
        Returns:
            Dict with CPU usage summary
        """
        if not self.snapshots:
            return {
                "current": {
                    "cpu_percent": 0,
                    "timestamp": datetime.now().isoformat()
                },
                "history": [],
                "health_score": 100.0,
                "baseline": None
            }
        
        # Get latest snapshot
        latest_snapshot = max(self.snapshots.values(), key=lambda s: s.timestamp)
        
        # Get baseline if set
        baseline = None
        baseline_diff = 0
        if self.baseline_snapshot_id:
            baseline_snapshot = self.snapshots.get(self.baseline_snapshot_id)
            if baseline_snapshot:
                baseline = {
                    "snapshot_id": self.baseline_snapshot_id,
                    "label": baseline_snapshot.label,
                    "timestamp": baseline_snapshot.timestamp.isoformat(),
                    "cpu_percent": baseline_snapshot.process_cpu_percent
                }
                baseline_diff = latest_snapshot.process_cpu_percent - baseline_snapshot.process_cpu_percent
        
        # Calculate metrics from history
        history_entries = list(self.cpu_history)
        history_dict = []
        
        # Calculate recent history (last 10 entries) with timestamps
        for ts, cpu in history_entries[-10:]:
            history_dict.append({
                "timestamp": ts.isoformat(),
                "cpu_percent": cpu
            })
        
        # Calculate average CPU usage
        avg_cpu = 0
        if history_entries:
            cpu_values = [cpu for _, cpu in history_entries]
            avg_cpu = sum(cpu_values) / len(cpu_values)
        
        # Get hotspots
        hotspots = self.identify_hotspots()
        
        return {
            "current": {
                "cpu_percent": latest_snapshot.process_cpu_percent,
                "timestamp": latest_snapshot.timestamp.isoformat(),
                "total_cpu_percent": latest_snapshot.total_cpu_percent,
                "per_cpu_percent": latest_snapshot.per_cpu_percent,
            },
            "history": history_dict,
            "average_cpu": avg_cpu,
            "health_score": self.calculate_health_score(),
            "baseline": baseline,
            "baseline_diff": baseline_diff,
            "hotspots": hotspots[:5] if hotspots else [],
            "system_stats": latest_snapshot.system_stats if latest_snapshot.system_stats else {},
            "snapshot_count": len(self.snapshots)
        }
    
    def stop(self) -> None:
        """Clean up resources used by the profiler."""
        self.stop_monitoring()
        
        if self.is_profiling:
            self.stop_profiling()
        
        self.snapshots.clear()
        logger.info("CPU profiler shut down")


# Decorator for CPU profiling
def profile_cpu(label=None):
    """Decorator to profile CPU usage of a function."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Get profiler from global state
            from app.utils.global_state import get_cpu_profiler
            profiler = get_cpu_profiler()
            
            if profiler:
                # Start profiling
                was_profiling = profiler.is_profiling
                if not was_profiling:
                    profiler.start_profiling()
                
                # Take before snapshot
                func_name = func.__name__
                before_label = f"{func_name}_start" if label is None else f"{label}_start"
                profiler.take_snapshot(before_label)
            
            # Call the function
            result = func(*args, **kwargs)
            
            if profiler:
                # Take after snapshot
                after_label = f"{func_name}_end" if label is None else f"{label}_end"
                profiler.take_snapshot(after_label)
                
                # Stop profiling if we started it
                if not was_profiling:
                    profiler.stop_profiling()
            
            return result
        return wrapper
    return decorator 