import tracemalloc
import linecache
import os
import gc
import sys
import logging
import psutil
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, DefaultDict
from collections import defaultdict, Counter

logger = logging.getLogger("arp_guard.utils.memory_profiler")

class MemorySnapshot:
    """Class representing a snapshot of memory usage at a point in time."""
    
    def __init__(self, 
                 snapshot_id: str, 
                 timestamp: datetime,
                 label: str,
                 rss: int,
                 vms: int,
                 uss: Optional[int] = None,
                 pss: Optional[int] = None,
                 cpu_percent: float = 0.0,
                 tracemalloc_snapshot = None,
                 object_counts: Optional[Counter] = None):
        """
        Initialize a memory snapshot.
        
        Args:
            snapshot_id: Unique ID for this snapshot
            timestamp: Time when snapshot was taken
            label: User-provided label for this snapshot
            rss: Resident set size in bytes
            vms: Virtual memory size in bytes
            uss: Unique set size in bytes (optional)
            pss: Proportional set size in bytes (optional)
            cpu_percent: CPU usage percentage at snapshot time
            tracemalloc_snapshot: Tracemalloc snapshot object (if enabled)
            object_counts: Counter of Python object types
        """
        self.snapshot_id = snapshot_id
        self.timestamp = timestamp
        self.label = label
        self.rss = rss
        self.vms = vms
        self.uss = uss
        self.pss = pss
        self.cpu_percent = cpu_percent
        self.tracemalloc_snapshot = tracemalloc_snapshot
        self.object_counts = object_counts or Counter()
    
    def __repr__(self):
        return f"<MemorySnapshot id={self.snapshot_id} label={self.label} rss={self.rss/1024/1024:.2f}MB>"


class MemoryProfiler:
    """Memory profiler for tracking application memory usage."""
    
    def __init__(self, enable_tracemalloc: bool = True, track_objects: bool = True):
        """
        Initialize the memory profiler.
        
        Args:
            enable_tracemalloc: Whether to enable tracemalloc for detailed memory tracking
            track_objects: Whether to track Python object counts
        """
        self.process = psutil.Process(os.getpid())
        self.enable_tracemalloc = enable_tracemalloc
        self.track_objects = track_objects
        self.snapshots: Dict[str, MemorySnapshot] = {}
        self.baseline_snapshot_id: Optional[str] = None
        self._is_tracemalloc_started = False
        
        # Start tracemalloc if enabled
        if enable_tracemalloc and not tracemalloc.is_tracing():
            try:
                tracemalloc.start(25)  # Capture 25 frames
                self._is_tracemalloc_started = True
                logger.info("Tracemalloc started for memory profiling")
            except Exception as e:
                logger.error(f"Failed to start tracemalloc: {str(e)}")
        
        # Take initial baseline snapshot
        self.baseline_snapshot_id = self.take_snapshot(label="baseline")
        logger.info(f"Memory profiler initialized with baseline snapshot {self.baseline_snapshot_id}")
    
    def take_snapshot(self, label: Optional[str] = None) -> str:
        """
        Take a snapshot of current memory usage.
        
        Args:
            label: Optional label for this snapshot
            
        Returns:
            ID of the created snapshot
        """
        snapshot_id = str(uuid.uuid4())
        timestamp = datetime.now()
        
        # Get memory info
        mem_info = self.process.memory_info()
        rss = mem_info.rss
        vms = mem_info.vms
        
        # Get extra memory metrics if available
        try:
            extended_mem = self.process.memory_full_info()
            uss = getattr(extended_mem, 'uss', None)
            pss = getattr(extended_mem, 'pss', None)
        except Exception:
            uss = None
            pss = None
        
        # Get CPU usage
        cpu_percent = self.process.cpu_percent(interval=0.1)
        
        # Get tracemalloc snapshot if enabled
        tracemalloc_snapshot = None
        if self.enable_tracemalloc and self._is_tracemalloc_started:
            try:
                tracemalloc_snapshot = tracemalloc.take_snapshot()
            except Exception as e:
                logger.error(f"Failed to take tracemalloc snapshot: {str(e)}")
        
        # Get object counts if tracking is enabled
        object_counts = None
        if self.track_objects:
            object_counts = self._get_object_counts()
        
        # Create and store snapshot
        snapshot = MemorySnapshot(
            snapshot_id=snapshot_id,
            timestamp=timestamp,
            label=label or f"snapshot_{snapshot_id[:8]}",
            rss=rss,
            vms=vms,
            uss=uss,
            pss=pss,
            cpu_percent=cpu_percent,
            tracemalloc_snapshot=tracemalloc_snapshot,
            object_counts=object_counts
        )
        self.snapshots[snapshot_id] = snapshot
        
        logger.debug(f"Memory snapshot taken: {snapshot}")
        return snapshot_id
    
    def get_snapshot(self, snapshot_id: str) -> Optional[MemorySnapshot]:
        """
        Get a snapshot by ID.
        
        Args:
            snapshot_id: ID of the snapshot to retrieve
            
        Returns:
            MemorySnapshot object or None if not found
        """
        return self.snapshots.get(snapshot_id)
    
    def get_all_snapshots(self) -> Dict[str, MemorySnapshot]:
        """
        Get all stored snapshots.
        
        Returns:
            Dictionary of snapshot_id to MemorySnapshot
        """
        return self.snapshots
    
    def clear_snapshots(self, keep_baseline: bool = True) -> None:
        """
        Clear all stored snapshots.
        
        Args:
            keep_baseline: Whether to keep the baseline snapshot
        """
        if keep_baseline and self.baseline_snapshot_id:
            baseline = self.snapshots.get(self.baseline_snapshot_id)
            self.snapshots.clear()
            if baseline:
                self.snapshots[self.baseline_snapshot_id] = baseline
        else:
            self.snapshots.clear()
        
        logger.info("Memory snapshots cleared")
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of memory usage.
        
        Returns:
            Dictionary with memory usage summary
        """
        # Get current snapshot
        current_snapshot_id = self.take_snapshot(label="summary")
        current = self.snapshots[current_snapshot_id]
        
        # Get baseline for comparison
        baseline = None
        if self.baseline_snapshot_id:
            baseline = self.snapshots.get(self.baseline_snapshot_id)
        
        # Calculate changes from baseline
        rss_change = 0
        vms_change = 0
        rss_change_pct = 0
        vms_change_pct = 0
        
        if baseline:
            rss_change = current.rss - baseline.rss
            vms_change = current.vms - baseline.vms
            
            if baseline.rss > 0:
                rss_change_pct = (rss_change / baseline.rss) * 100
            
            if baseline.vms > 0:
                vms_change_pct = (vms_change / baseline.vms) * 100
        
        # Get top memory consumers if tracemalloc is enabled
        top_consumers = []
        if self.enable_tracemalloc and current.tracemalloc_snapshot:
            try:
                top_stats = current.tracemalloc_snapshot.statistics('lineno', limit=10)
                for stat in top_stats:
                    frame = stat.traceback[0]
                    top_consumers.append({
                        'file': frame.filename,
                        'line': frame.lineno,
                        'size': stat.size,
                        'count': stat.count
                    })
            except Exception as e:
                logger.error(f"Failed to get tracemalloc statistics: {str(e)}")
        
        # Calculate growth rate if we have at least 2 snapshots
        growth_rate = None
        if len(self.snapshots) >= 2:
            # Get the two most recent snapshots (excluding the current one)
            sorted_snapshots = sorted(
                [s for s in self.snapshots.values() if s.snapshot_id != current_snapshot_id],
                key=lambda x: x.timestamp,
                reverse=True
            )
            
            if len(sorted_snapshots) >= 2:
                recent = sorted_snapshots[0]
                previous = sorted_snapshots[1]
                
                time_diff = (recent.timestamp - previous.timestamp).total_seconds()
                if time_diff > 0:
                    rss_diff = recent.rss - previous.rss
                    growth_rate = rss_diff / time_diff  # bytes per second
        
        return {
            "current": {
                "rss": current.rss,
                "rss_mb": current.rss / (1024 * 1024),
                "vms": current.vms,
                "vms_mb": current.vms / (1024 * 1024),
                "uss": current.uss,
                "uss_mb": current.uss / (1024 * 1024) if current.uss else None,
                "cpu_percent": current.cpu_percent
            },
            "change_from_baseline": {
                "rss_bytes": rss_change,
                "rss_mb": rss_change / (1024 * 1024),
                "rss_percent": rss_change_pct,
                "vms_bytes": vms_change,
                "vms_mb": vms_change / (1024 * 1024),
                "vms_percent": vms_change_pct
            },
            "growth_rate": {
                "bytes_per_second": growth_rate,
                "mb_per_hour": (growth_rate * 3600) / (1024 * 1024) if growth_rate is not None else None
            },
            "top_consumers": top_consumers,
            "snapshot_count": len(self.snapshots)
        }
    
    def find_leaks(self, threshold_percent: float = 10.0) -> List[Dict[str, Any]]:
        """
        Find potential memory leaks by analyzing snapshots.
        
        Args:
            threshold_percent: Percentage increase threshold to consider as a leak
            
        Returns:
            List of potential memory leaks
        """
        if len(self.snapshots) < 2:
            return []
        
        leaks = []
        
        # Only analyze if we track objects
        if not self.track_objects:
            return []
        
        # Get the earliest and latest snapshots
        sorted_snapshots = sorted(self.snapshots.values(), key=lambda x: x.timestamp)
        earliest = sorted_snapshots[0]
        latest = sorted_snapshots[-1]
        
        # Compare object counts
        for obj_type, count in latest.object_counts.items():
            if obj_type in earliest.object_counts:
                earlier_count = earliest.object_counts[obj_type]
                if earlier_count > 0:
                    increase_percent = ((count - earlier_count) / earlier_count) * 100
                    if increase_percent > threshold_percent:
                        leaks.append({
                            "object_type": obj_type,
                            "initial_count": earlier_count,
                            "current_count": count,
                            "increase": count - earlier_count,
                            "increase_percent": increase_percent
                        })
        
        # Sort by increase percentage
        leaks.sort(key=lambda x: x["increase_percent"], reverse=True)
        
        return leaks
    
    def get_growth_by_type(self) -> Dict[str, Dict[str, Any]]:
        """
        Get memory growth by object type.
        
        Returns:
            Dictionary mapping object types to their growth details
        """
        if len(self.snapshots) < 2 or not self.track_objects:
            return {}
        
        # Get the earliest and latest snapshots
        sorted_snapshots = sorted(self.snapshots.values(), key=lambda x: x.timestamp)
        earliest = sorted_snapshots[0]
        latest = sorted_snapshots[-1]
        
        result = {}
        
        # Compare object counts for all types
        all_types = set(list(earliest.object_counts.keys()) + list(latest.object_counts.keys()))
        
        for obj_type in all_types:
            earlier_count = earliest.object_counts.get(obj_type, 0)
            latest_count = latest.object_counts.get(obj_type, 0)
            
            change = latest_count - earlier_count
            change_percent = 0
            
            if earlier_count > 0:
                change_percent = (change / earlier_count) * 100
            
            result[obj_type] = {
                "initial_count": earlier_count,
                "current_count": latest_count,
                "change": change,
                "change_percent": change_percent
            }
        
        return result
    
    def compare_snapshots(self, snapshot_id1: str, snapshot_id2: str) -> Dict[str, Any]:
        """
        Compare two snapshots and return the differences.
        
        Args:
            snapshot_id1: ID of the first snapshot
            snapshot_id2: ID of the second snapshot
            
        Returns:
            Dictionary with memory usage differences
        """
        snapshot1 = self.get_snapshot(snapshot_id1)
        snapshot2 = self.get_snapshot(snapshot_id2)
        
        if not snapshot1 or not snapshot2:
            missing = []
            if not snapshot1:
                missing.append(snapshot_id1)
            if not snapshot2:
                missing.append(snapshot_id2)
            logger.error(f"Cannot compare snapshots, missing: {', '.join(missing)}")
            return {"error": f"Snapshots not found: {', '.join(missing)}"}
        
        # Calculate changes
        rss_change = snapshot2.rss - snapshot1.rss
        vms_change = snapshot2.vms - snapshot1.vms
        
        rss_change_pct = 0
        vms_change_pct = 0
        
        if snapshot1.rss > 0:
            rss_change_pct = (rss_change / snapshot1.rss) * 100
        
        if snapshot1.vms > 0:
            vms_change_pct = (vms_change / snapshot1.vms) * 100
        
        # Compare tracemalloc snapshots if available
        tracemalloc_diff = []
        if (self.enable_tracemalloc and 
            snapshot1.tracemalloc_snapshot and 
            snapshot2.tracemalloc_snapshot):
            try:
                # Get top differences
                diff_stats = snapshot2.tracemalloc_snapshot.compare_to(
                    snapshot1.tracemalloc_snapshot, 'lineno', cumulative=True)
                
                for stat in diff_stats[:10]:  # Top 10 differences
                    frame = stat.traceback[0]
                    tracemalloc_diff.append({
                        'file': frame.filename,
                        'line': frame.lineno,
                        'size_diff': stat.size_diff,
                        'count_diff': stat.count_diff
                    })
            except Exception as e:
                logger.error(f"Failed to compare tracemalloc snapshots: {str(e)}")
        
        # Compare object counts if available
        object_diffs = {}
        if self.track_objects and snapshot1.object_counts and snapshot2.object_counts:
            all_types = set(list(snapshot1.object_counts.keys()) + 
                            list(snapshot2.object_counts.keys()))
            
            for obj_type in all_types:
                count1 = snapshot1.object_counts.get(obj_type, 0)
                count2 = snapshot2.object_counts.get(obj_type, 0)
                diff = count2 - count1
                
                if diff != 0:  # Only include types that changed
                    object_diffs[obj_type] = {
                        "before": count1,
                        "after": count2,
                        "diff": diff
                    }
        
        # Only keep top 15 object diffs by absolute difference
        if object_diffs:
            top_diffs = sorted(
                object_diffs.items(), 
                key=lambda x: abs(x[1]["diff"]), 
                reverse=True
            )[:15]
            object_diffs = dict(top_diffs)
        
        return {
            "snapshot1": {
                "id": snapshot1.snapshot_id,
                "label": snapshot1.label,
                "timestamp": snapshot1.timestamp,
                "rss": snapshot1.rss,
                "vms": snapshot1.vms
            },
            "snapshot2": {
                "id": snapshot2.snapshot_id,
                "label": snapshot2.label,
                "timestamp": snapshot2.timestamp,
                "rss": snapshot2.rss,
                "vms": snapshot2.vms
            },
            "time_elapsed": (snapshot2.timestamp - snapshot1.timestamp).total_seconds(),
            "changes": {
                "rss_bytes": rss_change,
                "rss_mb": rss_change / (1024 * 1024),
                "rss_percent": rss_change_pct,
                "vms_bytes": vms_change,
                "vms_mb": vms_change / (1024 * 1024),
                "vms_percent": vms_change_pct
            },
            "tracemalloc_diff": tracemalloc_diff,
            "object_diffs": object_diffs
        }
    
    def force_garbage_collection(self) -> int:
        """
        Force Python garbage collection.
        
        Returns:
            Number of objects collected
        """
        # Take snapshot before GC
        before_snapshot_id = self.take_snapshot(label="before_gc")
        
        # Force garbage collection
        collected = gc.collect()
        logger.info(f"Forced garbage collection: {collected} objects collected")
        
        # Take snapshot after GC
        after_snapshot_id = self.take_snapshot(label="after_gc")
        
        # Compare and log the difference
        diff = self.compare_snapshots(before_snapshot_id, after_snapshot_id)
        logger.debug(f"Memory after GC: RSS change: {diff['changes']['rss_mb']:.2f}MB")
        
        return collected
    
    def calculate_health_score(self) -> float:
        """
        Calculate a health score based on memory usage and growth rate.
        
        Returns:
            Health score from 0.0 (bad) to 100.0 (excellent)
        """
        score = 100.0
        
        summary = self.get_summary()
        
        # Penalize for high growth rate
        growth_rate_mb_per_hour = summary.get("growth_rate", {}).get("mb_per_hour")
        if growth_rate_mb_per_hour is not None and growth_rate_mb_per_hour > 0:
            # Penalize more heavily for higher growth rates
            if growth_rate_mb_per_hour > 100:  # More than 100MB/hour
                score -= 50
            elif growth_rate_mb_per_hour > 50:  # 50-100MB/hour
                score -= 30
            elif growth_rate_mb_per_hour > 20:  # 20-50MB/hour
                score -= 20
            elif growth_rate_mb_per_hour > 10:  # 10-20MB/hour
                score -= 10
            elif growth_rate_mb_per_hour > 5:   # 5-10MB/hour
                score -= 5
        
        # Check for potential leaks
        leaks = self.find_leaks()
        if leaks:
            # Penalize based on number and severity of leaks
            leak_penalty = min(30, len(leaks) * 3)  # Maximum 30 points penalty
            score -= leak_penalty
        
        # Penalize for high absolute memory usage
        current_memory_mb = summary.get("current", {}).get("rss_mb", 0)
        if current_memory_mb > 1000:  # More than 1GB
            score -= 15
        elif current_memory_mb > 500:  # 500MB-1GB
            score -= 10
        elif current_memory_mb > 250:  # 250-500MB
            score -= 5
        
        # Ensure score is within bounds
        score = max(0.0, min(100.0, score))
        
        return score
    
    def _get_object_counts(self) -> Counter:
        """
        Count objects by type in memory.
        
        Returns:
            Counter mapping object types to counts
        """
        counts = Counter()
        
        try:
            # Get all objects
            for obj in gc.get_objects():
                obj_type = type(obj).__name__
                counts[obj_type] += 1
        except Exception as e:
            logger.error(f"Failed to count objects: {str(e)}")
        
        return counts
    
    def shutdown(self) -> None:
        """Clean up resources used by the profiler."""
        if self.enable_tracemalloc and self._is_tracemalloc_started:
            try:
                tracemalloc.stop()
                logger.info("Tracemalloc stopped")
            except Exception as e:
                logger.error(f"Error stopping tracemalloc: {str(e)}")
        
        self.snapshots.clear()
        logger.info("Memory profiler shut down")


# Decorator for memory profiling
def profile_memory(label=None):
    """Decorator to profile memory usage of a function."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Get profiler from global state
            from app.utils.global_state import get_memory_profiler
            profiler = get_memory_profiler()
            
            # Take before snapshot
            func_name = func.__name__
            before_label = f"{func_name}_start" if label is None else f"{label}_start"
            profiler.take_snapshot(before_label)
            
            # Call the function
            result = func(*args, **kwargs)
            
            # Take after snapshot
            after_label = f"{func_name}_end" if label is None else f"{label}_end"
            profiler.take_snapshot(after_label)
            
            return result
        return wrapper
    return decorator 