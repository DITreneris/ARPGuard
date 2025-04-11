import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("arp_guard.global")

# Global state container
_global_state = {
    "performance_monitor": None,
    "memory_profiler": None,
    "cpu_profiler": None,
    "settings": {}
}

def set_global_state(key: str, value: Any) -> None:
    """Set a value in the global state dictionary."""
    global _global_state
    _global_state[key] = value
    logger.debug(f"Global state updated: {key}")

def get_global_state(key: str, default: Any = None) -> Any:
    """Get a value from the global state dictionary."""
    return _global_state.get(key, default)

def get_performance_monitor():
    """Get the global performance monitor instance."""
    monitor = get_global_state("performance_monitor")
    if monitor is None:
        # Lazy import to avoid circular imports
        from app.utils.performance import PerformanceMonitor
        monitor = PerformanceMonitor()
        set_global_state("performance_monitor", monitor)
    return monitor

def get_memory_profiler():
    """Get the global memory profiler instance."""
    profiler = get_global_state("memory_profiler")
    if profiler is None:
        # Lazy import to avoid circular imports
        from app.utils.memory_profiler import MemoryProfiler
        profiler = MemoryProfiler()
        set_global_state("memory_profiler", profiler)
    return profiler

def get_cpu_profiler():
    """Get the global CPU profiler instance."""
    profiler = get_global_state("cpu_profiler")
    if profiler is None:
        from app.utils.cpu_profiler import CPUProfiler
        profiler = CPUProfiler(enable_system_monitoring=True, enable_process_profiling=True)
        set_global_state("cpu_profiler", profiler)
        logger.info("CPU profiler initialized")
    return profiler

def get_setting(key: str, default: Any = None) -> Any:
    """Get a setting from the global settings dictionary."""
    settings = get_global_state("settings", {})
    return settings.get(key, default)

def set_setting(key: str, value: Any) -> None:
    """Set a setting in the global settings dictionary."""
    settings = get_global_state("settings", {})
    settings[key] = value
    set_global_state("settings", settings)

def initialize_profilers(enable_performance: bool = True, 
                         enable_memory: bool = True,
                         enable_cpu: bool = True) -> Dict[str, Any]:
    """Initialize all profilers and return their instances."""
    profilers = {}
    
    if enable_performance:
        performance_monitor = get_performance_monitor()
        profilers["performance"] = performance_monitor
    
    if enable_memory:
        memory_profiler = get_memory_profiler()
        profilers["memory"] = memory_profiler
    
    if enable_cpu:
        cpu_profiler = get_cpu_profiler()
        if cpu_profiler:
            profilers["cpu"] = cpu_profiler
    
    return profilers

def shutdown_profilers() -> None:
    """Shut down all active profilers."""
    performance_monitor = get_global_state("performance_monitor")
    if performance_monitor:
        try:
            performance_monitor.stop()
            logger.info("Performance monitor stopped")
        except Exception as e:
            logger.error(f"Error stopping performance monitor: {e}")
    
    memory_profiler = get_global_state("memory_profiler")
    if memory_profiler:
        try:
            memory_profiler.stop()
            logger.info("Memory profiler stopped")
        except Exception as e:
            logger.error(f"Error stopping memory profiler: {e}")
    
    cpu_profiler = get_global_state("cpu_profiler")
    if cpu_profiler:
        try:
            cpu_profiler.stop()
            logger.info("CPU profiler stopped")
        except Exception as e:
            logger.error(f"Error stopping CPU profiler: {e}") 