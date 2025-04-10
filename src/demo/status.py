from dataclasses import dataclass
from typing import Dict, Optional
import time
from datetime import datetime
import psutil
import json
import os

@dataclass
class DemoMetrics:
    """Metrics for the demo system"""
    start_time: float
    packets_processed: int = 0
    alerts_generated: int = 0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    network_usage: Dict[str, int] = None
    
    def __post_init__(self):
        if self.network_usage is None:
            self.network_usage = {"bytes_sent": 0, "bytes_received": 0}
    
    def to_dict(self) -> dict:
        """Convert metrics to dictionary"""
        return {
            "uptime": time.time() - self.start_time,
            "packets_processed": self.packets_processed,
            "alerts_generated": self.alerts_generated,
            "cpu_usage": self.cpu_usage,
            "memory_usage": self.memory_usage,
            "network_usage": self.network_usage
        }

class StatusReporter:
    """Status reporting system for ARP Guard demo"""
    
    def __init__(self, metrics_file: str = "demo_metrics.json"):
        self.metrics = DemoMetrics(start_time=time.time())
        self.metrics_file = metrics_file
        self._last_update = time.time()
        self._update_interval = 5  # seconds
    
    def update_metrics(self) -> None:
        """Update system metrics"""
        current_time = time.time()
        if current_time - self._last_update < self._update_interval:
            return
            
        # Update CPU and memory usage
        self.metrics.cpu_usage = psutil.cpu_percent()
        self.metrics.memory_usage = psutil.virtual_memory().percent
        
        # Update network usage
        net_io = psutil.net_io_counters()
        self.metrics.network_usage = {
            "bytes_sent": net_io.bytes_sent,
            "bytes_received": net_io.bytes_recv
        }
        
        self._last_update = current_time
    
    def increment_packets(self, count: int = 1) -> None:
        """Increment packet counter"""
        self.metrics.packets_processed += count
    
    def increment_alerts(self, count: int = 1) -> None:
        """Increment alert counter"""
        self.metrics.alerts_generated += count
    
    def get_status(self) -> dict:
        """Get current status"""
        self.update_metrics()
        return self.metrics.to_dict()
    
    def save_metrics(self) -> None:
        """Save metrics to file"""
        os.makedirs("data", exist_ok=True)
        with open(os.path.join("data", self.metrics_file), 'w') as f:
            json.dump(self.metrics.to_dict(), f, indent=4)
    
    def load_metrics(self) -> None:
        """Load metrics from file"""
        metrics_path = os.path.join("data", self.metrics_file)
        if os.path.exists(metrics_path):
            with open(metrics_path, 'r') as f:
                metrics_data = json.load(f)
                self.metrics.packets_processed = metrics_data.get("packets_processed", 0)
                self.metrics.alerts_generated = metrics_data.get("alerts_generated", 0)
                self.metrics.cpu_usage = metrics_data.get("cpu_usage", 0.0)
                self.metrics.memory_usage = metrics_data.get("memory_usage", 0.0)
                self.metrics.network_usage = metrics_data.get("network_usage", {"bytes_sent": 0, "bytes_received": 0})
    
    def reset_metrics(self) -> None:
        """Reset all metrics"""
        self.metrics = DemoMetrics(start_time=time.time())
    
    def format_status(self) -> str:
        """Format status for display"""
        status = self.get_status()
        return (
            f"Demo Status:\n"
            f"Uptime: {status['uptime']:.2f} seconds\n"
            f"Packets Processed: {status['packets_processed']}\n"
            f"Alerts Generated: {status['alerts_generated']}\n"
            f"CPU Usage: {status['cpu_usage']}%\n"
            f"Memory Usage: {status['memory_usage']}%\n"
            f"Network Usage:\n"
            f"  Bytes Sent: {status['network_usage']['bytes_sent']}\n"
            f"  Bytes Received: {status['network_usage']['bytes_received']}"
        ) 