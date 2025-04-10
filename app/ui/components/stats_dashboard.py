from typing import Dict, List, Optional, Any
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                           QFrame, QGridLayout, QGroupBox, QProgressBar)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QColor, QPainter, QPen, QBrush
from datetime import datetime, timedelta
from app.utils.performance_monitor import measure_performance

class MetricCard(QFrame):
    """Widget for displaying a single metric"""
    def __init__(self, title: str, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Sunken)
        self.setMinimumHeight(100)
        
        layout = QVBoxLayout(self)
        
        # Title
        self.title_label = QLabel(title)
        self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.title_label)
        
        # Value
        self.value_label = QLabel("0")
        self.value_label.setAlignment(Qt.AlignCenter)
        self.value_label.setStyleSheet("font-size: 24px;")
        layout.addWidget(self.value_label)
        
        # Trend indicator
        self.trend_label = QLabel("")
        self.trend_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.trend_label)
        
    def set_value(self, value: Any, unit: str = "") -> None:
        """Set the metric value"""
        self.value_label.setText(f"{value}{unit}")
        
    def set_trend(self, trend: str, color: QColor) -> None:
        """Set the trend indicator"""
        self.trend_label.setText(trend)
        self.trend_label.setStyleSheet(f"color: {color.name()};")

class StatsDashboard(QWidget):
    """Real-time statistics dashboard"""
    metrics_updated = pyqtSignal(dict)  # Emits when metrics are updated
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        
        # Create metric cards
        self.metrics = {}
        
        # Network metrics
        network_group = QGroupBox("Network Metrics")
        network_layout = QGridLayout(network_group)
        
        self.metrics['packets_processed'] = MetricCard("Packets Processed")
        self.metrics['attacks_detected'] = MetricCard("Attacks Detected")
        self.metrics['false_positives'] = MetricCard("False Positives")
        self.metrics['response_time'] = MetricCard("Avg Response Time")
        
        network_layout.addWidget(self.metrics['packets_processed'], 0, 0)
        network_layout.addWidget(self.metrics['attacks_detected'], 0, 1)
        network_layout.addWidget(self.metrics['false_positives'], 1, 0)
        network_layout.addWidget(self.metrics['response_time'], 1, 1)
        
        # System metrics
        system_group = QGroupBox("System Metrics")
        system_layout = QGridLayout(system_group)
        
        self.metrics['network_throughput'] = MetricCard("Network Throughput")
        self.metrics['cpu_usage'] = MetricCard("CPU Usage")
        self.metrics['memory_usage'] = MetricCard("Memory Usage")
        self.metrics['active_alerts'] = MetricCard("Active Alerts")
        
        system_layout.addWidget(self.metrics['network_throughput'], 0, 0)
        system_layout.addWidget(self.metrics['cpu_usage'], 0, 1)
        system_layout.addWidget(self.metrics['memory_usage'], 1, 0)
        system_layout.addWidget(self.metrics['active_alerts'], 1, 1)
        
        # Add groups to main layout
        self.layout.addWidget(network_group)
        self.layout.addWidget(system_group)
        
        # Setup update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_metrics)
        self.update_timer.start(1000)  # Update every second
        
        # Initialize historical data
        self.history = {key: [] for key in self.metrics.keys()}
        self.max_history = 60  # Keep 60 seconds of history
        
    @measure_performance('update_metrics')
    def update_metrics(self) -> None:
        """Update all metrics"""
        current_time = datetime.now()
        
        # Update network metrics
        self._update_metric('packets_processed', 1500, " pps")
        self._update_metric('attacks_detected', 5, "")
        self._update_metric('false_positives', 2, "")
        self._update_metric('response_time', 45, " ms")
        
        # Update system metrics
        self._update_metric('network_throughput', 1200, " KB/s")
        self._update_metric('cpu_usage', 65, "%")
        self._update_metric('memory_usage', 45, "%")
        self._update_metric('active_alerts', 3, "")
        
        # Emit update signal
        self.metrics_updated.emit({
            'timestamp': current_time,
            'metrics': {key: self.history[key][-1] if self.history[key] else 0
                       for key in self.metrics.keys()}
        })
        
    def _update_metric(self, key: str, value: float, unit: str) -> None:
        """Update a single metric with trend calculation"""
        # Add value to history
        self.history[key].append(value)
        if len(self.history[key]) > self.max_history:
            self.history[key].pop(0)
            
        # Calculate trend
        if len(self.history[key]) > 1:
            prev_value = self.history[key][-2]
            trend = value - prev_value
            
            if trend > 0:
                trend_text = f"↑ {trend:.1f}"
                color = QColor('#F44336')  # Red for increase
            elif trend < 0:
                trend_text = f"↓ {abs(trend):.1f}"
                color = QColor('#4CAF50')  # Green for decrease
            else:
                trend_text = "→ 0.0"
                color = QColor('#9E9E9E')  # Gray for no change
                
            self.metrics[key].set_trend(trend_text, color)
            
        # Update value
        self.metrics[key].set_value(f"{value:.1f}", unit)
        
    def start_updates(self, interval_ms: int = 1000) -> None:
        """Start metric updates"""
        self.update_timer.start(interval_ms)
        
    def stop_updates(self) -> None:
        """Stop metric updates"""
        self.update_timer.stop()
        
    def get_metric_history(self, key: str) -> List[float]:
        """Get historical data for a metric"""
        return self.history.get(key, [])
        
    def get_all_metrics(self) -> Dict[str, float]:
        """Get current values for all metrics"""
        return {key: self.history[key][-1] if self.history[key] else 0
                for key in self.metrics.keys()} 