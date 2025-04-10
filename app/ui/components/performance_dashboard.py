from typing import Dict, List, Optional, Any
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                           QFrame, QProgressBar, QComboBox, QPushButton,
                           QGridLayout, QGroupBox, QCheckBox)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QColor, QPainter, QPen
from datetime import datetime, timedelta
import psutil
from app.utils.performance_monitor import measure_performance

class MetricGraph(QFrame):
    """Custom widget for displaying metric graphs"""
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setMinimumHeight(100)
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Sunken)
        self.data_points = []
        self.max_points = 60  # 1 minute of data at 1-second intervals
        
    def add_data_point(self, value: float) -> None:
        """Add a new data point to the graph"""
        self.data_points.append(value)
        if len(self.data_points) > self.max_points:
            self.data_points.pop(0)
        self.update()
        
    def paintEvent(self, event) -> None:
        """Custom paint event for drawing the graph"""
        super().paintEvent(event)
        if not self.data_points:
            return
            
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw grid
        pen = QPen(QColor('#E0E0E0'))
        painter.setPen(pen)
        
        # Draw horizontal grid lines
        for i in range(0, 101, 20):
            y = self.height() - (i / 100 * self.height())
            painter.drawLine(0, y, self.width(), y)
            
        # Draw vertical grid lines
        for i in range(0, self.width(), 20):
            painter.drawLine(i, 0, i, self.height())
            
        # Draw data line
        pen = QPen(QColor('#2196F3'))
        pen.setWidth(2)
        painter.setPen(pen)
        
        points = []
        for i, value in enumerate(self.data_points):
            x = (i / (self.max_points - 1)) * self.width()
            y = self.height() - (value / 100 * self.height())
            points.append((x, y))
            
        for i in range(len(points) - 1):
            painter.drawLine(points[i][0], points[i][1],
                           points[i + 1][0], points[i + 1][1])

class PerformanceDashboard(QWidget):
    """Performance monitoring dashboard"""
    metrics_updated = pyqtSignal(dict)  # Emits when metrics are updated
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        
        # Header with controls
        header_layout = QHBoxLayout()
        
        self.refresh_rate = QComboBox()
        self.refresh_rate.addItems(['1s', '5s', '10s', '30s', '1m'])
        self.refresh_rate.setCurrentText('1s')
        header_layout.addWidget(QLabel("Refresh Rate:"))
        header_layout.addWidget(self.refresh_rate)
        
        self.pause_button = QPushButton("Pause")
        header_layout.addWidget(self.pause_button)
        header_layout.addStretch()
        
        # Metrics grid
        metrics_layout = QGridLayout()
        
        # CPU Usage
        cpu_group = QGroupBox("CPU Usage")
        cpu_layout = QVBoxLayout(cpu_group)
        
        self.cpu_percent = QLabel("0%")
        self.cpu_percent.setAlignment(Qt.AlignCenter)
        self.cpu_graph = MetricGraph()
        
        cpu_layout.addWidget(self.cpu_percent)
        cpu_layout.addWidget(self.cpu_graph)
        
        # Memory Usage
        memory_group = QGroupBox("Memory Usage")
        memory_layout = QVBoxLayout(memory_group)
        
        self.memory_percent = QLabel("0%")
        self.memory_percent.setAlignment(Qt.AlignCenter)
        self.memory_graph = MetricGraph()
        
        memory_layout.addWidget(self.memory_percent)
        memory_layout.addWidget(self.memory_graph)
        
        # Network Usage
        network_group = QGroupBox("Network Usage")
        network_layout = QVBoxLayout(network_group)
        
        self.network_speed = QLabel("0 KB/s")
        self.network_speed.setAlignment(Qt.AlignCenter)
        self.network_graph = MetricGraph()
        
        network_layout.addWidget(self.network_speed)
        network_layout.addWidget(self.network_graph)
        
        # Disk Usage
        disk_group = QGroupBox("Disk Usage")
        disk_layout = QVBoxLayout(disk_group)
        
        self.disk_percent = QLabel("0%")
        self.disk_percent.setAlignment(Qt.AlignCenter)
        self.disk_graph = MetricGraph()
        
        disk_layout.addWidget(self.disk_percent)
        disk_layout.addWidget(self.disk_graph)
        
        # Add metric groups to grid
        metrics_layout.addWidget(cpu_group, 0, 0)
        metrics_layout.addWidget(memory_group, 0, 1)
        metrics_layout.addWidget(network_group, 1, 0)
        metrics_layout.addWidget(disk_group, 1, 1)
        
        # Add layouts to main layout
        self.layout.addLayout(header_layout)
        self.layout.addLayout(metrics_layout)
        
        # Connect signals
        self.refresh_rate.currentTextChanged.connect(self.update_refresh_rate)
        self.pause_button.clicked.connect(self.toggle_pause)
        
        # Setup update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_metrics)
        self.update_timer.start(1000)  # Start with 1-second refresh
        
        # Initialize network metrics
        self.last_net_io = psutil.net_io_counters()
        self.last_net_time = datetime.now()
        
    @measure_performance('update_metrics')
    def update_metrics(self) -> None:
        """Update all performance metrics"""
        # CPU Usage
        cpu_percent = psutil.cpu_percent()
        self.cpu_percent.setText(f"{cpu_percent}%")
        self.cpu_graph.add_data_point(cpu_percent)
        
        # Memory Usage
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        self.memory_percent.setText(f"{memory_percent}%")
        self.memory_graph.add_data_point(memory_percent)
        
        # Network Usage
        current_net_io = psutil.net_io_counters()
        current_time = datetime.now()
        time_diff = (current_time - self.last_net_time).total_seconds()
        
        bytes_sent = current_net_io.bytes_sent - self.last_net_io.bytes_sent
        bytes_recv = current_net_io.bytes_recv - self.last_net_io.bytes_recv
        total_bytes = bytes_sent + bytes_recv
        
        speed_kb = total_bytes / time_diff / 1024
        self.network_speed.setText(f"{speed_kb:.1f} KB/s")
        self.network_graph.add_data_point(min(speed_kb, 100))  # Cap at 100 KB/s for graph
        
        self.last_net_io = current_net_io
        self.last_net_time = current_time
        
        # Disk Usage
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent
        self.disk_percent.setText(f"{disk_percent}%")
        self.disk_graph.add_data_point(disk_percent)
        
        # Emit update signal
        self.metrics_updated.emit({
            'cpu': cpu_percent,
            'memory': memory_percent,
            'network': speed_kb,
            'disk': disk_percent
        })
        
    def update_refresh_rate(self, rate: str) -> None:
        """Update the refresh rate"""
        intervals = {
            '1s': 1000,
            '5s': 5000,
            '10s': 10000,
            '30s': 30000,
            '1m': 60000
        }
        self.update_timer.setInterval(intervals.get(rate, 1000))
        
    def toggle_pause(self) -> None:
        """Toggle pause state"""
        if self.update_timer.isActive():
            self.update_timer.stop()
            self.pause_button.setText("Resume")
        else:
            self.update_timer.start()
            self.pause_button.setText("Pause")
            
    def start_monitoring(self) -> None:
        """Start performance monitoring"""
        self.update_timer.start()
        
    def stop_monitoring(self) -> None:
        """Stop performance monitoring"""
        self.update_timer.stop() 