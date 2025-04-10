from typing import Dict, List, Optional, Any, Set
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                           QComboBox, QLineEdit, QPushButton, QFrame,
                           QGroupBox, QCheckBox, QDateTimeEdit, QSpinBox)
from PyQt5.QtCore import Qt, pyqtSignal, QDateTime, QDate, QTime
from PyQt5.QtGui import QColor
from datetime import datetime, timedelta
from app.utils.performance_monitor import measure_performance

class TimeRangeSelector(QFrame):
    """Widget for selecting time ranges"""
    range_changed = pyqtSignal(dict)  # Emits when time range changes
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        
        # Start time
        self.start_time = QDateTimeEdit()
        self.start_time.setDateTime(QDateTime.currentDateTime().addSecs(-3600))
        self.start_time.setCalendarPopup(True)
        layout.addWidget(QLabel("From:"))
        layout.addWidget(self.start_time)
        
        # End time
        self.end_time = QDateTimeEdit()
        self.end_time.setDateTime(QDateTime.currentDateTime())
        self.end_time.setCalendarPopup(True)
        layout.addWidget(QLabel("To:"))
        layout.addWidget(self.end_time)
        
        # Quick select buttons
        quick_select = QHBoxLayout()
        for label, hours in [("1h", 1), ("6h", 6), ("24h", 24), ("7d", 168)]:
            btn = QPushButton(label)
            btn.clicked.connect(lambda h=hours: self.set_relative_range(h))
            quick_select.addWidget(btn)
        layout.addLayout(quick_select)
        
        # Connect signals
        self.start_time.dateTimeChanged.connect(self._on_range_changed)
        self.end_time.dateTimeChanged.connect(self._on_range_changed)
        
    def set_relative_range(self, hours: int) -> None:
        """Set time range relative to current time"""
        now = QDateTime.currentDateTime()
        self.end_time.setDateTime(now)
        self.start_time.setDateTime(now.addSecs(-hours * 3600))
        
    def _on_range_changed(self) -> None:
        """Handle time range changes"""
        self.range_changed.emit(self.get_range())
        
    def get_range(self) -> Dict[str, datetime]:
        """Get selected time range"""
        return {
            'start': self.start_time.dateTime().toPyDateTime(),
            'end': self.end_time.dateTime().toPyDateTime()
        }

class ProtocolFilter(QFrame):
    """Widget for filtering by protocols"""
    protocols_changed = pyqtSignal(set)  # Emits when selected protocols change
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        
        # Protocol checkboxes
        self.protocols = {
            'ARP': QCheckBox('ARP'),
            'TCP': QCheckBox('TCP'),
            'UDP': QCheckBox('UDP'),
            'ICMP': QCheckBox('ICMP')
        }
        
        for cb in self.protocols.values():
            cb.setChecked(True)
            cb.stateChanged.connect(self._on_protocols_changed)
            layout.addWidget(cb)
            
    def _on_protocols_changed(self) -> None:
        """Handle protocol selection changes"""
        selected = {proto for proto, cb in self.protocols.items() if cb.isChecked()}
        self.protocols_changed.emit(selected)
        
    def get_selected_protocols(self) -> Set[str]:
        """Get selected protocols"""
        return {proto for proto, cb in self.protocols.items() if cb.isChecked()}

class SeverityFilter(QFrame):
    """Widget for filtering by severity levels"""
    severities_changed = pyqtSignal(set)  # Emits when selected severities change
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        
        # Severity checkboxes with color coding
        self.severities = {
            'Critical': QCheckBox('Critical'),
            'High': QCheckBox('High'),
            'Medium': QCheckBox('Medium'),
            'Low': QCheckBox('Low'),
            'Info': QCheckBox('Info')
        }
        
        # Set colors and initial state
        colors = {
            'Critical': '#F44336',
            'High': '#FF5722',
            'Medium': '#FFC107',
            'Low': '#4CAF50',
            'Info': '#2196F3'
        }
        
        for level, cb in self.severities.items():
            cb.setChecked(True)
            cb.setStyleSheet(f"color: {colors[level]};")
            cb.stateChanged.connect(self._on_severities_changed)
            layout.addWidget(cb)
            
    def _on_severities_changed(self) -> None:
        """Handle severity selection changes"""
        selected = {level for level, cb in self.severities.items() if cb.isChecked()}
        self.severities_changed.emit(selected)
        
    def get_selected_severities(self) -> Set[str]:
        """Get selected severity levels"""
        return {level for level, cb in self.severities.items() if cb.isChecked()}

class IPRangeFilter(QFrame):
    """Widget for filtering by IP ranges"""
    range_changed = pyqtSignal(dict)  # Emits when IP range changes
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        
        # Start IP
        start_layout = QHBoxLayout()
        self.start_ip = QLineEdit()
        self.start_ip.setPlaceholderText("Start IP")
        start_layout.addWidget(QLabel("From:"))
        start_layout.addWidget(self.start_ip)
        layout.addLayout(start_layout)
        
        # End IP
        end_layout = QHBoxLayout()
        self.end_ip = QLineEdit()
        self.end_ip.setPlaceholderText("End IP")
        end_layout.addWidget(QLabel("To:"))
        end_layout.addWidget(self.end_ip)
        layout.addLayout(end_layout)
        
        # Connect signals
        self.start_ip.textChanged.connect(self._on_range_changed)
        self.end_ip.textChanged.connect(self._on_range_changed)
        
    def _on_range_changed(self) -> None:
        """Handle IP range changes"""
        self.range_changed.emit(self.get_range())
        
    def get_range(self) -> Dict[str, str]:
        """Get selected IP range"""
        return {
            'start': self.start_ip.text(),
            'end': self.end_ip.text()
        }

class AdvancedFilter(QWidget):
    """Advanced filtering panel"""
    filters_changed = pyqtSignal(dict)  # Emits when any filter changes
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        
        # Create filter components
        self.time_range = TimeRangeSelector()
        self.protocol_filter = ProtocolFilter()
        self.severity_filter = SeverityFilter()
        self.ip_range = IPRangeFilter()
        
        # Group filters
        time_group = QGroupBox("Time Range")
        time_group.setLayout(QVBoxLayout())
        time_group.layout().addWidget(self.time_range)
        
        protocol_group = QGroupBox("Protocols")
        protocol_group.setLayout(QVBoxLayout())
        protocol_group.layout().addWidget(self.protocol_filter)
        
        severity_group = QGroupBox("Severity")
        severity_group.setLayout(QVBoxLayout())
        severity_group.layout().addWidget(self.severity_filter)
        
        ip_group = QGroupBox("IP Range")
        ip_group.setLayout(QVBoxLayout())
        ip_group.layout().addWidget(self.ip_range)
        
        # Add groups to layout
        self.layout.addWidget(time_group)
        self.layout.addWidget(protocol_group)
        self.layout.addWidget(severity_group)
        self.layout.addWidget(ip_group)
        
        # Add apply button
        self.apply_button = QPushButton("Apply Filters")
        self.apply_button.clicked.connect(self.apply_filters)
        self.layout.addWidget(self.apply_button)
        
        # Connect signals
        self.time_range.range_changed.connect(self._on_filters_changed)
        self.protocol_filter.protocols_changed.connect(self._on_filters_changed)
        self.severity_filter.severities_changed.connect(self._on_filters_changed)
        self.ip_range.range_changed.connect(self._on_filters_changed)
        
    @measure_performance('get_filters')
    def get_filters(self) -> Dict[str, Any]:
        """Get current filter settings"""
        return {
            'time_range': self.time_range.get_range(),
            'protocols': self.protocol_filter.get_selected_protocols(),
            'severities': self.severity_filter.get_selected_severities(),
            'ip_range': self.ip_range.get_range()
        }
        
    def _on_filters_changed(self) -> None:
        """Handle any filter change"""
        self.filters_changed.emit(self.get_filters())
        
    def apply_filters(self) -> None:
        """Apply current filters"""
        self.filters_changed.emit(self.get_filters())
        
    def save_preset(self, name: str) -> None:
        """Save current filter settings as a preset"""
        # Implementation would save to configuration
        pass
        
    def load_preset(self, name: str) -> None:
        """Load filter settings from a preset"""
        # Implementation would load from configuration
        pass 