from typing import Dict, List, Optional, Any
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                           QPushButton, QFrame, QScrollArea, QGroupBox,
                           QCheckBox, QLineEdit, QComboBox, QSpinBox)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QColor, QFont
from datetime import datetime
from app.utils.performance_monitor import measure_performance

class AlertItem(QFrame):
    """Widget for displaying a single alert"""
    
    def __init__(self, alert_data: Dict[str, Any], parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setLineWidth(1)
        
        layout = QVBoxLayout(self)
        
        # Header with severity and timestamp
        header = QHBoxLayout()
        self.severity_label = QLabel(alert_data.get('severity', 'Unknown'))
        self.severity_label.setFont(QFont('Arial', 10, QFont.Bold))
        self._set_severity_color(alert_data.get('severity', 'Unknown'))
        
        self.timestamp = QLabel(alert_data.get('timestamp', ''))
        self.timestamp.setAlignment(Qt.AlignRight)
        
        header.addWidget(self.severity_label)
        header.addWidget(self.timestamp)
        layout.addLayout(header)
        
        # Alert details
        self.description = QLabel(alert_data.get('description', ''))
        self.description.setWordWrap(True)
        layout.addWidget(self.description)
        
        # Source information
        source_layout = QHBoxLayout()
        self.source_ip = QLabel(f"Source: {alert_data.get('source_ip', 'Unknown')}")
        self.target_ip = QLabel(f"Target: {alert_data.get('target_ip', 'Unknown')}")
        source_layout.addWidget(self.source_ip)
        source_layout.addWidget(self.target_ip)
        layout.addLayout(source_layout)
        
        # Action buttons
        buttons = QHBoxLayout()
        self.acknowledge_btn = QPushButton("Acknowledge")
        self.ignore_btn = QPushButton("Ignore")
        self.details_btn = QPushButton("Details")
        
        buttons.addWidget(self.acknowledge_btn)
        buttons.addWidget(self.ignore_btn)
        buttons.addWidget(self.details_btn)
        layout.addLayout(buttons)
        
    def _set_severity_color(self, severity: str) -> None:
        """Set color based on severity level"""
        colors = {
            'Critical': '#F44336',
            'High': '#FF5722',
            'Medium': '#FFC107',
            'Low': '#4CAF50',
            'Info': '#2196F3'
        }
        color = colors.get(severity, '#9E9E9E')
        self.severity_label.setStyleSheet(f"color: {color};")

class AlertList(QScrollArea):
    """Widget for displaying a list of alerts"""
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameStyle(QFrame.NoFrame)
        
        # Container widget for alerts
        self.container = QWidget()
        self.layout = QVBoxLayout(self.container)
        self.layout.setAlignment(Qt.AlignTop)
        self.setWidget(self.container)
        
    def add_alert(self, alert_data: Dict[str, Any]) -> None:
        """Add a new alert to the list"""
        alert_item = AlertItem(alert_data)
        self.layout.addWidget(alert_item)
        
    def clear_alerts(self) -> None:
        """Clear all alerts from the list"""
        while self.layout.count():
            item = self.layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

class NotificationSettings(QGroupBox):
    """Widget for configuring notification settings"""
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__("Notification Settings", parent)
        layout = QVBoxLayout(self)
        
        # Notification methods
        methods_group = QGroupBox("Methods")
        methods_layout = QVBoxLayout(methods_group)
        self.methods = {
            'email': QCheckBox("Email"),
            'desktop': QCheckBox("Desktop"),
            'sound': QCheckBox("Sound"),
            'sms': QCheckBox("SMS")
        }
        for method in self.methods.values():
            methods_layout.addWidget(method)
        layout.addWidget(methods_group)
        
        # Email settings
        email_group = QGroupBox("Email Settings")
        email_layout = QVBoxLayout(email_group)
        self.email_address = QLineEdit()
        self.email_address.setPlaceholderText("Email Address")
        self.smtp_server = QLineEdit()
        self.smtp_server.setPlaceholderText("SMTP Server")
        self.smtp_port = QSpinBox()
        self.smtp_port.setRange(1, 65535)
        self.smtp_port.setValue(587)
        
        email_layout.addWidget(QLabel("Email Address:"))
        email_layout.addWidget(self.email_address)
        email_layout.addWidget(QLabel("SMTP Server:"))
        email_layout.addWidget(self.smtp_server)
        email_layout.addWidget(QLabel("SMTP Port:"))
        email_layout.addWidget(self.smtp_port)
        layout.addWidget(email_group)
        
        # Severity thresholds
        severity_group = QGroupBox("Severity Thresholds")
        severity_layout = QVBoxLayout(severity_group)
        self.thresholds = {
            'Critical': QCheckBox("Always notify for Critical"),
            'High': QCheckBox("Notify for High"),
            'Medium': QCheckBox("Notify for Medium"),
            'Low': QCheckBox("Notify for Low"),
            'Info': QCheckBox("Notify for Info")
        }
        for threshold in self.thresholds.values():
            severity_layout.addWidget(threshold)
        layout.addWidget(severity_group)
        
    def get_settings(self) -> Dict[str, Any]:
        """Get current notification settings"""
        return {
            'methods': {name: cb.isChecked() for name, cb in self.methods.items()},
            'email': {
                'address': self.email_address.text(),
                'smtp_server': self.smtp_server.text(),
                'smtp_port': self.smtp_port.value()
            },
            'thresholds': {name: cb.isChecked() for name, cb in self.thresholds.items()}
        }

class AlertManager(QWidget):
    """Main alert management panel"""
    
    alert_acknowledged = pyqtSignal(dict)  # Emits when alert is acknowledged
    alert_ignored = pyqtSignal(dict)  # Emits when alert is ignored
    settings_changed = pyqtSignal(dict)  # Emits when notification settings change
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        
        # Create components
        self.alert_list = AlertList()
        self.notification_settings = NotificationSettings()
        
        # Add components to layout
        layout.addWidget(self.alert_list)
        layout.addWidget(self.notification_settings)
        
        # Setup auto-update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_alerts)
        self.update_timer.start(5000)  # Update every 5 seconds
        
    def add_alert(self, alert_data: Dict[str, Any]) -> None:
        """Add a new alert"""
        self.alert_list.add_alert(alert_data)
        
    def clear_alerts(self) -> None:
        """Clear all alerts"""
        self.alert_list.clear_alerts()
        
    @measure_performance('update_alerts')
    def update_alerts(self) -> None:
        """Update alerts from data source"""
        # Implementation would fetch new alerts from data source
        pass
        
    def get_notification_settings(self) -> Dict[str, Any]:
        """Get current notification settings"""
        return self.notification_settings.get_settings()
        
    def configure_notifications(self, settings: Dict[str, Any]) -> None:
        """Configure notification settings"""
        # Implementation would apply notification settings
        self.settings_changed.emit(settings) 