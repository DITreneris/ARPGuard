from typing import Dict, List, Optional, Any
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                           QTableWidget, QTableWidgetItem, QPushButton,
                           QComboBox, QLineEdit, QFrame, QHeaderView,
                           QProgressBar, QToolButton, QMenu)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QColor, QIcon
from datetime import datetime
from app.utils.performance_monitor import measure_performance

class ThreatIntelligencePanel(QWidget):
    """Threat intelligence panel for displaying and managing threat data"""
    threat_updated = pyqtSignal(dict)  # Emits when threat data is updated
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        
        # Header with controls
        header_layout = QHBoxLayout()
        
        self.source_combo = QComboBox()
        self.source_combo.addItems(['Local Database', 'External Feed', 'Custom Source'])
        header_layout.addWidget(QLabel("Source:"))
        header_layout.addWidget(self.source_combo)
        
        self.refresh_button = QPushButton("Refresh")
        self.export_button = QPushButton("Export")
        self.settings_button = QToolButton()
        self.settings_button.setIcon(QIcon("icons/settings.png"))
        
        header_layout.addWidget(self.refresh_button)
        header_layout.addWidget(self.export_button)
        header_layout.addWidget(self.settings_button)
        header_layout.addStretch()
        
        # Status bar
        status_layout = QHBoxLayout()
        
        self.last_update = QLabel("Last Update: Never")
        self.update_progress = QProgressBar()
        self.update_progress.setMaximumWidth(200)
        self.update_progress.setVisible(False)
        
        status_layout.addWidget(self.last_update)
        status_layout.addWidget(self.update_progress)
        status_layout.addStretch()
        
        # Threat table
        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(6)
        self.threat_table.setHorizontalHeaderLabels([
            "IP Address", "Threat Type", "Severity", "First Seen",
            "Last Seen", "Confidence"
        ])
        
        # Configure table
        header = self.threat_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        
        # Add widgets to main layout
        self.layout.addLayout(header_layout)
        self.layout.addWidget(self.threat_table)
        self.layout.addLayout(status_layout)
        
        # Connect signals
        self.refresh_button.clicked.connect(self.refresh_threats)
        self.export_button.clicked.connect(self.export_threats)
        self.settings_button.clicked.connect(self.show_settings_menu)
        self.source_combo.currentTextChanged.connect(self.source_changed)
        
        # Setup auto-refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_threats)
        self.refresh_timer.start(300000)  # Refresh every 5 minutes
        
    @measure_performance('update_threats')
    def update_threats(self, threats: List[Dict[str, Any]]) -> None:
        """Update threat table with new data"""
        self.threat_table.setRowCount(len(threats))
        
        for row, threat in enumerate(threats):
            # IP Address
            ip_item = QTableWidgetItem(threat.get('ip_address', ''))
            self.threat_table.setItem(row, 0, ip_item)
            
            # Threat Type
            type_item = QTableWidgetItem(threat.get('threat_type', ''))
            self.threat_table.setItem(row, 1, type_item)
            
            # Severity
            severity = threat.get('severity', 'Unknown')
            severity_item = QTableWidgetItem(severity)
            severity_item.setBackground(self._get_severity_color(severity))
            self.threat_table.setItem(row, 2, severity_item)
            
            # First Seen
            first_seen = threat.get('first_seen', '')
            if isinstance(first_seen, datetime):
                first_seen = first_seen.strftime('%Y-%m-%d %H:%M:%S')
            self.threat_table.setItem(row, 3, QTableWidgetItem(first_seen))
            
            # Last Seen
            last_seen = threat.get('last_seen', '')
            if isinstance(last_seen, datetime):
                last_seen = last_seen.strftime('%Y-%m-%d %H:%M:%S')
            self.threat_table.setItem(row, 4, QTableWidgetItem(last_seen))
            
            # Confidence
            confidence = threat.get('confidence', 0)
            confidence_item = QTableWidgetItem(f"{confidence}%")
            confidence_item.setTextAlignment(Qt.AlignCenter)
            self.threat_table.setItem(row, 5, confidence_item)
            
        self.last_update.setText(f"Last Update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.threat_updated.emit({'count': len(threats)})
        
    def refresh_threats(self) -> None:
        """Refresh threat data from source"""
        self.update_progress.setVisible(True)
        self.update_progress.setValue(0)
        
        # Simulate progress
        for i in range(101):
            self.update_progress.setValue(i)
            QApplication.processEvents()
            
        self.update_progress.setVisible(False)
        
    def export_threats(self) -> None:
        """Export threat data"""
        # Implementation would export threat data to file
        pass
        
    def show_settings_menu(self) -> None:
        """Show settings menu"""
        menu = QMenu(self)
        menu.addAction("Update Frequency")
        menu.addAction("Data Sources")
        menu.addAction("Export Format")
        menu.addAction("Advanced Settings")
        menu.exec_(self.settings_button.mapToGlobal(self.settings_button.rect().bottomLeft()))
        
    def source_changed(self, source: str) -> None:
        """Handle source change"""
        # Implementation would update data source
        pass
        
    def _get_severity_color(self, severity: str) -> QColor:
        """Get color for severity level"""
        colors = {
            'Critical': QColor('#F44336'),
            'High': QColor('#FF5722'),
            'Medium': QColor('#FFC107'),
            'Low': QColor('#4CAF50'),
            'Unknown': QColor('#9E9E9E')
        }
        return colors.get(severity, QColor('#9E9E9E'))
        
    def start_auto_refresh(self, interval_ms: int = 300000) -> None:
        """Start automatic refresh"""
        self.refresh_timer.start(interval_ms)
        
    def stop_auto_refresh(self) -> None:
        """Stop automatic refresh"""
        self.refresh_timer.stop() 