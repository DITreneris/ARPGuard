from typing import Dict, List, Optional, Any
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                           QTextEdit, QPushButton, QComboBox, QLineEdit,
                           QCheckBox, QFrame, QScrollArea, QSplitter)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QTextCursor, QColor, QSyntaxHighlighter, QTextCharFormat
from datetime import datetime
import re
from app.utils.performance_monitor import measure_performance

class LogHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for log entries"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        
        # Error highlighting
        error_format = QTextCharFormat()
        error_format.setForeground(QColor('#F44336'))
        self.highlighting_rules.append((re.compile(r'ERROR|CRITICAL'), error_format))
        
        # Warning highlighting
        warning_format = QTextCharFormat()
        warning_format.setForeground(QColor('#FFC107'))
        self.highlighting_rules.append((re.compile(r'WARNING'), warning_format))
        
        # Info highlighting
        info_format = QTextCharFormat()
        info_format.setForeground(QColor('#2196F3'))
        self.highlighting_rules.append((re.compile(r'INFO'), info_format))
        
        # Debug highlighting
        debug_format = QTextCharFormat()
        debug_format.setForeground(QColor('#9E9E9E'))
        self.highlighting_rules.append((re.compile(r'DEBUG'), debug_format))
        
        # IP address highlighting
        ip_format = QTextCharFormat()
        ip_format.setForeground(QColor('#4CAF50'))
        self.highlighting_rules.append((re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), ip_format))
        
    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            for match in pattern.finditer(text):
                self.setFormat(match.start(), match.end() - match.start(), format)

class LogViewer(QWidget):
    """Advanced log viewer component"""
    log_exported = pyqtSignal(str)  # Emits when logs are exported
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        
        # Create splitter for log view and filters
        self.splitter = QSplitter(Qt.Horizontal)
        
        # Log display area
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setLineWrapMode(QTextEdit.NoWrap)
        self.highlighter = LogHighlighter(self.log_display.document())
        
        # Filter panel
        self.filter_panel = QFrame()
        filter_layout = QVBoxLayout(self.filter_panel)
        
        # Level filter
        level_group = QFrame()
        level_layout = QVBoxLayout(level_group)
        level_layout.addWidget(QLabel("Log Levels:"))
        
        self.level_filters = {
            'ERROR': QCheckBox('Error'),
            'WARNING': QCheckBox('Warning'),
            'INFO': QCheckBox('Info'),
            'DEBUG': QCheckBox('Debug')
        }
        for cb in self.level_filters.values():
            cb.setChecked(True)
            level_layout.addWidget(cb)
            
        # Time range filter
        time_group = QFrame()
        time_layout = QVBoxLayout(time_group)
        time_layout.addWidget(QLabel("Time Range:"))
        
        self.time_start = QLineEdit()
        self.time_end = QLineEdit()
        time_layout.addWidget(QLabel("From:"))
        time_layout.addWidget(self.time_start)
        time_layout.addWidget(QLabel("To:"))
        time_layout.addWidget(self.time_end)
        
        # Search filter
        search_group = QFrame()
        search_layout = QVBoxLayout(search_group)
        search_layout.addWidget(QLabel("Search:"))
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter search term...")
        search_layout.addWidget(self.search_input)
        
        # Add filter groups to panel
        filter_layout.addWidget(level_group)
        filter_layout.addWidget(time_group)
        filter_layout.addWidget(search_group)
        filter_layout.addStretch()
        
        # Add widgets to splitter
        self.splitter.addWidget(self.log_display)
        self.splitter.addWidget(self.filter_panel)
        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 1)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.clear_button = QPushButton("Clear")
        self.export_button = QPushButton("Export")
        self.refresh_button = QPushButton("Refresh")
        
        button_layout.addWidget(self.clear_button)
        button_layout.addWidget(self.export_button)
        button_layout.addWidget(self.refresh_button)
        
        # Add widgets to main layout
        self.layout.addWidget(self.splitter)
        self.layout.addLayout(button_layout)
        
        # Connect signals
        self.clear_button.clicked.connect(self.clear_logs)
        self.export_button.clicked.connect(self.export_logs)
        self.refresh_button.clicked.connect(self.refresh_logs)
        self.search_input.textChanged.connect(self.filter_logs)
        
        # Setup auto-refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_logs)
        self.refresh_timer.start(5000)  # Refresh every 5 seconds
        
    @measure_performance('add_log')
    def add_log(self, level: str, message: str, timestamp: Optional[datetime] = None) -> None:
        """Add new log entry"""
        if timestamp is None:
            timestamp = datetime.now()
            
        if self.level_filters[level].isChecked():
            log_entry = f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {level}: {message}\n"
            self.log_display.insertPlainText(log_entry)
            self.log_display.moveCursor(QTextCursor.End)
            
    def clear_logs(self) -> None:
        """Clear all logs"""
        self.log_display.clear()
        
    def export_logs(self) -> None:
        """Export logs to file"""
        logs = self.log_display.toPlainText()
        self.log_exported.emit(logs)
        
    def refresh_logs(self) -> None:
        """Refresh log display"""
        # Implementation would fetch new logs from log source
        pass
        
    def filter_logs(self) -> None:
        """Apply filters to log display"""
        search_term = self.search_input.text().lower()
        cursor = self.log_display.textCursor()
        cursor.movePosition(QTextCursor.Start)
        
        while not cursor.atEnd():
            cursor.movePosition(QTextCursor.EndOfLine, QTextCursor.KeepAnchor)
            line = cursor.selectedText()
            
            if search_term in line.lower():
                cursor.clearSelection()
                cursor.movePosition(QTextCursor.NextCharacter)
            else:
                cursor.removeSelectedText()
                cursor.insertText("")
                
    def start_auto_refresh(self, interval_ms: int = 5000) -> None:
        """Start automatic refresh"""
        self.refresh_timer.start(interval_ms)
        
    def stop_auto_refresh(self) -> None:
        """Stop automatic refresh"""
        self.refresh_timer.stop() 