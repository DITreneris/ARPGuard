"""Reporting interface improvements for ARPGuard.

This module provides utilities for enhancing the reporting interface with
improved data visualization and export options for a more intuitive user experience.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
    QPushButton, QFileDialog, QTableWidget, QTableWidgetItem,
    QCheckBox, QDateEdit, QGroupBox, QFormLayout, QSpinBox,
    QTabWidget, QSplitter
)
from PyQt5.QtCore import Qt, QDate, QDateTime
from PyQt5.QtGui import QIcon, QPixmap

import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional, Callable

import matplotlib
matplotlib.use('Qt5Agg')
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

from app.utils.logger import get_logger

# Module logger
logger = get_logger('utils.reporting_improvements')

class SimplifiedReportChart(FigureCanvasQTAgg):
    """A simplified matplotlib chart for reports."""
    
    def __init__(self, width=5, height=4, dpi=100):
        """Initialize the chart.
        
        Args:
            width: Width in inches
            height: Height in inches
            dpi: Dots per inch
        """
        self.fig = Figure(figsize=(width, height), dpi=dpi, tight_layout=True)
        self.axes = self.fig.add_subplot(111)
        
        # Set style
        plt.style.use('seaborn-v0_8-whitegrid')
        
        super().__init__(self.fig)

class ReportFilterPanel(QWidget):
    """A panel for filtering report data."""
    
    def __init__(self, parent=None):
        """Initialize the filter panel."""
        super().__init__(parent)
        
        # Setup UI
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Create filter form
        filter_group = QGroupBox("Filter Options")
        form_layout = QFormLayout(filter_group)
        
        # Date range
        self.start_date = QDateEdit()
        self.start_date.setDate(QDate.currentDate().addDays(-7))
        self.start_date.setCalendarPopup(True)
        
        self.end_date = QDateEdit()
        self.end_date.setDate(QDate.currentDate())
        self.end_date.setCalendarPopup(True)
        
        # Report type
        self.report_type = QComboBox()
        self.report_type.addItems(["All Reports", "Traffic Analysis", "Security Incidents", 
                                   "Network Scans", "Vulnerability Reports"])
        
        # Severity filter
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "Critical Only", "Critical & High", 
                                       "Non-critical Only"])
        
        # Include charts checkbox
        self.include_charts = QCheckBox("Include Charts")
        self.include_charts.setChecked(True)
        
        # Include raw data checkbox
        self.include_raw_data = QCheckBox("Include Raw Data")
        self.include_raw_data.setChecked(True)
        
        # Add to form layout
        form_layout.addRow("Start Date:", self.start_date)
        form_layout.addRow("End Date:", self.end_date)
        form_layout.addRow("Report Type:", self.report_type)
        form_layout.addRow("Severity:", self.severity_filter)
        form_layout.addRow(self.include_charts)
        form_layout.addRow(self.include_raw_data)
        
        # Add buttons
        buttons_layout = QHBoxLayout()
        
        self.apply_filter_button = QPushButton("Apply Filters")
        self.reset_button = QPushButton("Reset")
        
        buttons_layout.addWidget(self.apply_filter_button)
        buttons_layout.addWidget(self.reset_button)
        
        # Add to main layout
        layout.addWidget(filter_group)
        layout.addLayout(buttons_layout)
        layout.addStretch()
    
    def get_filter_settings(self) -> Dict[str, Any]:
        """Get the current filter settings.
        
        Returns:
            Dict[str, Any]: Dictionary of filter settings
        """
        return {
            'start_date': self.start_date.date().toPyDate(),
            'end_date': self.end_date.date().toPyDate(),
            'report_type': self.report_type.currentText(),
            'severity': self.severity_filter.currentText(),
            'include_charts': self.include_charts.isChecked(),
            'include_raw_data': self.include_raw_data.isChecked()
        }

class ReportExportPanel(QWidget):
    """A panel for exporting reports."""
    
    def __init__(self, parent=None):
        """Initialize the export panel."""
        super().__init__(parent)
        
        # Setup UI
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Create export options group
        export_group = QGroupBox("Export Options")
        form_layout = QFormLayout(export_group)
        
        # File format
        self.file_format = QComboBox()
        self.file_format.addItems(["PDF", "HTML", "Markdown", "CSV", "JSON"])
        
        # Include images
        self.include_images = QCheckBox("Include Images")
        self.include_images.setChecked(True)
        
        # Image quality
        self.image_quality = QSpinBox()
        self.image_quality.setRange(1, 100)
        self.image_quality.setValue(80)
        self.image_quality.setSuffix("%")
        
        # Add to form layout
        form_layout.addRow("File Format:", self.file_format)
        form_layout.addRow(self.include_images)
        form_layout.addRow("Image Quality:", self.image_quality)
        
        # Export button
        self.export_button = QPushButton("Export Report")
        self.export_button.setStyleSheet("font-weight: bold;")
        
        # Add to main layout
        layout.addWidget(export_group)
        layout.addWidget(self.export_button)
        layout.addStretch()
    
    def get_export_settings(self) -> Dict[str, Any]:
        """Get the current export settings.
        
        Returns:
            Dict[str, Any]: Dictionary of export settings
        """
        return {
            'file_format': self.file_format.currentText(),
            'include_images': self.include_images.isChecked(),
            'image_quality': self.image_quality.value()
        }

class ReportPreviewPanel(QWidget):
    """A panel for previewing reports."""
    
    def __init__(self, parent=None):
        """Initialize the preview panel."""
        super().__init__(parent)
        
        # Setup UI
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Preview tabs
        self.preview_tabs = QTabWidget()
        
        # Summary tab
        summary_tab = QWidget()
        summary_layout = QVBoxLayout(summary_tab)
        
        self.summary_label = QLabel("Report Summary")
        self.summary_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        
        # Add a chart
        self.summary_chart = SimplifiedReportChart(5, 4)
        
        summary_layout.addWidget(self.summary_label)
        summary_layout.addWidget(self.summary_chart)
        
        # Details tab
        details_tab = QWidget()
        details_layout = QVBoxLayout(details_tab)
        
        self.details_table = QTableWidget(0, 3)
        self.details_table.setHorizontalHeaderLabels(["Time", "Event", "Details"])
        self.details_table.horizontalHeader().setStretchLastSection(True)
        
        details_layout.addWidget(self.details_table)
        
        # Charts tab
        charts_tab = QWidget()
        charts_layout = QVBoxLayout(charts_tab)
        
        self.charts_tabs = QTabWidget()
        
        charts_layout.addWidget(self.charts_tabs)
        
        # Add tabs to preview
        self.preview_tabs.addTab(summary_tab, "Summary")
        self.preview_tabs.addTab(details_tab, "Details")
        self.preview_tabs.addTab(charts_tab, "Charts")
        
        # Add to main layout
        layout.addWidget(self.preview_tabs)
    
    def update_preview(self, report_data: Dict[str, Any]):
        """Update the report preview with new data.
        
        Args:
            report_data: Dictionary of report data
        """
        # Update summary chart
        self.update_summary_chart(report_data.get('summary_data', {}))
        
        # Update details table
        self.update_details_table(report_data.get('events', []))
        
        # Update charts
        self.update_charts(report_data.get('charts', {}))
    
    def update_summary_chart(self, summary_data: Dict[str, int]):
        """Update the summary chart with new data.
        
        Args:
            summary_data: Dictionary mapping categories to values
        """
        # Clear previous plot
        self.summary_chart.axes.clear()
        
        # Create bar chart
        if summary_data:
            categories = list(summary_data.keys())
            values = list(summary_data.values())
            
            bars = self.summary_chart.axes.bar(categories, values)
            
            # Add labels
            for bar in bars:
                height = bar.get_height()
                self.summary_chart.axes.text(
                    bar.get_x() + bar.get_width()/2.,
                    height + 0.3,
                    str(int(height)),
                    ha='center', va='bottom'
                )
            
            self.summary_chart.axes.set_title('Event Summary')
            self.summary_chart.axes.set_ylabel('Count')
            
            # Refresh the canvas
            self.summary_chart.draw()
    
    def update_details_table(self, events: List[Dict[str, Any]]):
        """Update the details table with new data.
        
        Args:
            events: List of event dictionaries
        """
        # Clear previous data
        self.details_table.setRowCount(0)
        
        # Add new data
        for row, event in enumerate(events):
            self.details_table.insertRow(row)
            
            # Add time
            time_item = QTableWidgetItem(event.get('time', ''))
            self.details_table.setItem(row, 0, time_item)
            
            # Add event type
            event_item = QTableWidgetItem(event.get('type', ''))
            self.details_table.setItem(row, 1, event_item)
            
            # Add details
            details_item = QTableWidgetItem(event.get('details', ''))
            self.details_table.setItem(row, 2, details_item)
    
    def update_charts(self, charts_data: Dict[str, Dict[str, Any]]):
        """Update the charts tab with new data.
        
        Args:
            charts_data: Dictionary mapping chart names to data
        """
        # Clear previous charts
        for i in range(self.charts_tabs.count()):
            self.charts_tabs.removeTab(0)
        
        # Add new charts
        for chart_name, chart_data in charts_data.items():
            chart_widget = QWidget()
            chart_layout = QVBoxLayout(chart_widget)
            
            # Create chart
            chart = SimplifiedReportChart(5, 4)
            
            # Plot based on chart type
            chart_type = chart_data.get('type', 'bar')
            
            if chart_type == 'bar':
                x = chart_data.get('x', [])
                y = chart_data.get('y', [])
                chart.axes.bar(x, y)
                
            elif chart_type == 'line':
                x = chart_data.get('x', [])
                y = chart_data.get('y', [])
                chart.axes.plot(x, y)
                
            elif chart_type == 'pie':
                labels = chart_data.get('labels', [])
                sizes = chart_data.get('sizes', [])
                chart.axes.pie(sizes, labels=labels, autopct='%1.1f%%')
                chart.axes.axis('equal')
            
            # Set chart title
            chart.axes.set_title(chart_name)
            
            # Add to layout
            chart_layout.addWidget(chart)
            
            # Add to tabs
            self.charts_tabs.addTab(chart_widget, chart_name)

def create_improved_report_interface(parent_widget: QWidget, 
                                     apply_filter_callback: Callable[[Dict[str, Any]], None] = None,
                                     export_callback: Callable[[Dict[str, Any]], None] = None) -> QWidget:
    """Create an improved reporting interface.
    
    Args:
        parent_widget: The parent widget to contain the interface
        apply_filter_callback: Function to call when filters are applied
        export_callback: Function to call when export is requested
    
    Returns:
        QWidget: The reporting interface container widget
    """
    report_container = QWidget(parent_widget)
    main_layout = QVBoxLayout(report_container)
    
    # Create header
    header_layout = QHBoxLayout()
    header_label = QLabel("Report Generator")
    header_label.setStyleSheet("font-size: 18px; font-weight: bold;")
    
    last_generated = QLabel("Last generated: Never")
    last_generated.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
    
    header_layout.addWidget(header_label)
    header_layout.addStretch()
    header_layout.addWidget(last_generated)
    
    # Create main content splitter
    content_splitter = QSplitter(Qt.Horizontal)
    
    # Left panel - controls
    left_panel = QWidget()
    left_layout = QVBoxLayout(left_panel)
    
    # Create filter panel
    filter_panel = ReportFilterPanel()
    if apply_filter_callback:
        filter_panel.apply_filter_button.clicked.connect(
            lambda: apply_filter_callback(filter_panel.get_filter_settings())
        )
    
    # Create export panel
    export_panel = ReportExportPanel()
    if export_callback:
        export_panel.export_button.clicked.connect(
            lambda: export_callback(export_panel.get_export_settings())
        )
    
    left_layout.addWidget(filter_panel)
    left_layout.addWidget(export_panel)
    
    # Right panel - preview
    right_panel = QWidget()
    right_layout = QVBoxLayout(right_panel)
    
    # Create preview panel
    preview_panel = ReportPreviewPanel()
    
    right_layout.addWidget(preview_panel)
    
    # Add panels to splitter
    content_splitter.addWidget(left_panel)
    content_splitter.addWidget(right_panel)
    
    # Set initial sizes (30% left, 70% right)
    content_splitter.setSizes([300, 700])
    
    # Add to main layout
    main_layout.addLayout(header_layout)
    main_layout.addWidget(content_splitter, 1)  # 1 = stretch factor
    
    logger.info("Improved reporting interface created")
    
    # Return both the container and preview panel for updating
    report_container.preview_panel = preview_panel
    report_container.filter_panel = filter_panel
    report_container.export_panel = export_panel
    report_container.last_generated_label = last_generated
    
    return report_container

def update_report_preview(report_interface: QWidget, report_data: Dict[str, Any]):
    """Update the report preview with new data.
    
    Args:
        report_interface: The report interface container widget
        report_data: Dictionary of report data
    """
    # Update the preview
    report_interface.preview_panel.update_preview(report_data)
    
    # Update last generated time
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    report_interface.last_generated_label.setText(f"Last generated: {now}")
    
    logger.debug("Report preview updated with new data")

def generate_demo_report_data() -> Dict[str, Any]:
    """Generate demonstration report data for testing.
    
    Returns:
        Dict[str, Any]: A dictionary of demo report data
    """
    # Summary data
    summary_data = {
        'Scans': 24,
        'Alerts': 17,
        'Attacks': 8,
        'Defenses': 5
    }
    
    # Events data
    events = [
        {
            'time': '2025-03-29 10:15',
            'type': 'Network Scan',
            'details': 'Full network scan completed. 12 devices found.'
        },
        {
            'time': '2025-03-29 10:35',
            'type': 'Alert',
            'details': 'Suspicious ARP activity detected from 192.168.1.105'
        },
        {
            'time': '2025-03-29 11:02',
            'type': 'Attack',
            'details': 'ARP spoofing attack detected. Attacker: 192.168.1.105, Target: 192.168.1.1'
        },
        {
            'time': '2025-03-29 11:03',
            'type': 'Defense',
            'details': 'Automatic ARP spoof defense activated. Protected gateway: 192.168.1.1'
        }
    ]
    
    # Charts data
    charts_data = {
        'Traffic by Protocol': {
            'type': 'pie',
            'labels': ['TCP', 'UDP', 'ICMP', 'ARP', 'Other'],
            'sizes': [45, 30, 10, 10, 5]
        },
        'Alerts Over Time': {
            'type': 'line',
            'x': ['10:00', '11:00', '12:00', '13:00', '14:00', '15:00'],
            'y': [1, 3, 2, 5, 4, 2]
        },
        'Top Talkers': {
            'type': 'bar',
            'x': ['192.168.1.105', '192.168.1.1', '192.168.1.10', '192.168.1.20'],
            'y': [230, 180, 120, 90]
        }
    }
    
    return {
        'summary_data': summary_data,
        'events': events,
        'charts': charts_data
    } 