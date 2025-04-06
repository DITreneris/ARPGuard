"""Dashboard visualization improvements for ARPGuard.

This module provides utilities for enhancing the dashboard view with
optimized data visualization and layout improvements for a more
intuitive user interface.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QFrame, QSizePolicy, QGraphicsDropShadowEffect
)
from PyQt5.QtCore import Qt, QSize, QTimer
from PyQt5.QtGui import QColor, QPainter, QPen, QFont, QBrush, QLinearGradient

import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional, Callable

from app.utils.logger import get_logger

# Module logger
logger = get_logger('utils.dashboard_improvements')

class DashboardMetricsCard(QFrame):
    """A card-style widget for displaying metrics on the dashboard."""
    
    def __init__(self, title: str, value: str, icon_name: str = None, parent=None):
        """Initialize the metrics card.
        
        Args:
            title: The title/label for the metric
            value: The value to display
            icon_name: Optional icon name (from resource file)
            parent: Parent widget
        """
        super().__init__(parent)
        self.title = title
        self.value = value
        self.icon_name = icon_name
        
        # Set frame style
        self.setFrameShape(QFrame.StyledPanel)
        self.setFrameShadow(QFrame.Raised)
        self.setObjectName("dashboardCard")
        self.setStyleSheet("""
            #dashboardCard {
                background-color: #ffffff;
                border-radius: 8px;
                border: 1px solid #e0e0e0;
            }
        """)
        
        # Add drop shadow
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 50))
        shadow.setOffset(0, 2)
        self.setGraphicsEffect(shadow)
        
        # Set size policy
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setMinimumHeight(120)
        
        # Setup layout
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface for the card."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Title label
        title_label = QLabel(self.title)
        title_label.setObjectName("cardTitle")
        title_label.setStyleSheet("""
            #cardTitle {
                color: #555555;
                font-size: 14px;
            }
        """)
        
        # Value label
        value_label = QLabel(self.value)
        value_label.setObjectName("cardValue")
        value_label.setStyleSheet("""
            #cardValue {
                color: #333333;
                font-size: 22px;
                font-weight: bold;
            }
        """)
        
        # Add to layout
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        layout.addStretch()

class SimplifiedNetworkStatus(QWidget):
    """A simplified network status widget for the dashboard."""
    
    def __init__(self, parent=None):
        """Initialize the network status widget."""
        super().__init__(parent)
        
        # Track status
        self.device_count = 0
        self.threat_count = 0
        self.last_scan_time = None
        
        # Setup UI
        self.setup_ui()
        
        # Update timer (for animation)
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_animation)
        self.update_timer.start(50)  # 50ms updates for smooth animation
        self.animation_offset = 0
    
    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Network status heading
        heading = QLabel("Network Status")
        heading.setObjectName("sectionHeading")
        heading.setStyleSheet("""
            #sectionHeading {
                font-size: 16px;
                font-weight: bold;
                color: #333333;
            }
        """)
        
        # Status display
        self.status_display = QWidget()
        self.status_display.setMinimumHeight(100)
        self.status_display.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        # Add to layout
        layout.addWidget(heading)
        layout.addWidget(self.status_display)
    
    def set_network_status(self, device_count: int, threat_count: int, last_scan_time: Optional[datetime] = None):
        """Update network status information.
        
        Args:
            device_count: Number of devices on the network
            threat_count: Number of detected threats
            last_scan_time: Time of the last network scan
        """
        self.device_count = device_count
        self.threat_count = threat_count
        self.last_scan_time = last_scan_time or datetime.now()
        self.update()
    
    def update_animation(self):
        """Update animation state for the network visualization."""
        self.animation_offset = (self.animation_offset + 1) % 40
        self.status_display.update()
    
    def paintEvent(self, event):
        """Paint the widget, overriding the default paint event."""
        super().paintEvent(event)
        
        # Let the status display handle its own painting
        self.status_display.paintEvent(event)
    
    def resizeEvent(self, event):
        """Handle resize events to update the display."""
        super().resizeEvent(event)
        self.status_display.update()

class QuickActionButton(QWidget):
    """A custom button for quick actions on the dashboard."""
    
    def __init__(self, title: str, description: str, action_callback: Callable, parent=None):
        """Initialize the quick action button.
        
        Args:
            title: Button title
            description: Short description of the action
            action_callback: Function to call when clicked
            parent: Parent widget
        """
        super().__init__(parent)
        self.title = title
        self.description = description
        self.action_callback = action_callback
        self.hovered = False
        
        # Setup UI
        self.setObjectName("quickActionButton")
        self.setStyleSheet("""
            #quickActionButton {
                background-color: #f5f5f5;
                border-radius: 8px;
                border: 1px solid #e0e0e0;
            }
            #quickActionButton:hover {
                background-color: #eaeaea;
            }
        """)
        
        # Set size policy
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setMinimumHeight(50)
        self.setMaximumHeight(60)
        
        # Make the widget clickable and track hover state
        self.setMouseTracking(True)
    
    def paintEvent(self, event):
        """Paint the button."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw background
        bg_color = QColor("#eaeaea") if self.hovered else QColor("#f5f5f5")
        painter.setBrush(QBrush(bg_color))
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(self.rect(), 8, 8)
        
        # Draw border
        painter.setPen(QPen(QColor("#e0e0e0"), 1))
        painter.drawRoundedRect(self.rect().adjusted(0, 0, -1, -1), 8, 8)
        
        # Draw text
        painter.setPen(QColor("#333333"))
        title_font = QFont()
        title_font.setBold(True)
        title_font.setPointSize(10)
        painter.setFont(title_font)
        painter.drawText(15, 20, self.title)
        
        desc_font = QFont()
        desc_font.setPointSize(8)
        painter.setFont(desc_font)
        painter.setPen(QColor("#666666"))
        painter.drawText(15, 40, self.description)
    
    def mousePressEvent(self, event):
        """Handle mouse press events."""
        if event.button() == Qt.LeftButton:
            self.action_callback()
    
    def enterEvent(self, event):
        """Handle mouse enter events."""
        self.hovered = True
        self.update()
    
    def leaveEvent(self, event):
        """Handle mouse leave events."""
        self.hovered = False
        self.update()

def create_dashboard_layout(parent_widget: QWidget, metrics_data: Dict[str, str]) -> QWidget:
    """Create an improved dashboard layout with metrics and status display.
    
    Args:
        parent_widget: The parent widget to contain the dashboard
        metrics_data: Dictionary of metrics to display as title-value pairs
    
    Returns:
        QWidget: The dashboard container widget
    """
    dashboard_container = QWidget(parent_widget)
    main_layout = QVBoxLayout(dashboard_container)
    
    # Header section
    header_layout = QHBoxLayout()
    header_title = QLabel("ARPGuard Dashboard")
    header_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #333333;")
    
    current_time = QLabel(datetime.now().strftime("%Y-%m-%d %H:%M"))
    current_time.setStyleSheet("font-size: 14px; color: #666666;")
    current_time.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
    
    header_layout.addWidget(header_title)
    header_layout.addStretch()
    header_layout.addWidget(current_time)
    
    # Metrics section
    metrics_layout = QHBoxLayout()
    
    for title, value in metrics_data.items():
        metric_card = DashboardMetricsCard(title, value)
        metrics_layout.addWidget(metric_card)
    
    # Network status section
    network_status = SimplifiedNetworkStatus()
    
    # Quick actions section
    actions_layout = QHBoxLayout()
    actions_label = QLabel("Quick Actions")
    actions_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #333333;")
    
    # Add layouts to main layout
    main_layout.addLayout(header_layout)
    main_layout.addSpacing(15)
    main_layout.addLayout(metrics_layout)
    main_layout.addSpacing(20)
    main_layout.addWidget(network_status)
    main_layout.addSpacing(20)
    main_layout.addWidget(actions_label)
    main_layout.addLayout(actions_layout)
    main_layout.addStretch()
    
    logger.info("Dashboard layout created with improved visualization")
    return dashboard_container

def update_dashboard_metrics(metrics_cards: List[DashboardMetricsCard], new_data: Dict[str, str]):
    """Update the dashboard metrics with new values.
    
    Args:
        metrics_cards: List of DashboardMetricsCard widgets to update
        new_data: Dictionary mapping card titles to new values
    """
    for card in metrics_cards:
        if card.title in new_data:
            # Find the value label and update it
            for child in card.children():
                if isinstance(child, QLabel) and child.objectName() == "cardValue":
                    child.setText(new_data[card.title])
                    break
    
    logger.debug(f"Dashboard metrics updated with {len(new_data)} values")

def apply_dashboard_theme(dashboard_widget: QWidget, theme: str = "light"):
    """Apply a color theme to the dashboard.
    
    Args:
        dashboard_widget: The dashboard widget to style
        theme: The theme name ('light' or 'dark')
    """
    if theme == "dark":
        # Dark theme
        dashboard_widget.setStyleSheet("""
            QWidget {
                background-color: #2d2d2d;
                color: #e0e0e0;
            }
            QLabel#sectionHeading {
                color: #ffffff;
            }
            QFrame#dashboardCard {
                background-color: #3d3d3d;
                border: 1px solid #555555;
            }
            QLabel#cardTitle {
                color: #bbbbbb;
            }
            QLabel#cardValue {
                color: #ffffff;
            }
            #quickActionButton {
                background-color: #3d3d3d;
                border: 1px solid #555555;
            }
            #quickActionButton:hover {
                background-color: #494949;
            }
        """)
    else:
        # Light theme (default)
        dashboard_widget.setStyleSheet("""
            QWidget {
                background-color: #f8f8f8;
                color: #333333;
            }
            QFrame#dashboardCard {
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
            }
            #quickActionButton {
                background-color: #f5f5f5;
                border: 1px solid #e0e0e0;
            }
            #quickActionButton:hover {
                background-color: #eaeaea;
            }
        """)
    
    logger.info(f"Applied {theme} theme to dashboard") 