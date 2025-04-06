from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QTableWidget, QTableWidgetItem, QLabel,
    QStatusBar, QSystemTrayIcon, QMenu, QAction, QMessageBox,
    QDialog, QTabWidget, QFormLayout, QLineEdit, QCheckBox,
    QSpinBox, QDoubleSpinBox, QComboBox, QProgressBar, QSplitter,
    QScrollArea, QFrame, QFileDialog
)
from PyQt5.QtCore import Qt, QTimer, QDateTime
from PyQt5.QtGui import QIcon, QColor, QBrush, QFont

import os
import csv
from datetime import datetime

from app.components.network_scanner import NetworkScanner
from app.components.arp_spoofer import ARPSpoofer
from app.components.threat_detector import ThreatDetector
from app.components.packet_display import PacketDisplay
from app.components.packet_view import PacketView
from app.components.session_history import SessionHistoryView
from app.components.report_viewer import ReportViewer
from app.components.attack_view import AttackView
from app.components.defense_view import DefenseView
from app.components.network_topology import NetworkTopologyView
from app.components.vulnerability_view import VulnerabilityView
from app.components.threat_intelligence_view import ThreatIntelligenceView
from app.components.ml_view import MLView
from app.components.ml_controller import MLController
from app.utils.icon import get_app_icon
from app.utils.config import get_config
from app.utils.logger import get_logger
from app.components.threat_intelligence import get_threat_intelligence
from app.utils.dashboard_improvements import (
    create_dashboard_layout, update_dashboard_metrics,
    apply_dashboard_theme, DashboardMetricsCard
)
from app.utils.reporting_improvements import (
    create_improved_report_interface, update_report_preview,
    generate_demo_report_data
)
from app.components.controller_view import ControllerView

# Module logger
logger = get_logger('components.main_window')

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # Track startup time for uptime calculations
        self.startup_time = datetime.now()
        
        # Load configuration
        self.config = get_config()
        
        # Set window properties
        self.setWindowTitle(self.config.get("app_name", "ARPGuard"))
        self.setMinimumSize(800, 600)
        
        # Set application icon
        self.app_icon = get_app_icon()
        self.setWindowIcon(self.app_icon)
        
        # Initialize components
        self.scanner = NetworkScanner()
        self.spoofer = ARPSpoofer()
        self.detector = ThreatDetector()
        
        # Initialize ML controller
        self.ml_controller = MLController()
        
        # Setup UI
        self.setup_ui()
        
        # Apply settings from config
        self.apply_config()
        
        # Apply UI improvements
        self.apply_ui_improvements()
        
        # Auto-scan on start if enabled
        if self.config.get("scanner.auto_scan_on_start", False):
            QTimer.singleShot(500, self.start_scan)
        
        # Auto-start detection if enabled
        if self.config.get("detector.start_on_launch", False):
            QTimer.singleShot(1000, self.toggle_detection)
        
        # Auto-start ML controller if enabled
        if self.config.get("ml.start_on_launch", False):
            QTimer.singleShot(1500, self.start_ml_controller)
        
        # Show onboarding on first launch (placeholder)
        self.show_onboarding()
        
    def setup_ui(self):
        """Set up the user interface."""
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Add existing tabs
        self.tab_widget.addTab(self.create_dashboard_tab(), "Dashboard")
        self.tab_widget.addTab(self.create_network_tab(), "Network")
        self.tab_widget.addTab(self.create_packets_tab(), "Packets")
        self.tab_widget.addTab(self.create_attacks_tab(), "Attacks")
        self.tab_widget.addTab(self.create_intelligence_tab(), "Intelligence")
        self.tab_widget.addTab(self.create_topology_tab(), "Topology")
        self.tab_widget.addTab(self.create_vulnerabilities_tab(), "Vulnerabilities")
        self.tab_widget.addTab(self.create_defense_tab(), "Defense")
        self.tab_widget.addTab(self.create_reports_tab(), "Reports")
        
        # Add ML tab
        self.ml_view = MLView()
        self.tab_widget.addTab(self.ml_view, "Machine Learning")
        
        # Add controller tab
        self.controller_view = ControllerView()
        self.tab_widget.addTab(self.controller_view, "Controller")
        
        # Add tab widget to main layout
        main_layout.addWidget(self.tab_widget)
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Add status indicators
        self.scan_status_label = QLabel("Scan: Ready")
        self.detection_status_label = QLabel("Detection: Stopped")
        self.ml_status_label = QLabel("ML: Stopped")
        self.uptime_label = QLabel("Uptime: 00:00:00")
        
        self.status_bar.addWidget(self.scan_status_label)
        self.status_bar.addWidget(self.detection_status_label)
        self.status_bar.addWidget(self.ml_status_label)
        self.status_bar.addPermanentWidget(self.uptime_label)
        
        # Setup uptime timer
        self.uptime_timer = QTimer()
        self.uptime_timer.timeout.connect(self.update_uptime)
        self.uptime_timer.start(1000)  # Update every second
        
        # Setup system tray
        self.setup_tray()
        
    def setup_tray(self):
        self.tray_icon = QSystemTrayIcon(self)
        tray_menu = QMenu()
        
        show_action = QAction("Show", self)
        exit_action = QAction("Exit", self)
        
        show_action.triggered.connect(self.show)
        exit_action.triggered.connect(self.close)
        
        tray_menu.addAction(show_action)
        tray_menu.addAction(exit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.setIcon(self.app_icon)  # Use the app icon
        self.tray_icon.setToolTip("ARPGuard")
        self.tray_icon.activated.connect(self.tray_icon_activated)
        
        self.tray_icon.show()
        
    def tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
            self.activateWindow()
            
    def start_scan(self):
        self.status_bar.showMessage("Scanning network...")
        self.scan_button.setEnabled(False)
        
        # Show progress bar
        self.scan_progress.setVisible(True)
        
        # Clear existing data
        self.device_table.setRowCount(0)
        
        # Connect to the actual scanner
        self.scanner.scan_network(callback=self.handle_scan_result)
        
    def handle_scan_result(self, devices, message):
        self.status_bar.showMessage(message)
        
        # Hide progress bar
        self.scan_progress.setVisible(False)
        
        if devices:
            for device in devices:
                row = self.device_table.rowCount()
                self.device_table.insertRow(row)
                self.device_table.setItem(row, 0, QTableWidgetItem(device["name"]))
                self.device_table.setItem(row, 1, QTableWidgetItem(device["ip"]))
                self.device_table.setItem(row, 2, QTableWidgetItem(device["mac"]))
                
                # Add vendor information if available
                if "vendor" in device:
                    self.device_table.setItem(row, 3, QTableWidgetItem(device["vendor"]))
                else:
                    self.device_table.setItem(row, 3, QTableWidgetItem("Unknown"))
            
            self.status_bar.showMessage(f"Found {len(devices)} devices on the network")
            
            # Reapply any filter
            if self.filter_input.text():
                self.apply_filter(self.filter_input.text())
            
            # Update topology view with the scanned devices
            self._update_topology_with_devices()
        else:
            # If no devices were found or there was an error, use simulated data for demo purposes
            self.handle_scan_complete()
            
        self.scan_button.setEnabled(True)
        
    def handle_scan_complete(self):
        # Simulated network scan results for demo purposes
        devices = [
            {"name": "Router", "ip": "192.168.1.1", "mac": "00:14:22:33:44:55", "vendor": "Cisco Systems"},
            {"name": "User's PC", "ip": "192.168.1.100", "mac": "00:1A:2B:3C:4D:5E", "vendor": "Intel Corporate"},
            {"name": "Smart TV", "ip": "192.168.1.120", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Samsung Electronics"}
        ]
        
        for device in devices:
            row = self.device_table.rowCount()
            self.device_table.insertRow(row)
            self.device_table.setItem(row, 0, QTableWidgetItem(device["name"]))
            self.device_table.setItem(row, 1, QTableWidgetItem(device["ip"]))
            self.device_table.setItem(row, 2, QTableWidgetItem(device["mac"]))
            self.device_table.setItem(row, 3, QTableWidgetItem(device["vendor"]))
            
        self.status_bar.showMessage(f"Found {len(devices)} devices on the network (simulated)")
        
    def show_device_context_menu(self, position):
        if self.device_table.rowCount() == 0:
            return
            
        menu = QMenu()
        spoof_action = QAction("Spoof This", self)
        spoof_action.triggered.connect(self.start_spoofing)
        menu.addAction(spoof_action)
        
        menu.exec_(self.device_table.mapToGlobal(position))
        
    def start_spoofing(self):
        # Get selected device
        selected_rows = self.device_table.selectionModel().selectedRows()
        if not selected_rows:
            return
            
        row = selected_rows[0].row()
        device_name = self.device_table.item(row, 0).text()
        device_ip = self.device_table.item(row, 1).text()
        
        # Show warning
        reply = QMessageBox.warning(
            self,
            "Ethical Warning",
            "Only use ARP spoofing on networks you own or have permission to test.\n\nContinue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Get the gateway IP to spoof as
            gateway_ip, _ = self.scanner.get_default_gateway()
            if not gateway_ip:
                QMessageBox.critical(
                    self,
                    "Error",
                    "Could not determine default gateway for spoofing."
                )
                return
            
            # Create packet display if it doesn't exist
            if not hasattr(self, 'packet_display'):
                self.packet_display = PacketDisplay()
                
            # Get the right panel and add the packet display
            right_panel = self.findChild(QWidget, "right_panel")
            
            # Clear the right panel layout
            while right_panel.layout().count():
                item = right_panel.layout().takeAt(0)
                if item.widget():
                    item.widget().setParent(None)
            
            # Add controls to the right panel
            right_layout = right_panel.layout()
            
            info_label = QLabel(f"<b>ARP Spoofing Active</b><br>Target: {device_name} ({device_ip})<br>Spoofing as: {gateway_ip}")
            right_layout.addWidget(info_label)
            
            self.stop_spoof_button = QPushButton("Stop Spoofing")
            self.stop_spoof_button.clicked.connect(self.stop_spoofing)
            right_layout.addWidget(self.stop_spoof_button)
            
            # Add packet display
            right_layout.addWidget(self.packet_display)
                
            # Start spoofing
            success = self.spoofer.start_spoofing(
                device_ip, 
                gateway_ip,
                callback=self.handle_spoof_update,
                packet_callback=self.packet_display.add_packet
            )
            
            if success:
                self.status_bar.showMessage(f"Spoofing {device_ip} as {gateway_ip}...")
            else:
                self.status_bar.showMessage("Failed to start spoofing.")
    
    def stop_spoofing(self):
        if self.spoofer.stop_spoofing():
            self.status_bar.showMessage("Spoofing stopped.")
            
            # Get packet history before clearing
            packet_history = self.spoofer.get_packet_history()
            
            # Right panel cleanup
            right_panel = self.findChild(QWidget, "right_panel")
            
            # Clear the right panel layout
            while right_panel.layout().count():
                item = right_panel.layout().takeAt(0)
                if item.widget():
                    item.widget().setParent(None)
                    
            # Reset the right panel to default state
            right_layout = right_panel.layout()
            self.info_label = QLabel("Select a device to see details")
            right_layout.addWidget(self.info_label)
            
            # Add progress bar for scan operations
            self.scan_progress = QProgressBar()
            self.scan_progress.setRange(0, 0)  # Indeterminate progress
            self.scan_progress.setVisible(False)
            right_layout.addWidget(self.scan_progress)
            
            right_layout.addStretch()
            
            # Show summary info
            if packet_history:
                QMessageBox.information(
                    self,
                    "Spoofing Summary",
                    f"Spoofing stopped.\n\n"
                    f"Total packets sent: {len(packet_history)}\n"
                    f"Duration: {(packet_history[-1]['time'] - packet_history[0]['time']).total_seconds():.2f} seconds"
                )
    
    def handle_spoof_update(self, success, message):
        if success:
            self.status_bar.showMessage(message)
        else:
            QMessageBox.warning(
                self,
                "Spoofing Error",
                message
            )
            self.stop_spoofing()
        
    def toggle_detection(self):
        if self.detect_button.text() == "Start Detection":
            # Start detection
            success = self.detector.start_detection(callback=self.handle_threat_detected)
            
            if success:
                self.detect_button.setText("Stop Detection")
                self.status_bar.showMessage("Threat detection active...")
            else:
                self.status_bar.showMessage("Failed to start threat detection.")
        else:
            # Stop detection
            if self.detector.stop_detection():
                self.detect_button.setText("Start Detection")
                self.status_bar.showMessage("Threat detection stopped")
    
    def handle_threat_detected(self, success, message):
        if success:
            # Determine severity based on message content
            severity = "info"
            if "CRITICAL" in message:
                severity = "critical"
            elif "WARNING" in message:
                severity = "warning"
            
            # Add to alert panel
            self.add_alert(message, severity)
            
            # Show notification for threats
            self.tray_icon.showMessage(
                "ARP Threat Detected!",
                message,
                QSystemTrayIcon.Warning,
                5000  # 5 seconds
            )
            
            # Update status bar
            self.status_bar.showMessage(message)
            
            # Update threat display in the threat table
            self.update_threat_table()
        else:
            # Show error message
            self.status_bar.showMessage(f"Detection error: {message}")
            # Add error to alert panel
            self.add_alert(f"Detection error: {message}", "warning")
    
    def show_help(self):
        QMessageBox.information(
            self,
            "ARPGuard Help",
            "ARPGuard is a tool to scan, test, and secure your network against ARP poisoning attacks.\n\n"
            "1. Scan Network: Discover all devices on your local network\n"
            "2. Spoof This: Simulate an ARP spoofing attack (right-click on a device)\n"
            "3. Start Detection: Monitor for real ARP poisoning attacks"
        )
        
    def show_onboarding(self):
        # Simple placeholder for onboarding tutorial
        QMessageBox.information(
            self,
            "Welcome to ARPGuard",
            "This tool helps you test and secure your network against ARP poisoning.\n\n"
            "Follow these steps to get started:\n"
            "1. Click 'Scan Network' to discover devices\n"
            "2. Right-click on a device and select 'Spoof This' to test\n"
            "3. Use 'Start Detection' to monitor for real threats"
        )
        
    def apply_config(self):
        """Apply settings from configuration."""
        # Apply window settings
        if self.config.get("ui.start_maximized", False):
            self.showMaximized()
        
        # Apply ML settings
        ml_collection_interval = self.config.get("ml.collection_interval", 10)
        ml_auto_training = self.config.get("ml.automatic_training", False)
        ml_training_interval = self.config.get("ml.training_interval", 3600)
        ml_min_samples = self.config.get("ml.min_training_samples", 1000)
        
        self.ml_controller.set_collection_interval(ml_collection_interval)
        self.ml_controller.set_training_settings(
            ml_auto_training, ml_training_interval, ml_min_samples
        )
        
        # Apply theme
        theme = self.config.get("theme", "dark")
        if theme == "dark":
            # Apply dark theme styles (placeholder)
            self.setStyleSheet("""
                QMainWindow, QDialog {
                    background-color: #2d2d2d;
                    color: #e0e0e0;
                }
                QWidget {
                    background-color: #2d2d2d;
                    color: #e0e0e0;
                }
                QPushButton {
                    background-color: #3d3d3d;
                    color: #e0e0e0;
                    border: 1px solid #5d5d5d;
                    padding: 5px;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: #4d4d4d;
                }
                QTableWidget {
                    background-color: #2d2d2d;
                    color: #e0e0e0;
                    border: 1px solid #3d3d3d;
                    gridline-color: #3d3d3d;
                }
                QTableWidget::item:selected {
                    background-color: #3d3d3d;
                }
                QHeaderView::section {
                    background-color: #3d3d3d;
                    color: #e0e0e0;
                    border: 1px solid #5d5d5d;
                }
                QLabel {
                    color: #e0e0e0;
                }
                QStatusBar {
                    background-color: #3d3d3d;
                    color: #e0e0e0;
                }
            """)
        else:
            # Apply light theme or no theme
            self.setStyleSheet("")
        
        # Configure components based on settings
        self.scanner.timeout = self.config.get("scanner.timeout", 3)
        self.spoofer.interval = self.config.get("spoofer.packet_interval", 1.0)
    
    def show_settings(self):
        """Show the settings dialog."""
        settings_dialog = SettingsDialog(self)
        if settings_dialog.exec_() == QDialog.Accepted:
            # Apply the new settings
            self.apply_config()
    
    def closeEvent(self, event):
        # Stop ML controller
        self.stop_ml_controller()
        
        # Check if we should minimize to tray instead of closing
        if self.config.get("minimize_to_tray", True):
            event.ignore()
            self.hide()
            self.tray_icon.showMessage(
                self.config.get("app_name", "ARPGuard"),
                "ARPGuard is still running in the background",
                QSystemTrayIcon.Information,
                2000
            )
        else:
            # Stop any active operations before closing
            if self.spoofer.running:
                self.spoofer.stop_spoofing()
            if self.detector.running:
                self.detector.stop_detection()
            event.accept()

    def apply_filter(self, filter_text):
        """Filter the device table based on user input."""
        filter_text = filter_text.lower()
        
        # If no filter, show all devices
        if not filter_text:
            for row in range(self.device_table.rowCount()):
                self.device_table.setRowHidden(row, False)
            return
            
        # Apply filter to each row
        for row in range(self.device_table.rowCount()):
            should_hide = True
            
            # Check each column for a match
            for col in range(self.device_table.columnCount()):
                item = self.device_table.item(row, col)
                if item and filter_text in item.text().lower():
                    should_hide = False
                    break
                    
            self.device_table.setRowHidden(row, should_hide)
            
        # Update status with filter info
        visible_count = sum(1 for row in range(self.device_table.rowCount()) 
                           if not self.device_table.isRowHidden(row))
        self.status_bar.showMessage(f"Showing {visible_count} of {self.device_table.rowCount()} devices")

    def create_alert_panel(self):
        """Create the alert panel for security alerts."""
        alert_container = QWidget()
        alert_layout = QVBoxLayout(alert_container)
        
        # Header with title and controls
        header_layout = QHBoxLayout()
        title_label = QLabel("<b>Security Alerts</b>")
        title_label.setFont(QFont(title_label.font().family(), 12))
        
        self.clear_alerts_button = QPushButton("Clear Alerts")
        self.clear_alerts_button.clicked.connect(self.clear_alerts)
        
        self.save_alerts_button = QPushButton("Save Alerts")
        self.save_alerts_button.clicked.connect(self.save_alerts_to_file)
        
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(self.save_alerts_button)
        header_layout.addWidget(self.clear_alerts_button)
        
        # Scroll area for alerts
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)
        
        # Container for alert messages
        self.alert_scroll_content = QWidget()
        self.alert_scroll_layout = QVBoxLayout(self.alert_scroll_content)
        self.alert_scroll_layout.setAlignment(Qt.AlignTop)
        self.alert_scroll_layout.setSpacing(5)
        
        # Initialize alert storage
        self.alerts = []  # List to store alerts: [{'timestamp': datetime, 'message': str, 'severity': str}]
        
        scroll_area.setWidget(self.alert_scroll_content)
        
        # Add components to layout
        alert_layout.addLayout(header_layout)
        alert_layout.addWidget(scroll_area)
        
        return alert_container
    
    def add_alert(self, message, severity="warning"):
        """Add an alert message to the alert panel.
        
        Args:
            message: The alert message text
            severity: The severity level (critical, warning, info)
        """
        # Get current time
        current_time = datetime.now()
        
        # Store the alert in our history
        self.alerts.append({
            'timestamp': current_time,
            'message': message,
            'severity': severity
        })
        
        # Create alert widget
        alert_widget = QFrame()
        alert_widget.setFrameShape(QFrame.StyledPanel)
        alert_widget.setLineWidth(1)
        
        # Set style based on severity
        if severity.lower() == "critical":
            alert_widget.setStyleSheet("""
                QFrame {
                    background-color: #ffdddd;
                    border: 1px solid #ff0000;
                    border-radius: 3px;
                }
            """)
            icon = "🔴"  # Red circle for critical
        elif severity.lower() == "warning":
            alert_widget.setStyleSheet("""
                QFrame {
                    background-color: #ffffdd;
                    border: 1px solid #ffcc00;
                    border-radius: 3px;
                }
            """)
            icon = "⚠️"  # Warning icon
        else:  # info
            alert_widget.setStyleSheet("""
                QFrame {
                    background-color: #ddffff;
                    border: 1px solid #00ccff;
                    border-radius: 3px;
                }
            """)
            icon = "ℹ️"  # Info icon
        
        # Create layout for the alert
        alert_layout = QHBoxLayout(alert_widget)
        alert_layout.setContentsMargins(10, 10, 10, 10)
        
        # Add timestamp
        timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S")
        
        # Create label with icon, timestamp and message
        label_text = f"{icon} <b>[{timestamp}]</b> {message}"
        message_label = QLabel(label_text)
        message_label.setWordWrap(True)
        
        # Add to alert layout
        alert_layout.addWidget(message_label)
        
        # Add to scroll area at the top
        self.alert_scroll_layout.insertWidget(0, alert_widget)
        
        # Also log the alert with our logger
        if severity.lower() == "critical":
            logger.critical(message)
        elif severity.lower() == "warning":
            logger.warning(message)
        else:
            logger.info(message)
        
        # Optional: play sound or flash if it's critical
        if severity.lower() == "critical" and self.config.get("alerts.enable_sounds", True):
            # Could play a sound here
            pass
    
    def clear_alerts(self):
        """Clear all alerts from the alert panel."""
        # Ask for confirmation if there are many alerts
        if len(self.alerts) > 5:
            reply = QMessageBox.question(
                self,
                "Clear Alerts",
                f"Are you sure you want to clear all {len(self.alerts)} alerts?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply != QMessageBox.Yes:
                return
        
        # Clear stored alerts
        self.alerts = []
        
        # Remove all alert widgets
        while self.alert_scroll_layout.count() > 0:
            item = self.alert_scroll_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
    
    def save_alerts_to_file(self):
        """Save alerts to a CSV or text file."""
        if not self.alerts:
            QMessageBox.information(
                self,
                "No Alerts",
                "There are no alerts to save.",
                QMessageBox.Ok
            )
            return
        
        # Ask for file location
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Alerts",
            os.path.expanduser("~/arpguard_alerts.csv"),
            "CSV Files (*.csv);;Text Files (*.txt);;All Files (*)"
        )
        
        if not filename:
            return  # User cancelled
        
        try:
            # Sort alerts by timestamp (newest first)
            sorted_alerts = sorted(
                self.alerts, 
                key=lambda x: x['timestamp'], 
                reverse=True
            )
            
            # Save based on file extension
            if filename.lower().endswith('.csv'):
                self._save_alerts_as_csv(filename, sorted_alerts)
            else:
                self._save_alerts_as_text(filename, sorted_alerts)
                
            # Show success message
            QMessageBox.information(
                self,
                "Alerts Saved",
                f"Successfully saved {len(self.alerts)} alerts to {filename}",
                QMessageBox.Ok
            )
            
            logger.info(f"Saved {len(self.alerts)} alerts to {filename}")
            
        except Exception as e:
            # Show error message
            QMessageBox.critical(
                self,
                "Error Saving Alerts",
                f"An error occurred while saving alerts: {str(e)}",
                QMessageBox.Ok
            )
            
            logger.error(f"Error saving alerts: {e}")
    
    def _save_alerts_as_csv(self, filename, alerts):
        """Save alerts to a CSV file.
        
        Args:
            filename: Path to the CSV file
            alerts: List of alert dictionaries
        """
        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file)
            
            # Write header
            writer.writerow(['Timestamp', 'Severity', 'Message'])
            
            # Write each alert
            for alert in alerts:
                writer.writerow([
                    alert['timestamp'].strftime("%Y-%m-%d %H:%M:%S"),
                    alert['severity'],
                    alert['message']
                ])
    
    def _save_alerts_as_text(self, filename, alerts):
        """Save alerts to a text file.
        
        Args:
            filename: Path to the text file
            alerts: List of alert dictionaries
        """
        with open(filename, 'w') as file:
            file.write("ARPGuard Security Alerts\n")
            file.write("=========================\n\n")
            
            # Write each alert
            for alert in alerts:
                timestamp = alert['timestamp'].strftime("%Y-%m-%d %H:%M:%S")
                severity = alert['severity'].upper()
                message = alert['message']
                
                file.write(f"[{timestamp}] {severity}: {message}\n\n")
    
    def update_threat_table(self):
        """Update the threat table with current threats."""
        # Get current threats
        threats = self.detector.get_threats()
        
        # Create threat table if it doesn't exist
        if not hasattr(self, 'threat_table'):
            # Create it in the right panel
            right_panel = self.findChild(QWidget, "right_panel")
            right_layout = right_panel.layout()
            
            # Add a label
            threat_label = QLabel("<b>Detected Threats:</b>")
            right_layout.insertWidget(1, threat_label)
            
            # Create and add the table
            self.threat_table = QTableWidget(0, 3)
            self.threat_table.setHorizontalHeaderLabels(["IP Address", "MAC Addresses", "First Seen"])
            right_layout.insertWidget(2, self.threat_table)
            
            # Set initial height
            self.threat_table.setMinimumHeight(100)
        
        # Update the table
        self.threat_table.setRowCount(len(threats))
        
        for i, threat in enumerate(threats):
            # IP Address
            self.threat_table.setItem(i, 0, QTableWidgetItem(threat['ip']))
            
            # MAC Addresses with vendors
            mac_text = ", ".join([
                f"{mac} ({vendor})" 
                for mac, vendor in zip(threat['macs'], threat['vendors'])
            ])
            mac_item = QTableWidgetItem(mac_text)
            
            # Color coding for gateway threats
            if threat.get('is_gateway', False):
                mac_item.setBackground(QBrush(QColor(255, 200, 200)))  # Light red for gateway threats
            
            self.threat_table.setItem(i, 1, mac_item)
            
            # First seen timestamp
            first_seen = threat['first_seen'].strftime("%Y-%m-%d %H:%M:%S")
            self.threat_table.setItem(i, 2, QTableWidgetItem(first_seen))

    def update_status(self, message):
        """Update status bar with message from components."""
        self.status_bar.showMessage(message)
    
    def handle_capture_toggle(self, capturing):
        """Handle packet capture start/stop."""
        # Update UI based on capture state if needed
        if capturing:
            self.tab_widget.setTabText(self.tab_widget.indexOf(self.packet_analysis_tab), "Packet Analysis ●")
        else:
            self.tab_widget.setTabText(self.tab_widget.indexOf(self.packet_analysis_tab), "Packet Analysis")

    def load_historical_session(self, session_id):
        """Load a historical packet capture session.
        
        Args:
            session_id: ID of the session to load
        """
        try:
            # Get database instance
            from app.utils.database import get_database
            db = get_database()
            
            # Get session summary
            session = db.get_session_summary(session_id)
            if not session:
                self.status_bar.showMessage(f"Could not find session {session_id}")
                return
            
            # Get packets for this session (limited to 1000 for performance)
            packets = db.get_packets(session_id, limit=1000)
            
            # Switch to the packet analysis tab
            self.tab_widget.setCurrentIndex(1)  # Index of packet analysis tab
            
            # Clear current packet view
            self.packet_view.clear_packets()
            
            # Add packets to the view
            for packet in packets:
                self.packet_view.handle_new_packet(packet)
            
            # Update status
            self.status_bar.showMessage(
                f"Loaded historical session {session_id} with {len(packets)} packets from {session['start_time'].strftime('%Y-%m-%d %H:%M:%S')}"
            )
            
        except Exception as e:
            self.status_bar.showMessage(f"Error loading session: {e}")
            logger.error(f"Error loading historical session: {e}")

    def handle_attack_detected(self, attack_details):
        """Handle attack detection events from the attack recognizer.
        
        Args:
            attack_details: Dictionary with attack details
        """
        # Get formatted message from the attack details
        attack_type = attack_details.get('type', 'unknown')
        attack_name = attack_details.get('name', 'Unknown Attack')
        severity = attack_details.get('severity', 'medium').upper()
        
        # Create a basic message based on attack type
        message = f"{severity}: {attack_name} detected"
        
        # Add to alert panel with appropriate severity
        if severity.lower() == 'critical':
            self.add_alert(message, "critical")
        elif severity.lower() == 'high':
            self.add_alert(message, "warning")
        else:
            self.add_alert(message, "info")
        
        # Switch to the Attack Patterns tab if this is a critical or high severity attack
        if severity.lower() in ('critical', 'high'):
            attack_tab_index = self.tab_widget.indexOf(self.attack_view)
            self.tab_widget.setCurrentIndex(attack_tab_index)
        
        # Forward the attack to the defense view for potential countermeasures
        self.defense_view.handle_attack_detected(attack_details)

    def handle_defense_activated(self, defense_details):
        """Handle defense activation events.
        
        Args:
            defense_details: Dictionary with defense details
        """
        # Get defense type and action
        defense_type = defense_details.get('type', 'unknown')
        defense_action = defense_details.get('action', 'unknown')
        
        # Create a message based on defense type
        if defense_type == 'arp_defense':
            # Get protected IPs
            protected_ips = defense_details.get('protected_ips', [])
            ip_count = len(protected_ips)
            
            if ip_count > 0:
                message = f"Defense activated: Static ARP entries added for {ip_count} IP address(es)"
            else:
                message = "Defense activated: ARP protection enabled"
            
        elif defense_type == 'port_scan_defense':
            # Get blocked IPs
            blocked_ips = defense_details.get('blocked_ips', [])
            ip_count = len(blocked_ips)
            
            if ip_count > 0:
                message = f"Defense activated: Blocked {ip_count} port scanner IP address(es)"
            else:
                message = "Defense activated: Port scan protection enabled"
            
        elif defense_type == 'ddos_defense':
            # Get protected targets
            protected_targets = defense_details.get('protected_targets', [])
            target_count = len(protected_targets)
            
            if target_count > 0:
                message = f"Defense activated: Rate limiting enabled for {target_count} target(s)"
            else:
                message = "Defense activated: DDoS protection enabled"
            
        elif defense_type == 'dns_defense':
            # Get protected domains
            protected_domains = defense_details.get('protected_domains', [])
            domain_count = len(protected_domains)
            
            if domain_count > 0:
                message = f"Defense activated: Protected {domain_count} domain(s) from DNS poisoning"
            else:
                message = "Defense activated: DNS protection enabled"
            
        else:
            message = f"Defense activated: {defense_action}"
        
        # Add to alert panel
        self.add_alert(message, "info")
        
        # Update status bar
        self.status_bar.showMessage(message)

    def handle_topology_node_selected(self, node_id):
        """Handle node selection in the topology view.
        
        Args:
            node_id: ID of the selected node
        """
        # Update status bar
        self.status_bar.showMessage(f"Selected node: {node_id}")
        
        # Find the device in the devices table
        for row in range(self.device_table.rowCount()):
            ip_item = self.device_table.item(row, 1)  # IP column
            if ip_item and ip_item.text() == node_id:
                # Select this row in the devices table
                self.device_table.selectRow(row)
                break

    def handle_topology_node_double_clicked(self, node_id):
        """Handle node double-click in the topology view.
        
        Args:
            node_id: ID of the double-clicked node
        """
        # Find device matching node_id
        device = None
        for d in self.devices:
            if d.get('ip') == node_id:
                device = d
                break
        
        if device:
            # Show device details
            msg = f"Device Details:\nIP: {device.get('ip')}\nMAC: {device.get('mac')}"
            if device.get('vendor'):
                msg += f"\nVendor: {device.get('vendor')}"
            if device.get('hostname'):
                msg += f"\nHostname: {device.get('hostname')}"
            
            QMessageBox.information(self, "Device Details", msg)

    def _update_topology_with_devices(self):
        """Update the network topology view with current device data."""
        if not hasattr(self, 'devices') or not self.devices:
            return
        
        # Convert devices to topology nodes
        nodes_data = []
        
        # Track the gateway device
        gateway_ip = None
        
        # First pass: create nodes
        for device in self.devices:
            ip = device.get('ip', '')
            mac = device.get('mac', '')
            hostname = device.get('hostname', '')
            vendor = device.get('vendor', '')
            is_gateway = device.get('is_gateway', False)
            
            # Use hostname as name if available, otherwise IP
            name = hostname if hostname else ip
            
            # Create node data
            node_data = {
                'id': ip,
                'name': name,
                'ip': ip,
                'mac': mac,
                'is_gateway': is_gateway,
                'vendor': vendor,
                'connections': [],
                'threat_level': 0
            }
            
            # Mark gateway for later use in connections
            if is_gateway:
                gateway_ip = ip
            
            # Check if this device has threats
            for threat in self.threats:
                if threat.get('ip') == ip:
                    severity = threat.get('severity', '').lower()
                    if severity == 'critical':
                        node_data['threat_level'] = 2
                    elif severity == 'warning':
                        node_data['threat_level'] = 1
            
            nodes_data.append(node_data)
        
        # Second pass: create connections (simplified model: all nodes connect to gateway)
        if gateway_ip:
            for node_data in nodes_data:
                if node_data['id'] != gateway_ip:
                    node_data['connections'].append(gateway_ip)
        
        # Update the topology view
        self.topology_view.set_nodes(nodes_data)
        self.topology_view.apply_layout()

    def _update_node_threat_levels(self):
        """Update threat levels of nodes in the topology view."""
        for threat in self.threats:
            ip = threat.get('ip')
            if ip:
                severity = threat.get('severity', '').lower()
                level = 2 if severity == 'critical' else 1 if severity == 'warning' else 0
                self.topology_view.set_node_threat_level(ip, level)
        
        # Apply layout to refresh the view
        self.topology_view.refresh_topology()

    def handle_vulnerability_scan_started(self):
        """Handle the start of a vulnerability scan."""
        # Set tab text to indicate scan in progress
        vuln_tab_index = self.tab_widget.indexOf(self.vulnerability_view)
        self.tab_widget.setTabText(vuln_tab_index, "Vulnerabilities ●")
    
    def handle_vulnerability_scan_completed(self):
        """Handle the completion of a vulnerability scan."""
        # Reset tab text
        vuln_tab_index = self.tab_widget.indexOf(self.vulnerability_view)
        self.tab_widget.setTabText(vuln_tab_index, "Vulnerabilities")
        
        # Get scan results
        vulnerabilities = self.vulnerability_view.get_vulnerabilities()
        
        # If critical vulnerabilities were found, show notification
        critical_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'critical']
        if critical_vulns:
            self.tray_icon.showMessage(
                "Critical Vulnerabilities Detected!",
                f"Found {len(critical_vulns)} critical vulnerabilities on your network.",
                QSystemTrayIcon.Critical,
                5000  # 5 seconds
            )
            
            # Add to alert panel
            for vuln in critical_vulns:
                message = f"CRITICAL VULNERABILITY: {vuln['name']} on {vuln['target']['ip']}"
                if 'port' in vuln:
                    message += f" (port {vuln['port']})"
                self.add_alert(message, "critical")
        
        # If there are any vulnerabilities, switch to vulnerability tab
        if vulnerabilities:
            self.tab_widget.setCurrentIndex(vuln_tab_index)

    def handle_status_change(self, message):
        """Handle status changes from various components."""
        self.update_status(message)

    def handle_threat_intel_updated(self, details):
        """Handle updates to threat intelligence data.
        
        Args:
            details: Dictionary with update details
        """
        # Update status
        sources = details.get('sources_successful', [])
        if sources:
            self.add_alert(
                "Threat intelligence updated",
                f"Updated data from {len(sources)} sources: {', '.join(sources)}",
                "info"
            )
        
        # Get statistics
        malicious_ips = details.get('malicious_ips_updated', 0)
        malicious_domains = details.get('malicious_domains_updated', 0)
        signatures = details.get('attack_signatures_updated', 0)
        
        # Add alert for important detections
        total_threats = malicious_ips + malicious_domains
        if total_threats > 0:
            severity = "warning" if total_threats > 10 else "info"
            self.add_alert(
                "New threat indicators detected",
                f"Added {malicious_ips} malicious IPs and {malicious_domains} malicious domains",
                severity
            )
        
        # Integrate the new data with threat detector
        self._integrate_threat_intelligence()

    def _integrate_threat_intelligence(self):
        """Integrate threat intelligence data with threat detector."""
        # Get the threat intelligence backend
        threat_intel = get_threat_intelligence()
        
        # Only proceed if threat detector is available and initialized
        if not hasattr(self, 'threat_detector_view'):
            return
            
        try:
            # Get critical threats
            malicious_ips = threat_intel.get_all_malicious_ips(min_score=90)
            if malicious_ips:
                # Add high-risk IPs to threat detector's blocklist
                for ip, details in malicious_ips.items():
                    categories = details.get('categories', [])
                    category_text = ", ".join(categories) if categories else "unknown"
                    
                    # Add to threat detector watchlist
                    self.threat_detector_view.add_to_watchlist(
                        ip_address=ip,
                        threat_type=f"Intelligence: {category_text}",
                        confidence=details.get('score', 90),
                        source=details.get('source', 'cloud_intel')
                    )
            
            # Get attack signatures
            critical_signatures = threat_intel.get_attack_signatures(severity="critical")
            high_signatures = threat_intel.get_attack_signatures(severity="high")
            
            if critical_signatures or high_signatures:
                # Log signature detection
                signature_count = len(critical_signatures) + len(high_signatures)
                logger.info(f"Integrating {signature_count} attack signatures from threat intelligence")
                
                # These would be used by packet analyzers or attack recognizers
                # In a full implementation, we would register these patterns
        except Exception as e:
            logger.error(f"Error integrating threat intelligence: {e}")

    def apply_ui_improvements(self):
        """Apply UI improvements and connect component signals."""
        # Connect ML components
        self._connect_ml_components()
        
        # Connect other components
        # ... existing code ...
    
    def _connect_ml_components(self):
        """Connect ML components to the application."""
        try:
            # Connect ML controller to ML view
            self.ml_view.ml_integration = self.ml_controller.ml_integration
            
            # Connect ML controller to threat detector
            self.detector.set_ml_controller(self.ml_controller)
            
            # Connect ML detector to ML integration
            self.ml_controller.ml_integration.ml_detector.set_ml_integration(
                self.ml_controller.ml_integration
            )
            
            # Start ML controller if auto-start is enabled
            if self.config.get("ml.start_on_launch", False):
                self.start_ml_controller()
                
            logger.info("ML components connected successfully")
            
        except Exception as e:
            logger.error(f"Error connecting ML components: {e}")

    def get_uptime_string(self):
        """Get a formatted string of the application uptime."""
        elapsed_time = datetime.now() - self.startup_time
        hours, remainder = divmod(int(elapsed_time.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m {seconds}s"

    def start_ml_controller(self):
        """Start the ML controller."""
        try:
            self.ml_controller.start()
            self.ml_status_label.setText("ML: Running")
            self.status_bar.showMessage("ML controller started", 3000)
        except Exception as e:
            logger.error(f"Error starting ML controller: {e}")
            self.ml_status_label.setText("ML: Error")
            self.status_bar.showMessage(f"Error starting ML controller: {e}", 5000)
    
    def stop_ml_controller(self):
        """Stop the ML controller."""
        try:
            self.ml_controller.stop()
            self.ml_status_label.setText("ML: Stopped")
            self.status_bar.showMessage("ML controller stopped", 3000)
        except Exception as e:
            logger.error(f"Error stopping ML controller: {e}")
            self.status_bar.showMessage(f"Error stopping ML controller: {e}", 5000)


class SettingsDialog(QDialog):
    """Settings dialog for ARPGuard."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.config = get_config()
        
        self.setWindowTitle("ARPGuard Settings")
        self.setMinimumWidth(400)
        
        # Create tab widget for settings categories
        tab_widget = QTabWidget()
        
        # General settings tab
        general_tab = QWidget()
        general_layout = QFormLayout(general_tab)
        
        # UI settings
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["dark", "light"])
        self.theme_combo.setCurrentText(self.config.get("theme", "dark"))
        
        self.minimize_to_tray_check = QCheckBox()
        self.minimize_to_tray_check.setChecked(self.config.get("minimize_to_tray", True))
        
        self.show_tooltips_check = QCheckBox()
        self.show_tooltips_check.setChecked(self.config.get("show_tooltips", True))
        
        general_layout.addRow("Theme:", self.theme_combo)
        general_layout.addRow("Minimize to tray:", self.minimize_to_tray_check)
        general_layout.addRow("Show tooltips:", self.show_tooltips_check)
        
        # Scanner settings tab
        scanner_tab = QWidget()
        scanner_layout = QFormLayout(scanner_tab)
        
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 10)
        self.timeout_spin.setValue(self.config.get("scanner.timeout", 3))
        
        self.auto_scan_check = QCheckBox()
        self.auto_scan_check.setChecked(self.config.get("scanner.auto_scan_on_start", False))
        
        self.save_results_check = QCheckBox()
        self.save_results_check.setChecked(self.config.get("scanner.save_results", True))
        
        scanner_layout.addRow("Scan timeout (seconds):", self.timeout_spin)
        scanner_layout.addRow("Auto-scan on start:", self.auto_scan_check)
        scanner_layout.addRow("Save scan results:", self.save_results_check)
        
        # Spoofer settings tab
        spoofer_tab = QWidget()
        spoofer_layout = QFormLayout(spoofer_tab)
        
        self.packet_interval_spin = QDoubleSpinBox()
        self.packet_interval_spin.setRange(0.1, 5.0)
        self.packet_interval_spin.setSingleStep(0.1)
        self.packet_interval_spin.setValue(self.config.get("spoofer.packet_interval", 1.0))
        
        self.restore_on_exit_check = QCheckBox()
        self.restore_on_exit_check.setChecked(self.config.get("spoofer.restore_on_exit", True))
        
        spoofer_layout.addRow("Packet interval (seconds):", self.packet_interval_spin)
        spoofer_layout.addRow("Restore ARP tables on exit:", self.restore_on_exit_check)
        
        # Detector settings tab
        detector_tab = QWidget()
        detector_layout = QFormLayout(detector_tab)
        
        self.start_on_launch_check = QCheckBox()
        self.start_on_launch_check.setChecked(self.config.get("detector.start_on_launch", False))
        
        self.notification_level_combo = QComboBox()
        self.notification_level_combo.addItems(["all", "critical", "none"])
        self.notification_level_combo.setCurrentText(self.config.get("detector.notification_level", "all"))
        
        detector_layout.addRow("Start detection on launch:", self.start_on_launch_check)
        detector_layout.addRow("Notification level:", self.notification_level_combo)
        
        # Add tabs to widget
        tab_widget.addTab(general_tab, "General")
        tab_widget.addTab(scanner_tab, "Scanner")
        tab_widget.addTab(spoofer_tab, "Spoofer")
        tab_widget.addTab(detector_tab, "Detector")
        
        # Add buttons
        button_layout = QHBoxLayout()
        save_button = QPushButton("Save")
        cancel_button = QPushButton("Cancel")
        reset_button = QPushButton("Reset to Defaults")
        
        save_button.clicked.connect(self.save_settings)
        cancel_button.clicked.connect(self.reject)
        reset_button.clicked.connect(self.reset_to_defaults)
        
        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)
        button_layout.addWidget(reset_button)
        
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.addWidget(tab_widget)
        main_layout.addLayout(button_layout)
    
    def save_settings(self):
        """Save the current settings to the configuration."""
        # General settings
        self.config.set("theme", self.theme_combo.currentText())
        self.config.set("minimize_to_tray", self.minimize_to_tray_check.isChecked())
        self.config.set("show_tooltips", self.show_tooltips_check.isChecked())
        
        # Scanner settings
        self.config.set("scanner.timeout", self.timeout_spin.value())
        self.config.set("scanner.auto_scan_on_start", self.auto_scan_check.isChecked())
        self.config.set("scanner.save_results", self.save_results_check.isChecked())
        
        # Spoofer settings
        self.config.set("spoofer.packet_interval", self.packet_interval_spin.value())
        self.config.set("spoofer.restore_on_exit", self.restore_on_exit_check.isChecked())
        
        # Detector settings
        self.config.set("detector.start_on_launch", self.start_on_launch_check.isChecked())
        self.config.set("detector.notification_level", self.notification_level_combo.currentText())
        
        # Save to file
        self.config.save()
        
        self.accept()
    
    def reset_to_defaults(self):
        """Reset all settings to default values."""
        reply = QMessageBox.question(
            self,
            "Reset Settings",
            "Are you sure you want to reset all settings to their default values?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.config.reset_to_defaults()
            self.accept() 