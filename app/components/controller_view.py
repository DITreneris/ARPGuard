from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox,
    QSplitter, QTabWidget, QTextEdit, QComboBox, QLineEdit,
    QFormLayout, QMessageBox
)
from PyQt5.QtCore import Qt, QTimer
from datetime import datetime
from typing import Dict, List, Any

from app.components.controller import Controller
from app.components.rbac import RBAC, Role, Permission
from app.components.audit_logger import AuditLogger, AuditEventType
from app.utils.logger import get_logger

# Module logger
logger = get_logger('components.controller_view')

class ControllerView(QWidget):
    """User interface component for managing the controller."""
    
    def __init__(self, parent=None):
        """Initialize the controller view."""
        super().__init__(parent)
        
        # Initialize components
        self.controller = Controller()
        self.rbac = RBAC()
        self.audit_logger = AuditLogger()
        
        # Setup UI
        self.setup_ui()
        
        # Connect signals
        self.controller.site_connected.connect(self.on_site_connected)
        self.controller.site_disconnected.connect(self.on_site_disconnected)
        self.controller.site_status_changed.connect(self.on_site_status_changed)
        self.controller.alert_received.connect(self.on_alert_received)
        
        # Start controller
        self.controller.start()
        
        # Setup refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_sites)
        self.refresh_timer.start(5000)  # Refresh every 5 seconds
    
    def setup_ui(self):
        """Set up the user interface."""
        main_layout = QVBoxLayout(self)
        
        # Top controls
        controls_layout = QHBoxLayout()
        
        self.start_button = QPushButton("Start Controller")
        self.start_button.clicked.connect(self.start_controller)
        
        self.stop_button = QPushButton("Stop Controller")
        self.stop_button.clicked.connect(self.stop_controller)
        self.stop_button.setEnabled(False)
        
        self.status_label = QLabel("Status: Stopped")
        
        controls_layout.addWidget(self.start_button)
        controls_layout.addWidget(self.stop_button)
        controls_layout.addStretch()
        controls_layout.addWidget(self.status_label)
        
        # Main content splitter
        content_splitter = QSplitter(Qt.Vertical)
        
        # Top part - Connected sites
        sites_group = QGroupBox("Connected Sites")
        sites_layout = QVBoxLayout(sites_group)
        
        self.sites_table = QTableWidget(0, 5)
        self.sites_table.setHorizontalHeaderLabels(["Site ID", "Address", "Last Seen", "Status", "Capabilities"])
        self.sites_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.sites_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.sites_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.sites_table.setAlternatingRowColors(True)
        
        sites_layout.addWidget(self.sites_table)
        
        # Bottom part - Alerts and commands
        bottom_tabs = QTabWidget()
        
        # Alerts tab
        alerts_tab = QWidget()
        alerts_layout = QVBoxLayout(alerts_tab)
        
        self.alerts_text = QTextEdit()
        self.alerts_text.setReadOnly(True)
        
        alerts_layout.addWidget(self.alerts_text)
        
        # Commands tab
        commands_tab = QWidget()
        commands_layout = QVBoxLayout(commands_tab)
        
        # Command form
        command_form = QGroupBox("Send Command")
        form_layout = QFormLayout()
        
        self.username_input = QLineEdit()
        form_layout.addRow("Username:", self.username_input)
        
        self.site_id_input = QLineEdit()
        form_layout.addRow("Site ID:", self.site_id_input)
        
        self.command_input = QComboBox()
        self.command_input.addItems([
            "scan_network",
            "start_detection",
            "stop_detection",
            "start_spoofing",
            "stop_spoofing"
        ])
        form_layout.addRow("Command:", self.command_input)
        
        self.send_button = QPushButton("Send Command")
        self.send_button.clicked.connect(self.send_command)
        form_layout.addRow("", self.send_button)
        
        command_form.setLayout(form_layout)
        commands_layout.addWidget(command_form)
        
        # Command history
        self.commands_text = QTextEdit()
        self.commands_text.setReadOnly(True)
        commands_layout.addWidget(self.commands_text)
        
        commands_tab.setLayout(commands_layout)
        bottom_tabs.addTab(commands_tab, "Commands")
        
        # Audit logs tab
        audit_tab = QWidget()
        audit_layout = QVBoxLayout(audit_tab)
        
        # Audit log filters
        filter_group = QGroupBox("Filters")
        filter_layout = QFormLayout()
        
        self.event_type_filter = QComboBox()
        self.event_type_filter.addItem("All")
        for event_type in AuditEventType:
            self.event_type_filter.addItem(event_type.name)
        filter_layout.addRow("Event Type:", self.event_type_filter)
        
        self.username_filter = QLineEdit()
        filter_layout.addRow("Username:", self.username_filter)
        
        self.site_id_filter = QLineEdit()
        filter_layout.addRow("Site ID:", self.site_id_filter)
        
        self.filter_button = QPushButton("Apply Filters")
        self.filter_button.clicked.connect(self.refresh_audit_logs)
        filter_layout.addRow("", self.filter_button)
        
        filter_group.setLayout(filter_layout)
        audit_layout.addWidget(filter_group)
        
        # Audit log display
        self.audit_logs_text = QTextEdit()
        self.audit_logs_text.setReadOnly(True)
        audit_layout.addWidget(self.audit_logs_text)
        
        audit_tab.setLayout(audit_layout)
        bottom_tabs.addTab(audit_tab, "Audit Logs")
        
        # Add to splitter
        content_splitter.addWidget(sites_group)
        content_splitter.addWidget(bottom_tabs)
        content_splitter.setSizes([200, 200])  # Equal initial sizes
        
        # Add to main layout
        main_layout.addLayout(controls_layout)
        main_layout.addWidget(content_splitter, 1)  # Give splitter stretch
    
    def start_controller(self):
        """Start the controller server."""
        try:
            self.controller.start()
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.status_label.setText("Status: Running")
            self.log_message("Controller started")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start controller: {e}")
    
    def stop_controller(self):
        """Stop the controller server."""
        self.controller.stop()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_label.setText("Status: Stopped")
        self.log_message("Controller stopped")
    
    def refresh_sites(self):
        """Refresh the connected sites table."""
        self.sites_table.setRowCount(0)
        
        for site in self.controller.get_connected_sites():
            row = self.sites_table.rowCount()
            self.sites_table.insertRow(row)
            
            self.sites_table.setItem(row, 0, QTableWidgetItem(site['site_id']))
            self.sites_table.setItem(row, 1, QTableWidgetItem(f"{site['address'][0]}:{site['address'][1]}"))
            self.sites_table.setItem(row, 2, QTableWidgetItem(site['last_seen'].strftime("%Y-%m-%d %H:%M:%S")))
            self.sites_table.setItem(row, 3, QTableWidgetItem(site['status']))
            self.sites_table.setItem(row, 4, QTableWidgetItem(str(site['capabilities'])))
    
    def send_command(self):
        """Send a command to a site."""
        username = self.username_input.text()
        site_id = self.site_id_input.text()
        command = self.command_input.currentText()
        
        if not username or not site_id:
            QMessageBox.warning(self, "Error", "Please enter username and site ID")
            return
        
        # Check permissions
        if not self.rbac.has_permission(username, Permission.COMMAND_EXECUTED, site_id):
            QMessageBox.warning(self, "Error", f"User {username} does not have permission to execute commands on site {site_id}")
            return
        
        if self.controller.send_command(username, site_id, command):
            self.log_message(f"Command sent: {command} to {site_id}")
            self.commands_text.append(f"[{datetime.now()}] {username} sent {command} to {site_id}")
        else:
            QMessageBox.warning(self, "Error", f"Failed to send command to {site_id}")
    
    def refresh_audit_logs(self):
        """Refresh the audit logs display."""
        self.audit_logs_text.clear()
        
        # Get filter values
        event_type = self.event_type_filter.currentText()
        username = self.username_filter.text()
        site_id = self.site_id_filter.text()
        
        # Get filtered events
        events = self.audit_logger.get_events(
            event_type=event_type if event_type != "All" else None,
            username=username if username else None,
            site_id=site_id if site_id else None
        )
        
        # Display events
        for event in events:
            self.audit_logs_text.append(
                f"[{event['timestamp']}] {event['event_type']} - "
                f"User: {event['username']}, Site: {event['site_id']}\n"
                f"Details: {event['details']}\n"
            )
    
    def log_message(self, message: str):
        """Log a message to the alerts text area."""
        self.alerts_text.append(f"[{datetime.now()}] {message}")
    
    def on_site_connected(self, site_id: str):
        """Handle site connection event.
        
        Args:
            site_id: ID of the connected site
        """
        self.log_message(f"Site connected: {site_id}")
        self.refresh_sites()
    
    def on_site_disconnected(self, site_id: str):
        """Handle site disconnection event.
        
        Args:
            site_id: ID of the disconnected site
        """
        self.log_message(f"Site disconnected: {site_id}")
        self.refresh_sites()
    
    def on_site_status_changed(self, site_id: str, status: str):
        """Handle site status change event.
        
        Args:
            site_id: ID of the site
            status: New status
        """
        self.log_message(f"Site {site_id} status changed: {status}")
        self.refresh_sites()
    
    def on_alert_received(self, alert_data: Dict[str, Any]):
        """Handle alert received event.
        
        Args:
            alert_data: Alert data
        """
        site_id = alert_data.get('site_id', 'unknown')
        alert_type = alert_data.get('type', 'unknown')
        self.log_message(f"Alert from {site_id}: {alert_type}")
        self.alerts_text.append(f"Details: {alert_data}") 