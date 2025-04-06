from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QTextEdit, QGroupBox, QFormLayout
)
from PyQt5.QtCore import Qt, QTimer
from datetime import datetime
import json

from app.components.site_client import SiteClient

class SiteClientView(QWidget):
    """User interface component for managing the site client."""
    
    def __init__(self, site_id: str, parent=None):
        """Initialize the site client view.
        
        Args:
            site_id: Unique identifier for this site
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.site_id = site_id
        
        # Initialize client
        self.client = SiteClient(site_id)
        
        # Setup UI
        self.setup_ui()
        
        # Connect signals
        self.client.connected.connect(self.on_connected)
        self.client.disconnected.connect(self.on_disconnected)
        self.client.command_received.connect(self.on_command_received)
        
        # Setup status update timer
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(30000)  # Update every 30 seconds
    
    def setup_ui(self):
        """Set up the user interface."""
        main_layout = QVBoxLayout(self)
        
        # Connection settings
        settings_group = QGroupBox("Connection Settings")
        settings_layout = QFormLayout(settings_group)
        
        self.host_edit = QLineEdit("localhost")
        self.port_edit = QLineEdit("5000")
        
        settings_layout.addRow("Controller Host:", self.host_edit)
        settings_layout.addRow("Controller Port:", self.port_edit)
        
        # Connection controls
        controls_layout = QHBoxLayout()
        
        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.connect_to_controller)
        
        self.disconnect_button = QPushButton("Disconnect")
        self.disconnect_button.clicked.connect(self.disconnect_from_controller)
        self.disconnect_button.setEnabled(False)
        
        self.status_label = QLabel("Status: Disconnected")
        
        controls_layout.addWidget(self.connect_button)
        controls_layout.addWidget(self.disconnect_button)
        controls_layout.addStretch()
        controls_layout.addWidget(self.status_label)
        
        # Messages
        messages_group = QGroupBox("Messages")
        messages_layout = QVBoxLayout(messages_group)
        
        self.messages_text = QTextEdit()
        self.messages_text.setReadOnly(True)
        
        messages_layout.addWidget(self.messages_text)
        
        # Add to main layout
        main_layout.addWidget(settings_group)
        main_layout.addLayout(controls_layout)
        main_layout.addWidget(messages_group, 1)  # Give messages group stretch
    
    def connect_to_controller(self):
        """Connect to the controller."""
        host = self.host_edit.text()
        port = int(self.port_edit.text())
        
        # Update client settings
        self.client.host = host
        self.client.port = port
        
        # Connect
        self.client.connect()
    
    def disconnect_from_controller(self):
        """Disconnect from the controller."""
        self.client.disconnect()
    
    def update_status(self):
        """Update status with the controller."""
        if self.client.running:
            self.client.send_status("active")
    
    def on_connected(self):
        """Handle connection event."""
        self.connect_button.setEnabled(False)
        self.disconnect_button.setEnabled(True)
        self.status_label.setText("Status: Connected")
        self.messages_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] Connected to controller")
    
    def on_disconnected(self):
        """Handle disconnection event."""
        self.connect_button.setEnabled(True)
        self.disconnect_button.setEnabled(False)
        self.status_label.setText("Status: Disconnected")
        self.messages_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] Disconnected from controller")
    
    def on_command_received(self, command: str, data: dict):
        """Handle command received event.
        
        Args:
            command: Command received
            data: Command data
        """
        self.messages_text.append(
            f"[{datetime.now().strftime('%H:%M:%S')}] Command received: {command}\n"
            f"Data: {json.dumps(data, indent=2)}"
        )
        
        # Handle specific commands
        if command == "scan_network":
            # TODO: Implement network scanning
            self.client.send_alert("scan", "Network scan completed", {
                "devices_found": 0  # Placeholder
            })
        
        elif command == "start_detection":
            # TODO: Implement threat detection
            self.client.send_alert("detection", "Threat detection started")
        
        elif command == "stop_detection":
            # TODO: Implement threat detection stop
            self.client.send_alert("detection", "Threat detection stopped") 