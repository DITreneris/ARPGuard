#!/usr/bin/env python3
import logging
import time
import sys
import os
from pathlib import Path
import threading
import json

# Add parent directory to path for imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir.parent))

from core.alert import AlertManager, AlertType, AlertPriority
from core.notification_channels import ConsoleChannel
from core.ui_notifier import UINotifier, WebUIConnector, DesktopNotifier

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('alert_ui_example')


# Simulate a simple WebSocket server
class MockWebSocketServer:
    def __init__(self):
        self.clients = []
        self.logger = logging.getLogger('mock_websocket')
        
    def broadcast(self, message):
        """Broadcast message to all clients."""
        self.logger.info(f"Broadcasting to {len(self.clients)} clients: {message}")
        for client in self.clients:
            self.logger.info(f"Sending to client: {client}")


def main():
    """
    Demonstrate the Alert UI Notification System functionality.
    """
    print("=== ARP Guard UI Notification System Example ===")
    
    # Create alert manager
    alert_mgr = AlertManager()
    alert_mgr.add_channel(ConsoleChannel())
    
    # Create UI notifier
    ui_notifier = UINotifier()
    ui_notifier.start()  # Start the notification thread
    
    try:
        # Step 1: Setup UI connectors
        print("\n1. Setting up UI connectors")
        setup_ui_connectors(ui_notifier)
        
        # Step 2: Generate alerts and observe UI notifications
        print("\n2. Generating alerts to trigger UI notifications")
        generate_alerts(alert_mgr, ui_notifier)
        
        # Step 3: Demonstrate client management
        print("\n3. Demonstrating client management")
        manage_clients(ui_notifier)
        
        # Wait a bit to allow all notifications to be processed
        print("\nWaiting for notifications to be processed...")
        time.sleep(2)
        
    finally:
        # Clean up
        ui_notifier.stop()
        print("\nUI notification system stopped")
    

def setup_ui_connectors(ui_notifier):
    """Set up various UI notification connectors."""
    
    # Create a mock WebSocket server
    websocket_server = MockWebSocketServer()
    websocket_server.clients.append("browser_client")
    
    # Set up Web UI connector
    web_connector = WebUIConnector(ui_notifier, websocket_server)
    web_connector.connect()
    print("Web UI connector connected")
    
    # Set up Desktop notifier
    desktop_notifier = DesktopNotifier(ui_notifier)
    desktop_notifier.connect()
    
    if desktop_notifier.notifier_available:
        print(f"Desktop notifier connected for {desktop_notifier.platform}")
    else:
        print("Desktop notifier not available - required libraries not installed")
        print("To enable desktop notifications, install the appropriate package:")
        print("  - Windows: pip install win10toast")
        print("  - macOS: pip install pync")
        print("  - Linux: pip install notify2")
        
    return web_connector, desktop_notifier


def generate_alerts(alert_mgr, ui_notifier):
    """Generate various alerts to demonstrate UI notifications."""
    
    # Register alert manager for UI notifications
    def alert_callback(alert):
        ui_notifier.notify(alert)
    
    alert_mgr.on_alert_created = alert_callback
    
    # Create different types of alerts with various priorities
    print("Creating alerts with different priorities...")
    
    # Low priority alert (desktop notification won't show for this)
    alert_mgr.create_alert(
        alert_type=AlertType.SYSTEM_INFO,
        priority=AlertPriority.LOW,
        message="System scan completed successfully",
        source="system_monitor",
        details={
            "scan_duration": 120,
            "devices_scanned": 25,
            "timestamp": time.time()
        }
    )
    print("Created LOW priority system info alert")
    
    # Medium priority alert
    alert_mgr.create_alert(
        alert_type=AlertType.RATE_ANOMALY,
        priority=AlertPriority.MEDIUM,
        message="Unusual packet rate detected: 1500 packets/sec",
        source="traffic_monitor",
        details={
            "current_rate": 1500,
            "baseline_rate": 500,
            "threshold": 1000,
            "window_size": 60,
            "timestamp": time.time()
        }
    )
    print("Created MEDIUM priority rate anomaly alert")
    
    # High priority alert (should trigger desktop notification)
    alert_mgr.create_alert(
        alert_type=AlertType.ARP_SPOOFING,
        priority=AlertPriority.HIGH,
        message="Potential ARP spoofing detected from device with MAC 00:11:22:33:44:55",
        source="arp_monitor",
        details={
            "mac_address": "00:11:22:33:44:55",
            "original_ip": "192.168.1.10", 
            "new_ip": "192.168.1.1",
            "timestamp": time.time()
        }
    )
    print("Created HIGH priority ARP spoofing alert")
    
    # Critical priority alert (should trigger desktop notification)
    alert_mgr.create_alert(
        alert_type=AlertType.SYSTEM_ERROR,
        priority=AlertPriority.CRITICAL,
        message="Network interface eth0 is down",
        source="system_monitor",
        details={
            "interface": "eth0",
            "error_code": "DEVICE_DOWN",
            "timestamp": time.time()
        }
    )
    print("Created CRITICAL priority system error alert")
    
    time.sleep(1)  # Give time for the notifications to be processed


def manage_clients(ui_notifier):
    """Demonstrate client management features."""
    
    # Get list of connected clients
    clients = ui_notifier.get_client_list()
    print(f"Connected clients: {len(clients)}")
    
    for client in clients:
        print(f"  - Client: {client['name']}, connected for {client['uptime']:.1f} seconds")
    
    # Add a custom client to receive notifications
    def custom_client_callback(notification):
        print(f"\n[CUSTOM CLIENT] Received notification: {notification['alert_type']} - {notification['priority']}")
        print(f"  Message: {notification['message']}")
    
    client_id = ui_notifier.connect_client(custom_client_callback, "custom_monitor")
    print(f"Added custom client with ID: {client_id}")
    
    # Create a test alert to see if our custom client gets it
    test_notification = {
        'type': 'alert',
        'alert_id': 'test_alert_1',
        'alert_type': 'TEST_ALERT',
        'priority': 'HIGH',
        'message': 'This is a test notification for the custom client',
        'source': 'example_script',
        'timestamp': time.time(),
        'status': 'ACTIVE',
        'details': {'test': True}
    }
    
    ui_notifier.notification_queue.put(test_notification)
    print("Sent test notification to custom client")
    
    # Wait a bit for the notification to be processed
    time.sleep(1)
    
    # Disconnect the custom client
    ui_notifier.disconnect_client(client_id)
    print(f"Disconnected custom client: {client_id}")
    
    # Verify it was removed
    updated_clients = ui_notifier.get_client_list()
    print(f"Remaining connected clients: {len(updated_clients)}")


if __name__ == "__main__":
    main() 