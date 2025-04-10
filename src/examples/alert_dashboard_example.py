#!/usr/bin/env python3
import logging
import sys
import os
import time
import threading
from pathlib import Path

# Add parent directory to path for imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir.parent))

from core.alert import AlertManager, AlertType, AlertPriority
from core.notification_channels import ConsoleChannel
from core.ui_notifier import UINotifier
from core.alert_dashboard import AlertDashboard

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('alert_dashboard_example')

def main():
    """
    Run the ARP Guard Alert Dashboard example.
    """
    print("=== Starting ARP Guard Alert Dashboard ===")
    
    # Set up the alert manager
    alert_mgr = AlertManager()
    alert_mgr.add_channel(ConsoleChannel())
    
    # Set up the UI notifier
    ui_notifier = UINotifier()
    ui_notifier.start()
    
    # Set up the alert dashboard
    dashboard = AlertDashboard(alert_mgr, ui_notifier, host="localhost", port=8080)
    
    # Register alert callback to notify UI
    def alert_created_callback(alert):
        ui_notifier.notify(alert)
    
    alert_mgr.on_alert_created = alert_created_callback
    alert_mgr.on_alert_updated = alert_created_callback
    
    # Start a thread to generate sample alerts
    alert_thread = threading.Thread(target=generate_sample_alerts, args=(alert_mgr,))
    alert_thread.daemon = True
    alert_thread.start()
    
    try:
        # Start the dashboard (this will block until the server is stopped)
        print("\nStarting dashboard on http://localhost:8080")
        print("Press Ctrl+C to stop the server")
        dashboard.start()
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
    finally:
        # Clean up
        ui_notifier.stop()
        dashboard.stop()
        print("Dashboard stopped")

def generate_sample_alerts(alert_mgr):
    """Generate sample alerts periodically."""
    # Wait for server to start
    time.sleep(2)
    
    print("Starting to generate sample alerts")
    
    # Generate some initial alerts
    create_sample_alerts(alert_mgr, 5)
    
    # Every 30 seconds, generate more alerts
    while True:
        time.sleep(30)
        print("Generating new sample alerts")
        create_sample_alerts(alert_mgr, 1)

def create_sample_alerts(alert_mgr, count):
    """Create a batch of sample alerts."""
    import random
    
    alert_types = [
        AlertType.ARP_SPOOFING,
        AlertType.RATE_ANOMALY,
        AlertType.PATTERN_MATCH,
        AlertType.SYSTEM_ERROR,
        AlertType.SYSTEM_INFO
    ]
    
    priorities = [
        AlertPriority.LOW,
        AlertPriority.MEDIUM,
        AlertPriority.HIGH,
        AlertPriority.CRITICAL
    ]
    
    sources = [
        "arp_monitor",
        "traffic_monitor",
        "system_monitor",
        "pattern_detector",
        "network_scanner"
    ]
    
    # Generate random alerts
    for i in range(count):
        alert_type = random.choice(alert_types)
        priority = random.choice(priorities)
        source = random.choice(sources)
        
        # Create different alert details based on type
        if alert_type == AlertType.ARP_SPOOFING:
            mac = f"00:1A:{random.randint(10, 99)}:{random.randint(10, 99)}:{random.randint(10, 99)}:{random.randint(10, 99)}"
            old_ip = f"192.168.1.{random.randint(2, 254)}"
            new_ip = f"192.168.1.{random.randint(2, 254)}"
            message = f"Possible ARP spoofing detected: MAC {mac} changed from IP {old_ip} to {new_ip}"
            details = {
                "mac_address": mac,
                "original_ip": old_ip,
                "new_ip": new_ip,
                "is_gateway": random.random() < 0.2,  # 20% chance to be gateway
                "timestamp": time.time(),
                "mac_changes": random.random() < 0.3  # 30% chance to have multiple changes
            }
            
        elif alert_type == AlertType.RATE_ANOMALY:
            baseline_rate = random.randint(100, 500)
            current_rate = baseline_rate * random.randint(2, 10)
            message = f"Unusual packet rate detected: {current_rate} packets/sec"
            details = {
                "current_rate": current_rate,
                "baseline_rate": baseline_rate,
                "threshold": baseline_rate * 2,
                "window_size": 60,
                "sustained": random.random() < 0.5,  # 50% chance to be sustained
                "timestamp": time.time()
            }
            
        elif alert_type == AlertType.PATTERN_MATCH:
            pattern_type = random.choice(["known_attack", "suspicious"])
            pattern_id = f"pattern_{random.randint(1000, 9999)}"
            message = f"Pattern match detected: {pattern_id}"
            details = {
                "pattern_id": pattern_id,
                "pattern_type": pattern_type,
                "matched_data": {
                    "timestamp": time.time(),
                    "confidence": random.random()
                }
            }
            
        elif alert_type == AlertType.SYSTEM_ERROR:
            error_codes = ["DEVICE_DOWN", "CONNECTION_LOST", "MEMORY_LOW", "CPU_OVERLOAD"]
            error_code = random.choice(error_codes)
            interface = f"eth{random.randint(0, 3)}"
            message = f"System error: {error_code} on {interface}"
            details = {
                "interface": interface,
                "error_code": error_code,
                "severity": random.randint(1, 10),
                "timestamp": time.time()
            }
            
        else:  # AlertType.SYSTEM_INFO
            info_types = ["SCAN_COMPLETE", "UPDATE_AVAILABLE", "DEVICE_CONNECTED", "CONFIG_CHANGED"]
            info_type = random.choice(info_types)
            message = f"System info: {info_type}"
            details = {
                "info_type": info_type,
                "devices_scanned": random.randint(10, 50),
                "duration": random.randint(30, 300),
                "timestamp": time.time()
            }
        
        # Create the alert
        alert_mgr.create_alert(
            alert_type=alert_type,
            priority=priority,
            message=message,
            source=source,
            details=details
        )

if __name__ == "__main__":
    main() 