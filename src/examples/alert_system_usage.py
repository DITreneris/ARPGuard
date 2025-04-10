#!/usr/bin/env python3
import logging
import time
import sys
import os
from pathlib import Path

# Add parent directory to path for imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir.parent))

from core.alert import AlertManager, AlertType, AlertPriority
from core.notification_channels import EmailChannel, SlackChannel, ConsoleChannel
from core.alert_config import AlertConfig
from core.alert_integration import AlertIntegration
from core.alert_handler import AlertHandler
from core.alert_rules import RuleLibrary, CustomRuleBuilder

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('alert_example')

def main():
    """
    Demonstrate the Alert Notification System functionality.
    """
    print("=== ARP Guard Alert Notification System Example ===")
    
    # Step 1: Basic AlertManager usage
    print("\n1. Basic AlertManager Usage")
    basic_alert_demo()
    
    # Step 2: Configuration-based setup
    print("\n2. Configuration-based Setup")
    config_based_demo()
    
    # Step 3: Alert integration with detection sources
    print("\n3. Alert Integration with Detection Sources")
    integration_demo()
    
    # Step 4: Alert handling with rules
    print("\n4. Alert Handling with Rules")
    alert_handler_demo()
    
    print("\nExample completed.")

def basic_alert_demo():
    """Demonstrate basic alert management functionality."""
    # Create an alert manager
    alert_mgr = AlertManager()
    
    # Add a console notification channel for demonstration
    console_channel = ConsoleChannel()
    alert_mgr.add_channel(console_channel)
    
    # Create different types of alerts
    print("Creating alerts of different types and priorities...")
    
    # ARP spoofing alert
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
    
    # Rate anomaly alert
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
    
    # System error alert
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
    
    # Retrieve active alerts
    active_alerts = alert_mgr.get_active_alerts()
    print(f"Number of active alerts: {len(active_alerts)}")
    
    # Acknowledge an alert
    if active_alerts:
        alert_id = active_alerts[0].id
        print(f"Acknowledging alert: {alert_id}")
        alert_mgr.acknowledge_alert(alert_id)
        
        # Verify acknowledgment
        updated_alert = alert_mgr.get_alert(alert_id)
        print(f"Alert status after acknowledgment: {updated_alert.status}")

def config_based_demo():
    """Demonstrate configuration-based alert setup."""
    # Create a temporary config directory
    os.makedirs("config", exist_ok=True)
    
    # Create alert configuration
    config = AlertConfig("config/alert_config.json")
    
    # Update email configuration
    email_config = {
        "enabled": True,
        "smtp_server": "smtp.example.com",
        "smtp_port": 587,
        "username": "alerts@example.com",
        "password": "password123",
        "from_addr": "alerts@example.com",
        "to_addrs": ["admin@example.com", "security@example.com"]
    }
    config.update_channel_config("email", email_config)
    
    # Update Slack configuration
    slack_config = {
        "enabled": True,
        "webhook_url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
        "channel": "#security-alerts"
    }
    config.update_channel_config("slack", slack_config)
    
    # Update rate anomaly thresholds
    rate_config = {
        "packets_per_second": 1500,
        "window_size": 120
    }
    config.update_threshold("rate_anomaly", rate_config)
    
    # Create channels from configuration
    print("Creating notification channels from configuration...")
    channels = config.create_channels()
    print(f"Created {len(channels)} notification channels")
    
    # Update email template
    email_template = """
    SECURITY ALERT: {type}
    Priority: {priority}
    Time: {timestamp}
    
    {message}
    
    Source: {source}
    Alert ID: {id}
    
    Details:
    {details}
    
    Please respond according to security procedures.
    """
    config.update_template("email", {"body": email_template})
    
    # Show current configuration
    print("Configuration settings:")
    print(f"- Rate anomaly threshold: {config.get_threshold('rate_anomaly')['packets_per_second']} packets/sec")
    print(f"- Email enabled: {config.get_channel_config('email')['enabled']}")
    print(f"- Slack enabled: {config.get_channel_config('slack')['enabled']}")
    print(f"- Console enabled: {config.get_channel_config('console')['enabled']}")

def integration_demo():
    """Demonstrate alert integration with detection sources."""
    # Create alert integration
    integration = AlertIntegration()
    
    # Simulate ARP packet detection
    print("Simulating ARP packet analysis...")
    
    # First packet establishes baseline
    integration.analyze_arp(mac="00:11:22:33:44:55", ip="192.168.1.10")
    print("Recorded initial MAC-IP mapping")
    
    # Second packet with same MAC but different IP triggers alert
    print("Simulating ARP spoofing attempt...")
    integration.analyze_arp(mac="00:11:22:33:44:55", ip="192.168.1.1")
    
    # Simulate rate anomaly detection
    print("\nSimulating packet rate analysis...")
    current_time = time.time()
    
    # Add baseline samples
    for i in range(5):
        sample_time = current_time - (10 * (5-i))
        packet_count = 500 * i
        integration.update_rate(sample_time, packet_count)
    
    # Add anomaly sample that will trigger alert
    integration.update_rate(current_time, 10000)
    
    # Simulate pattern matching
    print("\nSimulating pattern matching...")
    
    # Add a pattern to match
    integration.add_pattern(
        pattern_id="sequence_1",
        pattern_type="mac_sequence",
        pattern_data={"sequence": ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"]},
        priority=AlertPriority.MEDIUM
    )
    
    # Check data against pattern
    integration.check_pattern({
        "mac_sequence": ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"],
        "timestamp": time.time()
    })
    
    # Get active alerts
    active_alerts = integration.get_active_alerts()
    print(f"\nActive alerts after simulations: {len(active_alerts)}")
    
    # Acknowledge all alerts
    for alert in active_alerts:
        integration.acknowledge_alert(alert["id"])
    print("All alerts acknowledged")

def alert_handler_demo():
    """Demonstrate alert handling with rules."""
    # Create alert manager
    alert_mgr = AlertManager()
    alert_mgr.add_channel(ConsoleChannel())
    
    # Create alert handler
    handler = AlertHandler(alert_mgr)
    
    # Define command execution function
    def execute_command(cmd):
        print(f"Would execute: {cmd}")
        return True
    
    # Create rules
    print("Setting up alert rules...")
    handler.execute_command = execute_command
    handler.create_default_rules()
    
    # Add custom rule using rule builder
    print("Adding custom rule...")
    builder = CustomRuleBuilder(execute_command)
    custom_rule = builder.create_rule(
        rule_id="custom_gateway_protection",
        description="Enhanced gateway protection",
        alert_types=[AlertType.ARP_SPOOFING],
        min_priority=AlertPriority.MEDIUM,
        conditions={"details.is_gateway": True},
        log_enabled=True,
        block_mac_enabled=True,
        log_path="logs/gateway_alerts.log"
    )
    handler.add_rule(custom_rule)
    
    # Start processing in background
    print("Starting alert processing...")
    handler.start_processing(interval=1)
    
    # Create some test alerts
    print("Creating test alerts...")
    
    # Gateway ARP spoofing alert
    alert_mgr.create_alert(
        alert_type=AlertType.ARP_SPOOFING,
        priority=AlertPriority.HIGH,
        message="Gateway ARP table modified by unauthorized device",
        source="arp_monitor",
        details={
            "mac_address": "00:11:22:33:44:55",
            "original_ip": "192.168.1.10",
            "new_ip": "192.168.1.1",
            "is_gateway": True,
            "timestamp": time.time()
        }
    )
    
    # Critical rate anomaly alert
    alert_mgr.create_alert(
        alert_type=AlertType.RATE_ANOMALY,
        priority=AlertPriority.CRITICAL,
        message="Extreme packet rate detected: 5000 packets/sec",
        source="traffic_monitor",
        details={
            "current_rate": 5000,
            "threshold": 1000,
            "sustained": True,
            "timestamp": time.time()
        }
    )
    
    # Wait for processing
    print("Waiting for alert processing...")
    time.sleep(3)
    
    # Stop processing
    handler.stop_processing()
    print("Alert processing stopped")

if __name__ == "__main__":
    main() 