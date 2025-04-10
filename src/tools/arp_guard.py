#!/usr/bin/env python3
"""
ARP Guard - ARP Spoofing Detection Tool
Main script to run the ARP spoofing detection tool
"""

import os
import sys
import time
import signal
import logging
import argparse
import json
from typing import Optional, Dict, Any

# Add parent directory to path to make imports work
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.core.packet_analyzer import PacketAnalyzer, PacketAnalyzerConfig, SCAPY_AVAILABLE
from src.core.arp_detector import ARPSpoofDetector, DetectorConfig, ARPAlert, AlertSeverity

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('arp_guard.log')
    ]
)

logger = logging.getLogger("arp_guard")

# Global variables for signal handling
analyzer = None
detector = None
running = True


def signal_handler(sig, frame):
    """Handle interrupt signals"""
    global running
    logger.info("Received termination signal, shutting down...")
    running = False


def alert_callback(alert: ARPAlert) -> None:
    """Callback function for handling alerts"""
    # Print alert to console in color based on severity
    severity_colors = {
        AlertSeverity.INFO: "\033[94m",      # Blue
        AlertSeverity.LOW: "\033[96m",       # Cyan
        AlertSeverity.MEDIUM: "\033[93m",    # Yellow
        AlertSeverity.HIGH: "\033[91m",      # Red
        AlertSeverity.CRITICAL: "\033[1;91m" # Bold Red
    }
    
    reset_color = "\033[0m"
    color = severity_colors.get(alert.severity, "")
    
    print(f"{color}[{alert.severity.value.upper()}] {alert.description}{reset_color}")


def save_config(config_data: Dict[str, Any], filename: str) -> bool:
    """Save configuration to file"""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
        with open(filename, 'w') as f:
            json.dump(config_data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving configuration: {e}")
        return False


def create_default_configs(data_dir: str) -> Dict[str, str]:
    """Create default configuration files if they don't exist"""
    created_files = {}
    
    # Create data directory if it doesn't exist
    os.makedirs(data_dir, exist_ok=True)
    
    # Create trusted hosts file
    trusted_hosts_file = os.path.join(data_dir, "trusted_hosts.json")
    if not os.path.exists(trusted_hosts_file):
        trusted_hosts = {}
        save_config(trusted_hosts, trusted_hosts_file)
        created_files["trusted_hosts"] = trusted_hosts_file
    
    # Create gateways file
    gateways_file = os.path.join(data_dir, "gateways.json")
    if not os.path.exists(gateways_file):
        gateways = {}
        save_config(gateways, gateways_file)
        created_files["gateways"] = gateways_file
    
    # Create MAC vendors file
    mac_vendors_file = os.path.join(data_dir, "mac_vendors.json")
    if not os.path.exists(mac_vendors_file):
        mac_vendors = {}
        save_config(mac_vendors, mac_vendors_file)
        created_files["mac_vendors"] = mac_vendors_file
    
    # Create subnets file
    subnets_file = os.path.join(data_dir, "known_subnets.json")
    if not os.path.exists(subnets_file):
        subnets = {}
        save_config(subnets, subnets_file)
        created_files["subnets"] = subnets_file
    
    return created_files


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="ARP Guard - ARP Spoofing Detection Tool")
    
    parser.add_argument("-i", "--interface", dest="interface", 
                      help="Network interface to listen on")
    
    parser.add_argument("-d", "--data-dir", dest="data_dir", default="data",
                      help="Directory for data files (default: data)")
    
    parser.add_argument("-t", "--timeout", dest="timeout", type=int, default=0,
                      help="Run for specified seconds then exit (default: run indefinitely)")
    
    parser.add_argument("-o", "--output", dest="output",
                      help="File to save alerts to")
    
    parser.add_argument("-r", "--packet-rate", dest="packet_rate", type=int, default=20,
                      help="Packet rate threshold for alerts (default: 20 packets/sec)")
    
    parser.add_argument("-a", "--add-gateway", dest="add_gateway", action="store_true",
                      help="Add the default gateway to trusted gateways")
    
    parser.add_argument("-l", "--list-interfaces", dest="list_interfaces", action="store_true",
                      help="List available network interfaces and exit")
    
    return parser.parse_args()


def list_available_interfaces():
    """List available network interfaces"""
    if not SCAPY_AVAILABLE:
        print("Scapy is required to list interfaces")
        return
    
    try:
        from scapy.arch import get_if_list, get_if_addr
        from scapy.config import conf
        
        interfaces = get_if_list()
        
        print("\nAvailable Network Interfaces:")
        print("-" * 60)
        print(f"{'Interface':<20} {'IP Address':<15} {'Default'}")
        print("-" * 60)
        
        for iface in interfaces:
            try:
                ip = get_if_addr(iface)
                is_default = "*" if iface == conf.iface else ""
                print(f"{iface:<20} {ip:<15} {is_default}")
            except Exception:
                pass
        
        print("\n* Default interface")
    except Exception as e:
        print(f"Error listing interfaces: {e}")


def detect_and_add_default_gateway(data_dir: str) -> Optional[str]:
    """Detect and add default gateway to trusted gateways"""
    if not SCAPY_AVAILABLE:
        logger.error("Scapy is required to detect default gateway")
        return None
    
    try:
        import socket
        import struct
        from scapy.all import conf, sr1, IP, ICMP
        
        # Get default gateway
        gw = conf.route.route("0.0.0.0")[2]
        if gw == "0.0.0.0":
            logger.error("Could not determine default gateway")
            return None
        
        # Try to get the MAC address
        from scapy.all import getmacbyip
        gw_mac = getmacbyip(gw)
        
        if gw_mac:
            # Add to gateways file
            gateways_file = os.path.join(data_dir, "gateways.json")
            try:
                if os.path.exists(gateways_file):
                    with open(gateways_file, 'r') as f:
                        gateways = json.load(f)
                else:
                    gateways = {}
                
                gateways[gw] = gw_mac
                
                with open(gateways_file, 'w') as f:
                    json.dump(gateways, f, indent=2)
                
                logger.info(f"Added default gateway {gw} with MAC {gw_mac} to trusted gateways")
                return gw
            except Exception as e:
                logger.error(f"Error updating gateways file: {e}")
                return None
        else:
            logger.error(f"Could not determine MAC address for gateway {gw}")
            return None
    except Exception as e:
        logger.error(f"Error detecting default gateway: {e}")
        return None


def main():
    """Main function"""
    global analyzer, detector, running
    
    args = parse_arguments()
    
    # Just list interfaces and exit if requested
    if args.list_interfaces:
        list_available_interfaces()
        return
    
    # Create default config files if they don't exist
    created_files = create_default_configs(args.data_dir)
    if created_files:
        logger.info(f"Created default configuration files in {args.data_dir}")
        for file_type, path in created_files.items():
            logger.info(f"  - {file_type}: {path}")
    
    # Add default gateway if requested
    if args.add_gateway:
        gateway = detect_and_add_default_gateway(args.data_dir)
        if gateway:
            logger.info(f"Added default gateway: {gateway}")
        else:
            logger.warning("Failed to add default gateway")
    
    # Set up the packet analyzer
    analyzer_config = PacketAnalyzerConfig(
        interface=args.interface,
        mac_vendors_file=os.path.join(args.data_dir, "mac_vendors.json"),
        known_subnets_file=os.path.join(args.data_dir, "known_subnets.json")
    )
    
    # Set up the detector
    detector_config = DetectorConfig(
        trusted_hosts_file=os.path.join(args.data_dir, "trusted_hosts.json"),
        gateway_file=os.path.join(args.data_dir, "gateways.json"),
        packet_rate_threshold=args.packet_rate
    )
    
    # Create and configure the analyzer and detector
    analyzer = PacketAnalyzer(analyzer_config)
    detector = ARPSpoofDetector(analyzer, detector_config)
    
    # Register the alert callback
    detector.register_alert_callback(alert_callback)
    
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start the detector and analyzer
    logger.info("Starting ARP Guard...")
    
    if not analyzer.start_capture():
        logger.error("Failed to start packet capture")
        return 1
    
    if not detector.start_detection():
        logger.error("Failed to start detection")
        analyzer.stop_capture()
        return 1
    
    logger.info("ARP Guard is running. Press Ctrl+C to stop.")
    
    try:
        # Run until timeout or interrupt
        start_time = time.time()
        
        while running:
            if args.timeout and time.time() - start_time > args.timeout:
                logger.info(f"Timeout of {args.timeout} seconds reached")
                break
            
            # Sleep to reduce CPU usage
            time.sleep(0.1)
            
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    
    # Stop services
    detector.stop_detection()
    analyzer.stop_capture()
    
    # Save alerts if output file specified
    if args.output and detector.alerts:
        if detector.export_alerts(args.output):
            logger.info(f"Saved {len(detector.alerts)} alerts to {args.output}")
        else:
            logger.error(f"Failed to save alerts to {args.output}")
    
    # Display summary
    alert_count = len(detector.alerts)
    if alert_count > 0:
        stats = detector.get_stats()
        print("\nDetection Summary:")
        print(f"Total Alerts: {stats['total_alerts']}")
        print(f"Active Alerts: {stats['active_alerts']}")
        
        print("\nAlerts by Severity:")
        for severity, count in stats['alerts_by_severity'].items():
            if count > 0:
                print(f"  - {severity}: {count}")
        
        print("\nTop Alert Sources:")
        for src in stats['top_sources']:
            print(f"  - {src['source']}: {src['count']} alerts")
    else:
        print("\nNo ARP spoofing attempts detected")
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 