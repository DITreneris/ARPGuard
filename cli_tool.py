#!/usr/bin/env python3
"""
ARPGuard CLI - Command Line Interface for ARPGuard Network Security Tool

This script provides a command-line interface for network scanning, ARP spoofing detection,
and basic network security monitoring without requiring GUI dependencies.
"""

import os
import sys
import time
import argparse
import socket
import subprocess
import platform
from datetime import datetime
from threading import Thread
import logging

try:
    import scapy.all as scapy
except ImportError:
    print("Error: Scapy library not found. Please install it with 'pip install scapy'")
    sys.exit(1)

try:
    import netifaces
except ImportError:
    print("Warning: netifaces library not found. Some functionality may be limited.")
    netifaces = None

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('arpguard-cli')

class NetworkScanner:
    """Network scanner component."""
    
    def __init__(self):
        """Initialize the network scanner."""
        self.devices = []
        self.is_scanning = False
    
    def get_network_range(self):
        """Get the network range to scan."""
        # Try to get the network range automatically
        if netifaces:
            try:
                gateways = netifaces.gateways()
                default_gateway = gateways['default'][netifaces.AF_INET][0]
                default_interface = gateways['default'][netifaces.AF_INET][1]
                
                addresses = netifaces.ifaddresses(default_interface)
                ip_info = addresses[netifaces.AF_INET][0]
                
                ip_address = ip_info['addr']
                netmask = ip_info['netmask']
                
                # Calculate network range
                network = '.'.join(ip_address.split('.')[:3]) + '.0/24'
                logger.info(f"Detected network range: {network}")
                return network
            except Exception as e:
                logger.error(f"Error determining network range: {e}")
        
        # Fall back to common private network ranges
        common_ranges = [
            '192.168.0.0/24',
            '192.168.1.0/24',
            '10.0.0.0/24'
        ]
        
        logger.info(f"Using default network range: {common_ranges[0]}")
        return common_ranges[0]
    
    def scan_network(self, network_range=None, timeout=2):
        """Scan the network for devices.
        
        Args:
            network_range: Network range to scan (e.g., '192.168.1.0/24')
            timeout: Response timeout in seconds
        
        Returns:
            list: List of discovered devices
        """
        if self.is_scanning:
            logger.warning("Scan already in progress")
            return None
        
        self.is_scanning = True
        self.devices = []
        
        if not network_range:
            network_range = self.get_network_range()
        
        logger.info(f"Scanning network: {network_range}")
        
        try:
            # Create ARP request packet
            arp_request = scapy.ARP(pdst=network_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            
            # Send packet and get responses
            start_time = time.time()
            answered_list = scapy.srp(arp_request_broadcast, timeout=timeout, verbose=False)[0]
            
            # Process responses
            for sent, received in answered_list:
                device = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'hostname': self.get_hostname(received.psrc),
                    'vendor': self.get_vendor(received.hwsrc)
                }
                self.devices.append(device)
                logger.info(f"Discovered device: {device['ip']} ({device['mac']})")
            
            scan_time = time.time() - start_time
            logger.info(f"Scan completed in {scan_time:.2f} seconds, {len(self.devices)} devices found")
        except Exception as e:
            logger.error(f"Error during network scan: {e}")
        finally:
            self.is_scanning = False
        
        return self.devices
    
    def get_hostname(self, ip):
        """Get hostname for an IP address."""
        try:
            hostname = socket.getfqdn(ip)
            if hostname != ip:
                return hostname
            return ""
        except Exception:
            return ""
    
    def get_vendor(self, mac):
        """Get vendor for a MAC address."""
        # This is a simplified version - in a real implementation you'd
        # use a MAC vendor database
        return "Unknown"

class ARPSpooferDetector:
    """ARP spoofing detector component."""
    
    def __init__(self):
        """Initialize the ARP spoofing detector."""
        self.arp_table = {}
        self.gateway_mac = None
        self.gateway_ip = None
        self.is_monitoring = False
        self.monitor_thread = None
    
    def get_gateway(self):
        """Get the default gateway IP and MAC address."""
        if netifaces:
            try:
                gateways = netifaces.gateways()
                self.gateway_ip = gateways['default'][netifaces.AF_INET][0]
                
                # Get gateway MAC address
                arp_request = scapy.ARP(pdst=self.gateway_ip)
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast/arp_request
                
                answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
                
                if answered_list:
                    self.gateway_mac = answered_list[0][1].hwsrc
                    logger.info(f"Gateway detected: {self.gateway_ip} ({self.gateway_mac})")
                    return self.gateway_ip, self.gateway_mac
            except Exception as e:
                logger.error(f"Error determining gateway: {e}")
        
        logger.warning("Could not determine gateway automatically")
        return None, None
    
    def monitor_arp(self, duration=-1):
        """Monitor ARP traffic for spoofing attempts.
        
        Args:
            duration: Monitoring duration in seconds (-1 for indefinite)
        """
        if self.is_monitoring:
            logger.warning("Already monitoring ARP traffic")
            return
        
        if not self.gateway_ip or not self.gateway_mac:
            self.get_gateway()
        
        self.is_monitoring = True
        
        def monitor_thread_func():
            logger.info("Started ARP monitoring")
            start_time = time.time()
            
            # Define packet handler
            def process_packet(packet):
                if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:  # ARP reply
                    try:
                        # Extract real MAC from Ethernet frame
                        real_mac = packet[scapy.Ether].src
                        # Extract sender MAC from ARP portion
                        response_mac = packet[scapy.ARP].hwsrc
                        
                        # Check if gateway is being spoofed
                        if packet[scapy.ARP].psrc == self.gateway_ip and response_mac != self.gateway_mac:
                            logger.warning(f"ALERT: Possible ARP spoofing detected! "
                                           f"Gateway IP {self.gateway_ip} linked to "
                                           f"MAC {response_mac} (expected {self.gateway_mac})")
                        
                        # Check for inconsistencies
                        if response_mac != real_mac:
                            logger.warning(f"ALERT: MAC address mismatch in ARP packet! "
                                           f"Ethernet: {real_mac}, ARP: {response_mac}")
                            
                        # Update ARP table
                        ip = packet[scapy.ARP].psrc
                        mac = packet[scapy.ARP].hwsrc
                        
                        if ip in self.arp_table and self.arp_table[ip] != mac:
                            logger.warning(f"ALERT: ARP table change detected for {ip}! "
                                           f"Old: {self.arp_table[ip]}, New: {mac}")
                        
                        self.arp_table[ip] = mac
                    except Exception as e:
                        logger.error(f"Error processing ARP packet: {e}")
            
            # Start packet capture
            try:
                # Check for duration
                while self.is_monitoring and (duration < 0 or time.time() - start_time < duration):
                    scapy.sniff(filter="arp", prn=process_packet, store=0, timeout=2)
                    time.sleep(0.1)  # Small delay to reduce CPU usage
            except Exception as e:
                logger.error(f"Error in ARP monitoring: {e}")
            finally:
                logger.info("Stopped ARP monitoring")
                self.is_monitoring = False
        
        # Start monitoring thread
        self.monitor_thread = Thread(target=monitor_thread_func)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop ARP monitoring."""
        if self.is_monitoring:
            logger.info("Stopping ARP monitoring...")
            self.is_monitoring = False
            if self.monitor_thread:
                self.monitor_thread.join(timeout=3.0)
                
    def print_arp_table(self):
        """Print the current ARP table."""
        print("\nCurrent ARP Table:")
        print("-" * 50)
        print(f"{'IP Address':<15} {'MAC Address':<18}")
        print("-" * 50)
        
        for ip, mac in self.arp_table.items():
            print(f"{ip:<15} {mac:<18}")
        print("-" * 50)

def main():
    """Main function for the ARPGuard CLI tool."""
    parser = argparse.ArgumentParser(description='ARPGuard CLI - Network Security Tool')
    parser.add_argument('--scan', action='store_true', help='Scan the network for devices')
    parser.add_argument('--network', type=str, help='Network range to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('--monitor', action='store_true', help='Monitor for ARP spoofing attacks')
    parser.add_argument('--duration', type=int, default=-1, help='Monitoring duration in seconds (-1 for indefinite)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()
    
    # Setup logging level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Check for administrator/root privileges
    is_admin = False
    if platform.system() == 'Windows':
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            pass
    elif platform.system() in ['Linux', 'Darwin']:  # Linux or macOS
        is_admin = os.geteuid() == 0
    
    if not is_admin:
        logger.warning("Warning: ARPGuard CLI requires administrator/root privileges for full functionality.")
        logger.warning("Some features may not work properly.")
    
    # Print banner
    print("\n" + "=" * 60)
    print(" "*20 + "ARPGuard CLI Tool")
    print("=" * 60)
    print(f"System: {platform.system()} {platform.release()}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")
    
    # Initialize components
    scanner = NetworkScanner()
    detector = ARPSpooferDetector()
    
    # Get gateway information
    gateway_ip, gateway_mac = detector.get_gateway()
    
    # Run requested actions
    if args.scan:
        print("\nScanning Network...\n")
        devices = scanner.scan_network(args.network)
        
        # Print results
        if devices:
            print("\nDiscovered Devices:")
            print("-" * 70)
            print(f"{'IP Address':<15} {'MAC Address':<18} {'Hostname':<30}")
            print("-" * 70)
            
            for device in devices:
                print(f"{device['ip']:<15} {device['mac']:<18} {device['hostname']:<30}")
            
            print("-" * 70)
            print(f"Total devices found: {len(devices)}\n")
        else:
            print("No devices found or scan failed.\n")
    
    if args.monitor:
        print("\nMonitoring for ARP Spoofing Attacks...")
        print("Press Ctrl+C to stop monitoring\n")
        
        try:
            detector.monitor_arp(args.duration)
            
            # Keep the main thread running
            try:
                while detector.is_monitoring:
                    time.sleep(5)
                    if detector.arp_table:
                        detector.print_arp_table()
            except KeyboardInterrupt:
                print("\nStopping ARP monitoring...")
                detector.stop_monitoring()
                print("Monitoring stopped.\n")
        except Exception as e:
            logger.error(f"Error in monitoring: {e}")
    
    # If no action specified, show help
    if not args.scan and not args.monitor:
        parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unhandled error: {e}")
        sys.exit(1) 