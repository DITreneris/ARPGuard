#!/usr/bin/env python3
"""
ARPGuard CLI (Layer 3 Version) - Command Line Interface for ARPGuard Network Security Tool

This version uses Layer 3 sockets to work without WinPcap/Npcap dependencies.
Provides basic network scanning functionality on systems without packet capture drivers.
"""

import os
import sys
import time
import argparse
import socket
import subprocess
import platform
import ipaddress
import json
import csv
from datetime import datetime
from threading import Thread, Event
import logging
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import ssl
import re
from tqdm import tqdm

try:
    import scapy.all as scapy
    # Force Scapy to use L3 sockets
    scapy.conf.use_pcap = False
    scapy.conf.use_dnet = False
    scapy.conf.L2socket = None
    scapy.conf.L3socket = scapy.conf.L3socket
except ImportError:
    print("Error: Scapy library not found. Please install it with 'pip install scapy'")
    sys.exit(1)

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
    """Network scanner component using Layer 3 sockets."""
    
    def __init__(self):
        """Initialize the network scanner."""
        self.devices = []
        self.is_scanning = False
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        self.port_results = {}
        self.service_banners = {}
        self.latency_results = {}
        self.traceroute_results = {}
        self.monitoring = False
        self.monitoring_stop_event = Event()
        self.device_history = {}
        self.current_snapshot = {}
    
    def get_local_ip(self):
        """Get the local IP address."""
        try:
            # Create a socket to determine the local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Doesn't actually connect but gets local routing info
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as e:
            logger.error(f"Error getting local IP: {e}")
            return "127.0.0.1"
    
    def get_network_range(self):
        """Get the network range to scan."""
        try:
            local_ip = self.get_local_ip()
            # Assume a /24 network
            network = '.'.join(local_ip.split('.')[:3]) + '.0/24'
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
    
    def ping_host(self, ip):
        """Ping a host to check if it's up."""
        try:
            # Different ping command based on OS
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', '-w', '500', ip]
            
            # Run ping with subprocess
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1)
            return result.returncode == 0
        except Exception:
            return False
    
    def tcp_scan(self, ip, ports=[80, 443, 22, 445]):
        """Scan common TCP ports to detect if a host is up."""
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return True
            except:
                pass
        return False
    
    def scan_ports(self, ip, ports=None, timeout=1):
        """Scan ports on a specific IP address.
        
        Args:
            ip: IP address to scan
            ports: List of ports to scan (if None, uses common ports)
            timeout: Timeout for connection attempts
            
        Returns:
            dict: Dictionary of open ports and detected services
        """
        if ports is None:
            ports = self.common_ports
            
        # Display number of ports being scanned
        logger.debug(f"Scanning {len(ports)} ports on {ip}")
            
        open_ports = {}
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {
                executor.submit(self._check_port, ip, port, timeout): port 
                for port in ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open, service = future.result()
                    if is_open:
                        open_ports[port] = service
                except Exception as e:
                    logger.debug(f"Error scanning port {port} on {ip}: {e}")
        
        return open_ports
    
    def _check_port(self, ip, port, timeout=1):
        """Check if a port is open and grab banner if possible.
        
        Returns:
            tuple: (is_open, service_info)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                service = self._identify_service(sock, port)
                sock.close()
                return True, service
            sock.close()
            return False, None
        except Exception:
            return False, None
    
    def _identify_service(self, sock, port):
        """Attempt to identify service by grabbing banner."""
        service = {
            'name': self._get_service_name(port),
            'banner': None,
            'version': None,
            'ssl': False
        }
        
        # Try SSL for known secure ports
        if port in [443, 465, 636, 993, 995, 8443]:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                ssl_sock = context.wrap_socket(sock, server_hostname=sock.getpeername()[0])
                cert = ssl_sock.getpeercert(binary_form=True)
                if cert:
                    service['ssl'] = True
                    # Get certificate details if needed
            except:
                # Not an SSL service
                pass
                
        # Try to grab banner
        try:
            # Send appropriate probe based on port
            if port == 80 or port == 8080:
                sock.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 22:
                pass  # SSH sends banner automatically
            elif port == 25 or port == 587:
                pass  # SMTP sends banner automatically
            
            banner = sock.recv(1024)
            if banner:
                banner_str = banner.decode('utf-8', errors='ignore').strip()
                service['banner'] = banner_str
                
                # Extract version information
                version_match = re.search(r'([a-zA-Z]+)[/ ]([0-9.]+)', banner_str)
                if version_match:
                    service['version'] = version_match.group(2)
        except:
            pass
            
        return service
    
    def _get_service_name(self, port):
        """Get common service name for a port."""
        service_map = {
            21: "FTP", 
            22: "SSH", 
            23: "Telnet", 
            25: "SMTP",
            53: "DNS", 
            80: "HTTP", 
            110: "POP3", 
            111: "RPC",
            135: "MSRPC", 
            139: "NetBIOS", 
            143: "IMAP", 
            443: "HTTPS",
            445: "SMB", 
            993: "IMAPS", 
            995: "POP3S", 
            1723: "PPTP",
            3306: "MySQL", 
            3389: "RDP", 
            5900: "VNC", 
            8080: "HTTP-Proxy"
        }
        return service_map.get(port, "Unknown")
    
    def measure_latency(self, ip, count=3):
        """Measure network latency to a host.
        
        Args:
            ip: IP address to measure
            count: Number of ping attempts
            
        Returns:
            dict: Latency statistics (min, max, avg)
        """
        latency = {'min': None, 'max': None, 'avg': None, 'lost': 0}
        
        try:
            # Different ping parameters based on OS
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
            command = ['ping', param, str(count), timeout_param, '2', ip]
            
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = result.stdout
            
            if platform.system().lower() == 'windows':
                # Parse Windows ping output
                match = re.search(r'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms', output)
                if match:
                    latency['min'] = int(match.group(1))
                    latency['max'] = int(match.group(2))
                    latency['avg'] = int(match.group(3))
                
                # Parse packet loss
                loss_match = re.search(r'(\d+)% loss', output)
                if loss_match:
                    latency['lost'] = int(loss_match.group(1))
            else:
                # Parse Linux/Unix ping output
                match = re.search(r'min/avg/max/mdev = (\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)', output)
                if match:
                    latency['min'] = float(match.group(1))
                    latency['avg'] = float(match.group(2))
                    latency['max'] = float(match.group(3))
                    
                # Parse packet loss
                loss_match = re.search(r'(\d+)% packet loss', output)
                if loss_match:
                    latency['lost'] = int(loss_match.group(1))
        except Exception as e:
            logger.debug(f"Error measuring latency to {ip}: {e}")
            
        return latency
    
    def trace_route(self, ip):
        """Perform traceroute to a host.
        
        Args:
            ip: Target IP address
            
        Returns:
            list: Traceroute hops
        """
        hops = []
        
        try:
            if platform.system().lower() == 'windows':
                command = ['tracert', '-d', '-w', '500', ip]
            else:
                command = ['traceroute', '-n', '-w', '1', ip]
                
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
            output = result.stdout
            
            # Parse traceroute output
            lines = output.splitlines()
            hop_pattern = r'\s*(\d+)\s+(\d+|[*]+)\s+ms\s+(\d+|[*]+)\s+ms\s+(\d+|[*]+)\s+ms\s+([0-9.]+)'
            
            for line in lines:
                match = re.search(hop_pattern, line)
                if match:
                    hop_num = int(match.group(1))
                    hop_ip = match.group(5)
                    
                    # Calculate average time
                    times = []
                    for i in range(2, 5):
                        if match.group(i) != '*':
                            times.append(int(match.group(i)))
                    
                    avg_time = sum(times) / len(times) if times else None
                    
                    hops.append({
                        'hop': hop_num,
                        'ip': hop_ip,
                        'avg_time': avg_time
                    })
        except Exception as e:
            logger.debug(f"Error tracing route to {ip}: {e}")
            
        return hops
    
    def scan_network(self, network_range=None, timeout=2, scan_type='basic', max_ports=100, custom_ports=None):
        """Scan the network for devices using L3 techniques.
        
        Args:
            network_range: Network range to scan (e.g., '192.168.1.0/24')
            timeout: Response timeout in seconds
            scan_type: Type of scan (basic, ports, full)
            max_ports: Maximum number of ports to scan in full mode
            custom_ports: List of specific ports to scan (overrides scan_type port selection)
            
        Returns:
            list: List of discovered devices
        """
        if self.is_scanning:
            logger.warning("Scan already in progress")
            return None
        
        self.is_scanning = True
        self.devices = []
        self.port_results = {}
        self.service_banners = {}
        self.latency_results = {}
        self.traceroute_results = {}
        
        if not network_range:
            network_range = self.get_network_range()
        
        logger.info(f"Scanning network: {network_range}")
        
        try:
            # Get all IPs in the network range
            network = ipaddress.ip_network(network_range)
            total_hosts = network.num_addresses - 2  # Subtract network and broadcast addresses
            
            # For small networks, use a more intensive scan
            if total_hosts <= 256:
                targets = list(network.hosts())
            else:
                # For larger networks, sample a reasonable number of hosts
                targets = list(network.hosts())[:256]
            
            # Start timing
            start_time = time.time()
            
            # First try ICMP (ping)
            logger.info("Starting ICMP scan...")
            
            # Use tqdm for progress bar
            with tqdm(total=len(targets), desc="ICMP Scan", unit="host") as pbar:
                for ip in targets:
                    ip_str = str(ip)
                    
                    if self.ping_host(ip_str):
                        device = {
                            'ip': ip_str,
                            'mac': 'Unknown (L3 scan)',
                            'hostname': self.get_hostname(ip_str),
                            'vendor': 'Unknown',
                            'method': 'ICMP'
                        }
                        self.devices.append(device)
                        logger.info(f"Discovered device via ICMP: {device['ip']}")
                    
                    pbar.update(1)
            
            # Then try TCP for remaining hosts
            logger.info("Starting TCP port scan for remaining hosts...")
            
            remaining_targets = [str(ip) for ip in targets if not any(d['ip'] == str(ip) for d in self.devices)]
            
            with tqdm(total=len(remaining_targets), desc="TCP Scan", unit="host") as pbar:
                for ip_str in remaining_targets:
                    if self.tcp_scan(ip_str):
                        device = {
                            'ip': ip_str,
                            'mac': 'Unknown (L3 scan)',
                            'hostname': self.get_hostname(ip_str),
                            'vendor': 'Unknown',
                            'method': 'TCP'
                        }
                        self.devices.append(device)
                        logger.info(f"Discovered device via TCP: {device['ip']}")
                    
                    pbar.update(1)
            
            # Additional scans based on scan_type
            if scan_type in ['ports', 'full'] and self.devices:
                logger.info("Starting port scan on discovered devices...")
                
                # Determine which ports to scan
                if custom_ports:
                    scan_ports = custom_ports
                    logger.info(f"Using custom port list: {len(scan_ports)} ports")
                elif scan_type == 'full':
                    scan_ports = list(range(1, max_ports + 1))
                    logger.info(f"Performing full port scan (1-{max_ports})")
                else:
                    scan_ports = self.common_ports
                    logger.info(f"Scanning common ports: {self.common_ports}")
                
                with tqdm(total=len(self.devices), desc="Port Scanning", unit="host") as pbar:
                    for device in self.devices:
                        ip = device['ip']
                        self.port_results[ip] = self.scan_ports(ip, scan_ports)
                        pbar.update(1)
            
            # Latency measurements for discovered devices
            logger.info("Measuring network latency...")
            with tqdm(total=len(self.devices), desc="Latency Check", unit="host") as pbar:
                for device in self.devices:
                    ip = device['ip']
                    self.latency_results[ip] = self.measure_latency(ip)
                    pbar.update(1)
            
            # Traceroute for selected devices (limit to avoid long scans)
            if scan_type == 'full' and self.devices:
                logger.info("Performing traceroute on selected devices...")
                sample_size = min(5, len(self.devices))
                sample_devices = self.devices[:sample_size]
                
                with tqdm(total=sample_size, desc="Traceroute", unit="host") as pbar:
                    for device in sample_devices:
                        ip = device['ip']
                        self.traceroute_results[ip] = self.trace_route(ip)
                        pbar.update(1)
            
            scan_time = time.time() - start_time
            logger.info(f"Scan completed in {scan_time:.2f} seconds, {len(self.devices)} devices found")
        except Exception as e:
            logger.error(f"Error during network scan: {e}")
        finally:
            self.is_scanning = False
        
        return self.devices
    
    def export_results(self, format='json', filename=None):
        """Export scan results to a file.
        
        Args:
            format: Output format (json, csv)
            filename: Output filename (default: scan_results.<format>)
        
        Returns:
            str: Path to exported file
        """
        if not self.devices:
            logger.warning("No scan results to export")
            return None
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if not filename:
            filename = f"scan_results_{timestamp}.{format}"
        
        try:
            if format.lower() == 'json':
                data = {
                    'scan_time': timestamp,
                    'devices': self.devices,
                    'ports': self.port_results,
                    'latency': self.latency_results,
                    'traceroute': self.traceroute_results
                }
                
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
                
                logger.info(f"Results exported to {filename}")
                return filename
                
            elif format.lower() == 'csv':
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    
                    # Write header
                    writer.writerow(['IP', 'Hostname', 'Detection Method', 'Open Ports', 'Avg Latency (ms)'])
                    
                    # Write data
                    for device in self.devices:
                        ip = device['ip']
                        ports_str = ', '.join([f"{p} ({s['name']})" for p, s in self.port_results.get(ip, {}).items()])
                        latency = self.latency_results.get(ip, {}).get('avg', 'N/A')
                        
                        writer.writerow([
                            ip,
                            device.get('hostname', ''),
                            device.get('method', ''),
                            ports_str,
                            latency
                        ])
                
                logger.info(f"Results exported to {filename}")
                return filename
            else:
                logger.error(f"Unsupported export format: {format}")
                return None
        except Exception as e:
            logger.error(f"Error exporting results: {e}")
            return None
    
    def get_hostname(self, ip):
        """Get hostname for an IP address."""
        try:
            hostname = socket.getfqdn(ip)
            if hostname != ip:
                return hostname
            return ""
        except Exception:
            return ""
    
    def get_device_key(self, device):
        """Generate a unique key for a device."""
        return f"{device['ip']}_{device.get('hostname', '')}"
    
    def monitor_network(self, network_range=None, interval=60, callback=None):
        """
        Continuously monitor the network for changes.
        
        Args:
            network_range: Network range to scan
            interval: Time between scans in seconds
            callback: Function to call when changes are detected
                      with signature callback(new_devices, changed_devices, missing_devices)
        """
        if self.monitoring:
            logger.warning("Network monitoring already running")
            return False
        
        self.monitoring = True
        self.monitoring_stop_event.clear()
        
        # Initial scan to establish baseline
        logger.info(f"Starting continuous network monitoring (scan interval: {interval}s)")
        baseline_devices = self.scan_network(network_range)
        
        if not baseline_devices:
            logger.warning("Initial scan found no devices. Monitoring may not be effective.")
        else:
            logger.info(f"Established baseline with {len(baseline_devices)} devices")
            
        # Store initial state
        self.device_history = {}
        for device in baseline_devices:
            key = self.get_device_key(device)
            self.device_history[key] = {
                'first_seen': datetime.now(),
                'last_seen': datetime.now(),
                'device': device.copy(),
                'history': [device.copy()],
                'status': 'stable'
            }
        
        # Update current snapshot
        self.current_snapshot = {self.get_device_key(d): d.copy() for d in baseline_devices}
        
        # Start monitoring thread
        monitor_thread = Thread(target=self._monitor_loop, 
                               args=(network_range, interval, callback))
        monitor_thread.daemon = True
        monitor_thread.start()
        
        return True
    
    def _monitor_loop(self, network_range, interval, callback):
        """Internal loop for network monitoring."""
        scan_count = 1
        
        while not self.monitoring_stop_event.is_set():
            try:
                # Wait for the specified interval
                if self.monitoring_stop_event.wait(interval):
                    break
                
                # Perform a new scan
                scan_count += 1
                logger.info(f"Performing monitoring scan #{scan_count}")
                
                current_devices = self.scan_network(network_range)
                
                if not current_devices:
                    logger.warning("No devices found in monitoring scan")
                    continue
                
                # Create a new snapshot
                new_snapshot = {self.get_device_key(d): d.copy() for d in current_devices}
                
                # Compare with previous snapshot
                new_devices = []
                changed_devices = []
                missing_devices = []
                
                # Check for new or changed devices
                for key, device in new_snapshot.items():
                    if key not in self.current_snapshot:
                        # New device
                        new_devices.append(device)
                        # Add to history
                        self.device_history[key] = {
                            'first_seen': datetime.now(),
                            'last_seen': datetime.now(),
                            'device': device.copy(),
                            'history': [device.copy()],
                            'status': 'new'
                        }
                    else:
                        # Update last seen time
                        self.device_history[key]['last_seen'] = datetime.now()
                        # Check if any attribute changed
                        if self._device_changed(self.current_snapshot[key], device):
                            changed_devices.append((self.current_snapshot[key], device))
                            self.device_history[key]['history'].append(device.copy())
                            self.device_history[key]['status'] = 'changed'
                            self.device_history[key]['device'] = device.copy()
                        else:
                            self.device_history[key]['status'] = 'stable'
                
                # Check for missing devices
                for key, device in self.current_snapshot.items():
                    if key not in new_snapshot:
                        missing_devices.append(device)
                        if key in self.device_history:
                            self.device_history[key]['status'] = 'missing'
                
                # Update current snapshot
                self.current_snapshot = new_snapshot
                
                # Log and notify changes
                if new_devices:
                    logger.info(f"Found {len(new_devices)} new device(s)")
                    for device in new_devices:
                        logger.info(f"New device: {device['ip']} - {device.get('hostname', 'Unknown')}")
                
                if changed_devices:
                    logger.info(f"Found {len(changed_devices)} changed device(s)")
                    for old, new in changed_devices:
                        logger.info(f"Changed device: {new['ip']} - {new.get('hostname', 'Unknown')}")
                
                if missing_devices:
                    logger.info(f"Found {len(missing_devices)} missing device(s)")
                    for device in missing_devices:
                        logger.info(f"Missing device: {device['ip']} - {device.get('hostname', 'Unknown')}")
                
                # Call callback if provided
                if callback and (new_devices or changed_devices or missing_devices):
                    callback(new_devices, changed_devices, missing_devices)
                    
            except Exception as e:
                logger.error(f"Error during network monitoring: {e}")
                time.sleep(5)  # Wait before retrying
        
        logger.info("Network monitoring stopped")
        self.monitoring = False
    
    def _device_changed(self, old_device, new_device):
        """Check if a device has changed attributes."""
        # Only check specific attributes for changes
        attributes_to_check = ['hostname', 'method']
        
        for attr in attributes_to_check:
            if old_device.get(attr) != new_device.get(attr):
                return True
                
        # If we have port results, check for changes in open ports
        if self.port_results:
            old_ip = old_device['ip']
            new_ip = new_device['ip']
            
            old_ports = set(self.port_results.get(old_ip, {}).keys())
            new_ports = set(self.port_results.get(new_ip, {}).keys())
            
            if old_ports != new_ports:
                return True
        
        return False
    
    def stop_monitoring(self):
        """Stop network monitoring."""
        if not self.monitoring:
            logger.warning("Network monitoring not running")
            return False
            
        logger.info("Stopping network monitoring")
        self.monitoring_stop_event.set()
        return True
    
    def get_device_history(self):
        """Get history of monitored devices."""
        return self.device_history
    
    def export_monitoring_results(self, format='json', filename=None):
        """Export monitoring results to a file."""
        if not self.device_history:
            logger.warning("No monitoring results to export")
            return None
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if not filename:
            filename = f"monitoring_results_{timestamp}.{format}"
        
        try:
            if format.lower() == 'json':
                # Convert datetime objects to strings for JSON serialization
                export_data = {}
                for key, data in self.device_history.items():
                    export_data[key] = {
                        'first_seen': data['first_seen'].strftime("%Y-%m-%d %H:%M:%S"),
                        'last_seen': data['last_seen'].strftime("%Y-%m-%d %H:%M:%S"),
                        'device': data['device'],
                        'history': data['history'],
                        'status': data['status']
                    }
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                logger.info(f"Monitoring results exported to {filename}")
                return filename
                
            elif format.lower() == 'csv':
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    
                    # Write header
                    writer.writerow(['IP', 'Hostname', 'Status', 'First Seen', 'Last Seen'])
                    
                    # Write data
                    for key, data in self.device_history.items():
                        writer.writerow([
                            data['device']['ip'],
                            data['device'].get('hostname', ''),
                            data['status'],
                            data['first_seen'].strftime("%Y-%m-%d %H:%M:%S"),
                            data['last_seen'].strftime("%Y-%m-%d %H:%M:%S")
                        ])
                
                logger.info(f"Monitoring results exported to {filename}")
                return filename
                
            else:
                logger.error(f"Unsupported export format: {format}")
                return None
                
        except Exception as e:
            logger.error(f"Error exporting monitoring results: {e}")
            return None

def monitor_callback(new_devices, changed_devices, missing_devices):
    """Callback function for network monitoring."""
    if new_devices:
        print("\n" + "=" * 60)
        print(f"🆕 {len(new_devices)} NEW DEVICE(S) DETECTED!")
        print("-" * 60)
        for device in new_devices:
            print(f"IP: {device['ip']} | Hostname: {device.get('hostname', 'Unknown')}")
    
    if changed_devices:
        print("\n" + "=" * 60)
        print(f"📝 {len(changed_devices)} DEVICE(S) CHANGED!")
        print("-" * 60)
        for old, new in changed_devices:
            print(f"IP: {new['ip']} | Hostname: {new.get('hostname', 'Unknown')}")
    
    if missing_devices:
        print("\n" + "=" * 60)
        print(f"⚠️ {len(missing_devices)} DEVICE(S) DISAPPEARED!")
        print("-" * 60)
        for device in missing_devices:
            print(f"IP: {device['ip']} | Hostname: {device.get('hostname', 'Unknown')}")

def main():
    """Main function for the ARPGuard CLI (L3) tool."""
    parser = argparse.ArgumentParser(description='ARPGuard CLI (Layer 3) - Network Security Tool')
    parser.add_argument('--scan', action='store_true', help='Scan the network for devices')
    parser.add_argument('--monitor', action='store_true', help='Continuously monitor the network for changes')
    parser.add_argument('--monitor-interval', type=int, default=60, 
                      help='Monitoring interval in seconds (default: 60)')
    parser.add_argument('--network', type=str, help='Network range to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('--scan-type', choices=['basic', 'ports', 'full'], default='basic',
                        help='Scan type: basic (discovery only), ports (common ports), full (extensive)')
    parser.add_argument('--max-ports', type=int, default=100, help='Maximum number of ports to scan in full mode')
    parser.add_argument('--ports', type=str, help='Custom port specification (e.g., "22,80,443" or "20-25,80,443-445")')
    parser.add_argument('--export', choices=['json', 'csv'], help='Export results in specified format')
    parser.add_argument('--output', type=str, help='Output filename for exported results')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()
    
    # Setup logging level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Print banner
    print("\n" + "=" * 60)
    print(" "*15 + "ARPGuard CLI Tool (Layer 3)")
    print("=" * 60)
    print(f"System: {platform.system()} {platform.release()}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("This version uses Layer 3 sockets and works without WinPcap/Npcap")
    print("=" * 60 + "\n")
    
    # Initialize components
    scanner = NetworkScanner()
    
    # Run requested actions
    if args.scan:
        print(f"\nScanning Network (Layer 3 mode - {args.scan_type})...\n")
        print("This may take longer than L2 scanning and won't provide MAC addresses\n")
        
        # Parse custom port specification if provided
        custom_ports = None
        if args.ports:
            try:
                custom_ports = parse_port_specification(args.ports)
                print(f"Using custom port specification: {len(custom_ports)} ports selected")
                logger.info(f"Custom ports: {custom_ports}")
            except ValueError as e:
                logger.error(f"Invalid port specification: {e}")
                print(f"Error: {e}")
                sys.exit(1)
        
        devices = scanner.scan_network(
            args.network, 
            scan_type=args.scan_type,
            max_ports=args.max_ports,
            custom_ports=custom_ports
        )
        
        # Print results
        if devices:
            print("\nDiscovered Devices:")
            print("-" * 70)
            print(f"{'IP Address':<15} {'Detection Method':<15} {'Hostname':<30}")
            print("-" * 70)
            
            for device in devices:
                print(f"{device['ip']:<15} {device['method']:<15} {device['hostname']:<30}")
            
            print("-" * 70)
            print(f"Total devices found: {len(devices)}\n")
            
            # Print port scan results if available
            if scanner.port_results:
                print("\nOpen Ports:")
                print("-" * 100)
                print(f"{'IP Address':<15} {'Port':<7} {'Service':<15} {'Version':<15} {'SSL':<5} {'Banner':<40}")
                print("-" * 100)
                
                for ip, ports in scanner.port_results.items():
                    if not ports:
                        print(f"{ip:<15} No open ports detected")
                        continue
                        
                    for port, service in ports.items():
                        banner = service.get('banner', '')
                        if banner and len(banner) > 40:
                            banner = banner[:37] + '...'
                            
                        ssl_status = "Yes" if service.get('ssl', False) else "No"
                        
                        print(f"{ip:<15} {port:<7} {service.get('name', 'Unknown'):<15} "
                              f"{service.get('version', 'Unknown'):<15} {ssl_status:<5} {banner:<40}")
                
                print("-" * 100)
            
            # Print latency results if available
            if scanner.latency_results:
                print("\nNetwork Latency:")
                print("-" * 70)
                print(f"{'IP Address':<15} {'Min (ms)':<10} {'Avg (ms)':<10} {'Max (ms)':<10} {'Packet Loss':<12}")
                print("-" * 70)
                
                for ip, latency in scanner.latency_results.items():
                    min_val = latency.get('min', 'N/A')
                    avg_val = latency.get('avg', 'N/A')
                    max_val = latency.get('max', 'N/A')
                    loss = f"{latency.get('lost', 'N/A')}%"
                    
                    # Ensure all values are strings to avoid formatting issues with None
                    min_str = str(min_val) if min_val is not None else 'N/A'
                    avg_str = str(avg_val) if avg_val is not None else 'N/A'
                    max_str = str(max_val) if max_val is not None else 'N/A'
                    
                    print(f"{ip:<15} {min_str:<10} {avg_str:<10} {max_str:<10} {loss:<12}")
                
                print("-" * 70)
            
            # Print traceroute results if available
            if scanner.traceroute_results:
                print("\nTraceroute Results:")
                print("-" * 70)
                
                for ip, hops in scanner.traceroute_results.items():
                    print(f"\nRoute to {ip}:")
                    print(f"{'Hop':<5} {'IP Address':<15} {'Avg Time (ms)':<15}")
                    print("-" * 40)
                    
                    for hop in hops:
                        time_val = hop.get('avg_time', 'N/A')
                        if time_val is not None:
                            time_str = f"{time_val:.1f}"
                        else:
                            time_str = "*"
                            
                        print(f"{hop.get('hop', 'N/A'):<5} {hop.get('ip', 'N/A'):<15} {time_str:<15}")
                
                print("-" * 70)
            
            # Export results if requested
            if args.export:
                scanner.export_results(format=args.export, filename=args.output)
        else:
            print("No devices found or scan failed.\n")
    
    # Monitor network continuously
    elif args.monitor:
        print(f"\nStarting continuous network monitoring (interval: {args.monitor_interval}s)...")
        print("Press Ctrl+C to stop monitoring\n")
        
        # Start monitoring in the background
        scanner.monitor_network(
            network_range=args.network,
            interval=args.monitor_interval,
            callback=monitor_callback
        )
        
        try:
            # Keep the program running until user interrupts
            last_update = datetime.now()
            while True:
                # Calculate time until next scan
                now = datetime.now()
                elapsed = (now - last_update).total_seconds()
                remaining = max(0, args.monitor_interval - elapsed)
                
                # Update status message
                sys.stdout.write(f"\rNext scan in {int(remaining)} seconds... ")
                sys.stdout.flush()
                
                # Wait a second
                time.sleep(1)
                
                # Check if a scan happened
                if elapsed >= args.monitor_interval:
                    last_update = now
        except KeyboardInterrupt:
            print("\n\nStopping monitoring...")
            scanner.stop_monitoring()
            
            # Export results if requested
            if args.export:
                print("\nExporting monitoring results...")
                scanner.export_monitoring_results(format=args.export, filename=args.output)
        
    # If no action specified, show help
    if not args.scan and not args.monitor:
        parser.print_help()

def parse_port_specification(port_spec):
    """
    Parse a port specification string into a list of port numbers.
    
    Formats supported:
    - Individual ports: "22,80,443"
    - Port ranges: "20-25"
    - Combination: "20-25,80,443-445"
    
    Args:
        port_spec: String containing port specification
        
    Returns:
        list: List of port numbers
    
    Raises:
        ValueError: If the port specification is invalid
    """
    if not port_spec:
        return None
        
    ports = []
    segments = port_spec.split(',')
    
    for segment in segments:
        segment = segment.strip()
        if '-' in segment:
            # Port range
            try:
                start, end = segment.split('-')
                start_port = int(start.strip())
                end_port = int(end.strip())
                
                if start_port < 1 or start_port > 65535:
                    raise ValueError(f"Invalid port number: {start_port} (must be 1-65535)")
                if end_port < 1 or end_port > 65535:
                    raise ValueError(f"Invalid port number: {end_port} (must be 1-65535)")
                if start_port > end_port:
                    raise ValueError(f"Invalid port range: {segment} (start must be less than end)")
                    
                # Add the range (inclusive)
                ports.extend(range(start_port, end_port + 1))
            except ValueError as e:
                if "Invalid port" in str(e):
                    raise e
                raise ValueError(f"Invalid port range format: {segment}")
        else:
            # Single port
            try:
                port = int(segment)
                if port < 1 or port > 65535:
                    raise ValueError(f"Invalid port number: {port} (must be 1-65535)")
                ports.append(port)
            except ValueError:
                raise ValueError(f"Invalid port number: {segment}")
    
    # Remove duplicates and sort
    return sorted(list(set(ports)))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unhandled error: {e}")
        sys.exit(1) 