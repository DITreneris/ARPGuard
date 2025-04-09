import threading
import time
import subprocess
import re
import platform
import ipaddress
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable, Tuple

from app.utils.logger import get_logger
from app.utils.config import get_config
from app.components.network_scanner import NetworkScanner

# Module logger
logger = get_logger('components.arp_cache_monitor')

class ARPCacheMonitor:
    """Monitor the ARP cache for anomalies and potential ARP spoofing attacks."""
    
    def __init__(self):
        """Initialize the ARP cache monitor."""
        self.config = get_config()
        self.network_scanner = NetworkScanner()
        self.monitoring = False
        self.monitor_thread = None
        self.alerts = []
        self.cache_history = {}  # History of ARP cache entries
        self.known_devices = {}  # Known legitimate IP-MAC mappings
        self.gateway_ip, self.gateway_interface = self.network_scanner.get_default_gateway()
        self.alert_callback = None
        self.max_alerts = self.config.get("monitor.max_alerts", 100)
        self.check_interval = self.config.get("monitor.check_interval", 5)  # seconds
        
    def start_monitoring(self, interface: Optional[str] = None, 
                        alert_level: str = 'medium',
                        duration: int = 0,
                        callback: Optional[Callable] = None) -> bool:
        """Start monitoring the ARP cache.
        
        Args:
            interface: Network interface to monitor (if None, use default gateway interface)
            alert_level: Alert sensitivity level ('low', 'medium', 'high')
            duration: Monitoring duration in seconds (0 for continuous)
            callback: Callback function for alerts and status updates
            
        Returns:
            bool: True if monitoring started successfully, False otherwise
        """
        if self.monitoring:
            logger.warning("ARP cache monitoring already in progress")
            return False
            
        # Get interface if not provided
        if not interface:
            _, interface = self.network_scanner.get_default_gateway()
            if not interface:
                logger.error("Failed to determine default interface")
                return False
        
        # Initialize monitoring state
        self.alerts = []
        self.alert_callback = callback
        self.monitoring = True
        
        # Set alert thresholds based on sensitivity level
        self.set_alert_thresholds(alert_level)
        
        # Populate known devices from network scan
        self._initialize_known_devices()
        
        logger.info(f"Starting ARP cache monitoring on interface {interface}")
        
        # Start monitoring in a separate thread
        self.monitor_thread = threading.Thread(
            target=self._monitor_thread,
            args=(interface, duration, callback)
        )
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        return True
        
    def stop_monitoring(self) -> bool:
        """Stop monitoring the ARP cache.
        
        Returns:
            bool: True if stopped successfully, False otherwise
        """
        if not self.monitoring:
            logger.warning("ARP cache monitoring not active")
            return False
            
        logger.info("Stopping ARP cache monitoring")
        self.monitoring = False
        
        # Wait for the thread to terminate
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
            
        return True
    
    def set_alert_thresholds(self, level: str):
        """Set alert thresholds based on sensitivity level.
        
        Args:
            level: Alert sensitivity level ('low', 'medium', 'high')
        """
        if level == 'low':
            self.mac_change_threshold = 3  # Multiple MAC changes before alert
            self.gateway_impersonation_score = 7  # Higher threshold for gateway alerts
            self.check_interval = 10  # Longer interval between checks
        elif level == 'high':
            self.mac_change_threshold = 1  # Alert on any MAC change
            self.gateway_impersonation_score = 3  # More sensitive gateway detection
            self.check_interval = 2  # Frequent checks
        else:  # medium (default)
            self.mac_change_threshold = 2
            self.gateway_impersonation_score = 5
            self.check_interval = 5
    
    def get_alerts(self) -> List[Dict[str, Any]]:
        """Get the current list of alerts.
        
        Returns:
            list: List of alert dictionaries
        """
        return self.alerts.copy()
    
    def _monitor_thread(self, interface: str, duration: int, callback: Optional[Callable]):
        """Thread function to perform the actual ARP cache monitoring.
        
        Args:
            interface: Network interface to monitor
            duration: Monitoring duration in seconds (0 for continuous)
            callback: Callback function for status updates
        """
        start_time = time.time()
        check_count = 0
        
        try:
            # Main monitoring loop
            while self.monitoring:
                # Check if duration has expired
                if duration > 0 and (time.time() - start_time) > duration:
                    if callback:
                        callback(True, f"Monitoring completed after {duration} seconds")
                    break
                
                # Read the current ARP cache
                current_cache = self._read_arp_cache()
                check_count += 1
                
                # Analyze for anomalies if we have entries
                if current_cache:
                    anomalies = self._analyze_arp_cache(current_cache)
                    
                    # Process any detected anomalies
                    for anomaly in anomalies:
                        self._process_anomaly(anomaly)
                        
                    # Status update
                    status_msg = f"ARP cache check #{check_count}: {len(current_cache)} entries, {len(anomalies)} anomalies"
                    logger.debug(status_msg)
                    
                    if callback:
                        callback(True, status_msg)
                else:
                    logger.warning("Failed to read ARP cache")
                    
                # Sleep for the check interval
                time.sleep(self.check_interval)
                
        except Exception as e:
            error_msg = f"Monitoring error: {str(e)}"
            logger.error(error_msg)
            if callback:
                callback(False, error_msg)
                
        finally:
            self.monitoring = False
            if callback:
                callback(False, "Monitoring stopped")
    
    def _read_arp_cache(self) -> List[Dict[str, Any]]:
        """Read the current ARP cache from the system.
        
        Returns:
            list: List of ARP cache entries as dictionaries
        """
        arp_entries = []
        current_time = datetime.now()
        try:
            system = platform.system().lower()
            
            if system == 'windows':
                # Windows: use 'arp -a'
                output = subprocess.check_output('arp -a', shell=True).decode('utf-8')
                
                # Parse the output
                for line in output.split('\n'):
                    if 'dynamic' in line.lower() or 'static' in line.lower():
                        parts = re.split(r'\s+', line.strip())
                        if len(parts) >= 3:
                            ip = parts[0]
                            mac = parts[1].replace('-', ':')
                            entry_type = 'dynamic' if 'dynamic' in line.lower() else 'static'
                            
                            arp_entries.append({
                                'ip_address': ip,
                                'mac_address': mac.lower(),
                                'type': entry_type,
                                'interface': None,  # Windows output doesn't specify interface
                                'time': current_time
                            })
                            
            elif system == 'linux' or system == 'darwin':
                # Linux/macOS: use 'ip neigh' or 'arp -an'
                try:
                    # Try 'ip neigh' first (Linux)
                    output = subprocess.check_output('ip neigh', shell=True).decode('utf-8')
                    
                    # Parse the output
                    for line in output.split('\n'):
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 5 and parts[1] == 'dev':
                                ip = parts[0]
                                interface = parts[2]
                                
                                # Extract MAC if present (e.g., "lladdr aa:bb:cc:dd:ee:ff")
                                mac = None
                                if 'lladdr' in line:
                                    mac_idx = parts.index('lladdr') + 1
                                    if mac_idx < len(parts):
                                        mac = parts[mac_idx].lower()
                                
                                # Extract state if present
                                entry_type = 'unknown'
                                if 'REACHABLE' in line:
                                    entry_type = 'reachable'
                                elif 'STALE' in line:
                                    entry_type = 'stale'
                                elif 'PERMANENT' in line:
                                    entry_type = 'permanent'
                                
                                if mac and mac != 'FAILED':
                                    arp_entries.append({
                                        'ip_address': ip,
                                        'mac_address': mac,
                                        'type': entry_type,
                                        'interface': interface,
                                        'time': current_time
                                    })
                                    
                except subprocess.CalledProcessError:
                    # Fallback to 'arp -an'
                    output = subprocess.check_output('arp -an', shell=True).decode('utf-8')
                    
                    # Parse the output
                    for line in output.split('\n'):
                        if line.strip():
                            # Format: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
                            match = re.search(r'\(([^)]+)\) at ([^\s]+).*on (\w+)', line)
                            if match:
                                ip = match.group(1)
                                mac = match.group(2).lower()
                                interface = match.group(3)
                                
                                if mac != 'incomplete':
                                    arp_entries.append({
                                        'ip_address': ip,
                                        'mac_address': mac,
                                        'type': 'dynamic',  # Assume dynamic
                                        'interface': interface,
                                        'time': current_time
                                    })
            else:
                logger.error(f"Unsupported operating system: {system}")
                
            # Update cache history with new entries
            for entry in arp_entries:
                ip = entry['ip_address']
                mac = entry['mac_address']
                
                if ip not in self.cache_history:
                    self.cache_history[ip] = []
                
                # Add to history if MAC is different from last entry
                if not self.cache_history[ip] or self.cache_history[ip][-1]['mac_address'] != mac:
                    self.cache_history[ip].append({
                        'mac_address': mac,
                        'time': current_time,
                        'type': entry['type']
                    })
                    
                    # Limit history size
                    if len(self.cache_history[ip]) > 10:
                        self.cache_history[ip] = self.cache_history[ip][-10:]
                        
            return arp_entries
                
        except Exception as e:
            logger.error(f"Error reading ARP cache: {e}")
            return []
    
    def _analyze_arp_cache(self, current_cache: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze the ARP cache for anomalies.
        
        Args:
            current_cache: Current ARP cache entries
            
        Returns:
            list: List of detected anomalies
        """
        anomalies = []
        current_time = datetime.now()
        
        # Check for anomalies in each entry
        for entry in current_cache:
            ip = entry['ip_address']
            mac = entry['mac_address']
            
            # Check for gateway impersonation
            if self.gateway_ip and ip != self.gateway_ip and mac == self._get_gateway_mac():
                anomalies.append({
                    'type': 'gateway_impersonation',
                    'severity': 'high',
                    'ip_address': ip,
                    'mac_address': mac,
                    'time': current_time,
                    'details': f"Device {ip} is using the gateway's MAC address"
                })
                
            # Check for rapid MAC changes
            if ip in self.cache_history and len(self.cache_history[ip]) >= self.mac_change_threshold:
                # Calculate time window for changes
                recent_entries = self.cache_history[ip][-self.mac_change_threshold:]
                time_span = (recent_entries[-1]['time'] - recent_entries[0]['time']).total_seconds()
                
                # Check for multiple MAC addresses in a short time window
                unique_macs = set(entry['mac_address'] for entry in recent_entries)
                
                if len(unique_macs) >= self.mac_change_threshold and time_span < 60:  # Multiple changes within a minute
                    anomalies.append({
                        'type': 'mac_address_flapping',
                        'severity': 'medium',
                        'ip_address': ip,
                        'mac_address': mac,
                        'time': current_time,
                        'details': f"IP {ip} had {len(unique_macs)} different MAC addresses in {time_span:.1f} seconds"
                    })
                    
            # Check for conflicts with known devices
            if ip in self.known_devices and self.known_devices[ip] != mac:
                anomalies.append({
                    'type': 'mac_address_conflict',
                    'severity': 'medium',
                    'ip_address': ip,
                    'mac_address': mac,
                    'time': current_time,
                    'details': f"IP {ip} changed from {self.known_devices[ip]} to {mac}"
                })
                
            # Special check for gateway MAC changes
            if ip == self.gateway_ip and ip in self.known_devices and self.known_devices[ip] != mac:
                anomalies.append({
                    'type': 'gateway_mac_change',
                    'severity': 'high',
                    'ip_address': ip,
                    'mac_address': mac,
                    'time': current_time,
                    'details': f"Gateway MAC changed from {self.known_devices[ip]} to {mac}"
                })
                
        return anomalies
    
    def _process_anomaly(self, anomaly: Dict[str, Any]):
        """Process a detected anomaly and generate an alert if needed.
        
        Args:
            anomaly: Anomaly information dictionary
        """
        # Add to alerts list
        self.alerts.append(anomaly)
        
        # Limit alerts size
        if len(self.alerts) > self.max_alerts:
            self.alerts = self.alerts[-self.max_alerts:]
            
        # Log the anomaly
        logger.warning(f"ARP anomaly detected: {anomaly['type']} - {anomaly['details']}")
        
        # Notify via callback
        if self.alert_callback:
            self.alert_callback(anomaly)
    
    def _initialize_known_devices(self):
        """Initialize known devices from a network scan."""
        # Perform a quick scan to get baseline device information
        def scan_callback(devices, status):
            for device in devices:
                if 'ip_address' in device and 'mac_address' in device:
                    self.known_devices[device['ip_address']] = device['mac_address'].lower()
                    
                    # Special handling for gateway
                    if device.get('is_gateway', False):
                        self.gateway_ip = device['ip_address']
        
        self.network_scanner.start_scan(callback=scan_callback)
        
        # Wait for scan to complete
        while self.network_scanner.scanning:
            time.sleep(0.5)
            
        logger.info(f"Initialized {len(self.known_devices)} known devices for ARP monitoring")
    
    def _get_gateway_mac(self) -> Optional[str]:
        """Get the MAC address of the default gateway.
        
        Returns:
            str: MAC address of the gateway or None if not found
        """
        if not self.gateway_ip:
            return None
            
        if self.gateway_ip in self.known_devices:
            return self.known_devices[self.gateway_ip]
            
        # If not in known_devices, try to get it
        try:
            for ip, history in self.cache_history.items():
                if ip == self.gateway_ip and history:
                    return history[-1]['mac_address']
        except Exception as e:
            logger.error(f"Error getting gateway MAC: {e}")
            
        return None 