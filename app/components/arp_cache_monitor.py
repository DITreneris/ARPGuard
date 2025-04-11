import threading
import time
import subprocess
import re
import platform
import ipaddress
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable, Tuple
from scapy.all import sniff, ARP

from app.utils.logger import get_logger
from app.utils.config import get_config
from app.components.network_scanner import NetworkScanner

# Module logger
logger = get_logger('components.arp_cache_monitor')

class ARPCacheMonitor:
    """Monitor ARP cache for potential spoofing attacks."""
    
    def __init__(self):
        self._monitoring = False
        self._stop_event = threading.Event()
        self._thread = None
        self._cache = {}
        self._alert_callback = None
        self._status_callback = None
        self.config = get_config()
        self.network_scanner = NetworkScanner()
        self.alerts = []
        self.cache_history = {}  # History of ARP cache entries
        self.known_devices = {}  # Known legitimate IP-MAC mappings
        self.gateway_ip, self.gateway_interface = self.network_scanner.get_default_gateway()
        self.max_alerts = self.config.get("monitor.max_alerts", 100)
        self.check_interval = self.config.get("monitor.check_interval", 5)  # seconds
        
    def start_monitoring(self, interface: Optional[str] = None,
                        alert_level: str = 'medium',
                        duration: int = 0,
                        check_interval: int = 2,
                        alert_callback: Optional[Callable] = None,
                        status_callback: Optional[Callable] = None) -> bool:
        """
        Start monitoring ARP cache.
        
        Args:
            interface: Network interface to monitor
            alert_level: Alert level (low, medium, high)
            duration: Duration in seconds (0 for continuous)
            check_interval: Interval between checks in seconds
            alert_callback: Callback for alerts
            status_callback: Callback for status updates
            
        Returns:
            bool: True if monitoring started successfully
        """
        if self._monitoring:
            return False
            
        self._alert_callback = alert_callback
        self._status_callback = status_callback
        self._stop_event.clear()
        self._monitoring = True
        
        def monitor_thread():
            start_time = datetime.now()
            
            try:
                while not self._stop_event.is_set():
                    if duration > 0:
                        elapsed = (datetime.now() - start_time).total_seconds()
                        if elapsed >= duration:
                            break
                            
                    # Sniff ARP packets
                    sniff(filter="arp", count=1, timeout=check_interval,
                          prn=self._process_packet, store=0, iface=interface)
                    
                    # Check for suspicious activity
                    self._check_cache(alert_level)
                    
            except Exception as e:
                if status_callback:
                    status_callback(False, f"Error during monitoring: {str(e)}")
                return
                
            if status_callback:
                status_callback(True, "Monitoring completed")
                
            self._monitoring = False
            
        self._thread = threading.Thread(target=monitor_thread)
        self._thread.daemon = True
        self._thread.start()
        
        return True
        
    def stop_monitoring(self) -> None:
        """Stop monitoring."""
        if self._monitoring:
            self._stop_event.set()
            if self._thread:
                self._thread.join()
            self._monitoring = False
            
    def is_monitoring(self) -> bool:
        """Check if monitoring is active."""
        return self._monitoring
        
    def _process_packet(self, packet):
        """Process captured ARP packet."""
        if ARP in packet:
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            
            if ip not in self._cache:
                self._cache[ip] = {'mac': mac, 'first_seen': datetime.now(),
                                 'last_seen': datetime.now(), 'count': 1}
            else:
                entry = self._cache[ip]
                entry['last_seen'] = datetime.now()
                entry['count'] += 1
                
                if entry['mac'] != mac:
                    if self._alert_callback:
                        self._alert_callback({
                            'severity': 'HIGH',
                            'message': f'MAC address change detected for {ip}',
                            'source': ip,
                            'old_mac': entry['mac'],
                            'new_mac': mac
                        })
                    entry['mac'] = mac
                    
    def _check_cache(self, alert_level: str):
        """Check cache for suspicious activity."""
        now = datetime.now()
        suspicious_ips = []
        
        for ip, entry in self._cache.items():
            # Check for rapid ARP requests
            time_window = (now - entry['first_seen']).total_seconds()
            if time_window > 0:
                rate = entry['count'] / time_window
                
                if ((alert_level == 'low' and rate > 10) or
                    (alert_level == 'medium' and rate > 20) or
                    (alert_level == 'high' and rate > 30)):
                    suspicious_ips.append(ip)
                    
        # Report suspicious activity
        if suspicious_ips and self._alert_callback:
            self._alert_callback({
                'severity': 'MEDIUM',
                'message': 'Suspicious ARP activity detected',
                'sources': suspicious_ips
            })
    
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