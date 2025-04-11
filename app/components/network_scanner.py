import threading
import time
from datetime import datetime
import json
import os
import ipaddress
from typing import List, Dict, Any, Callable, Optional, Tuple

from scapy.all import ARP, Ether, srp, conf
import netifaces
import socket

from app.utils.logger import get_logger
from app.utils.config import get_config
from app.utils.mac_vendor import get_vendor_name

# Module logger
logger = get_logger('components.network_scanner')

class NetworkScanner:
    def __init__(self):
        self.devices = []
        self.scanning = False
        self.scan_thread = None
        self.config = get_config()
        # Increase default timeout for better reliability
        self.timeout = self.config.get("scanner.timeout", 5)  
        # Reduce default batch size to avoid overwhelming the network
        self.batch_size = self.config.get("scanner.batch_size", 32)  
        self.cache = {}
        self.cache_timeout = self.config.get("scanner.cache_timeout", 60 * 30)
        
        # Check for root/admin privileges
        self._check_privileges()
        
        # Create scan results directory if saving is enabled
        if self.config.get("scanner.save_results", True):
            self._ensure_results_dir()
        
    def _check_privileges(self):
        """Check if the program has the necessary privileges for ARP scanning."""
        try:
            # Try to create a raw socket which requires admin/root
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            s.close()
            logger.debug("Running with sufficient privileges for network scanning")
        except PermissionError:
            logger.error("Insufficient privileges. Network scanning requires root/admin privileges")
            raise PermissionError("Network scanning requires root/admin privileges")
        except Exception as e:
            logger.error(f"Error checking privileges: {e}")
            raise
        
    def get_default_gateway(self) -> Tuple[Optional[str], Optional[str]]:
        """Get the default gateway IP and interface.
        
        Returns:
            Tuple containing (gateway_ip, interface) or (None, None) if not found.
        """
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET]
            gateway_ip, interface = default_gateway[0], default_gateway[1]
            logger.debug(f"Default gateway: {gateway_ip} on interface {interface}")
            return gateway_ip, interface
        except Exception as e:
            logger.error(f"Failed to get default gateway: {e}")
            return None, None
            
    def get_network_range(self) -> Optional[str]:
        """Get the network range based on the default gateway.
        
        Returns:
            Network range in CIDR notation or None if not determined.
        """
        try:
            gateway_ip, interface = self.get_default_gateway()
            if not gateway_ip or not interface:
                logger.warning("Could not determine network range: No default gateway found")
                return None
            
            # Get the netmask for a more accurate subnet calculation
            addr_info = netifaces.ifaddresses(interface).get(netifaces.AF_INET, [])
            if not addr_info:
                # Fallback to /24 if we can't determine the actual netmask
                logger.warning(f"Could not determine netmask for interface {interface}, falling back to /24")
                ip_parts = gateway_ip.split('.')
                return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                
            # Use the first address info entry
            ip = addr_info[0]['addr']
            netmask = addr_info[0]['netmask']
            
            # Convert netmask to CIDR prefix
            netmask_parts = [int(part) for part in netmask.split('.')]
            prefix_len = sum(bin(part).count('1') for part in netmask_parts)
            
            # Create network in CIDR notation
            ip_obj = ipaddress.IPv4Address(ip)
            network_obj = ipaddress.IPv4Network(f"{ip}/{prefix_len}", strict=False)
            network_range = str(network_obj)
            
            logger.debug(f"Network range: {network_range}")
            return network_range
        except Exception as e:
            logger.error(f"Error determining network range: {e}")
            # Fallback to simple /24 subnet based on gateway
            gateway_ip, _ = self.get_default_gateway()
            if gateway_ip:
                ip_parts = gateway_ip.split('.')
                return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            return None
        
    def start_scan(self, callback: Optional[Callable] = None) -> bool:
        """Start scanning the network for devices.
        
        Args:
            callback: Optional callback function that is called with scan results
            
        Returns:
            True if scan started successfully, False otherwise
        """
        if self.scanning:
            logger.warning("Scan already in progress")
            if callback:
                callback([], "Scan already in progress")
            return False
            
        network_range = self.get_network_range()
        if not network_range:
            if callback:
                callback([], "Failed to determine network range")
            return False
            
        logger.info(f"Starting network scan on range: {network_range}")
        self.scanning = True
        self.devices = []
        
        # Start scanning in a separate thread
        self.scan_thread = threading.Thread(
            target=self._scan_thread,
            args=(network_range, callback)
        )
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        return True
        
    def _scan_thread(self, network_range: str, callback: Optional[Callable]):
        """Thread function to perform the actual network scan.
        
        Args:
            network_range: Network range in CIDR notation
            callback: Optional callback to be called with results
        """
        try:
            network = ipaddress.IPv4Network(network_range)
            total_ips = network.num_addresses
            discovered_devices = []
            start_time = time.time()
            
            # Skip network and broadcast addresses for regular subnets
            host_ips = list(network.hosts()) if total_ips > 2 else list(network)
            
            # Calculate optimal batch size based on network size
            batch_size = min(self.batch_size, len(host_ips))
            
            # First, scan the gateway and cached devices for faster initial results
            gateway_ip, _ = self.get_default_gateway()
            initial_targets = []
            
            if gateway_ip:
                initial_targets.append(gateway_ip)
            
            # Add recently cached devices to initial scan
            current_time = time.time()
            cached_ips = [ip for ip, (_, timestamp) in self.cache.items() 
                          if current_time - timestamp < self.cache_timeout and
                          ipaddress.IPv4Address(ip) in network]
            
            initial_targets.extend(cached_ips)
            
            # Convert initial targets to IP objects for removal from main list
            initial_target_objects = [ipaddress.IPv4Address(ip) for ip in initial_targets if ip]
            remaining_ips = [ip for ip in host_ips if ip not in initial_target_objects]
            
            # Scan initial targets first if any exist
            if initial_targets:
                initial_devices = self._batch_scan(initial_targets, is_priority=True)
                discovered_devices.extend(initial_devices)
                
                # Send an early callback with initial results
                if callback and initial_devices:
                    callback(initial_devices.copy(), "Initial scan results")
            
            # Process remaining IPs in batches
            for i in range(0, len(remaining_ips), batch_size):
                if not self.scanning:
                    logger.info("Scan stopped by user")
                    break
                    
                batch = remaining_ips[i:i+batch_size]
                batch_devices = self._batch_scan(batch)
                discovered_devices.extend(batch_devices)
                
                # Update progress if there's a significant number of devices
                progress = min(100, (i + batch_size) / len(remaining_ips) * 100)
                logger.debug(f"Scan progress: {progress:.1f}% ({len(discovered_devices)} devices found)")
                
                # Optionally provide progress updates via callback
                if callback and batch_devices:
                    callback(discovered_devices.copy(), 
                             f"Scan in progress: {progress:.1f}% complete")
            
            # Update final device list
            self.devices = discovered_devices
            scan_time = time.time() - start_time
            
            # Save scan results if enabled
            if self.config.get("scanner.save_results", True):
                self._save_scan_results(discovered_devices)
            
            logger.info(f"Scan completed in {scan_time:.2f} seconds, found {len(discovered_devices)} devices")
            
            if callback:
                callback(discovered_devices, f"Scan completed in {scan_time:.2f} seconds")
                
        except Exception as e:
            logger.error(f"Scan error: {str(e)}")
            if callback:
                callback([], f"Scan error: {str(e)}")
                
        finally:
            self.scanning = False
    
    def _batch_scan(self, ip_batch, is_priority=False) -> List[Dict[str, Any]]:
        """Scan a batch of IP addresses.
        
        Args:
            ip_batch: List of IP addresses to scan
            is_priority: Whether this is a priority batch (gateway, cached devices)
            
        Returns:
            List of discovered devices in this batch
        """
        # Convert IP objects to strings if needed
        ip_strings = [str(ip) for ip in ip_batch]
        
        # Use slightly higher timeout for priority batch
        timeout = self.timeout * 1.5 if is_priority else self.timeout
        
        try:
            # Create ARP request packets for all IPs in the batch
            arp = ARP(pdst=ip_strings)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send packets and capture responses with retry mechanism
            max_retries = 2
            for retry in range(max_retries):
                try:
                    logger.debug(f"Sending ARP requests to {len(ip_strings)} IPs (attempt {retry + 1}/{max_retries})")
                    result = srp(packet, timeout=timeout, verbose=0, retry=1)[0]
                    break
                except Exception as e:
                    if retry == max_retries - 1:
                        logger.error(f"Failed to send ARP requests after {max_retries} attempts: {e}")
                        return []
                    logger.warning(f"ARP request failed (attempt {retry + 1}), retrying: {e}")
                    time.sleep(1)  # Wait before retry
            
            # Process results
            devices = []
            for sent, received in result:
                try:
                    mac_address = received.hwsrc
                    ip_address = received.psrc
                    
                    # Basic validation of MAC and IP
                    if not mac_address or not ip_address:
                        continue
                        
                    # Get device info with error handling
                    device_info = {
                        'ip': ip_address,
                        'mac': mac_address,
                        'vendor': get_vendor_name(mac_address) or 'Unknown',
                        'hostname': self._get_hostname(ip_address),
                        'last_seen': datetime.now().isoformat()
                    }
                    
                    # Update cache
                    self.cache[ip_address] = (device_info, time.time())
                    devices.append(device_info)
                    
                except Exception as e:
                    logger.warning(f"Error processing device {ip_address if 'ip_address' in locals() else 'unknown'}: {e}")
                    continue
            
            return devices
            
        except Exception as e:
            logger.error(f"Batch scan error: {str(e)}")
            return []
            
    def _get_hostname(self, ip: str) -> str:
        """Try to resolve hostname from IP address.
        
        Args:
            ip: The IP address to resolve
            
        Returns:
            Hostname or a default name if resolution fails
        """
        try:
            logger.debug(f"Resolving hostname for {ip}")
            hostname = socket.getfqdn(ip)
            # If getfqdn just returns the IP, it's not resolved
            if hostname == ip:
                if ip.split('.')[-1] == '1':
                    return "Router"
                return f"Device ({ip})"
            return hostname
        except Exception as e:
            logger.debug(f"Failed to resolve hostname for {ip}: {e}")
            if ip.split('.')[-1] == '1':
                return "Router"
            return f"Device ({ip})"
            
    def _ensure_results_dir(self) -> str:
        """Ensure the scan results directory exists.
        
        Returns:
            Path to the scan results directory
        """
        if os.name == 'nt':  # Windows
            base_dir = os.path.join(os.environ.get('APPDATA', ''), 'ARPGuard')
        else:  # macOS, Linux
            base_dir = os.path.join(os.path.expanduser('~'), '.arpguard')
            
        results_dir = os.path.join(base_dir, 'scan_results')
        
        try:
            os.makedirs(results_dir, exist_ok=True)
            logger.debug(f"Scan results directory: {results_dir}")
        except Exception as e:
            logger.error(f"Failed to create scan results directory: {e}")
            # Fallback to working directory
            results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'scan_results')
            os.makedirs(results_dir, exist_ok=True)
            
        return results_dir
        
    def _save_scan_results(self, devices: List[Dict[str, Any]]):
        """Save the scan results to a file.
        
        Args:
            devices: List of device dictionaries to save
        """
        if not devices:
            return
            
        try:
            results_dir = self._ensure_results_dir()
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"scan_{timestamp}.json"
            filepath = os.path.join(results_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump({
                    'timestamp': timestamp,
                    'devices': devices
                }, f, indent=2)
                
            logger.info(f"Saved scan results to {filepath}")
            
            # Cleanup old scan files if needed
            self._cleanup_old_scans(results_dir)
            
        except Exception as e:
            logger.error(f"Failed to save scan results: {e}")
            
    def _cleanup_old_scans(self, results_dir: str):
        """Delete old scan files to stay within the limit.
        
        Args:
            results_dir: Directory containing scan results
        """
        max_files = self.config.get("scanner.max_saved_scans", 5)
        if max_files <= 0:
            return
            
        try:
            files = [os.path.join(results_dir, f) for f in os.listdir(results_dir)
                    if f.startswith('scan_') and f.endswith('.json')]
            
            # Sort by modification time (oldest first)
            files.sort(key=lambda x: os.path.getmtime(x))
            
            # Remove oldest files if we exceed the limit
            if len(files) > max_files:
                for old_file in files[:-max_files]:
                    os.remove(old_file)
                    logger.debug(f"Deleted old scan file: {old_file}")
                    
        except Exception as e:
            logger.error(f"Failed to cleanup old scan files: {e}")
            
    def get_last_scan_results(self) -> List[Dict[str, Any]]:
        """Get the results of the last scan.
        
        Returns:
            List of device dictionaries from the last scan
        """
        return self.devices 
    
    def stop_scan(self) -> bool:
        """Stop an ongoing scan.
        
        Returns:
            True if stopping the scan succeeded, False otherwise
        """
        if not self.scanning:
            logger.warning("No scan in progress to stop")
            return False
            
        logger.info("Stopping network scan")
        self.scanning = False
        
        # Wait for scan thread to complete
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(2.0)  # Wait up to 2 seconds
            
        return True
    
    def clear_cache(self):
        """Clear the device cache."""
        self.cache = {}
        logger.info("Device cache cleared")
        
    def get_estimated_scan_time(self, network_range: str = None) -> float:
        """Get an estimate of how long a scan will take.
        
        Args:
            network_range: Optional network range, will use default if None
            
        Returns:
            Estimated time in seconds for the scan
        """
        if not network_range:
            network_range = self.get_network_range()
            if not network_range:
                return 0
                
        # Calculate based on network size and timeout
        try:
            network = ipaddress.IPv4Network(network_range)
            host_count = network.num_addresses
            # Subtract network and broadcast addresses for regular subnets
            if host_count > 2:
                host_count -= 2
                
            # Calculate number of batches
            batch_size = self.batch_size
            batch_count = (host_count + batch_size - 1) // batch_size
            
            # Estimate time based on batch count and timeout
            estimate = batch_count * self.timeout
            
            # Add some overhead for processing
            estimate = estimate * 1.1
            
            return max(5.0, estimate)  # Minimum 5 seconds
            
        except Exception as e:
            logger.error(f"Error calculating estimated scan time: {e}")
            return self.timeout * 10  # Fallback estimate 