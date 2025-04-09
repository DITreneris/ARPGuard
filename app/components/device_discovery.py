import ipaddress
import json
import os
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Callable

from app.components.network_scanner import NetworkScanner
from app.utils.logger import get_logger
from app.utils.config import get_config

# Module logger
logger = get_logger('components.device_discovery')

class DeviceDiscovery:
    """Device discovery module for the ARP Guard CLI."""
    
    def __init__(self):
        """Initialize the device discovery module."""
        self.network_scanner = NetworkScanner()
        self.config = get_config()
        self.devices = []
        self.current_scan_id = None
        self.discovery_in_progress = False
        self.last_scan_timestamp = None
        
    def discover_devices(self, subnet: Optional[str] = None, timeout: int = 5, 
                         progress_callback: Optional[Callable] = None) -> Tuple[str, List[Dict[str, Any]]]:
        """Discover devices on the network.
        
        Args:
            subnet: Subnet to scan in CIDR notation (e.g., 192.168.1.0/24)
                   If None, automatically determine from default gateway
            timeout: Scan timeout in seconds
            progress_callback: Optional callback for scan progress updates
            
        Returns:
            Tuple of (scan_id, devices) where devices is a list of device dictionaries
        """
        if self.discovery_in_progress:
            logger.warning("Device discovery already in progress")
            return None, []
        
        self.discovery_in_progress = True
        self.devices = []
        
        # Override scanner timeout with the provided value
        original_timeout = self.network_scanner.timeout
        self.network_scanner.timeout = timeout
        
        try:
            # Generate a scan ID based on timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            scan_id = f"scan_{timestamp}"
            self.current_scan_id = scan_id
            
            # Define a callback to track progress
            def internal_callback(devices, status):
                self.devices = devices
                if progress_callback:
                    progress_callback(len(devices), status)
            
            # If subnet is provided, validate it
            if subnet:
                try:
                    ipaddress.IPv4Network(subnet)
                except ValueError as e:
                    logger.error(f"Invalid subnet format: {e}")
                    self.discovery_in_progress = False
                    return None, []
            else:
                # Get subnet from network scanner
                subnet = self.network_scanner.get_network_range()
                if not subnet:
                    logger.error("Failed to determine network range")
                    self.discovery_in_progress = False
                    return None, []
            
            # Start the scan
            logger.info(f"Starting device discovery on subnet {subnet}")
            success = self.network_scanner.start_scan(callback=internal_callback)
            
            if not success:
                logger.error("Failed to start network scan")
                self.discovery_in_progress = False
                return None, []
            
            # Wait for scan to complete
            while self.network_scanner.scanning:
                time.sleep(0.5)
                
            self.last_scan_timestamp = datetime.now()
            
            # Save the results with scan_id
            self._save_discovery_results(scan_id, self.devices)
            
            return scan_id, self.devices
            
        except Exception as e:
            logger.error(f"Error in device discovery: {e}")
            return None, []
        finally:
            # Restore original timeout
            self.network_scanner.timeout = original_timeout
            self.discovery_in_progress = False
    
    def get_discovery_details(self, scan_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific discovery scan.
        
        Args:
            scan_id: The ID of the scan to retrieve
            
        Returns:
            Dictionary with scan details
        """
        # Check if this is the current scan
        if scan_id == self.current_scan_id:
            timestamp = self.last_scan_timestamp or datetime.now()
            return {
                'scan_id': scan_id,
                'timestamp': timestamp.isoformat(),
                'device_count': len(self.devices),
                'devices': self.devices
            }
        
        # Otherwise load from saved results
        result_file = os.path.join(self._get_results_dir(), f"{scan_id}.json")
        if os.path.exists(result_file):
            try:
                with open(result_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading scan results: {e}")
                return {'error': str(e)}
        else:
            return {'error': f"Scan {scan_id} not found"}
    
    def classify_devices(self, devices: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Classify devices into categories based on type or other attributes.
        
        Args:
            devices: List of device dictionaries
            
        Returns:
            Dictionary with device categories
        """
        categories = {
            'gateway': [],
            'router': [],
            'switch': [],
            'server': [],
            'iot': [],
            'mobile': [],
            'desktop': [],
            'unknown': []
        }
        
        for device in devices:
            # Check if it's a gateway
            if device.get('is_gateway', False):
                categories['gateway'].append(device)
                continue
                
            # Use vendor information to guess device type
            vendor = device.get('vendor', '').lower()
            
            # Basic classification based on common vendors
            if any(x in vendor for x in ['cisco', 'juniper', 'huawei', 'arista']):
                categories['router'].append(device)
            elif any(x in vendor for x in ['vmware', 'microsoft', 'linux', 'unix', 'oracle']):
                categories['server'].append(device)
            elif any(x in vendor for x in ['apple', 'samsung', 'xiaomi', 'huawei']):
                categories['mobile'].append(device)
            elif any(x in vendor for x in ['dell', 'hp', 'lenovo', 'acer', 'asus']):
                categories['desktop'].append(device)
            elif any(x in vendor for x in ['nest', 'ring', 'sonos', 'roku', 'amazon']):
                categories['iot'].append(device)
            else:
                categories['unknown'].append(device)
                
        return categories
    
    def stop_discovery(self) -> bool:
        """Stop an ongoing device discovery scan.
        
        Returns:
            True if successfully stopped, False otherwise
        """
        if not self.discovery_in_progress:
            logger.warning("No device discovery in progress")
            return False
            
        stopped = self.network_scanner.stop_scan()
        self.discovery_in_progress = False
        return stopped
    
    def get_last_discovery(self) -> List[Dict[str, Any]]:
        """Get the results of the last discovery scan.
        
        Returns:
            List of device dictionaries
        """
        if self.devices:
            return self.devices
        
        # Attempt to load the most recent scan
        return self.network_scanner.get_last_scan_results()
    
    def _save_discovery_results(self, scan_id: str, devices: List[Dict[str, Any]]):
        """Save discovery results to a file.
        
        Args:
            scan_id: The ID of the scan
            devices: List of discovered devices
        """
        if not self.config.get("scanner.save_results", True):
            return
            
        results_dir = self._get_results_dir()
        result_file = os.path.join(results_dir, f"{scan_id}.json")
        
        try:
            data = {
                'scan_id': scan_id,
                'timestamp': datetime.now().isoformat(),
                'device_count': len(devices),
                'devices': devices
            }
            
            with open(result_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.debug(f"Saved discovery results to {result_file}")
        except Exception as e:
            logger.error(f"Error saving discovery results: {e}")
    
    def _get_results_dir(self) -> str:
        """Get or create the directory for storing scan results.
        
        Returns:
            Path to the results directory
        """
        results_dir = os.path.join(os.path.expanduser('~'), '.arpguard', 'scan_results')
        os.makedirs(results_dir, exist_ok=True)
        return results_dir 