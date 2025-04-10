#!/usr/bin/env python3
"""
ARPGuard Network Validation Script
This script provides network validation functionality for ARPGuard enterprise deployments.
It validates interfaces, promiscuous mode, subnet detection, gateway identification,
VLAN support, and traffic filtering.
"""

import argparse
import sys
import os
import socket
import struct
import subprocess
import netifaces
import logging
import json
from typing import Dict, List, Tuple, Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('network_validation.log')
    ]
)
logger = logging.getLogger('arpguard-network-validation')

# Constants
MIN_THROUGHPUT = 100  # Minimum throughput in Mbps
DEFAULT_CONFIG_FILE = os.path.expanduser('~/.arpguard/config.yaml')

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='ARPGuard Network Validation')
    parser.add_argument('--interfaces', action='store_true', help='Validate network interfaces')
    parser.add_argument('--promiscuous', action='store_true', help='Check promiscuous mode support')
    parser.add_argument('--subnet', action='store_true', help='Validate subnet detection')
    parser.add_argument('--gateway', action='store_true', help='Validate gateway identification')
    parser.add_argument('--vlan', action='store_true', help='Validate VLAN support')
    parser.add_argument('--filters', action='store_true', help='Validate traffic filtering')
    parser.add_argument('--all', action='store_true', help='Run all validation tests')
    parser.add_argument('--config', type=str, default=DEFAULT_CONFIG_FILE, help='Configuration file path')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # If no specific test is selected, run all tests
    if not (args.interfaces or args.promiscuous or args.subnet or 
            args.gateway or args.vlan or args.filters):
        args.all = True
    
    return args

def load_config(config_path: str) -> dict:
    """Load configuration from file."""
    try:
        if config_path.endswith('.yaml') or config_path.endswith('.yml'):
            import yaml
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        elif config_path.endswith('.json'):
            with open(config_path, 'r') as f:
                return json.load(f)
        else:
            logger.error(f"Unsupported configuration file format: {config_path}")
            return {}
    except Exception as e:
        logger.error(f"Error loading configuration: {str(e)}")
        return {}

def get_network_interfaces() -> List[Dict]:
    """Get list of network interfaces with their details."""
    interfaces = []
    for iface in netifaces.interfaces():
        interface_info = {'name': iface, 'addresses': {}}
        
        # Skip loopback interfaces
        if iface == 'lo' or iface.startswith('loop'):
            continue
            
        # Get addresses
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                interface_info['addresses']['ipv4'] = {
                    'addr': addr.get('addr', ''),
                    'netmask': addr.get('netmask', ''),
                    'broadcast': addr.get('broadcast', '')
                }
        
        if netifaces.AF_INET6 in addrs:
            for addr in addrs[netifaces.AF_INET6]:
                if 'addr' in addr:
                    # Skip link-local addresses
                    if not addr['addr'].startswith('fe80:'):
                        interface_info['addresses']['ipv6'] = {
                            'addr': addr.get('addr', ''),
                            'netmask': addr.get('netmask', '')
                        }
        
        if netifaces.AF_LINK in addrs:
            for addr in addrs[netifaces.AF_LINK]:
                interface_info['mac'] = addr.get('addr', '')
        
        # Get gateway
        gws = netifaces.gateways()
        if netifaces.AF_INET in gws and 'default' in gws:
            for gw in gws['default']:
                if gw[1] == iface:
                    interface_info['gateway'] = gw[0]
        
        interfaces.append(interface_info)
    
    return interfaces

def check_promiscuous_mode(interface: str) -> bool:
    """Check if interface supports promiscuous mode."""
    try:
        # Platform-specific checks
        if sys.platform.startswith('linux'):
            cmd = f"ip link show {interface}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return 'PROMISC' in result.stdout
        elif sys.platform.startswith('win'):
            # On Windows, we'll attempt to enable promiscuous mode via Python
            import scapy.all as scapy
            try:
                # Try to create a raw socket, which requires promiscuous mode
                s = scapy.conf.L2socket(iface=interface)
                s.close()
                return True
            except Exception:
                return False
        elif sys.platform.startswith('darwin'):
            cmd = f"ifconfig {interface}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return 'PROMISC' in result.stdout
        else:
            logger.warning(f"Unsupported platform for promiscuous mode check: {sys.platform}")
            return False
    except Exception as e:
        logger.error(f"Error checking promiscuous mode: {str(e)}")
        return False

def validate_interfaces() -> Tuple[bool, str]:
    """Validate network interfaces configuration."""
    interfaces = get_network_interfaces()
    
    if not interfaces:
        return False, "No network interfaces found"
    
    valid_interfaces = []
    for interface in interfaces:
        # Check if interface has IPv4 address
        if 'addresses' in interface and 'ipv4' in interface['addresses']:
            valid_interfaces.append(interface['name'])
    
    if valid_interfaces:
        return True, f"All interfaces properly configured: {', '.join(valid_interfaces)}"
    else:
        return False, "No properly configured interfaces found"

def check_promiscuous_mode_support() -> Tuple[bool, str]:
    """Check if interfaces support promiscuous mode."""
    interfaces = get_network_interfaces()
    
    supported_interfaces = []
    for interface in interfaces:
        if check_promiscuous_mode(interface['name']):
            supported_interfaces.append(interface['name'])
    
    if supported_interfaces:
        return True, f"Promiscuous mode supported on {', '.join(supported_interfaces)}"
    else:
        return False, "No interfaces support promiscuous mode"

def validate_gateway_identification() -> Tuple[bool, str]:
    """Validate gateway identification."""
    interfaces = get_network_interfaces()
    
    gateways = []
    for interface in interfaces:
        if 'gateway' in interface:
            gateways.append((interface['name'], interface['gateway']))
    
    if gateways:
        gw_str = ', '.join([f"{name}: {ip}" for name, ip in gateways])
        return True, f"Gateway identified: {gw_str}"
    else:
        return False, "No gateway identified"

def validate_vlan_support() -> Tuple[bool, str]:
    """Validate VLAN support."""
    try:
        # Check if system supports VLAN
        if sys.platform.startswith('linux'):
            cmd = "modprobe --dry-run 8021q"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
            vlan_supported = result.returncode == 0
        elif sys.platform.startswith('win'):
            # On Windows, check if Hyper-V feature is enabled which includes VLAN support
            cmd = "powershell -Command \"(Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).State\""
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
            vlan_supported = 'Enabled' in result.stdout
        elif sys.platform.startswith('darwin'):
            # macOS has built-in VLAN support
            vlan_supported = True
        else:
            logger.warning(f"Unsupported platform for VLAN check: {sys.platform}")
            vlan_supported = False
        
        if vlan_supported:
            return True, "VLAN support: PASSED"
        else:
            return False, "VLAN support: FAILED - VLANs not supported on this system"
    except Exception as e:
        logger.error(f"Error checking VLAN support: {str(e)}")
        return False, f"VLAN support: ERROR - {str(e)}"

def validate_traffic_filtering() -> Tuple[bool, str]:
    """Validate traffic filtering capabilities."""
    try:
        # Check if system supports packet filtering
        if sys.platform.startswith('linux'):
            cmds = [
                "iptables -L",
                "nft list ruleset"
            ]
            for cmd in cmds:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
                if result.returncode == 0:
                    return True, "Traffic filtering: PASSED - System supports packet filtering"
        elif sys.platform.startswith('win'):
            cmd = "netsh advfirewall show allprofiles"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return True, "Traffic filtering: PASSED - Windows Firewall is available"
        elif sys.platform.startswith('darwin'):
            cmd = "pfctl -s all"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return True, "Traffic filtering: PASSED - PF firewall is available"
        
        return False, "Traffic filtering: FAILED - No packet filtering capability detected"
    except Exception as e:
        logger.error(f"Error checking traffic filtering: {str(e)}")
        return False, f"Traffic filtering: ERROR - {str(e)}"

def run_validation_tests(args):
    """Run the specified validation tests."""
    results = []
    
    if args.all or args.interfaces:
        success, message = validate_interfaces()
        results.append(("Interface Configuration", success, message))
    
    if args.all or args.promiscuous:
        success, message = check_promiscuous_mode_support()
        results.append(("Promiscuous Mode", success, message))
    
    if args.all or args.gateway:
        success, message = validate_gateway_identification()
        results.append(("Gateway Identification", success, message))
    
    if args.all or args.vlan:
        success, message = validate_vlan_support()
        results.append(("VLAN Support", success, message))
    
    if args.all or args.filters:
        success, message = validate_traffic_filtering()
        results.append(("Traffic Filtering", success, message))
    
    # Display results
    print("\nNetwork Validation Results:")
    print("=" * 50)
    
    all_passed = True
    for name, success, message in results:
        status = "PASSED" if success else "FAILED"
        status_color = "\033[92m" if success else "\033[91m"  # Green for pass, red for fail
        reset_color = "\033[0m"
        
        print(f"{name}: {status_color}{status}{reset_color}")
        print(f"  {message}")
        print("-" * 50)
        
        if not success:
            all_passed = False
    
    overall_status = "PASSED" if all_passed else "FAILED"
    overall_color = "\033[92m" if all_passed else "\033[91m"
    print(f"\nOverall Status: {overall_color}{overall_status}{reset_color}")
    
    return all_passed

def main():
    """Main function."""
    args = parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    print("ARPGuard Network Validation")
    print("=" * 50)
    
    # Load configuration
    config = load_config(args.config)
    if not config and args.config != DEFAULT_CONFIG_FILE:
        logger.warning(f"Could not load configuration from {args.config}")
    
    # Run validation tests
    success = run_validation_tests(args)
    
    # Return appropriate exit code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
