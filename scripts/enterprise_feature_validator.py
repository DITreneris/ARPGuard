#!/usr/bin/env python3
"""
ARPGuard Enterprise Feature Validator
This script performs enterprise-specific feature validation to ensure
ARPGuard is ready for production deployment in enterprise environments.
"""

import os
import sys
import json
import yaml
import logging
import platform
import subprocess
import argparse
import psutil
import socket
import ipaddress
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('logs/enterprise_validation.log')
    ]
)
logger = logging.getLogger('arpguard.enterprise_validation')

class EnterpriseFeatureValidator:
    """Validator for enterprise-specific features of ARPGuard"""
    
    def __init__(self, config_path: str = 'config/validation_config.yaml'):
        """Initialize the validator with configuration"""
        self.config = self._load_config(config_path)
        self.results = {}
        self.is_windows = platform.system() == 'Windows'

    def _load_config(self, config_path: str) -> Dict:
        """Load validation configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {str(e)}")
            raise

    def validate_all(self) -> Dict[str, Dict[str, Any]]:
        """Run all enterprise feature validations"""
        # Role-based access control validation
        self.results['rbac'] = self.validate_rbac()
        
        # Multi-subnet monitoring validation
        self.results['multi_subnet'] = self.validate_multi_subnet()
        
        # High availability configuration
        self.results['high_availability'] = self.validate_high_availability()
        
        # Integration validation
        self.results['api_security'] = self.validate_api_security()
        
        # VLAN support validation
        self.results['vlan_support'] = self.validate_vlan_support()
        
        return self.results
        
    def validate_rbac(self) -> Dict[str, Any]:
        """Validate role-based access control features"""
        result = {'status': 'PASS', 'details': []}
        
        try:
            # Check if config file exists and contains RBAC settings
            if os.path.exists('config.yaml'):
                with open('config.yaml', 'r') as f:
                    config = yaml.safe_load(f)
                
                if 'rbac' not in config:
                    result['status'] = 'FAIL'
                    result['details'].append("RBAC configuration missing from config.yaml")
                else:
                    # Verify RBAC roles exist
                    if 'roles' not in config['rbac'] or not config['rbac']['roles']:
                        result['status'] = 'FAIL'
                        result['details'].append("No RBAC roles defined")
                    else:
                        result['details'].append(f"Found {len(config['rbac']['roles'])} roles defined")
                    
                    # Verify admin role exists
                    admin_role = next((r for r in config['rbac'].get('roles', []) 
                                      if r.get('name') == 'admin'), None)
                    if not admin_role:
                        result['status'] = 'FAIL'
                        result['details'].append("Admin role not defined")
                    else:
                        result['details'].append("Admin role properly configured")
            else:
                result['status'] = 'FAIL'
                result['details'].append("Config file not found")
        except Exception as e:
            result['status'] = 'FAIL'
            result['details'].append(f"Error validating RBAC: {str(e)}")
            
        return result
        
    def validate_multi_subnet(self) -> Dict[str, Any]:
        """Validate multi-subnet monitoring capabilities"""
        result = {'status': 'PASS', 'details': []}
        
        try:
            # Get all network interfaces and their IPs
            interfaces = psutil.net_if_addrs()
            networks = []
            
            for interface, addrs in interfaces.items():
                for addr in addrs:
                    # Check if IPv4 address
                    if addr.family == socket.AF_INET:
                        try:
                            ip = ipaddress.IPv4Address(addr.address)
                            # Skip localhost
                            if not ip.is_loopback:
                                networks.append(str(ip))
                                result['details'].append(f"Found network interface {interface} with IP {addr.address}")
                        except ValueError:
                            pass
            
            # Verify we can detect multiple subnets
            if len(networks) < 2:
                result['status'] = 'WARNING'
                result['details'].append("Only one network detected. Multi-subnet capability cannot be fully verified.")
                
            # Check if we can ping other networks
            if networks:
                for network in networks:
                    if self.is_windows:
                        cmd = f"ping -n 1 {network}"
                    else:
                        cmd = f"ping -c 1 {network}"
                    
                    try:
                        subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT)
                        result['details'].append(f"Successfully pinged {network}")
                    except subprocess.CalledProcessError:
                        result['details'].append(f"Failed to ping {network}")
            else:
                result['status'] = 'FAIL'
                result['details'].append("No networks detected")
                
        except Exception as e:
            result['status'] = 'FAIL'
            result['details'].append(f"Error validating multi-subnet capability: {str(e)}")
            
        return result
        
    def validate_high_availability(self) -> Dict[str, Any]:
        """Validate high availability configuration"""
        result = {'status': 'PASS', 'details': []}
        
        try:
            # Check for failover configuration
            if os.path.exists('config/ha_config.yaml'):
                with open('config/ha_config.yaml', 'r') as f:
                    ha_config = yaml.safe_load(f)
                
                # Check for primary and backup nodes
                if 'nodes' not in ha_config:
                    result['status'] = 'FAIL'
                    result['details'].append("No nodes defined in HA configuration")
                else:
                    primary_nodes = [n for n in ha_config.get('nodes', []) 
                                     if n.get('role') == 'primary']
                    backup_nodes = [n for n in ha_config.get('nodes', []) 
                                    if n.get('role') == 'backup']
                    
                    if not primary_nodes:
                        result['status'] = 'FAIL'
                        result['details'].append("No primary node defined")
                    else:
                        result['details'].append(f"Found {len(primary_nodes)} primary nodes")
                        
                    if not backup_nodes:
                        result['status'] = 'FAIL'
                        result['details'].append("No backup nodes defined")
                    else:
                        result['details'].append(f"Found {len(backup_nodes)} backup nodes")
                        
                # Check heartbeat settings
                if 'heartbeat' not in ha_config:
                    result['status'] = 'FAIL'
                    result['details'].append("No heartbeat configuration defined")
                else:
                    result['details'].append("Heartbeat configuration found")
                    
                # Check failover procedure
                if 'failover_procedure' not in ha_config:
                    result['status'] = 'FAIL'
                    result['details'].append("No failover procedure defined")
                else:
                    result['details'].append("Failover procedure defined")
            else:
                result['status'] = 'WARNING'
                result['details'].append("High availability configuration file not found")
                result['details'].append("HA might not be configured for this installation")
        except Exception as e:
            result['status'] = 'FAIL'
            result['details'].append(f"Error validating high availability: {str(e)}")
            
        return result
        
    def validate_api_security(self) -> Dict[str, Any]:
        """Validate API security and rate limiting"""
        result = {'status': 'PASS', 'details': []}
        
        try:
            # Check if API config exists
            if os.path.exists('config/api_config.yaml'):
                with open('config/api_config.yaml', 'r') as f:
                    api_config = yaml.safe_load(f)
                
                # Check authentication method
                if 'authentication' not in api_config:
                    result['status'] = 'FAIL'
                    result['details'].append("API authentication not configured")
                else:
                    auth_method = api_config.get('authentication', {}).get('method')
                    if not auth_method:
                        result['status'] = 'FAIL'
                        result['details'].append("No API authentication method specified")
                    else:
                        result['details'].append(f"API authentication method: {auth_method}")
                
                # Check rate limiting
                if 'rate_limiting' not in api_config:
                    result['status'] = 'FAIL'
                    result['details'].append("API rate limiting not configured")
                else:
                    rate_limit = api_config.get('rate_limiting', {}).get('requests_per_minute')
                    if not rate_limit:
                        result['status'] = 'FAIL'
                        result['details'].append("No API rate limit specified")
                    else:
                        result['details'].append(f"API rate limit: {rate_limit} requests per minute")
                
                # Check API endpoints security
                if 'endpoints' not in api_config:
                    result['status'] = 'FAIL'
                    result['details'].append("API endpoints not configured")
                else:
                    endpoints = api_config.get('endpoints', [])
                    secure_endpoints = [e for e in endpoints 
                                       if e.get('secure', False)]
                    
                    if not secure_endpoints:
                        result['status'] = 'FAIL'
                        result['details'].append("No secure API endpoints found")
                    else:
                        result['details'].append(f"Found {len(secure_endpoints)} secure API endpoints")
            else:
                result['status'] = 'FAIL'
                result['details'].append("API configuration file not found")
        except Exception as e:
            result['status'] = 'FAIL'
            result['details'].append(f"Error validating API security: {str(e)}")
            
        return result
        
    def validate_vlan_support(self) -> Dict[str, Any]:
        """Validate VLAN support"""
        result = {'status': 'PASS', 'details': []}
        
        try:
            # Check for VLAN interfaces on the system
            vlan_found = False
            interfaces = psutil.net_if_addrs()
            
            for interface in interfaces:
                if '.' in interface or 'vlan' in interface.lower():
                    vlan_found = True
                    result['details'].append(f"Found potential VLAN interface: {interface}")
            
            if not vlan_found:
                result['status'] = 'WARNING'
                result['details'].append("No VLAN interfaces detected on the system")
            
            # Check if ARP Guard config has VLAN settings
            if os.path.exists('config.yaml'):
                with open('config.yaml', 'r') as f:
                    config = yaml.safe_load(f)
                
                if 'vlan' not in config:
                    result['status'] = 'WARNING'
                    result['details'].append("VLAN configuration not found in ARPGuard config")
                else:
                    vlan_config = config.get('vlan', {})
                    enabled = vlan_config.get('enabled', False)
                    
                    if not enabled:
                        result['status'] = 'WARNING'
                        result['details'].append("VLAN support is disabled in configuration")
                    else:
                        result['details'].append("VLAN support is enabled in configuration")
                        
                    # Check for specific VLAN IDs
                    vlan_ids = vlan_config.get('vlan_ids', [])
                    if not vlan_ids:
                        result['status'] = 'WARNING'
                        result['details'].append("No specific VLAN IDs configured")
                    else:
                        result['details'].append(f"Found {len(vlan_ids)} VLAN IDs configured")
            else:
                result['status'] = 'FAIL'
                result['details'].append("ARPGuard configuration file not found")
        except Exception as e:
            result['status'] = 'FAIL'
            result['details'].append(f"Error validating VLAN support: {str(e)}")
            
        return result

def save_results(results: Dict[str, Dict[str, Any]], output_path: str):
    """Save validation results to a file"""
    try:
        with open(output_path, 'w') as f:
            yaml.dump(results, f, default_flow_style=False)
        logger.info(f"Results saved to {output_path}")
    except Exception as e:
        logger.error(f"Failed to save results: {str(e)}")

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='ARPGuard Enterprise Feature Validator')
    parser.add_argument('--config', type=str, default='config/validation_config.yaml',
                        help='Path to validation configuration file')
    parser.add_argument('--output', type=str, default='enterprise_features.yaml',
                        help='Output file for validation results')
    return parser.parse_args()

def main():
    """Main function"""
    args = parse_args()
    
    try:
        # Initialize validator
        validator = EnterpriseFeatureValidator(args.config)
        
        # Run validations
        logger.info("Starting enterprise feature validation")
        results = validator.validate_all()
        
        # Save results
        save_results(results, args.output)
        
        # Check for failures
        failures = [name for name, result in results.items() 
                   if result.get('status') == 'FAIL']
        
        if failures:
            logger.error(f"Validation failed for: {', '.join(failures)}")
            return 1
        else:
            logger.info("All validations passed successfully")
            return 0
    except Exception as e:
        logger.error(f"Error during validation: {str(e)}")
        return 1

if __name__ == '__main__':
    sys.exit(main()) 