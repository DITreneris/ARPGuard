#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network Configuration Module for ARP Guard

This module provides functionality to configure network interfaces, monitoring modes,
and packet capture settings for ARP Guard.
"""

import os
import sys
import yaml
import logging
import socket
import subprocess
import platform
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass, field, asdict
import json

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class NetworkInterfaceConfig:
    """Configuration for a network interface."""
    name: str
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    is_up: bool = True
    is_monitoring: bool = False
    promiscuous_mode: bool = False
    packet_buffer_size: int = 1024
    packet_timeout: float = 1.0
    mtu: int = 1500
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class NetworkMonitoringConfig:
    """Configuration for network monitoring settings."""
    monitoring_mode: str = "promiscuous"  # Options: promiscuous, passive, active
    capture_arp_only: bool = True
    detect_ip_conflicts: bool = True
    detect_mac_spoofing: bool = True
    max_packets_per_scan: int = 5000
    scan_interval_seconds: float = 5.0
    adapter_reset_on_error: bool = False
    filter_string: str = "arp"  # Default pcap filter string

@dataclass
class NetworkConfig:
    """Main network configuration class."""
    primary_interface: str
    interfaces: Dict[str, NetworkInterfaceConfig] = field(default_factory=dict)
    monitoring: NetworkMonitoringConfig = field(default_factory=NetworkMonitoringConfig)
    allow_ip_forwarding: bool = False
    multi_interface_mode: bool = False
    fallback_interfaces: List[str] = field(default_factory=list)
    config_version: str = "1.0"

class NetworkConfigManager:
    """Manager class for network configuration."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the network configuration manager.
        
        Args:
            config_path: Path to configuration file. If None, uses default.
        """
        self.config_path = config_path or os.path.join("config", "network_config.yaml")
        self.config = self._load_default_config()
        self.os_platform = platform.system().lower()
        
        # Load configuration file if it exists
        if os.path.exists(self.config_path):
            try:
                self._load_config()
            except Exception as e:
                logger.error(f"Failed to load network configuration: {e}")
                logger.info("Using default network configuration")
    
    def _load_default_config(self) -> NetworkConfig:
        """Load default network configuration."""
        primary_interface = self._get_default_interface()
        interfaces = {
            primary_interface: NetworkInterfaceConfig(
                name=primary_interface,
                ip_address=self._get_interface_ip(primary_interface),
                mac_address=self._get_interface_mac(primary_interface),
            )
        }
        
        return NetworkConfig(
            primary_interface=primary_interface,
            interfaces=interfaces
        )
    
    def _load_config(self) -> None:
        """Load configuration from file."""
        try:
            with open(self.config_path, 'r') as f:
                config_data = yaml.safe_load(f)
            
            # Extract primary interface
            primary_interface = config_data.get('primary_interface', self._get_default_interface())
            
            # Extract interface configurations
            interfaces = {}
            for iface_name, iface_data in config_data.get('interfaces', {}).items():
                interfaces[iface_name] = NetworkInterfaceConfig(
                    name=iface_name,
                    **{k: v for k, v in iface_data.items() if k != 'name'}
                )
            
            # Extract monitoring configuration
            monitoring_data = config_data.get('monitoring', {})
            monitoring = NetworkMonitoringConfig(**monitoring_data)
            
            # Create the network configuration
            self.config = NetworkConfig(
                primary_interface=primary_interface,
                interfaces=interfaces,
                monitoring=monitoring,
                allow_ip_forwarding=config_data.get('allow_ip_forwarding', False),
                multi_interface_mode=config_data.get('multi_interface_mode', False),
                fallback_interfaces=config_data.get('fallback_interfaces', []),
                config_version=config_data.get('config_version', "1.0")
            )
            
            logger.info(f"Loaded network configuration from {self.config_path}")
            
        except Exception as e:
            logger.error(f"Error loading network configuration: {e}")
            raise
    
    def save_config(self, config_path: Optional[str] = None) -> None:
        """Save configuration to file.
        
        Args:
            config_path: Path to save configuration. If None, uses current path.
        """
        save_path = config_path or self.config_path
        
        try:
            # Convert dataclasses to dictionaries
            config_dict = {
                'primary_interface': self.config.primary_interface,
                'interfaces': {
                    name: asdict(interface_config) 
                    for name, interface_config in self.config.interfaces.items()
                },
                'monitoring': asdict(self.config.monitoring),
                'allow_ip_forwarding': self.config.allow_ip_forwarding,
                'multi_interface_mode': self.config.multi_interface_mode,
                'fallback_interfaces': self.config.fallback_interfaces,
                'config_version': self.config.config_version
            }
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            
            # Save to YAML file
            with open(save_path, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False)
            
            logger.info(f"Saved network configuration to {save_path}")
            
        except Exception as e:
            logger.error(f"Error saving network configuration: {e}")
            raise
    
    def _get_default_interface(self) -> str:
        """Get the default network interface based on OS."""
        try:
            if self.os_platform == 'windows':
                # For Windows, create a temporary socket and get interface
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect(("8.8.8.8", 80))
                    return s.getsockname()[0]
            elif self.os_platform == 'linux':
                # For Linux, parse route information
                try:
                    output = subprocess.check_output("ip route | grep default", shell=True).decode('utf-8')
                    return output.split()[4]
                except:
                    return "eth0"  # Fallback
            elif self.os_platform == 'darwin':  # macOS
                try:
                    output = subprocess.check_output("route -n get default | grep interface", shell=True).decode('utf-8')
                    return output.split()[-1]
                except:
                    return "en0"  # Fallback
            else:
                return "eth0"  # Generic fallback
        except Exception as e:
            logger.warning(f"Failed to determine default interface: {e}")
            # Fallback interfaces based on OS
            if self.os_platform == 'windows':
                return "Ethernet"
            elif self.os_platform == 'darwin':
                return "en0"
            else:
                return "eth0"
    
    def _get_interface_ip(self, interface_name: str) -> Optional[str]:
        """Get the IP address of the specified interface."""
        try:
            if self.os_platform == 'windows':
                # Windows implementation
                # This is simplified; in a real implementation, you would parse ipconfig output
                return socket.gethostbyname(socket.gethostname())
            elif self.os_platform in ['linux', 'darwin']:
                # Linux/macOS implementation
                output = subprocess.check_output(
                    f"ifconfig {interface_name} | grep 'inet ' | awk '{{print $2}}'", 
                    shell=True
                ).decode('utf-8').strip()
                return output
            else:
                return None
        except Exception as e:
            logger.warning(f"Failed to get IP for interface {interface_name}: {e}")
            return None
    
    def _get_interface_mac(self, interface_name: str) -> Optional[str]:
        """Get the MAC address of the specified interface."""
        try:
            if self.os_platform == 'windows':
                # Windows implementation
                # In a real implementation, you would parse ipconfig /all output
                return "00:00:00:00:00:00"  # Placeholder
            elif self.os_platform in ['linux', 'darwin']:
                # Linux/macOS implementation
                output = subprocess.check_output(
                    f"ifconfig {interface_name} | grep -o -E '([0-9a-fA-F]{{2}}:){{5}}[0-9a-fA-F]{{2}}'",
                    shell=True
                ).decode('utf-8').strip()
                return output
            else:
                return None
        except Exception as e:
            logger.warning(f"Failed to get MAC for interface {interface_name}: {e}")
            return None
    
    def get_all_interfaces(self) -> List[str]:
        """Get a list of all available network interfaces."""
        try:
            if self.os_platform == 'windows':
                # Windows implementation
                # In a real implementation, you would parse ipconfig output
                output = subprocess.check_output("ipconfig /all", shell=True).decode('utf-8')
                # Simple parsing, not comprehensive
                interfaces = []
                for line in output.split('\n'):
                    if "adapter" in line and ":" in line:
                        iface = line.split(":")[0].strip()
                        interfaces.append(iface)
                return interfaces
            elif self.os_platform == 'linux':
                # Linux implementation
                output = subprocess.check_output("ls /sys/class/net", shell=True).decode('utf-8')
                return output.strip().split()
            elif self.os_platform == 'darwin':
                # macOS implementation
                output = subprocess.check_output("ifconfig -l", shell=True).decode('utf-8')
                return output.strip().split()
            else:
                return []
        except Exception as e:
            logger.warning(f"Failed to get interface list: {e}")
            return []
    
    def set_interface_promiscuous(self, interface_name: str, enable: bool = True) -> bool:
        """Enable or disable promiscuous mode on the interface.
        
        Args:
            interface_name: Name of the interface
            enable: True to enable, False to disable
            
        Returns:
            bool: Success status
        """
        if interface_name not in self.config.interfaces:
            logger.error(f"Interface {interface_name} not found in configuration")
            return False
        
        try:
            if self.os_platform == 'windows':
                # Windows requires a dedicated packet capture library like WinPcap/Npcap
                logger.info(f"Setting promiscuous mode to {enable} for {interface_name} on Windows")
                # This is a placeholder; actual implementation would use libpcap API
                self.config.interfaces[interface_name].promiscuous_mode = enable
                return True
            elif self.os_platform in ['linux', 'darwin']:
                # Linux/macOS implementation
                mode = "promisc" if enable else "-promisc"
                subprocess.check_call(f"ifconfig {interface_name} {mode}", shell=True)
                self.config.interfaces[interface_name].promiscuous_mode = enable
                logger.info(f"Set {interface_name} promiscuous mode to {enable}")
                return True
            else:
                logger.error(f"Unsupported OS for promiscuous mode: {self.os_platform}")
                return False
        except Exception as e:
            logger.error(f"Failed to set promiscuous mode: {e}")
            return False
    
    def apply_monitoring_settings(self) -> bool:
        """Apply the current monitoring settings to the primary interface.
        
        Returns:
            bool: Success status
        """
        interface_name = self.config.primary_interface
        if interface_name not in self.config.interfaces:
            logger.error(f"Primary interface {interface_name} not found in configuration")
            return False
        
        try:
            # Apply promiscuous mode if needed
            if self.config.monitoring.monitoring_mode == "promiscuous":
                success = self.set_interface_promiscuous(interface_name, True)
                if not success:
                    logger.warning(f"Failed to set promiscuous mode on {interface_name}")
            
            # Update interface config
            interface_config = self.config.interfaces[interface_name]
            interface_config.is_monitoring = True
            interface_config.packet_buffer_size = self.config.monitoring.max_packets_per_scan
            interface_config.packet_timeout = self.config.monitoring.scan_interval_seconds
            
            logger.info(f"Applied monitoring settings to {interface_name}")
            
            # Save the updated configuration
            self.save_config()
            
            return True
        except Exception as e:
            logger.error(f"Failed to apply monitoring settings: {e}")
            return False
    
    def get_interface_status(self, interface_name: str) -> Dict[str, Any]:
        """Get current status of the interface.
        
        Args:
            interface_name: Name of the interface
            
        Returns:
            Dict with status information
        """
        if interface_name not in self.config.interfaces:
            return {"error": f"Interface {interface_name} not found"}
        
        interface_config = self.config.interfaces[interface_name]
        
        # Check if interface is currently up
        is_up = self._check_interface_is_up(interface_name)
        
        # Get current IP if different from stored
        current_ip = self._get_interface_ip(interface_name)
        
        return {
            "name": interface_name,
            "is_up": is_up,
            "current_ip": current_ip,
            "configured_ip": interface_config.ip_address,
            "mac_address": interface_config.mac_address,
            "is_monitoring": interface_config.is_monitoring,
            "promiscuous_mode": interface_config.promiscuous_mode,
            "mtu": interface_config.mtu,
            "is_primary": (interface_name == self.config.primary_interface)
        }
    
    def _check_interface_is_up(self, interface_name: str) -> bool:
        """Check if the interface is up and running.
        
        Args:
            interface_name: Name of the interface
            
        Returns:
            bool: True if interface is up
        """
        try:
            if self.os_platform == 'windows':
                # Windows implementation
                output = subprocess.check_output(
                    f"netsh interface show interface name=\"{interface_name}\"", 
                    shell=True
                ).decode('utf-8')
                return "Connected" in output
            elif self.os_platform == 'linux':
                # Linux implementation
                output = subprocess.check_output(
                    f"ip link show {interface_name}", 
                    shell=True
                ).decode('utf-8')
                return "UP" in output and "LOWER_UP" in output
            elif self.os_platform == 'darwin':
                # macOS implementation
                output = subprocess.check_output(
                    f"ifconfig {interface_name}", 
                    shell=True
                ).decode('utf-8')
                return "status: active" in output.lower()
            else:
                return False
        except Exception as e:
            logger.warning(f"Failed to check if interface {interface_name} is up: {e}")
            return False
    
    def set_primary_interface(self, interface_name: str) -> bool:
        """Set the primary network interface.
        
        Args:
            interface_name: Name of the interface to set as primary
            
        Returns:
            bool: Success status
        """
        if interface_name not in self.get_all_interfaces():
            logger.error(f"Interface {interface_name} not found in available interfaces")
            return False
        
        try:
            # Add interface to config if it doesn't exist
            if interface_name not in self.config.interfaces:
                self.config.interfaces[interface_name] = NetworkInterfaceConfig(
                    name=interface_name,
                    ip_address=self._get_interface_ip(interface_name),
                    mac_address=self._get_interface_mac(interface_name)
                )
            
            # Set as primary
            self.config.primary_interface = interface_name
            logger.info(f"Set {interface_name} as primary interface")
            
            # Save the updated configuration
            self.save_config()
            
            return True
        except Exception as e:
            logger.error(f"Failed to set primary interface: {e}")
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'primary_interface': self.config.primary_interface,
            'interfaces': {
                name: asdict(interface_config) 
                for name, interface_config in self.config.interfaces.items()
            },
            'monitoring': asdict(self.config.monitoring),
            'allow_ip_forwarding': self.config.allow_ip_forwarding,
            'multi_interface_mode': self.config.multi_interface_mode,
            'fallback_interfaces': self.config.fallback_interfaces,
            'config_version': self.config.config_version
        }
    
    def from_dict(self, config_dict: Dict[str, Any]) -> None:
        """Update configuration from dictionary.
        
        Args:
            config_dict: Dictionary with configuration values
        """
        try:
            # Extract primary interface
            self.config.primary_interface = config_dict.get(
                'primary_interface', self.config.primary_interface
            )
            
            # Extract interface configurations
            interfaces = {}
            for iface_name, iface_data in config_dict.get('interfaces', {}).items():
                interfaces[iface_name] = NetworkInterfaceConfig(
                    name=iface_name,
                    **{k: v for k, v in iface_data.items() if k != 'name'}
                )
            
            # Update interfaces dict
            if interfaces:
                self.config.interfaces = interfaces
            
            # Extract monitoring configuration
            monitoring_data = config_dict.get('monitoring', {})
            if monitoring_data:
                self.config.monitoring = NetworkMonitoringConfig(**monitoring_data)
            
            # Update other fields
            for field in ['allow_ip_forwarding', 'multi_interface_mode', 
                          'fallback_interfaces', 'config_version']:
                if field in config_dict:
                    setattr(self.config, field, config_dict[field])
            
            logger.info("Updated network configuration from dictionary")
            
        except Exception as e:
            logger.error(f"Error updating network configuration from dict: {e}")
            raise

# Create default configuration file if it doesn't exist
def create_default_config(config_path: str = os.path.join("config", "network_config.yaml")) -> None:
    """Create default network configuration file if it doesn't exist.
    
    Args:
        config_path: Path to configuration file
    """
    if os.path.exists(config_path):
        return
    
    try:
        # Create network config manager with default settings
        network_manager = NetworkConfigManager()
        
        # Save default configuration
        network_manager.save_config(config_path)
        
        logger.info(f"Created default network configuration at {config_path}")
        
    except Exception as e:
        logger.error(f"Failed to create default network configuration: {e}")

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create default configuration if called directly
    create_default_config()
    
    # Test the network configuration manager
    network_manager = NetworkConfigManager()
    print("Primary interface:", network_manager.config.primary_interface)
    print("All interfaces:", network_manager.get_all_interfaces())
    
    # Display configuration as JSON
    print(json.dumps(network_manager.to_dict(), indent=2)) 