import os
import subprocess
from typing import List, Optional
import logging
from logger import DemoLogger

class NetworkManager:
    """Manages network namespaces and virtual interfaces for the demo"""
    
    def __init__(self, logger: Optional[DemoLogger] = None):
        self.logger = logger or DemoLogger()
        self.namespaces: List[str] = []
        self.interfaces: List[str] = []
    
    def create_namespace(self, name: str) -> bool:
        """Create a new network namespace"""
        try:
            # Check if namespace already exists
            if self._namespace_exists(name):
                self.logger.warning(f"Namespace {name} already exists")
                return True
                
            # Create namespace
            subprocess.run(["ip", "netns", "add", name], check=True)
            self.namespaces.append(name)
            self.logger.info(f"Created network namespace: {name}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to create namespace {name}: {e}")
            return False
    
    def delete_namespace(self, name: str) -> bool:
        """Delete a network namespace"""
        try:
            if not self._namespace_exists(name):
                self.logger.warning(f"Namespace {name} does not exist")
                return True
                
            subprocess.run(["ip", "netns", "delete", name], check=True)
            self.namespaces.remove(name)
            self.logger.info(f"Deleted network namespace: {name}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to delete namespace {name}: {e}")
            return False
    
    def create_virtual_interface(self, name: str, namespace: str) -> bool:
        """Create a virtual network interface in a namespace"""
        try:
            # Create veth pair
            peer_name = f"{name}-peer"
            subprocess.run([
                "ip", "link", "add", name, "type", "veth", "peer", "name", peer_name
            ], check=True)
            
            # Move peer to namespace
            subprocess.run([
                "ip", "link", "set", peer_name, "netns", namespace
            ], check=True)
            
            # Bring up interfaces
            subprocess.run(["ip", "link", "set", name, "up"], check=True)
            subprocess.run([
                "ip", "netns", "exec", namespace, "ip", "link", "set", peer_name, "up"
            ], check=True)
            
            self.interfaces.append(name)
            self.logger.info(f"Created virtual interface {name} in namespace {namespace}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to create virtual interface {name}: {e}")
            return False
    
    def delete_virtual_interface(self, name: str) -> bool:
        """Delete a virtual network interface"""
        try:
            if name not in self.interfaces:
                self.logger.warning(f"Interface {name} does not exist")
                return True
                
            subprocess.run(["ip", "link", "delete", name], check=True)
            self.interfaces.remove(name)
            self.logger.info(f"Deleted virtual interface: {name}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to delete interface {name}: {e}")
            return False
    
    def setup_packet_capture(self, interface: str, namespace: str) -> bool:
        """Setup packet capture capability for an interface"""
        try:
            # Enable promiscuous mode
            subprocess.run([
                "ip", "netns", "exec", namespace,
                "ip", "link", "set", interface, "promisc", "on"
            ], check=True)
            
            # Enable packet capture
            subprocess.run([
                "ip", "netns", "exec", namespace,
                "tcpdump", "-i", interface, "-w", f"capture_{interface}.pcap"
            ], check=True, capture_output=True)
            
            self.logger.info(f"Setup packet capture for interface {interface}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to setup packet capture for {interface}: {e}")
            return False
    
    def _namespace_exists(self, name: str) -> bool:
        """Check if a network namespace exists"""
        try:
            subprocess.run(["ip", "netns", "list"], check=True, capture_output=True)
            return name in self.namespaces
        except subprocess.CalledProcessError:
            return False
    
    def cleanup(self) -> None:
        """Cleanup all created namespaces and interfaces"""
        for interface in self.interfaces[:]:
            self.delete_virtual_interface(interface)
            
        for namespace in self.namespaces[:]:
            self.delete_namespace(namespace)
            
        self.logger.info("Cleaned up all network resources") 