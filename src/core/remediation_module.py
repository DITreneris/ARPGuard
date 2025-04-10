#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Remediation Module for ARP Guard

This module provides functionality to automatically respond to detected ARP spoofing attacks
by implementing various remediation strategies.
"""

import logging
import subprocess
import platform
from typing import Dict, List, Optional, Union
from dataclasses import dataclass, field
import time
import threading
from .module_interface import Module, ModuleConfig
import json
import os
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class RemediationConfig(ModuleConfig):
    """Configuration for remediation actions."""
    enabled: bool = True
    auto_block: bool = True
    block_duration: int = 1800  # 30 minutes in seconds
    notify_admin: bool = True
    notification_email: str = ""
    notification_threshold: int = 3
    whitelist: List[str] = field(default_factory=list)  # Format: "MAC:IP"
    blocked_hosts: Dict[str, Dict] = field(default_factory=dict)  # MAC -> {ip, reason, timestamp}

class RemediationModule(Module):
    """Module for handling automated remediation of ARP spoofing attacks."""
    
    def __init__(self, config: Optional[RemediationConfig] = None):
        """Initialize the remediation module.
        
        Args:
            config: Optional configuration for the module
        """
        super().__init__("remediation", "ARP Spoofing Remediation", config or RemediationConfig())
        self.os_platform = platform.system().lower()
        self._load_config()
        self._cleanup_expired_blocks()
        
    def _load_config(self) -> None:
        """Load configuration from file if exists."""
        config_path = os.path.join("config", "remediation_config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    data = json.load(f)
                    for key, value in data.items():
                        if hasattr(self.config, key):
                            setattr(self.config, key, value)
            except Exception as e:
                logger.error(f"Error loading remediation config: {e}")
                
    def _save_config(self) -> None:
        """Save current configuration to file."""
        try:
            os.makedirs("config", exist_ok=True)
            config_path = os.path.join("config", "remediation_config.json")
            with open(config_path, 'w') as f:
                json.dump(self.config.__dict__, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving remediation config: {e}")
            
    def _cleanup_expired_blocks(self) -> None:
        """Remove expired blocked hosts."""
        current_time = datetime.now()
        expired = []
        
        for mac, info in self.config.blocked_hosts.items():
            block_time = datetime.fromtimestamp(info['timestamp'])
            if current_time - block_time > timedelta(seconds=self.config.block_duration):
                expired.append(mac)
                
        for mac in expired:
            del self.config.blocked_hosts[mac]
            logger.info(f"Removed expired block for {mac}")
            
    def initialize(self) -> bool:
        """Initialize the remediation module."""
        try:
            logger.info("Initializing remediation module")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize remediation module: {e}")
            return False
    
    def shutdown(self) -> bool:
        """Shutdown the remediation module."""
        try:
            logger.info("Shutting down remediation module")
            # Unblock all blocked hosts
            self._unblock_all_hosts()
            return True
        except Exception as e:
            logger.error(f"Failed to shutdown remediation module: {e}")
            return False
    
    def handle_detection(self, mac_address: str, ip_address: str, threat_level: str, details: Dict) -> bool:
        """Handle a detection event with optimized decision making.
        
        Args:
            mac_address: MAC address of detected host
            ip_address: IP address of detected host
            threat_level: Threat level (low, medium, high)
            details: Additional detection details
            
        Returns:
            True if handled successfully, False otherwise
        """
        # Fast path: Skip for whitelisted hosts
        if self._is_whitelisted_fast(mac_address, ip_address):
            return True
            
        # Track detection count for throttling notifications
        if not hasattr(self, '_detection_count'):
            self._detection_count = {}
            
        current_time = time.time()
        
        # Update detection count
        if mac_address not in self._detection_count:
            self._detection_count[mac_address] = {'count': 0, 'last_notification': 0}
            
        self._detection_count[mac_address]['count'] += 1
        
        # Handle based on threat level
        if threat_level == "high" and self.config.auto_block:
            reason = f"High threat level detection: {details.get('reason', 'Unknown')}"
            return self.block_host(mac_address, ip_address, reason)
            
        # Throttle notifications to reduce spam
        if self.config.notify_admin:
            # Only notify if threshold reached and we haven't notified in the last 10 minutes
            if (self._detection_count[mac_address]['count'] >= self.config.notification_threshold and
                current_time - self._detection_count[mac_address]['last_notification'] > 600):
                
                self._send_notification(mac_address, ip_address, threat_level, details)
                self._detection_count[mac_address]['last_notification'] = current_time
                
        return True
    
    def _block_host_linux(self, mac_address: str, ip_address: str) -> bool:
        """Block a host on Linux using iptables.
        
        Args:
            mac_address: MAC address to block
            ip_address: IP address to block
            
        Returns:
            True if blocked successfully, False otherwise
        """
        try:
            # Block by MAC address
            subprocess.run(['iptables', '-A', 'INPUT', '-m', 'mac', '--mac-source', mac_address, '-j', 'DROP'], check=True)
            subprocess.run(['iptables', '-A', 'FORWARD', '-m', 'mac', '--mac-source', mac_address, '-j', 'DROP'], check=True)
            
            # Block by IP address
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'], check=True)
            subprocess.run(['iptables', '-A', 'FORWARD', '-s', ip_address, '-j', 'DROP'], check=True)
            
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block host using iptables: {e}")
            return False
            
    def _block_host_windows(self, mac_address: str, ip_address: str) -> bool:
        """Block a host on Windows using Windows Firewall.
        
        Args:
            mac_address: MAC address to block
            ip_address: IP address to block
            
        Returns:
            True if blocked successfully, False otherwise
        """
        try:
            # Create firewall rule to block the IP
            rule_name = f"ARP_Guard_Block_{mac_address.replace(':', '_')}"
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name="{rule_name}"',
                'dir=in',
                'action=block',
                f'remoteip={ip_address}',
                'protocol=any'
            ], check=True)
            
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block host using Windows Firewall: {e}")
            return False
            
    def _unblock_host_linux(self, mac_address: str, ip_address: str) -> bool:
        """Unblock a host on Linux.
        
        Args:
            mac_address: MAC address to unblock
            ip_address: IP address to unblock
            
        Returns:
            True if unblocked successfully, False otherwise
        """
        try:
            # Remove MAC-based rules
            subprocess.run(['iptables', '-D', 'INPUT', '-m', 'mac', '--mac-source', mac_address, '-j', 'DROP'], check=True)
            subprocess.run(['iptables', '-D', 'FORWARD', '-m', 'mac', '--mac-source', mac_address, '-j', 'DROP'], check=True)
            
            # Remove IP-based rules
            subprocess.run(['iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'], check=True)
            subprocess.run(['iptables', '-D', 'FORWARD', '-s', ip_address, '-j', 'DROP'], check=True)
            
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unblock host using iptables: {e}")
            return False
            
    def _unblock_host_windows(self, mac_address: str) -> bool:
        """Unblock a host on Windows.
        
        Args:
            mac_address: MAC address to unblock
            
        Returns:
            True if unblocked successfully, False otherwise
        """
        try:
            rule_name = f"ARP_Guard_Block_{mac_address.replace(':', '_')}"
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name="{rule_name}"'
            ], check=True)
            
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unblock host using Windows Firewall: {e}")
            return False
            
    def _send_notification(self, mac_address: str, ip_address: str, threat_level: str, details: Dict) -> None:
        """Send notification about detected attack.
        
        Args:
            mac_address: MAC address of attacker
            ip_address: IP address of attacker
            threat_level: Level of threat
            details: Additional detection details
        """
        if not self.config.notification_email:
            return
            
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = 'arp_guard@localhost'
            msg['To'] = self.config.notification_email
            msg['Subject'] = f'ARP Guard Alert: {threat_level} Threat Detected'
            
            # Create email body
            body = f"""
            ARP Guard has detected a potential ARP spoofing attack:
            
            Threat Level: {threat_level}
            MAC Address: {mac_address}
            IP Address: {ip_address}
            Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            
            Details:
            {json.dumps(details, indent=2)}
            
            Action taken: {'Blocked' if threat_level == 'high' else 'Monitored'}
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            with smtplib.SMTP('localhost') as server:
                server.send_message(msg)
                
            logger.info(f"Notification sent to {self.config.notification_email}")
            
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")
            
    def block_host(self, mac_address: str, ip_address: str, reason: str) -> bool:
        """Block a host from the network.
        
        Args:
            mac_address: MAC address to block
            ip_address: IP address to block
            reason: Reason for blocking
            
        Returns:
            True if blocked successfully, False otherwise
        """
        # Fast path: Check if already blocked
        if mac_address in self.config.blocked_hosts:
            # Update reason if needed
            if self.config.blocked_hosts[mac_address]['reason'] != reason:
                self.config.blocked_hosts[mac_address]['reason'] = reason
                # No need to save config for just a reason update
            logger.info(f"Host {mac_address} already blocked")
            return True
            
        # Fast path: Check whitelist with O(1) lookup
        if self._is_whitelisted_fast(mac_address, ip_address):
            logger.info(f"Not blocking whitelisted host {mac_address} ({ip_address})")
            return False
            
        try:
            # Block based on OS with optimized rule creation
            success = False
            if self.os_platform == 'linux':
                success = self._block_host_linux_optimized(mac_address, ip_address)
            elif self.os_platform == 'windows':
                success = self._block_host_windows_optimized(mac_address, ip_address)
            else:
                logger.error(f"Unsupported platform: {self.os_platform}")
                return False
                
            if not success:
                return False
                
            # Record the blocked host
            self.config.blocked_hosts[mac_address] = {
                'ip_address': ip_address,
                'reason': reason,
                'timestamp': time.time()
            }
            
            # Only save config periodically or when we have significant changes
            self._schedule_config_save()
            
            # Schedule unblocking with optimized timer management
            if self.config.block_duration > 0:
                self._schedule_unblock(mac_address, self.config.block_duration)
                
            return True
            
        except Exception as e:
            logger.error(f"Failed to block host {mac_address}: {e}")
            return False
            
    def _block_host_linux_optimized(self, mac_address: str, ip_address: str) -> bool:
        """Optimized host blocking on Linux.
        
        Args:
            mac_address: MAC address to block
            ip_address: IP address to block
            
        Returns:
            True if blocked successfully, False otherwise
        """
        try:
            # Batch iptables commands for better performance
            commands = [
                f"iptables -A INPUT -m mac --mac-source {mac_address} -j DROP",
                f"iptables -A FORWARD -m mac --mac-source {mac_address} -j DROP",
                f"iptables -A INPUT -s {ip_address} -j DROP",
                f"iptables -A FORWARD -s {ip_address} -j DROP"
            ]
            
            # Use shell=True to execute commands in a batch
            script = " && ".join(commands)
            result = subprocess.run(script, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"Failed to block host using iptables: {result.stderr}")
                return False
                
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block host using iptables: {e}")
            return False
            
    def _block_host_windows_optimized(self, mac_address: str, ip_address: str) -> bool:
        """Optimized host blocking on Windows.
        
        Args:
            mac_address: MAC address to block
            ip_address: IP address to block
            
        Returns:
            True if blocked successfully, False otherwise
        """
        try:
            # Use more efficient rule naming with shorter names
            rule_name = f"ARP_Guard_{mac_address.replace(':', '')[:8]}"
            
            # Create a temporary batch file for better performance
            batch_file = os.path.join(os.environ.get('TEMP', '.'), f"arpguard_block_{int(time.time())}.bat")
            with open(batch_file, 'w') as f:
                f.write(f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address} protocol=any\n')
                
            # Execute batch file
            result = subprocess.run(f"cmd /c {batch_file}", shell=True, capture_output=True, text=True)
            
            # Clean up batch file
            try:
                os.remove(batch_file)
            except:
                pass
                
            if result.returncode != 0:
                logger.error(f"Failed to block host using Windows Firewall: {result.stderr}")
                return False
                
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block host using Windows Firewall: {e}")
            return False
            
    def _is_whitelisted_fast(self, mac: str, ip: str) -> bool:
        """Optimized whitelist checking with O(1) lookup.
        
        Args:
            mac: MAC address
            ip: IP address
            
        Returns:
            True if whitelisted, False otherwise
        """
        # Use a set for O(1) lookup
        if not hasattr(self, '_whitelist_set'):
            self._rebuild_whitelist_set()
            
        # Check if entry is in whitelist set
        entry = f"{mac}:{ip}"
        return entry in self._whitelist_set
        
    def _rebuild_whitelist_set(self) -> None:
        """Rebuild whitelist set for optimized lookups."""
        self._whitelist_set = set(self.config.whitelist)
        
    def _schedule_config_save(self) -> None:
        """Schedule a delayed config save to reduce disk I/O."""
        if hasattr(self, '_save_timer') and self._save_timer:
            # Timer already scheduled, nothing to do
            return
            
        self._save_timer = threading.Timer(5.0, self._delayed_save_config)
        self._save_timer.daemon = True
        self._save_timer.start()
        
    def _delayed_save_config(self) -> None:
        """Delayed config save to batch multiple changes."""
        self._save_config()
        self._save_timer = None
        
    def _schedule_unblock(self, mac_address: str, duration: int) -> None:
        """Schedule host unblocking with optimized timer management.
        
        Args:
            mac_address: MAC address to unblock
            duration: Duration in seconds
        """
        # Only create a new timer if needed
        if not hasattr(self, '_unblock_timers'):
            self._unblock_timers = {}
            
        # Cancel existing timer if any
        if mac_address in self._unblock_timers and self._unblock_timers[mac_address]:
            self._unblock_timers[mac_address].cancel()
            
        # Schedule new timer
        timer = threading.Timer(duration, self.unblock_host, args=[mac_address])
        timer.daemon = True
        timer.start()
        self._unblock_timers[mac_address] = timer
        
    def unblock_host(self, mac_address: str) -> bool:
        """Unblock a host from the network.
        
        Args:
            mac_address: MAC address to unblock
            
        Returns:
            True if unblocked successfully, False otherwise
        """
        if mac_address not in self.config.blocked_hosts:
            logger.warning(f"Host {mac_address} is not blocked")
            return False
            
        try:
            info = self.config.blocked_hosts[mac_address]
            
            # Unblock based on OS
            if self.os_platform == 'linux':
                success = self._unblock_host_linux(mac_address, info['ip_address'])
            elif self.os_platform == 'windows':
                success = self._unblock_host_windows(mac_address)
            else:
                logger.error(f"Unsupported platform: {self.os_platform}")
                return False
                
            if not success:
                return False
                
            del self.config.blocked_hosts[mac_address]
            self._save_config()
            return True
            
        except Exception as e:
            logger.error(f"Failed to unblock host {mac_address}: {e}")
            return False
    
    def _unblock_all_hosts(self) -> None:
        """Unblock all currently blocked hosts."""
        for mac_address in list(self.config.blocked_hosts.keys()):
            self.unblock_host(mac_address)
    
    def get_status(self) -> Dict:
        """Get the current status of the remediation module.
        
        Returns:
            Dictionary containing status information
        """
        return {
            'enabled': self.config.enabled,
            'auto_block': self.config.auto_block,
            'block_duration': self.config.block_duration,
            'notify_admin': self.config.notify_admin,
            'notification_email': self.config.notification_email,
            'notification_threshold': self.config.notification_threshold,
            'whitelist_count': len(self.config.whitelist),
            'blocked_hosts_count': len(self.config.blocked_hosts)
        }
    
    def get_blocked_hosts(self) -> List[Dict]:
        """Get list of currently blocked hosts.
        
        Returns:
            List of dictionaries containing blocked host information
        """
        return [
            {
                'mac_address': mac,
                'ip_address': info['ip_address'],
                'reason': info['reason'],
                'blocked_at': datetime.fromtimestamp(info['timestamp']).isoformat(),
                'expires_at': (datetime.fromtimestamp(info['timestamp']) + 
                             timedelta(seconds=self.config.block_duration)).isoformat()
            }
            for mac, info in self.config.blocked_hosts.items()
        ] 