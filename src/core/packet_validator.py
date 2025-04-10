import logging
from typing import Dict, Optional
from datetime import datetime, timedelta
from .arp_packet import ARPPacket

class ARPPacketValidator:
    """Validates ARP packets for potential spoofing attempts."""
    
    def __init__(self):
        """Initialize the ARP packet validator."""
        self.mac_ip_bindings: Dict[str, str] = {}  # MAC -> IP mapping
        self.last_seen: Dict[str, datetime] = {}   # MAC -> last seen timestamp
        self.logger = logging.getLogger('arp_packet_validator')
        
    def validate_packet(self, packet: ARPPacket) -> bool:
        """
        Validate an ARP packet for potential spoofing.
        
        Args:
            packet: ARP packet to validate
            
        Returns:
            True if packet is valid, False if potential spoofing detected
        """
        try:
            # Check if this is a new MAC-IP binding
            if packet.sender_mac not in self.mac_ip_bindings:
                self._add_new_binding(packet.sender_mac, packet.sender_ip)
                return True
                
            # Check for MAC-IP binding changes
            if self.mac_ip_bindings[packet.sender_mac] != packet.sender_ip:
                self.logger.warning(
                    f"Potential ARP spoofing detected: "
                    f"MAC {packet.sender_mac} changed IP from "
                    f"{self.mac_ip_bindings[packet.sender_mac]} to {packet.sender_ip}"
                )
                return False
                
            # Update last seen timestamp
            self.last_seen[packet.sender_mac] = packet.timestamp
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating packet: {e}")
            return False
            
    def _add_new_binding(self, mac: str, ip: str) -> None:
        """
        Add a new MAC-IP binding to the validator.
        
        Args:
            mac: MAC address
            ip: IP address
        """
        self.mac_ip_bindings[mac] = ip
        self.last_seen[mac] = datetime.now()
        self.logger.info(f"Added new MAC-IP binding: {mac} -> {ip}")
        
    def cleanup_old_bindings(self, max_age: timedelta = timedelta(hours=24)) -> None:
        """
        Remove old MAC-IP bindings that haven't been seen recently.
        
        Args:
            max_age: Maximum age of bindings to keep
        """
        current_time = datetime.now()
        old_bindings = [
            mac for mac, last_seen in self.last_seen.items()
            if current_time - last_seen > max_age
        ]
        
        for mac in old_bindings:
            del self.mac_ip_bindings[mac]
            del self.last_seen[mac]
            self.logger.info(f"Removed old binding for MAC: {mac}")
            
    def get_binding(self, mac: str) -> Optional[str]:
        """
        Get the IP address bound to a MAC address.
        
        Args:
            mac: MAC address to look up
            
        Returns:
            IP address if found, None otherwise
        """
        return self.mac_ip_bindings.get(mac)
        
    def get_all_bindings(self) -> Dict[str, str]:
        """
        Get all current MAC-IP bindings.
        
        Returns:
            Dictionary of MAC -> IP bindings
        """
        return self.mac_ip_bindings.copy() 