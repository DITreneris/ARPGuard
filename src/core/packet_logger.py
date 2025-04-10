import logging
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from .arp_packet import ARPPacket

class ARPPacketLogger:
    """Handles logging of ARP packets and potential spoofing attempts."""
    
    def __init__(self, log_dir: str = "logs"):
        """
        Initialize the ARP packet logger.
        
        Args:
            log_dir: Directory to store log files
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Set up logging
        self.logger = logging.getLogger('arp_packet_logger')
        self.logger.setLevel(logging.INFO)
        
        # File handler for all packets
        self.packet_handler = logging.FileHandler(
            self.log_dir / 'arp_packets.log'
        )
        self.packet_handler.setLevel(logging.INFO)
        
        # File handler for alerts
        self.alert_handler = logging.FileHandler(
            self.log_dir / 'arp_alerts.log'
        )
        self.alert_handler.setLevel(logging.WARNING)
        
        # Add handlers to logger
        self.logger.addHandler(self.packet_handler)
        self.logger.addHandler(self.alert_handler)
        
        # Initialize packet storage
        self.packets: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []
        
    def log_packet(self, packet: ARPPacket, is_valid: bool = True) -> None:
        """
        Log an ARP packet.
        
        Args:
            packet: ARP packet to log
            is_valid: Whether the packet passed validation
        """
        packet_data = {
            'timestamp': packet.timestamp.isoformat(),
            'hardware_type': packet.hardware_type,
            'protocol_type': packet.protocol_type,
            'opcode': packet.opcode,
            'sender_mac': packet.sender_mac,
            'sender_ip': packet.sender_ip,
            'target_mac': packet.target_mac,
            'target_ip': packet.target_ip,
            'is_valid': is_valid
        }
        
        # Add to memory storage
        self.packets.append(packet_data)
        
        # Log to file
        self.logger.info(json.dumps(packet_data))
        
    def log_alert(self, packet: ARPPacket, reason: str) -> None:
        """
        Log an ARP spoofing alert.
        
        Args:
            packet: ARP packet that triggered the alert
            reason: Reason for the alert
        """
        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'packet': {
                'sender_mac': packet.sender_mac,
                'sender_ip': packet.sender_ip,
                'target_mac': packet.target_mac,
                'target_ip': packet.target_ip
            },
            'reason': reason
        }
        
        # Add to memory storage
        self.alerts.append(alert_data)
        
        # Log to file
        self.logger.warning(json.dumps(alert_data))
        
    def get_recent_packets(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent ARP packets.
        
        Args:
            limit: Maximum number of packets to return
            
        Returns:
            List of recent packet data
        """
        return self.packets[-limit:]
        
    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get recent ARP spoofing alerts.
        
        Args:
            limit: Maximum number of alerts to return
            
        Returns:
            List of recent alert data
        """
        return self.alerts[-limit:]
        
    def clear_old_data(self, max_age_days: int = 7) -> None:
        """
        Clear old packet and alert data.
        
        Args:
            max_age_days: Maximum age of data to keep in days
        """
        cutoff = datetime.now().timestamp() - (max_age_days * 86400)
        
        # Clear old packets
        self.packets = [
            p for p in self.packets
            if datetime.fromisoformat(p['timestamp']).timestamp() > cutoff
        ]
        
        # Clear old alerts
        self.alerts = [
            a for a in self.alerts
            if datetime.fromisoformat(a['timestamp']).timestamp() > cutoff
        ]
        
    def export_data(self, output_dir: str = None) -> None:
        """
        Export packet and alert data to JSON files.
        
        Args:
            output_dir: Directory to save export files
        """
        if output_dir is None:
            output_dir = self.log_dir / 'exports'
        else:
            output_dir = Path(output_dir)
            
        output_dir.mkdir(exist_ok=True)
        
        # Export packets
        with open(output_dir / 'packets.json', 'w') as f:
            json.dump(self.packets, f, indent=2)
            
        # Export alerts
        with open(output_dir / 'alerts.json', 'w') as f:
            json.dump(self.alerts, f, indent=2) 