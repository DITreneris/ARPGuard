import socket
import struct
import logging
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ARPPacket:
    """Represents an ARP packet with all relevant fields."""
    hardware_type: int
    protocol_type: int
    hardware_size: int
    protocol_size: int
    opcode: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str
    timestamp: datetime

class ARPPacketAnalyzer:
    """Handles ARP packet capture and analysis."""
    
    def __init__(self, interface: str = None):
        """
        Initialize the ARP packet analyzer.
        
        Args:
            interface: Network interface to capture packets from
        """
        self.interface = interface
        self.socket = None
        self.logger = logging.getLogger('arp_packet_analyzer')
        
    def start_capture(self) -> None:
        """Start capturing ARP packets."""
        try:
            # Create raw socket
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            if self.interface:
                self.socket.bind((self.interface, 0))
            self.logger.info(f"Started ARP packet capture on interface {self.interface or 'all'}")
        except Exception as e:
            self.logger.error(f"Failed to start packet capture: {e}")
            raise

    def stop_capture(self) -> None:
        """Stop capturing ARP packets."""
        if self.socket:
            self.socket.close()
            self.socket = None
            self.logger.info("Stopped ARP packet capture")

    def parse_arp_packet(self, packet: bytes) -> Optional[ARPPacket]:
        """
        Parse raw packet data into ARPPacket object.
        
        Args:
            packet: Raw packet data
            
        Returns:
            ARPPacket object if valid ARP packet, None otherwise
        """
        try:
            # Ethernet header is 14 bytes
            eth_header = packet[:14]
            eth_protocol = struct.unpack('!H', eth_header[12:14])[0]
            
            # Check if it's an ARP packet (0x0806)
            if eth_protocol != 0x0806:
                return None
                
            # ARP packet starts after Ethernet header
            arp_packet = packet[14:]
            
            # Parse ARP header
            hardware_type = struct.unpack('!H', arp_packet[0:2])[0]
            protocol_type = struct.unpack('!H', arp_packet[2:4])[0]
            hardware_size = arp_packet[4]
            protocol_size = arp_packet[5]
            opcode = struct.unpack('!H', arp_packet[6:8])[0]
            
            # Parse MAC and IP addresses
            sender_mac = ':'.join(f'{b:02x}' for b in arp_packet[8:14])
            sender_ip = socket.inet_ntoa(arp_packet[14:18])
            target_mac = ':'.join(f'{b:02x}' for b in arp_packet[18:24])
            target_ip = socket.inet_ntoa(arp_packet[24:28])
            
            return ARPPacket(
                hardware_type=hardware_type,
                protocol_type=protocol_type,
                hardware_size=hardware_size,
                protocol_size=protocol_size,
                opcode=opcode,
                sender_mac=sender_mac,
                sender_ip=sender_ip,
                target_mac=target_mac,
                target_ip=target_ip,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            self.logger.error(f"Failed to parse ARP packet: {e}")
            return None

    def capture_packets(self) -> None:
        """Continuously capture and process ARP packets."""
        while self.socket:
            try:
                packet = self.socket.recv(65535)
                arp_packet = self.parse_arp_packet(packet)
                if arp_packet:
                    self._process_packet(arp_packet)
            except Exception as e:
                self.logger.error(f"Error capturing packet: {e}")

    def _process_packet(self, packet: ARPPacket) -> None:
        """
        Process a parsed ARP packet.
        
        Args:
            packet: Parsed ARP packet
        """
        # Log the packet details
        self.logger.info(
            f"ARP Packet: {packet.opcode} "
            f"Sender: {packet.sender_mac} ({packet.sender_ip}) "
            f"Target: {packet.target_mac} ({packet.target_ip})"
        )
        
        # TODO: Add packet validation and analysis logic 