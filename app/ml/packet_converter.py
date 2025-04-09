"""
Packet converter for ARPGuard.

This module provides functions for converting Scapy packets to formats
that can be used by the rule engine and ML components.
"""

from typing import Dict, Any, Optional, Union, List, Tuple
from datetime import datetime
import socket
import struct
import numpy as np

from app.utils.logger import get_logger

# Setup module logger
logger = get_logger("ml.packet_converter")

def convert_arp_packet(packet: Any) -> Dict[str, Any]:
    """
    Convert a Scapy ARP packet to a dictionary format.
    
    Args:
        packet: Scapy ARP packet
        
    Returns:
        Dictionary representation of the packet
    """
    try:
        # Check if this is a valid packet
        if not hasattr(packet, 'op') or not hasattr(packet, 'hwsrc'):
            logger.warning("Invalid packet format")
            return {}
            
        # Handle ARP packets
        if hasattr(packet, 'op') and packet.op is not None:
            # Basic ARP packet information
            converted = {
                "type": "arp",
                "timestamp": datetime.now(),
                "op": int(packet.op),  # 1=request, 2=reply
                "src_mac": packet.hwsrc.lower() if hasattr(packet, 'hwsrc') else None,
                "dst_mac": packet.hwdst.lower() if hasattr(packet, 'hwdst') else None,
                "src_ip": packet.psrc if hasattr(packet, 'psrc') else None,
                "dst_ip": packet.pdst if hasattr(packet, 'pdst') else None,
            }
            
            # Add source hardware type if available
            if hasattr(packet, 'hwtype'):
                converted["hw_type"] = int(packet.hwtype)
                
            # Add protocol type if available
            if hasattr(packet, 'ptype'):
                converted["proto_type"] = int(packet.ptype)
                
            # Add hardware size if available
            if hasattr(packet, 'hwlen'):
                converted["hw_len"] = int(packet.hwlen)
                
            # Add protocol size if available
            if hasattr(packet, 'plen'):
                converted["proto_len"] = int(packet.plen)
            
            return converted
            
        logger.warning("Packet is not an ARP packet")
        return {}
        
    except Exception as e:
        logger.error(f"Error converting packet: {e}")
        return {}
        
def extract_packet_features(packet_dict: Dict[str, Any]) -> np.ndarray:
    """
    Extract features from a packet dictionary for ML models.
    
    Args:
        packet_dict: Dictionary representation of a packet
        
    Returns:
        Numpy array of features
    """
    try:
        # Convert MAC addresses to numerical values
        src_mac_value = mac_to_int(packet_dict.get("src_mac", "00:00:00:00:00:00"))
        dst_mac_value = mac_to_int(packet_dict.get("dst_mac", "00:00:00:00:00:00"))
        
        # Convert IP addresses to numerical values
        src_ip_value = ip_to_int(packet_dict.get("src_ip", "0.0.0.0"))
        dst_ip_value = ip_to_int(packet_dict.get("dst_ip", "0.0.0.0"))
        
        # Create feature vector
        features = [
            packet_dict.get("op", 0),  # Operation (1=request, 2=reply)
            src_mac_value,             # Source MAC as int
            dst_mac_value,             # Destination MAC as int
            src_ip_value,              # Source IP as int
            dst_ip_value,              # Destination IP as int
            packet_dict.get("hw_type", 0),  # Hardware type
            packet_dict.get("proto_type", 0),  # Protocol type
            packet_dict.get("hw_len", 0),  # Hardware length
            packet_dict.get("proto_len", 0),  # Protocol length
            # Is gratuitous ARP (src_ip == dst_ip in ARP reply)
            1 if (packet_dict.get("op") == 2 and packet_dict.get("src_ip") == packet_dict.get("dst_ip")) else 0,
            # Is broadcast (dst_mac is broadcast)
            1 if packet_dict.get("dst_mac") == "ff:ff:ff:ff:ff:ff" else 0,
        ]
        
        return np.array(features, dtype=np.float32)
        
    except Exception as e:
        logger.error(f"Error extracting features: {e}")
        return np.zeros(11, dtype=np.float32)  # Return zeroes on error
        
def mac_to_int(mac_str: Optional[str]) -> int:
    """
    Convert a MAC address string to an integer.
    
    Args:
        mac_str: MAC address string (e.g., "00:11:22:33:44:55")
        
    Returns:
        Integer representation of the MAC address
    """
    if not mac_str:
        return 0
        
    try:
        # Remove separators and convert to integer
        mac_str = mac_str.replace(":", "").replace("-", "").replace(".", "")
        return int(mac_str, 16)
    except (ValueError, AttributeError):
        return 0
        
def ip_to_int(ip_str: Optional[str]) -> int:
    """
    Convert an IP address string to an integer.
    
    Args:
        ip_str: IP address string (e.g., "192.168.1.1")
        
    Returns:
        Integer representation of the IP address
    """
    if not ip_str:
        return 0
        
    try:
        # Convert string to packed binary, then to integer
        return struct.unpack("!I", socket.inet_aton(ip_str))[0]
    except (socket.error, struct.error):
        return 0
        
def int_to_ip(ip_int: int) -> str:
    """
    Convert an integer to an IP address string.
    
    Args:
        ip_int: Integer representation of an IP address
        
    Returns:
        IP address string
    """
    try:
        return socket.inet_ntoa(struct.pack("!I", ip_int))
    except (struct.error, ValueError, OverflowError):
        return "0.0.0.0"
        
def int_to_mac(mac_int: int) -> str:
    """
    Convert an integer to a MAC address string.
    
    Args:
        mac_int: Integer representation of a MAC address
        
    Returns:
        MAC address string
    """
    try:
        mac_hex = f"{mac_int:012x}"
        return ":".join(mac_hex[i:i+2] for i in range(0, 12, 2))
    except (ValueError, TypeError):
        return "00:00:00:00:00:00" 