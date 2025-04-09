"""
Feature extraction module for ARP packets.

This module extracts relevant features from ARP packets for machine learning analysis.
"""

import time
import math
import ipaddress
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

from app.utils.logger import get_logger

# Get module logger
logger = get_logger("ml.feature_extraction")

class FeatureExtractor:
    """Feature extractor for ARP packets.
    
    This class handles extraction of numerical features from ARP packets
    to be used in machine learning models.
    """
    
    def __init__(self):
        """Initialize the feature extractor."""
        # Keep track of recent traffic to calculate temporal features
        self.recent_packets = []
        self.max_recent_packets = 100
        self.packet_window = 30  # 30 second window
        
        # Keep track of IPs and MACs seen
        self.ip_mac_mappings = {}  # IP -> set of MACs
        self.mac_ip_mappings = {}  # MAC -> set of IPs
        
        # Special network prefixes
        self.special_prefixes = [
            "0.0.0.0/8",      # Current network
            "10.0.0.0/8",     # Private network
            "100.64.0.0/10",  # Carrier-grade NAT
            "127.0.0.0/8",    # Localhost
            "169.254.0.0/16", # Link-local
            "172.16.0.0/12",  # Private network
            "192.0.0.0/24",   # IETF Protocol assignments
            "192.0.2.0/24",   # Documentation (TEST-NET-1)
            "192.88.99.0/24", # 6to4 Relay Anycast
            "192.168.0.0/16", # Private network
            "198.18.0.0/15",  # Network benchmark tests
            "198.51.100.0/24",# Documentation (TEST-NET-2)
            "203.0.113.0/24", # Documentation (TEST-NET-3)
            "224.0.0.0/4",    # Multicast
            "240.0.0.0/4",    # Reserved
            "255.255.255.255/32" # Broadcast
        ]
        self.special_networks = [ipaddress.ip_network(prefix) for prefix in self.special_prefixes]
        
    def extract_features(self, packet: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from an ARP packet.
        
        Args:
            packet: Dictionary containing ARP packet data
            
        Returns:
            Dictionary of numerical features
        """
        features = {}
        
        try:
            # Basic packet features
            features.update(self._extract_basic_features(packet))
            
            # Add to recent packets for temporal features
            self._update_recent_packets(packet)
            
            # IP/MAC mappings for relationship features
            self._update_ip_mac_mappings(packet)
            
            # Temporal features
            features.update(self._extract_temporal_features(packet))
            
            # IP/MAC relationship features
            features.update(self._extract_relationship_features(packet))
            
            # Network and subnet features
            features.update(self._extract_network_features(packet))
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            
        return features
    
    def _extract_basic_features(self, packet: Dict[str, Any]) -> Dict[str, float]:
        """Extract basic features from the packet.
        
        Args:
            packet: ARP packet dictionary
            
        Returns:
            Dictionary of basic features
        """
        features = {}
        
        # Extract operation type (request=1, reply=2)
        features["operation"] = float(packet.get("op", 0))
        
        # Is operation valid?
        features["is_valid_operation"] = 1.0 if packet.get("op") in [1, 2] else 0.0
        
        # Is a broadcast request?
        is_broadcast_dst = packet.get("dst_mac", "") == "ff:ff:ff:ff:ff:ff"
        features["is_broadcast"] = 1.0 if is_broadcast_dst else 0.0
        
        # Is a reply to broadcast?
        features["is_reply_to_broadcast"] = 1.0 if packet.get("op") == 2 and is_broadcast_dst else 0.0
        
        # Are source MAC and target MAC the same? (unusual)
        src_mac = packet.get("src_mac", "").lower()
        dst_mac = packet.get("dst_mac", "").lower()
        features["src_dst_mac_same"] = 1.0 if src_mac == dst_mac and src_mac != "" else 0.0
        
        # Are source IP and target IP the same? (unusual for regular ARP)
        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")
        features["src_dst_ip_same"] = 1.0 if src_ip == dst_ip and src_ip != "" else 0.0
        
        # Is it a gratuitous ARP? (sending to self)
        features["is_gratuitous"] = 1.0 if src_ip == dst_ip and src_ip != "" else 0.0
        
        # Hardware/protocol types and lengths (usually constant, but can be anomalous)
        features["hw_type"] = float(packet.get("hw_type", 1))  # Usually 1 for Ethernet
        features["proto_type"] = float(packet.get("proto_type", 0x0800)) / 65535.0  # Usually 0x0800 for IPv4
        features["hw_len"] = float(packet.get("hw_len", 6))    # Usually 6 for MAC address
        features["proto_len"] = float(packet.get("proto_len", 4))  # Usually 4 for IPv4
        
        # Is hw_type valid? (1 for Ethernet)
        features["is_valid_hw_type"] = 1.0 if features["hw_type"] == 1 else 0.0
        
        # Is proto_type valid? (0x0800 for IPv4)
        features["is_valid_proto_type"] = 1.0 if abs(features["proto_type"] - 0x0800/65535.0) < 0.001 else 0.0
        
        # Is packet complete? (has all required fields)
        has_required = all(k in packet for k in ["op", "src_mac", "dst_mac", "src_ip", "dst_ip"])
        features["is_complete"] = 1.0 if has_required else 0.0
        
        return features
    
    def _update_recent_packets(self, packet: Dict[str, Any]):
        """Update the recent packets buffer.
        
        Args:
            packet: Current packet
        """
        # Get current time
        now = datetime.now().timestamp() if "timestamp" not in packet else \
              packet["timestamp"].timestamp() if isinstance(packet["timestamp"], datetime) else \
              float(packet["timestamp"])
        
        # Add packet with timestamp
        packet_copy = packet.copy()
        if "timestamp" not in packet_copy:
            packet_copy["timestamp"] = now
            
        self.recent_packets.append(packet_copy)
        
        # Remove old packets outside window
        self.recent_packets = [
            p for p in self.recent_packets 
            if now - (p["timestamp"].timestamp() if isinstance(p["timestamp"], datetime) 
                     else float(p["timestamp"])) <= self.packet_window
        ]
        
        # Limit size
        if len(self.recent_packets) > self.max_recent_packets:
            self.recent_packets = self.recent_packets[-self.max_recent_packets:]
    
    def _update_ip_mac_mappings(self, packet: Dict[str, Any]):
        """Update IP to MAC and MAC to IP mappings.
        
        Args:
            packet: Current packet
        """
        src_ip = packet.get("src_ip")
        src_mac = packet.get("src_mac")
        
        if src_ip and src_mac:
            # Update IP -> MAC mapping
            if src_ip not in self.ip_mac_mappings:
                self.ip_mac_mappings[src_ip] = set()
            self.ip_mac_mappings[src_ip].add(src_mac)
            
            # Update MAC -> IP mapping
            if src_mac not in self.mac_ip_mappings:
                self.mac_ip_mappings[src_mac] = set()
            self.mac_ip_mappings[src_mac].add(src_ip)
    
    def _extract_temporal_features(self, packet: Dict[str, Any]) -> Dict[str, float]:
        """Extract temporal features from recent packet history.
        
        Args:
            packet: Current packet
            
        Returns:
            Dictionary of temporal features
        """
        features = {}
        
        if not self.recent_packets:
            # Default values for no history
            features["packet_rate"] = 0.0
            features["request_rate"] = 0.0
            features["reply_rate"] = 0.0
            features["src_mac_freq"] = 0.0
            features["src_ip_freq"] = 0.0
            features["unique_ip_count"] = 0.0
            features["unique_mac_count"] = 0.0
            features["request_reply_ratio"] = 0.5  # Neutral value
            return features
            
        # Get current values
        src_mac = packet.get("src_mac", "").lower()
        src_ip = packet.get("src_ip", "")
        
        # Time window
        now = datetime.now().timestamp() if "timestamp" not in packet else \
              packet["timestamp"].timestamp() if isinstance(packet["timestamp"], datetime) else \
              float(packet["timestamp"])
        
        oldest_time = min(
            p["timestamp"].timestamp() if isinstance(p["timestamp"], datetime) 
            else float(p["timestamp"]) 
            for p in self.recent_packets
        )
        
        time_window = max(now - oldest_time, 1.0)  # Avoid division by zero
        
        # Packet rate
        features["packet_rate"] = len(self.recent_packets) / time_window
        
        # Request/reply counts
        request_count = sum(1 for p in self.recent_packets if p.get("op") == 1)
        reply_count = sum(1 for p in self.recent_packets if p.get("op") == 2)
        
        # Request/reply rates
        features["request_rate"] = request_count / time_window
        features["reply_rate"] = reply_count / time_window
        
        # Request/reply ratio
        total = request_count + reply_count
        features["request_reply_ratio"] = request_count / total if total > 0 else 0.5
        
        # Frequency of current source MAC
        if src_mac:
            src_mac_count = sum(1 for p in self.recent_packets if p.get("src_mac", "").lower() == src_mac)
            features["src_mac_freq"] = src_mac_count / len(self.recent_packets)
        else:
            features["src_mac_freq"] = 0.0
            
        # Frequency of current source IP
        if src_ip:
            src_ip_count = sum(1 for p in self.recent_packets if p.get("src_ip") == src_ip)
            features["src_ip_freq"] = src_ip_count / len(self.recent_packets)
        else:
            features["src_ip_freq"] = 0.0
            
        # Unique IP and MAC counts (normalized)
        unique_ips = set(p.get("src_ip") for p in self.recent_packets if p.get("src_ip"))
        unique_macs = set(p.get("src_mac", "").lower() for p in self.recent_packets if p.get("src_mac"))
        
        features["unique_ip_count"] = len(unique_ips) / len(self.recent_packets)
        features["unique_mac_count"] = len(unique_macs) / len(self.recent_packets)
        
        return features
    
    def _extract_relationship_features(self, packet: Dict[str, Any]) -> Dict[str, float]:
        """Extract features related to IP/MAC relationships.
        
        Args:
            packet: Current packet
            
        Returns:
            Dictionary of relationship features
        """
        features = {}
        
        src_ip = packet.get("src_ip")
        src_mac = packet.get("src_mac")
        
        # Multiple MACs for this IP?
        if src_ip and src_ip in self.ip_mac_mappings:
            features["ip_mac_count"] = len(self.ip_mac_mappings[src_ip])
        else:
            features["ip_mac_count"] = 0.0
            
        # Multiple IPs for this MAC?
        if src_mac and src_mac in self.mac_ip_mappings:
            features["mac_ip_count"] = len(self.mac_ip_mappings[src_mac])
        else:
            features["mac_ip_count"] = 0.0
            
        # Is this a new IP -> MAC mapping?
        if src_ip and src_mac:
            features["is_new_mapping"] = 0.0
            if src_ip in self.ip_mac_mappings:
                features["is_new_mapping"] = 1.0 if src_mac not in self.ip_mac_mappings[src_ip] else 0.0
            else:
                features["is_new_mapping"] = 1.0  # First time seeing this IP
        else:
            features["is_new_mapping"] = 0.0
            
        # Normalize the counts (capped at 10)
        features["ip_mac_count"] = min(features["ip_mac_count"], 10.0) / 10.0
        features["mac_ip_count"] = min(features["mac_ip_count"], 10.0) / 10.0
        
        return features
    
    def _extract_network_features(self, packet: Dict[str, Any]) -> Dict[str, float]:
        """Extract features related to network properties.
        
        Args:
            packet: Current packet
            
        Returns:
            Dictionary of network features
        """
        features = {}
        
        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")
        
        # Check if IPs are in special networks
        features["src_is_special"] = 0.0
        features["dst_is_special"] = 0.0
        features["src_dst_same_subnet"] = 0.0
        
        try:
            if src_ip:
                src_ip_obj = ipaddress.ip_address(src_ip)
                for network in self.special_networks:
                    if src_ip_obj in network:
                        features["src_is_special"] = 1.0
                        break
                        
            if dst_ip:
                dst_ip_obj = ipaddress.ip_address(dst_ip)
                for network in self.special_networks:
                    if dst_ip_obj in network:
                        features["dst_is_special"] = 1.0
                        break
                        
            # Are source and destination in same subnet?
            if src_ip and dst_ip:
                src_prefix = src_ip.rsplit('.', 1)[0]
                dst_prefix = dst_ip.rsplit('.', 1)[0]
                features["src_dst_same_subnet"] = 1.0 if src_prefix == dst_prefix else 0.0
                
        except (ValueError, ipaddress.AddressValueError):
            # If IP address parsing fails, leave defaults
            pass
            
        return features 