"""
Context tracker for rule-based detection in ARPGuard.

This module maintains the network state and historical data needed
for effective rule-based detection of ARP-based attacks.
"""

import time
from datetime import datetime, timedelta
from collections import deque, defaultdict
from threading import Lock
from typing import Dict, List, Any, Optional, Set, Deque, Tuple

from app.utils.logger import get_logger

# Setup module logger
logger = get_logger("ml.context_tracker")

class ContextTracker:
    """
    Tracks network context for rule-based detection.
    
    This class maintains historical data and network state information
    that rules need to evaluate packets effectively.
    """
    
    def __init__(self, history_window: int = 300):
        """
        Initialize the context tracker.
        
        Args:
            history_window: Number of seconds to maintain history for
        """
        self.history_window = history_window
        self.lock = Lock()
        
        # Maps IP -> MAC
        self.ip_mac_map = {}
        
        # Maps MAC -> set of IPs
        self.mac_ip_map = defaultdict(set)
        
        # Maps MAC -> timestamp -> packet count
        self.packet_history = defaultdict(lambda: defaultdict(int))
        
        # Recent packets for each MAC (sliding window)
        self.recent_packets = defaultdict(lambda: deque(maxlen=100))
        
        # Gateway information
        self.gateway_ip = None
        self.gateway_mac = None
        
        # Track suspicious activities
        self.suspicious_activities = []
        
        # Track the timestamp of the last cleanup
        self.last_cleanup = datetime.now()
        
    def update(self, packet: Dict[str, Any]) -> None:
        """
        Update context with information from a packet.
        
        Args:
            packet: Dictionary containing packet information
        """
        with self.lock:
            # Extract packet information
            src_ip = packet.get("src_ip")
            src_mac = packet.get("src_mac")
            dst_ip = packet.get("dst_ip")
            dst_mac = packet.get("dst_mac")
            timestamp = packet.get("timestamp", datetime.now())
            
            # Skip invalid packets
            if not (src_ip and src_mac):
                return
                
            # Store packet in recent history
            self.recent_packets[src_mac].append(packet)
            
            # Update packet count
            self.packet_history[src_mac][self._get_time_bucket(timestamp)] += 1
            
            # Update IP-MAC mapping
            old_mac = self.ip_mac_map.get(src_ip)
            if old_mac and old_mac != src_mac:
                # MAC changed for IP - potential spoofing
                self._record_suspicious_activity(
                    "mac_change", 
                    src_ip=src_ip,
                    old_mac=old_mac,
                    new_mac=src_mac,
                    timestamp=timestamp
                )
                
            self.ip_mac_map[src_ip] = src_mac
            self.mac_ip_map[src_mac].add(src_ip)
            
            # Detect if this is a gateway
            if self._is_potential_gateway(packet):
                if not self.gateway_ip:
                    logger.info(f"Identified potential gateway: {src_ip} / {src_mac}")
                    self.gateway_ip = src_ip
                    self.gateway_mac = src_mac
                elif src_ip == self.gateway_ip and src_mac != self.gateway_mac:
                    # Gateway MAC changed - potential attack
                    self._record_suspicious_activity(
                        "gateway_impersonation",
                        gateway_ip=src_ip,
                        expected_mac=self.gateway_mac,
                        received_mac=src_mac,
                        timestamp=timestamp
                    )
            
            # Periodic cleanup of old data
            self._maybe_cleanup()
            
    def get_context(self) -> Dict[str, Any]:
        """
        Get the current context.
        
        Returns:
            Dictionary containing context information
        """
        with self.lock:
            context = {
                "ip_mac_map": dict(self.ip_mac_map),
                "mac_ip_map": {mac: list(ips) for mac, ips in self.mac_ip_map.items()},
                "gateway_ip": self.gateway_ip,
                "gateway_mac": self.gateway_mac,
                "packet_counts": self._get_recent_packet_counts(),
                "suspicious_activities": list(self.suspicious_activities)
            }
            return context
        
    def _get_time_bucket(self, timestamp: datetime) -> int:
        """
        Convert timestamp to a time bucket (in seconds).
        
        Args:
            timestamp: Datetime object
            
        Returns:
            Integer representing the time bucket
        """
        return int(timestamp.timestamp() // 1)  # 1-second buckets
        
    def _get_recent_packet_counts(self, window: int = 5) -> Dict[str, int]:
        """
        Get packet counts for each MAC in the recent window.
        
        Args:
            window: Number of seconds to include
            
        Returns:
            Dictionary mapping MAC -> packet count
        """
        now = datetime.now()
        counts = {}
        
        # Calculate the oldest bucket to include
        oldest_bucket = self._get_time_bucket(now - timedelta(seconds=window))
        
        for mac, time_buckets in self.packet_history.items():
            count = 0
            for bucket, bucket_count in time_buckets.items():
                if bucket >= oldest_bucket:
                    count += bucket_count
            counts[mac] = count
            
        return counts
    
    def _is_potential_gateway(self, packet: Dict[str, Any]) -> bool:
        """
        Check if a packet is likely from a gateway device.
        
        Args:
            packet: Dictionary containing packet information
            
        Returns:
            True if packet is likely from a gateway, False otherwise
        """
        # Simple heuristic: Gateway devices often send gratuitous ARPs
        # and have high packet counts
        if packet.get("op") == 2 and packet.get("src_ip") == packet.get("dst_ip"):
            src_mac = packet.get("src_mac")
            recent_count = len(self.recent_packets.get(src_mac, []))
            
            # If we've seen multiple packets from this MAC, it might be a gateway
            return recent_count > 5
            
        return False
        
    def _record_suspicious_activity(self, activity_type: str, **details) -> None:
        """
        Record a suspicious activity.
        
        Args:
            activity_type: Type of activity
            **details: Additional details about the activity
        """
        activity = {
            "type": activity_type,
            "timestamp": details.get("timestamp", datetime.now()),
            "details": details
        }
        
        self.suspicious_activities.append(activity)
        
        # Keep only recent suspicious activities
        max_activities = 100
        if len(self.suspicious_activities) > max_activities:
            self.suspicious_activities = self.suspicious_activities[-max_activities:]
            
        logger.info(f"Recorded suspicious activity: {activity_type}")
        
    def _maybe_cleanup(self) -> None:
        """
        Clean up old data if needed.
        """
        now = datetime.now()
        
        # Only clean up every minute
        if (now - self.last_cleanup).total_seconds() < 60:
            return
            
        logger.debug("Cleaning up old context data")
        
        # Calculate the oldest bucket to keep
        oldest_bucket = self._get_time_bucket(now - timedelta(seconds=self.history_window))
        
        # Clean up packet history
        for mac in list(self.packet_history.keys()):
            self.packet_history[mac] = {
                bucket: count 
                for bucket, count in self.packet_history[mac].items() 
                if bucket >= oldest_bucket
            }
            
            # Remove empty entries
            if not self.packet_history[mac]:
                del self.packet_history[mac]
                
        # Clean up suspicious activities
        cutoff_time = now - timedelta(seconds=self.history_window)
        self.suspicious_activities = [
            activity for activity in self.suspicious_activities
            if activity["timestamp"] > cutoff_time
        ]
        
        self.last_cleanup = now 