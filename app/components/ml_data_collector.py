import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import logging
from collections import defaultdict

from app.utils.logger import get_logger

logger = get_logger('components.ml_data_collector')

class MLDataCollector:
    """Collects and prepares data for ML model training."""
    
    def __init__(self, window_size: int = 60):
        """Initialize the data collector.
        
        Args:
            window_size: Time window in seconds for aggregating features
        """
        self.window_size = window_size
        self.packet_buffer = []
        self.feature_buffer = []
        self.labels = []
        
        # Statistics tracking
        self.packet_stats = defaultdict(lambda: {
            'count': 0,
            'bytes': 0,
            'unique_ports': set(),
            'connection_attempts': 0,
            'first_seen': None,
            'last_seen': None
        })
        
        # Time window tracking
        self.current_window_start = None
        self.current_window_end = None
    
    def add_packet(self, packet: Dict[str, Any], label: Optional[bool] = None):
        """Add a packet to the collection buffer.
        
        Args:
            packet: Dictionary containing packet information
            label: Optional label indicating if the packet is malicious
        """
        timestamp = datetime.now()
        
        # Initialize window if needed
        if self.current_window_start is None:
            self.current_window_start = timestamp
            self.current_window_end = timestamp + timedelta(seconds=self.window_size)
        
        # Check if we need to process the current window
        if timestamp > self.current_window_end:
            self._process_window()
            self.current_window_start = timestamp
            self.current_window_end = timestamp + timedelta(seconds=self.window_size)
        
        # Add packet to buffer
        self.packet_buffer.append((timestamp, packet, label))
        
        # Update statistics
        src_ip = packet.get('src_ip')
        if src_ip:
            stats = self.packet_stats[src_ip]
            stats['count'] += 1
            stats['bytes'] += packet.get('packet_length', 0)
            stats['unique_ports'].add(packet.get('dst_port', 0))
            stats['connection_attempts'] += 1
            
            if stats['first_seen'] is None:
                stats['first_seen'] = timestamp
            stats['last_seen'] = timestamp
    
    def _process_window(self):
        """Process the current time window and extract features."""
        if not self.packet_buffer:
            return
        
        # Group packets by source IP
        ip_packets = defaultdict(list)
        for timestamp, packet, label in self.packet_buffer:
            src_ip = packet.get('src_ip')
            if src_ip:
                ip_packets[src_ip].append((timestamp, packet, label))
        
        # Extract features for each IP
        for src_ip, packets in ip_packets.items():
            features = self._extract_features(src_ip, packets)
            if features is not None:
                self.feature_buffer.append(features)
                
                # Determine label for this window
                window_label = any(label for _, _, label in packets if label is not None)
                self.labels.append(window_label)
        
        # Clear buffer
        self.packet_buffer = []
    
    def _extract_features(self, src_ip: str, packets: List[Tuple[datetime, Dict[str, Any], Optional[bool]]]) -> Optional[np.ndarray]:
        """Extract features for a source IP's packets in the current window.
        
        Args:
            src_ip: Source IP address
            packets: List of (timestamp, packet, label) tuples
            
        Returns:
            Numpy array of features or None if insufficient data
        """
        if not packets:
            return None
        
        stats = self.packet_stats[src_ip]
        
        # Calculate time-based features
        duration = (stats['last_seen'] - stats['first_seen']).total_seconds()
        if duration == 0:
            duration = 1  # Avoid division by zero
        
        # Extract features
        features = [
            # Basic statistics
            stats['count'],  # Total packets
            stats['bytes'],  # Total bytes
            len(stats['unique_ports']),  # Unique destination ports
            stats['connection_attempts'],  # Connection attempts
            
            # Rate-based features
            stats['count'] / duration,  # Packets per second
            stats['bytes'] / duration,  # Bytes per second
            stats['connection_attempts'] / duration,  # Connections per second
            
            # Protocol distribution
            sum(1 for _, p, _ in packets if p.get('protocol') == 6),  # TCP packets
            sum(1 for _, p, _ in packets if p.get('protocol') == 17),  # UDP packets
            sum(1 for _, p, _ in packets if p.get('protocol') == 1),  # ICMP packets
            
            # Threat intelligence features
            max(p.get('threat_score', 0) for _, p, _ in packets),  # Max threat score
            max(p.get('reputation_score', 0) for _, p, _ in packets)  # Max reputation score
        ]
        
        return np.array(features)
    
    def get_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Get the collected training data.
        
        Returns:
            Tuple of (features, labels) as numpy arrays
        """
        if not self.feature_buffer:
            return np.array([]), np.array([])
        
        return np.array(self.feature_buffer), np.array(self.labels)
    
    def clear_data(self):
        """Clear all collected data."""
        self.packet_buffer = []
        self.feature_buffer = []
        self.labels = []
        self.packet_stats.clear()
        self.current_window_start = None
        self.current_window_end = None 