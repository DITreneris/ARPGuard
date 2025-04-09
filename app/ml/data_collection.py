from typing import Dict, List, Any, Union
import numpy as np
import pandas as pd
from datetime import datetime

class DataCollector:
    """Collects and validates network packet data."""
    
    def __init__(self):
        """Initialize the data collector."""
        self.valid_protocols = {'TCP', 'UDP', 'ICMP', 'ARP'}
        self.min_port = 0
        self.max_port = 65535
        self.min_length = 0
        self.max_length = 65535

    def collect_data(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Collect and validate network packet data.
        
        Args:
            packets: List of network packets
            
        Returns:
            List of validated packets
        """
        validated_packets = []
        
        for packet in packets:
            try:
                # Validate required fields
                if not all(key in packet for key in [
                    'src_ip', 'dst_ip', 'src_port', 'dst_port',
                    'protocol', 'length', 'timestamp'
                ]):
                    continue
                
                # Validate IP addresses
                if not self._is_valid_ip(packet['src_ip']) or not self._is_valid_ip(packet['dst_ip']):
                    continue
                
                # Validate ports
                if not self._is_valid_port(packet['src_port']) or not self._is_valid_port(packet['dst_port']):
                    continue
                
                # Validate protocol
                if packet['protocol'].upper() not in self.valid_protocols:
                    continue
                
                # Validate packet length
                if not self._is_valid_length(packet['length']):
                    continue
                
                # Validate timestamp
                if not self._is_valid_timestamp(packet['timestamp']):
                    continue
                
                # Add validated packet
                validated_packets.append(packet)
                
            except (ValueError, TypeError):
                continue
        
        return validated_packets

    def _is_valid_ip(self, ip: str) -> bool:
        """
        Validate IP address format.
        
        Args:
            ip: IP address to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False

    def _is_valid_port(self, port: Union[int, str]) -> bool:
        """
        Validate port number.
        
        Args:
            port: Port number to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            port = int(port)
            return self.min_port <= port <= self.max_port
        except (ValueError, TypeError):
            return False

    def _is_valid_length(self, length: Union[int, float]) -> bool:
        """
        Validate packet length.
        
        Args:
            length: Packet length to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            length = int(length)
            return self.min_length <= length <= self.max_length
        except (ValueError, TypeError):
            return False

    def _is_valid_timestamp(self, timestamp: Union[float, int, str]) -> bool:
        """
        Validate timestamp.
        
        Args:
            timestamp: Timestamp to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            timestamp = float(timestamp)
            # Check if timestamp is within reasonable range (last 10 years)
            current_time = datetime.now().timestamp()
            return current_time - 315360000 <= timestamp <= current_time
        except (ValueError, TypeError):
            return False

    def get_statistics(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate statistics for collected packets.
        
        Args:
            packets: List of network packets
            
        Returns:
            Dictionary containing packet statistics
        """
        if not packets:
            return {}
        
        # Convert to DataFrame for easier analysis
        df = pd.DataFrame(packets)
        
        # Calculate basic statistics
        stats = {
            'total_packets': len(packets),
            'protocol_distribution': df['protocol'].value_counts().to_dict(),
            'avg_packet_length': df['length'].mean(),
            'min_packet_length': df['length'].min(),
            'max_packet_length': df['length'].max(),
            'unique_src_ips': len(df['src_ip'].unique()),
            'unique_dst_ips': len(df['dst_ip'].unique()),
            'unique_src_ports': len(df['src_port'].unique()),
            'unique_dst_ports': len(df['dst_port'].unique()),
            'time_range': {
                'start': datetime.fromtimestamp(df['timestamp'].min()),
                'end': datetime.fromtimestamp(df['timestamp'].max())
            }
        }
        
        return stats

    def filter_packets(self, 
                      packets: List[Dict[str, Any]], 
                      filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Filter packets based on specified criteria.
        
        Args:
            packets: List of network packets
            filters: Dictionary of filter criteria
            
        Returns:
            List of filtered packets
        """
        filtered_packets = packets
        
        # Apply IP filters
        if 'src_ip' in filters:
            filtered_packets = [p for p in filtered_packets if p['src_ip'] == filters['src_ip']]
        if 'dst_ip' in filters:
            filtered_packets = [p for p in filtered_packets if p['dst_ip'] == filters['dst_ip']]
        
        # Apply port filters
        if 'src_port' in filters:
            filtered_packets = [p for p in filtered_packets if p['src_port'] == filters['src_port']]
        if 'dst_port' in filters:
            filtered_packets = [p for p in filtered_packets if p['dst_port'] == filters['dst_port']]
        
        # Apply protocol filter
        if 'protocol' in filters:
            filtered_packets = [p for p in filtered_packets if p['protocol'] == filters['protocol']]
        
        # Apply length filters
        if 'min_length' in filters:
            filtered_packets = [p for p in filtered_packets if p['length'] >= filters['min_length']]
        if 'max_length' in filters:
            filtered_packets = [p for p in filtered_packets if p['length'] <= filters['max_length']]
        
        # Apply time filters
        if 'start_time' in filters:
            filtered_packets = [p for p in filtered_packets if p['timestamp'] >= filters['start_time']]
        if 'end_time' in filters:
            filtered_packets = [p for p in filtered_packets if p['timestamp'] <= filters['end_time']]
        
        return filtered_packets 