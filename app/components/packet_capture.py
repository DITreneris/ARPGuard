"""
Packet Capture Interface Module

This module provides a command-line interface for capturing
and analyzing network packets.
"""
import time
from datetime import datetime
from typing import Optional, Dict, List, Callable
import threading
import os
import json

try:
    import pyshark
    from scapy.all import sniff, wrpcap, rdpcap, Packet
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from app.utils.logger import get_logger
from app.utils.config import get_config_manager

# Initialize logger
logger = get_logger(__name__)

class PacketCapture:
    """
    Packet capture and analysis interface.
    """
    def __init__(self):
        """Initialize the packet capture interface."""
        self.config = get_config_manager()
        self.running = False
        self.capture_thread = None
        self.captured_packets = []
        self.packet_count = 0
        self.start_time = None
        self.protocol_counts = {}
        self.source_ips = {}
        self.dest_ips = {}
        self.packet_sizes = []
        self.packet_callback = None
        self.status_callback = None
        
        # Check if required libraries are available
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy library not available. Packet capture functionality is limited.")
    
    def start_capture(self, 
                     interface: Optional[str] = None, 
                     packet_filter: Optional[str] = None,
                     duration: int = 0,
                     max_packets: int = 0,
                     packet_callback: Optional[Callable] = None,
                     status_callback: Optional[Callable] = None) -> bool:
        """
        Start capturing packets on the specified interface.
        
        Args:
            interface: Network interface to capture on (None for default)
            packet_filter: BPF filter string (e.g., "tcp port 80")
            duration: Capture duration in seconds (0 for indefinite)
            max_packets: Maximum packets to capture (0 for unlimited)
            packet_callback: Callback function for processed packets
            status_callback: Callback function for status updates
            
        Returns:
            bool: True if capture started successfully
        """
        if not SCAPY_AVAILABLE:
            if status_callback:
                status_callback(False, "Required packet capture libraries not available")
            return False
            
        if self.running:
            if status_callback:
                status_callback(False, "Packet capture already running")
            return False
        
        # Store parameters
        self.packet_callback = packet_callback
        self.status_callback = status_callback
        
        # Reset statistics
        self._reset_statistics()
        
        # Start capture thread
        self.running = True
        self.start_time = datetime.now()
        
        self.capture_thread = threading.Thread(
            target=self._capture_thread,
            args=(interface, packet_filter, duration, max_packets)
        )
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        if status_callback:
            filter_info = f" with filter '{packet_filter}'" if packet_filter else ""
            interface_info = f" on {interface}" if interface else ""
            status_callback(True, f"Started packet capture{interface_info}{filter_info}")
        
        return True
    
    def stop_capture(self) -> bool:
        """
        Stop the current packet capture.
        
        Returns:
            bool: True if stopped successfully
        """
        if not self.running:
            return False
            
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
            
        if self.status_callback:
            duration = (datetime.now() - self.start_time).total_seconds()
            self.status_callback(True, f"Stopped packet capture. Captured {self.packet_count} packets in {duration:.1f} seconds")
            
        return True
    
    def save_to_pcap(self, filename: str) -> bool:
        """
        Save captured packets to a PCAP file.
        
        Args:
            filename: Path to save the PCAP file
            
        Returns:
            bool: True if saved successfully
        """
        if not SCAPY_AVAILABLE:
            return False
            
        if not self.captured_packets:
            return False
            
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
            wrpcap(filename, self.captured_packets)
            return True
        except Exception as e:
            logger.error(f"Error saving PCAP file: {e}")
            return False
    
    def analyze_pcap(self, 
                    filename: str, 
                    packet_filter: Optional[str] = None,
                    protocol: Optional[str] = None,
                    max_packets: int = 0) -> Dict:
        """
        Analyze a PCAP file and return statistics.
        
        Args:
            filename: Path to the PCAP file
            packet_filter: BPF filter to apply
            protocol: Protocol to focus on (e.g., 'tcp', 'udp', 'arp')
            max_packets: Maximum packets to analyze (0 for all)
            
        Returns:
            dict: Analysis results
        """
        if not SCAPY_AVAILABLE:
            return {"error": "Required packet analysis libraries not available"}
            
        if not os.path.exists(filename):
            return {"error": f"File not found: {filename}"}
            
        try:
            # Reset statistics
            self._reset_statistics()
            
            # Read PCAP file
            packets = rdpcap(filename)
            
            # Apply filter if specified
            if packet_filter:
                # Simple filtering based on protocol
                if protocol:
                    protocol = protocol.lower()
                    if protocol == 'arp':
                        packets = [p for p in packets if ARP in p]
                    elif protocol == 'tcp':
                        packets = [p for p in packets if TCP in p]
                    elif protocol == 'udp':
                        packets = [p for p in packets if UDP in p]
                    elif protocol == 'icmp':
                        packets = [p for p in packets if ICMP in p]
            
            # Limit the number of packets if specified
            if max_packets > 0 and len(packets) > max_packets:
                packets = packets[:max_packets]
            
            # Process each packet
            for packet in packets:
                self._process_packet(packet)
                
            # Prepare results
            return self.get_statistics()
            
        except Exception as e:
            logger.error(f"Error analyzing PCAP file: {e}")
            return {"error": str(e)}
    
    def get_statistics(self) -> Dict:
        """
        Get current statistics about captured packets.
        
        Returns:
            dict: Statistics about captured packets
        """
        if not self.start_time:
            return {}
            
        duration = (datetime.now() - self.start_time).total_seconds()
        
        return {
            "packet_count": self.packet_count,
            "duration_seconds": duration,
            "packets_per_second": self.packet_count / max(1, duration),
            "protocols": self.protocol_counts,
            "top_source_ips": dict(sorted(self.source_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
            "top_destination_ips": dict(sorted(self.dest_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
            "avg_packet_size": sum(self.packet_sizes) / max(1, len(self.packet_sizes)) if self.packet_sizes else 0,
            "min_packet_size": min(self.packet_sizes) if self.packet_sizes else 0,
            "max_packet_size": max(self.packet_sizes) if self.packet_sizes else 0,
        }
    
    def display_packet_hex(self, packet_index: int, bytes_per_line: int = 16) -> str:
        """
        Get the hexadecimal representation of a packet.
        
        Args:
            packet_index: Index of the packet in the capture
            bytes_per_line: Number of bytes to display per line
            
        Returns:
            str: Hexadecimal representation of the packet
        """
        if not SCAPY_AVAILABLE or packet_index >= len(self.captured_packets):
            return ""
            
        packet = self.captured_packets[packet_index]
        
        if not hasattr(packet, 'original'):
            return "Packet data not available"
            
        hex_bytes = packet.original
        hex_dump = []
        
        for i in range(0, len(hex_bytes), bytes_per_line):
            chunk = hex_bytes[i:i+bytes_per_line]
            # Create the hex part
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            
            # Create the ASCII part
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            
            # Add the formatted line
            hex_dump.append(f'{i:04x}:  {hex_part.ljust(bytes_per_line*3)}  {ascii_part}')
            
        return '\n'.join(hex_dump)
    
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.captured_packets = []
        self.packet_count = 0
        self.start_time = datetime.now()
        self.protocol_counts = {}
        self.source_ips = {}
        self.dest_ips = {}
        self.packet_sizes = []
    
    def _capture_thread(self, interface, packet_filter, duration, max_packets):
        """
        Background thread for packet capture.
        
        Args:
            interface: Network interface to capture on
            packet_filter: BPF filter string
            duration: Capture duration in seconds
            max_packets: Maximum packets to capture
        """
        try:
            # Calculate end time if duration is specified
            end_time = None
            if duration > 0:
                end_time = time.time() + duration
            
            # Start sniffing packets
            while self.running:
                # Check if we've reached the duration limit
                if end_time and time.time() >= end_time:
                    self.running = False
                    break
                    
                # Check if we've reached the packet count limit
                if max_packets > 0 and self.packet_count >= max_packets:
                    self.running = False
                    break
                
                # Capture packets in small batches with timeout
                packets = sniff(
                    iface=interface,
                    filter=packet_filter,
                    count=min(100, max(1, max_packets - self.packet_count) if max_packets > 0 else 100),
                    timeout=1,
                    store=True
                )
                
                # Process captured packets
                for packet in packets:
                    if not self.running:
                        break
                        
                    self._process_packet(packet)
                    
                    # Check packet count limit after each packet
                    if max_packets > 0 and self.packet_count >= max_packets:
                        self.running = False
                        break
                
                # Provide periodic status updates (every 2 seconds)
                if self.status_callback and time.time() % 2 < 0.1:
                    stats = self.get_statistics()
                    self.status_callback(
                        True, 
                        f"Captured {stats['packet_count']} packets "
                        f"({stats['packets_per_second']:.1f} packets/sec)"
                    )
                    
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            if self.status_callback:
                self.status_callback(False, f"Capture error: {str(e)}")
        finally:
            self.running = False
            if self.status_callback:
                stats = self.get_statistics()
                self.status_callback(
                    True, 
                    f"Packet capture completed. Captured {stats['packet_count']} packets "
                    f"in {stats['duration_seconds']:.1f} seconds"
                )
    
    def _process_packet(self, packet: Packet):
        """
        Process a captured packet for statistics and storage.
        
        Args:
            packet: Scapy packet to process
        """
        # Store the packet
        self.captured_packets.append(packet)
        self.packet_count += 1
        
        # Extract packet size if available
        if hasattr(packet, 'len'):
            self.packet_sizes.append(packet.len)
        elif 'IP' in packet and hasattr(packet['IP'], 'len'):
            self.packet_sizes.append(packet['IP'].len)
        elif hasattr(packet, 'original'):
            self.packet_sizes.append(len(packet.original))
        
        # Determine protocol
        protocol = 'Unknown'
        if ARP in packet:
            protocol = 'ARP'
        elif IP in packet:
            if TCP in packet:
                protocol = f"TCP/{packet[TCP].dport}" if packet[TCP].dport in [80, 443, 22, 53] else 'TCP'
            elif UDP in packet:
                protocol = f"UDP/{packet[UDP].dport}" if packet[UDP].dport in [53, 67, 68] else 'UDP'
            elif ICMP in packet:
                protocol = 'ICMP'
            else:
                protocol = 'IP'
        elif Ether in packet:
            protocol = 'Ethernet'
        
        # Update protocol counter
        self.protocol_counts[protocol] = self.protocol_counts.get(protocol, 0) + 1
        
        # Extract IP addresses if available
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Update IP counters
            self.source_ips[src_ip] = self.source_ips.get(src_ip, 0) + 1
            self.dest_ips[dst_ip] = self.dest_ips.get(dst_ip, 0) + 1
        
        # Call the packet callback if registered
        if self.packet_callback:
            packet_info = self._extract_packet_info(packet)
            self.packet_callback(packet_info)
    
    def _extract_packet_info(self, packet: Packet) -> Dict:
        """
        Extract useful information from a packet.
        
        Args:
            packet: Scapy packet
            
        Returns:
            dict: Packet information
        """
        info = {
            'time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'length': 0
        }
        
        # Extract Ethernet information
        if Ether in packet:
            info['src_mac'] = packet[Ether].src
            info['dst_mac'] = packet[Ether].dst
        
        # Extract ARP information
        if ARP in packet:
            info['protocol'] = 'ARP'
            info['src_ip'] = packet[ARP].psrc
            info['dst_ip'] = packet[ARP].pdst
            info['info'] = f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}" if packet[ARP].op == 1 else f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"
        
        # Extract IP information
        elif IP in packet:
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            info['length'] = packet[IP].len
            
            # Extract TCP information
            if TCP in packet:
                info['protocol'] = 'TCP'
                info['src_port'] = packet[TCP].sport
                info['dst_port'] = packet[TCP].dport
                info['info'] = f"{packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}"
                
                # Check for well-known services
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    info['protocol'] = 'HTTP'
                elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    info['protocol'] = 'HTTPS'
                elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                    info['protocol'] = 'SSH'
            
            # Extract UDP information
            elif UDP in packet:
                info['protocol'] = 'UDP'
                info['src_port'] = packet[UDP].sport
                info['dst_port'] = packet[UDP].dport
                info['info'] = f"{packet[IP].src}:{packet[UDP].sport} -> {packet[IP].dst}:{packet[UDP].dport}"
                
                # Check for well-known services
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    info['protocol'] = 'DNS'
                elif packet[UDP].dport == 67 or packet[UDP].dport == 68:
                    info['protocol'] = 'DHCP'
            
            # Extract ICMP information
            elif ICMP in packet:
                info['protocol'] = 'ICMP'
                info['type'] = packet[ICMP].type
                info['code'] = packet[ICMP].code
                
                # Determine ICMP message type
                icmp_type = "Unknown"
                if packet[ICMP].type == 0:
                    icmp_type = "Echo Reply"
                elif packet[ICMP].type == 8:
                    icmp_type = "Echo Request"
                
                info['info'] = f"{icmp_type} from {packet[IP].src} to {packet[IP].dst}"
        
        return info 