import threading
import time
from datetime import datetime
from typing import Dict, List, Set, Callable, Optional, Any, Tuple
from collections import defaultdict, Counter

from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, Raw
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS
import netifaces

from app.utils.logger import get_logger
from app.utils.config import get_config
from app.utils.database import get_database
from app.utils.memory_manager import MemoryManager, PacketMemoryOptimizer, MemoryPressureLevel

# Module logger
logger = get_logger('components.packet_analyzer')

class PacketAnalyzer:
    """Captures and analyzes various types of network packets."""
    
    def __init__(self):
        """Initialize the packet analyzer."""
        self.running = False
        self.analyzer_thread = None
        self.config = get_config()
        
        # Initialize memory manager
        self.memory_manager = MemoryManager()
        self.packet_optimizer = PacketMemoryOptimizer(self.memory_manager)
        
        # Register for memory pressure callbacks
        self.memory_manager.register_pressure_callback(self._handle_memory_pressure)
        
        # Initialize packet storage with memory optimization
        self.packet_history = []  # Limited history of actual packets
        self.max_history = self.config.get("analyzer.max_packets", 1000)
        self.packet_buffer = []  # Temporary buffer for batch processing
        self.buffer_size = self.memory_manager.get_max_buffer_size() // 10  # Start with 1/10th of max
        
        # Storage for analysis results with memory optimization
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)  # Source IPs
        self.dst_ip_counts = defaultdict(int)  # Destination IPs
        self.port_counts = defaultdict(int)  # Destination ports
        self.connection_pairs = set()  # (src_ip, dst_ip, dst_port) tuples
        
        # Traffic statistics
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.start_time = None
        self.last_update_time = None
        
        # Filtering settings
        self.capture_filter = None  # BPF filter string
        self.exclude_ips = set()  # IPs to exclude from capture
        
        # Packet callback
        self.packet_callback = None
        self.status_callback = None
        
        # Database session
        self.db_session_id = None
        self.database = get_database()
        
        # Memory management statistics
        self.mem_packets_dropped = 0
        self.mem_packets_optimized = 0
        self.mem_bytes_saved = 0
        
        # Start memory monitoring
        self.memory_manager.start_monitoring()
        
    def __del__(self):
        """Clean up resources when the analyzer is destroyed."""
        self.stop_capture()
        self.memory_manager.stop_monitoring()
        
    def start_capture(self, 
                     interface: Optional[str] = None,
                     packet_filter: Optional[str] = None,
                     packet_callback: Optional[Callable] = None,
                     status_callback: Optional[Callable] = None,
                     save_to_db: bool = True,
                     description: Optional[str] = None) -> bool:
        """Start capturing packets.
        
        Args:
            interface: Network interface to capture on (None for default)
            packet_filter: BPF filter string (e.g., "tcp port 80")
            packet_callback: Callback function for processed packets
            status_callback: Callback function for status updates
            save_to_db: Whether to save packets to the database
            description: Description for the capture session
        
        Returns:
            bool: True if capture started successfully
        """
        if self.running:
            if status_callback:
                status_callback(False, "Packet capture already running")
            logger.warning("Attempted to start capture when already running")
            return False
        
        # Store parameters
        self.capture_filter = packet_filter
        self.packet_callback = packet_callback
        self.status_callback = status_callback
        
        # Reset statistics
        self._reset_statistics()
        
        # Clear packet history
        self.packet_history = []
        
        # Reset memory manager metrics
        self.memory_manager.reset_metrics()
        self.packet_optimizer.reset_metrics()
        
        # Adjust buffer size based on current memory conditions
        self.buffer_size = max(50, self.memory_manager.get_max_buffer_size() // 10)
        
        # Create database session if saving to DB
        if save_to_db:
            try:
                self.db_session_id = self.database.create_capture_session(
                    description=description or f"Capture on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    interface=interface,
                    filter_str=packet_filter
                )
                logger.info(f"Created database session {self.db_session_id}")
            except Exception as e:
                logger.error(f"Failed to create database session: {e}")
                if status_callback:
                    status_callback(False, f"Database error: {e}")
                return False
        
        # Start capture thread
        self.running = True
        self.start_time = datetime.now()
        self.last_update_time = self.start_time
        
        self.analyzer_thread = threading.Thread(
            target=self._analyzer_thread,
            args=(interface, packet_filter)
        )
        self.analyzer_thread.daemon = True
        self.analyzer_thread.start()
        
        if status_callback:
            filter_info = f" with filter '{packet_filter}'" if packet_filter else ""
            interface_info = f" on {interface}" if interface else ""
            status_callback(True, f"Started packet capture{interface_info}{filter_info}")
        
        logger.info(f"Started packet capture on {interface or 'default'} with filter: {packet_filter or 'none'}")
        return True
        
    def stop_capture(self):
        """Stop packet capture and analysis.
        
        Returns:
            bool: True if stopped, False if not running
        """
        if not self.running:
            logger.warning("Packet analyzer not running")
            return False
            
        logger.info("Stopping packet capture")
        self.running = False
        
        # Process any remaining packets in buffer
        self._process_packet_buffer()
        
        # Wait for thread to terminate
        if self.analyzer_thread:
            self.analyzer_thread.join(timeout=2.0)
            
        # Update database session if active
        if self.db_session_id:
            try:
                self.database.end_capture_session(
                    self.db_session_id,
                    self.packets_analyzed,
                    self.bytes_analyzed
                )
                logger.info(f"Ended database session {self.db_session_id}")
                
                # Store final snapshot if we have packets
                if self.packets_analyzed > 0:
                    self._save_traffic_snapshot()
                    
                # Reset DB session
                self.db_session_id = None
                
            except Exception as e:
                logger.error(f"Error ending database session: {e}")
        
        # Log memory management metrics
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        logger.info(f"Memory management metrics: "
                   f"Pressure changes: {mem_metrics.get('pressure_changes', 0)}, "
                   f"Peak memory usage: {mem_metrics.get('peak_memory_usage', 0):.1f}%, "
                   f"Packets dropped: {mem_metrics.get('packets_dropped', 0)}")
        
        logger.info(f"Packet optimization metrics: "
                   f"Packets optimized: {optimizer_metrics.get('packets_optimized', 0)}, "
                   f"Bytes saved: {optimizer_metrics.get('bytes_saved', 0) / (1024*1024):.2f} MB, "
                   f"Payloads truncated: {optimizer_metrics.get('payloads_truncated', 0)}")
        
        return True
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get current packet capture statistics.
        
        Returns:
            dict: Statistics about captured packets
        """
        duration = 0
        if self.start_time:
            current_time = datetime.now()
            duration = (current_time - self.start_time).total_seconds()
            
        return {
            'packets_analyzed': self.packets_analyzed,
            'bytes_analyzed': self.bytes_analyzed,
            'duration_seconds': duration,
            'packets_per_second': self.packets_analyzed / max(1, duration),
            'bytes_per_second': self.bytes_analyzed / max(1, duration),
            'protocol_distribution': dict(self.protocol_counts),
            'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
            'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
            'top_ports': dict(Counter(self.port_counts).most_common(10)),
            'unique_connections': len(self.connection_pairs)
        }
        
    def get_packet_history(self, 
                         count: Optional[int] = None, 
                         protocol_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get packet history with optional filtering.
        
        Args:
            count: Maximum number of packets to return (None for all)
            protocol_filter: Filter by protocol (e.g., "TCP", "UDP", "ARP")
            
        Returns:
            list: List of packet information dictionaries
        """
        if count is None:
            count = self.max_history
            
        filtered_packets = self.packet_history
        
        # Apply protocol filter if provided
        if protocol_filter:
            protocol_filter = protocol_filter.upper()
            filtered_packets = [p for p in filtered_packets 
                              if p.get('protocol', '').upper() == protocol_filter]
            
        # Return at most 'count' packets from the end of the list (most recent)
        return filtered_packets[-count:]
        
    def add_exclude_ip(self, ip: str):
        """Add an IP address to exclude from analysis.
        
        Args:
            ip: IP address to exclude
        """
        self.exclude_ips.add(ip)
        logger.info(f"Added {ip} to excluded IPs")
        
    def remove_exclude_ip(self, ip: str):
        """Remove an IP address from the exclusion list.
        
        Args:
            ip: IP address to remove from exclusion
        """
        if ip in self.exclude_ips:
            self.exclude_ips.remove(ip)
            logger.info(f"Removed {ip} from excluded IPs")
            
    def _analyzer_thread(self, interface: str, packet_filter: Optional[str]):
        """Thread function for packet capturing and analysis.
        
        Args:
            interface: Network interface to capture on
            packet_filter: BPF filter string
        """
        try:
            # Start packet sniffing
            logger.info(f"Starting packet capture on {interface}")
            
            # Notify via callback
            if self.status_callback:
                self.status_callback(True, f"Capturing packets on {interface}")
                
            # Use non-blocking sniff with timeout to allow checking the running flag
            while self.running:
                packets = sniff(
                    iface=interface,
                    filter=packet_filter,
                    count=100,  # Capture in small batches
                    timeout=1,  # Short timeout to check running flag
                    store=True
                )
                
                # Process captured packets
                for packet in packets:
                    if not self.running:
                        break
                    self._process_packet(packet)
                    
                # Periodic status updates (every 5 seconds)
                current_time = datetime.now()
                if (current_time - self.last_update_time).total_seconds() >= 5:
                    self._send_status_update()
                    self.last_update_time = current_time
                    
        except Exception as e:
            logger.error(f"Error in packet analyzer: {e}")
            if self.status_callback:
                self.status_callback(False, f"Analyzer error: {str(e)}")
        finally:
            self.running = False
            
    def _process_packet(self, packet):
        """
        Process a single packet.
        
        Args:
            packet: Scapy packet object
        """
        # Check if we should process this packet based on memory conditions
        if not self.memory_manager.should_process_packet():
            self.mem_packets_dropped += 1
            return
            
        # Extract features from packet
        packet_dict = self._extract_packet_features(packet)
        
        # Optimize packet storage
        optimized_packet = self.packet_optimizer.optimize_packet(packet_dict)
        self.mem_packets_optimized += 1
        
        # Add to buffer
        self.packet_buffer.append(optimized_packet)
        
        # Process buffer if it reaches the threshold
        if len(self.packet_buffer) >= self.buffer_size:
            self._process_packet_buffer()
            
        # Update metrics
        self.packets_analyzed += 1
        size = len(packet) if hasattr(packet, "__len__") else 0
        self.bytes_analyzed += size
        
    def _process_packet_buffer(self):
        """Process the accumulated packet buffer."""
        if not self.packet_buffer:
            return
            
        start_time = time.time()
        buffer_size = len(self.packet_buffer)
        
        # Add to history with size limit
        history_limit = min(self.max_history, self.memory_manager.get_max_buffer_size())
        self.packet_history.extend(self.packet_buffer)
        
        # Trim history if needed
        if len(self.packet_history) > history_limit:
            # Keep the most recent packets
            self.packet_history = self.packet_history[-history_limit:]
            
        # Update analytics
        for packet in self.packet_buffer:
            self._update_analytics(packet)
            
        # Save to database if active
        if self.db_session_id:
            try:
                # Save in batches for efficiency
                self.database.add_packets(self.db_session_id, self.packet_buffer)
                
                # Periodically save traffic snapshots
                now = datetime.now()
                if (now - self.last_update_time).total_seconds() >= 60:  # Every minute
                    self._save_traffic_snapshot()
                    self.last_update_time = now
                    
            except Exception as e:
                logger.error(f"Error saving packets to database: {e}")
                
        # Call packet callback if set
        if self.packet_callback:
            for packet in self.packet_buffer:
                try:
                    self.packet_callback(packet)
                except Exception as e:
                    logger.error(f"Error in packet callback: {e}")
                    
        # Clear buffer
        processed_count = len(self.packet_buffer)
        self.packet_buffer = []
        
        # Log performance
        processing_time = time.time() - start_time
        if processing_time > 0.1:  # Only log if it took more than 100ms
            logger.debug(f"Processed {processed_count} packets in {processing_time:.3f}s "
                        f"({processed_count/processing_time:.1f} packets/s)")
        
    def _handle_memory_pressure(self, level: MemoryPressureLevel):
        """
        Handle changes in memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        logger.info(f"Memory pressure changed to {level}, adjusting packet capture behavior")
        
        # Adjust buffer size based on memory pressure
        new_buffer_size = max(10, self.memory_manager.get_max_buffer_size() // 10)
        
        # Log the change
        logger.info(f"Adjusting packet buffer size from {self.buffer_size} to {new_buffer_size}")
        
        # Update buffer size
        self.buffer_size = new_buffer_size
        
        # Trim history if pressure is high or critical
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL):
            self._trim_packet_history(aggressive=True)
            
        # Process any pending packets in buffer if high/critical pressure
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL) and len(self.packet_buffer) > 0:
            self._process_packet_buffer()

        # Register the adaptive action
        self.memory_manager.register_adaptive_action()
        
    def _trim_packet_history(self, aggressive=False):
        """
        Trim packet history to reduce memory usage.
        
        Args:
            aggressive: If True, trim more aggressively
        """
        if not self.packet_history:
            return
            
        current_size = len(self.packet_history)
        
        if aggressive:
            # Keep only 25% of packets during high memory pressure
            target_size = max(100, current_size // 4)
        else:
            # Keep 50% of packets during normal trim
            target_size = max(100, current_size // 2)
            
        if current_size > target_size:
            # Keep newest packets, discard oldest
            self.packet_history = self.packet_history[-target_size:]
            logger.info(f"Trimmed packet history from {current_size} to {len(self.packet_history)}")
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface != 'localhost':
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        return interface
                        
        except Exception as e:
            logger.error(f"Error determining default interface: {e}")
            
        return None 

    def _maybe_save_traffic_snapshot(self) -> None:
        """Save traffic snapshot if enough time has passed."""
        if not self.db_session_id:
            return
            
        now = datetime.now()
        
        # Initialize last snapshot time if needed
        if self.stats['last_snapshot_time'] is None:
            self.stats['last_snapshot_time'] = now
            return
            
        # Check if it's time for a new snapshot (every 10 seconds)
        time_since_last = (now - self.stats['last_snapshot_time']).total_seconds()
        if time_since_last >= 10:
            self._save_traffic_snapshot()
            self.stats['last_snapshot_time'] = now
    
    def _save_traffic_snapshot(self) -> None:
        """Save a traffic snapshot to the database."""
        if not self.db_session_id:
            return
            
        try:
            # Get current statistics
            stats = self.get_statistics()
            
            # Prepare protocol stats
            protocol_stats = {}
            for proto, count in self.protocol_counts.items():
                protocol_stats[proto] = {
                    'count': count,
                    'bytes': self.bytes_analyzed
                }
                
            # Add protocol stats to database
            self.database.add_protocol_stats(
                self.db_session_id,
                datetime.now(),
                protocol_stats
            )
            
            # Prepare IP stats
            ip_stats = {}
            for ip, traffic in self.ip_counts.items():
                ip_stats[ip] = {
                    'sent_packets': traffic,
                    'recv_packets': self.dst_ip_counts[ip],
                    'sent_bytes': self.bytes_analyzed
                }
                
            # Add IP stats to database
            self.database.add_ip_stats(
                self.db_session_id,
                datetime.now(),
                ip_stats
            )
            
            # Add traffic snapshot
            self.database.add_traffic_snapshot(
                self.db_session_id,
                datetime.now(),
                stats['duration_seconds'],
                stats['packets_analyzed'],
                stats['bytes_analyzed'],
                stats['packets_per_second'],
                stats['bytes_per_second'],
                {
                    'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
                    'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
                    'tcp_ports': dict(Counter(self.port_counts).most_common(10)),
                    'http_methods': dict(Counter(self.protocol_counts).most_common(10)),
                    'dns_queries': dict(Counter(self.protocol_counts).most_common(10))
                }
            )
            
            logger.debug(f"Saved traffic snapshot for session {self.db_session_id}")
            
        except Exception as e:
            logger.error(f"Error saving traffic snapshot: {e}")
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory management statistics.
        
        Returns:
            Dict containing memory statistics
        """
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        stats = {
            "current_memory_usage": mem_metrics.get("current_memory_usage", 0),
            "peak_memory_usage": mem_metrics.get("peak_memory_usage", 0),
            "memory_pressure_level": mem_metrics.get("current_pressure_level", "LOW"),
            "memory_checks": mem_metrics.get("memory_checks", 0),
            "pressure_changes": mem_metrics.get("pressure_changes", 0),
            "gc_invocations": mem_metrics.get("gc_invocations", 0),
            "packets_dropped": mem_metrics.get("packets_dropped", 0) + self.mem_packets_dropped,
            "packets_optimized": optimizer_metrics.get("packets_optimized", 0),
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0),
            "payloads_truncated": optimizer_metrics.get("payloads_truncated", 0),
            "buffer_size": self.buffer_size,
            "max_buffer_size": self.memory_manager.get_max_buffer_size(),
            "history_size": len(self.packet_history),
            "ip_cache_size": optimizer_metrics.get("ip_cache_size", 0),
            "mac_cache_size": optimizer_metrics.get("mac_cache_size", 0),
            "current_strategy": {
                "sampling_rate": self.memory_manager.get_current_strategy().get("sampling_rate", 1.0),
                "max_payload_size": self.packet_optimizer.max_payload_size
            },
            "process_memory": mem_metrics.get("process_memory", {})
        }
        
        return stats
        
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _update_analytics(self, packet_info: Dict[str, Any]):
        """Update statistical counters based on packet info.
        
        Args:
            packet_info: The packet information dictionary
        """
        # Increment packet count
        self.packets_analyzed += 1
        
        # Add packet length to byte count
        if 'length' in packet_info:
            self.bytes_analyzed += packet_info['length']
            
        # Update protocol counter
        protocol = packet_info.get('protocol', 'UNKNOWN')
        self.protocol_counts[protocol] += 1
        
        # Update IP counters
        if 'src_ip' in packet_info:
            self.ip_counts[packet_info['src_ip']] += 1
            
        if 'dst_ip' in packet_info:
            self.dst_ip_counts[packet_info['dst_ip']] += 1
            
        # Update port counter
        if 'dst_port' in packet_info:
            self.port_counts[packet_info['dst_port']] += 1
            
    def _extract_packet_features(self, packet):
        """Extract useful information from a packet.
        
        Args:
            packet: The Scapy packet
            
        Returns:
            dict: Extracted packet information or None if invalid
        """
        timestamp = datetime.now()
        
        # Initialize with basic information
        info = {
            'time': timestamp,
            'raw_packet': packet
        }
        
        # Extract Ethernet layer info if present
        if Ether in packet:
            info['src_mac'] = packet[Ether].src
            info['dst_mac'] = packet[Ether].dst
            
        # Extract IP layer info if present
        if IP in packet:
            info['protocol'] = 'IP'
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            info['ttl'] = packet[IP].ttl
            info['length'] = packet[IP].len
            
            # Check for TCP layer
            if TCP in packet:
                info['protocol'] = 'TCP'
                info['src_port'] = packet[TCP].sport
                info['dst_port'] = packet[TCP].dport
                info['flags'] = self._parse_tcp_flags(packet[TCP].flags)
                
                # Add connection tuple
                self._add_connection(info['src_ip'], info['dst_ip'], info['dst_port'], 'TCP')
                
                # Check for HTTP data
                if Raw in packet and packet[TCP].dport in (80, 8080):
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        if payload.startswith(('GET ', 'POST ', 'HTTP')):
                            info['protocol'] = 'HTTP'
                            info['http_data'] = self._parse_http(payload)
                    except:
                        pass
                        
            # Check for UDP layer
            elif UDP in packet:
                info['protocol'] = 'UDP'
                info['src_port'] = packet[UDP].sport
                info['dst_port'] = packet[UDP].dport
                
                # Add connection tuple
                self._add_connection(info['src_ip'], info['dst_ip'], info['dst_port'], 'UDP')
                
                # Check for DNS data
                if info['dst_port'] == 53 or info['src_port'] == 53:
                    info['protocol'] = 'DNS'
                    
            # Check for ICMP layer
            elif ICMP in packet:
                info['protocol'] = 'ICMP'
                info['icmp_type'] = packet[ICMP].type
                info['icmp_code'] = packet[ICMP].code
                
        # Extract ARP layer info if present
        elif ARP in packet:
            info['protocol'] = 'ARP'
            info['src_ip'] = packet[ARP].psrc
            info['dst_ip'] = packet[ARP].pdst
            info['src_mac'] = packet[ARP].hwsrc
            info['dst_mac'] = packet[ARP].hwdst
            info['arp_op'] = 'request' if packet[ARP].op == 1 else 'reply'
            
        else:
            # Unknown packet type, set protocol based on Ethernet type
            if Ether in packet:
                info['protocol'] = f"UNKNOWN:{packet[Ether].type}"
            else:
                info['protocol'] = "UNKNOWN"
                
        # Generate human-readable info
        info['info'] = self._generate_info_string(info)
            
        return info
        
    def _generate_info_string(self, info: Dict[str, Any]) -> str:
        """Generate a human-readable description of the packet.
        
        Args:
            info: The packet information dictionary
            
        Returns:
            str: Human-readable packet description
        """
        protocol = info.get('protocol', 'UNKNOWN')
        
        if protocol == 'ARP':
            op_type = info.get('arp_op', 'unknown')
            return f"ARP {op_type}: {info.get('src_ip')} -> {info.get('dst_ip')}"
            
        elif protocol == 'ICMP':
            icmp_type = info.get('icmp_type')
            return f"ICMP Type {icmp_type}: {info.get('src_ip')} -> {info.get('dst_ip')}"
            
        elif protocol == 'TCP':
            flags = info.get('flags', '')
            return f"TCP {info.get('src_ip')}:{info.get('src_port')} -> {info.get('dst_ip')}:{info.get('dst_port')} [{flags}]"
            
        elif protocol == 'UDP':
            return f"UDP {info.get('src_ip')}:{info.get('src_port')} -> {info.get('dst_ip')}:{info.get('dst_port')}"
            
        elif protocol == 'HTTP':
            http_data = info.get('http_data', {})
            method = http_data.get('method', '')
            path = http_data.get('path', '')
            return f"HTTP {method} {path}: {info.get('src_ip')}:{info.get('src_port')} -> {info.get('dst_ip')}:{info.get('dst_port')}"
            
        elif protocol == 'DNS':
            return f"DNS: {info.get('src_ip')}:{info.get('src_port')} -> {info.get('dst_ip')}:{info.get('dst_port')}"
            
        else:
            return f"{protocol}: {info.get('src_ip', 'unknown')} -> {info.get('dst_ip', 'unknown')}"
        
    def _parse_tcp_flags(self, flags) -> str:
        """Convert TCP flags to a readable string.
        
        Args:
            flags: The TCP flags value
            
        Returns:
            str: String representation of flags
        """
        flag_chars = []
        
        if flags & 0x01:  # FIN
            flag_chars.append('F')
        if flags & 0x02:  # SYN
            flag_chars.append('S')
        if flags & 0x04:  # RST
            flag_chars.append('R')
        if flags & 0x08:  # PSH
            flag_chars.append('P')
        if flags & 0x10:  # ACK
            flag_chars.append('A')
        if flags & 0x20:  # URG
            flag_chars.append('U')
        if flags & 0x40:  # ECE
            flag_chars.append('E')
        if flags & 0x80:  # CWR
            flag_chars.append('C')
            
        return ''.join(flag_chars) if flag_chars else '.'
        
    def _parse_http(self, data: str) -> Dict[str, str]:
        """Parse HTTP request/response data.
        
        Args:
            data: The HTTP data as a string
            
        Returns:
            dict: Parsed HTTP information
        """
        result = {}
        
        # Split into lines
        lines = data.split('\r\n')
        if not lines:
            return result
            
        # Parse first line
        first_line = lines[0]
        
        # Check if it's a request
        if first_line.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
            parts = first_line.split(' ', 2)
            if len(parts) >= 3:
                result['method'] = parts[0]
                result['path'] = parts[1]
                result['version'] = parts[2]
                
        # Check if it's a response
        elif first_line.startswith('HTTP/'):
            parts = first_line.split(' ', 2)
            if len(parts) >= 3:
                result['version'] = parts[0]
                result['status_code'] = parts[1]
                result['status_message'] = parts[2]
                
        # Parse headers
        headers = {}
        for line in lines[1:]:
            if not line or line.isspace():
                break
                
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
                
        if headers:
            result['headers'] = headers
            
        return result
        
    def _add_connection(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str):
        """Add a connection tuple to the tracking set.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port
            protocol: Protocol (TCP/UDP)
        """
        conn_tuple = (src_ip, dst_ip, dst_port, protocol)
        self.connection_pairs.add(conn_tuple)
        
    def _update_analytics(self, packet_info: Dict[str, Any]):
        """Update statistical counters based on packet info.
        
        Args:
            packet_info: The packet information dictionary
        """
        # Increment packet count
        self.packets_analyzed += 1
        
        # Add packet length to byte count
        if 'length' in packet_info:
            self.bytes_analyzed += packet_info['length']
            
        # Update protocol counter
        protocol = packet_info.get('protocol', 'UNKNOWN')
        self.protocol_counts[protocol] += 1
        
        # Update IP counters
        if 'src_ip' in packet_info:
            self.ip_counts[packet_info['src_ip']] += 1
            
        if 'dst_ip' in packet_info:
            self.dst_ip_counts[packet_info['dst_ip']] += 1
            
        # Update port counter
        if 'dst_port' in packet_info:
            self.port_counts[packet_info['dst_port']] += 1
            
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface != 'localhost':
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        return interface
                        
        except Exception as e:
            logger.error(f"Error determining default interface: {e}")
            
        return None 

    def _maybe_save_traffic_snapshot(self) -> None:
        """Save traffic snapshot if enough time has passed."""
        if not self.db_session_id:
            return
            
        now = datetime.now()
        
        # Initialize last snapshot time if needed
        if self.stats['last_snapshot_time'] is None:
            self.stats['last_snapshot_time'] = now
            return
            
        # Check if it's time for a new snapshot (every 10 seconds)
        time_since_last = (now - self.stats['last_snapshot_time']).total_seconds()
        if time_since_last >= 10:
            self._save_traffic_snapshot()
            self.stats['last_snapshot_time'] = now
    
    def _save_traffic_snapshot(self) -> None:
        """Save a traffic snapshot to the database."""
        if not self.db_session_id:
            return
            
        try:
            # Get current statistics
            stats = self.get_statistics()
            
            # Prepare protocol stats
            protocol_stats = {}
            for proto, count in self.protocol_counts.items():
                protocol_stats[proto] = {
                    'count': count,
                    'bytes': self.bytes_analyzed
                }
                
            # Add protocol stats to database
            self.database.add_protocol_stats(
                self.db_session_id,
                datetime.now(),
                protocol_stats
            )
            
            # Prepare IP stats
            ip_stats = {}
            for ip, traffic in self.ip_counts.items():
                ip_stats[ip] = {
                    'sent_packets': traffic,
                    'recv_packets': self.dst_ip_counts[ip],
                    'sent_bytes': self.bytes_analyzed
                }
                
            # Add IP stats to database
            self.database.add_ip_stats(
                self.db_session_id,
                datetime.now(),
                ip_stats
            )
            
            # Add traffic snapshot
            self.database.add_traffic_snapshot(
                self.db_session_id,
                datetime.now(),
                stats['duration_seconds'],
                stats['packets_analyzed'],
                stats['bytes_analyzed'],
                stats['packets_per_second'],
                stats['bytes_per_second'],
                {
                    'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
                    'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
                    'tcp_ports': dict(Counter(self.port_counts).most_common(10)),
                    'http_methods': dict(Counter(self.protocol_counts).most_common(10)),
                    'dns_queries': dict(Counter(self.protocol_counts).most_common(10))
                }
            )
            
            logger.debug(f"Saved traffic snapshot for session {self.db_session_id}")
            
        except Exception as e:
            logger.error(f"Error saving traffic snapshot: {e}")
        
    def _handle_memory_pressure(self, level: MemoryPressureLevel):
        """
        Handle changes in memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        logger.info(f"Memory pressure changed to {level}, adjusting packet capture behavior")
        
        # Adjust buffer size based on memory pressure
        new_buffer_size = max(10, self.memory_manager.get_max_buffer_size() // 10)
        
        # Log the change
        logger.info(f"Adjusting packet buffer size from {self.buffer_size} to {new_buffer_size}")
        
        # Update buffer size
        self.buffer_size = new_buffer_size
        
        # Trim history if pressure is high or critical
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL):
            self._trim_packet_history(aggressive=True)
            
        # Process any pending packets in buffer if high/critical pressure
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL) and len(self.packet_buffer) > 0:
            self._process_packet_buffer()

        # Register the adaptive action
        self.memory_manager.register_adaptive_action()
        
    def _trim_packet_history(self, aggressive=False):
        """
        Trim packet history to reduce memory usage.
        
        Args:
            aggressive: If True, trim more aggressively
        """
        if not self.packet_history:
            return
            
        current_size = len(self.packet_history)
        
        if aggressive:
            # Keep only 25% of packets during high memory pressure
            target_size = max(100, current_size // 4)
        else:
            # Keep 50% of packets during normal trim
            target_size = max(100, current_size // 2)
            
        if current_size > target_size:
            # Keep newest packets, discard oldest
            self.packet_history = self.packet_history[-target_size:]
            logger.info(f"Trimmed packet history from {current_size} to {len(self.packet_history)}")
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory management statistics.
        
        Returns:
            Dict containing memory statistics
        """
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        stats = {
            "current_memory_usage": mem_metrics.get("current_memory_usage", 0),
            "peak_memory_usage": mem_metrics.get("peak_memory_usage", 0),
            "memory_pressure_level": mem_metrics.get("current_pressure_level", "LOW"),
            "memory_checks": mem_metrics.get("memory_checks", 0),
            "pressure_changes": mem_metrics.get("pressure_changes", 0),
            "gc_invocations": mem_metrics.get("gc_invocations", 0),
            "packets_dropped": mem_metrics.get("packets_dropped", 0) + self.mem_packets_dropped,
            "packets_optimized": optimizer_metrics.get("packets_optimized", 0),
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0),
            "payloads_truncated": optimizer_metrics.get("payloads_truncated", 0),
            "buffer_size": self.buffer_size,
            "max_buffer_size": self.memory_manager.get_max_buffer_size(),
            "history_size": len(self.packet_history),
            "ip_cache_size": optimizer_metrics.get("ip_cache_size", 0),
            "mac_cache_size": optimizer_metrics.get("mac_cache_size", 0),
            "current_strategy": {
                "sampling_rate": self.memory_manager.get_current_strategy().get("sampling_rate", 1.0),
                "max_payload_size": self.packet_optimizer.max_payload_size
            },
            "process_memory": mem_metrics.get("process_memory", {})
        }
        
        return stats
        
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface != 'localhost':
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        return interface
                        
        except Exception as e:
            logger.error(f"Error determining default interface: {e}")
            
        return None 

    def _maybe_save_traffic_snapshot(self) -> None:
        """Save traffic snapshot if enough time has passed."""
        if not self.db_session_id:
            return
            
        now = datetime.now()
        
        # Initialize last snapshot time if needed
        if self.stats['last_snapshot_time'] is None:
            self.stats['last_snapshot_time'] = now
            return
            
        # Check if it's time for a new snapshot (every 10 seconds)
        time_since_last = (now - self.stats['last_snapshot_time']).total_seconds()
        if time_since_last >= 10:
            self._save_traffic_snapshot()
            self.stats['last_snapshot_time'] = now
    
    def _save_traffic_snapshot(self) -> None:
        """Save a traffic snapshot to the database."""
        if not self.db_session_id:
            return
            
        try:
            # Get current statistics
            stats = self.get_statistics()
            
            # Prepare protocol stats
            protocol_stats = {}
            for proto, count in self.protocol_counts.items():
                protocol_stats[proto] = {
                    'count': count,
                    'bytes': self.bytes_analyzed
                }
                
            # Add protocol stats to database
            self.database.add_protocol_stats(
                self.db_session_id,
                datetime.now(),
                protocol_stats
            )
            
            # Prepare IP stats
            ip_stats = {}
            for ip, traffic in self.ip_counts.items():
                ip_stats[ip] = {
                    'sent_packets': traffic,
                    'recv_packets': self.dst_ip_counts[ip],
                    'sent_bytes': self.bytes_analyzed
                }
                
            # Add IP stats to database
            self.database.add_ip_stats(
                self.db_session_id,
                datetime.now(),
                ip_stats
            )
            
            # Add traffic snapshot
            self.database.add_traffic_snapshot(
                self.db_session_id,
                datetime.now(),
                stats['duration_seconds'],
                stats['packets_analyzed'],
                stats['bytes_analyzed'],
                stats['packets_per_second'],
                stats['bytes_per_second'],
                {
                    'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
                    'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
                    'tcp_ports': dict(Counter(self.port_counts).most_common(10)),
                    'http_methods': dict(Counter(self.protocol_counts).most_common(10)),
                    'dns_queries': dict(Counter(self.protocol_counts).most_common(10))
                }
            )
            
            logger.debug(f"Saved traffic snapshot for session {self.db_session_id}")
            
        except Exception as e:
            logger.error(f"Error saving traffic snapshot: {e}")
        
    def _handle_memory_pressure(self, level: MemoryPressureLevel):
        """
        Handle changes in memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        logger.info(f"Memory pressure changed to {level}, adjusting packet capture behavior")
        
        # Adjust buffer size based on memory pressure
        new_buffer_size = max(10, self.memory_manager.get_max_buffer_size() // 10)
        
        # Log the change
        logger.info(f"Adjusting packet buffer size from {self.buffer_size} to {new_buffer_size}")
        
        # Update buffer size
        self.buffer_size = new_buffer_size
        
        # Trim history if pressure is high or critical
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL):
            self._trim_packet_history(aggressive=True)
            
        # Process any pending packets in buffer if high/critical pressure
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL) and len(self.packet_buffer) > 0:
            self._process_packet_buffer()

        # Register the adaptive action
        self.memory_manager.register_adaptive_action()
        
    def _trim_packet_history(self, aggressive=False):
        """
        Trim packet history to reduce memory usage.
        
        Args:
            aggressive: If True, trim more aggressively
        """
        if not self.packet_history:
            return
            
        current_size = len(self.packet_history)
        
        if aggressive:
            # Keep only 25% of packets during high memory pressure
            target_size = max(100, current_size // 4)
        else:
            # Keep 50% of packets during normal trim
            target_size = max(100, current_size // 2)
            
        if current_size > target_size:
            # Keep newest packets, discard oldest
            self.packet_history = self.packet_history[-target_size:]
            logger.info(f"Trimmed packet history from {current_size} to {len(self.packet_history)}")
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory management statistics.
        
        Returns:
            Dict containing memory statistics
        """
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        stats = {
            "current_memory_usage": mem_metrics.get("current_memory_usage", 0),
            "peak_memory_usage": mem_metrics.get("peak_memory_usage", 0),
            "memory_pressure_level": mem_metrics.get("current_pressure_level", "LOW"),
            "memory_checks": mem_metrics.get("memory_checks", 0),
            "pressure_changes": mem_metrics.get("pressure_changes", 0),
            "gc_invocations": mem_metrics.get("gc_invocations", 0),
            "packets_dropped": mem_metrics.get("packets_dropped", 0) + self.mem_packets_dropped,
            "packets_optimized": optimizer_metrics.get("packets_optimized", 0),
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0),
            "payloads_truncated": optimizer_metrics.get("payloads_truncated", 0),
            "buffer_size": self.buffer_size,
            "max_buffer_size": self.memory_manager.get_max_buffer_size(),
            "history_size": len(self.packet_history),
            "ip_cache_size": optimizer_metrics.get("ip_cache_size", 0),
            "mac_cache_size": optimizer_metrics.get("mac_cache_size", 0),
            "current_strategy": {
                "sampling_rate": self.memory_manager.get_current_strategy().get("sampling_rate", 1.0),
                "max_payload_size": self.packet_optimizer.max_payload_size
            },
            "process_memory": mem_metrics.get("process_memory", {})
        }
        
        return stats
        
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface != 'localhost':
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        return interface
                        
        except Exception as e:
            logger.error(f"Error determining default interface: {e}")
            
        return None 

    def _maybe_save_traffic_snapshot(self) -> None:
        """Save traffic snapshot if enough time has passed."""
        if not self.db_session_id:
            return
            
        now = datetime.now()
        
        # Initialize last snapshot time if needed
        if self.stats['last_snapshot_time'] is None:
            self.stats['last_snapshot_time'] = now
            return
            
        # Check if it's time for a new snapshot (every 10 seconds)
        time_since_last = (now - self.stats['last_snapshot_time']).total_seconds()
        if time_since_last >= 10:
            self._save_traffic_snapshot()
            self.stats['last_snapshot_time'] = now
    
    def _save_traffic_snapshot(self) -> None:
        """Save a traffic snapshot to the database."""
        if not self.db_session_id:
            return
            
        try:
            # Get current statistics
            stats = self.get_statistics()
            
            # Prepare protocol stats
            protocol_stats = {}
            for proto, count in self.protocol_counts.items():
                protocol_stats[proto] = {
                    'count': count,
                    'bytes': self.bytes_analyzed
                }
                
            # Add protocol stats to database
            self.database.add_protocol_stats(
                self.db_session_id,
                datetime.now(),
                protocol_stats
            )
            
            # Prepare IP stats
            ip_stats = {}
            for ip, traffic in self.ip_counts.items():
                ip_stats[ip] = {
                    'sent_packets': traffic,
                    'recv_packets': self.dst_ip_counts[ip],
                    'sent_bytes': self.bytes_analyzed
                }
                
            # Add IP stats to database
            self.database.add_ip_stats(
                self.db_session_id,
                datetime.now(),
                ip_stats
            )
            
            # Add traffic snapshot
            self.database.add_traffic_snapshot(
                self.db_session_id,
                datetime.now(),
                stats['duration_seconds'],
                stats['packets_analyzed'],
                stats['bytes_analyzed'],
                stats['packets_per_second'],
                stats['bytes_per_second'],
                {
                    'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
                    'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
                    'tcp_ports': dict(Counter(self.port_counts).most_common(10)),
                    'http_methods': dict(Counter(self.protocol_counts).most_common(10)),
                    'dns_queries': dict(Counter(self.protocol_counts).most_common(10))
                }
            )
            
            logger.debug(f"Saved traffic snapshot for session {self.db_session_id}")
            
        except Exception as e:
            logger.error(f"Error saving traffic snapshot: {e}")
        
    def _handle_memory_pressure(self, level: MemoryPressureLevel):
        """
        Handle changes in memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        logger.info(f"Memory pressure changed to {level}, adjusting packet capture behavior")
        
        # Adjust buffer size based on memory pressure
        new_buffer_size = max(10, self.memory_manager.get_max_buffer_size() // 10)
        
        # Log the change
        logger.info(f"Adjusting packet buffer size from {self.buffer_size} to {new_buffer_size}")
        
        # Update buffer size
        self.buffer_size = new_buffer_size
        
        # Trim history if pressure is high or critical
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL):
            self._trim_packet_history(aggressive=True)
            
        # Process any pending packets in buffer if high/critical pressure
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL) and len(self.packet_buffer) > 0:
            self._process_packet_buffer()

        # Register the adaptive action
        self.memory_manager.register_adaptive_action()
        
    def _trim_packet_history(self, aggressive=False):
        """
        Trim packet history to reduce memory usage.
        
        Args:
            aggressive: If True, trim more aggressively
        """
        if not self.packet_history:
            return
            
        current_size = len(self.packet_history)
        
        if aggressive:
            # Keep only 25% of packets during high memory pressure
            target_size = max(100, current_size // 4)
        else:
            # Keep 50% of packets during normal trim
            target_size = max(100, current_size // 2)
            
        if current_size > target_size:
            # Keep newest packets, discard oldest
            self.packet_history = self.packet_history[-target_size:]
            logger.info(f"Trimmed packet history from {current_size} to {len(self.packet_history)}")
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory management statistics.
        
        Returns:
            Dict containing memory statistics
        """
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        stats = {
            "current_memory_usage": mem_metrics.get("current_memory_usage", 0),
            "peak_memory_usage": mem_metrics.get("peak_memory_usage", 0),
            "memory_pressure_level": mem_metrics.get("current_pressure_level", "LOW"),
            "memory_checks": mem_metrics.get("memory_checks", 0),
            "pressure_changes": mem_metrics.get("pressure_changes", 0),
            "gc_invocations": mem_metrics.get("gc_invocations", 0),
            "packets_dropped": mem_metrics.get("packets_dropped", 0) + self.mem_packets_dropped,
            "packets_optimized": optimizer_metrics.get("packets_optimized", 0),
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0),
            "payloads_truncated": optimizer_metrics.get("payloads_truncated", 0),
            "buffer_size": self.buffer_size,
            "max_buffer_size": self.memory_manager.get_max_buffer_size(),
            "history_size": len(self.packet_history),
            "ip_cache_size": optimizer_metrics.get("ip_cache_size", 0),
            "mac_cache_size": optimizer_metrics.get("mac_cache_size", 0),
            "current_strategy": {
                "sampling_rate": self.memory_manager.get_current_strategy().get("sampling_rate", 1.0),
                "max_payload_size": self.packet_optimizer.max_payload_size
            },
            "process_memory": mem_metrics.get("process_memory", {})
        }
        
        return stats
        
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface != 'localhost':
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        return interface
                        
        except Exception as e:
            logger.error(f"Error determining default interface: {e}")
            
        return None 

    def _maybe_save_traffic_snapshot(self) -> None:
        """Save traffic snapshot if enough time has passed."""
        if not self.db_session_id:
            return
            
        now = datetime.now()
        
        # Initialize last snapshot time if needed
        if self.stats['last_snapshot_time'] is None:
            self.stats['last_snapshot_time'] = now
            return
            
        # Check if it's time for a new snapshot (every 10 seconds)
        time_since_last = (now - self.stats['last_snapshot_time']).total_seconds()
        if time_since_last >= 10:
            self._save_traffic_snapshot()
            self.stats['last_snapshot_time'] = now
    
    def _save_traffic_snapshot(self) -> None:
        """Save a traffic snapshot to the database."""
        if not self.db_session_id:
            return
            
        try:
            # Get current statistics
            stats = self.get_statistics()
            
            # Prepare protocol stats
            protocol_stats = {}
            for proto, count in self.protocol_counts.items():
                protocol_stats[proto] = {
                    'count': count,
                    'bytes': self.bytes_analyzed
                }
                
            # Add protocol stats to database
            self.database.add_protocol_stats(
                self.db_session_id,
                datetime.now(),
                protocol_stats
            )
            
            # Prepare IP stats
            ip_stats = {}
            for ip, traffic in self.ip_counts.items():
                ip_stats[ip] = {
                    'sent_packets': traffic,
                    'recv_packets': self.dst_ip_counts[ip],
                    'sent_bytes': self.bytes_analyzed
                }
                
            # Add IP stats to database
            self.database.add_ip_stats(
                self.db_session_id,
                datetime.now(),
                ip_stats
            )
            
            # Add traffic snapshot
            self.database.add_traffic_snapshot(
                self.db_session_id,
                datetime.now(),
                stats['duration_seconds'],
                stats['packets_analyzed'],
                stats['bytes_analyzed'],
                stats['packets_per_second'],
                stats['bytes_per_second'],
                {
                    'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
                    'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
                    'tcp_ports': dict(Counter(self.port_counts).most_common(10)),
                    'http_methods': dict(Counter(self.protocol_counts).most_common(10)),
                    'dns_queries': dict(Counter(self.protocol_counts).most_common(10))
                }
            )
            
            logger.debug(f"Saved traffic snapshot for session {self.db_session_id}")
            
        except Exception as e:
            logger.error(f"Error saving traffic snapshot: {e}")
        
    def _handle_memory_pressure(self, level: MemoryPressureLevel):
        """
        Handle changes in memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        logger.info(f"Memory pressure changed to {level}, adjusting packet capture behavior")
        
        # Adjust buffer size based on memory pressure
        new_buffer_size = max(10, self.memory_manager.get_max_buffer_size() // 10)
        
        # Log the change
        logger.info(f"Adjusting packet buffer size from {self.buffer_size} to {new_buffer_size}")
        
        # Update buffer size
        self.buffer_size = new_buffer_size
        
        # Trim history if pressure is high or critical
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL):
            self._trim_packet_history(aggressive=True)
            
        # Process any pending packets in buffer if high/critical pressure
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL) and len(self.packet_buffer) > 0:
            self._process_packet_buffer()

        # Register the adaptive action
        self.memory_manager.register_adaptive_action()
        
    def _trim_packet_history(self, aggressive=False):
        """
        Trim packet history to reduce memory usage.
        
        Args:
            aggressive: If True, trim more aggressively
        """
        if not self.packet_history:
            return
            
        current_size = len(self.packet_history)
        
        if aggressive:
            # Keep only 25% of packets during high memory pressure
            target_size = max(100, current_size // 4)
        else:
            # Keep 50% of packets during normal trim
            target_size = max(100, current_size // 2)
            
        if current_size > target_size:
            # Keep newest packets, discard oldest
            self.packet_history = self.packet_history[-target_size:]
            logger.info(f"Trimmed packet history from {current_size} to {len(self.packet_history)}")
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory management statistics.
        
        Returns:
            Dict containing memory statistics
        """
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        stats = {
            "current_memory_usage": mem_metrics.get("current_memory_usage", 0),
            "peak_memory_usage": mem_metrics.get("peak_memory_usage", 0),
            "memory_pressure_level": mem_metrics.get("current_pressure_level", "LOW"),
            "memory_checks": mem_metrics.get("memory_checks", 0),
            "pressure_changes": mem_metrics.get("pressure_changes", 0),
            "gc_invocations": mem_metrics.get("gc_invocations", 0),
            "packets_dropped": mem_metrics.get("packets_dropped", 0) + self.mem_packets_dropped,
            "packets_optimized": optimizer_metrics.get("packets_optimized", 0),
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0),
            "payloads_truncated": optimizer_metrics.get("payloads_truncated", 0),
            "buffer_size": self.buffer_size,
            "max_buffer_size": self.memory_manager.get_max_buffer_size(),
            "history_size": len(self.packet_history),
            "ip_cache_size": optimizer_metrics.get("ip_cache_size", 0),
            "mac_cache_size": optimizer_metrics.get("mac_cache_size", 0),
            "current_strategy": {
                "sampling_rate": self.memory_manager.get_current_strategy().get("sampling_rate", 1.0),
                "max_payload_size": self.packet_optimizer.max_payload_size
            },
            "process_memory": mem_metrics.get("process_memory", {})
        }
        
        return stats
        
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface != 'localhost':
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        return interface
                        
        except Exception as e:
            logger.error(f"Error determining default interface: {e}")
            
        return None 

    def _maybe_save_traffic_snapshot(self) -> None:
        """Save traffic snapshot if enough time has passed."""
        if not self.db_session_id:
            return
            
        now = datetime.now()
        
        # Initialize last snapshot time if needed
        if self.stats['last_snapshot_time'] is None:
            self.stats['last_snapshot_time'] = now
            return
            
        # Check if it's time for a new snapshot (every 10 seconds)
        time_since_last = (now - self.stats['last_snapshot_time']).total_seconds()
        if time_since_last >= 10:
            self._save_traffic_snapshot()
            self.stats['last_snapshot_time'] = now
    
    def _save_traffic_snapshot(self) -> None:
        """Save a traffic snapshot to the database."""
        if not self.db_session_id:
            return
            
        try:
            # Get current statistics
            stats = self.get_statistics()
            
            # Prepare protocol stats
            protocol_stats = {}
            for proto, count in self.protocol_counts.items():
                protocol_stats[proto] = {
                    'count': count,
                    'bytes': self.bytes_analyzed
                }
                
            # Add protocol stats to database
            self.database.add_protocol_stats(
                self.db_session_id,
                datetime.now(),
                protocol_stats
            )
            
            # Prepare IP stats
            ip_stats = {}
            for ip, traffic in self.ip_counts.items():
                ip_stats[ip] = {
                    'sent_packets': traffic,
                    'recv_packets': self.dst_ip_counts[ip],
                    'sent_bytes': self.bytes_analyzed
                }
                
            # Add IP stats to database
            self.database.add_ip_stats(
                self.db_session_id,
                datetime.now(),
                ip_stats
            )
            
            # Add traffic snapshot
            self.database.add_traffic_snapshot(
                self.db_session_id,
                datetime.now(),
                stats['duration_seconds'],
                stats['packets_analyzed'],
                stats['bytes_analyzed'],
                stats['packets_per_second'],
                stats['bytes_per_second'],
                {
                    'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
                    'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
                    'tcp_ports': dict(Counter(self.port_counts).most_common(10)),
                    'http_methods': dict(Counter(self.protocol_counts).most_common(10)),
                    'dns_queries': dict(Counter(self.protocol_counts).most_common(10))
                }
            )
            
            logger.debug(f"Saved traffic snapshot for session {self.db_session_id}")
            
        except Exception as e:
            logger.error(f"Error saving traffic snapshot: {e}")
        
    def _handle_memory_pressure(self, level: MemoryPressureLevel):
        """
        Handle changes in memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        logger.info(f"Memory pressure changed to {level}, adjusting packet capture behavior")
        
        # Adjust buffer size based on memory pressure
        new_buffer_size = max(10, self.memory_manager.get_max_buffer_size() // 10)
        
        # Log the change
        logger.info(f"Adjusting packet buffer size from {self.buffer_size} to {new_buffer_size}")
        
        # Update buffer size
        self.buffer_size = new_buffer_size
        
        # Trim history if pressure is high or critical
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL):
            self._trim_packet_history(aggressive=True)
            
        # Process any pending packets in buffer if high/critical pressure
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL) and len(self.packet_buffer) > 0:
            self._process_packet_buffer()

        # Register the adaptive action
        self.memory_manager.register_adaptive_action()
        
    def _trim_packet_history(self, aggressive=False):
        """
        Trim packet history to reduce memory usage.
        
        Args:
            aggressive: If True, trim more aggressively
        """
        if not self.packet_history:
            return
            
        current_size = len(self.packet_history)
        
        if aggressive:
            # Keep only 25% of packets during high memory pressure
            target_size = max(100, current_size // 4)
        else:
            # Keep 50% of packets during normal trim
            target_size = max(100, current_size // 2)
            
        if current_size > target_size:
            # Keep newest packets, discard oldest
            self.packet_history = self.packet_history[-target_size:]
            logger.info(f"Trimmed packet history from {current_size} to {len(self.packet_history)}")
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory management statistics.
        
        Returns:
            Dict containing memory statistics
        """
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        stats = {
            "current_memory_usage": mem_metrics.get("current_memory_usage", 0),
            "peak_memory_usage": mem_metrics.get("peak_memory_usage", 0),
            "memory_pressure_level": mem_metrics.get("current_pressure_level", "LOW"),
            "memory_checks": mem_metrics.get("memory_checks", 0),
            "pressure_changes": mem_metrics.get("pressure_changes", 0),
            "gc_invocations": mem_metrics.get("gc_invocations", 0),
            "packets_dropped": mem_metrics.get("packets_dropped", 0) + self.mem_packets_dropped,
            "packets_optimized": optimizer_metrics.get("packets_optimized", 0),
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0),
            "payloads_truncated": optimizer_metrics.get("payloads_truncated", 0),
            "buffer_size": self.buffer_size,
            "max_buffer_size": self.memory_manager.get_max_buffer_size(),
            "history_size": len(self.packet_history),
            "ip_cache_size": optimizer_metrics.get("ip_cache_size", 0),
            "mac_cache_size": optimizer_metrics.get("mac_cache_size", 0),
            "current_strategy": {
                "sampling_rate": self.memory_manager.get_current_strategy().get("sampling_rate", 1.0),
                "max_payload_size": self.packet_optimizer.max_payload_size
            },
            "process_memory": mem_metrics.get("process_memory", {})
        }
        
        return stats
        
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface != 'localhost':
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        return interface
                        
        except Exception as e:
            logger.error(f"Error determining default interface: {e}")
            
        return None 

    def _maybe_save_traffic_snapshot(self) -> None:
        """Save traffic snapshot if enough time has passed."""
        if not self.db_session_id:
            return
            
        now = datetime.now()
        
        # Initialize last snapshot time if needed
        if self.stats['last_snapshot_time'] is None:
            self.stats['last_snapshot_time'] = now
            return
            
        # Check if it's time for a new snapshot (every 10 seconds)
        time_since_last = (now - self.stats['last_snapshot_time']).total_seconds()
        if time_since_last >= 10:
            self._save_traffic_snapshot()
            self.stats['last_snapshot_time'] = now
    
    def _save_traffic_snapshot(self) -> None:
        """Save a traffic snapshot to the database."""
        if not self.db_session_id:
            return
            
        try:
            # Get current statistics
            stats = self.get_statistics()
            
            # Prepare protocol stats
            protocol_stats = {}
            for proto, count in self.protocol_counts.items():
                protocol_stats[proto] = {
                    'count': count,
                    'bytes': self.bytes_analyzed
                }
                
            # Add protocol stats to database
            self.database.add_protocol_stats(
                self.db_session_id,
                datetime.now(),
                protocol_stats
            )
            
            # Prepare IP stats
            ip_stats = {}
            for ip, traffic in self.ip_counts.items():
                ip_stats[ip] = {
                    'sent_packets': traffic,
                    'recv_packets': self.dst_ip_counts[ip],
                    'sent_bytes': self.bytes_analyzed
                }
                
            # Add IP stats to database
            self.database.add_ip_stats(
                self.db_session_id,
                datetime.now(),
                ip_stats
            )
            
            # Add traffic snapshot
            self.database.add_traffic_snapshot(
                self.db_session_id,
                datetime.now(),
                stats['duration_seconds'],
                stats['packets_analyzed'],
                stats['bytes_analyzed'],
                stats['packets_per_second'],
                stats['bytes_per_second'],
                {
                    'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
                    'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
                    'tcp_ports': dict(Counter(self.port_counts).most_common(10)),
                    'http_methods': dict(Counter(self.protocol_counts).most_common(10)),
                    'dns_queries': dict(Counter(self.protocol_counts).most_common(10))
                }
            )
            
            logger.debug(f"Saved traffic snapshot for session {self.db_session_id}")
            
        except Exception as e:
            logger.error(f"Error saving traffic snapshot: {e}")
        
    def _handle_memory_pressure(self, level: MemoryPressureLevel):
        """
        Handle changes in memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        logger.info(f"Memory pressure changed to {level}, adjusting packet capture behavior")
        
        # Adjust buffer size based on memory pressure
        new_buffer_size = max(10, self.memory_manager.get_max_buffer_size() // 10)
        
        # Log the change
        logger.info(f"Adjusting packet buffer size from {self.buffer_size} to {new_buffer_size}")
        
        # Update buffer size
        self.buffer_size = new_buffer_size
        
        # Trim history if pressure is high or critical
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL):
            self._trim_packet_history(aggressive=True)
            
        # Process any pending packets in buffer if high/critical pressure
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL) and len(self.packet_buffer) > 0:
            self._process_packet_buffer()

        # Register the adaptive action
        self.memory_manager.register_adaptive_action()
        
    def _trim_packet_history(self, aggressive=False):
        """
        Trim packet history to reduce memory usage.
        
        Args:
            aggressive: If True, trim more aggressively
        """
        if not self.packet_history:
            return
            
        current_size = len(self.packet_history)
        
        if aggressive:
            # Keep only 25% of packets during high memory pressure
            target_size = max(100, current_size // 4)
        else:
            # Keep 50% of packets during normal trim
            target_size = max(100, current_size // 2)
            
        if current_size > target_size:
            # Keep newest packets, discard oldest
            self.packet_history = self.packet_history[-target_size:]
            logger.info(f"Trimmed packet history from {current_size} to {len(self.packet_history)}")
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory management statistics.
        
        Returns:
            Dict containing memory statistics
        """
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        stats = {
            "current_memory_usage": mem_metrics.get("current_memory_usage", 0),
            "peak_memory_usage": mem_metrics.get("peak_memory_usage", 0),
            "memory_pressure_level": mem_metrics.get("current_pressure_level", "LOW"),
            "memory_checks": mem_metrics.get("memory_checks", 0),
            "pressure_changes": mem_metrics.get("pressure_changes", 0),
            "gc_invocations": mem_metrics.get("gc_invocations", 0),
            "packets_dropped": mem_metrics.get("packets_dropped", 0) + self.mem_packets_dropped,
            "packets_optimized": optimizer_metrics.get("packets_optimized", 0),
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0),
            "payloads_truncated": optimizer_metrics.get("payloads_truncated", 0),
            "buffer_size": self.buffer_size,
            "max_buffer_size": self.memory_manager.get_max_buffer_size(),
            "history_size": len(self.packet_history),
            "ip_cache_size": optimizer_metrics.get("ip_cache_size", 0),
            "mac_cache_size": optimizer_metrics.get("mac_cache_size", 0),
            "current_strategy": {
                "sampling_rate": self.memory_manager.get_current_strategy().get("sampling_rate", 1.0),
                "max_payload_size": self.packet_optimizer.max_payload_size
            },
            "process_memory": mem_metrics.get("process_memory", {})
        }
        
        return stats
        
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface != 'localhost':
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        return interface
                        
        except Exception as e:
            logger.error(f"Error determining default interface: {e}")
            
        return None 

    def _maybe_save_traffic_snapshot(self) -> None:
        """Save traffic snapshot if enough time has passed."""
        if not self.db_session_id:
            return
            
        now = datetime.now()
        
        # Initialize last snapshot time if needed
        if self.stats['last_snapshot_time'] is None:
            self.stats['last_snapshot_time'] = now
            return
            
        # Check if it's time for a new snapshot (every 10 seconds)
        time_since_last = (now - self.stats['last_snapshot_time']).total_seconds()
        if time_since_last >= 10:
            self._save_traffic_snapshot()
            self.stats['last_snapshot_time'] = now
    
    def _save_traffic_snapshot(self) -> None:
        """Save a traffic snapshot to the database."""
        if not self.db_session_id:
            return
            
        try:
            # Get current statistics
            stats = self.get_statistics()
            
            # Prepare protocol stats
            protocol_stats = {}
            for proto, count in self.protocol_counts.items():
                protocol_stats[proto] = {
                    'count': count,
                    'bytes': self.bytes_analyzed
                }
                
            # Add protocol stats to database
            self.database.add_protocol_stats(
                self.db_session_id,
                datetime.now(),
                protocol_stats
            )
            
            # Prepare IP stats
            ip_stats = {}
            for ip, traffic in self.ip_counts.items():
                ip_stats[ip] = {
                    'sent_packets': traffic,
                    'recv_packets': self.dst_ip_counts[ip],
                    'sent_bytes': self.bytes_analyzed
                }
                
            # Add IP stats to database
            self.database.add_ip_stats(
                self.db_session_id,
                datetime.now(),
                ip_stats
            )
            
            # Add traffic snapshot
            self.database.add_traffic_snapshot(
                self.db_session_id,
                datetime.now(),
                stats['duration_seconds'],
                stats['packets_analyzed'],
                stats['bytes_analyzed'],
                stats['packets_per_second'],
                stats['bytes_per_second'],
                {
                    'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
                    'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
                    'tcp_ports': dict(Counter(self.port_counts).most_common(10)),
                    'http_methods': dict(Counter(self.protocol_counts).most_common(10)),
                    'dns_queries': dict(Counter(self.protocol_counts).most_common(10))
                }
            )
            
            logger.debug(f"Saved traffic snapshot for session {self.db_session_id}")
            
        except Exception as e:
            logger.error(f"Error saving traffic snapshot: {e}")
        
    def _handle_memory_pressure(self, level: MemoryPressureLevel):
        """
        Handle changes in memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        logger.info(f"Memory pressure changed to {level}, adjusting packet capture behavior")
        
        # Adjust buffer size based on memory pressure
        new_buffer_size = max(10, self.memory_manager.get_max_buffer_size() // 10)
        
        # Log the change
        logger.info(f"Adjusting packet buffer size from {self.buffer_size} to {new_buffer_size}")
        
        # Update buffer size
        self.buffer_size = new_buffer_size
        
        # Trim history if pressure is high or critical
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL):
            self._trim_packet_history(aggressive=True)
            
        # Process any pending packets in buffer if high/critical pressure
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL) and len(self.packet_buffer) > 0:
            self._process_packet_buffer()

        # Register the adaptive action
        self.memory_manager.register_adaptive_action()
        
    def _trim_packet_history(self, aggressive=False):
        """
        Trim packet history to reduce memory usage.
        
        Args:
            aggressive: If True, trim more aggressively
        """
        if not self.packet_history:
            return
            
        current_size = len(self.packet_history)
        
        if aggressive:
            # Keep only 25% of packets during high memory pressure
            target_size = max(100, current_size // 4)
        else:
            # Keep 50% of packets during normal trim
            target_size = max(100, current_size // 2)
            
        if current_size > target_size:
            # Keep newest packets, discard oldest
            self.packet_history = self.packet_history[-target_size:]
            logger.info(f"Trimmed packet history from {current_size} to {len(self.packet_history)}")
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory management statistics.
        
        Returns:
            Dict containing memory statistics
        """
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        stats = {
            "current_memory_usage": mem_metrics.get("current_memory_usage", 0),
            "peak_memory_usage": mem_metrics.get("peak_memory_usage", 0),
            "memory_pressure_level": mem_metrics.get("current_pressure_level", "LOW"),
            "memory_checks": mem_metrics.get("memory_checks", 0),
            "pressure_changes": mem_metrics.get("pressure_changes", 0),
            "gc_invocations": mem_metrics.get("gc_invocations", 0),
            "packets_dropped": mem_metrics.get("packets_dropped", 0) + self.mem_packets_dropped,
            "packets_optimized": optimizer_metrics.get("packets_optimized", 0),
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0),
            "payloads_truncated": optimizer_metrics.get("payloads_truncated", 0),
            "buffer_size": self.buffer_size,
            "max_buffer_size": self.memory_manager.get_max_buffer_size(),
            "history_size": len(self.packet_history),
            "ip_cache_size": optimizer_metrics.get("ip_cache_size", 0),
            "mac_cache_size": optimizer_metrics.get("mac_cache_size", 0),
            "current_strategy": {
                "sampling_rate": self.memory_manager.get_current_strategy().get("sampling_rate", 1.0),
                "max_payload_size": self.packet_optimizer.max_payload_size
            },
            "process_memory": mem_metrics.get("process_memory", {})
        }
        
        return stats
        
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface != 'localhost':
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        return interface
                        
        except Exception as e:
            logger.error(f"Error determining default interface: {e}")
            
        return None 

    def _maybe_save_traffic_snapshot(self) -> None:
        """Save traffic snapshot if enough time has passed."""
        if not self.db_session_id:
            return
            
        now = datetime.now()
        
        # Initialize last snapshot time if needed
        if self.stats['last_snapshot_time'] is None:
            self.stats['last_snapshot_time'] = now
            return
            
        # Check if it's time for a new snapshot (every 10 seconds)
        time_since_last = (now - self.stats['last_snapshot_time']).total_seconds()
        if time_since_last >= 10:
            self._save_traffic_snapshot()
            self.stats['last_snapshot_time'] = now
    
    def _save_traffic_snapshot(self) -> None:
        """Save a traffic snapshot to the database."""
        if not self.db_session_id:
            return
            
        try:
            # Get current statistics
            stats = self.get_statistics()
            
            # Prepare protocol stats
            protocol_stats = {}
            for proto, count in self.protocol_counts.items():
                protocol_stats[proto] = {
                    'count': count,
                    'bytes': self.bytes_analyzed
                }
                
            # Add protocol stats to database
            self.database.add_protocol_stats(
                self.db_session_id,
                datetime.now(),
                protocol_stats
            )
            
            # Prepare IP stats
            ip_stats = {}
            for ip, traffic in self.ip_counts.items():
                ip_stats[ip] = {
                    'sent_packets': traffic,
                    'recv_packets': self.dst_ip_counts[ip],
                    'sent_bytes': self.bytes_analyzed
                }
                
            # Add IP stats to database
            self.database.add_ip_stats(
                self.db_session_id,
                datetime.now(),
                ip_stats
            )
            
            # Add traffic snapshot
            self.database.add_traffic_snapshot(
                self.db_session_id,
                datetime.now(),
                stats['duration_seconds'],
                stats['packets_analyzed'],
                stats['bytes_analyzed'],
                stats['packets_per_second'],
                stats['bytes_per_second'],
                {
                    'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
                    'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
                    'tcp_ports': dict(Counter(self.port_counts).most_common(10)),
                    'http_methods': dict(Counter(self.protocol_counts).most_common(10)),
                    'dns_queries': dict(Counter(self.protocol_counts).most_common(10))
                }
            )
            
            logger.debug(f"Saved traffic snapshot for session {self.db_session_id}")
            
        except Exception as e:
            logger.error(f"Error saving traffic snapshot: {e}")
        
    def _handle_memory_pressure(self, level: MemoryPressureLevel):
        """
        Handle changes in memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        logger.info(f"Memory pressure changed to {level}, adjusting packet capture behavior")
        
        # Adjust buffer size based on memory pressure
        new_buffer_size = max(10, self.memory_manager.get_max_buffer_size() // 10)
        
        # Log the change
        logger.info(f"Adjusting packet buffer size from {self.buffer_size} to {new_buffer_size}")
        
        # Update buffer size
        self.buffer_size = new_buffer_size
        
        # Trim history if pressure is high or critical
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL):
            self._trim_packet_history(aggressive=True)
            
        # Process any pending packets in buffer if high/critical pressure
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL) and len(self.packet_buffer) > 0:
            self._process_packet_buffer()

        # Register the adaptive action
        self.memory_manager.register_adaptive_action()
        
    def _trim_packet_history(self, aggressive=False):
        """
        Trim packet history to reduce memory usage.
        
        Args:
            aggressive: If True, trim more aggressively
        """
        if not self.packet_history:
            return
            
        current_size = len(self.packet_history)
        
        if aggressive:
            # Keep only 25% of packets during high memory pressure
            target_size = max(100, current_size // 4)
        else:
            # Keep 50% of packets during normal trim
            target_size = max(100, current_size // 2)
            
        if current_size > target_size:
            # Keep newest packets, discard oldest
            self.packet_history = self.packet_history[-target_size:]
            logger.info(f"Trimmed packet history from {current_size} to {len(self.packet_history)}")
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory management statistics.
        
        Returns:
            Dict containing memory statistics
        """
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        stats = {
            "current_memory_usage": mem_metrics.get("current_memory_usage", 0),
            "peak_memory_usage": mem_metrics.get("peak_memory_usage", 0),
            "memory_pressure_level": mem_metrics.get("current_pressure_level", "LOW"),
            "memory_checks": mem_metrics.get("memory_checks", 0),
            "pressure_changes": mem_metrics.get("pressure_changes", 0),
            "gc_invocations": mem_metrics.get("gc_invocations", 0),
            "packets_dropped": mem_metrics.get("packets_dropped", 0) + self.mem_packets_dropped,
            "packets_optimized": optimizer_metrics.get("packets_optimized", 0),
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0),
            "payloads_truncated": optimizer_metrics.get("payloads_truncated", 0),
            "buffer_size": self.buffer_size,
            "max_buffer_size": self.memory_manager.get_max_buffer_size(),
            "history_size": len(self.packet_history),
            "ip_cache_size": optimizer_metrics.get("ip_cache_size", 0),
            "mac_cache_size": optimizer_metrics.get("mac_cache_size", 0),
            "current_strategy": {
                "sampling_rate": self.memory_manager.get_current_strategy().get("sampling_rate", 1.0),
                "max_payload_size": self.packet_optimizer.max_payload_size
            },
            "process_memory": mem_metrics.get("process_memory", {})
        }
        
        return stats
        
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface != 'localhost':
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        return interface
                        
        except Exception as e:
            logger.error(f"Error determining default interface: {e}")
            
        return None 

    def _maybe_save_traffic_snapshot(self) -> None:
        """Save traffic snapshot if enough time has passed."""
        if not self.db_session_id:
            return
            
        now = datetime.now()
        
        # Initialize last snapshot time if needed
        if self.stats['last_snapshot_time'] is None:
            self.stats['last_snapshot_time'] = now
            return
            
        # Check if it's time for a new snapshot (every 10 seconds)
        time_since_last = (now - self.stats['last_snapshot_time']).total_seconds()
        if time_since_last >= 10:
            self._save_traffic_snapshot()
            self.stats['last_snapshot_time'] = now
    
    def _save_traffic_snapshot(self) -> None:
        """Save a traffic snapshot to the database."""
        if not self.db_session_id:
            return
            
        try:
            # Get current statistics
            stats = self.get_statistics()
            
            # Prepare protocol stats
            protocol_stats = {}
            for proto, count in self.protocol_counts.items():
                protocol_stats[proto] = {
                    'count': count,
                    'bytes': self.bytes_analyzed
                }
                
            # Add protocol stats to database
            self.database.add_protocol_stats(
                self.db_session_id,
                datetime.now(),
                protocol_stats
            )
            
            # Prepare IP stats
            ip_stats = {}
            for ip, traffic in self.ip_counts.items():
                ip_stats[ip] = {
                    'sent_packets': traffic,
                    'recv_packets': self.dst_ip_counts[ip],
                    'sent_bytes': self.bytes_analyzed
                }
                
            # Add IP stats to database
            self.database.add_ip_stats(
                self.db_session_id,
                datetime.now(),
                ip_stats
            )
            
            # Add traffic snapshot
            self.database.add_traffic_snapshot(
                self.db_session_id,
                datetime.now(),
                stats['duration_seconds'],
                stats['packets_analyzed'],
                stats['bytes_analyzed'],
                stats['packets_per_second'],
                stats['bytes_per_second'],
                {
                    'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
                    'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
                    'tcp_ports': dict(Counter(self.port_counts).most_common(10)),
                    'http_methods': dict(Counter(self.protocol_counts).most_common(10)),
                    'dns_queries': dict(Counter(self.protocol_counts).most_common(10))
                }
            )
            
            logger.debug(f"Saved traffic snapshot for session {self.db_session_id}")
            
        except Exception as e:
            logger.error(f"Error saving traffic snapshot: {e}")
        
    def _handle_memory_pressure(self, level: MemoryPressureLevel):
        """
        Handle changes in memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        logger.info(f"Memory pressure changed to {level}, adjusting packet capture behavior")
        
        # Adjust buffer size based on memory pressure
        new_buffer_size = max(10, self.memory_manager.get_max_buffer_size() // 10)
        
        # Log the change
        logger.info(f"Adjusting packet buffer size from {self.buffer_size} to {new_buffer_size}")
        
        # Update buffer size
        self.buffer_size = new_buffer_size
        
        # Trim history if pressure is high or critical
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL):
            self._trim_packet_history(aggressive=True)
            
        # Process any pending packets in buffer if high/critical pressure
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL) and len(self.packet_buffer) > 0:
            self._process_packet_buffer()

        # Register the adaptive action
        self.memory_manager.register_adaptive_action()
        
    def _trim_packet_history(self, aggressive=False):
        """
        Trim packet history to reduce memory usage.
        
        Args:
            aggressive: If True, trim more aggressively
        """
        if not self.packet_history:
            return
            
        current_size = len(self.packet_history)
        
        if aggressive:
            # Keep only 25% of packets during high memory pressure
            target_size = max(100, current_size // 4)
        else:
            # Keep 50% of packets during normal trim
            target_size = max(100, current_size // 2)
            
        if current_size > target_size:
            # Keep newest packets, discard oldest
            self.packet_history = self.packet_history[-target_size:]
            logger.info(f"Trimmed packet history from {current_size} to {len(self.packet_history)}")
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory management statistics.
        
        Returns:
            Dict containing memory statistics
        """
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        stats = {
            "current_memory_usage": mem_metrics.get("current_memory_usage", 0),
            "peak_memory_usage": mem_metrics.get("peak_memory_usage", 0),
            "memory_pressure_level": mem_metrics.get("current_pressure_level", "LOW"),
            "memory_checks": mem_metrics.get("memory_checks", 0),
            "pressure_changes": mem_metrics.get("pressure_changes", 0),
            "gc_invocations": mem_metrics.get("gc_invocations", 0),
            "packets_dropped": mem_metrics.get("packets_dropped", 0) + self.mem_packets_dropped,
            "packets_optimized": optimizer_metrics.get("packets_optimized", 0),
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0),
            "payloads_truncated": optimizer_metrics.get("payloads_truncated", 0),
            "buffer_size": self.buffer_size,
            "max_buffer_size": self.memory_manager.get_max_buffer_size(),
            "history_size": len(self.packet_history),
            "ip_cache_size": optimizer_metrics.get("ip_cache_size", 0),
            "mac_cache_size": optimizer_metrics.get("mac_cache_size", 0),
            "current_strategy": {
                "sampling_rate": self.memory_manager.get_current_strategy().get("sampling_rate", 1.0),
                "max_payload_size": self.packet_optimizer.max_payload_size
            },
            "process_memory": mem_metrics.get("process_memory", {})
        }
        
        return stats
        
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface != 'localhost':
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        return interface
                        
        except Exception as e:
            logger.error(f"Error determining default interface: {e}")
            
        return None 

    def _maybe_save_traffic_snapshot(self) -> None:
        """Save traffic snapshot if enough time has passed."""
        if not self.db_session_id:
            return
            
        now = datetime.now()
        
        # Initialize last snapshot time if needed
        if self.stats['last_snapshot_time'] is None:
            self.stats['last_snapshot_time'] = now
            return
            
        # Check if it's time for a new snapshot (every 10 seconds)
        time_since_last = (now - self.stats['last_snapshot_time']).total_seconds()
        if time_since_last >= 10:
            self._save_traffic_snapshot()
            self.stats['last_snapshot_time'] = now
    
    def _save_traffic_snapshot(self) -> None:
        """Save a traffic snapshot to the database."""
        if not self.db_session_id:
            return
            
        try:
            # Get current statistics
            stats = self.get_statistics()
            
            # Prepare protocol stats
            protocol_stats = {}
            for proto, count in self.protocol_counts.items():
                protocol_stats[proto] = {
                    'count': count,
                    'bytes': self.bytes_analyzed
                }
                
            # Add protocol stats to database
            self.database.add_protocol_stats(
                self.db_session_id,
                datetime.now(),
                protocol_stats
            )
            
            # Prepare IP stats
            ip_stats = {}
            for ip, traffic in self.ip_counts.items():
                ip_stats[ip] = {
                    'sent_packets': traffic,
                    'recv_packets': self.dst_ip_counts[ip],
                    'sent_bytes': self.bytes_analyzed
                }
                
            # Add IP stats to database
            self.database.add_ip_stats(
                self.db_session_id,
                datetime.now(),
                ip_stats
            )
            
            # Add traffic snapshot
            self.database.add_traffic_snapshot(
                self.db_session_id,
                datetime.now(),
                stats['duration_seconds'],
                stats['packets_analyzed'],
                stats['bytes_analyzed'],
                stats['packets_per_second'],
                stats['bytes_per_second'],
                {
                    'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
                    'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
                    'tcp_ports': dict(Counter(self.port_counts).most_common(10)),
                    'http_methods': dict(Counter(self.protocol_counts).most_common(10)),
                    'dns_queries': dict(Counter(self.protocol_counts).most_common(10))
                }
            )
            
            logger.debug(f"Saved traffic snapshot for session {self.db_session_id}")
            
        except Exception as e:
            logger.error(f"Error saving traffic snapshot: {e}")
        
    def _handle_memory_pressure(self, level: MemoryPressureLevel):
        """
        Handle changes in memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        logger.info(f"Memory pressure changed to {level}, adjusting packet capture behavior")
        
        # Adjust buffer size based on memory pressure
        new_buffer_size = max(10, self.memory_manager.get_max_buffer_size() // 10)
        
        # Log the change
        logger.info(f"Adjusting packet buffer size from {self.buffer_size} to {new_buffer_size}")
        
        # Update buffer size
        self.buffer_size = new_buffer_size
        
        # Trim history if pressure is high or critical
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL):
            self._trim_packet_history(aggressive=True)
            
        # Process any pending packets in buffer if high/critical pressure
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL) and len(self.packet_buffer) > 0:
            self._process_packet_buffer()

        # Register the adaptive action
        self.memory_manager.register_adaptive_action()
        
    def _trim_packet_history(self, aggressive=False):
        """
        Trim packet history to reduce memory usage.
        
        Args:
            aggressive: If True, trim more aggressively
        """
        if not self.packet_history:
            return
            
        current_size = len(self.packet_history)
        
        if aggressive:
            # Keep only 25% of packets during high memory pressure
            target_size = max(100, current_size // 4)
        else:
            # Keep 50% of packets during normal trim
            target_size = max(100, current_size // 2)
            
        if current_size > target_size:
            # Keep newest packets, discard oldest
            self.packet_history = self.packet_history[-target_size:]
            logger.info(f"Trimmed packet history from {current_size} to {len(self.packet_history)}")
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory management statistics.
        
        Returns:
            Dict containing memory statistics
        """
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        stats = {
            "current_memory_usage": mem_metrics.get("current_memory_usage", 0),
            "peak_memory_usage": mem_metrics.get("peak_memory_usage", 0),
            "memory_pressure_level": mem_metrics.get("current_pressure_level", "LOW"),
            "memory_checks": mem_metrics.get("memory_checks", 0),
            "pressure_changes": mem_metrics.get("pressure_changes", 0),
            "gc_invocations": mem_metrics.get("gc_invocations", 0),
            "packets_dropped": mem_metrics.get("packets_dropped", 0) + self.mem_packets_dropped,
            "packets_optimized": optimizer_metrics.get("packets_optimized", 0),
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0),
            "payloads_truncated": optimizer_metrics.get("payloads_truncated", 0),
            "buffer_size": self.buffer_size,
            "max_buffer_size": self.memory_manager.get_max_buffer_size(),
            "history_size": len(self.packet_history),
            "ip_cache_size": optimizer_metrics.get("ip_cache_size", 0),
            "mac_cache_size": optimizer_metrics.get("mac_cache_size", 0),
            "current_strategy": {
                "sampling_rate": self.memory_manager.get_current_strategy().get("sampling_rate", 1.0),
                "max_payload_size": self.packet_optimizer.max_payload_size
            },
            "process_memory": mem_metrics.get("process_memory", {})
        }
        
        return stats
        
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface != 'localhost':
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        return interface
                        
        except Exception as e:
            logger.error(f"Error determining default interface: {e}")
            
        return None 

    def _maybe_save_traffic_snapshot(self) -> None:
        """Save traffic snapshot if enough time has passed."""
        if not self.db_session_id:
            return
            
        now = datetime.now()
        
        # Initialize last snapshot time if needed
        if self.stats['last_snapshot_time'] is None:
            self.stats['last_snapshot_time'] = now
            return
            
        # Check if it's time for a new snapshot (every 10 seconds)
        time_since_last = (now - self.stats['last_snapshot_time']).total_seconds()
        if time_since_last >= 10:
            self._save_traffic_snapshot()
            self.stats['last_snapshot_time'] = now
    
    def _save_traffic_snapshot(self) -> None:
        """Save a traffic snapshot to the database."""
        if not self.db_session_id:
            return
            
        try:
            # Get current statistics
            stats = self.get_statistics()
            
            # Prepare protocol stats
            protocol_stats = {}
            for proto, count in self.protocol_counts.items():
                protocol_stats[proto] = {
                    'count': count,
                    'bytes': self.bytes_analyzed
                }
                
            # Add protocol stats to database
            self.database.add_protocol_stats(
                self.db_session_id,
                datetime.now(),
                protocol_stats
            )
            
            # Prepare IP stats
            ip_stats = {}
            for ip, traffic in self.ip_counts.items():
                ip_stats[ip] = {
                    'sent_packets': traffic,
                    'recv_packets': self.dst_ip_counts[ip],
                    'sent_bytes': self.bytes_analyzed
                }
                
            # Add IP stats to database
            self.database.add_ip_stats(
                self.db_session_id,
                datetime.now(),
                ip_stats
            )
            
            # Add traffic snapshot
            self.database.add_traffic_snapshot(
                self.db_session_id,
                datetime.now(),
                stats['duration_seconds'],
                stats['packets_analyzed'],
                stats['bytes_analyzed'],
                stats['packets_per_second'],
                stats['bytes_per_second'],
                {
                    'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
                    'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
                    'tcp_ports': dict(Counter(self.port_counts).most_common(10)),
                    'http_methods': dict(Counter(self.protocol_counts).most_common(10)),
                    'dns_queries': dict(Counter(self.protocol_counts).most_common(10))
                }
            )
            
            logger.debug(f"Saved traffic snapshot for session {self.db_session_id}")
            
        except Exception as e:
            logger.error(f"Error saving traffic snapshot: {e}")
        
    def _handle_memory_pressure(self, level: MemoryPressureLevel):
        """
        Handle changes in memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        logger.info(f"Memory pressure changed to {level}, adjusting packet capture behavior")
        
        # Adjust buffer size based on memory pressure
        new_buffer_size = max(10, self.memory_manager.get_max_buffer_size() // 10)
        
        # Log the change
        logger.info(f"Adjusting packet buffer size from {self.buffer_size} to {new_buffer_size}")
        
        # Update buffer size
        self.buffer_size = new_buffer_size
        
        # Trim history if pressure is high or critical
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL):
            self._trim_packet_history(aggressive=True)
            
        # Process any pending packets in buffer if high/critical pressure
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL) and len(self.packet_buffer) > 0:
            self._process_packet_buffer()

        # Register the adaptive action
        self.memory_manager.register_adaptive_action()
        
    def _trim_packet_history(self, aggressive=False):
        """
        Trim packet history to reduce memory usage.
        
        Args:
            aggressive: If True, trim more aggressively
        """
        if not self.packet_history:
            return
            
        current_size = len(self.packet_history)
        
        if aggressive:
            # Keep only 25% of packets during high memory pressure
            target_size = max(100, current_size // 4)
        else:
            # Keep 50% of packets during normal trim
            target_size = max(100, current_size // 2)
            
        if current_size > target_size:
            # Keep newest packets, discard oldest
            self.packet_history = self.packet_history[-target_size:]
            logger.info(f"Trimmed packet history from {current_size} to {len(self.packet_history)}")
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory management statistics.
        
        Returns:
            Dict containing memory statistics
        """
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        stats = {
            "current_memory_usage": mem_metrics.get("current_memory_usage", 0),
            "peak_memory_usage": mem_metrics.get("peak_memory_usage", 0),
            "memory_pressure_level": mem_metrics.get("current_pressure_level", "LOW"),
            "memory_checks": mem_metrics.get("memory_checks", 0),
            "pressure_changes": mem_metrics.get("pressure_changes", 0),
            "gc_invocations": mem_metrics.get("gc_invocations", 0),
            "packets_dropped": mem_metrics.get("packets_dropped", 0) + self.mem_packets_dropped,
            "packets_optimized": optimizer_metrics.get("packets_optimized", 0),
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0),
            "payloads_truncated": optimizer_metrics.get("payloads_truncated", 0),
            "buffer_size": self.buffer_size,
            "max_buffer_size": self.memory_manager.get_max_buffer_size(),
            "history_size": len(self.packet_history),
            "ip_cache_size": optimizer_metrics.get("ip_cache_size", 0),
            "mac_cache_size": optimizer_metrics.get("mac_cache_size", 0),
            "current_strategy": {
                "sampling_rate": self.memory_manager.get_current_strategy().get("sampling_rate", 1.0),
                "max_payload_size": self.packet_optimizer.max_payload_size
            },
            "process_memory": mem_metrics.get("process_memory", {})
        }
        
        return stats
        
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface != 'localhost':
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        return interface
                        
        except Exception as e:
            logger.error(f"Error determining default interface: {e}")
            
        return None 

    def _maybe_save_traffic_snapshot(self) -> None:
        """Save traffic snapshot if enough time has passed."""
        if not self.db_session_id:
            return
            
        now = datetime.now()
        
        # Initialize last snapshot time if needed
        if self.stats['last_snapshot_time'] is None:
            self.stats['last_snapshot_time'] = now
            return
            
        # Check if it's time for a new snapshot (every 10 seconds)
        time_since_last = (now - self.stats['last_snapshot_time']).total_seconds()
        if time_since_last >= 10:
            self._save_traffic_snapshot()
            self.stats['last_snapshot_time'] = now
    
    def _save_traffic_snapshot(self) -> None:
        """Save a traffic snapshot to the database."""
        if not self.db_session_id:
            return
            
        try:
            # Get current statistics
            stats = self.get_statistics()
            
            # Prepare protocol stats
            protocol_stats = {}
            for proto, count in self.protocol_counts.items():
                protocol_stats[proto] = {
                    'count': count,
                    'bytes': self.bytes_analyzed
                }
                
            # Add protocol stats to database
            self.database.add_protocol_stats(
                self.db_session_id,
                datetime.now(),
                protocol_stats
            )
            
            # Prepare IP stats
            ip_stats = {}
            for ip, traffic in self.ip_counts.items():
                ip_stats[ip] = {
                    'sent_packets': traffic,
                    'recv_packets': self.dst_ip_counts[ip],
                    'sent_bytes': self.bytes_analyzed
                }
                
            # Add IP stats to database
            self.database.add_ip_stats(
                self.db_session_id,
                datetime.now(),
                ip_stats
            )
            
            # Add traffic snapshot
            self.database.add_traffic_snapshot(
                self.db_session_id,
                datetime.now(),
                stats['duration_seconds'],
                stats['packets_analyzed'],
                stats['bytes_analyzed'],
                stats['packets_per_second'],
                stats['bytes_per_second'],
                {
                    'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
                    'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
                    'tcp_ports': dict(Counter(self.port_counts).most_common(10)),
                    'http_methods': dict(Counter(self.protocol_counts).most_common(10)),
                    'dns_queries': dict(Counter(self.protocol_counts).most_common(10))
                }
            )
            
            logger.debug(f"Saved traffic snapshot for session {self.db_session_id}")
            
        except Exception as e:
            logger.error(f"Error saving traffic snapshot: {e}")
        
    def _handle_memory_pressure(self, level: MemoryPressureLevel):
        """
        Handle changes in memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        logger.info(f"Memory pressure changed to {level}, adjusting packet capture behavior")
        
        # Adjust buffer size based on memory pressure
        new_buffer_size = max(10, self.memory_manager.get_max_buffer_size() // 10)
        
        # Log the change
        logger.info(f"Adjusting packet buffer size from {self.buffer_size} to {new_buffer_size}")
        
        # Update buffer size
        self.buffer_size = new_buffer_size
        
        # Trim history if pressure is high or critical
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL):
            self._trim_packet_history(aggressive=True)
            
        # Process any pending packets in buffer if high/critical pressure
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL) and len(self.packet_buffer) > 0:
            self._process_packet_buffer()

        # Register the adaptive action
        self.memory_manager.register_adaptive_action()
        
    def _trim_packet_history(self, aggressive=False):
        """
        Trim packet history to reduce memory usage.
        
        Args:
            aggressive: If True, trim more aggressively
        """
        if not self.packet_history:
            return
            
        current_size = len(self.packet_history)
        
        if aggressive:
            # Keep only 25% of packets during high memory pressure
            target_size = max(100, current_size // 4)
        else:
            # Keep 50% of packets during normal trim
            target_size = max(100, current_size // 2)
            
        if current_size > target_size:
            # Keep newest packets, discard oldest
            self.packet_history = self.packet_history[-target_size:]
            logger.info(f"Trimmed packet history from {current_size} to {len(self.packet_history)}")
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory management statistics.
        
        Returns:
            Dict containing memory statistics
        """
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        stats = {
            "current_memory_usage": mem_metrics.get("current_memory_usage", 0),
            "peak_memory_usage": mem_metrics.get("peak_memory_usage", 0),
            "memory_pressure_level": mem_metrics.get("current_pressure_level", "LOW"),
            "memory_checks": mem_metrics.get("memory_checks", 0),
            "pressure_changes": mem_metrics.get("pressure_changes", 0),
            "gc_invocations": mem_metrics.get("gc_invocations", 0),
            "packets_dropped": mem_metrics.get("packets_dropped", 0) + self.mem_packets_dropped,
            "packets_optimized": optimizer_metrics.get("packets_optimized", 0),
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0),
            "payloads_truncated": optimizer_metrics.get("payloads_truncated", 0),
            "buffer_size": self.buffer_size,
            "max_buffer_size": self.memory_manager.get_max_buffer_size(),
            "history_size": len(self.packet_history),
            "ip_cache_size": optimizer_metrics.get("ip_cache_size", 0),
            "mac_cache_size": optimizer_metrics.get("mac_cache_size", 0),
            "current_strategy": {
                "sampling_rate": self.memory_manager.get_current_strategy().get("sampling_rate", 1.0),
                "max_payload_size": self.packet_optimizer.max_payload_size
            },
            "process_memory": mem_metrics.get("process_memory", {})
        }
        
        return stats
        
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface != 'localhost':
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        return interface
                        
        except Exception as e:
            logger.error(f"Error determining default interface: {e}")
            
        return None 

    def _maybe_save_traffic_snapshot(self) -> None:
        """Save traffic snapshot if enough time has passed."""
        if not self.db_session_id:
            return
            
        now = datetime.now()
        
        # Initialize last snapshot time if needed
        if self.stats['last_snapshot_time'] is None:
            self.stats['last_snapshot_time'] = now
            return
            
        # Check if it's time for a new snapshot (every 10 seconds)
        time_since_last = (now - self.stats['last_snapshot_time']).total_seconds()
        if time_since_last >= 10:
            self._save_traffic_snapshot()
            self.stats['last_snapshot_time'] = now
    
    def _save_traffic_snapshot(self) -> None:
        """Save a traffic snapshot to the database."""
        if not self.db_session_id:
            return
            
        try:
            # Get current statistics
            stats = self.get_statistics()
            
            # Prepare protocol stats
            protocol_stats = {}
            for proto, count in self.protocol_counts.items():
                protocol_stats[proto] = {
                    'count': count,
                    'bytes': self.bytes_analyzed
                }
                
            # Add protocol stats to database
            self.database.add_protocol_stats(
                self.db_session_id,
                datetime.now(),
                protocol_stats
            )
            
            # Prepare IP stats
            ip_stats = {}
            for ip, traffic in self.ip_counts.items():
                ip_stats[ip] = {
                    'sent_packets': traffic,
                    'recv_packets': self.dst_ip_counts[ip],
                    'sent_bytes': self.bytes_analyzed
                }
                
            # Add IP stats to database
            self.database.add_ip_stats(
                self.db_session_id,
                datetime.now(),
                ip_stats
            )
            
            # Add traffic snapshot
            self.database.add_traffic_snapshot(
                self.db_session_id,
                datetime.now(),
                stats['duration_seconds'],
                stats['packets_analyzed'],
                stats['bytes_analyzed'],
                stats['packets_per_second'],
                stats['bytes_per_second'],
                {
                    'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
                    'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
                    'tcp_ports': dict(Counter(self.port_counts).most_common(10)),
                    'http_methods': dict(Counter(self.protocol_counts).most_common(10)),
                    'dns_queries': dict(Counter(self.protocol_counts).most_common(10))
                }
            )
            
            logger.debug(f"Saved traffic snapshot for session {self.db_session_id}")
            
        except Exception as e:
            logger.error(f"Error saving traffic snapshot: {e}")
        
    def _handle_memory_pressure(self, level: MemoryPressureLevel):
        """
        Handle changes in memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        logger.info(f"Memory pressure changed to {level}, adjusting packet capture behavior")
        
        # Adjust buffer size based on memory pressure
        new_buffer_size = max(10, self.memory_manager.get_max_buffer_size() // 10)
        
        # Log the change
        logger.info(f"Adjusting packet buffer size from {self.buffer_size} to {new_buffer_size}")
        
        # Update buffer size
        self.buffer_size = new_buffer_size
        
        # Trim history if pressure is high or critical
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL):
            self._trim_packet_history(aggressive=True)
            
        # Process any pending packets in buffer if high/critical pressure
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL) and len(self.packet_buffer) > 0:
            self._process_packet_buffer()

        # Register the adaptive action
        self.memory_manager.register_adaptive_action()
        
    def _trim_packet_history(self, aggressive=False):
        """
        Trim packet history to reduce memory usage.
        
        Args:
            aggressive: If True, trim more aggressively
        """
        if not self.packet_history:
            return
            
        current_size = len(self.packet_history)
        
        if aggressive:
            # Keep only 25% of packets during high memory pressure
            target_size = max(100, current_size // 4)
        else:
            # Keep 50% of packets during normal trim
            target_size = max(100, current_size // 2)
            
        if current_size > target_size:
            # Keep newest packets, discard oldest
            self.packet_history = self.packet_history[-target_size:]
            logger.info(f"Trimmed packet history from {current_size} to {len(self.packet_history)}")
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory management statistics.
        
        Returns:
            Dict containing memory statistics
        """
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        stats = {
            "current_memory_usage": mem_metrics.get("current_memory_usage", 0),
            "peak_memory_usage": mem_metrics.get("peak_memory_usage", 0),
            "memory_pressure_level": mem_metrics.get("current_pressure_level", "LOW"),
            "memory_checks": mem_metrics.get("memory_checks", 0),
            "pressure_changes": mem_metrics.get("pressure_changes", 0),
            "gc_invocations": mem_metrics.get("gc_invocations", 0),
            "packets_dropped": mem_metrics.get("packets_dropped", 0) + self.mem_packets_dropped,
            "packets_optimized": optimizer_metrics.get("packets_optimized", 0),
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0),
            "payloads_truncated": optimizer_metrics.get("payloads_truncated", 0),
            "buffer_size": self.buffer_size,
            "max_buffer_size": self.memory_manager.get_max_buffer_size(),
            "history_size": len(self.packet_history),
            "ip_cache_size": optimizer_metrics.get("ip_cache_size", 0),
            "mac_cache_size": optimizer_metrics.get("mac_cache_size", 0),
            "current_strategy": {
                "sampling_rate": self.memory_manager.get_current_strategy().get("sampling_rate", 1.0),
                "max_payload_size": self.packet_optimizer.max_payload_size
            },
            "process_memory": mem_metrics.get("process_memory", {})
        }
        
        return stats
        
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface != 'localhost':
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        return interface
                        
        except Exception as e:
            logger.error(f"Error determining default interface: {e}")
            
        return None 

    def _maybe_save_traffic_snapshot(self) -> None:
        """Save traffic snapshot if enough time has passed."""
        if not self.db_session_id:
            return
            
        now = datetime.now()
        
        # Initialize last snapshot time if needed
        if self.stats['last_snapshot_time'] is None:
            self.stats['last_snapshot_time'] = now
            return
            
        # Check if it's time for a new snapshot (every 10 seconds)
        time_since_last = (now - self.stats['last_snapshot_time']).total_seconds()
        if time_since_last >= 10:
            self._save_traffic_snapshot()
            self.stats['last_snapshot_time'] = now
    
    def _save_traffic_snapshot(self) -> None:
        """Save a traffic snapshot to the database."""
        if not self.db_session_id:
            return
            
        try:
            # Get current statistics
            stats = self.get_statistics()
            
            # Prepare protocol stats
            protocol_stats = {}
            for proto, count in self.protocol_counts.items():
                protocol_stats[proto] = {
                    'count': count,
                    'bytes': self.bytes_analyzed
                }
                
            # Add protocol stats to database
            self.database.add_protocol_stats(
                self.db_session_id,
                datetime.now(),
                protocol_stats
            )
            
            # Prepare IP stats
            ip_stats = {}
            for ip, traffic in self.ip_counts.items():
                ip_stats[ip] = {
                    'sent_packets': traffic,
                    'recv_packets': self.dst_ip_counts[ip],
                    'sent_bytes': self.bytes_analyzed
                }
                
            # Add IP stats to database
            self.database.add_ip_stats(
                self.db_session_id,
                datetime.now(),
                ip_stats
            )
            
            # Add traffic snapshot
            self.database.add_traffic_snapshot(
                self.db_session_id,
                datetime.now(),
                stats['duration_seconds'],
                stats['packets_analyzed'],
                stats['bytes_analyzed'],
                stats['packets_per_second'],
                stats['bytes_per_second'],
                {
                    'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
                    'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
                    'tcp_ports': dict(Counter(self.port_counts).most_common(10)),
                    'http_methods': dict(Counter(self.protocol_counts).most_common(10)),
                    'dns_queries': dict(Counter(self.protocol_counts).most_common(10))
                }
            )
            
            logger.debug(f"Saved traffic snapshot for session {self.db_session_id}")
            
        except Exception as e:
            logger.error(f"Error saving traffic snapshot: {e}")
        
    def _handle_memory_pressure(self, level: MemoryPressureLevel):
        """
        Handle changes in memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        logger.info(f"Memory pressure changed to {level}, adjusting packet capture behavior")
        
        # Adjust buffer size based on memory pressure
        new_buffer_size = max(10, self.memory_manager.get_max_buffer_size() // 10)
        
        # Log the change
        logger.info(f"Adjusting packet buffer size from {self.buffer_size} to {new_buffer_size}")
        
        # Update buffer size
        self.buffer_size = new_buffer_size
        
        # Trim history if pressure is high or critical
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL):
            self._trim_packet_history(aggressive=True)
            
        # Process any pending packets in buffer if high/critical pressure
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL) and len(self.packet_buffer) > 0:
            self._process_packet_buffer()

        # Register the adaptive action
        self.memory_manager.register_adaptive_action()
        
    def _trim_packet_history(self, aggressive=False):
        """
        Trim packet history to reduce memory usage.
        
        Args:
            aggressive: If True, trim more aggressively
        """
        if not self.packet_history:
            return
            
        current_size = len(self.packet_history)
        
        if aggressive:
            # Keep only 25% of packets during high memory pressure
            target_size = max(100, current_size // 4)
        else:
            # Keep 50% of packets during normal trim
            target_size = max(100, current_size // 2)
            
        if current_size > target_size:
            # Keep newest packets, discard oldest
            self.packet_history = self.packet_history[-target_size:]
            logger.info(f"Trimmed packet history from {current_size} to {len(self.packet_history)}")
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory management statistics.
        
        Returns:
            Dict containing memory statistics
        """
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        stats = {
            "current_memory_usage": mem_metrics.get("current_memory_usage", 0),
            "peak_memory_usage": mem_metrics.get("peak_memory_usage", 0),
            "memory_pressure_level": mem_metrics.get("current_pressure_level", "LOW"),
            "memory_checks": mem_metrics.get("memory_checks", 0),
            "pressure_changes": mem_metrics.get("pressure_changes", 0),
            "gc_invocations": mem_metrics.get("gc_invocations", 0),
            "packets_dropped": mem_metrics.get("packets_dropped", 0) + self.mem_packets_dropped,
            "packets_optimized": optimizer_metrics.get("packets_optimized", 0),
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0),
            "payloads_truncated": optimizer_metrics.get("payloads_truncated", 0),
            "buffer_size": self.buffer_size,
            "max_buffer_size": self.memory_manager.get_max_buffer_size(),
            "history_size": len(self.packet_history),
            "ip_cache_size": optimizer_metrics.get("ip_cache_size", 0),
            "mac_cache_size": optimizer_metrics.get("mac_cache_size", 0),
            "current_strategy": {
                "sampling_rate": self.memory_manager.get_current_strategy().get("sampling_rate", 1.0),
                "max_payload_size": self.packet_optimizer.max_payload_size
            },
            "process_memory": mem_metrics.get("process_memory", {})
        }
        
        return stats
        
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface != 'localhost':
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        return interface
                        
        except Exception as e:
            logger.error(f"Error determining default interface: {e}")
            
        return None 

    def _maybe_save_traffic_snapshot(self) -> None:
        """Save traffic snapshot if enough time has passed."""
        if not self.db_session_id:
            return
            
        now = datetime.now()
        
        # Initialize last snapshot time if needed
        if self.stats['last_snapshot_time'] is None:
            self.stats['last_snapshot_time'] = now
            return
            
        # Check if it's time for a new snapshot (every 10 seconds)
        time_since_last = (now - self.stats['last_snapshot_time']).total_seconds()
        if time_since_last >= 10:
            self._save_traffic_snapshot()
            self.stats['last_snapshot_time'] = now
    
    def _save_traffic_snapshot(self) -> None:
        """Save a traffic snapshot to the database."""
        if not self.db_session_id:
            return
            
        try:
            # Get current statistics
            stats = self.get_statistics()
            
            # Prepare protocol stats
            protocol_stats = {}
            for proto, count in self.protocol_counts.items():
                protocol_stats[proto] = {
                    'count': count,
                    'bytes': self.bytes_analyzed
                }
                
            # Add protocol stats to database
            self.database.add_protocol_stats(
                self.db_session_id,
                datetime.now(),
                protocol_stats
            )
            
            # Prepare IP stats
            ip_stats = {}
            for ip, traffic in self.ip_counts.items():
                ip_stats[ip] = {
                    'sent_packets': traffic,
                    'recv_packets': self.dst_ip_counts[ip],
                    'sent_bytes': self.bytes_analyzed
                }
                
            # Add IP stats to database
            self.database.add_ip_stats(
                self.db_session_id,
                datetime.now(),
                ip_stats
            )
            
            # Add traffic snapshot
            self.database.add_traffic_snapshot(
                self.db_session_id,
                datetime.now(),
                stats['duration_seconds'],
                stats['packets_analyzed'],
                stats['bytes_analyzed'],
                stats['packets_per_second'],
                stats['bytes_per_second'],
                {
                    'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
                    'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
                    'tcp_ports': dict(Counter(self.port_counts).most_common(10)),
                    'http_methods': dict(Counter(self.protocol_counts).most_common(10)),
                    'dns_queries': dict(Counter(self.protocol_counts).most_common(10))
                }
            )
            
            logger.debug(f"Saved traffic snapshot for session {self.db_session_id}")
            
        except Exception as e:
            logger.error(f"Error saving traffic snapshot: {e}")
        
    def _handle_memory_pressure(self, level: MemoryPressureLevel):
        """
        Handle changes in memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        logger.info(f"Memory pressure changed to {level}, adjusting packet capture behavior")
        
        # Adjust buffer size based on memory pressure
        new_buffer_size = max(10, self.memory_manager.get_max_buffer_size() // 10)
        
        # Log the change
        logger.info(f"Adjusting packet buffer size from {self.buffer_size} to {new_buffer_size}")
        
        # Update buffer size
        self.buffer_size = new_buffer_size
        
        # Trim history if pressure is high or critical
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL):
            self._trim_packet_history(aggressive=True)
            
        # Process any pending packets in buffer if high/critical pressure
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL) and len(self.packet_buffer) > 0:
            self._process_packet_buffer()

        # Register the adaptive action
        self.memory_manager.register_adaptive_action()
        
    def _trim_packet_history(self, aggressive=False):
        """
        Trim packet history to reduce memory usage.
        
        Args:
            aggressive: If True, trim more aggressively
        """
        if not self.packet_history:
            return
            
        current_size = len(self.packet_history)
        
        if aggressive:
            # Keep only 25% of packets during high memory pressure
            target_size = max(100, current_size // 4)
        else:
            # Keep 50% of packets during normal trim
            target_size = max(100, current_size // 2)
            
        if current_size > target_size:
            # Keep newest packets, discard oldest
            self.packet_history = self.packet_history[-target_size:]
            logger.info(f"Trimmed packet history from {current_size} to {len(self.packet_history)}")
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory management statistics.
        
        Returns:
            Dict containing memory statistics
        """
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        stats = {
            "current_memory_usage": mem_metrics.get("current_memory_usage", 0),
            "peak_memory_usage": mem_metrics.get("peak_memory_usage", 0),
            "memory_pressure_level": mem_metrics.get("current_pressure_level", "LOW"),
            "memory_checks": mem_metrics.get("memory_checks", 0),
            "pressure_changes": mem_metrics.get("pressure_changes", 0),
            "gc_invocations": mem_metrics.get("gc_invocations", 0),
            "packets_dropped": mem_metrics.get("packets_dropped", 0) + self.mem_packets_dropped,
            "packets_optimized": optimizer_metrics.get("packets_optimized", 0),
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0),
            "payloads_truncated": optimizer_metrics.get("payloads_truncated", 0),
            "buffer_size": self.buffer_size,
            "max_buffer_size": self.memory_manager.get_max_buffer_size(),
            "history_size": len(self.packet_history),
            "ip_cache_size": optimizer_metrics.get("ip_cache_size", 0),
            "mac_cache_size": optimizer_metrics.get("mac_cache_size", 0),
            "current_strategy": {
                "sampling_rate": self.memory_manager.get_current_strategy().get("sampling_rate", 1.0),
                "max_payload_size": self.packet_optimizer.max_payload_size
            },
            "process_memory": mem_metrics.get("process_memory", {})
        }
        
        return stats
        
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface != 'localhost':
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        return interface
                        
        except Exception as e:
            logger.error(f"Error determining default interface: {e}")
            
        return None 

    def _maybe_save_traffic_snapshot(self) -> None:
        """Save traffic snapshot if enough time has passed."""
        if not self.db_session_id:
            return
            
        now = datetime.now()
        
        # Initialize last snapshot time if needed
        if self.stats['last_snapshot_time'] is None:
            self.stats['last_snapshot_time'] = now
            return
            
        # Check if it's time for a new snapshot (every 10 seconds)
        time_since_last = (now - self.stats['last_snapshot_time']).total_seconds()
        if time_since_last >= 10:
            self._save_traffic_snapshot()
            self.stats['last_snapshot_time'] = now
    
    def _save_traffic_snapshot(self) -> None:
        """Save a traffic snapshot to the database."""
        if not self.db_session_id:
            return
            
        try:
            # Get current statistics
            stats = self.get_statistics()
            
            # Prepare protocol stats
            protocol_stats = {}
            for proto, count in self.protocol_counts.items():
                protocol_stats[proto] = {
                    'count': count,
                    'bytes': self.bytes_analyzed
                }
                
            # Add protocol stats to database
            self.database.add_protocol_stats(
                self.db_session_id,
                datetime.now(),
                protocol_stats
            )
            
            # Prepare IP stats
            ip_stats = {}
            for ip, traffic in self.ip_counts.items():
                ip_stats[ip] = {
                    'sent_packets': traffic,
                    'recv_packets': self.dst_ip_counts[ip],
                    'sent_bytes': self.bytes_analyzed
                }
                
            # Add IP stats to database
            self.database.add_ip_stats(
                self.db_session_id,
                datetime.now(),
                ip_stats
            )
            
            # Add traffic snapshot
            self.database.add_traffic_snapshot(
                self.db_session_id,
                datetime.now(),
                stats['duration_seconds'],
                stats['packets_analyzed'],
                stats['bytes_analyzed'],
                stats['packets_per_second'],
                stats['bytes_per_second'],
                {
                    'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
                    'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
                    'tcp_ports': dict(Counter(self.port_counts).most_common(10)),
                    'http_methods': dict(Counter(self.protocol_counts).most_common(10)),
                    'dns_queries': dict(Counter(self.protocol_counts).most_common(10))
                }
            )
            
            logger.debug(f"Saved traffic snapshot for session {self.db_session_id}")
            
        except Exception as e:
            logger.error(f"Error saving traffic snapshot: {e}")
        
    def _handle_memory_pressure(self, level: MemoryPressureLevel):
        """
        Handle changes in memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        logger.info(f"Memory pressure changed to {level}, adjusting packet capture behavior")
        
        # Adjust buffer size based on memory pressure
        new_buffer_size = max(10, self.memory_manager.get_max_buffer_size() // 10)
        
        # Log the change
        logger.info(f"Adjusting packet buffer size from {self.buffer_size} to {new_buffer_size}")
        
        # Update buffer size
        self.buffer_size = new_buffer_size
        
        # Trim history if pressure is high or critical
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL):
            self._trim_packet_history(aggressive=True)
            
        # Process any pending packets in buffer if high/critical pressure
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL) and len(self.packet_buffer) > 0:
            self._process_packet_buffer()

        # Register the adaptive action
        self.memory_manager.register_adaptive_action()
        
    def _trim_packet_history(self, aggressive=False):
        """
        Trim packet history to reduce memory usage.
        
        Args:
            aggressive: If True, trim more aggressively
        """
        if not self.packet_history:
            return
            
        current_size = len(self.packet_history)
        
        if aggressive:
            # Keep only 25% of packets during high memory pressure
            target_size = max(100, current_size // 4)
        else:
            # Keep 50% of packets during normal trim
            target_size = max(100, current_size // 2)
            
        if current_size > target_size:
            # Keep newest packets, discard oldest
            self.packet_history = self.packet_history[-target_size:]
            logger.info(f"Trimmed packet history from {current_size} to {len(self.packet_history)}")
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory management statistics.
        
        Returns:
            Dict containing memory statistics
        """
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        stats = {
            "current_memory_usage": mem_metrics.get("current_memory_usage", 0),
            "peak_memory_usage": mem_metrics.get("peak_memory_usage", 0),
            "memory_pressure_level": mem_metrics.get("current_pressure_level", "LOW"),
            "memory_checks": mem_metrics.get("memory_checks", 0),
            "pressure_changes": mem_metrics.get("pressure_changes", 0),
            "gc_invocations": mem_metrics.get("gc_invocations", 0),
            "packets_dropped": mem_metrics.get("packets_dropped", 0) + self.mem_packets_dropped,
            "packets_optimized": optimizer_metrics.get("packets_optimized", 0),
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0),
            "payloads_truncated": optimizer_metrics.get("payloads_truncated", 0),
            "buffer_size": self.buffer_size,
            "max_buffer_size": self.memory_manager.get_max_buffer_size(),
            "history_size": len(self.packet_history),
            "ip_cache_size": optimizer_metrics.get("ip_cache_size", 0),
            "mac_cache_size": optimizer_metrics.get("mac_cache_size", 0),
            "current_strategy": {
                "sampling_rate": self.memory_manager.get_current_strategy().get("sampling_rate", 1.0),
                "max_payload_size": self.packet_optimizer.max_payload_size
            },
            "process_memory": mem_metrics.get("process_memory", {})
        }
        
        return stats
        
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface != 'localhost':
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        return interface
                        
        except Exception as e:
            logger.error(f"Error determining default interface: {e}")
            
        return None 

    def _maybe_save_traffic_snapshot(self) -> None:
        """Save traffic snapshot if enough time has passed."""
        if not self.db_session_id:
            return
            
        now = datetime.now()
        
        # Initialize last snapshot time if needed
        if self.stats['last_snapshot_time'] is None:
            self.stats['last_snapshot_time'] = now
            return
            
        # Check if it's time for a new snapshot (every 10 seconds)
        time_since_last = (now - self.stats['last_snapshot_time']).total_seconds()
        if time_since_last >= 10:
            self._save_traffic_snapshot()
            self.stats['last_snapshot_time'] = now
    
    def _save_traffic_snapshot(self) -> None:
        """Save a traffic snapshot to the database."""
        if not self.db_session_id:
            return
            
        try:
            # Get current statistics
            stats = self.get_statistics()
            
            # Prepare protocol stats
            protocol_stats = {}
            for proto, count in self.protocol_counts.items():
                protocol_stats[proto] = {
                    'count': count,
                    'bytes': self.bytes_analyzed
                }
                
            # Add protocol stats to database
            self.database.add_protocol_stats(
                self.db_session_id,
                datetime.now(),
                protocol_stats
            )
            
            # Prepare IP stats
            ip_stats = {}
            for ip, traffic in self.ip_counts.items():
                ip_stats[ip] = {
                    'sent_packets': traffic,
                    'recv_packets': self.dst_ip_counts[ip],
                    'sent_bytes': self.bytes_analyzed
                }
                
            # Add IP stats to database
            self.database.add_ip_stats(
                self.db_session_id,
                datetime.now(),
                ip_stats
            )
            
            # Add traffic snapshot
            self.database.add_traffic_snapshot(
                self.db_session_id,
                datetime.now(),
                stats['duration_seconds'],
                stats['packets_analyzed'],
                stats['bytes_analyzed'],
                stats['packets_per_second'],
                stats['bytes_per_second'],
                {
                    'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
                    'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
                    'tcp_ports': dict(Counter(self.port_counts).most_common(10)),
                    'http_methods': dict(Counter(self.protocol_counts).most_common(10)),
                    'dns_queries': dict(Counter(self.protocol_counts).most_common(10))
                }
            )
            
            logger.debug(f"Saved traffic snapshot for session {self.db_session_id}")
            
        except Exception as e:
            logger.error(f"Error saving traffic snapshot: {e}")
        
    def _handle_memory_pressure(self, level: MemoryPressureLevel):
        """
        Handle changes in memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        logger.info(f"Memory pressure changed to {level}, adjusting packet capture behavior")
        
        # Adjust buffer size based on memory pressure
        new_buffer_size = max(10, self.memory_manager.get_max_buffer_size() // 10)
        
        # Log the change
        logger.info(f"Adjusting packet buffer size from {self.buffer_size} to {new_buffer_size}")
        
        # Update buffer size
        self.buffer_size = new_buffer_size
        
        # Trim history if pressure is high or critical
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL):
            self._trim_packet_history(aggressive=True)
            
        # Process any pending packets in buffer if high/critical pressure
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL) and len(self.packet_buffer) > 0:
            self._process_packet_buffer()

        # Register the adaptive action
        self.memory_manager.register_adaptive_action()
        
    def _trim_packet_history(self, aggressive=False):
        """
        Trim packet history to reduce memory usage.
        
        Args:
            aggressive: If True, trim more aggressively
        """
        if not self.packet_history:
            return
            
        current_size = len(self.packet_history)
        
        if aggressive:
            # Keep only 25% of packets during high memory pressure
            target_size = max(100, current_size // 4)
        else:
            # Keep 50% of packets during normal trim
            target_size = max(100, current_size // 2)
            
        if current_size > target_size:
            # Keep newest packets, discard oldest
            self.packet_history = self.packet_history[-target_size:]
            logger.info(f"Trimmed packet history from {current_size} to {len(self.packet_history)}")
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory management statistics.
        
        Returns:
            Dict containing memory statistics
        """
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        stats = {
            "current_memory_usage": mem_metrics.get("current_memory_usage", 0),
            "peak_memory_usage": mem_metrics.get("peak_memory_usage", 0),
            "memory_pressure_level": mem_metrics.get("current_pressure_level", "LOW"),
            "memory_checks": mem_metrics.get("memory_checks", 0),
            "pressure_changes": mem_metrics.get("pressure_changes", 0),
            "gc_invocations": mem_metrics.get("gc_invocations", 0),
            "packets_dropped": mem_metrics.get("packets_dropped", 0) + self.mem_packets_dropped,
            "packets_optimized": optimizer_metrics.get("packets_optimized", 0),
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0),
            "payloads_truncated": optimizer_metrics.get("payloads_truncated", 0),
            "buffer_size": self.buffer_size,
            "max_buffer_size": self.memory_manager.get_max_buffer_size(),
            "history_size": len(self.packet_history),
            "ip_cache_size": optimizer_metrics.get("ip_cache_size", 0),
            "mac_cache_size": optimizer_metrics.get("mac_cache_size", 0),
            "current_strategy": {
                "sampling_rate": self.memory_manager.get_current_strategy().get("sampling_rate", 1.0),
                "max_payload_size": self.packet_optimizer.max_payload_size
            },
            "process_memory": mem_metrics.get("process_memory", {})
        }
        
        return stats
        
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            for interface in netifaces.interfaces():
                if interface != 'lo' and interface != 'localhost':
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        return interface
                        
        except Exception as e:
            logger.error(f"Error determining default interface: {e}")
            
        return None 

    def _maybe_save_traffic_snapshot(self) -> None:
        """Save traffic snapshot if enough time has passed."""
        if not self.db_session_id:
            return
            
        now = datetime.now()
        
        # Initialize last snapshot time if needed
        if self.stats['last_snapshot_time'] is None:
            self.stats['last_snapshot_time'] = now
            return
            
        # Check if it's time for a new snapshot (every 10 seconds)
        time_since_last = (now - self.stats['last_snapshot_time']).total_seconds()
        if time_since_last >= 10:
            self._save_traffic_snapshot()
            self.stats['last_snapshot_time'] = now
    
    def _save_traffic_snapshot(self) -> None:
        """Save a traffic snapshot to the database."""
        if not self.db_session_id:
            return
            
        try:
            # Get current statistics
            stats = self.get_statistics()
            
            # Prepare protocol stats
            protocol_stats = {}
            for proto, count in self.protocol_counts.items():
                protocol_stats[proto] = {
                    'count': count,
                    'bytes': self.bytes_analyzed
                }
                
            # Add protocol stats to database
            self.database.add_protocol_stats(
                self.db_session_id,
                datetime.now(),
                protocol_stats
            )
            
            # Prepare IP stats
            ip_stats = {}
            for ip, traffic in self.ip_counts.items():
                ip_stats[ip] = {
                    'sent_packets': traffic,
                    'recv_packets': self.dst_ip_counts[ip],
                    'sent_bytes': self.bytes_analyzed
                }
                
            # Add IP stats to database
            self.database.add_ip_stats(
                self.db_session_id,
                datetime.now(),
                ip_stats
            )
            
            # Add traffic snapshot
            self.database.add_traffic_snapshot(
                self.db_session_id,
                datetime.now(),
                stats['duration_seconds'],
                stats['packets_analyzed'],
                stats['bytes_analyzed'],
                stats['packets_per_second'],
                stats['bytes_per_second'],
                {
                    'top_source_ips': dict(Counter(self.ip_counts).most_common(10)),
                    'top_destination_ips': dict(Counter(self.dst_ip_counts).most_common(10)),
                    'tcp_ports': dict(Counter(self.port_counts).most_common(10)),
                    'http_methods': dict(Counter(self.protocol_counts).most_common(10)),
                    'dns_queries': dict(Counter(self.protocol_counts).most_common(10))
                }
            )
            
            logger.debug(f"Saved traffic snapshot for session {self.db_session_id}")
            
        except Exception as e:
            logger.error(f"Error saving traffic snapshot: {e}")
        
    def _handle_memory_pressure(self, level: MemoryPressureLevel):
        """
        Handle changes in memory pressure level.
        
        Args:
            level: New memory pressure level
        """
        logger.info(f"Memory pressure changed to {level}, adjusting packet capture behavior")
        
        # Adjust buffer size based on memory pressure
        new_buffer_size = max(10, self.memory_manager.get_max_buffer_size() // 10)
        
        # Log the change
        logger.info(f"Adjusting packet buffer size from {self.buffer_size} to {new_buffer_size}")
        
        # Update buffer size
        self.buffer_size = new_buffer_size
        
        # Trim history if pressure is high or critical
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL):
            self._trim_packet_history(aggressive=True)
            
        # Process any pending packets in buffer if high/critical pressure
        if level in (MemoryPressureLevel.HIGH, MemoryPressureLevel.CRITICAL) and len(self.packet_buffer) > 0:
            self._process_packet_buffer()

        # Register the adaptive action
        self.memory_manager.register_adaptive_action()
        
    def _trim_packet_history(self, aggressive=False):
        """
        Trim packet history to reduce memory usage.
        
        Args:
            aggressive: If True, trim more aggressively
        """
        if not self.packet_history:
            return
            
        current_size = len(self.packet_history)
        
        if aggressive:
            # Keep only 25% of packets during high memory pressure
            target_size = max(100, current_size // 4)
        else:
            # Keep 50% of packets during normal trim
            target_size = max(100, current_size // 2)
            
        if current_size > target_size:
            # Keep newest packets, discard oldest
            self.packet_history = self.packet_history[-target_size:]
            logger.info(f"Trimmed packet history from {current_size} to {len(self.packet_history)}")
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory management statistics.
        
        Returns:
            Dict containing memory statistics
        """
        mem_metrics = self.memory_manager.get_metrics()
        optimizer_metrics = self.packet_optimizer.get_metrics()
        
        stats = {
            "current_memory_usage": mem_metrics.get("current_memory_usage", 0),
            "peak_memory_usage": mem_metrics.get("peak_memory_usage", 0),
            "memory_pressure_level": mem_metrics.get("current_pressure_level", "LOW"),
            "memory_checks": mem_metrics.get("memory_checks", 0),
            "pressure_changes": mem_metrics.get("pressure_changes", 0),
            "gc_invocations": mem_metrics.get("gc_invocations", 0),
            "packets_dropped": mem_metrics.get("packets_dropped", 0) + self.mem_packets_dropped,
            "packets_optimized": optimizer_metrics.get("packets_optimized", 0),
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0),
            "payloads_truncated": optimizer_metrics.get("payloads_truncated", 0),
            "buffer_size": self.buffer_size,
            "max_buffer_size": self.memory_manager.get_max_buffer_size(),
            "history_size": len(self.packet_history),
            "ip_cache_size": optimizer_metrics.get("ip_cache_size", 0),
            "mac_cache_size": optimizer_metrics.get("mac_cache_size", 0),
            "current_strategy": {
                "sampling_rate": self.memory_manager.get_current_strategy().get("sampling_rate", 1.0),
                "max_payload_size": self.packet_optimizer.max_payload_size
            },
            "process_memory": mem_metrics.get("process_memory", {})
        }
        
        return stats
        
    def _reset_statistics(self):
        """Reset all statistical counters."""
        self.protocol_counts = Counter()
        self.ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.connection_pairs = set()
        self.bytes_analyzed = 0
        self.packets_analyzed = 0
        self.packet_history = []
        
    def _send_status_update(self):
        """Send a status update via the callback if registered."""
        if not self.status_callback:
            return
            
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        packets_per_second = self.packets_analyzed / max(1, duration)
        
        status_message = (
            f"Captured {self.packets_analyzed} packets "
            f"({self.bytes_analyzed} bytes) in {duration:.1f} seconds "
            f"({packets_per_second:.1f} packets/sec)"
        )
        
        self.status_callback(True, status_message)
        
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface.
        
        Returns:
            str: Interface name or None if unavailable
        """
        try:
            # Get the default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                _, interface = gateways['default'][netifaces.AF_INET]
                return interface
                
            # If no default found, try to use the first non-loopback interface
            "bytes_saved": optimizer_metrics.get("bytes_saved", 0