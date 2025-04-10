"""
Packet Analyzer Module for ARP Guard
Handles packet capture, filtering, and analysis
"""

import os
import time
import json
import logging
import threading
import gc
from typing import Dict, List, Set, Optional, Callable, Tuple, Any
from enum import Enum
from dataclasses import dataclass
from datetime import datetime
import ipaddress
from collections import deque
import multiprocessing
from concurrent.futures import ThreadPoolExecutor

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    
try:
    from scapy.all import ARP, sniff, Ether, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)

# Constants for optimization
BATCH_SIZE = 50  # Process packets in batches of this size
MAX_WORKER_THREADS = min(4, multiprocessing.cpu_count())
MEMORY_CHECK_INTERVAL = 10  # Check memory usage every 10 seconds
DEFAULT_MEMORY_LIMIT_MB = 512  # Default memory limit in MB


class PacketType(Enum):
    """Enum for different packet types"""
    ARP_REQUEST = "arp_request"
    ARP_REPLY = "arp_reply"
    ARP_ANNOUNCEMENT = "arp_announcement"
    ARP_PROBE = "arp_probe"
    ARP_UNKNOWN = "arp_unknown"


@dataclass
class ARPPacket:
    """Class to represent an ARP packet with relevant fields extracted"""
    source_mac: str
    source_ip: str
    dest_mac: str
    dest_ip: str
    packet_type: PacketType
    timestamp: float
    op_code: int
    raw_packet: Any = None  # Will store the raw scapy packet
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "source_mac": self.source_mac,
            "source_ip": self.source_ip,
            "dest_mac": self.dest_mac,
            "dest_ip": self.dest_ip,
            "packet_type": self.packet_type.value,
            "timestamp": self.timestamp,
            "op_code": self.op_code,
            "datetime": datetime.fromtimestamp(self.timestamp).isoformat()
        }


class PacketAnalyzerConfig:
    """Configuration for the packet analyzer"""
    
    def __init__(self, 
                interface: Optional[str] = None,
                packet_buffer_size: int = 1000,
                mac_vendor_file: str = "data/mac_vendors.json",
                subnet_file: str = "data/known_subnets.json",
                filter_string: str = "arp",
                promisc_mode: bool = True,
                batch_processing: bool = True,
                worker_threads: int = MAX_WORKER_THREADS,
                memory_limit_mb: int = DEFAULT_MEMORY_LIMIT_MB,
                dynamic_batch_size: bool = True):
        """
        Initialize packet analyzer configuration
        
        Args:
            interface: Network interface to capture on (None for auto)
            packet_buffer_size: Maximum number of packets to keep in memory
            mac_vendor_file: Path to MAC vendor database
            subnet_file: Path to known subnets file
            filter_string: BPF filter string for packet capture
            promisc_mode: Whether to enable promiscuous mode
            batch_processing: Whether to process packets in batches
            worker_threads: Number of worker threads for processing
            memory_limit_mb: Memory limit in MB
            dynamic_batch_size: Whether to dynamically adjust batch size based on memory usage
        """
        self.interface = interface
        self.packet_buffer_size = packet_buffer_size
        self.mac_vendor_file = mac_vendor_file
        self.subnet_file = subnet_file
        self.filter_string = filter_string
        self.promisc_mode = promisc_mode
        self.batch_processing = batch_processing
        self.worker_threads = min(worker_threads, MAX_WORKER_THREADS)
        self.memory_limit_mb = memory_limit_mb
        self.dynamic_batch_size = dynamic_batch_size
        
        # Loaded data
        self.mac_vendors: Dict[str, str] = {}
        self.known_subnets: List[str] = []
        
        # Load data if files exist
        self._load_mac_vendors()
        self._load_known_subnets()
        
    def _load_mac_vendors(self) -> None:
        """Load MAC vendor database if file exists"""
        if os.path.exists(self.mac_vendor_file):
            try:
                with open(self.mac_vendor_file, 'r') as f:
                    self.mac_vendors = json.load(f)
                logger.info(f"Loaded {len(self.mac_vendors)} MAC vendors from {self.mac_vendor_file}")
            except Exception as e:
                logger.error(f"Failed to load MAC vendors: {e}")
        else:
            logger.warning(f"MAC vendor file not found: {self.mac_vendor_file}")
            
    def _load_known_subnets(self) -> None:
        """Load known subnets if file exists"""
        if os.path.exists(self.subnet_file):
            try:
                with open(self.subnet_file, 'r') as f:
                    self.known_subnets = json.load(f)
                logger.info(f"Loaded {len(self.known_subnets)} known subnets from {self.subnet_file}")
            except Exception as e:
                logger.error(f"Failed to load known subnets: {e}")
        else:
            logger.warning(f"Known subnets file not found: {self.subnet_file}")
            
    def get_vendor_for_mac(self, mac: str) -> Optional[str]:
        """Get vendor for a MAC address"""
        if not mac:
            return None
            
        # Normalize MAC address format
        mac = mac.replace(':', '').replace('-', '').replace('.', '').upper()
        
        # Try different prefix lengths (common are OUI-24, OUI-28, OUI-36)
        for prefix_len in [6, 7, 9]:
            if len(mac) >= prefix_len:
                prefix = mac[:prefix_len]
                if prefix in self.mac_vendors:
                    return self.mac_vendors[prefix]
        
        return None
        
    def is_ip_in_known_subnet(self, ip: str) -> bool:
        """Check if IP is within a known subnet"""
        try:
            addr = ipaddress.ip_address(ip)
            for subnet_str in self.known_subnets:
                network = ipaddress.ip_network(subnet_str, strict=False)
                if addr in network:
                    return True
        except ValueError:
            return False
            
        return False


class PacketAnalyzer:
    """
    Analyzes and processes ARP packets
    """
    
    def __init__(self, config: Optional[PacketAnalyzerConfig] = None):
        """
        Initialize packet analyzer
        
        Args:
            config: Configuration for packet analyzer
        """
        self.config = config or PacketAnalyzerConfig()
        # Use deque instead of list for better performance with fixed size
        self.packets = deque(maxlen=self.config.packet_buffer_size)
        self.packet_batch = []  # Temporary batch storage
        self.ip_mac_mapping: Dict[str, Set[str]] = {}  # IP -> Set of MACs
        self.mac_ip_mapping: Dict[str, Set[str]] = {}  # MAC -> Set of IPs
        self.packet_counts: Dict[str, int] = {}  # IP or MAC -> count
        self.is_running = False
        self.capture_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.callbacks: List[Callable[[ARPPacket], None]] = []
        self.batch_lock = threading.Lock()
        
        # Dynamic batch size parameters
        self.current_batch_size = BATCH_SIZE
        self.memory_monitor_thread = None
        self.last_memory_check = time.time()
        self.current_memory_usage_mb = 0
        
        # Performance metrics
        self.processing_times = deque(maxlen=100)  # Store last 100 processing times
        self.packets_processed = 0
        self.batch_processed = 0
        self.memory_checks = 0
        self.batch_size_adjustments = 0
        
        # ThreadPoolExecutor for parallel processing
        self.executor = None
        if self.config.batch_processing:
            self.executor = ThreadPoolExecutor(max_workers=self.config.worker_threads)
        
        # Check if scapy is available
        if not SCAPY_AVAILABLE:
            logger.error("Scapy library not available. Packet analysis will not work.")
            
    def start_capture(self) -> bool:
        """
        Start packet capture in a separate thread
        
        Returns:
            bool: True if started successfully
        """
        if not SCAPY_AVAILABLE:
            logger.error("Cannot start capture: Scapy library not available")
            return False
            
        if self.is_running:
            logger.warning("Packet capture already running")
            return True
            
        self.is_running = True
        self.stop_event.clear()
        
        # Start capture thread
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            daemon=True
        )
        self.capture_thread.start()
        
        # Start batch processing thread if enabled
        if self.config.batch_processing:
            self.batch_processing_thread = threading.Thread(
                target=self._batch_processor,
                daemon=True
            )
            self.batch_processing_thread.start()
            
        # Start memory monitoring thread if dynamic batch size is enabled
        if self.config.dynamic_batch_size and PSUTIL_AVAILABLE:
            self.memory_monitor_thread = threading.Thread(
                target=self._monitor_memory_usage,
                daemon=True
            )
            self.memory_monitor_thread.start()
        
        logger.info(f"Started packet capture on interface {self.config.interface or 'default'}")
        return True
        
    def stop_capture(self) -> None:
        """Stop packet capture"""
        if not self.is_running:
            return
            
        logger.info("Stopping packet capture...")
        self.stop_event.set()
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2.0)
            
        if self.config.batch_processing and hasattr(self, 'batch_processing_thread') and self.batch_processing_thread.is_alive():
            self.batch_processing_thread.join(timeout=2.0)
            
        if self.memory_monitor_thread and self.memory_monitor_thread.is_alive():
            self.memory_monitor_thread.join(timeout=2.0)
            
        if self.executor:
            self.executor.shutdown(wait=False)
            
        self.is_running = False
        logger.info("Packet capture stopped")
        
    def register_callback(self, callback: Callable[[ARPPacket], None]) -> None:
        """
        Register a callback function to be called for each packet
        
        Args:
            callback: Function to call with each new packet
        """
        self.callbacks.append(callback)
        
    def _capture_packets(self) -> None:
        """Internal method for packet capture thread"""
        try:
            # Start sniffing
            sniff(
                iface=self.config.interface,
                filter=self.config.filter_string,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: self.stop_event.is_set()
            )
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            self.is_running = False
            
    def _monitor_memory_usage(self) -> None:
        """Monitor memory usage and adjust batch size accordingly"""
        if not PSUTIL_AVAILABLE:
            logger.warning("psutil library not available, memory monitoring disabled")
            return
            
        process = psutil.Process()
        
        while not self.stop_event.is_set() and self.is_running:
            try:
                # Check memory usage periodically
                current_time = time.time()
                if current_time - self.last_memory_check >= MEMORY_CHECK_INTERVAL:
                    self.memory_checks += 1
                    self.last_memory_check = current_time
                    
                    # Get current memory usage in MB
                    memory_info = process.memory_info()
                    self.current_memory_usage_mb = memory_info.rss / (1024 * 1024)
                    
                    # Adjust batch size if needed
                    if self.config.dynamic_batch_size:
                        self._adjust_batch_size()
                        
                    # Force garbage collection if memory usage is high
                    if self.current_memory_usage_mb > self.config.memory_limit_mb * 0.9:
                        gc.collect()
                
                # Sleep to avoid busy waiting
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in memory monitoring: {e}")
    
    def _adjust_batch_size(self) -> None:
        """Dynamically adjust batch size based on memory usage"""
        memory_percent = self.current_memory_usage_mb / self.config.memory_limit_mb
        
        with self.batch_lock:
            old_batch_size = self.current_batch_size
            
            # If memory usage is high, decrease batch size
            if memory_percent > 0.8:
                self.current_batch_size = max(10, int(self.current_batch_size * 0.75))
            # If memory usage is low, increase batch size
            elif memory_percent < 0.5:
                self.current_batch_size = min(200, int(self.current_batch_size * 1.25))
            
            # Log change if batch size changed
            if old_batch_size != self.current_batch_size:
                self.batch_size_adjustments += 1
                logger.info(f"Adjusted batch size from {old_batch_size} to {self.current_batch_size} " 
                           f"(Memory: {self.current_memory_usage_mb:.1f}MB, {memory_percent*100:.1f}%)")
        
    def _batch_processor(self) -> None:
        """Process batches of packets in background thread"""
        while not self.stop_event.is_set():
            current_batch = None
            current_batch_size = self.current_batch_size  # Get current batch size
            
            with self.batch_lock:
                if len(self.packet_batch) >= current_batch_size:
                    current_batch = self.packet_batch[:current_batch_size]
                    self.packet_batch = self.packet_batch[current_batch_size:]
            
            if current_batch:
                self._process_packet_batch(current_batch)
                self.batch_processed += 1
            else:
                # Sleep a short time to avoid busy wait
                time.sleep(0.01)
                
    def _process_packet_batch(self, batch: List[ARPPacket]) -> None:
        """Process a batch of packets in parallel"""
        start_time = time.time()
        
        if self.executor:
            # Process in parallel using thread pool
            list(self.executor.map(self._process_single_packet, batch))
        else:
            # Fallback to sequential processing
            for packet in batch:
                self._process_single_packet(packet)
                
        end_time = time.time()
        processing_time = end_time - start_time
        self.processing_times.append(processing_time)
        self.packets_processed += len(batch)
                
    def _process_single_packet(self, packet: ARPPacket) -> None:
        """Process a single packet"""
        # Add to packet list
        self.packets.append(packet)
        
        # Update mappings
        self._update_mappings(packet)
        
        # Call registered callbacks
        for callback in self.callbacks:
            try:
                callback(packet)
            except Exception as e:
                logger.error(f"Error in packet callback: {e}")
        
    def _process_packet(self, packet: Any) -> None:
        """
        Process a captured packet
        
        Args:
            packet: Raw scapy packet
        """
        try:
            # Check if it's an ARP packet
            if ARP in packet:
                arp_packet = packet[ARP]
                
                # Extract fields
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst
                src_ip = arp_packet.psrc
                dst_ip = arp_packet.pdst
                op_code = arp_packet.op
                
                # Determine packet type
                packet_type = self._determine_packet_type(packet)
                
                # Create ARPPacket object
                arp_packet_obj = ARPPacket(
                    source_mac=src_mac,
                    source_ip=src_ip,
                    dest_mac=dst_mac,
                    dest_ip=dst_ip,
                    packet_type=packet_type,
                    timestamp=time.time(),
                    op_code=op_code,
                    raw_packet=packet
                )
                
                if self.config.batch_processing:
                    # Add to batch for processing
                    with self.batch_lock:
                        self.packet_batch.append(arp_packet_obj)
                        
                        # If batch is full, process immediately
                        if len(self.packet_batch) >= BATCH_SIZE * 2:  # Allow some overflow
                            batch = self.packet_batch
                            self.packet_batch = []
                            # Process batch in thread pool
                            self.executor.submit(self._process_packet_batch, batch)
                else:
                    # Process immediately
                    self._process_single_packet(arp_packet_obj)
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            
    def _add_packet(self, packet: ARPPacket) -> None:
        """Add packet to buffer, maintaining max size"""
        self.packets.append(packet)
        
        # Maintain buffer size
        while len(self.packets) > self.config.packet_buffer_size:
            self.packets.pop(0)
            
    def _update_mappings(self, packet: ARPPacket) -> None:
        """Update IP-MAC mappings"""
        # Update IP -> MAC mapping
        if packet.source_ip:
            if packet.source_ip not in self.ip_mac_mapping:
                self.ip_mac_mapping[packet.source_ip] = set()
            self.ip_mac_mapping[packet.source_ip].add(packet.source_mac)
            
        # Update MAC -> IP mapping
        if packet.source_mac:
            if packet.source_mac not in self.mac_ip_mapping:
                self.mac_ip_mapping[packet.source_mac] = set()
            self.mac_ip_mapping[packet.source_mac].add(packet.source_ip)
            
        # Update packet counts
        self.packet_counts[packet.source_ip] = self.packet_counts.get(packet.source_ip, 0) + 1
        self.packet_counts[packet.source_mac] = self.packet_counts.get(packet.source_mac, 0) + 1
            
    def _determine_packet_type(self, packet: Any) -> PacketType:
        """
        Determine the type of ARP packet
        
        Args:
            packet: Raw scapy packet
            
        Returns:
            PacketType: The type of ARP packet
        """
        arp = packet[ARP]
        
        # Check op code
        if arp.op == 1:  # who-has (request)
            # Check for ARP probe
            if arp.psrc == "0.0.0.0":
                return PacketType.ARP_PROBE
            return PacketType.ARP_REQUEST
            
        elif arp.op == 2:  # is-at (reply)
            # Check for gratuitous ARP (announcement)
            if arp.pdst == "0.0.0.0" or arp.pdst == arp.psrc:
                return PacketType.ARP_ANNOUNCEMENT
            return PacketType.ARP_REPLY
            
        return PacketType.ARP_UNKNOWN
        
    def get_ip_for_mac(self, mac: str) -> Set[str]:
        """
        Get all IPs for a given MAC address
        
        Args:
            mac: MAC address
            
        Returns:
            Set of IP addresses
        """
        return self.mac_ip_mapping.get(mac, set())
        
    def get_mac_for_ip(self, ip: str) -> Set[str]:
        """
        Get all MACs for a given IP address
        
        Args:
            ip: IP address
            
        Returns:
            Set of MAC addresses
        """
        return self.ip_mac_mapping.get(ip, set())
        
    def get_packets_for_ip(self, ip: str) -> List[ARPPacket]:
        """
        Get all packets for a given IP
        
        Args:
            ip: IP address
            
        Returns:
            List of packets
        """
        return [p for p in self.packets if p.source_ip == ip or p.dest_ip == ip]
        
    def get_packets_for_mac(self, mac: str) -> List[ARPPacket]:
        """
        Get all packets for a given MAC
        
        Args:
            mac: MAC address
            
        Returns:
            List of packets
        """
        return [p for p in self.packets if p.source_mac == mac or p.dest_mac == mac]
        
    def get_stats(self) -> Dict[str, Any]:
        """
        Get analyzer statistics
        
        Returns:
            Statistics dictionary
        """
        stats = {
            "packet_count": len(self.packets),
            "ip_count": len(self.ip_mac_mapping),
            "mac_count": len(self.mac_ip_mapping),
            "is_running": self.is_running,
            "packets_processed": self.packets_processed,
            "batches_processed": self.batch_processed,
            "current_batch_size": self.current_batch_size,
            "memory_usage_mb": self.current_memory_usage_mb,
            "memory_limit_mb": self.config.memory_limit_mb,
            "memory_checks": self.memory_checks,
            "batch_size_adjustments": self.batch_size_adjustments
        }
        
        # Add performance metrics
        if self.processing_times:
            avg_time = sum(self.processing_times) / len(self.processing_times)
            stats["avg_processing_time_ms"] = avg_time * 1000
            stats["packets_per_second"] = 1.0 / avg_time if avg_time > 0 else 0
            
        return stats
        
    def search_packets(self, query: str) -> List[ARPPacket]:
        """
        Search packets using a simple query
        
        Args:
            query: Search string (MAC, IP, or part of them)
            
        Returns:
            List of matching packets
        """
        results = []
        
        for packet in self.packets:
            if (query in packet.source_mac or query in packet.dest_mac or
                query in packet.source_ip or query in packet.dest_ip):
                results.append(packet)
                
        return results
        
    def clear_packets(self) -> None:
        """Clear packet buffer"""
        self.packets.clear()
        
    def export_packets(self, filename: str) -> bool:
        """
        Export captured packets to a JSON file
        
        Args:
            filename: Output filename
            
        Returns:
            True if successful
        """
        try:
            data = [p.to_dict() for p in self.packets]
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
                
            logger.info(f"Exported {len(data)} packets to {filename}")
            return True
        except Exception as e:
            logger.error(f"Error exporting packets: {e}")
            return False 