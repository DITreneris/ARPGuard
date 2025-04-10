#!/usr/bin/env python3
"""
Lite Detection Module for ARP Guard
A lightweight version of the detection module with reduced resource usage
"""

import os
import time
import json
import logging
import threading
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from collections import deque, Counter
import queue

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s'
)
logger = logging.getLogger(__name__)

try:
    import scapy.all as scapy
    from scapy.layers.l2 import ARP, Ether
except ImportError:
    logger.error("scapy library not found. Install with: pip install scapy")
    scapy = None

from .detection_module import DetectionModuleConfig, TTLDict

# Constants
PRIORITY_HIGH = 0
PRIORITY_LOW = 1
PRIORITY_LEVELS = 2  # Simplified to just high and low priority


class LiteDetectionModule:
    """
    Lightweight ARP spoofing detection module.
    
    Optimized for lower resource usage with focus on essential security features.
    """
    
    def __init__(self, config: DetectionModuleConfig):
        """
        Initialize the lite detection module.
        
        Args:
            config: Configuration for the detection module
        """
        self.config = config
        
        # Core state
        self.started_at = time.time()
        self.running = False
        
        # Create storage directory if it doesn't exist
        os.makedirs(self.config.storage_path, exist_ok=True)
        
        # Network state - optimized data structures
        self.packet_cache = deque(maxlen=100)  # Smaller cache size
        self.arp_table = {}  # Simple dict instead of TTLDict to reduce overhead
        self.mac_vendors = {}
        self.suspicious_sources = {}
        self.gateway_info = {}
        
        # Network statistics (minimal set)
        self.stats = {
            "packets_processed": 0,
            "arp_packets_processed": 0,
            "suspicious_packets": 0,
            "attack_alerts": 0,
            "uptime": 0,
            "last_attack_time": 0
        }
        
        # Processing state (simplified)
        self.worker_thread = None
        self.work_queue = queue.Queue(maxsize=200)  # Smaller queue
        self.stop_event = threading.Event()
        
        # Load essential data
        self._load_gateway_info()
        logger.info("Lite detection module initialized")
    
    def start(self) -> None:
        """Start the detection module with a single worker thread"""
        if self.running:
            logger.warning("Lite detection module already running")
            return
            
        self.running = True
        self.started_at = time.time()
        self.stop_event.clear()
        
        # Start single worker thread
        self.worker_thread = threading.Thread(
            target=self._worker_thread,
            name="lite-detection-worker",
            daemon=True
        )
        self.worker_thread.start()
        
        logger.info("Lite detection module started")
    
    def stop(self) -> None:
        """Stop the detection module"""
        if not self.running:
            logger.warning("Lite detection module not running")
            return
        
        logger.info("Stopping lite detection module...")
        self.running = False
        self.stop_event.set()
        
        # Wait for worker thread to finish
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=1.0)
                
        # Clear queue
        while not self.work_queue.empty():
            try:
                self.work_queue.get(block=False)
                self.work_queue.task_done()
            except queue.Empty:
                break
                
        self.worker_thread = None
        logger.info("Lite detection module stopped")
        
    def process_packet(self, packet: scapy.Packet) -> None:
        """
        Process a single packet
        
        Args:
            packet: Scapy packet to process
        """
        # Quick reject check - skip non-ARP packets immediately
        if not packet.haslayer(scapy.ARP):
            return
            
        # Update stats
        self.stats["packets_processed"] += 1
        
        # Quick check for common safe patterns
        if self._is_safe_packet(packet):
            return
            
        # Queue packet for processing
        if self.running:
            try:
                self.work_queue.put_nowait((packet, time.time()))
            except queue.Full:
                # Just drop the packet if queue is full
                pass
    
    def _is_safe_packet(self, packet: scapy.Packet) -> bool:
        """
        Quick check if a packet is clearly safe
        
        Args:
            packet: Packet to check
            
        Returns:
            True if packet is definitely safe
        """
        arp = packet.getlayer(scapy.ARP)
        
        # Skip packets with invalid/empty addresses
        if (not arp.psrc or 
            arp.psrc == "0.0.0.0" or 
            not arp.hwsrc or 
            arp.hwsrc == "00:00:00:00:00:00"):
            return True
            
        # Skip if source is not in suspicious list and we've seen it before with same MAC
        if (arp.psrc in self.arp_table and 
            arp.psrc not in self.suspicious_sources and
            self.arp_table[arp.psrc].get("mac") == arp.hwsrc):
            # Update last seen time
            self.arp_table[arp.psrc]["last_seen"] = time.time()
            self.arp_table[arp.psrc]["count"] += 1
            return True
            
        return False
    
    def _worker_thread(self) -> None:
        """Single worker thread for processing packets"""
        logger.debug("Worker thread started")
        
        while not self.stop_event.is_set():
            try:
                # Get packet from queue with 0.1s timeout
                work_item = self.work_queue.get(timeout=0.1)
                packet, timestamp = work_item
                
                # Process the packet
                self._analyze_packet(packet)
                
                # Mark task as done
                self.work_queue.task_done()
                
            except queue.Empty:
                # No packets, sleep briefly
                time.sleep(0.01)
            except Exception as e:
                logger.error(f"Error in worker thread: {e}")
            
        logger.debug("Worker thread stopped")
        
    def _analyze_packet(self, packet: scapy.Packet) -> None:
        """
        Analyze a packet for ARP spoofing detection
        
        Args:
            packet: Scapy packet to analyze
        """
        # Verify it's an ARP packet
        if not packet.haslayer(scapy.ARP):
            return
            
        # Increment ARP packet counter
        self.stats["arp_packets_processed"] += 1
        
        # Extract ARP fields
        arp = packet.getlayer(scapy.ARP)
        src_ip = arp.psrc
        src_mac = arp.hwsrc
        dst_ip = arp.pdst
        dst_mac = arp.hwdst
        op_code = arp.op
        
        # Skip packets with empty or broadcast addresses
        if not src_ip or not src_mac or src_ip == "0.0.0.0" or src_mac == "00:00:00:00:00:00":
            return
            
        # Check if this is a gateway
        is_gateway = (src_ip == self.gateway_info.get("ip")) or (src_mac == self.gateway_info.get("mac"))
        
        # Update ARP table
        if src_ip not in self.arp_table:
            self.arp_table[src_ip] = {
                "mac": src_mac,
                "first_seen": time.time(),
                "last_seen": time.time(),
                "count": 1,
                "is_gateway": is_gateway,
                "op_codes": Counter([op_code])
            }
        else:
            # Existing IP in table
            existing_entry = self.arp_table[src_ip]
            existing_entry["last_seen"] = time.time()
            existing_entry["count"] += 1
            
            # Check for MAC change - potential spoofing
            if existing_entry["mac"] != src_mac:
                # Mark as suspicious
                self.stats["suspicious_packets"] += 1
                
                # Check if this is a known suspicious source
                if src_ip in self.suspicious_sources:
                    # Update existing entry
                    entry = self.suspicious_sources[src_ip]
                    entry["last_seen"] = time.time()
                    entry["count"] += 1
                    
                    # Add to MAC history if not already there
                    if src_mac not in entry["mac_history"]:
                        entry["mac_history"].append(src_mac)
                        
                    # Check alert threshold
                    if entry["count"] >= 3 and not entry["alerted"]:
                        entry["alerted"] = True
                        self.stats["attack_alerts"] += 1
                        self.stats["last_attack_time"] = time.time()
                        
                        # Log alert
                        logger.warning(f"ARP SPOOF ALERT: IP {src_ip} using multiple MAC addresses {entry['mac_history']}")
                else:
                    # New suspicious source
                    self.suspicious_sources[src_ip] = {
                        "first_seen": time.time(),
                        "last_seen": time.time(),
                        "count": 1,
                        "mac_history": [existing_entry["mac"], src_mac],
                        "alerted": False
                    }
                    
                    logger.info(f"New suspicious source: {src_ip} changed MAC from {existing_entry['mac']} to {src_mac}")
                
                # Update ARP table with new MAC
                existing_entry["mac"] = src_mac
                existing_entry["changes"] = existing_entry.get("changes", 0) + 1
    
    def _load_gateway_info(self) -> None:
        """Load gateway information from configuration"""
        try:
            gateway_file = os.path.join(self.config.storage_path, "gateway_info.json")
            if os.path.exists(gateway_file):
                with open(gateway_file, "r") as f:
                    self.gateway_info = json.load(f)
                    logger.info(f"Loaded gateway info: {self.gateway_info['ip']} ({self.gateway_info['mac']})")
            else:
                # Default gateway info if file doesn't exist
                self.gateway_info = {
                    "ip": "192.168.1.1",  # Default gateway IP
                    "mac": "00:00:00:00:00:00",  # Default gateway MAC
                    "last_seen": time.time(),
                    "verified": False
                }
                logger.warning(f"Using default gateway info: {self.gateway_info['ip']}")
        except Exception as e:
            logger.error(f"Error loading gateway info: {e}")
            # Fallback to defaults
            self.gateway_info = {"ip": "192.168.1.1", "mac": "00:00:00:00:00:00"}
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get detection module statistics and status
        
        Returns:
            Dictionary with current statistics
        """
        # Update dynamic statistics
        self.stats["uptime"] = time.time() - self.started_at
        
        return self.stats.copy()
    
    def get_suspicious_sources(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all suspicious sources detected
        
        Returns:
            Dictionary of suspicious sources with metadata
        """
        return self.suspicious_sources.copy()
    
    def get_arp_table(self) -> Dict[str, Dict[str, Any]]:
        """
        Get the current ARP table
            
        Returns:
            Dictionary of IP to MAC mappings with metadata
        """
        return self.arp_table.copy()
    
    def reset_stats(self) -> None:
        """Reset all module statistics"""
        current_time = time.time()
        self.stats = {
            "packets_processed": 0,
            "arp_packets_processed": 0,
            "suspicious_packets": 0,
            "attack_alerts": 0,
            "uptime": current_time - self.started_at,
            "last_attack_time": 0
        } 