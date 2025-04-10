#!/usr/bin/env python3
"""
ARP Guard - Network protection against ARP spoofing attacks
"""

import os
import sys
import time
import json
import argparse
import logging
import threading
import signal
import queue
from typing import Dict, Any, List, Optional

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
    sys.exit(1)

from core.module_factory import ModuleFactory
from core.detection_module import DetectionModule
from core.lite_detection_module import LiteDetectionModule
from core.remediation_module import RemediationModule

# Default configuration
DEFAULT_CONFIG = {
    "interface": None,  # Auto-detect
    "detection_interval": 5,
    "storage_path": os.path.join(os.path.expanduser("~"), ".arpguard"),
    "max_packet_cache": 1000,
    "auto_protect": False,
    "history_size": 10,
    "worker_threads": 2,
    "enable_sampling": True,
    "sampling_rate": 0.5,
    "batch_size": 50,
    "prioritize_packets": True,
    "remediation_enabled": False,
    "protection_methods": ["notify"],
    "use_lite_version": False,  # Default to full version
    "lite_mode_memory_threshold": 500  # Switch to lite mode if less than 500MB RAM
}


class ARPGuard:
    """
    Main application class for ARP Guard
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize ARP Guard
        
        Args:
            config: Configuration dictionary (optional)
        """
        # Load configuration
        self.config = DEFAULT_CONFIG.copy()
        if config:
            self.config.update(config)
            
        # Create storage directory if it doesn't exist
        os.makedirs(self.config["storage_path"], exist_ok=True)
        
        # Runtime state
        self.running = False
        self.stop_event = threading.Event()
        self.packet_queue = queue.Queue(maxsize=10000)
        
        # Determine if we should use lite version
        self.use_lite_version = self._determine_use_lite_version()
        
        # Create modules
        self.remediation = ModuleFactory.create_remediation_module(self.config)
        self.detection = ModuleFactory.create_detection_module(
            self.config, 
            self.remediation,
            use_lite_version=self.use_lite_version
        )
        
        # Capture state
        self.capture_thread = None
        self.processor_thread = None
        self.interface = self.config["interface"] or self._get_default_interface()
        
        logger.info(f"ARP Guard initialized on interface {self.interface}")
        logger.info(f"Using {'lite' if self.use_lite_version else 'full'} detection module")
    
    def _determine_use_lite_version(self) -> bool:
        """
        Determine if we should use the lite version based on config and system resources
        
        Returns:
            True if we should use lite version
        """
        # If explicitly set in config, use that
        if "use_lite_version" in self.config:
            return self.config["use_lite_version"]
            
        # Check available memory
        try:
            import psutil
            memory = psutil.virtual_memory()
            available_mb = memory.available / (1024 * 1024)
            
            # If less than threshold, use lite version
            if available_mb < self.config["lite_mode_memory_threshold"]:
                logger.info(f"Available memory ({available_mb:.1f}MB) below threshold, using lite mode")
                return True
        except ImportError:
            logger.warning("psutil not available, cannot check memory")
            
        return False
    
    def start(self) -> None:
        """Start ARP Guard monitoring"""
        if self.running:
            logger.warning("ARP Guard already running")
            return
            
        self.running = True
        self.stop_event.clear()
        
        # Start detection module
        self.detection.start()
        
        # Start packet capture thread
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            name="capture-thread", 
            daemon=True
        )
        self.capture_thread.start()
        
        # Start packet processor thread
        self.processor_thread = threading.Thread(
            target=self._process_packets,
            name="processor-thread", 
            daemon=True
        )
        self.processor_thread.start()
        
        logger.info("ARP Guard started")
        
    def stop(self) -> None:
        """Stop ARP Guard monitoring"""
        if not self.running:
            logger.warning("ARP Guard not running")
            return
            
        logger.info("Stopping ARP Guard...")
        self.running = False
        self.stop_event.set()
        
        # Wait for threads to finish
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2.0)
            
        if self.processor_thread and self.processor_thread.is_alive():
            self.processor_thread.join(timeout=2.0)
            
        # Stop detection module
        self.detection.stop()
        
        logger.info("ARP Guard stopped")
        
    def _capture_packets(self) -> None:
        """Capture packets using scapy"""
        logger.info(f"Starting packet capture on interface {self.interface}")
        
        try:
            # Start packet capture with filter for ARP packets
            scapy.sniff(
                iface=self.interface,
                filter="arp",
                store=False,
                prn=self._packet_callback,
                stop_filter=lambda _: self.stop_event.is_set()
            )
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            
        logger.info("Packet capture stopped")
        
    def _packet_callback(self, packet: scapy.Packet) -> None:
        """Callback for packet capture"""
        try:
            # Queue packet for processing
            if self.running and not self.stop_event.is_set():
                self.packet_queue.put(packet, block=False)
        except queue.Full:
            logger.warning("Packet queue is full, dropping packet")
        except Exception as e:
            logger.error(f"Error in packet callback: {e}")
            
    def _process_packets(self) -> None:
        """Process captured packets"""
        logger.info("Starting packet processor")
        
        while not self.stop_event.is_set():
            try:
                # Get packet from queue with 0.1s timeout
                packet = self.packet_queue.get(timeout=0.1)
                
                # Process packet
                self.detection.process_packet(packet)
                
                # Mark task as done
                self.packet_queue.task_done()
                
            except queue.Empty:
                # No packets, sleep briefly
                time.sleep(0.01)
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
                
        logger.info("Packet processor stopped")
        
    def _get_default_interface(self) -> str:
        """Get default network interface"""
        try:
            # Try to auto-detect the interface
            return scapy.conf.iface
        except:
            # Fallback to common interface names
            if os.name == "nt":  # Windows
                return "Ethernet"
            else:  # Linux/Mac
                return "eth0"
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        return {
            "detection": self.detection.get_stats(),
            "queue_size": self.packet_queue.qsize(),
            "running": self.running,
            "interface": self.interface,
            "mode": "lite" if self.use_lite_version else "full"
        }
    
    def get_arp_table(self) -> Dict[str, Dict[str, Any]]:
        """Get current ARP table"""
        return self.detection.get_arp_table()
    
    def get_suspicious_sources(self) -> Dict[str, Dict[str, Any]]:
        """Get suspicious sources"""
        return self.detection.get_suspicious_sources()


def parse_args() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="ARP Guard - Network protection against ARP spoofing attacks")
    
    parser.add_argument("-i", "--interface", help="Network interface to monitor")
    parser.add_argument("-c", "--config", help="Path to configuration file")
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("--lite", action="store_true", help="Use lite version of detection module")
    parser.add_argument("--auto-protect", action="store_true", help="Enable automatic protection")
    parser.add_argument("--daemon", action="store_true", help="Run as daemon in background")
    
    return parser.parse_args()


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from file
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary
    """
    config = DEFAULT_CONFIG.copy()
    
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                file_config = json.load(f)
                config.update(file_config)
            logger.info(f"Loaded configuration from {config_path}")
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            
    return config


def setup_signal_handlers(arp_guard: ARPGuard) -> None:
    """
    Setup signal handlers for graceful shutdown
    
    Args:
        arp_guard: ARPGuard instance
    """
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down")
        arp_guard.stop()
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def main() -> None:
    """Main entry point"""
    args = parse_args()
    
    # Load configuration
    config = load_config(args.config)
    
    # Override with command line arguments
    if args.interface:
        config["interface"] = args.interface
        
    if args.auto_protect:
        config["auto_protect"] = True
        config["remediation_enabled"] = True
        
    if args.lite:
        config["use_lite_version"] = True
    
    # Create and start ARP Guard
    arp_guard = ARPGuard(config)
    
    # Setup signal handlers
    setup_signal_handlers(arp_guard)
    
    # Start monitoring
    arp_guard.start()
    
    # Run as daemon if requested
    if args.daemon:
        # Detach from terminal
        if os.name != "nt":  # Not on Windows
            if os.fork() > 0:
                sys.exit(0)
                
        # Keep running until stopped
        try:
            while arp_guard.running:
                time.sleep(1)
        except KeyboardInterrupt:
            arp_guard.stop()
    else:
        # Interactive mode
        try:
            print("ARP Guard running. Press Ctrl+C to stop.")
            
            while arp_guard.running:
                stats = arp_guard.get_stats()
                suspicious = arp_guard.get_suspicious_sources()
                
                # Print simple status
                print(f"\rMode: {stats['mode']}, Packets: {stats['detection']['packets_processed']}, "
                      f"Suspicious: {len(suspicious)}, Alerts: {stats['detection']['attack_alerts']}",
                      end="", flush=True)
                
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\nStopping ARP Guard...")
            arp_guard.stop()
            
            # Print final summary
            stats = arp_guard.get_stats()
            suspicious = arp_guard.get_suspicious_sources()
            
            print("\nFinal statistics:")
            print(f"- Mode: {stats['mode']}")
            print(f"- Total packets processed: {stats['detection']['packets_processed']}")
            print(f"- Suspicious sources: {len(suspicious)}")
            print(f"- Alerts: {stats['detection']['attack_alerts']}")
            
            # Write to output file if specified
            if args.output:
                try:
                    with open(args.output, "w") as f:
                        json.dump({
                            "stats": stats,
                            "suspicious_sources": suspicious,
                            "arp_table": arp_guard.get_arp_table()
                        }, f, indent=2)
                    print(f"Results written to {args.output}")
                except Exception as e:
                    logger.error(f"Error writing results: {e}")


if __name__ == "__main__":
    main() 