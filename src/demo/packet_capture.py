from scapy.all import *
from typing import Optional, Callable
import threading
import time
from logger import DemoLogger
from status import StatusReporter

class PacketCapture:
    """Handles packet capture and analysis"""
    
    def __init__(
        self,
        interface: str,
        filter: str = "arp",
        logger: Optional[DemoLogger] = None,
        status_reporter: Optional[StatusReporter] = None
    ):
        self.interface = interface
        self.filter = filter
        self.logger = logger or DemoLogger()
        self.status_reporter = status_reporter or StatusReporter()
        self.capture_thread: Optional[threading.Thread] = None
        self.running = False
        self.packet_handler: Optional[Callable] = None
    
    def start_capture(self, packet_handler: Optional[Callable] = None) -> bool:
        """Start packet capture"""
        try:
            if self.running:
                self.logger.warning("Capture already running")
                return True
                
            self.packet_handler = packet_handler
            self.running = True
            self.capture_thread = threading.Thread(target=self._capture_loop)
            self.capture_thread.start()
            
            self.logger.info(f"Started packet capture on {self.interface}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to start capture: {e}")
            return False
    
    def stop_capture(self) -> bool:
        """Stop packet capture"""
        try:
            if not self.running:
                self.logger.warning("Capture not running")
                return True
                
            self.running = False
            if self.capture_thread:
                self.capture_thread.join(timeout=5)
                
            self.logger.info("Stopped packet capture")
            return True
        except Exception as e:
            self.logger.error(f"Failed to stop capture: {e}")
            return False
    
    def _capture_loop(self) -> None:
        """Main capture loop"""
        try:
            sniff(
                iface=self.interface,
                filter=self.filter,
                prn=self._process_packet,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            self.logger.error(f"Error in capture loop: {e}")
            self.running = False
    
    def _process_packet(self, packet) -> None:
        """Process captured packet"""
        try:
            # Update metrics
            self.status_reporter.increment_packets()
            
            # Log packet details
            if ARP in packet:
                self.logger.log_packet_event(
                    "ARP",
                    packet[ARP].psrc,
                    packet[ARP].pdst
                )
            
            # Call custom packet handler if provided
            if self.packet_handler:
                self.packet_handler(packet)
                
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def save_capture(self, filename: str) -> bool:
        """Save captured packets to file"""
        try:
            wrpcap(filename, self._get_captured_packets())
            self.logger.info(f"Saved capture to {filename}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to save capture: {e}")
            return False
    
    def _get_captured_packets(self) -> list:
        """Get list of captured packets"""
        # TODO: Implement packet storage
        return []
    
    def analyze_packets(self) -> dict:
        """Analyze captured packets"""
        try:
            analysis = {
                "total_packets": self.status_reporter.metrics.packets_processed,
                "arp_packets": 0,
                "suspicious_packets": 0,
                "unique_sources": set(),
                "unique_destinations": set()
            }
            
            # TODO: Implement packet analysis
            return analysis
        except Exception as e:
            self.logger.error(f"Failed to analyze packets: {e}")
            return {} 