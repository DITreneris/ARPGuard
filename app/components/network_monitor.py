import sys
import time
from datetime import datetime
from collections import deque
from PyQt5.QtCore import QObject, pyqtSignal
from app.utils.performance import PerformanceMonitor

class NetworkMonitor(QObject):
    arp_attack_detected = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.performance_monitor = PerformanceMonitor()
        self.packet_buffer = deque(maxlen=10000)  # Limit buffer size
        self.object_pool = {}
        self.pool_size = 1000
        self.pool_allocations = 0
        self.pool_releases = 0
        self.packets_processed = 0
        self.invalid_packets_detected = 0
        self.duplicate_packets_detected = 0
        self.is_monitoring_active = False
        self.is_throttled = False
        self.memory_warning_issued = False
        self.error_recovery_attempted = False
        self.last_processing_time = time.time()
        self.processing_interval = 0.001  # 1ms between processing batches
        
    def initialize_object_pool(self, size):
        """Initialize the object pool with a given size"""
        self.pool_size = size
        self.object_pool = {}
        for i in range(size):
            self.object_pool[i] = {
                "timestamp": None,
                "src_mac": None,
                "dst_mac": None,
                "src_ip": None,
                "dst_ip": None,
                "protocol": None,
                "length": None,
                "info": None,
                "in_use": False
            }
    
    def allocate_from_pool(self):
        """Allocate an object from the pool"""
        self.pool_allocations += 1
        for obj_id, obj in self.object_pool.items():
            if not obj["in_use"]:
                obj["in_use"] = True
                return obj_id, obj
        # If pool is full, create a new object
        new_id = len(self.object_pool)
        new_obj = {
            "timestamp": None,
            "src_mac": None,
            "dst_mac": None,
            "src_ip": None,
            "dst_ip": None,
            "protocol": None,
            "length": None,
            "info": None,
            "in_use": True
        }
        self.object_pool[new_id] = new_obj
        return new_id, new_obj
    
    def release_to_pool(self, obj_id):
        """Release an object back to the pool"""
        if obj_id in self.object_pool:
            self.object_pool[obj_id]["in_use"] = False
            self.pool_releases += 1
    
    def clear_object_pool(self):
        """Clear the object pool"""
        self.object_pool.clear()
        self.pool_allocations = 0
        self.pool_releases = 0
    
    def process_packet(self, packet):
        """Process a single packet"""
        start_time = time.time()
        
        # Check if throttling is needed
        current_time = time.time()
        if current_time - self.last_processing_time < self.processing_interval:
            self.is_throttled = True
            return
        
        self.is_throttled = False
        
        # Validate packet
        if not self._validate_packet(packet):
            self.invalid_packets_detected += 1
            return
        
        # Check for duplicates
        if self._is_duplicate_packet(packet):
            self.duplicate_packets_detected += 1
            return
        
        # Process packet
        self.packet_buffer.append(packet)
        self.packets_processed += 1
        
        # Update performance metrics
        processing_time = time.time() - start_time
        self.performance_monitor.record_processing_time(processing_time)
        self.performance_monitor.increment_packet_count()
        self.performance_monitor.record_memory_usage()
        
        # Check for memory warnings
        if self.performance_monitor.metrics["memory_usage"] > 100 * 1024 * 1024:  # 100MB
            self.memory_warning_issued = True
        
        self.last_processing_time = current_time
    
    def process_packet_batch(self, packets):
        """Process a batch of packets"""
        start_time = time.time()
        
        # Process each packet in the batch
        for packet in packets:
            self.process_packet(packet)
        
        # Update batch processing metrics
        batch_time = time.time() - start_time
        self.performance_monitor.record_processing_time(batch_time / len(packets))
    
    def _validate_packet(self, packet):
        """Validate packet format and content"""
        required_fields = ["timestamp", "src_mac", "dst_mac", "src_ip", "dst_ip", "protocol", "length"]
        if not all(field in packet for field in required_fields):
            return False
        
        # Validate MAC addresses
        if not self._is_valid_mac(packet["src_mac"]) or not self._is_valid_mac(packet["dst_mac"]):
            return False
        
        # Validate IP addresses
        if not self._is_valid_ip(packet["src_ip"]) or not self._is_valid_ip(packet["dst_ip"]):
            return False
        
        # Validate length
        if not isinstance(packet["length"], int) or packet["length"] <= 0 or packet["length"] > 65536:
            return False
        
        return True
    
    def _is_valid_mac(self, mac):
        """Validate MAC address format"""
        if not isinstance(mac, str):
            return False
        parts = mac.split(":")
        if len(parts) != 6:
            return False
        for part in parts:
            if not all(c in "0123456789ABCDEFabcdef" for c in part):
                return False
        return True
    
    def _is_valid_ip(self, ip):
        """Validate IP address format"""
        if not isinstance(ip, str):
            return False
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        for part in parts:
            try:
                num = int(part)
                if not 0 <= num <= 255:
                    return False
            except ValueError:
                return False
        return True
    
    def _is_duplicate_packet(self, packet):
        """Check if packet is a duplicate"""
        # Simple duplicate detection based on source MAC and IP
        for buffered_packet in self.packet_buffer:
            if (buffered_packet["src_mac"] == packet["src_mac"] and 
                buffered_packet["src_ip"] == packet["src_ip"] and
                buffered_packet["dst_ip"] == packet["dst_ip"]):
                return True
        return False
    
    def reset_counters(self):
        """Reset all counters and metrics"""
        self.packets_processed = 0
        self.invalid_packets_detected = 0
        self.duplicate_packets_detected = 0
        self.memory_warning_issued = False
        self.error_recovery_attempted = False
        self.performance_monitor.reset_metrics()
    
    def get_performance_report(self):
        """Get detailed performance report"""
        return self.performance_monitor.get_performance_report()
    
    def stop_monitoring(self):
        """Stop packet monitoring"""
        self.is_monitoring_active = False
        self.packet_buffer.clear()
        self.clear_object_pool()
        self.reset_counters() 