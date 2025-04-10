import unittest
import sys
import time
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
import psutil
import numpy as np

from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt

from app.components.network_monitor import NetworkMonitor
from app.components.arp_protection import ARPProtection
from app.utils.performance import PerformanceMonitor

class TestPerformanceOptimization(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        cls.performance_monitor = PerformanceMonitor()
        
    def setUp(self):
        # Create mock components
        with patch('app.utils.network.get_interfaces', return_value=["eth0", "wlan0"]):
            self.network_monitor = NetworkMonitor()
            self.arp_protection = ARPProtection()
        
        # Set up mock signals
        self.network_monitor.arp_attack_detected = Mock()
        self.arp_protection.attack_handled = Mock()
        
        # Initialize performance metrics
        self.performance_monitor.reset_metrics()
        
    def tearDown(self):
        self.network_monitor.stop_monitoring()
        self.network_monitor.close()
        self.network_monitor.deleteLater()
        self.arp_protection.close()
        self.arp_protection.deleteLater()
        
    def test_packet_processing_optimization(self):
        """Test optimized packet processing"""
        # Test batch processing
        batch_sizes = [10, 100, 1000]
        for batch_size in batch_sizes:
            # Generate batch of packets
            packets = [
                {
                    "timestamp": datetime.now(),
                    "src_mac": f"00:11:22:33:44:{i:02}",
                    "dst_mac": "AA:BB:CC:DD:EE:FF",
                    "src_ip": f"192.168.1.{i}",
                    "dst_ip": "192.168.1.1",
                    "protocol": "ARP",
                    "length": 64,
                    "info": f"Packet {i}"
                }
                for i in range(batch_size)
            ]
            
            # Process batch and measure performance
            start_time = time.time()
            self.network_monitor.process_packet_batch(packets)
            processing_time = time.time() - start_time
            
            # Verify performance metrics
            self.assertLess(processing_time, batch_size * 0.001)  # Should process within 1ms per packet
            self.assertEqual(self.network_monitor.packets_processed, batch_size)
            
            # Verify memory usage
            memory_usage = psutil.Process().memory_info().rss
            self.assertLess(memory_usage, batch_size * 1000)  # Should use less than 1KB per packet
            
            # Reset for next batch size
            self.network_monitor.reset_counters()
    
    def test_memory_optimization(self):
        """Test memory usage optimization"""
        # Test object pooling
        pool_sizes = [100, 1000, 10000]
        for pool_size in pool_sizes:
            # Initialize object pool
            self.network_monitor.initialize_object_pool(pool_size)
            
            # Measure initial memory usage
            initial_memory = psutil.Process().memory_info().rss
            
            # Allocate and release objects
            objects = []
            for _ in range(pool_size * 2):  # Test pool overflow
                obj = self.network_monitor.allocate_from_pool()
                objects.append(obj)
            
            # Release half of the objects
            for obj in objects[:pool_size]:
                self.network_monitor.release_to_pool(obj)
            
            # Measure memory usage after operations
            final_memory = psutil.Process().memory_info().rss
            memory_increase = final_memory - initial_memory
            
            # Verify memory efficiency
            self.assertLess(memory_increase, pool_size * 100)  # Should use less than 100 bytes per object
            
            # Verify pool statistics
            self.assertEqual(self.network_monitor.pool_allocations, pool_size * 2)
            self.assertEqual(self.network_monitor.pool_releases, pool_size)
            
            # Clean up
            self.network_monitor.clear_object_pool()
    
    def test_performance_metrics(self):
        """Test performance metrics collection"""
        # Test packet processing metrics
        packet_counts = [100, 1000, 10000]
        for count in packet_counts:
            # Process packets
            for i in range(count):
                packet = {
                    "timestamp": datetime.now(),
                    "src_mac": f"00:11:22:33:44:{i:02}",
                    "dst_mac": "AA:BB:CC:DD:EE:FF",
                    "src_ip": f"192.168.1.{i}",
                    "dst_ip": "192.168.1.1",
                    "protocol": "ARP",
                    "length": 64,
                    "info": f"Packet {i}"
                }
                self.network_monitor.process_packet(packet)
            
            # Get performance metrics
            metrics = self.performance_monitor.get_metrics()
            
            # Verify metrics
            self.assertEqual(metrics["packets_processed"], count)
            self.assertGreater(metrics["processing_rate"], 0)
            self.assertLess(metrics["average_processing_time"], 0.001)  # Should process within 1ms
            
            # Verify memory metrics
            self.assertGreater(metrics["memory_usage"], 0)
            self.assertLess(metrics["memory_usage"], count * 1000)  # Should use less than 1KB per packet
            
            # Reset for next count
            self.network_monitor.reset_counters()
            self.performance_monitor.reset_metrics()
    
    def test_memory_monitoring(self):
        """Test memory usage monitoring"""
        # Test memory monitoring under different loads
        load_levels = [1000, 5000, 10000]
        for load in load_levels:
            # Generate load
            packets = [
                {
                    "timestamp": datetime.now(),
                    "src_mac": f"00:11:22:33:44:{i:02}",
                    "dst_mac": "AA:BB:CC:DD:EE:FF",
                    "src_ip": f"192.168.1.{i}",
                    "dst_ip": "192.168.1.1",
                    "protocol": "ARP",
                    "length": 64,
                    "info": "A" * 1000  # Large info to increase memory usage
                }
                for i in range(load)
            ]
            
            # Process packets and monitor memory
            memory_samples = []
            for packet in packets:
                self.network_monitor.process_packet(packet)
                memory_samples.append(psutil.Process().memory_info().rss)
            
            # Analyze memory patterns
            memory_array = np.array(memory_samples)
            memory_increase = memory_array[-1] - memory_array[0]
            memory_std = np.std(memory_array)
            
            # Verify memory patterns
            self.assertLess(memory_increase, load * 2000)  # Should use less than 2KB per packet
            self.assertLess(memory_std, load * 500)  # Memory usage should be stable
            
            # Verify memory warnings
            if memory_increase > load * 1000:
                self.assertTrue(self.network_monitor.memory_warning_issued)
            
            # Reset for next load level
            self.network_monitor.reset_counters()
            self.performance_monitor.reset_metrics()
    
    def test_processing_throttling(self):
        """Test processing throttling under high load"""
        # Test different load levels
        load_levels = [1000, 5000, 10000]
        for load in load_levels:
            # Generate high load
            packets = [
                {
                    "timestamp": datetime.now(),
                    "src_mac": f"00:11:22:33:44:{i:02}",
                    "dst_mac": "AA:BB:CC:DD:EE:FF",
                    "src_ip": f"192.168.1.{i}",
                    "dst_ip": "192.168.1.1",
                    "protocol": "ARP",
                    "length": 64,
                    "info": f"Packet {i}"
                }
                for i in range(load)
            ]
            
            # Process packets and measure throttling
            start_time = time.time()
            for packet in packets:
                self.network_monitor.process_packet(packet)
            processing_time = time.time() - start_time
            
            # Get performance metrics
            metrics = self.performance_monitor.get_metrics()
            
            # Verify throttling behavior
            if load > 5000:
                self.assertTrue(self.network_monitor.is_throttled)
                self.assertLess(metrics["processing_rate"], load / 2)  # Rate should be reduced
            else:
                self.assertFalse(self.network_monitor.is_throttled)
                self.assertGreater(metrics["processing_rate"], load * 0.8)  # Should maintain high rate
            
            # Reset for next load level
            self.network_monitor.reset_counters()
            self.performance_monitor.reset_metrics()

if __name__ == '__main__':
    unittest.main() 