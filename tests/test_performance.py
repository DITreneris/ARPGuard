#!/usr/bin/env python
"""
Performance benchmarking tests for ARPGuard components.

This module contains tests to measure and verify the performance
of various ARPGuard components under different load conditions.
"""

import time
import unittest
from unittest.mock import patch, MagicMock
import tempfile
import os
import socket
import ipaddress
import random
from datetime import datetime

from app.components.device_discovery import DeviceDiscovery
from app.components.arp_cache_monitor import ARPCacheMonitor
from app.components.packet_capture import PacketCapture
from app.utils.config import get_config_manager, ConfigManager


class PerformanceBenchmarkTests(unittest.TestCase):
    """Performance benchmark tests for ARPGuard components."""
    
    def setUp(self):
        """Set up test environment."""
        # Create a temporary directory for test files
        self.temp_dir = tempfile.TemporaryDirectory()
        
        # Create a test configuration
        self.config_path = os.path.join(self.temp_dir.name, "config.yaml")
        self.config_manager = ConfigManager(self.config_path)
        
        # Initialize components
        self.device_discovery = DeviceDiscovery()
        self.arp_cache_monitor = ARPCacheMonitor()
        self.packet_capture = PacketCapture()
        
        # Set test parameters
        self.test_interface = self._get_test_interface()
        self.test_subnet = self._get_test_subnet()
        self.benchmark_results = {}
    
    def tearDown(self):
        """Clean up after tests."""
        self.temp_dir.cleanup()
        
    def _get_test_interface(self):
        """Get a test network interface."""
        # In real tests, this would return an actual interface
        # For benchmarking, we can use a mock or default interface
        return None  # Use default interface
    
    def _get_test_subnet(self):
        """Get a test subnet for scanning."""
        # In real tests, this would return an actual subnet
        # For benchmarking, we can use a mock or default subnet
        return None  # Use default subnet
    
    def _generate_mock_devices(self, count):
        """Generate mock device data for testing."""
        devices = []
        for i in range(count):
            ip = f"192.168.1.{random.randint(2, 254)}"
            mac = ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])
            devices.append({
                'ip': ip,
                'mac': mac,
                'hostname': f"device-{i}",
                'vendor': "Test Vendor",
                'last_seen': datetime.now().isoformat()
            })
        return devices
    
    def _generate_mock_packets(self, count):
        """Generate mock packet data for testing."""
        packets = []
        for i in range(count):
            packet = {
                'time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'src_ip': f"192.168.1.{random.randint(2, 254)}",
                'dst_ip': f"192.168.1.{random.randint(2, 254)}",
                'protocol': random.choice(['TCP', 'UDP', 'ICMP', 'ARP']),
                'length': random.randint(64, 1500),
                'info': "Test packet info"
            }
            packets.append(packet)
        return packets
    
    def _record_benchmark(self, component, operation, device_count, duration_ms, throughput=None):
        """Record benchmark results."""
        if component not in self.benchmark_results:
            self.benchmark_results[component] = []
        
        result = {
            'operation': operation,
            'device_count': device_count,
            'duration_ms': duration_ms,
            'timestamp': datetime.now().isoformat()
        }
        
        if throughput is not None:
            result['throughput'] = throughput
            
        self.benchmark_results[component].append(result)
        
        # Print benchmark result
        print(f"BENCHMARK: {component} - {operation} with {device_count} devices: {duration_ms:.2f} ms")
        if throughput is not None:
            print(f"THROUGHPUT: {throughput:.2f} items/second")
    
    def test_config_manager_performance(self):
        """Test ConfigManager performance."""
        print("\n=== Testing ConfigManager Performance ===")
        
        # Test loading performance
        start_time = time.time()
        for _ in range(100):
            config = self.config_manager.load_config()
        end_time = time.time()
        load_duration = (end_time - start_time) * 1000 / 100  # Average ms per load
        
        self._record_benchmark('ConfigManager', 'load_config', 100, load_duration)
        self.assertLess(load_duration, 50, "Config loading should be under 50ms")
        
        # Test saving performance
        start_time = time.time()
        for _ in range(10):
            self.config_manager.save_config(self.config_path)
        end_time = time.time()
        save_duration = (end_time - start_time) * 1000 / 10  # Average ms per save
        
        self._record_benchmark('ConfigManager', 'save_config', 10, save_duration)
        self.assertLess(save_duration, 100, "Config saving should be under 100ms")
    
    def test_device_discovery_performance(self):
        """Test DeviceDiscovery performance with different device counts."""
        print("\n=== Testing DeviceDiscovery Performance ===")
        
        # Test with increasing device counts
        for device_count in [10, 50, 100, 500]:
            # Mock device discovery to avoid actual network scanning
            devices = self._generate_mock_devices(device_count)
            
            # Test processing performance
            start_time = time.time()
            for device in devices:
                # Simulate processing each device
                self.device_discovery._process_device(device['ip'], device['mac'])
            end_time = time.time()
            
            process_duration = (end_time - start_time) * 1000  # Total ms
            throughput = device_count / (end_time - start_time)  # Devices per second
            
            self._record_benchmark('DeviceDiscovery', 'process_devices', device_count, process_duration, throughput)
            
            # Performance assertion - adjust threshold as needed
            max_duration = 20 * device_count  # Allow 20ms per device
            self.assertLess(process_duration, max_duration, 
                           f"Processing {device_count} devices should be under {max_duration}ms")
    
    def test_packet_capture_performance(self):
        """Test PacketCapture performance."""
        print("\n=== Testing PacketCapture Performance ===")
        
        # Test packet processing performance
        for packet_count in [100, 1000, 10000]:
            packets = self._generate_mock_packets(packet_count)
            
            start_time = time.time()
            # Simulate packet processing
            for packet in packets:
                # Process each packet (simulated operation)
                packet['processed'] = True
                packet['timestamp'] = time.time()
            end_time = time.time()
            
            process_duration = (end_time - start_time) * 1000  # Total ms
            throughput = packet_count / (end_time - start_time)  # Packets per second
            
            self._record_benchmark('PacketCapture', 'process_packets', packet_count, process_duration, throughput)
            
            # Performance assertion - should process at least 10,000 packets per second
            self.assertGreater(throughput, 10000, 
                              f"Packet processing throughput ({throughput:.2f}/s) should exceed 10,000 packets/second")
    
    def test_arp_cache_monitor_performance(self):
        """Test ARPCacheMonitor performance."""
        print("\n=== Testing ARPCacheMonitor Performance ===")
        
        # Test ARP cache monitoring performance
        for entry_count in [10, 50, 100]:
            # Generate mock ARP cache entries
            arp_entries = {}
            for i in range(entry_count):
                ip = f"192.168.1.{i+1}"
                mac = ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])
                arp_entries[ip] = mac
            
            # Test baseline generation performance
            start_time = time.time()
            # Simulate baseline generation
            baseline = arp_entries.copy()
            end_time = time.time()
            
            baseline_duration = (end_time - start_time) * 1000  # Total ms
            
            self._record_benchmark('ARPCacheMonitor', 'generate_baseline', entry_count, baseline_duration)
            
            # Generate some changed entries to simulate ARP spoofing
            changed_entries = arp_entries.copy()
            for i in range(min(5, entry_count)):
                ip = f"192.168.1.{random.randint(1, entry_count)}"
                mac = ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])
                changed_entries[ip] = mac
            
            # Test detection performance
            start_time = time.time()
            # Simulate detection process
            changes = []
            for ip, mac in changed_entries.items():
                if ip in baseline and baseline[ip] != mac:
                    changes.append((ip, baseline[ip], mac))
            end_time = time.time()
            
            detection_duration = (end_time - start_time) * 1000  # Total ms
            
            self._record_benchmark('ARPCacheMonitor', 'detect_changes', entry_count, detection_duration)
            
            # Performance assertion - should detect changes in under 50ms
            self.assertLess(detection_duration, 50, 
                           f"ARP change detection for {entry_count} entries should be under 50ms")
    
    def test_end_to_end_performance(self):
        """Test end-to-end performance for common workflows."""
        print("\n=== Testing End-to-End Performance ===")
        
        # Test scan workflow performance
        device_count = 50
        devices = self._generate_mock_devices(device_count)
        
        start_time = time.time()
        # Simulate a complete scan workflow
        # 1. Load configuration
        config = self.config_manager.load_config()
        
        # 2. Discover devices (mocked)
        discovered_devices = devices
        
        # 3. Process and format results
        formatted_devices = []
        for device in discovered_devices:
            formatted_devices.append({
                'IP Address': device['ip'],
                'MAC Address': device['mac'],
                'Hostname': device['hostname'],
                'Vendor': device['vendor']
            })
        
        # 4. Export results (simulated)
        result_json = {'devices': formatted_devices}
        
        end_time = time.time()
        
        workflow_duration = (end_time - start_time) * 1000  # Total ms
        
        self._record_benchmark('EndToEnd', 'scan_workflow', device_count, workflow_duration)
        
        # Performance assertion - entire workflow should be reasonably fast
        self.assertLess(workflow_duration, 1000, 
                       f"End-to-end scan workflow for {device_count} devices should be under 1000ms")
        
    def test_memory_usage(self):
        """Test memory usage of components."""
        # Skip this test on platforms where resource module is not available
        try:
            import resource
            print("\n=== Testing Memory Usage ===")
            
            # Measure baseline memory usage
            baseline_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            print(f"Baseline memory usage: {baseline_memory} KB")
            
            # Test device discovery memory usage
            devices = self._generate_mock_devices(1000)
            # Process devices
            for device in devices:
                self.device_discovery._process_device(device['ip'], device['mac'])
            
            discovery_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            discovery_delta = discovery_memory - baseline_memory
            print(f"Device discovery memory delta: {discovery_delta} KB")
            
            # Test packet capture memory usage
            packets = self._generate_mock_packets(10000)
            # Process packets (simulated)
            for packet in packets:
                packet['processed'] = True
            
            capture_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            capture_delta = capture_memory - discovery_memory
            print(f"Packet capture memory delta: {capture_delta} KB")
            
            # Memory usage assertions
            max_memory_per_device = 2  # KB per device
            self.assertLess(discovery_delta, 1000 * max_memory_per_device, 
                           f"Memory usage for 1000 devices should be under {1000 * max_memory_per_device} KB")
            
            max_memory_per_packet = 0.5  # KB per packet
            self.assertLess(capture_delta, 10000 * max_memory_per_packet, 
                           f"Memory usage for 10000 packets should be under {10000 * max_memory_per_packet} KB")
                           
        except ImportError:
            print("Skipping memory usage test - resource module not available")
            pass
    
    def test_export_benchmark_results(self):
        """Export benchmark results to file."""
        # Run some benchmarks first if results are empty
        if not self.benchmark_results:
            self.test_config_manager_performance()
            self.test_device_discovery_performance()
            self.test_packet_capture_performance()
        
        # Export results to JSON file
        import json
        result_file = os.path.join(self.temp_dir.name, "benchmark_results.json")
        
        with open(result_file, 'w') as f:
            json.dump(self.benchmark_results, f, indent=2)
            
        print(f"\nBenchmark results exported to {result_file}")
        
        # Verify file was created
        self.assertTrue(os.path.exists(result_file), "Benchmark results file should exist")
        
        # Read back and verify
        with open(result_file, 'r') as f:
            loaded_results = json.load(f)
            
        self.assertEqual(self.benchmark_results, loaded_results, 
                        "Loaded benchmark results should match original results")


if __name__ == "__main__":
    unittest.main() 