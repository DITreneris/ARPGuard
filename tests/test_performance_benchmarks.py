import unittest
import time
import sys
import os
from unittest.mock import Mock, patch, MagicMock
import threading
import statistics
from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt, QTimer
import json
import tempfile
import shutil
import random
import gc

# Add the app directory to the Python path
sys.path.append('app')

from components.network_scanner import NetworkScanner
from components.packet_analyzer import PacketAnalyzer
from components.main_window import MainWindow
from components.threat_detector import ThreatDetector

try:
    from src.core.detection_module import DetectionModule, DetectionModuleConfig
    from src.core.lite_detection_module import LiteDetectionModule
except ImportError:
    print("Warning: Failed to import detection modules. Some tests may fail.")

# Try to import optional performance monitoring tools
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import memory_profiler
    MEMORY_PROFILER_AVAILABLE = True
except ImportError:
    MEMORY_PROFILER_AVAILABLE = False

class TestNetworkScannerPerformance(unittest.TestCase):
    """Performance tests for the NetworkScanner component"""
    
    @classmethod
    def setUpClass(cls):
        """Initialize common resources for all tests"""
        cls.app = QApplication(sys.argv) if not QApplication.instance() else QApplication.instance()
        
    def setUp(self):
        """Set up a fresh NetworkScanner instance for each test"""
        self.scanner = NetworkScanner()
        
    def test_scan_speed_small_network(self):
        """Benchmark network scanning speed for a small network (1-10 hosts)"""
        # Define test parameters
        test_range = "192.168.1.1-10"  # Small range of 10 hosts
        iterations = 3
        scan_times = []
        
        # Run multiple iterations to get average performance
        for i in range(iterations):
            start_time = time.time()
            self.scanner.scan_range(test_range)
            end_time = time.time()
            scan_times.append(end_time - start_time)
            
        # Calculate performance metrics
        avg_time = statistics.mean(scan_times)
        max_time = max(scan_times)
        min_time = min(scan_times)
        
        # Log the results (instead of asserting specific values)
        print(f"\nSmall Network Scan Performance:")
        print(f"  Average scan time: {avg_time:.2f} seconds")
        print(f"  Min/Max scan time: {min_time:.2f}/{max_time:.2f} seconds")
        print(f"  Hosts per second: {10/avg_time:.2f}")
        
        # Ensure scan completes in a reasonable time (adjust threshold based on expected performance)
        self.assertLess(avg_time, 5.0, "Small network scan took too long")
    
    def test_scan_speed_medium_network(self):
        """Benchmark network scanning speed for a medium network (1-50 hosts)"""
        # Use a mock to avoid actual network scanning of 50 hosts
        with patch.object(self.scanner, '_scan_ip', return_value={'ip': 'mock', 'mac': 'mock', 'hostname': 'mock'}):
            # Define test parameters
            test_range = "192.168.1.1-50"  # Medium range of 50 hosts
            iterations = 3
            scan_times = []
            
            # Run multiple iterations to get average performance
            for i in range(iterations):
                start_time = time.time()
                self.scanner.scan_range(test_range)
                end_time = time.time()
                scan_times.append(end_time - start_time)
                
            # Calculate performance metrics
            avg_time = statistics.mean(scan_times)
            max_time = max(scan_times)
            min_time = min(scan_times)
            
            # Log the results
            print(f"\nMedium Network Scan Performance:")
            print(f"  Average scan time: {avg_time:.2f} seconds")
            print(f"  Min/Max scan time: {min_time:.2f}/{max_time:.2f} seconds")
            print(f"  Hosts per second: {50/avg_time:.2f}")
            
            # Ensure scan completes in a reasonable time
            self.assertLess(avg_time, 10.0, "Medium network scan took too long")
    
    def test_scan_memory_usage(self):
        """Test memory usage during network scanning"""
        # This is a simplified test that checks if scan results are properly managed
        
        # Use a mock to generate a large number of results without actual scanning
        num_devices = 1000
        mock_devices = []
        
        with patch.object(self.scanner, 'scan_range', return_value=None), \
             patch.object(self.scanner, 'get_devices') as mock_get_devices:
            
            # Generate mock devices
            for i in range(num_devices):
                mock_devices.append({
                    "ip": f"192.168.1.{i % 255}",
                    "mac": f"00:11:22:33:44:{i % 255:02x}",
                    "hostname": f"device-{i}",
                    "vendor": "Test Vendor"
                })
            
            # Set up the mock to return the large device list
            mock_get_devices.return_value = mock_devices
            
            # Measure memory before
            # Note: This is a simplified approach. For a real test, you'd use
            # memory_profiler or a similar tool
            import psutil
            process = psutil.Process(os.getpid())
            memory_before = process.memory_info().rss / (1024 * 1024)  # MB
            
            # Trigger operations that would use the large result set
            devices = self.scanner.get_devices()
            self.assertEqual(len(devices), num_devices)
            
            # Filter and process the results multiple times
            for i in range(10):
                filtered = [d for d in devices if int(d["ip"].split(".")[-1]) % 2 == 0]
                sorted_devices = sorted(devices, key=lambda d: d["ip"])
            
            # Measure memory after
            memory_after = process.memory_info().rss / (1024 * 1024)  # MB
            memory_diff = memory_after - memory_before
            
            # Log memory usage
            print(f"\nMemory Usage for Processing {num_devices} devices:")
            print(f"  Before: {memory_before:.2f} MB")
            print(f"  After: {memory_after:.2f} MB")
            print(f"  Difference: {memory_diff:.2f} MB")
            
            # Ensure memory usage is reasonable
            # This threshold would need to be adjusted based on the actual application
            self.assertLess(memory_diff, 100.0, "Memory usage increased too much")
    
    def test_concurrent_scan_performance(self):
        """Test performance when running concurrent scans"""
        # Initialize test parameters
        num_threads = 4
        test_ranges = [
            "192.168.1.1-25",
            "192.168.1.26-50",
            "192.168.1.51-75",
            "192.168.1.76-100"
        ]
        
        # Use a mock to avoid actual network scanning
        with patch.object(NetworkScanner, 'scan_range', return_value=None):
            # Create a scanner for each thread
            scanners = [NetworkScanner() for _ in range(num_threads)]
            
            # Function for threads to execute
            def run_scan(scanner, ip_range):
                scanner.scan_range(ip_range)
            
            # Create and start threads
            start_time = time.time()
            threads = []
            for i in range(num_threads):
                thread = threading.Thread(
                    target=run_scan,
                    args=(scanners[i], test_ranges[i])
                )
                threads.append(thread)
                thread.start()
            
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
            
            end_time = time.time()
            total_time = end_time - start_time
            
            # Log performance
            print(f"\nConcurrent Scan Performance ({num_threads} threads):")
            print(f"  Total time: {total_time:.2f} seconds")
            print(f"  Average time per scan: {total_time/num_threads:.2f} seconds")
            
            # Verify concurrent execution is faster than sequential would be
            # This is a simplified check; in a real test, compare to actual sequential execution
            self.assertLess(total_time, 8.0, "Concurrent scanning performance is too slow")


class TestPacketAnalysisPerformance(unittest.TestCase):
    """Performance tests for the PacketAnalyzer component"""
    
    def setUp(self):
        """Set up a fresh PacketAnalyzer instance for each test"""
        self.analyzer = PacketAnalyzer()
        
    def test_packet_processing_speed(self):
        """Test the speed of processing packets"""
        # Create sample packet data
        # This is a simplified representation of what a real packet would look like
        sample_packets = []
        num_packets = 1000
        
        for i in range(num_packets):
            packet = {
                "timestamp": time.time(),
                "source_ip": f"192.168.1.{i % 255}",
                "dest_ip": f"192.168.1.{(i + 1) % 255}",
                "source_port": 1024 + (i % 1000),
                "dest_port": 80,
                "protocol": "TCP",
                "length": 64 + (i % 1000),
                "data": b"X" * (64 + (i % 1000))
            }
            sample_packets.append(packet)
        
        # Measure processing speed
        with patch.object(self.analyzer, 'capture_packet', return_value=None):
            start_time = time.time()
            
            # Process all packets
            for packet in sample_packets:
                self.analyzer.process_packet(packet)
            
            end_time = time.time()
            processing_time = end_time - start_time
            
            # Calculate and log metrics
            packets_per_second = num_packets / processing_time
            print(f"\nPacket Processing Performance:")
            print(f"  Total packets: {num_packets}")
            print(f"  Processing time: {processing_time:.2f} seconds")
            print(f"  Packets per second: {packets_per_second:.2f}")
            
            # Assert reasonable performance
            self.assertGreater(packets_per_second, 1000, "Packet processing too slow")
    
    def test_protocol_analysis_speed(self):
        """Test speed of protocol-specific analysis"""
        # Sample packets for different protocols
        protocols = ["TCP", "UDP", "HTTP", "DNS", "ARP"]
        packets_per_protocol = 200
        
        # Create sample packets for each protocol
        protocol_packets = {}
        for protocol in protocols:
            protocol_packets[protocol] = []
            for i in range(packets_per_protocol):
                packet = {
                    "timestamp": time.time(),
                    "source_ip": f"192.168.1.{i % 255}",
                    "dest_ip": f"192.168.1.{(i + 1) % 255}",
                    "source_port": 1024 + (i % 1000),
                    "dest_port": 80,
                    "protocol": protocol,
                    "length": 64 + (i % 1000),
                    "data": b"X" * (64 + (i % 1000))
                }
                protocol_packets[protocol].append(packet)
        
        # Measure processing time for each protocol
        with patch.object(self.analyzer, 'capture_packet', return_value=None):
            protocol_times = {}
            
            for protocol in protocols:
                start_time = time.time()
                
                # Process all packets for this protocol
                for packet in protocol_packets[protocol]:
                    self.analyzer.process_packet(packet)
                
                end_time = time.time()
                protocol_times[protocol] = end_time - start_time
            
            # Log results
            print("\nProtocol Analysis Performance:")
            for protocol, proc_time in protocol_times.items():
                packets_per_second = packets_per_protocol / proc_time
                print(f"  {protocol}: {proc_time:.4f} seconds ({packets_per_second:.2f} packets/sec)")
            
            # Compare protocols to ensure none are significantly slower
            avg_time = statistics.mean(protocol_times.values())
            for protocol, proc_time in protocol_times.items():
                # No protocol should take more than twice the average time
                self.assertLess(proc_time, avg_time * 2,
                               f"{protocol} analysis is significantly slower than average")


class TestUIResponsiveness(unittest.TestCase):
    """Performance tests for UI responsiveness"""
    
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv) if not QApplication.instance() else QApplication.instance()
        
    def setUp(self):
        """Set up mocks and prepare the main window for testing"""
        # Create mock objects for the main components to avoid real operations
        self.mock_scanner = Mock(spec=NetworkScanner)
        self.mock_detector = Mock(spec=ThreatDetector)
        
        # Mock device data
        self.mock_devices = []
        for i in range(100):  # Create 100 mock devices
            self.mock_devices.append({
                "ip": f"192.168.1.{i}",
                "mac": f"00:11:22:33:44:{i:02x}",
                "hostname": f"device-{i}",
                "vendor": "Test Vendor"
            })
        
        # Configure scanner mock
        self.mock_scanner.get_devices.return_value = self.mock_devices
        
        # Patch component classes
        self.scanner_patcher = patch('components.main_window.NetworkScanner', 
                                    return_value=self.mock_scanner)
        self.detector_patcher = patch('components.main_window.ThreatDetector', 
                                     return_value=self.mock_detector)
        
        # Start patchers
        self.scanner_patcher.start()
        self.detector_patcher.start()
        
        # Create the main window
        self.window = MainWindow()
        
    def tearDown(self):
        """Clean up after each test"""
        self.window.close()
        self.window.deleteLater()
        
        # Stop patchers
        self.scanner_patcher.stop()
        self.detector_patcher.stop()
        
    def test_ui_update_speed(self):
        """Test speed of updating the UI with large datasets"""
        # Measure time to update device list with 100 devices
        start_time = time.time()
        
        # Update the UI
        self.window.update_device_list()
        
        # Process events to ensure UI updates are applied
        QApplication.processEvents()
        
        end_time = time.time()
        update_time = end_time - start_time
        
        # Log results
        print(f"\nUI Update Performance:")
        print(f"  Time to update device list (100 devices): {update_time:.4f} seconds")
        
        # Assert reasonable performance
        self.assertLess(update_time, 0.5, "UI updates are too slow")
    
    def test_ui_filter_speed(self):
        """Test speed of filtering in the UI"""
        # First update the device list
        self.window.update_device_list()
        
        # Define filters to test
        filters = [
            {"field": "ip", "value": "192.168.1.1"},
            {"field": "vendor", "value": "Test"},
            {"field": "hostname", "value": "device-"}
        ]
        
        # Test each filter
        for filter_info in filters:
            # Set the filter
            start_time = time.time()
            
            # Apply filter - this will depend on the actual implementation
            # For example, if there's a filter_input field:
            if hasattr(self.window, 'filter_input'):
                self.window.filter_input.setText(filter_info["value"])
                QTest.keyPress(self.window.filter_input, Qt.Key_Return)
            
            # Process events to ensure UI updates are applied
            QApplication.processEvents()
            
            end_time = time.time()
            filter_time = end_time - start_time
            
            # Log results
            print(f"  Time to filter by {filter_info['field']} ({filter_info['value']}): {filter_time:.4f} seconds")
            
            # Assert reasonable performance
            self.assertLess(filter_time, 0.2, f"Filtering by {filter_info['field']} is too slow")
    
    def test_ui_responsiveness_during_scan(self):
        """Test UI responsiveness while a scan is in progress"""
        # This test simulates a long-running scan and checks if the UI remains responsive
        
        # Set up a mock scan that takes a few seconds
        scan_duration = 3.0  # seconds
        self.mock_scanner.start_scan = Mock(side_effect=lambda: time.sleep(scan_duration))
        self.mock_scanner.is_scanning = Mock(return_value=True)
        
        # Start the scan in a separate thread to avoid blocking
        scan_thread = threading.Thread(target=self.window.start_scan)
        scan_thread.daemon = True
        scan_thread.start()
        
        # Wait a moment for the scan to start
        time.sleep(0.5)
        
        # Measure UI response time during scan
        start_time = time.time()
        
        # Perform UI operations that should still be responsive
        # For example, try to open a menu or click a button
        if hasattr(self.window, 'menuFile'):
            self.window.menuFile.aboutToShow.emit()
        
        # Click in the UI somewhere
        if hasattr(self.window, 'status_bar'):
            QTest.mouseClick(self.window.status_bar, Qt.LeftButton)
        
        # Process events to ensure UI updates are applied
        QApplication.processEvents()
        
        end_time = time.time()
        response_time = end_time - start_time
        
        # Log results
        print(f"\nUI Responsiveness During Scan:")
        print(f"  Response time while scan in progress: {response_time:.4f} seconds")
        
        # Wait for scan to complete
        scan_thread.join()
        
        # Assert reasonable responsiveness
        self.assertLess(response_time, 0.2, "UI is not responsive enough during scanning")


class TestPerformanceBenchmarks(unittest.TestCase):
    def setUp(self) -> None:
        """Set up test environment before each test"""
        # Create a temporary directory for test storage
        self.test_dir = tempfile.mkdtemp()
        
        # Default config with test storage path
        self.config = DetectionModuleConfig(
            storage_path=self.test_dir,
            default_gateway_ip="192.168.1.1",
            default_gateway_mac="00:11:22:33:44:55"
        )
        
        # Force garbage collection before each test
        gc.collect()
        
    def tearDown(self) -> None:
        """Clean up after each test"""
        # Remove the temporary directory
        shutil.rmtree(self.test_dir)
        
        # Force garbage collection after each test
        gc.collect()
    
    def _measure_execution_time(self, func, iterations=100) -> Tuple[float, float, float]:
        """
        Measure execution time statistics for a function
        
        Args:
            func: Function to measure
            iterations: Number of iterations to run
            
        Returns:
            Tuple of (average_time, min_time, max_time) in milliseconds
        """
        times = []
        
        for _ in range(iterations):
            start_time = time.time()
            func()
            end_time = time.time()
            times.append((end_time - start_time) * 1000)  # Convert to ms
            
        avg_time = statistics.mean(times)
        min_time = min(times)
        max_time = max(times)
        
        return avg_time, min_time, max_time
    
    def _measure_memory_usage(self, func) -> Tuple[float, float]:
        """
        Measure memory usage for a function
        
        Args:
            func: Function to measure
            
        Returns:
            Tuple of (memory_before, memory_after) in MB
        """
        if not PSUTIL_AVAILABLE:
            self.skipTest("psutil not available")
            
        # Force garbage collection
        gc.collect()
        
        # Measure memory before
        process = psutil.Process(os.getpid())
        memory_before = process.memory_info().rss / (1024 * 1024)  # Convert to MB
        
        # Run function
        func()
        
        # Force garbage collection
        gc.collect()
        
        # Measure memory after
        memory_after = process.memory_info().rss / (1024 * 1024)  # Convert to MB
        
        return memory_before, memory_after

    def test_gateway_loading_speed(self) -> None:
        """Benchmark for gateway info loading speed"""
        # Create gateway file with different sizes
        sizes = [10, 100, 1000]
        
        for size in sizes:
            # Create a large gateway info file
            gateway_data = {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "last_seen": time.time(),
                "verified": True,
                # Add extra data to increase file size
                "extra_data": [{"key": f"value_{i}", "data": "x" * 100} for i in range(size)]
            }
            
            gateway_file = os.path.join(self.test_dir, "gateway_info.json")
            with open(gateway_file, 'w') as f:
                json.dump(gateway_data, f)
            
            # Measure load time
            module = DetectionModule(self.config)
            
            # Function to benchmark
            def load_gateway():
                module._gateway_info_loaded = False
                module._load_gateway_info()
            
            avg_time, min_time, max_time = self._measure_execution_time(load_gateway, iterations=50)
            
            print(f"\nGateway file size: {size} entries")
            print(f"  Average load time: {avg_time:.2f} ms")
            print(f"  Min load time: {min_time:.2f} ms")
            print(f"  Max load time: {max_time:.2f} ms")
            
            # Basic assertion to ensure performance doesn't degrade terribly
            # This is a flexible threshold that should work across different systems
            self.assertLess(avg_time, 1000, f"Gateway loading too slow with {size} entries")
    
    def test_gateway_ip_retrieval_performance(self) -> None:
        """Benchmark for gateway IP retrieval performance"""
        # Configure module
        module = DetectionModule(self.config)
        module.gateway_info = {
            "ip": "192.168.1.1",
            "mac": "00:11:22:33:44:55"
        }
        module._gateway_info_loaded = True
        
        # Function to benchmark
        def get_gateway_ips():
            return module._get_gateway_ips()
        
        avg_time, min_time, max_time = self._measure_execution_time(get_gateway_ips, iterations=1000)
        
        print(f"\nGateway IP retrieval performance:")
        print(f"  Average time: {avg_time:.2f} ms")
        print(f"  Min time: {min_time:.2f} ms")
        print(f"  Max time: {max_time:.2f} ms")
        
        # Basic assertion to ensure performance is acceptable
        # This is a critical function that should be very fast
        self.assertLess(avg_time, 10, "Gateway IP retrieval too slow")
    
    def test_full_vs_lite_module_performance(self) -> None:
        """Compare performance between full and lite detection modules"""
        # Create gateway file
        gateway_data = {
            "ip": "192.168.1.1",
            "mac": "00:11:22:33:44:55",
            "last_seen": time.time(),
            "verified": True
        }
        
        gateway_file = os.path.join(self.test_dir, "gateway_info.json")
        with open(gateway_file, 'w') as f:
            json.dump(gateway_data, f)
        
        # Function to benchmark full module initialization
        def init_full_module():
            DetectionModule(self.config)
        
        # Function to benchmark lite module initialization
        def init_lite_module():
            LiteDetectionModule(self.config)
        
        # Measure full module performance
        full_avg, full_min, full_max = self._measure_execution_time(init_full_module, iterations=20)
        
        # Measure lite module performance
        lite_avg, lite_min, lite_max = self._measure_execution_time(init_lite_module, iterations=20)
        
        print(f"\nModule initialization performance comparison:")
        print(f"  Full module - Avg: {full_avg:.2f} ms, Min: {full_min:.2f} ms, Max: {full_max:.2f} ms")
        print(f"  Lite module - Avg: {lite_avg:.2f} ms, Min: {lite_min:.2f} ms, Max: {lite_max:.2f} ms")
        print(f"  Improvement ratio: {full_avg/lite_avg:.2f}x faster")
        
        # Test memory usage for both modules
        if PSUTIL_AVAILABLE:
            full_before, full_after = self._measure_memory_usage(init_full_module)
            lite_before, lite_after = self._measure_memory_usage(init_lite_module)
            
            full_usage = full_after - full_before
            lite_usage = lite_after - lite_before
            
            print(f"\nMemory usage comparison:")
            print(f"  Full module: {full_usage:.2f} MB")
            print(f"  Lite module: {lite_usage:.2f} MB")
            print(f"  Memory savings: {max(0, full_usage - lite_usage):.2f} MB")
            
            # The lite module should use less memory than the full module
            self.assertLess(lite_usage, full_usage, "Lite module should use less memory")
        
        # The lite module should be faster than the full module
        self.assertLess(lite_avg, full_avg, "Lite module should be faster")
    
    def test_gateway_detection_under_load(self) -> None:
        """Test gateway detection performance under simulated load"""
        # Create module with minimal configuration
        module = DetectionModule(self.config)
        module.gateway_info = {
            "ip": "192.168.1.1",
            "mac": "00:11:22:33:44:55"
        }
        module._gateway_info_loaded = True
        
        # Function to simulate load and measure gateway IP retrieval
        def retrieve_under_load():
            # Simulate load by creating a large temporary data structure
            load_data = [random.random() for _ in range(10000)]
            
            # Measure gateway IP retrieval
            start_time = time.time()
            ips = module._get_gateway_ips()
            retrieval_time = (time.time() - start_time) * 1000  # ms
            
            # Force usage of load_data to prevent optimization
            return retrieval_time, sum(load_data) > 0, len(ips)
        
        # Run test multiple times
        times = []
        for _ in range(50):
            retrieval_time, _, _ = retrieve_under_load()
            times.append(retrieval_time)
        
        avg_time = statistics.mean(times)
        max_time = max(times)
        
        print(f"\nGateway detection under load:")
        print(f"  Average retrieval time: {avg_time:.2f} ms")
        print(f"  Maximum retrieval time: {max_time:.2f} ms")
        
        # Even under load, gateway IP retrieval should be fast
        self.assertLess(avg_time, 10, "Gateway IP retrieval too slow under load")
        self.assertLess(max_time, 50, "Gateway IP retrieval max time too high under load")


if __name__ == '__main__':
    unittest.main() 