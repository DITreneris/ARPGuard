import time
import psutil
import pytest
from scapy.all import *
from arpguard.core import PacketCaptureEngine, AnalysisEngine, StorageManager
from arpguard.config import ConfigManager

class TestPerformance:
    @pytest.fixture
    def setup_engines(self):
        """Setup test environment with all required engines"""
        config = ConfigManager()
        pce = PacketCaptureEngine(config)
        ae = AnalysisEngine(config)
        sm = StorageManager(config)
        return pce, ae, sm

    def test_packet_capture_throughput(self, setup_engines):
        """Test packet capture engine throughput"""
        pce, _, _ = setup_engines
        packet_count = 100000
        start_time = time.time()
        
        # Generate test packets
        packets = [Ether()/ARP(op=1, pdst="192.168.1.1") for _ in range(packet_count)]
        
        # Process packets
        for packet in packets:
            pce.process_packet(packet)
            
        end_time = time.time()
        duration = end_time - start_time
        throughput = packet_count / duration
        
        print(f"Packet Capture Throughput: {throughput:.2f} packets/second")
        assert throughput > 50000  # Minimum required throughput

    def test_analysis_engine_latency(self, setup_engines):
        """Test analysis engine processing latency"""
        _, ae, _ = setup_engines
        test_packets = 1000
        latencies = []
        
        for _ in range(test_packets):
            packet = Ether()/ARP(op=1, pdst="192.168.1.1")
            start_time = time.time()
            ae.analyze_packet(packet)
            end_time = time.time()
            latencies.append((end_time - start_time) * 1000)  # Convert to milliseconds
            
        avg_latency = sum(latencies) / len(latencies)
        print(f"Average Analysis Latency: {avg_latency:.2f} ms")
        assert avg_latency < 1.0  # Maximum allowed latency in milliseconds

    def test_storage_write_performance(self, setup_engines):
        """Test storage manager write performance"""
        _, _, sm = setup_engines
        events = 10000
        start_time = time.time()
        
        for i in range(events):
            event = {
                "timestamp": time.time(),
                "type": "ARP_REQUEST",
                "source_ip": f"192.168.1.{i % 254 + 1}",
                "target_ip": "192.168.1.1"
            }
            sm.store_event(event)
            
        end_time = time.time()
        duration = end_time - start_time
        write_speed = events / duration
        
        print(f"Storage Write Speed: {write_speed:.2f} events/second")
        assert write_speed > 1000  # Minimum required write speed

    def test_memory_usage(self, setup_engines):
        """Test memory usage during high load"""
        pce, ae, sm = setup_engines
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        
        # Generate and process high volume of packets
        packets = [Ether()/ARP(op=1, pdst="192.168.1.1") for _ in range(100000)]
        for packet in packets:
            pce.process_packet(packet)
            ae.analyze_packet(packet)
            sm.store_event({
                "timestamp": time.time(),
                "type": "ARP_REQUEST",
                "source_ip": "192.168.1.2",
                "target_ip": "192.168.1.1"
            })
            
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        print(f"Memory Usage Increase: {memory_increase:.2f} MB")
        assert memory_increase < 100  # Maximum allowed memory increase in MB

    def test_cpu_utilization(self, setup_engines):
        """Test CPU utilization during high load (R-002)"""
        pce, ae, sm = setup_engines
        
        # Get initial CPU usage
        process = psutil.Process()
        initial_cpu_times = process.cpu_times()
        initial_system_times = psutil.cpu_times()
        
        # Generate test workload - 50,000 packets should be sufficient
        packets = [Ether()/ARP(op=1, pdst="192.168.1.1") for _ in range(50000)]
        
        # Start monitoring
        start_time = time.time()
        cpu_samples = []
        
        # Set up monitoring thread
        def monitor_cpu():
            while time.time() - start_time < 30:  # Monitor for 30 seconds
                cpu_samples.append(process.cpu_percent(interval=0.5))
                time.sleep(0.1)  # Small sleep to avoid excessive sampling
        
        import threading
        monitor_thread = threading.Thread(target=monitor_cpu)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Process packets
        for packet in packets:
            pce.process_packet(packet)
            ae.analyze_packet(packet)
            sm.store_event({
                "timestamp": time.time(),
                "type": "ARP_REQUEST",
                "source_ip": "192.168.1.2",
                "target_ip": "192.168.1.1"
            })
        
        # Make sure monitoring completes
        monitor_thread.join()
        
        # Calculate CPU usage
        if cpu_samples:
            avg_cpu = sum(cpu_samples) / len(cpu_samples)
            max_cpu = max(cpu_samples)
            
            # Calculate per-core usage
            num_cores = psutil.cpu_count(logical=True)
            per_core_avg = avg_cpu / num_cores
            
            print(f"Average CPU Usage: {avg_cpu:.2f}% (Total), {per_core_avg:.2f}% (Per Core)")
            print(f"Peak CPU Usage: {max_cpu:.2f}%")
            
            # Our target is less than 30% per core CPU utilization
            assert per_core_avg < 30, f"CPU utilization too high: {per_core_avg:.2f}% > 30%"
            assert max_cpu / num_cores < 50, f"Peak CPU utilization too high: {max_cpu/num_cores:.2f}% > 50%"
        else:
            pytest.fail("Failed to collect CPU usage samples")

    def test_network_overhead(self, setup_engines):
        """Test network overhead during monitoring (R-003)"""
        pce, ae, _ = setup_engines
        config = ConfigManager()
        
        # Enable network statistics collection
        import socket
        import select
        import struct
        
        # Set up network capture for baseline measurement
        def measure_traffic(duration, with_arpguard=False):
            # Create raw socket to capture all traffic
            try:
                # Create a raw socket
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                
                start_time = time.time()
                total_bytes = 0
                packet_count = 0
                
                # Run ARPGuard monitoring if requested
                monitor_thread = None
                if with_arpguard:
                    def run_monitoring():
                        # Configure ARPGuard to monitor the network
                        pce.start_monitoring(config.get_interface())
                        while time.time() - start_time < duration:
                            time.sleep(0.1)
                        pce.stop_monitoring()
                    
                    monitor_thread = threading.Thread(target=run_monitoring)
                    monitor_thread.daemon = True
                    monitor_thread.start()
                
                # Measure traffic for specified duration
                while time.time() - start_time < duration:
                    # Set a timeout to avoid blocking
                    ready = select.select([s], [], [], 0.1)
                    if ready[0]:
                        packet = s.recvfrom(65535)
                        total_bytes += len(packet[0])
                        packet_count += 1
                
                if with_arpguard and monitor_thread:
                    monitor_thread.join()
                
                s.close()
                return total_bytes, packet_count
                
            except socket.error as e:
                pytest.skip(f"Skipping test - unable to create raw socket: {e}")
                return 0, 0
            
        # Measure baseline traffic (10 seconds)
        print("Measuring baseline network traffic...")
        baseline_bytes, baseline_packets = measure_traffic(10, with_arpguard=False)
        
        # Allow network to settle
        time.sleep(5)
        
        # Measure traffic with ARPGuard monitoring (10 seconds)
        print("Measuring network traffic with ARPGuard...")
        arpguard_bytes, arpguard_packets = measure_traffic(10, with_arpguard=True)
        
        # Calculate overhead
        if baseline_bytes > 0:
            overhead_bytes = arpguard_bytes - baseline_bytes
            overhead_percentage = (overhead_bytes / baseline_bytes) * 100
            
            print(f"Baseline Traffic: {baseline_bytes/1024:.2f} KB ({baseline_packets} packets)")
            print(f"ARPGuard Traffic: {arpguard_bytes/1024:.2f} KB ({arpguard_packets} packets)")
            print(f"Overhead: {overhead_bytes/1024:.2f} KB ({overhead_percentage:.2f}%)")
            
            # Target is less than 5% overhead
            assert overhead_percentage < 5, f"Network overhead too high: {overhead_percentage:.2f}% > 5%"
        else:
            pytest.skip("Baseline traffic measurement failed - cannot calculate overhead")

    def test_concurrent_processing(self, setup_engines):
        """Test system performance under concurrent load"""
        pce, ae, sm = setup_engines
        threads = 4
        packets_per_thread = 25000
        start_time = time.time()
        
        def process_packets(thread_id):
            for i in range(packets_per_thread):
                packet = Ether()/ARP(op=1, pdst=f"192.168.1.{thread_id + 1}")
                pce.process_packet(packet)
                ae.analyze_packet(packet)
                sm.store_event({
                    "timestamp": time.time(),
                    "type": "ARP_REQUEST",
                    "source_ip": f"192.168.1.{thread_id + 1}",
                    "target_ip": "192.168.1.1"
                })
        
        # Create and start threads
        import threading
        thread_list = []
        for i in range(threads):
            t = threading.Thread(target=process_packets, args=(i,))
            thread_list.append(t)
            t.start()
            
        # Wait for all threads to complete
        for t in thread_list:
            t.join()
            
        end_time = time.time()
        duration = end_time - start_time
        total_packets = threads * packets_per_thread
        throughput = total_packets / duration
        
        print(f"Concurrent Processing Throughput: {throughput:.2f} packets/second")
        assert throughput > 100000  # Minimum required concurrent throughput

    def test_detection_accuracy(self, setup_engines):
        """Test ARP spoofing detection accuracy"""
        _, ae, _ = setup_engines
        total_tests = 1000
        true_positives = 0
        false_positives = 0
        
        # Generate legitimate and spoofed ARP packets
        for i in range(total_tests):
            # Legitimate packet
            legit_packet = Ether()/ARP(op=1, pdst="192.168.1.1", psrc="192.168.1.2")
            if not ae.analyze_packet(legit_packet).is_spoofing:
                true_positives += 1
                
            # Spoofed packet
            spoofed_packet = Ether()/ARP(op=1, pdst="192.168.1.1", psrc="192.168.1.3", hwsrc="00:11:22:33:44:55")
            if ae.analyze_packet(spoofed_packet).is_spoofing:
                true_positives += 1
                
        accuracy = (true_positives / (total_tests * 2)) * 100
        print(f"Detection Accuracy: {accuracy:.2f}%")
        assert accuracy >= 99.8  # Minimum required accuracy percentage

if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 