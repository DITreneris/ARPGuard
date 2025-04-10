#!/usr/bin/env python3
"""
Benchmark script to compare the performance of the regular detection module
versus the parallel version.

This script generates a large number of mock packets and measures the
processing time for both implementations.
"""

import os
import sys
import time
import random
import logging
import argparse
from typing import List, Dict, Any, Tuple
import threading
import json
import csv
from datetime import datetime

# Add the parent directory to the path so we can import the modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.detection_module import DetectionModule
from src.core.parallel_detection_module import ParallelDetectionModule

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("benchmark_results.log")
    ]
)

logger = logging.getLogger("benchmark")

class MockPacket:
    """Mock packet class for testing."""
    
    def __init__(self, psrc, hwsrc, pdst, hwdst, packet_type="arp"):
        self.psrc = psrc
        self.hwsrc = hwsrc
        self.pdst = pdst
        self.hwdst = hwdst
        self.type = packet_type
        self.time = time.time()

def generate_random_ip():
    """Generate a random IP address."""
    return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_random_mac():
    """Generate a random MAC address."""
    return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])

def generate_mock_packets(count: int, packet_types: List[str] = None) -> List[MockPacket]:
    """
    Generate a list of mock packets for testing.
    
    Args:
        count: Number of packets to generate
        packet_types: List of packet types to use, or None for default
        
    Returns:
        List of MockPacket objects
    """
    if packet_types is None:
        packet_types = ["arp", "icmp", "tcp", "udp"]
    
    packets = []
    for _ in range(count):
        packet_type = random.choice(packet_types)
        source_ip = generate_random_ip()
        source_mac = generate_random_mac()
        target_ip = generate_random_ip()
        target_mac = generate_random_mac()
        
        packet = MockPacket(source_ip, source_mac, target_ip, target_mac, packet_type)
        packets.append(packet)
    
    # Add some suspicious packets to test detection
    gateway_ip = "192.168.1.1"
    gateway_mac = "00:11:22:33:44:55"
    
    # Add spoofed gateway packets
    for _ in range(count // 20):  # 5% of packets are suspicious
        spoof_mac = generate_random_mac()
        packet = MockPacket(gateway_ip, spoof_mac, generate_random_ip(), generate_random_mac(), "arp")
        packets.append(packet)
    
    # Add MITM packets
    for _ in range(count // 25):  # 4% of packets are MITM attempts
        source_ip = generate_random_ip()
        source_mac = generate_random_mac()
        packet = MockPacket(source_ip, source_mac, gateway_ip, gateway_mac, "arp")
        packets.append(packet)
    
    # Shuffle the packets
    random.shuffle(packets)
    
    return packets

def benchmark_detection_module(packets: List[MockPacket], batch_size: int) -> Dict[str, Any]:
    """
    Benchmark the standard DetectionModule.
    
    Args:
        packets: List of packets to process
        batch_size: Number of packets to process in each batch
        
    Returns:
        Dictionary containing benchmark results
    """
    logger.info(f"Benchmarking standard DetectionModule with {len(packets)} packets")
    
    # Initialize the module
    module = DetectionModule(interface=None)
    
    # Add gateway and trusted hosts
    module.trusted_hosts = ["192.168.1.100", "192.168.1.101"]
    module.gateway_ips = ["192.168.1.1"]
    
    # Start the module
    module.start()
    
    # Process packets in batches to avoid memory issues
    start_time = time.time()
    
    batch_times = []
    alert_counts = []
    
    for i in range(0, len(packets), batch_size):
        batch = packets[i:i+batch_size]
        
        batch_start = time.time()
        for packet in batch:
            module._process_packet(packet)
        batch_end = time.time()
        
        batch_time = batch_end - batch_start
        batch_times.append(batch_time)
        
        # Get the current alert count
        with module.stats_lock:
            alert_counts.append(module.stats["alerts"])
        
        logger.info(f"Processed batch {i//batch_size + 1}/{len(packets)//batch_size + 1} in {batch_time:.4f} seconds")
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # Get final statistics
    stats = module.get_stats()
    
    # Stop the module
    module.stop()
    
    # Prepare results
    results = {
        "implementation": "standard",
        "total_packets": len(packets),
        "total_time": total_time,
        "packets_per_second": len(packets) / total_time if total_time > 0 else 0,
        "batch_times": batch_times,
        "average_batch_time": sum(batch_times) / len(batch_times) if batch_times else 0,
        "alert_progression": alert_counts,
        "final_alerts": stats["alerts"],
        "final_stats": stats
    }
    
    logger.info(f"Standard DetectionModule processed {len(packets)} packets in {total_time:.4f} seconds "
                f"({results['packets_per_second']:.2f} packets/sec)")
    
    return results

def benchmark_parallel_detection_module(packets: List[MockPacket], batch_size: int, num_workers: int) -> Dict[str, Any]:
    """
    Benchmark the ParallelDetectionModule.
    
    Args:
        packets: List of packets to process
        batch_size: Number of packets to process in each batch
        num_workers: Number of worker threads to use
        
    Returns:
        Dictionary containing benchmark results
    """
    logger.info(f"Benchmarking ParallelDetectionModule with {len(packets)} packets, {num_workers} workers")
    
    # Initialize the module
    module = ParallelDetectionModule(interface=None, num_workers=num_workers, batch_size=batch_size)
    
    # Add gateway and trusted hosts
    module.trusted_hosts = ["192.168.1.100", "192.168.1.101"]
    module.gateway_ips = ["192.168.1.1"]
    
    # Start the module
    module.start()
    
    # Process packets in batches to avoid memory issues
    start_time = time.time()
    
    batch_times = []
    alert_counts = []
    
    for i in range(0, len(packets), batch_size):
        batch = packets[i:i+batch_size]
        
        batch_start = time.time()
        for packet in batch:
            module._process_packet(packet)
        batch_end = time.time()
        
        batch_time = batch_end - batch_start
        batch_times.append(batch_time)
        
        # Get the current alert count
        with module.stats_lock:
            alert_counts.append(module.stats["alerts"])
        
        logger.info(f"Processed batch {i//batch_size + 1}/{len(packets)//batch_size + 1} in {batch_time:.4f} seconds")
    
    # Wait for all packets to be processed
    module.wait_for_completion(timeout=10.0)
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # Get final statistics
    stats = module.get_stats()
    
    # Stop the module
    module.stop()
    
    # Prepare results
    results = {
        "implementation": f"parallel_{num_workers}",
        "total_packets": len(packets),
        "total_time": total_time,
        "packets_per_second": len(packets) / total_time if total_time > 0 else 0,
        "batch_times": batch_times,
        "average_batch_time": sum(batch_times) / len(batch_times) if batch_times else 0,
        "alert_progression": alert_counts,
        "final_alerts": stats["alerts"],
        "final_stats": stats
    }
    
    logger.info(f"ParallelDetectionModule with {num_workers} workers processed {len(packets)} packets "
                f"in {total_time:.4f} seconds ({results['packets_per_second']:.2f} packets/sec)")
    
    return results

def run_benchmarks(packet_count: int, batch_size: int, worker_counts: List[int]) -> Dict[str, Dict[str, Any]]:
    """
    Run benchmarks for both implementations.
    
    Args:
        packet_count: Number of packets to generate
        batch_size: Number of packets to process in each batch
        worker_counts: List of worker counts to test
        
    Returns:
        Dictionary containing benchmark results for all implementations
    """
    logger.info(f"Generating {packet_count} mock packets for benchmarking")
    packets = generate_mock_packets(packet_count)
    
    results = {}
    
    # Benchmark standard implementation
    standard_results = benchmark_detection_module(packets, batch_size)
    results["standard"] = standard_results
    
    # Benchmark parallel implementation with different worker counts
    for worker_count in worker_counts:
        parallel_results = benchmark_parallel_detection_module(packets, batch_size, worker_count)
        results[f"parallel_{worker_count}"] = parallel_results
    
    return results

def save_results(results: Dict[str, Dict[str, Any]], output_dir: str):
    """
    Save benchmark results to files.
    
    Args:
        results: Dictionary containing benchmark results
        output_dir: Directory to save results to
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # Save full results as JSON
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(output_dir, f"benchmark_results_{timestamp}.json")
    
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"Saved full results to {json_path}")
    
    # Save summary as CSV
    csv_path = os.path.join(output_dir, f"benchmark_summary_{timestamp}.csv")
    
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Implementation", "Total Packets", "Total Time (s)", "Packets/Second", "Final Alerts"])
        
        for impl_name, impl_results in results.items():
            writer.writerow([
                impl_name,
                impl_results["total_packets"],
                f"{impl_results['total_time']:.4f}",
                f"{impl_results['packets_per_second']:.2f}",
                impl_results["final_alerts"]
            ])
    
    logger.info(f"Saved summary to {csv_path}")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Benchmark detection module implementations")
    
    parser.add_argument("--packets", type=int, default=10000,
                        help="Number of packets to generate (default: 10000)")
    parser.add_argument("--batch-size", type=int, default=100,
                        help="Number of packets to process in each batch (default: 100)")
    parser.add_argument("--workers", type=str, default="2,4,8",
                        help="Comma-separated list of worker counts to test (default: 2,4,8)")
    parser.add_argument("--output-dir", type=str, default="benchmark_results",
                        help="Directory to save results to (default: benchmark_results)")
    
    return parser.parse_args()

def main():
    """Main function."""
    args = parse_args()
    
    packet_count = args.packets
    batch_size = args.batch_size
    worker_counts = [int(x) for x in args.workers.split(",")]
    output_dir = args.output_dir
    
    logger.info(f"Starting benchmarks with {packet_count} packets, batch size {batch_size}, "
                f"worker counts {worker_counts}")
    
    results = run_benchmarks(packet_count, batch_size, worker_counts)
    save_results(results, output_dir)
    
    # Print summary
    print("\nBenchmark Summary:")
    print("-----------------")
    print(f"{'Implementation':<20} {'Packets':<10} {'Time (s)':<10} {'Packets/s':<12} {'Alerts':<10}")
    print("-" * 65)
    
    for impl_name, impl_results in results.items():
        print(f"{impl_name:<20} {impl_results['total_packets']:<10} "
              f"{impl_results['total_time']:.4f}   {impl_results['packets_per_second']:.2f}      "
              f"{impl_results['final_alerts']}")

if __name__ == "__main__":
    main() 