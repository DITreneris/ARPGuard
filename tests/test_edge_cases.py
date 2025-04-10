import unittest
import sys
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt

from app.components.network_monitor import NetworkMonitor
from app.components.arp_protection import ARPProtection

class TestEdgeCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        # Create mock components
        with patch('app.utils.network.get_interfaces', return_value=["eth0", "wlan0"]):
            self.network_monitor = NetworkMonitor()
            self.arp_protection = ARPProtection()
        
        # Set up mock signals
        self.network_monitor.arp_attack_detected = Mock()
        self.arp_protection.attack_handled = Mock()
        
    def tearDown(self):
        self.network_monitor.stop_monitoring()
        self.network_monitor.close()
        self.network_monitor.deleteLater()
        self.arp_protection.close()
        self.arp_protection.deleteLater()
        
    def test_malformed_arp_packets(self):
        """Test handling of malformed ARP packets"""
        # Test packets with invalid MAC addresses
        invalid_mac_packets = [
            {
                "timestamp": datetime.now(),
                "src_mac": "invalid_mac",
                "dst_mac": "AA:BB:CC:DD:EE:FF",
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.1",
                "protocol": "ARP",
                "length": 64,
                "info": "Who has 192.168.1.1? Tell 192.168.1.10"
            },
            {
                "timestamp": datetime.now(),
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "invalid_mac",
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.1",
                "protocol": "ARP",
                "length": 64,
                "info": "192.168.1.1 is at 00:11:22:33:44:55"
            },
            # Add more edge cases
            {
                "timestamp": datetime.now(),
                "src_mac": "00:11:22:33:44:55:66",  # Too long MAC
                "dst_mac": "AA:BB:CC:DD:EE:FF",
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.1",
                "protocol": "ARP",
                "length": 64,
                "info": "Invalid MAC length"
            },
            {
                "timestamp": datetime.now(),
                "src_mac": "00:11:22:33:44",  # Too short MAC
                "dst_mac": "AA:BB:CC:DD:EE:FF",
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.1",
                "protocol": "ARP",
                "length": 64,
                "info": "Invalid MAC length"
            }
        ]
        
        for packet in invalid_mac_packets:
            self.network_monitor.process_packet(packet)
            self.assertFalse(self.network_monitor.arp_attack_detected.called)
            self.assertTrue(self.network_monitor.invalid_packets_detected > 0)
        
        # Test packets with invalid IP addresses
        invalid_ip_packets = [
            {
                "timestamp": datetime.now(),
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "AA:BB:CC:DD:EE:FF",
                "src_ip": "invalid_ip",
                "dst_ip": "192.168.1.1",
                "protocol": "ARP",
                "length": 64,
                "info": "Who has 192.168.1.1? Tell invalid_ip"
            },
            {
                "timestamp": datetime.now(),
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "AA:BB:CC:DD:EE:FF",
                "src_ip": "192.168.1.10",
                "dst_ip": "invalid_ip",
                "protocol": "ARP",
                "length": 64,
                "info": "Who has invalid_ip? Tell 192.168.1.10"
            },
            # Add more edge cases
            {
                "timestamp": datetime.now(),
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "AA:BB:CC:DD:EE:FF",
                "src_ip": "256.256.256.256",  # Invalid IP range
                "dst_ip": "192.168.1.1",
                "protocol": "ARP",
                "length": 64,
                "info": "Invalid IP range"
            },
            {
                "timestamp": datetime.now(),
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "AA:BB:CC:DD:EE:FF",
                "src_ip": "192.168.1.10",
                "dst_ip": "0.0.0.0",  # Invalid destination IP
                "protocol": "ARP",
                "length": 64,
                "info": "Invalid destination IP"
            }
        ]
        
        for packet in invalid_ip_packets:
            self.network_monitor.process_packet(packet)
            self.assertFalse(self.network_monitor.arp_attack_detected.called)
            self.assertTrue(self.network_monitor.invalid_packets_detected > 0)
        
        # Test packets with unusual lengths
        unusual_length_packets = [
            {
                "timestamp": datetime.now(),
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "AA:BB:CC:DD:EE:FF",
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.1",
                "protocol": "ARP",
                "length": 0,  # Zero length
                "info": ""
            },
            {
                "timestamp": datetime.now(),
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "AA:BB:CC:DD:EE:FF",
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.1",
                "protocol": "ARP",
                "length": 1000,  # Unusually large
                "info": "A" * 1000  # Very long info
            },
            # Add more edge cases
            {
                "timestamp": datetime.now(),
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "AA:BB:CC:DD:EE:FF",
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.1",
                "protocol": "ARP",
                "length": -1,  # Negative length
                "info": "Negative length"
            },
            {
                "timestamp": datetime.now(),
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "AA:BB:CC:DD:EE:FF",
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.1",
                "protocol": "ARP",
                "length": 65536,  # Exceeds maximum
                "info": "Exceeds maximum length"
            }
        ]
        
        for packet in unusual_length_packets:
            self.network_monitor.process_packet(packet)
            self.assertFalse(self.network_monitor.arp_attack_detected.called)
            self.assertTrue(self.network_monitor.invalid_packets_detected > 0)
    
    def test_high_packet_rate(self):
        """Test handling of high packet rates"""
        # Mock time.sleep to speed up test
        with patch('time.sleep', return_value=None):
            # Process packets with different rates
            rates = [100, 1000, 10000]  # Packets per second
            for rate in rates:
                start_time = datetime.now()
                packets_processed = 0
                
                # Process packets at specified rate
                for i in range(rate):
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
                    packets_processed += 1
                
                # Verify performance metrics
                processing_time = (datetime.now() - start_time).total_seconds()
                actual_rate = packets_processed / processing_time
                
                # Check if system can handle the rate
                self.assertLess(processing_time, 2.0)  # Should process within 2 seconds
                self.assertGreater(actual_rate, rate * 0.8)  # Should maintain at least 80% of target rate
                
                # Verify buffer management
                self.assertLess(len(self.network_monitor.packet_buffer), rate * 0.1)  # Buffer should be limited
                self.assertEqual(self.network_monitor.packets_processed, packets_processed)
                
                # Reset counters for next rate test
                self.network_monitor.reset_counters()
    
    def test_network_interface_changes(self):
        """Test handling of network interface changes"""
        # Test interface state transitions
        interface_states = [
            (["eth0", "wlan0"], 2),  # Initial state
            (["eth0"], 1),  # Remove wlan0
            (["eth0", "wlan0", "eth1"], 3),  # Add interfaces
            ([], 0),  # All interfaces removed
            (["eth0", "wlan0"], 2),  # Interfaces restored
            (["eth0", "wlan0", "eth1", "eth2"], 4),  # Add more interfaces
            (["eth0"], 1)  # Remove multiple interfaces
        ]
        
        for interfaces, expected_count in interface_states:
            with patch('app.utils.network.get_interfaces', return_value=interfaces):
                self.network_monitor.refresh_interfaces()
                self.assertEqual(self.network_monitor.interface_selector.count(), expected_count)
                
                # Verify interface list is updated
                current_interfaces = [self.network_monitor.interface_selector.itemText(i) 
                                    for i in range(self.network_monitor.interface_selector.count())]
                self.assertEqual(set(current_interfaces), set(interfaces))
                
                # Verify monitoring state
                if expected_count > 0:
                    self.assertTrue(self.network_monitor.is_monitoring_active)
                else:
                    self.assertFalse(self.network_monitor.is_monitoring_active)
    
    def test_concurrent_attacks(self):
        """Test handling of concurrent ARP attacks"""
        # Test different attack patterns
        attack_patterns = [
            {
                "name": "Sequential Attacks",
                "attacks": [
                    {
                        "timestamp": datetime.now(),
                        "attacker_mac": f"00:11:22:33:44:{i:02}",
                        "attacker_ip": f"192.168.1.{100+i}",
                        "target_ip": "192.168.1.1",
                        "gateway_ip": "192.168.1.1",
                        "interface": "eth0",
                        "attack_type": "ARP Spoofing"
                    }
                    for i in range(10)
                ]
            },
            {
                "name": "Mixed Attack Types",
                "attacks": [
                    {
                        "timestamp": datetime.now(),
                        "attacker_mac": f"00:11:22:33:44:{i:02}",
                        "attacker_ip": f"192.168.1.{100+i}",
                        "target_ip": "192.168.1.1",
                        "gateway_ip": "192.168.1.1",
                        "interface": "eth0",
                        "attack_type": attack_type
                    }
                    for i, attack_type in enumerate(["ARP Spoofing", "ARP Flood", "MAC Spoofing"] * 3)
                ]
            },
            {
                "name": "Same Attacker Multiple Targets",
                "attacks": [
                    {
                        "timestamp": datetime.now(),
                        "attacker_mac": "00:11:22:33:44:55",
                        "attacker_ip": "192.168.1.100",
                        "target_ip": f"192.168.1.{i}",
                        "gateway_ip": "192.168.1.1",
                        "interface": "eth0",
                        "attack_type": "ARP Spoofing"
                    }
                    for i in range(10)
                ]
            }
        ]
        
        for pattern in attack_patterns:
            # Process all attacks in the pattern
            for attack in pattern["attacks"]:
                self.network_monitor.arp_attack_detected.emit(attack)
                self.arp_protection.handle_attack_detection(attack)
            
            # Verify attack handling
            self.assertEqual(self.arp_protection.handle_attack_detection.call_count, 
                           len(pattern["attacks"]))
            self.assertEqual(len(self.arp_protection.attack_log), len(pattern["attacks"]))
            
            # Verify attack details
            for i, attack in enumerate(pattern["attacks"]):
                logged_attack = self.arp_protection.attack_log[i]
                self.assertEqual(logged_attack["attacker_mac"], attack["attacker_mac"])
                self.assertEqual(logged_attack["attacker_ip"], attack["attacker_ip"])
                self.assertEqual(logged_attack["target_ip"], attack["target_ip"])
                self.assertEqual(logged_attack["attack_type"], attack["attack_type"])
            
            # Reset for next pattern
            self.arp_protection.handle_attack_detection.reset_mock()
            self.arp_protection.attack_log.clear()
    
    def test_resource_limits(self):
        """Test handling of resource limits"""
        # Test memory usage with different packet sizes
        packet_sizes = [64, 128, 256, 512, 1024]  # Bytes
        for size in packet_sizes:
            with patch('psutil.Process.memory_info', return_value=MagicMock(rss=1000000)):  # 1MB
                i = 0
                while True:
                    packet = {
                        "timestamp": datetime.now(),
                        "src_mac": f"00:11:22:33:44:{i:02}",
                        "dst_mac": "AA:BB:CC:DD:EE:FF",
                        "src_ip": f"192.168.1.{i}",
                        "dst_ip": "192.168.1.1",
                        "protocol": "ARP",
                        "length": size,
                        "info": "A" * (size - 64)  # Fill remaining space
                    }
                    try:
                        self.network_monitor.process_packet(packet)
                        i += 1
                    except MemoryError:
                        break
                
                # Verify memory limit was enforced
                self.assertLess(i * size, 1000000)  # Total memory used should be less than limit
                self.assertTrue(self.network_monitor.memory_usage_warning_issued)
        
        # Test CPU usage with different loads
        cpu_loads = [50, 75, 90, 95]  # Percentage
        for load in cpu_loads:
            with patch('psutil.cpu_percent', return_value=load):
                packet = {
                    "timestamp": datetime.now(),
                    "src_mac": "00:11:22:33:44:55",
                    "dst_mac": "AA:BB:CC:DD:EE:FF",
                    "src_ip": "192.168.1.10",
                    "dst_ip": "192.168.1.1",
                    "protocol": "ARP",
                    "length": 64,
                    "info": "Test packet"
                }
                
                # Verify throttling behavior
                self.network_monitor.process_packet(packet)
                if load >= 90:
                    self.assertTrue(self.network_monitor.is_throttled)
                    self.assertFalse(self.network_monitor.arp_attack_detected.called)
                else:
                    self.assertFalse(self.network_monitor.is_throttled)
    
    def test_error_recovery(self):
        """Test error recovery mechanisms"""
        # Test network error recovery
        network_errors = [
            Exception("Network interface not found"),
            Exception("Network is down"),
            Exception("Connection refused"),
            Exception("Timeout"),
            Exception("Host unreachable")
        ]
        
        for error in network_errors:
            with patch('app.utils.network.get_interfaces', side_effect=error):
                self.network_monitor.refresh_interfaces()
                self.assertEqual(self.network_monitor.interface_selector.count(), 0)
                self.assertTrue(self.network_monitor.error_recovery_attempted)
        
        # Test file system error recovery
        file_errors = [
            IOError("No space left on device"),
            IOError("Permission denied"),
            IOError("File not found"),
            IOError("Device or resource busy"),
            IOError("Input/output error")
        ]
        
        for error in file_errors:
            with patch('builtins.open', side_effect=error):
                self.network_monitor.save_packets_to_file("test.pcap")
                self.assertFalse(os.path.exists("test.pcap"))
                self.assertTrue(self.network_monitor.error_recovery_attempted)
        
        # Test data validation error recovery
        data_errors = [
            ValueError("Invalid JSON"),
            ValueError("Invalid data format"),
            ValueError("Missing required field"),
            ValueError("Invalid value type"),
            ValueError("Data validation failed")
        ]
        
        for error in data_errors:
            with patch('json.loads', side_effect=error):
                self.network_monitor.load_configuration()
                self.assertIsNotNone(self.network_monitor.configuration)
                self.assertTrue(self.network_monitor.error_recovery_attempted)
    
    def test_security_measures(self):
        """Test security measures and protections"""
        # Test file permissions with different modes
        permission_modes = [
            (0o644, True),  # Owner read/write, others read
            (0o600, True),  # Owner read/write only
            (0o666, False),  # Everyone read/write
            (0o777, False),  # Everyone full access
            (0o444, True)   # Everyone read only
        ]
        
        for mode, expected_valid in permission_modes:
            with patch('os.path.exists', return_value=True):
                with patch('os.stat', return_value=MagicMock(st_mode=mode)):
                    self.assertEqual(self.network_monitor.verify_config_permissions(), expected_valid)
                    self.assertEqual(self.network_monitor.verify_log_permissions(), expected_valid)
        
        # Test input validation with various patterns
        input_patterns = [
            ("ip", "192.168.1.1", True),
            ("ip", "256.256.256.256", False),
            ("ip", "invalid_ip", False),
            ("mac", "00:11:22:33:44:55", True),
            ("mac", "invalid_mac", False),
            ("mac", "00:11:22:33:44:55:66", False),
            ("mac", "00:11:22:33:44", False)
        ]
        
        for input_type, value, expected_valid in input_patterns:
            if expected_valid:
                self.assertTrue(self.network_monitor.validate_input(value, input_type))
            else:
                with self.assertRaises(ValueError):
                    self.network_monitor.validate_input(value, input_type)
        
        # Test secure communication with different scenarios
        ssl_scenarios = [
            ("https://example.com", True),
            ("http://example.com", False),
            ("https://invalid-cert.com", False),
            ("https://expired-cert.com", False),
            ("https://self-signed.com", False)
        ]
        
        for url, expected_valid in ssl_scenarios:
            with patch('app.utils.security.verify_ssl_certificate', return_value=expected_valid):
                self.assertEqual(self.network_monitor.verify_ssl_certificate(url), expected_valid)
    
    def test_network_partitioning(self):
        """Test handling of network partitioning scenarios"""
        # Test network interface going down
        with patch('app.utils.network.is_interface_up', return_value=False):
            self.network_monitor.check_interface_status()
            self.assertFalse(self.network_monitor.is_monitoring_active)
        
        # Test network interface coming back up
        with patch('app.utils.network.is_interface_up', return_value=True):
            self.network_monitor.check_interface_status()
            self.assertTrue(self.network_monitor.is_monitoring_active)
        
        # Test partial network connectivity
        with patch('app.utils.network.check_connectivity', return_value=False):
            self.network_monitor.verify_network_connectivity()
            self.assertFalse(self.network_monitor.has_network_connectivity)
    
    def test_clock_drift(self):
        """Test handling of system clock drift and time synchronization issues"""
        # Test packet with future timestamp
        future_packet = {
            "timestamp": datetime.now().replace(year=datetime.now().year + 1),
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "AA:BB:CC:DD:EE:FF",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "protocol": "ARP",
            "length": 64,
            "info": "Future packet"
        }
        self.network_monitor.process_packet(future_packet)
        self.assertFalse(self.network_monitor.arp_attack_detected.called)
        
        # Test packet with very old timestamp
        old_packet = {
            "timestamp": datetime.now().replace(year=datetime.now().year - 1),
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "AA:BB:CC:DD:EE:FF",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "protocol": "ARP",
            "length": 64,
            "info": "Old packet"
        }
        self.network_monitor.process_packet(old_packet)
        self.assertFalse(self.network_monitor.arp_attack_detected.called)
    
    def test_duplicate_packets(self):
        """Test handling of duplicate ARP packets"""
        # Create identical packets with different timestamps
        base_packet = {
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "AA:BB:CC:DD:EE:FF",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "protocol": "ARP",
            "length": 64,
            "info": "Duplicate packet"
        }
        
        # Process 10 identical packets
        for i in range(10):
            packet = base_packet.copy()
            packet["timestamp"] = datetime.now()
            self.network_monitor.process_packet(packet)
        
        # Verify duplicate detection
        self.assertEqual(self.network_monitor.duplicate_packets_detected, 9)
        self.assertFalse(self.network_monitor.arp_attack_detected.called)
    
    def test_rapid_configuration_changes(self):
        """Test handling of rapid configuration changes"""
        # Create test configurations
        configs = [
            {"protection_level": "low", "monitoring_interval": 1},
            {"protection_level": "medium", "monitoring_interval": 2},
            {"protection_level": "high", "monitoring_interval": 3}
        ]
        
        # Apply configurations rapidly
        for config in configs:
            self.network_monitor.apply_configuration(config)
            self.arp_protection.apply_configuration(config)
        
        # Verify final configuration
        self.assertEqual(self.network_monitor.configuration["protection_level"], "high")
        self.assertEqual(self.network_monitor.configuration["monitoring_interval"], 3)
    
    def test_system_resources_exhaustion(self):
        """Test handling of system resource exhaustion"""
        # Test file system full
        with patch('builtins.open', side_effect=IOError("No space left on device")):
            self.network_monitor.save_packets_to_file("test.pcap")
            self.assertFalse(os.path.exists("test.pcap"))
        
        # Test out of memory
        with patch('psutil.Process.memory_info', return_value=MagicMock(rss=1000000000)):  # 1GB
            with self.assertRaises(MemoryError):
                self.network_monitor.process_large_packet_buffer()
        
        # Test CPU overload
        with patch('psutil.cpu_percent', return_value=95):
            self.network_monitor.throttle_processing()
            self.assertTrue(self.network_monitor.is_throttled)
    
    def test_network_protocol_variations(self):
        """Test handling of different network protocol variations"""
        # Test different ARP operation types
        arp_operations = [
            {"operation": 1, "name": "ARP Request"},
            {"operation": 2, "name": "ARP Reply"},
            {"operation": 3, "name": "RARP Request"},
            {"operation": 4, "name": "RARP Reply"}
        ]
        
        for op in arp_operations:
            packet = {
                "timestamp": datetime.now(),
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "AA:BB:CC:DD:EE:FF",
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.1",
                "protocol": "ARP",
                "operation": op["operation"],
                "length": 64,
                "info": f"{op['name']} test"
            }
            self.network_monitor.process_packet(packet)
        
        # Test different Ethernet types
        ether_types = [
            {"type": 0x0800, "name": "IPv4"},
            {"type": 0x0806, "name": "ARP"},
            {"type": 0x86DD, "name": "IPv6"}
        ]
        
        for eth_type in ether_types:
            packet = {
                "timestamp": datetime.now(),
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "AA:BB:CC:DD:EE:FF",
                "ether_type": eth_type["type"],
                "length": 64,
                "info": f"{eth_type['name']} test"
            }
            self.network_monitor.process_packet(packet)
    
    def test_attack_pattern_variations(self):
        """Test handling of different ARP attack patterns"""
        # Test different attack types
        attack_patterns = [
            {
                "type": "ARP Cache Poisoning",
                "packets": [
                    {"src_mac": "00:11:22:33:44:55", "src_ip": "192.168.1.100", "dst_ip": "192.168.1.1"},
                    {"src_mac": "00:11:22:33:44:55", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.100"}
                ]
            },
            {
                "type": "ARP Flood",
                "packets": [
                    {"src_mac": f"00:11:22:33:44:{i:02}", "src_ip": f"192.168.1.{i}", "dst_ip": "192.168.1.1"}
                    for i in range(100)
                ]
            },
            {
                "type": "MAC Spoofing",
                "packets": [
                    {"src_mac": "00:11:22:33:44:55", "src_ip": "192.168.1.10", "dst_ip": "192.168.1.1"},
                    {"src_mac": "00:11:22:33:44:55", "src_ip": "192.168.1.20", "dst_ip": "192.168.1.1"}
                ]
            }
        ]
        
        for pattern in attack_patterns:
            for packet_data in pattern["packets"]:
                packet = {
                    "timestamp": datetime.now(),
                    "src_mac": packet_data["src_mac"],
                    "dst_mac": "AA:BB:CC:DD:EE:FF",
                    "src_ip": packet_data["src_ip"],
                    "dst_ip": packet_data["dst_ip"],
                    "protocol": "ARP",
                    "length": 64,
                    "info": f"{pattern['type']} test"
                }
                self.network_monitor.process_packet(packet)
            
            # Verify attack detection
            self.assertTrue(self.network_monitor.arp_attack_detected.called)
            self.network_monitor.arp_attack_detected.reset_mock()

if __name__ == '__main__':
    unittest.main() 