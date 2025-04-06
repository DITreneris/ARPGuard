import unittest
import json
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
import os
import sys

# Add the parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from components.attack_recognizer import (
    AttackRecognizer, MitMPattern, SYNFloodPattern,
    SMBExploitPattern, SSHBruteForcePattern, WebAttackPattern
)

class TestAttackDetection(unittest.TestCase):
    """Test cases for attack detection functionality."""
    
    def setUp(self):
        """Set up test environment before each test case."""
        self.recognizer = AttackRecognizer()
        self.test_callback = MagicMock()
        
        # Common timestamps for packet generation
        self.base_time = datetime.now()
    
    def tearDown(self):
        """Clean up after each test case."""
        if hasattr(self.recognizer, 'is_running') and self.recognizer.is_running:
            self.recognizer.stop_detection()
    
    def test_mitm_detection(self):
        """Test detection of Man-in-the-Middle attacks."""
        # Create mock packets showing MITM indicators
        mitm_packets = self._generate_mitm_packets()
        
        # Create a standalone MITM detector for direct testing
        mitm_detector = MitMPattern()
        
        # Test the detection
        result = mitm_detector.analyze(mitm_packets)
        
        # Verify the detection result
        self.assertIsNotNone(result, "MITM attack should be detected")
        self.assertEqual(result['type'], 'mitm_attack')
        self.assertGreaterEqual(len(result['redirected_flows']), 1)
        
        # Test with the full recognizer
        with patch.object(self.recognizer, 'get_packets_for_analysis', return_value=mitm_packets):
            self.recognizer.start_detection(callback=self.test_callback)
            time.sleep(0.5)  # Allow time for analysis
            self.recognizer.stop_detection()
            
        # Verify callback was called with attack details
        self.test_callback.assert_called()
        args = self.test_callback.call_args_list[-1][0]
        self.assertTrue(args[0], "Detection should be successful")
        self.assertIn('MITM', args[1], "Message should indicate MITM attack")
    
    def test_syn_flood_detection(self):
        """Test detection of SYN flood attacks."""
        # Create mock packets showing SYN flood
        syn_flood_packets = self._generate_syn_flood_packets()
        
        # Create a standalone SYN flood detector
        syn_detector = SYNFloodPattern()
        
        # Test the detection
        result = syn_detector.analyze(syn_flood_packets)
        
        # Verify the detection result
        self.assertIsNotNone(result, "SYN flood attack should be detected")
        self.assertEqual(result['type'], 'syn_flood')
        self.assertGreaterEqual(len(result['targets']), 1)
        
        # Test with the full recognizer
        with patch.object(self.recognizer, 'get_packets_for_analysis', return_value=syn_flood_packets):
            self.recognizer.start_detection(callback=self.test_callback)
            time.sleep(0.5)  # Allow time for analysis
            self.recognizer.stop_detection()
            
        # Verify callback was called with attack details
        self.test_callback.assert_called()
        args = self.test_callback.call_args_list[-1][0]
        self.assertTrue(args[0], "Detection should be successful")
        self.assertIn('SYN', args[1], "Message should indicate SYN flood attack")
    
    def test_smb_exploit_detection(self):
        """Test detection of SMB exploitation attempts."""
        # Create mock packets showing SMB exploitation
        smb_packets = self._generate_smb_exploit_packets()
        
        # Create a standalone SMB detector
        smb_detector = SMBExploitPattern()
        
        # Test the detection
        result = smb_detector.analyze(smb_packets)
        
        # Verify the detection result
        self.assertIsNotNone(result, "SMB exploit attack should be detected")
        self.assertEqual(result['type'], 'smb_exploit')
        self.assertGreaterEqual(len(result['exploit_attempts']), 1)
        
        # Test with the full recognizer
        with patch.object(self.recognizer, 'get_packets_for_analysis', return_value=smb_packets):
            self.recognizer.start_detection(callback=self.test_callback)
            time.sleep(0.5)  # Allow time for analysis
            self.recognizer.stop_detection()
            
        # Verify callback was called with attack details
        self.test_callback.assert_called()
        args = self.test_callback.call_args_list[-1][0]
        self.assertTrue(args[0], "Detection should be successful")
        self.assertIn('SMB', args[1], "Message should indicate SMB attack")
    
    def test_ssh_brute_force_detection(self):
        """Test detection of SSH brute force attempts."""
        # Create mock packets showing SSH brute force
        ssh_packets = self._generate_ssh_brute_force_packets()
        
        # Create a standalone SSH detector
        ssh_detector = SSHBruteForcePattern()
        
        # Test the detection
        result = ssh_detector.analyze(ssh_packets)
        
        # Verify the detection result
        self.assertIsNotNone(result, "SSH brute force attack should be detected")
        self.assertEqual(result['type'], 'ssh_brute_force')
        self.assertGreaterEqual(len(result['sources']), 1)
        
        # Test with the full recognizer
        with patch.object(self.recognizer, 'get_packets_for_analysis', return_value=ssh_packets):
            self.recognizer.start_detection(callback=self.test_callback)
            time.sleep(0.5)  # Allow time for analysis
            self.recognizer.stop_detection()
            
        # Verify callback was called with attack details
        self.test_callback.assert_called()
        args = self.test_callback.call_args_list[-1][0]
        self.assertTrue(args[0], "Detection should be successful")
        self.assertIn('SSH', args[1], "Message should indicate SSH attack")
    
    def test_web_attack_detection(self):
        """Test detection of web application attacks."""
        # Create mock packets showing web attacks
        web_packets = self._generate_web_attack_packets()
        
        # Create a standalone web attack detector
        web_detector = WebAttackPattern()
        
        # Test the detection
        result = web_detector.analyze(web_packets)
        
        # Verify the detection result
        self.assertIsNotNone(result, "Web attack should be detected")
        self.assertTrue(result['type'].startswith('web_'))
        self.assertGreaterEqual(len(result['sources']), 1)
        
        # Test with the full recognizer
        with patch.object(self.recognizer, 'get_packets_for_analysis', return_value=web_packets):
            self.recognizer.start_detection(callback=self.test_callback)
            time.sleep(0.5)  # Allow time for analysis
            self.recognizer.stop_detection()
            
        # Verify callback was called with attack details
        self.test_callback.assert_called()
        args = self.test_callback.call_args_list[-1][0]
        self.assertTrue(args[0], "Detection should be successful")
        self.assertIn('Web', args[1], "Message should indicate web attack")
    
    def _generate_mitm_packets(self):
        """Generate mock packets showing MITM attack indicators."""
        packets = []
        
        # Timestamps for ordered packet sequence
        timestamp = self.base_time
        
        # Create packets with asymmetric routing (MAC address inconsistencies)
        for i in range(20):
            # Normal forward packet
            forward_packet = {
                'id': f'pkt{i*2}',
                'timestamp': timestamp,
                'protocol': 'TCP',
                'src_ip': '192.168.1.10',
                'src_mac': '00:11:22:33:44:55' if i < 10 else '00:11:22:33:44:66',  # MAC changes halfway
                'dst_ip': '192.168.1.100',
                'dst_mac': '00:aa:bb:cc:dd:ee',
                'src_port': 12345,
                'dst_port': 80,
                'ttl': 64,
                'info': 'HTTP GET request'
            }
            
            # Response packet
            timestamp += timedelta(milliseconds=50)
            reverse_packet = {
                'id': f'pkt{i*2+1}',
                'timestamp': timestamp,
                'protocol': 'TCP',
                'src_ip': '192.168.1.100',
                'src_mac': '00:aa:bb:cc:dd:ee',
                'dst_ip': '192.168.1.10',
                'dst_mac': '00:11:22:33:44:55',  # Doesn't change to match the new src_mac
                'src_port': 80,
                'dst_port': 12345,
                'ttl': 64,
                'info': 'HTTP 200 OK'
            }
            
            packets.append(forward_packet)
            packets.append(reverse_packet)
            timestamp += timedelta(milliseconds=100)
            
        # Add some ICMP redirects
        for i in range(5):
            redirect_packet = {
                'id': f'redirect{i}',
                'timestamp': timestamp,
                'protocol': 'ICMP',
                'src_ip': '192.168.1.1',
                'src_mac': '00:de:ad:be:ef:00',
                'dst_ip': '192.168.1.10',
                'dst_mac': '00:11:22:33:44:55',
                'ttl': 64,
                'info': 'redirect for host 192.168.1.100'
            }
            packets.append(redirect_packet)
            timestamp += timedelta(milliseconds=100)
            
        # Add some SSL/TLS errors
        for i in range(5):
            tls_error_packet = {
                'id': f'tls{i}',
                'timestamp': timestamp,
                'protocol': 'TLS',
                'src_ip': '192.168.1.100',
                'src_mac': '00:aa:bb:cc:dd:ee',
                'dst_ip': '192.168.1.10',
                'dst_mac': '00:11:22:33:44:55',
                'ttl': 64,
                'info': 'alert level warning, handshake failure'
            }
            packets.append(tls_error_packet)
            timestamp += timedelta(milliseconds=100)
            
        return packets
    
    def _generate_syn_flood_packets(self):
        """Generate mock packets showing SYN flood attack."""
        packets = []
        
        # Timestamps for ordered packet sequence
        timestamp = self.base_time
        
        # Create many SYN packets to a single destination
        target_ip = '192.168.1.100'
        target_port = 80
        
        # Generate 300 SYN packets for a SYN flood
        for i in range(300):
            # SYN packet
            syn_packet = {
                'id': f'syn{i}',
                'timestamp': timestamp,
                'protocol': 'TCP',
                'src_ip': f'10.0.0.{i % 10 + 1}',  # 10 different source IPs
                'src_mac': f'00:11:22:33:44:{i % 10 + 1:02x}',
                'dst_ip': target_ip,
                'dst_port': target_port,
                'src_port': 10000 + (i % 5000),  # Random source ports
                'flags': 'SYN',
                'ttl': 64,
                'info': 'TCP SYN'
            }
            
            packets.append(syn_packet)
            # Small time increment to simulate high rate
            timestamp += timedelta(milliseconds=3)  # 333 packets per second
            
        return packets
    
    def _generate_smb_exploit_packets(self):
        """Generate mock packets showing SMB exploitation attempts."""
        packets = []
        
        # Timestamps for ordered packet sequence
        timestamp = self.base_time
        
        # Generate SMB exploitation packets
        for i in range(15):
            # SMB packet with suspicious signature
            smb_packet = {
                'id': f'smb{i}',
                'timestamp': timestamp,
                'protocol': 'SMB',
                'src_ip': '10.0.0.5',
                'src_mac': '00:11:22:33:44:55',
                'dst_ip': '192.168.1.100',
                'dst_port': 445,
                'src_port': 49152 + i,
                'ttl': 64,
                'info': 'SMB2 NEGOTIATE REQUEST',
                'raw_data': b'\x00\x00\x00\x45\xff\x53\x4d\x42'  # EternalBlue signature
            }
            
            packets.append(smb_packet)
            timestamp += timedelta(milliseconds=100)
            
        # Generate SMB brute force packets
        for i in range(15):
            # SMB authentication failure
            auth_packet = {
                'id': f'smbauth{i}',
                'timestamp': timestamp,
                'protocol': 'SMB',
                'src_ip': '10.0.0.6',
                'src_mac': '00:aa:bb:cc:dd:ee',
                'dst_ip': '192.168.1.101',
                'dst_port': 445,
                'src_port': 49200 + i,
                'ttl': 64,
                'info': 'SMB2 SESSION SETUP RESPONSE status: ACCESS_DENIED'
            }
            
            packets.append(auth_packet)
            timestamp += timedelta(milliseconds=200)
            
        return packets
    
    def _generate_ssh_brute_force_packets(self):
        """Generate mock packets showing SSH brute force attempts."""
        packets = []
        
        # Timestamps for ordered packet sequence
        timestamp = self.base_time
        
        # Generate SSH brute force packets
        for i in range(20):
            # SSH SYN packet
            syn_packet = {
                'id': f'ssh{i*2}',
                'timestamp': timestamp,
                'protocol': 'TCP',
                'src_ip': '10.0.0.7',
                'src_mac': '00:11:22:33:44:77',
                'dst_ip': '192.168.1.102',
                'dst_port': 22,
                'src_port': 50000 + i,
                'flags': 'SYN',
                'ttl': 64,
                'info': 'TCP SYN'
            }
            
            packets.append(syn_packet)
            timestamp += timedelta(milliseconds=50)
            
            # SSH failure packet
            if i % 3 == 0:  # Every few attempts, add a failure message
                fail_packet = {
                    'id': f'ssh{i*2+1}',
                    'timestamp': timestamp,
                    'protocol': 'SSH',
                    'src_ip': '192.168.1.102',
                    'src_mac': '00:aa:bb:cc:dd:ff',
                    'dst_ip': '10.0.0.7',
                    'dst_port': 50000 + i,
                    'src_port': 22,
                    'ttl': 64,
                    'info': 'authentication failure for user root from 10.0.0.7'
                }
                
                packets.append(fail_packet)
            
            timestamp += timedelta(milliseconds=300)
            
        return packets
    
    def _generate_web_attack_packets(self):
        """Generate mock packets showing web application attacks."""
        packets = []
        
        # Timestamps for ordered packet sequence
        timestamp = self.base_time
        
        # Generate SQL injection attack packets
        for i in range(5):
            # SQL injection attempt packet
            sql_packet = {
                'id': f'sql{i}',
                'timestamp': timestamp,
                'protocol': 'TCP',
                'src_ip': '10.0.0.8',
                'src_mac': '00:11:22:33:44:88',
                'dst_ip': '192.168.1.103',
                'dst_port': 80,
                'src_port': 51000 + i,
                'ttl': 64,
                'info': 'HTTP GET request',
                'http_request': f"GET /login.php?username=admin' OR '1'='1&password=test HTTP/1.1"
            }
            
            packets.append(sql_packet)
            timestamp += timedelta(milliseconds=500)
            
        # Generate XSS attack packets
        for i in range(5):
            # XSS attempt packet
            xss_packet = {
                'id': f'xss{i}',
                'timestamp': timestamp,
                'protocol': 'TCP',
                'src_ip': '10.0.0.8',
                'src_mac': '00:11:22:33:44:88',
                'dst_ip': '192.168.1.103',
                'dst_port': 80,
                'src_port': 51100 + i,
                'ttl': 64,
                'info': 'HTTP POST request',
                'http_request': f"POST /comment.php HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ncomment=<script>alert(document.cookie)</script>"
            }
            
            packets.append(xss_packet)
            timestamp += timedelta(milliseconds=500)
            
        # Generate path traversal attack packets
        for i in range(5):
            # Path traversal attempt packet
            path_packet = {
                'id': f'path{i}',
                'timestamp': timestamp,
                'protocol': 'TCP',
                'src_ip': '10.0.0.9',
                'src_mac': '00:11:22:33:44:99',
                'dst_ip': '192.168.1.103',
                'dst_port': 80,
                'src_port': 51200 + i,
                'ttl': 64,
                'info': 'HTTP GET request',
                'http_request': f"GET /download.php?file=../../../etc/passwd HTTP/1.1"
            }
            
            packets.append(path_packet)
            timestamp += timedelta(milliseconds=500)
            
        return packets

if __name__ == '__main__':
    unittest.main() 