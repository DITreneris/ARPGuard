import unittest
import os
import sys
from unittest.mock import patch, MagicMock
from datetime import datetime

# Add the parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from components.defense_mechanism import DefenseMechanism

class TestDefenseMechanisms(unittest.TestCase):
    """Test cases for defense mechanisms against different attack types."""
    
    def setUp(self):
        """Set up test environment before each test case."""
        # Create a defense mechanism instance with mocked subprocess calls
        self.defense = DefenseMechanism()
        self.test_callback = MagicMock()
        
        # Mock OS detection to ensure consistent tests
        patcher = patch.object(self.defense, 'os_type', 'windows')
        self.mock_os_type = patcher.start()
        self.addCleanup(patcher.stop)
        
        # Mock subprocess.run to prevent actual command execution
        patcher = patch('subprocess.run')
        self.mock_subprocess_run = patcher.start()
        self.addCleanup(patcher.stop)
        
        # Configure mock subprocess to return success for commands
        self.mock_subprocess_run.return_value.returncode = 0
    
    def tearDown(self):
        """Clean up after each test case."""
        # Stop all defenses
        self.defense.stop_all_defenses()
    
    def test_arp_spoofing_defense(self):
        """Test defenses against ARP spoofing attacks."""
        # Mock attack details
        attack_details = {
            'type': 'arp_spoofing',
            'detection_time': datetime.now(),
            'suspicious_ips': [
                {'ip': '192.168.1.1', 'macs': ['00:11:22:33:44:55', '00:AA:BB:CC:DD:EE']},
                {'ip': '192.168.1.2', 'macs': ['00:11:22:33:44:66', '00:AA:BB:CC:DD:FF']}
            ]
        }
        
        # Activate defense
        result = self.defense.start_defense(attack_details, self.test_callback)
        
        # Verify defense was activated
        self.assertTrue(result, "ARP spoofing defense should activate successfully")
        self.test_callback.assert_called()
        
        # Verify correct commands were executed
        self.mock_subprocess_run.assert_called()
        
        # Verify defense is tracked
        active_defenses = self.defense.get_active_defenses()
        self.assertEqual(len(active_defenses), 1, "Should have one active defense")
        
        # Stop defense
        defense_id = list(active_defenses.keys())[0]
        stop_result = self.defense.stop_defense(defense_id)
        
        # Verify defense was deactivated
        self.assertTrue(stop_result, "ARP spoofing defense should deactivate successfully")
        self.assertEqual(len(self.defense.get_active_defenses()), 0, "Should have no active defenses")
    
    def test_port_scan_defense(self):
        """Test defenses against port scanning attacks."""
        # Mock attack details
        attack_details = {
            'type': 'port_scanning',
            'detection_time': datetime.now(),
            'scanners': [
                {
                    'src_ip': '10.0.0.5',
                    'unique_port_count': 100,
                    'packet_count': 150,
                    'targets': [{'ip': '192.168.1.100', 'port_count': 100}]
                }
            ],
            'most_active': {
                'src_ip': '10.0.0.5',
                'unique_port_count': 100,
                'packet_count': 150,
                'targets': [{'ip': '192.168.1.100', 'port_count': 100}]
            }
        }
        
        # Activate defense
        result = self.defense.start_defense(attack_details, self.test_callback)
        
        # Verify defense was activated
        self.assertTrue(result, "Port scanning defense should activate successfully")
        self.test_callback.assert_called()
        
        # Verify defense is tracked
        active_defenses = self.defense.get_active_defenses()
        self.assertEqual(len(active_defenses), 1, "Should have one active defense")
        
        # Stop defense
        defense_id = list(active_defenses.keys())[0]
        stop_result = self.defense.stop_defense(defense_id)
        
        # Verify defense was deactivated
        self.assertTrue(stop_result, "Port scanning defense should deactivate successfully")
    
    def test_mitm_defense(self):
        """Test defenses against Man-in-the-Middle attacks."""
        # Mock attack details
        attack_details = {
            'type': 'mitm_attack',
            'detection_time': datetime.now(),
            'redirected_flows': [
                {
                    'src_ip': '10.0.0.6',
                    'dst_ip': '192.168.1.100',
                    'forward_macs': ['00:11:22:33:44:55', '00:11:22:33:44:66'],
                    'reverse_macs': ['00:AA:BB:CC:DD:EE'],
                    'packet_count': 30
                },
                {
                    'type': 'icmp_redirect',
                    'count': 5,
                    'sources': ['10.0.0.7']
                }
            ],
            'ssl_issues': 3
        }
        
        # Activate defense
        result = self.defense.start_defense(attack_details, self.test_callback)
        
        # Verify defense was activated
        self.assertTrue(result, "MITM defense should activate successfully")
        self.test_callback.assert_called()
        
        # Verify defense is tracked
        active_defenses = self.defense.get_active_defenses()
        self.assertEqual(len(active_defenses), 1, "Should have one active defense")
        
        # Verify correct IPs were blocked
        defense_details = active_defenses[list(active_defenses.keys())[0]]['defense_details']
        blocked_flows = defense_details.get('blocked_flows', [])
        
        # Should have at least 2 blocked flows (one regular flow and one ICMP redirect)
        self.assertGreaterEqual(len(blocked_flows), 2, "Should block at least 2 flows")
        
        # Stop defense
        defense_id = list(active_defenses.keys())[0]
        stop_result = self.defense.stop_defense(defense_id)
        
        # Verify defense was deactivated
        self.assertTrue(stop_result, "MITM defense should deactivate successfully")
    
    def test_syn_flood_defense(self):
        """Test defenses against SYN flood attacks."""
        # Mock attack details
        attack_details = {
            'type': 'syn_flood',
            'detection_time': datetime.now(),
            'targets': [
                {
                    'dst_ip': '192.168.1.100',
                    'dst_port': 80,
                    'service': 'HTTP',
                    'syn_count': 300,
                    'rate_per_second': 150.0,
                    'source_ip_count': 10,
                    'duration_seconds': 2.0
                }
            ],
            'distributed': True,
            'max_rate': 150.0
        }
        
        # Activate defense
        result = self.defense.start_defense(attack_details, self.test_callback)
        
        # Verify defense was activated
        self.assertTrue(result, "SYN flood defense should activate successfully")
        self.test_callback.assert_called()
        
        # Verify defense is tracked
        active_defenses = self.defense.get_active_defenses()
        self.assertEqual(len(active_defenses), 1, "Should have one active defense")
        
        # Verify target was protected
        defense_details = active_defenses[list(active_defenses.keys())[0]]['defense_details']
        protected_targets = defense_details.get('protected_targets', [])
        self.assertEqual(len(protected_targets), 1, "Should protect 1 target")
        self.assertEqual(protected_targets[0]['ip'], '192.168.1.100', "Should protect the correct target IP")
        
        # Stop defense
        defense_id = list(active_defenses.keys())[0]
        stop_result = self.defense.stop_defense(defense_id)
        
        # Verify defense was deactivated
        self.assertTrue(stop_result, "SYN flood defense should deactivate successfully")
    
    def test_smb_attack_defense(self):
        """Test defenses against SMB-related attacks."""
        # Mock attack details
        attack_details = {
            'type': 'smb_exploit',
            'detection_time': datetime.now(),
            'exploit_attempts': [
                {
                    'src_ip': '10.0.0.8',
                    'dst_ip': '192.168.1.100',
                    'timestamp': datetime.now(),
                    'signature': '0000002fff534d42',
                    'packet_id': 'pkt123'
                }
            ],
            'brute_force_sources': [
                {
                    'src_ip': '10.0.0.9',
                    'failed_attempts': 15,
                    'packet_count': 30
                }
            ],
            'exploitation_risk': 'High'
        }
        
        # Activate defense
        result = self.defense.start_defense(attack_details, self.test_callback)
        
        # Verify defense was activated
        self.assertTrue(result, "SMB attack defense should activate successfully")
        self.test_callback.assert_called()
        
        # Verify defense is tracked
        active_defenses = self.defense.get_active_defenses()
        self.assertEqual(len(active_defenses), 1, "Should have one active defense")
        
        # Verify sources were blocked
        defense_details = active_defenses[list(active_defenses.keys())[0]]['defense_details']
        blocked_sources = defense_details.get('blocked_sources', [])
        self.assertGreaterEqual(len(blocked_sources), 2, "Should block at least 2 sources")
        
        # Verify both exploit and brute force sources were blocked
        blocked_ips = [source['ip'] for source in blocked_sources]
        self.assertIn('10.0.0.8', blocked_ips, "Should block exploit attempt source")
        self.assertIn('10.0.0.9', blocked_ips, "Should block brute force source")
        
        # Stop defense
        defense_id = list(active_defenses.keys())[0]
        stop_result = self.defense.stop_defense(defense_id)
        
        # Verify defense was deactivated
        self.assertTrue(stop_result, "SMB attack defense should deactivate successfully")
    
    def test_ssh_brute_force_defense(self):
        """Test defenses against SSH brute force attacks."""
        # Mock attack details
        attack_details = {
            'type': 'ssh_brute_force',
            'detection_time': datetime.now(),
            'sources': [
                {
                    'src_ip': '10.0.0.10',
                    'connection_attempts': 20,
                    'unique_targets': 1,
                    'target_ips': ['192.168.1.100'],
                    'rate_per_second': 3.0,
                    'duration_seconds': 6.66
                }
            ],
            'max_attempts': 20
        }
        
        # Activate defense
        result = self.defense.start_defense(attack_details, self.test_callback)
        
        # Verify defense was activated
        self.assertTrue(result, "SSH brute force defense should activate successfully")
        self.test_callback.assert_called()
        
        # Verify defense is tracked
        active_defenses = self.defense.get_active_defenses()
        self.assertEqual(len(active_defenses), 1, "Should have one active defense")
        
        # Verify source was blocked
        defense_details = active_defenses[list(active_defenses.keys())[0]]['defense_details']
        blocked_sources = defense_details.get('blocked_sources', [])
        self.assertEqual(len(blocked_sources), 1, "Should block 1 source")
        self.assertEqual(blocked_sources[0]['ip'], '10.0.0.10', "Should block the correct source IP")
        
        # Stop defense
        defense_id = list(active_defenses.keys())[0]
        stop_result = self.defense.stop_defense(defense_id)
        
        # Verify defense was deactivated
        self.assertTrue(stop_result, "SSH brute force defense should deactivate successfully")
    
    def test_web_attack_defense(self):
        """Test defenses against web application attacks."""
        # Mock attack details
        attack_details = {
            'type': 'web_sql_injection',
            'detection_time': datetime.now(),
            'sources': [
                {
                    'src_ip': '10.0.0.11',
                    'attack_types': [
                        {'type': 'sql_injection', 'count': 5},
                        {'type': 'xss', 'count': 3}
                    ],
                    'total_attempts': 8
                },
                {
                    'src_ip': '10.0.0.12',
                    'attack_types': [
                        {'type': 'path_traversal', 'count': 5}
                    ],
                    'total_attempts': 5
                }
            ],
            'most_common_attack': 'sql_injection',
            'attack_types_found': ['sql_injection', 'xss', 'path_traversal']
        }
        
        # Activate defense
        result = self.defense.start_defense(attack_details, self.test_callback)
        
        # Verify defense was activated
        self.assertTrue(result, "Web attack defense should activate successfully")
        self.test_callback.assert_called()
        
        # Verify defense is tracked
        active_defenses = self.defense.get_active_defenses()
        self.assertEqual(len(active_defenses), 1, "Should have one active defense")
        
        # Verify sources were blocked
        defense_details = active_defenses[list(active_defenses.keys())[0]]['defense_details']
        blocked_sources = defense_details.get('blocked_sources', [])
        self.assertEqual(len(blocked_sources), 2, "Should block 2 sources")
        
        # Verify both attack sources were blocked
        blocked_ips = [source['ip'] for source in blocked_sources]
        self.assertIn('10.0.0.11', blocked_ips, "Should block SQL injection source")
        self.assertIn('10.0.0.12', blocked_ips, "Should block path traversal source")
        
        # Stop defense
        defense_id = list(active_defenses.keys())[0]
        stop_result = self.defense.stop_defense(defense_id)
        
        # Verify defense was deactivated
        self.assertTrue(stop_result, "Web attack defense should deactivate successfully")
    
    def test_stop_all_defenses(self):
        """Test stopping all active defenses at once."""
        # Create multiple mock attacks
        attacks = [
            {
                'type': 'arp_spoofing',
                'detection_time': datetime.now(),
                'suspicious_ips': [
                    {'ip': '192.168.1.1', 'macs': ['00:11:22:33:44:55', '00:AA:BB:CC:DD:EE']}
                ]
            },
            {
                'type': 'syn_flood',
                'detection_time': datetime.now(),
                'targets': [
                    {
                        'dst_ip': '192.168.1.100',
                        'dst_port': 80,
                        'service': 'HTTP',
                        'syn_count': 300,
                        'rate_per_second': 150.0,
                        'source_ip_count': 10,
                        'duration_seconds': 2.0
                    }
                ]
            },
            {
                'type': 'ssh_brute_force',
                'detection_time': datetime.now(),
                'sources': [
                    {
                        'src_ip': '10.0.0.10',
                        'connection_attempts': 20,
                        'unique_targets': 1,
                        'target_ips': ['192.168.1.100'],
                        'rate_per_second': 3.0,
                        'duration_seconds': 6.66
                    }
                ]
            }
        ]
        
        # Activate multiple defenses
        for attack in attacks:
            self.defense.start_defense(attack, self.test_callback)
        
        # Verify multiple defenses are active
        active_defenses = self.defense.get_active_defenses()
        self.assertEqual(len(active_defenses), 3, "Should have 3 active defenses")
        
        # Stop all defenses
        result = self.defense.stop_all_defenses()
        
        # Verify all defenses were stopped
        self.assertTrue(result, "Should successfully stop all defenses")
        self.assertEqual(len(self.defense.get_active_defenses()), 0, "Should have no active defenses")

if __name__ == '__main__':
    unittest.main() 