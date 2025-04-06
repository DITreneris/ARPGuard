import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Add parent directory to path so we can import app modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.components.network_scanner import NetworkScanner

class TestNetworkScanner(unittest.TestCase):
    
    def setUp(self):
        self.scanner = NetworkScanner()
    
    @patch('app.components.network_scanner.netifaces')
    def test_get_default_gateway(self, mock_netifaces):
        # Mock the netifaces.gateways() return value
        mock_netifaces.gateways.return_value = {
            'default': {
                mock_netifaces.AF_INET: ('192.168.1.1', 'eth0')
            }
        }
        mock_netifaces.AF_INET = 2  # Mock the constant
        
        # Test the function
        gateway_ip, interface = self.scanner.get_default_gateway()
        
        # Verify the results
        self.assertEqual(gateway_ip, '192.168.1.1')
        self.assertEqual(interface, 'eth0')
        
    @patch('app.components.network_scanner.netifaces')
    def test_get_default_gateway_exception(self, mock_netifaces):
        # Mock an exception
        mock_netifaces.gateways.side_effect = Exception("Test exception")
        
        # Test the function
        gateway_ip, interface = self.scanner.get_default_gateway()
        
        # Verify error handling
        self.assertIsNone(gateway_ip)
        self.assertIsNone(interface)
    
    def test_get_network_range(self):
        # Mock the get_default_gateway method
        self.scanner.get_default_gateway = MagicMock(return_value=('192.168.1.1', 'eth0'))
        
        # Test the function
        network_range = self.scanner.get_network_range()
        
        # Verify the result
        self.assertEqual(network_range, '192.168.1.0/24')
        
    def test_get_network_range_no_gateway(self):
        # Mock the get_default_gateway method to return None
        self.scanner.get_default_gateway = MagicMock(return_value=(None, None))
        
        # Test the function
        network_range = self.scanner.get_network_range()
        
        # Verify the result
        self.assertIsNone(network_range)

    @patch('app.components.network_scanner.socket')
    def test_get_hostname(self, mock_socket):
        # Mock the socket.getfqdn function
        mock_socket.getfqdn.return_value = 'device.local'
        
        # Test the function
        hostname = self.scanner._get_hostname('192.168.1.10')
        
        # Verify the result
        self.assertEqual(hostname, 'device.local')
        
    @patch('app.components.network_scanner.socket')
    def test_get_hostname_router(self, mock_socket):
        # Mock the socket.getfqdn function to raise an exception
        mock_socket.getfqdn.side_effect = Exception("Test exception")
        
        # Test the function with an IP ending in .1 (usually a router)
        hostname = self.scanner._get_hostname('192.168.1.1')
        
        # Verify the result
        self.assertEqual(hostname, 'Router')
        
    @patch('app.components.network_scanner.socket')
    def test_get_hostname_exception(self, mock_socket):
        # Mock the socket.getfqdn function to raise an exception
        mock_socket.getfqdn.side_effect = Exception("Test exception")
        
        # Test the function with a generic IP
        hostname = self.scanner._get_hostname('192.168.1.10')
        
        # Verify the result
        self.assertEqual(hostname, 'Device (192.168.1.10)')

if __name__ == '__main__':
    unittest.main() 