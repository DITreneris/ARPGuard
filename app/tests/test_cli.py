import unittest
from unittest.mock import patch, MagicMock
from io import StringIO
import sys
from app.components.cli import ARPGuardCLI

class TestARPGuardCLI(unittest.TestCase):
    def setUp(self):
        self.cli = ARPGuardCLI()
    
    def test_help_command(self):
        """Test that help is displayed when no arguments are provided."""
        with patch('sys.stdout', new=StringIO()) as fake_out:
            self.cli.run([])
            output = fake_out.getvalue()
            self.assertIn('ARPGuard - Network Security Monitoring Tool', output)
            self.assertIn('Available commands', output)
            self.assertIn('Examples:', output)
    
    def test_version_flag(self):
        """Test the version flag displays version information."""
        with patch('sys.stdout', new=StringIO()) as fake_out:
            with self.assertRaises(SystemExit):
                self.cli.run(['--version'])
            output = fake_out.getvalue()
            self.assertIn('ARPGuard 1.0.0', output)
    
    def test_dedicated_help_command(self):
        """Test the dedicated help command."""
        with patch('sys.stdout', new=StringIO()) as fake_out:
            self.cli.run(['help'])
            output = fake_out.getvalue()
            self.assertIn('ARPGuard - Network Security Monitoring Tool', output)
            self.assertIn('Examples:', output)
    
    def test_command_specific_help(self):
        """Test getting help for a specific command."""
        with patch('sys.stdout', new=StringIO()) as fake_out:
            self.cli.run(['help', 'scan'])
            output = fake_out.getvalue()
            self.assertIn("Help for command 'scan'", output)
            self.assertIn("discover devices on your network", output)
            self.assertIn("Examples:", output)
    
    def test_unknown_command_help(self):
        """Test getting help for an unknown command."""
        with patch('sys.stdout', new=StringIO()) as fake_out:
            self.cli.run(['help', 'unknown'])
            output = fake_out.getvalue()
            self.assertIn("Unknown command: unknown", output)
            self.assertIn("Available commands:", output)
    
    def test_scan_command(self):
        """Test the scan command structure."""
        with patch('sys.stdout', new=StringIO()) as fake_out:
            self.cli.run(['scan', '--subnet', '192.168.1.0/24'])
            output = fake_out.getvalue()
            self.assertIn('Scanning subnet 192.168.1.0/24', output)
    
    def test_scan_command_with_ports(self):
        """Test the scan command with port specification."""
        with patch('sys.stdout', new=StringIO()) as fake_out:
            self.cli.run(['scan', '--subnet', '192.168.1.0/24', '--ports', '22,80,443'])
            output = fake_out.getvalue()
            self.assertIn('Scanning subnet 192.168.1.0/24', output)
            self.assertIn('Scanning ports: 22,80,443', output)
    
    def test_monitor_command(self):
        """Test the monitor command structure."""
        with patch('sys.stdout', new=StringIO()) as fake_out:
            self.cli.run(['monitor', '--interface', 'eth0'])
            output = fake_out.getvalue()
            self.assertIn('Monitoring interface eth0', output)
            self.assertIn('with alert level: medium', output)
            self.assertIn('Monitoring continuously', output)
    
    def test_monitor_command_with_duration(self):
        """Test the monitor command with duration."""
        with patch('sys.stdout', new=StringIO()) as fake_out:
            self.cli.run(['monitor', '--interface', 'eth0', '--duration', '60', '--alert-level', 'high'])
            output = fake_out.getvalue()
            self.assertIn('Monitoring interface eth0', output)
            self.assertIn('with alert level: high', output)
            self.assertIn('Duration: 60s', output)
    
    def test_analyze_command(self):
        """Test the analyze command structure."""
        with patch('sys.stdout', new=StringIO()) as fake_out:
            self.cli.run(['analyze', '--file', 'test.pcap'])
            output = fake_out.getvalue()
            self.assertIn('Analyzing file: test.pcap', output)
    
    def test_analyze_command_with_options(self):
        """Test the analyze command with additional options."""
        with patch('sys.stdout', new=StringIO()) as fake_out:
            self.cli.run(['analyze', '--file', 'test.pcap', '--rules', 'custom.rules', '--protocol', 'arp'])
            output = fake_out.getvalue()
            self.assertIn('Analyzing file: test.pcap', output)
            self.assertIn('Using custom rules from: custom.rules', output)
            self.assertIn('Focusing on protocol: arp', output)
    
    def test_export_command(self):
        """Test the export command structure."""
        with patch('sys.stdout', new=StringIO()) as fake_out:
            self.cli.run(['export', '--format', 'json', '--output', 'results.json'])
            output = fake_out.getvalue()
            self.assertIn('Exporting all data to results.json in json format', output)
    
    def test_export_command_with_type(self):
        """Test the export command with data type."""
        with patch('sys.stdout', new=StringIO()) as fake_out:
            self.cli.run(['export', '--format', 'csv', '--output', 'threats.csv', '--type', 'threats'])
            output = fake_out.getvalue()
            self.assertIn('Exporting threats data to threats.csv in csv format', output)
    
    def test_invalid_command(self):
        """Test handling of invalid commands."""
        with patch('sys.stdout', new=StringIO()) as fake_out:
            self.cli.run(['invalid'])
            output = fake_out.getvalue()
            self.assertIn('error: argument command: invalid choice', output)
    
    def test_error_handling(self):
        """Test error handling in command execution."""
        with patch.object(self.cli.parser, 'parse_args') as mock_parse_args:
            mock_parse_args.side_effect = Exception("Test error")
            with patch('sys.stdout', new=StringIO()) as fake_out:
                result = self.cli.run(['scan'])
                self.assertEqual(result, 1)
                output = fake_out.getvalue()
                self.assertIn('Error: Test error', output)

if __name__ == '__main__':
    unittest.main() 