#!/usr/bin/env python
"""
Integration tests for the configuration management system.
"""
import os
import sys
import json
import tempfile
import unittest
from io import StringIO
from contextlib import redirect_stdout

from app.utils.config import ConfigManager, DEFAULT_CONFIG, get_config_manager
from app.components.cli import ARPGuardCLI


class TestConfigIntegration(unittest.TestCase):
    """
    Integration tests for the configuration management system.
    Tests the integration between ConfigManager and CLI components.
    """
    def setUp(self):
        """Set up the test case."""
        # Create a temporary directory for test files
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.temp_dir.name, "config.yaml")
        
        # Reset the global config manager
        global get_config_manager
        from app.utils.config import get_config_manager as original_gcm
        self.original_gcm = original_gcm
        
        # Create a custom config manager for testing
        self.config_manager = ConfigManager(self.config_path)
        
        # Override the global config manager to use our test instance
        import app.utils.config
        app.utils.config.config_manager = self.config_manager
        app.utils.config.get_config_manager = lambda config_file=None: self.config_manager
        
        # Create CLI with our config manager
        self.cli = ARPGuardCLI()
    
    def tearDown(self):
        """Clean up after the test case."""
        self.temp_dir.cleanup()
        
        # Restore the original get_config_manager
        import app.utils.config
        app.utils.config.get_config_manager = self.original_gcm
        app.utils.config.config_manager = None
    
    def _capture_output(self, func, *args, **kwargs):
        """Capture stdout from a function call."""
        captured_output = StringIO()
        with redirect_stdout(captured_output):
            result = func(*args, **kwargs)
        return result, captured_output.getvalue()
    
    def test_config_cli_get(self):
        """Test the config get command."""
        # Set a known value
        self.config_manager.set("scan", "default_timeout", 10)
        
        # Test getting the value via CLI
        result, output = self._capture_output(
            self.cli.run, ["config", "get", "scan", "default_timeout"]
        )
        
        # Verify the output contains the expected value
        self.assertEqual(result, 0)
        self.assertIn("10", output.strip())
    
    def test_config_cli_set(self):
        """Test the config set command."""
        # Use CLI to set a value
        result, output = self._capture_output(
            self.cli.run, ["config", "set", "scan", "default_timeout", "15"]
        )
        
        # Verify the command succeeded
        self.assertEqual(result, 0)
        
        # Verify the value was actually set in the configuration
        timeout = self.config_manager.get("scan", "default_timeout")
        self.assertEqual(timeout, 15)
    
    def test_config_cli_list(self):
        """Test the config list command."""
        result, output = self._capture_output(
            self.cli.run, ["config", "list", "scan"]
        )
        
        # Verify the command succeeded and output contains expected keys
        self.assertEqual(result, 0)
        self.assertIn("default_timeout", output)
        self.assertIn("default_ports", output)
        self.assertIn("classify_devices", output)
    
    def test_config_cli_save(self):
        """Test the config save command."""
        # Set a known value
        self.config_manager.set("scan", "default_timeout", 20)
        
        # Save the configuration using CLI
        result, output = self._capture_output(
            self.cli.run, ["config", "save"]
        )
        
        # Verify the command succeeded
        self.assertEqual(result, 0)
        self.assertIn("saved to", output)
        
        # Create a new config manager to load the saved config
        new_config_manager = ConfigManager(self.config_path)
        
        # Verify the value was properly saved
        timeout = new_config_manager.get("scan", "default_timeout")
        self.assertEqual(timeout, 20)
    
    def test_config_cli_reset(self):
        """Test the config reset command."""
        # Set a known value
        self.config_manager.set("scan", "default_timeout", 30)
        
        # Reset using CLI
        result, output = self._capture_output(
            self.cli.run, ["config", "reset", "-s", "scan"]
        )
        
        # Verify the command succeeded
        self.assertEqual(result, 0)
        self.assertIn("Reset", output)
        
        # Verify the value was reset to default
        timeout = self.config_manager.get("scan", "default_timeout")
        self.assertEqual(timeout, DEFAULT_CONFIG["scan"]["default_timeout"])
    
    def test_config_cli_create(self):
        """Test the config create command."""
        new_config_path = os.path.join(self.temp_dir.name, "new_config.yaml")
        
        # Create a default config file using CLI
        result, output = self._capture_output(
            self.cli.run, ["config", "create", "-f", new_config_path]
        )
        
        # Verify the command succeeded
        self.assertEqual(result, 0)
        self.assertIn("Created", output)
        
        # Verify the file exists
        self.assertTrue(os.path.exists(new_config_path))
        
        # Load the created config and verify it matches the default
        new_config_manager = ConfigManager(new_config_path)
        for section in DEFAULT_CONFIG:
            default_section = DEFAULT_CONFIG[section]
            created_section = new_config_manager.get(section)
            self.assertEqual(created_section, default_section)
    
    def test_config_type_conversion(self):
        """Test type conversion in the config set command."""
        test_cases = [
            # Command args, expected type, expected value
            (["config", "set", "scan", "default_timeout", "25"], int, 25),
            (["config", "set", "general", "log_level", "DEBUG"], str, "DEBUG"),
            (["config", "set", "general", "color_output", "false"], bool, False),
            (["config", "set", "scan", "default_ports", "22,80,443"], list, [22, 80, 443]),
        ]
        
        for cmd_args, expected_type, expected_value in test_cases:
            # Use CLI to set the value
            result, _ = self._capture_output(self.cli.run, cmd_args)
            self.assertEqual(result, 0)
            
            # Verify the value was set with the correct type and value
            section, key = cmd_args[2], cmd_args[3]
            actual_value = self.config_manager.get(section, key)
            self.assertIsInstance(actual_value, expected_type)
            self.assertEqual(actual_value, expected_value)
    
    def test_end_to_end_config_workflow(self):
        """Test an end-to-end configuration workflow."""
        # 1. Create a new config file
        config_path = os.path.join(self.temp_dir.name, "workflow_config.yaml")
        self.cli.run(["config", "create", "-f", config_path])
        
        # Override the config manager to use this new file
        self.config_manager = ConfigManager(config_path)
        import app.utils.config
        app.utils.config.config_manager = self.config_manager
        
        # 2. Set some custom values
        self.cli.run(["config", "set", "scan", "default_timeout", "5"])
        self.cli.run(["config", "set", "scan", "default_ports", "22,80,443,8080"])
        self.cli.run(["config", "set", "monitor", "alert_level", "high"])
        
        # 3. Save the configuration
        self.cli.run(["config", "save"])
        
        # 4. Reload the configuration with a new manager
        new_config_manager = ConfigManager(config_path)
        
        # 5. Verify all values were properly set and saved
        self.assertEqual(new_config_manager.get("scan", "default_timeout"), 5)
        self.assertEqual(new_config_manager.get("scan", "default_ports"), [22, 80, 443, 8080])
        self.assertEqual(new_config_manager.get("monitor", "alert_level"), "high")
        
        # 6. Reset one section to defaults
        self.cli.run(["config", "reset", "-s", "scan"])
        
        # 7. Verify only that section was reset
        self.assertEqual(
            self.config_manager.get("scan", "default_timeout"), 
            DEFAULT_CONFIG["scan"]["default_timeout"]
        )
        self.assertEqual(
            self.config_manager.get("scan", "default_ports"), 
            DEFAULT_CONFIG["scan"]["default_ports"]
        )
        self.assertEqual(self.config_manager.get("monitor", "alert_level"), "high")
    
    def test_cli_scan_uses_config(self):
        """Test that the scan command uses configuration values."""
        # Set specific configuration values
        self.config_manager.set("scan", "default_timeout", 7)
        self.config_manager.set("scan", "classify_devices", True)
        
        # Mock the device_discovery.discover method
        original_discover = self.cli.device_discovery.discover
        
        try:
            # Track called arguments
            called_args = {}
            
            def mock_discover(*args, **kwargs):
                # Save args for verification
                nonlocal called_args
                called_args = kwargs
                # Return empty list to avoid further processing
                return []
            
            # Replace with mock
            self.cli.device_discovery.discover = mock_discover
            
            # Run scan command without specifying timeout (should use config default)
            self.cli.run(["scan", "-s", "192.168.1.0/24"])
            
            # Verify config values were used
            self.assertEqual(called_args.get("timeout"), 7)
            self.assertEqual(called_args.get("classify"), True)
            
        finally:
            # Restore original method
            self.cli.device_discovery.discover = original_discover
    
    def test_cli_monitor_uses_config(self):
        """Test that the monitor command uses configuration values."""
        # Set specific configuration values
        self.config_manager.set("monitor", "alert_level", "high")
        self.config_manager.set("monitor", "check_interval", 5)
        
        # Mock the arp_cache_monitor.start_monitoring method
        original_start_monitoring = self.cli.arp_cache_monitor.start_monitoring
        
        try:
            # Track called arguments
            called_args = {}
            
            def mock_start_monitoring(*args, **kwargs):
                # Save args for verification
                nonlocal called_args
                called_args = kwargs
                # Return True to simulate success
                return True
            
            # Replace with mock
            self.cli.arp_cache_monitor.start_monitoring = mock_start_monitoring
            
            # Mock is_monitoring to return False to exit the monitoring loop
            self.cli.arp_cache_monitor.is_monitoring = lambda: False
            
            # Run monitor command without specifying alert level (should use config default)
            self.cli.run(["monitor", "-i", "eth0"])
            
            # Verify config values were used
            self.assertEqual(called_args.get("alert_level"), "high")
            self.assertEqual(called_args.get("check_interval"), 5)
            
        finally:
            # Restore original method
            self.cli.arp_cache_monitor.start_monitoring = original_start_monitoring


if __name__ == "__main__":
    unittest.main() 