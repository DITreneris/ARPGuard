#!/usr/bin/env python
"""
Unit tests for the configuration management module.
"""
import os
import tempfile
import unittest
import yaml

from app.utils.config import ConfigManager, DEFAULT_CONFIG


class TestConfigManager(unittest.TestCase):
    """
    Test cases for the configuration management functionality.
    """
    def setUp(self):
        """Set up the test case."""
        # Create a temporary directory for test files
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.temp_dir.name, "config.yaml")
        self.config_manager = None
    
    def tearDown(self):
        """Clean up after the test case."""
        self.temp_dir.cleanup()
    
    def test_default_config_load(self):
        """Test loading the default configuration."""
        # Create a config manager with no config file
        config_manager = ConfigManager(None)
        
        # Ensure the default config is loaded
        self.assertEqual(config_manager.config, DEFAULT_CONFIG)
        
        # Test getting values from the default config
        self.assertEqual(config_manager.get("general", "log_level"), "INFO")
        self.assertEqual(config_manager.get("scan", "default_timeout"), 2)
        self.assertEqual(config_manager.get("monitor", "alert_level"), "medium")
    
    def test_config_save_load(self):
        """Test saving and loading configuration."""
        # Create a config manager
        config_manager = ConfigManager(None)
        
        # Modify some settings
        config_manager.set("general", "log_level", "DEBUG")
        config_manager.set("scan", "default_timeout", 10)
        config_manager.set("monitor", "alert_level", "high")
        
        # Save the configuration
        config_manager.save_config(self.config_path)
        
        # Create a new config manager to load the saved config
        new_config_manager = ConfigManager(self.config_path)
        
        # Verify the loaded settings
        self.assertEqual(new_config_manager.get("general", "log_level"), "DEBUG")
        self.assertEqual(new_config_manager.get("scan", "default_timeout"), 10)
        self.assertEqual(new_config_manager.get("monitor", "alert_level"), "high")
    
    def test_config_validation(self):
        """Test configuration validation."""
        # Create an invalid configuration (wrong type)
        invalid_config = DEFAULT_CONFIG.copy()
        invalid_config["scan"]["default_timeout"] = "not_an_integer"
        
        with open(self.config_path, "w") as f:
            yaml.dump(invalid_config, f)
        
        # Loading should fail validation and use default
        config_manager = ConfigManager(self.config_path)
        self.assertEqual(config_manager.config, DEFAULT_CONFIG)
        
        # Create an invalid configuration (missing required field)
        invalid_config = DEFAULT_CONFIG.copy()
        del invalid_config["scan"]["default_ports"]
        
        with open(self.config_path, "w") as f:
            yaml.dump(invalid_config, f)
        
        # Loading should fail validation and use default
        config_manager = ConfigManager(self.config_path)
        self.assertEqual(config_manager.config, DEFAULT_CONFIG)
    
    def test_config_section_access(self):
        """Test accessing configuration sections."""
        config_manager = ConfigManager(None)
        
        # Get entire section
        general_section = config_manager.get("general")
        self.assertIsInstance(general_section, dict)
        self.assertEqual(general_section["log_level"], "INFO")
        
        # Get missing section
        self.assertIsNone(config_manager.get("non_existent_section"))
        
        # Get with default
        self.assertEqual(
            config_manager.get("non_existent_section", default="default_value"),
            "default_value"
        )
    
    def test_config_create_default(self):
        """Test creating a default configuration file."""
        # Create a new config manager
        config_manager = ConfigManager(None)
        
        # Create a default config file
        config_manager.create_default_config(self.config_path)
        
        # Check if the file exists
        self.assertTrue(os.path.exists(self.config_path))
        
        # Load and verify the default config
        with open(self.config_path, "r") as f:
            loaded_config = yaml.safe_load(f)
        
        self.assertEqual(loaded_config, DEFAULT_CONFIG)
    
    def test_set_get_operations(self):
        """Test setting and getting configuration values."""
        config_manager = ConfigManager(None)
        
        # Test setting various types of values
        tests = [
            ("general", "test_string", "test_value"),
            ("general", "test_int", 42),
            ("general", "test_float", 3.14),
            ("general", "test_bool", True),
            ("general", "test_list", [1, 2, 3]),
            ("general", "test_dict", {"key": "value"})
        ]
        
        for section, key, value in tests:
            # Set the value
            config_manager.set(section, key, value)
            
            # Get the value back
            retrieved = config_manager.get(section, key)
            
            # Check if it's the same
            self.assertEqual(retrieved, value)
    
    def test_custom_validation(self):
        """Test custom validation rules."""
        # Create a config with an invalid subnet
        invalid_config = DEFAULT_CONFIG.copy()
        invalid_config["scan"]["default_subnet"] = "not_a_subnet"
        
        with open(self.config_path, "w") as f:
            yaml.dump(invalid_config, f)
        
        # Loading should fail validation and use default
        config_manager = ConfigManager(self.config_path)
        self.assertEqual(config_manager.config, DEFAULT_CONFIG)
        
        # Create a config with a valid subnet
        valid_config = DEFAULT_CONFIG.copy()
        valid_config["scan"]["default_subnet"] = "192.168.1.0/24"
        
        with open(self.config_path, "w") as f:
            yaml.dump(valid_config, f)
        
        # Loading should pass validation
        config_manager = ConfigManager(self.config_path)
        self.assertEqual(config_manager.get("scan", "default_subnet"), "192.168.1.0/24")


if __name__ == "__main__":
    unittest.main() 