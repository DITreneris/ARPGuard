"""
Configuration Management Module for ARPGuard

This module handles loading, saving, and validating configuration files
for the ARPGuard application.
"""
import os
import yaml
import jsonschema
import ipaddress
from pathlib import Path
import logging
from typing import Any, Dict, Optional

# Define the configuration schema
CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "general": {
            "type": "object",
            "properties": {
                "log_level": {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]},
                "log_file": {"type": "string"},
                "color_output": {"type": "boolean"},
                "progress_indicators": {"type": "boolean"}
            },
            "required": ["log_level", "color_output", "progress_indicators"]
        },
        "scan": {
            "type": "object",
            "properties": {
                "default_interface": {"type": "string"},
                "default_timeout": {"type": "integer", "minimum": 1},
                "default_ports": {
                    "type": "array",
                    "items": {"type": "integer", "minimum": 1, "maximum": 65535}
                },
                "default_subnet": {"type": "string"},
                "classify_devices": {"type": "boolean"},
                "output_format": {"type": "string", "enum": ["table", "json", "csv"]}
            },
            "required": ["default_timeout", "default_ports", "classify_devices", "output_format"]
        },
        "monitor": {
            "type": "object",
            "properties": {
                "default_interface": {"type": "string"},
                "alert_level": {"type": "string", "enum": ["low", "medium", "high"]},
                "check_interval": {"type": "integer", "minimum": 1},
                "output_format": {"type": "string", "enum": ["normal", "json"]},
                "known_devices_file": {"type": "string"}
            },
            "required": ["alert_level", "check_interval", "output_format"]
        },
        "analyze": {
            "type": "object",
            "properties": {
                "pcap_dir": {"type": "string"},
                "max_packets": {"type": "integer", "minimum": 1},
                "filter_expression": {"type": "string"},
                "output_format": {"type": "string", "enum": ["table", "json", "csv"]}
            },
            "required": ["output_format"]
        },
        "export": {
            "type": "object",
            "properties": {
                "default_format": {"type": "string", "enum": ["json", "csv", "html", "pdf"]},
                "default_dir": {"type": "string"},
                "include_metadata": {"type": "boolean"}
            },
            "required": ["default_format", "include_metadata"]
        }
    },
    "required": ["general", "scan", "monitor", "analyze", "export"]
}

# Configuration file path
CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'config.yaml')

# Default configuration values
DEFAULT_CONFIG = {
    'general': {
        'log_level': 'INFO',
        'log_file': 'arpguard.log',
        'color_output': True,
        'progress_indicators': True
    },
    'scan': {
        'default_interface': 'eth0',
        'default_timeout': 3,
        'default_ports': [22, 80, 443, 3389, 5900, 8080],
        'default_subnet': '192.168.1.0/24',
        'classify_devices': True,
        'output_format': 'table'
    },
    'monitor': {
        'default_interface': 'eth0',
        'alert_level': 'medium',
        'check_interval': 1,
        'output_format': 'normal',
        'known_devices_file': 'known_devices.json'
    },
    'analyze': {
        'pcap_dir': 'captures',
        'max_packets': 20000,
        'filter_expression': 'tcp or udp or arp',
        'output_format': 'table'
    },
    'export': {
        'default_format': 'json',
        'default_dir': 'exports',
        'include_metadata': True
    }
}

# Global configuration object
_config = None

def load_config() -> Dict[str, Any]:
    """Load configuration from file or use defaults."""
    global _config
    
    if _config is not None:
        return _config
    
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = yaml.safe_load(f)
                print(f"Loaded configuration from {CONFIG_FILE}")
                _config = config
                return config
    except Exception as e:
        logging.error(f"Error loading configuration: {e}")
    
    print("Using default configuration")
    _config = DEFAULT_CONFIG
    return DEFAULT_CONFIG

def get_config() -> Dict[str, Any]:
    """Get the current configuration."""
    global _config
    
    if _config is None:
        return load_config()
    
    return _config

def get_config_value(section: str, key: str, default: Any = None) -> Any:
    """Get a specific configuration value."""
    config = get_config()
    return config.get(section, {}).get(key, default)

def set_config_value(section: str, key: str, value: Any) -> bool:
    """Set a specific configuration value."""
    config = get_config()
    
    if section not in config:
        config[section] = {}
    
    config[section][key] = value
    return True

def save_config(filepath: Optional[str] = None) -> bool:
    """Save the current configuration to file."""
    config = get_config()
    
    try:
        save_path = filepath or CONFIG_FILE
        with open(save_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
            print(f"Configuration saved to {save_path}")
        return True
    except Exception as e:
        logging.error(f"Error saving configuration: {e}")
        return False

# Configuration manager class for CLI
class ConfigManager:
    def __init__(self):
        self.config = get_config()
    
    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value with fallback to default."""
        if section in self.config and key in self.config[section]:
            return self.config[section][key]
        return default
    
    def set(self, section: str, key: str, value: Any) -> bool:
        """Set a configuration value."""
        if section not in self.config:
            self.config[section] = {}
        
        # Convert value to appropriate type based on default
        if isinstance(value, str) and value.lower() in ('true', 'false'):
            value = value.lower() == 'true'
        elif isinstance(value, str) and value.isdigit():
            value = int(value)
        
        self.config[section][key] = value
        return True
    
    def save(self, filepath: Optional[str] = None) -> bool:
        """Save the configuration."""
        try:
            save_path = filepath or CONFIG_FILE
            with open(save_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
            return True
        except Exception as e:
            logging.error(f"Error saving configuration: {e}")
            return False
    
    def load(self, filepath: Optional[str] = None) -> bool:
        """Load configuration from a file."""
        try:
            load_path = filepath or CONFIG_FILE
            if os.path.exists(load_path):
                with open(load_path, 'r') as f:
                    self.config = yaml.safe_load(f)
                return True
        except Exception as e:
            logging.error(f"Error loading configuration: {e}")
        return False
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get an entire configuration section."""
        if section in self.config:
            return self.config[section]
        return {}
    
    def list_sections(self) -> list:
        """List all configuration sections."""
        return list(self.config.keys())

def get_config_manager() -> ConfigManager:
    """Get a configuration manager instance."""
    return ConfigManager()

class ConfigManager:
    """
    Manages configuration loading, validation, and saving for ARPGuard.
    """
    def __init__(self, config_file=None):
        """
        Initialize the configuration manager with an optional config file path.
        
        Args:
            config_file (str, optional): Path to the configuration file. If None,
                                         default locations will be checked.
        """
        self.config = None
        self.config_file = config_file
        self.load_config()
    
    def load_config(self):
        """
        Load configuration from the specified file or search in default locations.
        If no config is found, the default configuration is used.
        
        Returns:
            dict: The loaded configuration.
        """
        config_locations = [
            self.config_file,
            os.path.expanduser("~/.config/arpguard/config.yaml"),
            os.path.expanduser("~/.arpguard/config.yaml"),
            os.path.join(os.getcwd(), "config.yaml")
        ]
        
        # Filter out None values
        config_locations = [loc for loc in config_locations if loc is not None]
        
        for location in config_locations:
            if location and os.path.exists(location):
                try:
                    with open(location, 'r') as file:
                        loaded_config = yaml.safe_load(file)
                        if self.validate_config(loaded_config):
                            self.config = loaded_config
                            self.config_file = location
                            print(f"Loaded configuration from {location}")
                            return self.config
                except Exception as e:
                    print(f"Error loading config from {location}: {str(e)}")
        
        # If no valid config is found, use the default
        print("Using default configuration")
        self.config = DEFAULT_CONFIG
        return self.config
    
    def validate_config(self, config):
        """
        Validate the configuration against the schema.
        
        Args:
            config (dict): The configuration to validate.
            
        Returns:
            bool: True if the configuration is valid, False otherwise.
        """
        try:
            jsonschema.validate(instance=config, schema=CONFIG_SCHEMA)
            return self._validate_custom_rules(config)
        except jsonschema.exceptions.ValidationError as e:
            print(f"Configuration validation error: {str(e)}")
            return False
    
    def _validate_custom_rules(self, config):
        """
        Additional custom validation rules not covered by JSON schema.
        
        Args:
            config (dict): The configuration to validate.
            
        Returns:
            bool: True if the configuration passes custom validation, False otherwise.
        """
        # Validate subnet format if provided
        if 'scan' in config and 'default_subnet' in config['scan'] and config['scan']['default_subnet']:
            try:
                ipaddress.ip_network(config['scan']['default_subnet'], strict=False)
            except ValueError:
                print(f"Invalid subnet format: {config['scan']['default_subnet']}")
                return False
        
        # Add more custom validations as needed
        return True
    
    def save_config(self, file_path=None):
        """
        Save the current configuration to a file.
        
        Args:
            file_path (str, optional): Path to save the configuration. If None,
                                       the current config_file is used.
                                       
        Returns:
            bool: True if the configuration was saved successfully, False otherwise.
        """
        if not file_path and not self.config_file:
            # Default to user config directory if no path is specified
            config_dir = os.path.expanduser("~/.config/arpguard")
            os.makedirs(config_dir, exist_ok=True)
            self.config_file = os.path.join(config_dir, "config.yaml")
        
        save_path = file_path or self.config_file
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)
            
            with open(save_path, 'w') as file:
                yaml.dump(self.config, file, default_flow_style=False, sort_keys=False)
            print(f"Configuration saved to {save_path}")
            return True
        except Exception as e:
            print(f"Error saving configuration: {str(e)}")
            return False
    
    def import_config(self, file_path):
        """
        Import configuration from a file.
        
        Args:
            file_path (str): Path to the configuration file.
            
        Returns:
            bool: True if the configuration was imported successfully, False otherwise.
        """
        if not file_path or not os.path.exists(file_path):
            print(f"Config file not found: {file_path}")
            return False
            
        try:
            with open(file_path, 'r') as file:
                loaded_config = yaml.safe_load(file)
                
            if not self.validate_config(loaded_config):
                print(f"Invalid configuration in {file_path}")
                return False
                
            self.config = loaded_config
            self.config_file = file_path
            print(f"Imported configuration from {file_path}")
            return True
        except Exception as e:
            print(f"Error importing config from {file_path}: {str(e)}")
            return False
    
    def create_template_config(self, file_path):
        """
        Create a configuration template file with comments.
        
        Args:
            file_path (str): Path to save the template.
            
        Returns:
            bool: True if the template was created successfully, False otherwise.
        """
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
            
            # Template content
            template = """# ARPGuard Configuration File
# This is a template configuration file that can be customized 
# according to your needs.

general:
  # Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  log_level: INFO
  
  # Log file location
  log_file: arpguard.log
  
  # Enable colorized terminal output
  color_output: true
  
  # Show progress indicators during operations
  progress_indicators: true

scan:
  # Default network interface (leave empty for auto-detection)
  default_interface: ""
  
  # Default timeout in seconds for scan operations
  default_timeout: 2
  
  # Default ports to scan
  default_ports:
    - 22    # SSH
    - 80    # HTTP
    - 443   # HTTPS
    - 3389  # RDP
    - 5900  # VNC
  
  # Default subnet to scan (leave empty for auto-detection)
  default_subnet: ""
  
  # Classify devices by type using MAC address
  classify_devices: true
  
  # Output format (table, json, csv)
  output_format: table

monitor:
  # Default network interface (leave empty for auto-detection)
  default_interface: ""
  
  # Alert level (low, medium, high)
  alert_level: medium
  
  # Check interval in seconds
  check_interval: 2
  
  # Output format (normal, json)
  output_format: normal
  
  # Known devices database file
  known_devices_file: known_devices.json

analyze:
  # Directory for packet captures
  pcap_dir: captures
  
  # Maximum packets to analyze
  max_packets: 10000
  
  # Filter expression for packet analysis
  filter_expression: ""
  
  # Output format (table, json, csv)
  output_format: table

export:
  # Default export format (json, csv, html, pdf)
  default_format: json
  
  # Default directory for exports
  default_dir: exports
  
  # Include metadata in exports
  include_metadata: true
"""
            
            with open(file_path, 'w') as file:
                file.write(template)
            print(f"Configuration template created at {file_path}")
            return True
        except Exception as e:
            print(f"Error creating config template: {str(e)}")
            return False
    
    def get(self, section, key=None, default=None):
        """
        Get a configuration value.
        
        Args:
            section (str): The configuration section.
            key (str, optional): The specific key in the section. If None, the entire section is returned.
            default: The default value to return if the key is not found.
            
        Returns:
            The configuration value or default if not found.
        """
        if not self.config:
            self.load_config()
            
        if section not in self.config:
            return default
            
        if key is None:
            return self.config[section]
            
        return self.config[section].get(key, default)
    
    def set(self, section, key, value):
        """
        Set a configuration value.
        
        Args:
            section (str): The configuration section.
            key (str): The specific key in the section.
            value: The value to set.
            
        Returns:
            bool: True if the value was set successfully, False otherwise.
        """
        if not self.config:
            self.load_config()
            
        if section not in self.config:
            self.config[section] = {}
            
        self.config[section][key] = value
        return True
    
    def create_default_config(self, file_path):
        """
        Create a default configuration file.
        
        Args:
            file_path (str): Path to save the default configuration.
            
        Returns:
            bool: True if the configuration was created successfully, False otherwise.
        """
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
            
            with open(file_path, 'w') as file:
                yaml.dump(DEFAULT_CONFIG, file, default_flow_style=False, sort_keys=False)
            print(f"Default configuration created at {file_path}")
            return True
        except Exception as e:
            print(f"Error creating default configuration: {str(e)}")
            return False


# Global configuration instance
config_manager = None

def get_config_manager(config_file=None):
    """
    Get the global configuration manager instance.
    
    Args:
        config_file (str, optional): Path to the configuration file.
        
    Returns:
        ConfigManager: The configuration manager instance.
    """
    global config_manager
    if config_manager is None:
        config_manager = ConfigManager(config_file)
    return config_manager 

# Global config manager instance
_config_manager = None

def get_config(config_file=None):
    """
    Get the configuration. If no configuration exists, create one with defaults.
    
    Args:
        config_file (str, optional): Path to the configuration file.
        
    Returns:
        dict: The configuration dictionary.
    """
    global _config_manager
    
    if _config_manager is None:
        _config_manager = ConfigManager(config_file)
        
    return _config_manager.config 