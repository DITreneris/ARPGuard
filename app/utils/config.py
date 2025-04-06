import os
import json
import logging
from typing import Dict, Any, Optional

# Default configuration
DEFAULT_CONFIG = {
    # General settings
    "app_name": "ARPGuard",
    "version": "0.1.0",
    "debug_mode": False,
    "log_level": "INFO",
    
    # UI settings
    "theme": "dark",
    "language": "en",
    "show_tooltips": True,
    "minimize_to_tray": True,
    
    # Network scanner settings
    "scanner": {
        "timeout": 3,
        "auto_scan_on_start": False,
        "save_results": True,
        "max_saved_scans": 5,
        "default_subnet_mask": "/24"
    },
    
    # ARP spoofing settings
    "spoofer": {
        "packet_interval": 1.0,
        "restore_on_exit": True,
        "max_packets": 0  # 0 means unlimited
    },
    
    # Threat detection settings
    "detector": {
        "start_on_launch": False,
        "notification_level": "all",  # all, critical, none
        "auto_protect": False,
        "max_history": 100
    }
}

class Config:
    """Configuration manager for ARPGuard."""
    
    def __init__(self):
        """Initialize the configuration manager."""
        self.config_dir = self._get_config_dir()
        self.config_file = os.path.join(self.config_dir, 'config.json')
        self.config = self._load_config()
        
    def _get_config_dir(self) -> str:
        """Get the configuration directory based on the OS."""
        if os.name == 'nt':  # Windows
            config_dir = os.path.join(os.environ.get('APPDATA', ''), 'ARPGuard')
        else:  # macOS, Linux
            config_dir = os.path.join(os.path.expanduser('~'), '.arpguard')
            
        # Create the config directory if it doesn't exist
        if not os.path.exists(config_dir):
            try:
                os.makedirs(config_dir)
            except Exception as e:
                logging.error(f"Failed to create config directory: {e}")
                # Fall back to the current directory
                config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')
                
        return config_dir
    
    def _load_config(self) -> Dict[str, Any]:
        """Load the configuration from the config file or use defaults."""
        config = DEFAULT_CONFIG.copy()
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    user_config = json.load(f)
                    
                # Update the default config with user settings
                self._deep_update(config, user_config)
            except Exception as e:
                logging.error(f"Failed to load config file: {e}")
                
        return config
    
    def _deep_update(self, target: Dict[str, Any], source: Dict[str, Any]) -> None:
        """Recursively update a nested dictionary."""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_update(target[key], value)
            else:
                target[key] = value
    
    def save(self) -> bool:
        """Save the current configuration to the config file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            logging.error(f"Failed to save config file: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key."""
        keys = key.split('.')
        result = self.config
        
        try:
            for k in keys:
                result = result[k]
            return result
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> None:
        """Set a configuration value by key."""
        keys = key.split('.')
        target = self.config
        
        # Navigate to the deepest dict
        for k in keys[:-1]:
            if k not in target or not isinstance(target[k], dict):
                target[k] = {}
            target = target[k]
            
        # Set the value
        target[keys[-1]] = value
    
    def reset_to_defaults(self) -> None:
        """Reset the configuration to default values."""
        self.config = DEFAULT_CONFIG.copy()
        self.save()
    
    def get_all(self) -> Dict[str, Any]:
        """Get the entire configuration dictionary."""
        return self.config.copy()


# Singleton pattern for config access
_config_instance = None

def get_config() -> Config:
    """Get the singleton configuration instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
    return _config_instance 