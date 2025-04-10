from dataclasses import dataclass
from typing import List, Dict, Optional
import json
import os

@dataclass
class DemoConfig:
    """Configuration for ARP Guard demo package"""
    # Network settings
    interface: str = "eth0"
    capture_filter: str = "arp"
    promiscuous_mode: bool = True
    
    # Detection settings
    detection_threshold: float = 0.8
    sample_window: int = 100
    alert_cooldown: int = 60  # seconds
    
    # Logging settings
    log_level: str = "INFO"
    log_file: str = "arpguard_demo.log"
    
    # Demo specific settings
    demo_duration: int = 300  # seconds
    max_packets: int = 1000
    visualization_enabled: bool = True
    
    @classmethod
    def from_file(cls, config_path: str) -> 'DemoConfig':
        """Load configuration from file"""
        if not os.path.exists(config_path):
            return cls()  # Return default config if file doesn't exist
            
        with open(config_path, 'r') as f:
            config_data = json.load(f)
            return cls(**config_data)
    
    def to_file(self, config_path: str) -> None:
        """Save configuration to file"""
        config_data = {
            "interface": self.interface,
            "capture_filter": self.capture_filter,
            "promiscuous_mode": self.promiscuous_mode,
            "detection_threshold": self.detection_threshold,
            "sample_window": self.sample_window,
            "alert_cooldown": self.alert_cooldown,
            "log_level": self.log_level,
            "log_file": self.log_file,
            "demo_duration": self.demo_duration,
            "max_packets": self.max_packets,
            "visualization_enabled": self.visualization_enabled
        }
        
        with open(config_path, 'w') as f:
            json.dump(config_data, f, indent=4)

# Preset configurations for different demo scenarios
PRESET_CONFIGS = {
    "basic": DemoConfig(
        interface="eth0",
        capture_filter="arp",
        detection_threshold=0.8,
        sample_window=100,
        demo_duration=300
    ),
    "advanced": DemoConfig(
        interface="eth0",
        capture_filter="arp",
        detection_threshold=0.9,
        sample_window=200,
        demo_duration=600,
        max_packets=2000
    ),
    "performance": DemoConfig(
        interface="eth0",
        capture_filter="arp",
        detection_threshold=0.7,
        sample_window=50,
        demo_duration=900,
        max_packets=5000
    )
}

def get_preset_config(preset_name: str) -> Optional[DemoConfig]:
    """Get a preset configuration by name"""
    return PRESET_CONFIGS.get(preset_name) 