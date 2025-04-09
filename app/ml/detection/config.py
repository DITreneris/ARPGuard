from typing import Dict, Any
import yaml
import os
from pathlib import Path

class RuleConfig:
    """Manages rule configurations"""
    def __init__(self, config_path: str = None):
        """
        Initialize RuleConfig with a configuration path.
        
        Args:
            config_path: Path to the configuration file. If None, uses default path.
        """
        if config_path is None:
            # Use default configuration path in the data directory
            base_dir = Path(__file__).parent.parent.parent.parent  # ARPGuard/
            config_path = os.path.join(base_dir, "data", "rules_config.yaml")
            
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self.load_config()
        
    def load_config(self) -> None:
        """Load configuration from file"""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    self.config = yaml.safe_load(f) or {}
            except Exception as e:
                print(f"Error loading rule configuration: {e}")
                self.config = {}
        else:
            # Create a default configuration
            self.config = self._create_default_config()
            self.save_config()
                
    def save_config(self) -> None:
        """Save configuration to file"""
        # Create directory if it doesn't exist
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
        except Exception as e:
            print(f"Error saving rule configuration: {e}")
            
    def get_rule_config(self, rule_id: str) -> Dict[str, Any]:
        """Get configuration for a specific rule"""
        return self.config.get(rule_id, {})
        
    def update_rule_config(self, rule_id: str, config: Dict[str, Any]) -> None:
        """Update configuration for a specific rule"""
        self.config[rule_id] = config
        self.save_config()
        
    def _create_default_config(self) -> Dict[str, Any]:
        """Create a default configuration for all rules"""
        return {
            "ARP_SPOOFING_001": {
                "enabled": True,
                "threshold": 0.8,
                "action": "alert"
            },
            "ARP_GRATUITOUS_001": {
                "enabled": True,
                "threshold": 0.7,
                "action": "log",
                "rate_threshold": 10
            },
            "ARP_FLOOD_001": {
                "enabled": True,
                "threshold": 0.8,
                "action": "alert",
                "packets_per_second_threshold": 20
            }
        } 