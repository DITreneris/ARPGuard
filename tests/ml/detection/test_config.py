import pytest
import os
import yaml
from pathlib import Path
from app.ml.detection.config import RuleConfig

class TestRuleConfig:
    """Tests for the RuleConfig class"""
    
    def setup_method(self):
        """Set up test fixtures"""
        # Use a temporary file for testing
        self.test_config_path = "test_rules_config.yaml"
        
    def teardown_method(self):
        """Tear down test fixtures"""
        # Clean up temporary file
        if os.path.exists(self.test_config_path):
            os.remove(self.test_config_path)
            
    def test_create_default_config(self):
        """Test that default configuration is created when file doesn't exist"""
        # Make sure the file doesn't exist
        if os.path.exists(self.test_config_path):
            os.remove(self.test_config_path)
            
        # Create config
        config = RuleConfig(self.test_config_path)
        
        # Check that the file was created
        assert os.path.exists(self.test_config_path)
        
        # Check that default values were set
        assert "ARP_SPOOFING_001" in config.config
        assert config.config["ARP_SPOOFING_001"]["enabled"] is True
        assert config.config["ARP_SPOOFING_001"]["threshold"] == 0.8
        
        assert "ARP_GRATUITOUS_001" in config.config
        assert config.config["ARP_GRATUITOUS_001"]["enabled"] is True
        assert config.config["ARP_GRATUITOUS_001"]["rate_threshold"] == 10
        
        assert "ARP_FLOOD_001" in config.config
        assert config.config["ARP_FLOOD_001"]["enabled"] is True
        assert config.config["ARP_FLOOD_001"]["packets_per_second_threshold"] == 20
        
    def test_load_existing_config(self):
        """Test that existing configuration is loaded correctly"""
        # Create a config file manually
        test_config = {
            "ARP_SPOOFING_001": {
                "enabled": False,
                "threshold": 0.5,
                "action": "log"
            }
        }
        
        with open(self.test_config_path, 'w') as f:
            yaml.dump(test_config, f)
            
        # Load the config
        config = RuleConfig(self.test_config_path)
        
        # Check that values were loaded correctly
        assert "ARP_SPOOFING_001" in config.config
        assert config.config["ARP_SPOOFING_001"]["enabled"] is False
        assert config.config["ARP_SPOOFING_001"]["threshold"] == 0.5
        assert config.config["ARP_SPOOFING_001"]["action"] == "log"
        
    def test_get_rule_config(self):
        """Test getting configuration for a specific rule"""
        config = RuleConfig(self.test_config_path)
        
        # Get config for a rule
        rule_config = config.get_rule_config("ARP_SPOOFING_001")
        
        # Check values
        assert rule_config["enabled"] is True
        assert rule_config["threshold"] == 0.8
        assert rule_config["action"] == "alert"
        
    def test_get_nonexistent_rule_config(self):
        """Test getting configuration for a rule that doesn't exist"""
        config = RuleConfig(self.test_config_path)
        
        # Get config for a nonexistent rule
        rule_config = config.get_rule_config("NONEXISTENT_RULE")
        
        # Should return empty dict
        assert rule_config == {}
        
    def test_update_rule_config(self):
        """Test updating configuration for a specific rule"""
        config = RuleConfig(self.test_config_path)
        
        # Update config for a rule
        new_config = {
            "enabled": False,
            "threshold": 0.6,
            "action": "block"
        }
        config.update_rule_config("ARP_SPOOFING_001", new_config)
        
        # Check values were updated
        rule_config = config.get_rule_config("ARP_SPOOFING_001")
        assert rule_config["enabled"] is False
        assert rule_config["threshold"] == 0.6
        assert rule_config["action"] == "block"
        
        # Check that the file was saved
        with open(self.test_config_path, 'r') as f:
            saved_config = yaml.safe_load(f)
            
        assert saved_config["ARP_SPOOFING_001"]["enabled"] is False
        assert saved_config["ARP_SPOOFING_001"]["threshold"] == 0.6
        assert saved_config["ARP_SPOOFING_001"]["action"] == "block"
        
    def test_add_new_rule_config(self):
        """Test adding configuration for a new rule"""
        config = RuleConfig(self.test_config_path)
        
        # Add config for a new rule
        new_config = {
            "enabled": True,
            "threshold": 0.7,
            "action": "log"
        }
        config.update_rule_config("NEW_RULE_001", new_config)
        
        # Check values were added
        rule_config = config.get_rule_config("NEW_RULE_001")
        assert rule_config["enabled"] is True
        assert rule_config["threshold"] == 0.7
        assert rule_config["action"] == "log" 