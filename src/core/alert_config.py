import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from .alert import AlertPriority, AlertType
from .notification_channels import EmailChannel, SlackChannel, WebhookChannel, ConsoleChannel

class AlertConfig:
    """Manages alert system configuration."""
    
    def __init__(self, config_path: str = "config/alert_config.json"):
        """
        Initialize alert configuration.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self.logger = logging.getLogger('alert_config')
        
        # Create config directory if it doesn't exist
        self.config_path.parent.mkdir(exist_ok=True)
        
        # Load or create default config
        self._load_config()
        
    def _load_config(self) -> None:
        """Load configuration from file or create default."""
        try:
            if self.config_path.exists():
                with open(self.config_path) as f:
                    self.config = json.load(f)
            else:
                self._create_default_config()
                self._save_config()
                
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            self._create_default_config()
            
    def _create_default_config(self) -> None:
        """Create default configuration."""
        self.config = {
            "channels": {
                "email": {
                    "enabled": False,
                    "smtp_server": "smtp.example.com",
                    "smtp_port": 587,
                    "username": "",
                    "password": "",
                    "from_addr": "alerts@example.com",
                    "to_addrs": []
                },
                "slack": {
                    "enabled": False,
                    "webhook_url": "",
                    "channel": "#alerts"
                },
                "webhook": {
                    "enabled": False,
                    "url": "",
                    "headers": {}
                },
                "console": {
                    "enabled": True
                }
            },
            "thresholds": {
                "rate_anomaly": {
                    "packets_per_second": 1000,
                    "window_size": 60
                }
            },
            "templates": {
                "email": {
                    "subject": "[{priority}] {type} Alert",
                    "body": """
                    Alert ID: {id}
                    Type: {type}
                    Priority: {priority}
                    Time: {timestamp}
                    Source: {source}
                    
                    Message:
                    {message}
                    
                    Details:
                    {details}
                    """
                },
                "slack": {
                    "message": "*[{priority}] {type} Alert*\n{message}",
                    "color": {
                        "LOW": "#36a64f",
                        "MEDIUM": "#f2c744",
                        "HIGH": "#e67e22",
                        "CRITICAL": "#e74c3c"
                    }
                }
            }
        }
        
    def _save_config(self) -> None:
        """Save configuration to file."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save config: {e}")
            
    def get_channel_config(self, channel_type: str) -> Dict[str, Any]:
        """
        Get configuration for a specific channel.
        
        Args:
            channel_type: Type of channel (email, slack, webhook, console)
            
        Returns:
            Channel configuration
        """
        return self.config["channels"].get(channel_type, {})
        
    def update_channel_config(self, 
                            channel_type: str, 
                            config: Dict[str, Any]) -> None:
        """
        Update configuration for a specific channel.
        
        Args:
            channel_type: Type of channel
            config: New configuration
        """
        self.config["channels"][channel_type].update(config)
        self._save_config()
        
    def get_threshold(self, threshold_type: str) -> Dict[str, Any]:
        """
        Get threshold configuration.
        
        Args:
            threshold_type: Type of threshold
            
        Returns:
            Threshold configuration
        """
        return self.config["thresholds"].get(threshold_type, {})
        
    def update_threshold(self, 
                        threshold_type: str, 
                        config: Dict[str, Any]) -> None:
        """
        Update threshold configuration.
        
        Args:
            threshold_type: Type of threshold
            config: New configuration
        """
        self.config["thresholds"][threshold_type].update(config)
        self._save_config()
        
    def get_template(self, 
                    template_type: str, 
                    alert_type: Optional[AlertType] = None) -> str:
        """
        Get alert template.
        
        Args:
            template_type: Type of template (email, slack)
            alert_type: Optional alert type for specific template
            
        Returns:
            Template string
        """
        template_key = f"{template_type}_{alert_type.value}" if alert_type else template_type
        return self.config["templates"].get(template_key, 
                                          self.config["templates"][template_type])
        
    def update_template(self, 
                       template_type: str, 
                       template: str,
                       alert_type: Optional[AlertType] = None) -> None:
        """
        Update alert template.
        
        Args:
            template_type: Type of template
            template: New template
            alert_type: Optional alert type for specific template
        """
        template_key = f"{template_type}_{alert_type.value}" if alert_type else template_type
        self.config["templates"][template_key] = template
        self._save_config()
        
    def create_channels(self) -> List[AlertChannel]:
        """
        Create notification channels based on configuration.
        
        Returns:
            List of configured channels
        """
        channels = []
        
        # Email channel
        email_config = self.get_channel_config("email")
        if email_config.get("enabled", False):
            channels.append(EmailChannel(
                smtp_server=email_config["smtp_server"],
                smtp_port=email_config["smtp_port"],
                username=email_config["username"],
                password=email_config["password"],
                from_addr=email_config["from_addr"],
                to_addrs=email_config["to_addrs"]
            ))
            
        # Slack channel
        slack_config = self.get_channel_config("slack")
        if slack_config.get("enabled", False):
            channels.append(SlackChannel(
                webhook_url=slack_config["webhook_url"],
                channel=slack_config.get("channel")
            ))
            
        # Webhook channel
        webhook_config = self.get_channel_config("webhook")
        if webhook_config.get("enabled", False):
            channels.append(WebhookChannel(
                webhook_url=webhook_config["url"],
                headers=webhook_config.get("headers", {})
            ))
            
        # Console channel
        console_config = self.get_channel_config("console")
        if console_config.get("enabled", True):
            channels.append(ConsoleChannel())
            
        return channels 