import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import logging
from typing import Dict, Any, List, Optional
from .alert import Alert, AlertChannel, AlertPriority, AlertType, AlertStatus

logger = logging.getLogger(__name__)

class EmailChannel(AlertChannel):
    """Email notification channel"""
    
    def __init__(
        self,
        smtp_server: str,
        smtp_port: int,
        username: str,
        password: str,
        sender_email: str,
        recipient_emails: List[str],
        use_tls: bool = True,
        name: str = "email",
        config: Dict[str, Any] = None
    ):
        """
        Initialize email channel.
        
        Args:
            smtp_server: SMTP server hostname
            smtp_port: SMTP server port
            username: SMTP username
            password: SMTP password
            sender_email: Sender email address
            recipient_emails: List of recipient email addresses
            use_tls: Whether to use TLS
            name: Channel name
            config: Additional configuration
        """
        super().__init__(name, config or {})
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.sender_email = sender_email
        self.recipient_emails = recipient_emails
        self.use_tls = use_tls
    
    def _send_alert(self, alert: Alert) -> bool:
        """
        Send alert via email.
        
        Args:
            alert: Alert to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            # Create message
            msg = MIMEMultipart()
            msg["Subject"] = f"[{alert.priority.name}] ARP Guard Alert: {alert.type.name}"
            msg["From"] = self.sender_email
            msg["To"] = ", ".join(self.recipient_emails)
            
            # Email body
            body = self._format_alert_email(alert)
            msg.attach(MIMEText(body, "plain"))
            
            # Connect to SMTP server
            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls(context=context)
                
                server.login(self.username, self.password)
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            logger.error(f"Error sending email alert: {e}")
            return False
    
    def _format_alert_email(self, alert: Alert) -> str:
        """
        Format alert for email.
        
        Args:
            alert: Alert to format
            
        Returns:
            Formatted email body
        """
        lines = [
            f"Alert ID: {alert.id}",
            f"Type: {alert.type.name}",
            f"Priority: {alert.priority.name}",
            f"Time: {self._format_timestamp(alert.timestamp)}",
            f"Source: {alert.source}",
            f"Status: {alert.status.name}",
            f"Message: {alert.message}",
            ""
        ]
        
        # Add details if present
        if alert.details:
            lines.append("Details:")
            for key, value in alert.details.items():
                if isinstance(value, dict):
                    lines.append(f"  {key}:")
                    for k, v in value.items():
                        lines.append(f"    {k}: {v}")
                else:
                    lines.append(f"  {key}: {value}")
        
        return "\n".join(lines)
    
    def _format_timestamp(self, timestamp: float) -> str:
        """
        Format timestamp for display.
        
        Args:
            timestamp: Unix timestamp
            
        Returns:
            Formatted timestamp
        """
        from datetime import datetime
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


class SlackChannel(AlertChannel):
    """Slack notification channel using incoming webhooks"""
    
    def __init__(
        self,
        webhook_url: str,
        channel: Optional[str] = None,
        username: str = "ARP Guard",
        icon_emoji: str = ":shield:",
        name: str = "slack",
        config: Dict[str, Any] = None
    ):
        """
        Initialize Slack channel.
        
        Args:
            webhook_url: Slack webhook URL
            channel: Slack channel to send to (optional)
            username: Username to display
            icon_emoji: Emoji to use as icon
            name: Channel name
            config: Additional configuration
        """
        super().__init__(name, config or {})
        self.webhook_url = webhook_url
        self.channel = channel
        self.username = username
        self.icon_emoji = icon_emoji
    
    def _send_alert(self, alert: Alert) -> bool:
        """
        Send alert to Slack.
        
        Args:
            alert: Alert to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            # Create payload
            payload = {
                "username": self.username,
                "icon_emoji": self.icon_emoji
            }
            
            if self.channel:
                payload["channel"] = self.channel
            
            # Add blocks for prettier formatting
            payload["blocks"] = self._format_slack_blocks(alert)
            
            # Send to webhook
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                return True
            else:
                logger.warning(f"Slack API returned {response.status_code}: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending Slack alert: {e}")
            return False
    
    def _format_slack_blocks(self, alert: Alert) -> List[Dict[str, Any]]:
        """
        Format alert as Slack blocks.
        
        Args:
            alert: Alert to format
            
        Returns:
            List of Slack blocks
        """
        # Determine color based on priority
        color = self._get_priority_color(alert.priority)
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{self._get_emoji(alert)} {alert.type.name} Alert"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{alert.message}*"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*ID:*\n{alert.id}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Priority:*\n{alert.priority.name}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Source:*\n{alert.source}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Status:*\n{alert.status.name}"
                    }
                ]
            }
        ]
        
        # Add details if present
        if alert.details:
            details_text = "*Details:*\n"
            for key, value in alert.details.items():
                if isinstance(value, dict):
                    details_text += f"• *{key}*:\n"
                    for k, v in value.items():
                        if isinstance(v, (dict, list)):
                            v = str(v)
                        details_text += f"  • {k}: {v}\n"
                elif isinstance(value, list):
                    details_text += f"• *{key}*: {', '.join(map(str, value))}\n"
                else:
                    details_text += f"• *{key}*: {value}\n"
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": details_text
                }
            })
        
        return blocks
    
    def _get_priority_color(self, priority: AlertPriority) -> str:
        """
        Get color for priority.
        
        Args:
            priority: Alert priority
            
        Returns:
            Hex color code
        """
        colors = {
            AlertPriority.CRITICAL: "#FF0000",  # Red
            AlertPriority.HIGH: "#FFA500",      # Orange
            AlertPriority.MEDIUM: "#FFFF00",    # Yellow
            AlertPriority.LOW: "#00FF00",       # Green
            AlertPriority.INFO: "#0000FF"       # Blue
        }
        return colors.get(priority, "#808080")  # Default gray
    
    def _get_emoji(self, alert: Alert) -> str:
        """
        Get emoji for alert type.
        
        Args:
            alert: Alert
            
        Returns:
            Emoji string
        """
        emojis = {
            AlertType.SYSTEM: ":gear:",
            AlertType.RATE_ANOMALY: ":chart_with_upwards_trend:",
            AlertType.PATTERN_MATCH: ":mag:",
            AlertType.ARP_SPOOFING: ":warning:",
            AlertType.GATEWAY_CHANGE: ":door:",
            AlertType.NETWORK_SCAN: ":globe_with_meridians:",
            AlertType.CUSTOM: ":star:"
        }
        return emojis.get(alert.type, ":bell:")


class WebhookChannel(AlertChannel):
    """Generic webhook notification channel"""
    
    def __init__(
        self,
        url: str,
        method: str = "POST",
        headers: Dict[str, str] = None,
        name: str = "webhook",
        config: Dict[str, Any] = None
    ):
        """
        Initialize webhook channel.
        
        Args:
            url: Webhook URL
            method: HTTP method to use ("POST" or "PUT")
            headers: HTTP headers to include
            name: Channel name
            config: Additional configuration
        """
        super().__init__(name, config or {})
        self.url = url
        self.method = method.upper()
        if self.method not in ["POST", "PUT"]:
            raise ValueError("Method must be POST or PUT")
        self.headers = headers or {
            "Content-Type": "application/json"
        }
    
    def _send_alert(self, alert: Alert) -> bool:
        """
        Send alert to webhook.
        
        Args:
            alert: Alert to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            # Convert alert to JSON payload
            payload = self._alert_to_dict(alert)
            
            # Send request
            if self.method == "POST":
                response = requests.post(self.url, json=payload, headers=self.headers)
            else:  # PUT
                response = requests.put(self.url, json=payload, headers=self.headers)
            
            if response.status_code >= 200 and response.status_code < 300:
                return True
            else:
                logger.warning(f"Webhook returned {response.status_code}: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending webhook alert: {e}")
            return False
    
    def _alert_to_dict(self, alert: Alert) -> Dict[str, Any]:
        """
        Convert alert to dictionary format.
        
        Args:
            alert: Alert to convert
            
        Returns:
            Dictionary representation of alert
        """
        return {
            "id": alert.id,
            "type": alert.type.name,
            "priority": alert.priority.name,
            "message": alert.message,
            "timestamp": alert.timestamp,
            "source": alert.source,
            "status": alert.status.name,
            "details": alert.details
        }


class ConsoleChannel(AlertChannel):
    """Console notification channel for debugging"""
    
    def __init__(
        self,
        colored: bool = True,
        name: str = "console",
        config: Dict[str, Any] = None
    ):
        """
        Initialize console channel.
        
        Args:
            colored: Whether to use colored output
            name: Channel name
            config: Additional configuration
        """
        super().__init__(name, config or {})
        self.colored = colored
    
    def _send_alert(self, alert: Alert) -> bool:
        """
        Print alert to console.
        
        Args:
            alert: Alert to print
            
        Returns:
            Always True
        """
        try:
            # Format the alert
            alert_text = self._format_alert(alert)
            
            # Print to console
            print(alert_text)
            
            return True
            
        except Exception as e:
            logger.error(f"Error printing console alert: {e}")
            return False
    
    def _format_alert(self, alert: Alert) -> str:
        """
        Format alert for console output.
        
        Args:
            alert: Alert to format
            
        Returns:
            Formatted alert string
        """
        from datetime import datetime
        
        # Priority colors
        colors = {
            AlertPriority.CRITICAL: "\033[91m",  # Red
            AlertPriority.HIGH: "\033[93m",      # Yellow
            AlertPriority.MEDIUM: "\033[94m",    # Blue
            AlertPriority.LOW: "\033[92m",       # Green
            AlertPriority.INFO: "\033[96m"       # Cyan
        }
        reset = "\033[0m"
        
        # Format timestamp
        timestamp = datetime.fromtimestamp(alert.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        
        # Format header
        if self.colored:
            color = colors.get(alert.priority, "")
            header = f"{color}[{alert.priority.name}] {alert.type.name} ALERT{reset}"
        else:
            header = f"[{alert.priority.name}] {alert.type.name} ALERT"
        
        # Format message
        lines = [
            "=" * 60,
            header,
            "=" * 60,
            f"ID: {alert.id}",
            f"Time: {timestamp}",
            f"Source: {alert.source}",
            f"Status: {alert.status.name}",
            f"Message: {alert.message}",
            "-" * 60
        ]
        
        # Add details if present
        if alert.details:
            lines.append("Details:")
            for key, value in alert.details.items():
                if isinstance(value, dict):
                    lines.append(f"  {key}:")
                    for k, v in value.items():
                        lines.append(f"    {k}: {v}")
                elif isinstance(value, list):
                    lines.append(f"  {key}: {', '.join(map(str, value))}")
                else:
                    lines.append(f"  {key}: {value}")
        
        lines.append("=" * 60)
        
        return "\n".join(lines) 