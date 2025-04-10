import unittest
import time
import os
import sys
import tempfile
import json
import threading
from unittest.mock import MagicMock, patch
from pathlib import Path

# Add src directory to path
sys.path.append(str(Path(__file__).parent.parent))

from src.core.alert import (
    Alert, AlertManager, AlertChannel, AlertType, AlertPriority, AlertStatus
)
from src.core.notification_channels import (
    EmailChannel, SlackChannel, WebhookChannel, ConsoleChannel
)

class MockChannel(AlertChannel):
    """Mock channel for testing"""
    
    def __init__(self, name="mock", should_succeed=True):
        super().__init__(name)
        self.alerts = []
        self.should_succeed = should_succeed
    
    def _send_alert(self, alert):
        self.alerts.append(alert)
        return self.should_succeed


class TestAlert(unittest.TestCase):
    """Test Alert data class"""
    
    def test_init(self):
        """Test Alert initialization"""
        alert = Alert(
            id="test-id",
            type=AlertType.ARP_SPOOFING,
            priority=AlertPriority.HIGH,
            message="Test alert",
            timestamp=1642524000.0,
            source="test",
            details={"key": "value"}
        )
        
        self.assertEqual(alert.id, "test-id")
        self.assertEqual(alert.type, AlertType.ARP_SPOOFING)
        self.assertEqual(alert.priority, AlertPriority.HIGH)
        self.assertEqual(alert.message, "Test alert")
        self.assertEqual(alert.timestamp, 1642524000.0)
        self.assertEqual(alert.source, "test")
        self.assertEqual(alert.details, {"key": "value"})
        self.assertEqual(alert.status, AlertStatus.NEW)


class TestAlertManager(unittest.TestCase):
    """Test AlertManager"""
    
    def setUp(self):
        """Set up test environment"""
        self.manager = AlertManager()
        self.mock_channel = MockChannel()
        self.manager.add_channel(self.mock_channel)
    
    def test_create_alert(self):
        """Test creating an alert"""
        alert = self.manager.create_alert(
            AlertType.SYSTEM,
            AlertPriority.MEDIUM,
            "Test alert",
            "test_system",
            {"detail1": "value1"}
        )
        
        self.assertIsNotNone(alert)
        self.assertEqual(alert.type, AlertType.SYSTEM)
        self.assertEqual(alert.priority, AlertPriority.MEDIUM)
        self.assertEqual(alert.message, "Test alert")
        self.assertEqual(alert.source, "test_system")
        self.assertEqual(alert.details, {"detail1": "value1"})
        
        # Check if alert was sent to channel
        self.assertEqual(len(self.mock_channel.alerts), 1)
        self.assertEqual(self.mock_channel.alerts[0].id, alert.id)
    
    def test_get_alert(self):
        """Test getting an alert by ID"""
        alert = self.manager.create_alert(
            AlertType.PATTERN_MATCH,
            AlertPriority.HIGH,
            "Test retrieval",
            "test_system"
        )
        
        retrieved = self.manager.get_alert(alert.id)
        self.assertEqual(retrieved, alert)
        
        # Non-existent alert
        self.assertIsNone(self.manager.get_alert("non-existent-id"))
    
    def test_acknowledge_alert(self):
        """Test acknowledging an alert"""
        alert = self.manager.create_alert(
            AlertType.ARP_SPOOFING,
            AlertPriority.CRITICAL,
            "Test acknowledge",
            "test_system"
        )
        
        # Mock callback
        callback_called = False
        alert_updated = None
        
        def on_update(updated_alert):
            nonlocal callback_called, alert_updated
            callback_called = True
            alert_updated = updated_alert
        
        self.manager.on_alert_updated = on_update
        
        # Acknowledge alert
        result = self.manager.acknowledge_alert(alert.id, "Acknowledged by test")
        self.assertTrue(result)
        
        # Check status
        alert = self.manager.get_alert(alert.id)
        self.assertEqual(alert.status, AlertStatus.ACKNOWLEDGED)
        self.assertIsNotNone(alert.acknowledged_at)
        self.assertEqual(alert.acknowledgement_message, "Acknowledged by test")
        
        # Check callback
        self.assertTrue(callback_called)
        self.assertEqual(alert_updated, alert)
        
        # Non-existent alert
        result = self.manager.acknowledge_alert("non-existent-id")
        self.assertFalse(result)
    
    def test_resolve_alert(self):
        """Test resolving an alert"""
        alert = self.manager.create_alert(
            AlertType.RATE_ANOMALY,
            AlertPriority.HIGH,
            "Test resolve",
            "test_system"
        )
        
        # Mock callback
        callback_called = False
        alert_updated = None
        
        def on_update(updated_alert):
            nonlocal callback_called, alert_updated
            callback_called = True
            alert_updated = updated_alert
        
        self.manager.on_alert_updated = on_update
        
        # Resolve alert
        result = self.manager.resolve_alert(alert.id, "Resolved by test")
        self.assertTrue(result)
        
        # Check status
        alert = self.manager.get_alert(alert.id)
        self.assertEqual(alert.status, AlertStatus.RESOLVED)
        self.assertIsNotNone(alert.resolved_at)
        self.assertEqual(alert.resolution_message, "Resolved by test")
        
        # Check callback
        self.assertTrue(callback_called)
        self.assertEqual(alert_updated, alert)
        
        # Non-existent alert
        result = self.manager.resolve_alert("non-existent-id")
        self.assertFalse(result)
    
    def test_get_alerts(self):
        """Test getting filtered alerts"""
        # Create alerts with different properties
        alert1 = self.manager.create_alert(
            AlertType.SYSTEM,
            AlertPriority.LOW,
            "System alert",
            "system"
        )
        
        alert2 = self.manager.create_alert(
            AlertType.ARP_SPOOFING,
            AlertPriority.CRITICAL,
            "Critical alert",
            "arp_monitor"
        )
        
        alert3 = self.manager.create_alert(
            AlertType.SYSTEM,
            AlertPriority.MEDIUM,
            "Another system alert",
            "system"
        )
        
        # Acknowledge one alert
        self.manager.acknowledge_alert(alert3.id)
        
        # Test filtering by type
        system_alerts = self.manager.get_alerts(alert_type=AlertType.SYSTEM)
        self.assertEqual(len(system_alerts), 2)
        self.assertIn(alert1, system_alerts)
        self.assertIn(alert3, system_alerts)
        
        # Test filtering by priority
        critical_alerts = self.manager.get_alerts(priority=AlertPriority.CRITICAL)
        self.assertEqual(len(critical_alerts), 1)
        self.assertEqual(critical_alerts[0], alert2)
        
        # Test filtering by status
        acknowledged_alerts = self.manager.get_alerts(status=AlertStatus.ACKNOWLEDGED)
        self.assertEqual(len(acknowledged_alerts), 1)
        self.assertEqual(acknowledged_alerts[0], alert3)
        
        # Test filtering by source
        system_source_alerts = self.manager.get_alerts(source="system")
        self.assertEqual(len(system_source_alerts), 2)
        
        # Test filtering by time
        current_time = time.time()
        recent_alerts = self.manager.get_alerts(start_time=current_time - 10)
        self.assertEqual(len(recent_alerts), 3)  # All alerts are recent
        
        # Test limit
        limited_alerts = self.manager.get_alerts(limit=1)
        self.assertEqual(len(limited_alerts), 1)
    
    def test_add_filter(self):
        """Test adding alert filters"""
        # Add a filter that blocks low priority alerts
        def filter_low_priority(alert):
            return alert.priority != AlertPriority.LOW
        
        self.manager.add_filter(filter_low_priority)
        
        # Create low priority alert - should be filtered
        low_alert = self.manager.create_alert(
            AlertType.SYSTEM,
            AlertPriority.LOW,
            "Low priority alert",
            "test"
        )
        
        # Create medium priority alert - should pass filter
        medium_alert = self.manager.create_alert(
            AlertType.SYSTEM,
            AlertPriority.MEDIUM,
            "Medium priority alert",
            "test"
        )
        
        # Check if only medium alert was sent to channel
        self.assertEqual(len(self.mock_channel.alerts), 1)
        self.assertEqual(self.mock_channel.alerts[0].id, medium_alert.id)
    
    def test_remove_channel(self):
        """Test removing a notification channel"""
        # Add a second channel
        second_channel = MockChannel("second")
        self.manager.add_channel(second_channel)
        
        # Create an alert - should go to both channels
        alert = self.manager.create_alert(
            AlertType.SYSTEM,
            AlertPriority.MEDIUM,
            "Test channel removal",
            "test"
        )
        
        self.assertEqual(len(self.mock_channel.alerts), 1)
        self.assertEqual(len(second_channel.alerts), 1)
        
        # Remove first channel
        result = self.manager.remove_channel("mock")
        self.assertTrue(result)
        
        # Create another alert - should only go to second channel
        alert2 = self.manager.create_alert(
            AlertType.SYSTEM,
            AlertPriority.MEDIUM,
            "After removal",
            "test"
        )
        
        self.assertEqual(len(self.mock_channel.alerts), 1)  # No change
        self.assertEqual(len(second_channel.alerts), 2)
        
        # Try to remove non-existent channel
        result = self.manager.remove_channel("non-existent")
        self.assertFalse(result)
    
    def test_max_alerts(self):
        """Test max alerts limit"""
        # Create a manager with small max_alerts value
        manager = AlertManager()
        manager.max_alerts = 3
        
        # Create 5 alerts
        alerts = []
        for i in range(5):
            alert = manager.create_alert(
                AlertType.SYSTEM,
                AlertPriority.MEDIUM,
                f"Alert {i}",
                "test"
            )
            alerts.append(alert)
            time.sleep(0.01)  # Ensure different timestamps
        
        # Should only keep the newest 3
        stored_alerts = manager.get_alerts()
        self.assertEqual(len(stored_alerts), 3)
        
        # Check that we have the newest alerts (last 3 created)
        for alert in alerts[2:]:
            self.assertIn(alert.id, [a.id for a in stored_alerts])


class TestEmailChannel(unittest.TestCase):
    """Test EmailChannel"""
    
    @patch("smtplib.SMTP")
    def test_send_alert(self, mock_smtp):
        """Test sending alert via email"""
        # Configure mock
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server
        
        # Create channel
        channel = EmailChannel(
            smtp_server="smtp.example.com",
            smtp_port=587,
            username="user",
            password="pass",
            sender_email="sender@example.com",
            recipient_emails=["recipient@example.com"]
        )
        
        # Create alert
        alert = Alert(
            id="test-id",
            type=AlertType.ARP_SPOOFING,
            priority=AlertPriority.HIGH,
            message="Test email alert",
            timestamp=time.time(),
            source="test",
            details={"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"}
        )
        
        # Send alert
        result = channel.send(alert)
        
        # Verify result
        self.assertTrue(result)
        
        # Verify SMTP interactions
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("user", "pass")
        mock_server.send_message.assert_called_once()
        
        # Check email contents
        sent_message = mock_server.send_message.call_args[0][0]
        self.assertEqual(sent_message["From"], "sender@example.com")
        self.assertEqual(sent_message["To"], "recipient@example.com")
        self.assertIn("[HIGH] ARP Guard Alert: ARP_SPOOFING", sent_message["Subject"])


class TestSlackChannel(unittest.TestCase):
    """Test SlackChannel"""
    
    @patch("requests.post")
    def test_send_alert(self, mock_post):
        """Test sending alert via Slack"""
        # Configure mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        # Create channel
        channel = SlackChannel(
            webhook_url="https://hooks.slack.com/services/xxx",
            channel="#alerts",
            username="ARP Guard Bot"
        )
        
        # Create alert
        alert = Alert(
            id="test-id",
            type=AlertType.PATTERN_MATCH,
            priority=AlertPriority.MEDIUM,
            message="Test Slack alert",
            timestamp=time.time(),
            source="test",
            details={"pattern": "gateway_impersonation"}
        )
        
        # Send alert
        result = channel.send(alert)
        
        # Verify result
        self.assertTrue(result)
        
        # Verify request
        mock_post.assert_called_once()
        url = mock_post.call_args[0][0]
        payload = mock_post.call_args[1]["json"]
        
        self.assertEqual(url, "https://hooks.slack.com/services/xxx")
        self.assertEqual(payload["username"], "ARP Guard Bot")
        self.assertEqual(payload["channel"], "#alerts")
        
        # Check blocks
        blocks = payload["blocks"]
        self.assertTrue(len(blocks) >= 3)
        self.assertEqual(blocks[0]["type"], "header")
        self.assertIn("PATTERN_MATCH Alert", blocks[0]["text"]["text"])
        
        # Test with error response
        mock_response.status_code = 400
        result = channel.send(alert)
        self.assertFalse(result)


class TestWebhookChannel(unittest.TestCase):
    """Test WebhookChannel"""
    
    @patch("requests.post")
    @patch("requests.put")
    def test_send_alert(self, mock_put, mock_post):
        """Test sending alert via webhook"""
        # Configure mocks
        mock_post_response = MagicMock()
        mock_post_response.status_code = 200
        mock_post.return_value = mock_post_response
        
        mock_put_response = MagicMock()
        mock_put_response.status_code = 201
        mock_put.return_value = mock_put_response
        
        # Create POST channel
        post_channel = WebhookChannel(
            url="https://example.com/webhook",
            method="POST",
            headers={"X-Api-Key": "secret"}
        )
        
        # Create PUT channel
        put_channel = WebhookChannel(
            url="https://example.com/webhook",
            method="PUT",
            headers={"X-Api-Key": "secret"}
        )
        
        # Create alert
        alert = Alert(
            id="test-id",
            type=AlertType.GATEWAY_CHANGE,
            priority=AlertPriority.HIGH,
            message="Test webhook alert",
            timestamp=time.time(),
            source="test",
            details={"old_mac": "00:11:22:33:44:55", "new_mac": "AA:BB:CC:DD:EE:FF"}
        )
        
        # Send alert via POST
        post_result = post_channel.send(alert)
        self.assertTrue(post_result)
        
        # Verify POST request
        mock_post.assert_called_once()
        post_url = mock_post.call_args[0][0]
        post_json = mock_post.call_args[1]["json"]
        post_headers = mock_post.call_args[1]["headers"]
        
        self.assertEqual(post_url, "https://example.com/webhook")
        self.assertEqual(post_json["id"], "test-id")
        self.assertEqual(post_json["type"], "GATEWAY_CHANGE")
        self.assertEqual(post_headers["X-Api-Key"], "secret")
        
        # Send alert via PUT
        put_result = put_channel.send(alert)
        self.assertTrue(put_result)
        
        # Verify PUT request
        mock_put.assert_called_once()
        put_url = mock_put.call_args[0][0]
        put_json = mock_put.call_args[1]["json"]
        put_headers = mock_put.call_args[1]["headers"]
        
        self.assertEqual(put_url, "https://example.com/webhook")
        self.assertEqual(put_json["id"], "test-id")
        self.assertEqual(put_json["type"], "GATEWAY_CHANGE")
        self.assertEqual(put_headers["X-Api-Key"], "secret")


class TestConsoleChannel(unittest.TestCase):
    """Test ConsoleChannel"""
    
    @patch("builtins.print")
    def test_send_alert(self, mock_print):
        """Test sending alert to console"""
        # Create channel
        channel = ConsoleChannel(colored=False)
        
        # Create alert
        alert = Alert(
            id="test-id",
            type=AlertType.RATE_ANOMALY,
            priority=AlertPriority.CRITICAL,
            message="Test console alert",
            timestamp=time.time(),
            source="test",
            details={"rate": 1000, "threshold": 500}
        )
        
        # Send alert
        result = channel.send(alert)
        
        # Verify result
        self.assertTrue(result)
        
        # Verify print call
        mock_print.assert_called_once()
        printed_text = mock_print.call_args[0][0]
        
        # Check content
        self.assertIn("[CRITICAL] RATE_ANOMALY ALERT", printed_text)
        self.assertIn("test-id", printed_text)
        self.assertIn("Test console alert", printed_text)
        self.assertIn("rate: 1000", printed_text)
        self.assertIn("threshold: 500", printed_text)


if __name__ == "__main__":
    unittest.main() 