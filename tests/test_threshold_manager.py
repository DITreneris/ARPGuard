import unittest
from unittest.mock import MagicMock, patch
import time

from src.core.threshold_manager import (
    ThresholdRule, 
    LogActionHandler, 
    AlertActionHandler, 
    CommandActionHandler, 
    ThresholdManager
)


class TestThresholdRule(unittest.TestCase):
    """Tests for ThresholdRule class."""
    
    def test_init(self):
        """Test initialization of ThresholdRule."""
        rule = ThresholdRule(
            name="test_rule",
            detector_name="arp_detector",
            threshold_type="high_rate",
            action="log",
            duration=10,
            cooldown=60,
            condition=">="
        )
        
        # Verify attributes
        self.assertEqual(rule.name, "test_rule")
        self.assertEqual(rule.detector_name, "arp_detector")
        self.assertEqual(rule.threshold_type, "high_rate")
        self.assertEqual(rule.action, "log")
        self.assertEqual(rule.duration, 10)
        self.assertEqual(rule.cooldown, 60)
        self.assertEqual(rule.condition, ">=")
        self.assertEqual(rule.last_triggered, 0)
        self.assertEqual(rule.violation_start, 0)
        self.assertFalse(rule.is_active)
    
    def test_check_condition(self):
        """Test check_condition method."""
        # Test >= condition
        rule = ThresholdRule("test", "test", "test", "test", condition=">=")
        self.assertTrue(rule.check_condition(10, 5))
        self.assertTrue(rule.check_condition(5, 5))
        self.assertFalse(rule.check_condition(4, 5))
        
        # Test > condition
        rule = ThresholdRule("test", "test", "test", "test", condition=">")
        self.assertTrue(rule.check_condition(10, 5))
        self.assertFalse(rule.check_condition(5, 5))
        self.assertFalse(rule.check_condition(4, 5))
        
        # Test == condition
        rule = ThresholdRule("test", "test", "test", "test", condition="==")
        self.assertFalse(rule.check_condition(10, 5))
        self.assertTrue(rule.check_condition(5, 5))
        self.assertFalse(rule.check_condition(4, 5))
        
        # Test <= condition
        rule = ThresholdRule("test", "test", "test", "test", condition="<=")
        self.assertFalse(rule.check_condition(10, 5))
        self.assertTrue(rule.check_condition(5, 5))
        self.assertTrue(rule.check_condition(4, 5))
        
        # Test < condition
        rule = ThresholdRule("test", "test", "test", "test", condition="<")
        self.assertFalse(rule.check_condition(10, 5))
        self.assertFalse(rule.check_condition(5, 5))
        self.assertTrue(rule.check_condition(4, 5))
    
    def test_check_violation_cooldown(self):
        """Test check_violation method respects cooldown."""
        rule = ThresholdRule(
            "test", "test", "test", "test", duration=0, cooldown=60
        )
        
        # Set last_triggered to current time
        current_time = time.time()
        rule.last_triggered = current_time
        
        # Check violation should return False during cooldown
        self.assertFalse(rule.check_violation(10, 5, current_time + 30))
        
        # Check violation should return True after cooldown
        self.assertTrue(rule.check_violation(10, 5, current_time + 61))
    
    def test_check_violation_duration(self):
        """Test check_violation method requires condition to be met for duration."""
        rule = ThresholdRule(
            "test", "test", "test", "test", duration=5, cooldown=0
        )
        
        # Start time for test
        start_time = time.time()
        
        # Should start tracking but not trigger immediately
        self.assertFalse(rule.check_violation(10, 5, start_time))
        self.assertTrue(rule.is_active)
        self.assertEqual(rule.violation_start, start_time)
        
        # Still not long enough
        self.assertFalse(rule.check_violation(10, 5, start_time + 3))
        self.assertTrue(rule.is_active)
        
        # Now long enough to trigger
        self.assertTrue(rule.check_violation(10, 5, start_time + 5))
        self.assertFalse(rule.is_active)  # Reset after triggering
        
        # Check that last_triggered was updated
        self.assertEqual(rule.last_triggered, start_time + 5)
    
    def test_check_violation_reset(self):
        """Test check_violation resets tracking when condition not met."""
        rule = ThresholdRule(
            "test", "test", "test", "test", duration=5, cooldown=0
        )
        
        # Start time for test
        start_time = time.time()
        
        # Should start tracking
        self.assertFalse(rule.check_violation(10, 5, start_time))
        self.assertTrue(rule.is_active)
        
        # Condition no longer met, should reset
        self.assertFalse(rule.check_violation(4, 5, start_time + 3))
        self.assertFalse(rule.is_active)
    
    def test_serialization(self):
        """Test to_dict and from_dict methods."""
        rule = ThresholdRule(
            name="test_rule",
            detector_name="arp_detector",
            threshold_type="high_rate",
            action="log",
            duration=10,
            cooldown=60,
            condition=">="
        )
        
        # Set some values that would normally be set during operation
        rule.last_triggered = 12345
        rule.is_active = True
        
        # Convert to dict
        rule_dict = rule.to_dict()
        
        # Check dict values
        self.assertEqual(rule_dict["name"], "test_rule")
        self.assertEqual(rule_dict["detector_name"], "arp_detector")
        self.assertEqual(rule_dict["threshold_type"], "high_rate")
        self.assertEqual(rule_dict["action"], "log")
        self.assertEqual(rule_dict["duration"], 10)
        self.assertEqual(rule_dict["cooldown"], 60)
        self.assertEqual(rule_dict["condition"], ">=")
        self.assertEqual(rule_dict["last_triggered"], 12345)
        self.assertEqual(rule_dict["is_active"], True)
        
        # Create new rule from dict
        new_rule = ThresholdRule.from_dict(rule_dict)
        
        # Check attributes
        self.assertEqual(new_rule.name, "test_rule")
        self.assertEqual(new_rule.detector_name, "arp_detector")
        self.assertEqual(new_rule.threshold_type, "high_rate")
        self.assertEqual(new_rule.action, "log")
        self.assertEqual(new_rule.duration, 10)
        self.assertEqual(new_rule.cooldown, 60)
        self.assertEqual(new_rule.condition, ">=")
        self.assertEqual(new_rule.last_triggered, 12345)
        self.assertEqual(new_rule.is_active, True)


class TestActionHandlers(unittest.TestCase):
    """Tests for action handler classes."""
    
    @patch('src.core.threshold_manager.logger')
    def test_log_action_handler(self, mock_logger):
        """Test LogActionHandler."""
        handler = LogActionHandler()
        rule = ThresholdRule("test", "detector", "high_rate", "log")
        context = {"value": 100, "threshold": 50}
        
        # Execute action
        result = handler.execute(rule, context)
        
        # Check result
        self.assertTrue(result)
        
        # Check that logger was called
        mock_logger.warning.assert_called_once()
    
    def test_alert_action_handler_no_manager(self):
        """Test AlertActionHandler with no alert manager."""
        handler = AlertActionHandler()
        rule = ThresholdRule("test", "detector", "high_rate", "alert")
        context = {"value": 100, "threshold": 50}
        
        # Execute action
        with patch('src.core.threshold_manager.logger') as mock_logger:
            result = handler.execute(rule, context)
        
        # Check result
        self.assertFalse(result)
        mock_logger.error.assert_called_once()
    
    def test_alert_action_handler_with_manager(self):
        """Test AlertActionHandler with alert manager."""
        # Create mock alert manager
        mock_alert_manager = MagicMock()
        
        handler = AlertActionHandler(mock_alert_manager)
        rule = ThresholdRule("test", "detector", "high_rate", "alert")
        context = {"value": 100, "threshold": 50}
        
        # Execute action
        result = handler.execute(rule, context)
        
        # Check result
        self.assertTrue(result)
        
        # Check that alert manager was called
        mock_alert_manager.create_alert.assert_called_once()
    
    def test_command_action_handler_no_executor(self):
        """Test CommandActionHandler with no command executor."""
        handler = CommandActionHandler()
        rule = ThresholdRule("test", "detector", "high_rate", "command")
        context = {"value": 100, "threshold": 50}
        
        # Execute action
        with patch('src.core.threshold_manager.logger') as mock_logger:
            result = handler.execute(rule, context)
        
        # Check result
        self.assertFalse(result)
        mock_logger.error.assert_called_once()
    
    def test_command_action_handler_with_executor(self):
        """Test CommandActionHandler with command executor."""
        # Create mock command executor
        mock_executor = MagicMock()
        
        handler = CommandActionHandler(mock_executor)
        rule = ThresholdRule("test", "detector", "high_rate", "command:test")
        context = {"value": 100, "threshold": 50}
        
        # Execute action
        result = handler.execute(rule, context)
        
        # Check result
        self.assertTrue(result)
        
        # Check that command executor was called
        mock_executor.execute.assert_called_once()


class TestThresholdManager(unittest.TestCase):
    """Tests for ThresholdManager class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create mock objects
        self.mock_rate_monitor = MagicMock()
        self.mock_rate_analyzer = MagicMock()
        
        # Create threshold manager
        self.manager = ThresholdManager(
            self.mock_rate_monitor,
            self.mock_rate_analyzer,
            check_interval=1
        )
        
        # Add some test rules
        self.rule1 = ThresholdRule(
            name="test_rule1",
            detector_name="detector1",
            threshold_type="high_rate",
            action="log",
            duration=0,
            cooldown=0
        )
        self.rule2 = ThresholdRule(
            name="test_rule2",
            detector_name="detector2",
            threshold_type="critical_rate",
            action="alert:high",
            duration=0,
            cooldown=0
        )
        
        self.manager.add_rule(self.rule1)
        self.manager.add_rule(self.rule2)
    
    def test_add_remove_get_rule(self):
        """Test add_rule, remove_rule, and get_rule methods."""
        # Check rules were added in setUp
        self.assertEqual(len(self.manager.rules), 2)
        
        # Get rule by name
        rule = self.manager.get_rule("test_rule1")
        self.assertEqual(rule, self.rule1)
        
        # Get non-existent rule
        rule = self.manager.get_rule("non_existent")
        self.assertIsNone(rule)
        
        # Remove rule
        result = self.manager.remove_rule("test_rule1")
        self.assertTrue(result)
        self.assertEqual(len(self.manager.rules), 1)
        
        # Try to remove non-existent rule
        result = self.manager.remove_rule("non_existent")
        self.assertFalse(result)
        self.assertEqual(len(self.manager.rules), 1)
    
    def test_register_action_handler(self):
        """Test register_action_handler method."""
        # Create mock action handler
        mock_handler = MagicMock()
        
        # Register handler
        self.manager.register_action_handler("test_action", mock_handler)
        
        # Check handler was registered
        self.assertEqual(self.manager.action_handlers["test_action"], mock_handler)
    
    def test_check_thresholds(self):
        """Test check_thresholds method."""
        # Set up mock rate monitor
        self.mock_rate_monitor.get_status.return_value = {
            "detector1": {
                "detector_status": {"stats": {"current": 100}}
            },
            "detector2": {
                "detector_status": {"stats": {"current": 200}}
            }
        }
        
        # Set up mock rate analyzer
        self.mock_rate_analyzer.analyze_detector.side_effect = lambda detector: {
            "high_rate": 50,
            "critical_rate": 150
        }
        
        # Check thresholds
        triggered_rules = self.manager.check_thresholds()
        
        # Should have two triggered rules
        self.assertEqual(len(triggered_rules), 2)
        
        # Verify rule1 triggered
        rule, context = triggered_rules[0]
        self.assertEqual(rule, self.rule1)
        self.assertEqual(context["value"], 100)
        self.assertEqual(context["threshold"], 50)
        
        # Verify rule2 triggered
        rule, context = triggered_rules[1]
        self.assertEqual(rule, self.rule2)
        self.assertEqual(context["value"], 200)
        self.assertEqual(context["threshold"], 150)
    
    def test_execute_actions(self):
        """Test execute_actions method."""
        # Create mock action handlers
        mock_log_handler = MagicMock()
        mock_alert_handler = MagicMock()
        
        # Register handlers
        self.manager.action_handlers["log"] = mock_log_handler
        self.manager.action_handlers["alert"] = mock_alert_handler
        
        # Create triggered rules
        rule1 = ThresholdRule("test1", "detector1", "high_rate", "log")
        rule2 = ThresholdRule("test2", "detector2", "critical_rate", "alert:high")
        
        triggered_rules = [
            (rule1, {"value": 100, "threshold": 50}),
            (rule2, {"value": 200, "threshold": 150})
        ]
        
        # Execute actions
        self.manager.execute_actions(triggered_rules)
        
        # Check that handlers were called
        mock_log_handler.execute.assert_called_once()
        mock_alert_handler.execute.assert_called_once()
    
    @patch('src.core.threshold_manager.threading.Thread')
    def test_start_stop(self, mock_thread):
        """Test start and stop methods."""
        # Mock adaptive_manager methods
        self.manager.adaptive_manager.start = MagicMock()
        self.manager.adaptive_manager.stop = MagicMock()
        
        # Start threshold manager
        self.manager.start()
        
        # Check state
        self.assertTrue(self.manager.running)
        self.assertEqual(self.manager.thread, mock_thread.return_value)
        mock_thread.assert_called_once_with(target=self.manager.run, daemon=True)
        mock_thread.return_value.start.assert_called_once()
        self.manager.adaptive_manager.start.assert_called_once()
        
        # Stop threshold manager
        self.manager.stop()
        
        # Check state
        self.assertFalse(self.manager.running)
        mock_thread.return_value.join.assert_called_once_with(timeout=2)
        self.manager.adaptive_manager.stop.assert_called_once()
    
    def test_run_once(self):
        """Test run_once method."""
        # Mock methods
        self.manager.rate_analyzer.update_from_monitor = MagicMock()
        self.manager.check_thresholds = MagicMock(return_value=[])
        self.manager.execute_actions = MagicMock()
        
        # Run once
        self.manager.run_once()
        
        # Check that methods were called
        self.manager.rate_analyzer.update_from_monitor.assert_called_once()
        self.manager.check_thresholds.assert_called_once()
        self.manager.execute_actions.assert_called_once_with([])
    
    def test_get_status(self):
        """Test get_status method."""
        # Mock adaptive_manager.get_status
        self.manager.adaptive_manager.get_status = MagicMock(return_value={"running": True})
        
        # Get status
        status = self.manager.get_status()
        
        # Check status
        self.assertFalse(status["running"])
        self.assertEqual(status["check_interval"], 1)
        self.assertEqual(status["rules_count"], 2)
        self.assertEqual(len(status["rules"]), 2)
        self.assertEqual(status["adaptive_manager"], {"running": True})
    
    def test_create_default_rules(self):
        """Test create_default_rules method."""
        # Reset rules
        self.manager.rules = []
        
        # Mock rate_monitor.detectors
        self.mock_rate_monitor.detectors = {"detector1": MagicMock(), "detector2": MagicMock()}
        
        # Create default rules
        self.manager.create_default_rules()
        
        # Should have 4 rules per detector = 8 total
        self.assertEqual(len(self.manager.rules), 8)
        
        # Check rule names
        rule_names = [rule.name for rule in self.manager.rules]
        expected_names = [
            "detector1_high_rate", "detector1_critical_rate", 
            "detector1_sustained_high", "detector1_low_rate",
            "detector2_high_rate", "detector2_critical_rate", 
            "detector2_sustained_high", "detector2_low_rate"
        ]
        
        for name in expected_names:
            self.assertIn(name, rule_names)


if __name__ == "__main__":
    unittest.main() 