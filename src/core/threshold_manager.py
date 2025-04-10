import time
import logging
import threading
from typing import Dict, List, Optional, Any, Tuple

from src.core.rate_monitor import TrafficRateMonitor
from src.core.rate_analysis import RateAnalyzer, AdaptiveThresholdManager

logger = logging.getLogger(__name__)

class ThresholdRule:
    """Represents a rule for threshold violations and actions."""
    
    def __init__(self, name: str, detector_name: str, threshold_type: str, 
                 action: str, duration: int = 0, cooldown: int = 300,
                 condition: str = ">="):
        """
        Initialize a threshold rule.
        
        Args:
            name: Rule name
            detector_name: Name of the detector this rule applies to
            threshold_type: Type of threshold ('high_rate', 'critical_rate', etc.)
            action: Action to take when rule is triggered
            duration: Duration in seconds that condition must be met
            cooldown: Cooldown period in seconds before rule can be triggered again
            condition: Comparison operator (>=, >, ==, etc.)
        """
        self.name = name
        self.detector_name = detector_name
        self.threshold_type = threshold_type
        self.action = action
        self.duration = duration
        self.cooldown = cooldown
        self.condition = condition
        self.last_triggered = 0
        self.violation_start = 0
        self.is_active = False
        
    def check_condition(self, value: float, threshold: float) -> bool:
        """Check if the condition is met between value and threshold."""
        if self.condition == ">=":
            return value >= threshold
        elif self.condition == ">":
            return value > threshold
        elif self.condition == "==":
            return value == threshold
        elif self.condition == "<=":
            return value <= threshold
        elif self.condition == "<":
            return value < threshold
        else:
            return False
            
    def check_violation(self, value: float, threshold: float, current_time: float) -> bool:
        """
        Check if the rule has been violated.
        
        Args:
            value: Current value to check against threshold
            threshold: Threshold value
            current_time: Current timestamp
            
        Returns:
            bool: Whether the rule has been violated and should trigger an action
        """
        # Check if rule is in cooldown
        if current_time - self.last_triggered < self.cooldown:
            return False
            
        # Check if condition is met
        if self.check_condition(value, threshold):
            # If not already tracking a violation, start now
            if not self.is_active:
                self.violation_start = current_time
                self.is_active = True
                
            # Check if violation has lasted long enough
            if current_time - self.violation_start >= self.duration:
                self.last_triggered = current_time
                self.is_active = False
                return True
        else:
            # Reset violation tracking
            self.is_active = False
            
        return False
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary for serialization."""
        return {
            "name": self.name,
            "detector_name": self.detector_name,
            "threshold_type": self.threshold_type,
            "action": self.action,
            "duration": self.duration,
            "cooldown": self.cooldown,
            "condition": self.condition,
            "last_triggered": self.last_triggered,
            "is_active": self.is_active
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThresholdRule':
        """Create rule from dictionary."""
        rule = cls(
            name=data["name"],
            detector_name=data["detector_name"],
            threshold_type=data["threshold_type"],
            action=data["action"],
            duration=data["duration"],
            cooldown=data["cooldown"],
            condition=data["condition"]
        )
        rule.last_triggered = data.get("last_triggered", 0)
        rule.is_active = data.get("is_active", False)
        return rule


class ActionHandler:
    """Base class for handling actions when rules are triggered."""
    
    def execute(self, rule: ThresholdRule, context: Dict[str, Any]) -> bool:
        """
        Execute the action for a triggered rule.
        
        Args:
            rule: The rule that was triggered
            context: Additional context for the action
            
        Returns:
            bool: Whether the action was executed successfully
        """
        raise NotImplementedError("Subclasses must implement execute()")


class LogActionHandler(ActionHandler):
    """Action handler that logs rule violations."""
    
    def execute(self, rule: ThresholdRule, context: Dict[str, Any]) -> bool:
        """Log the rule violation."""
        logger.warning(
            f"Rule '{rule.name}' triggered for detector '{rule.detector_name}': "
            f"{context.get('value', 'unknown')} {rule.condition} "
            f"{context.get('threshold', 'unknown')} "
            f"[{rule.threshold_type}]"
        )
        return True


class AlertActionHandler(ActionHandler):
    """Action handler that creates alerts for rule violations."""
    
    def __init__(self, alert_manager=None):
        """Initialize with an alert manager."""
        self.alert_manager = alert_manager
        
    def execute(self, rule: ThresholdRule, context: Dict[str, Any]) -> bool:
        """Create an alert for the rule violation."""
        if not self.alert_manager:
            logger.error("Alert action handler has no alert manager")
            return False
            
        try:
            self.alert_manager.create_alert(
                alert_type="threshold_violation",
                priority="high",
                message=f"Threshold violation: {rule.name}",
                source=f"detector:{rule.detector_name}",
                details={
                    "rule": rule.to_dict(),
                    "value": context.get("value"),
                    "threshold": context.get("threshold"),
                    "detector_status": context.get("detector_status", {})
                }
            )
            return True
        except Exception as e:
            logger.error(f"Failed to create alert for rule '{rule.name}': {e}")
            return False


class CommandActionHandler(ActionHandler):
    """Action handler that executes commands for rule violations."""
    
    def __init__(self, command_executor=None):
        """Initialize with a command executor."""
        self.command_executor = command_executor
        
    def execute(self, rule: ThresholdRule, context: Dict[str, Any]) -> bool:
        """Execute a command for the rule violation."""
        if not self.command_executor:
            logger.error("Command action handler has no command executor")
            return False
            
        try:
            # The action field contains the command to execute
            self.command_executor.execute(
                rule.action,
                context=context
            )
            return True
        except Exception as e:
            logger.error(f"Failed to execute command for rule '{rule.name}': {e}")
            return False


class ThresholdManager:
    """Manages thresholds, rules, and actions for rate monitoring."""
    
    def __init__(self, 
                 rate_monitor: TrafficRateMonitor, 
                 rate_analyzer: RateAnalyzer,
                 check_interval: int = 5):
        """
        Initialize the threshold manager.
        
        Args:
            rate_monitor: The rate monitor to get values from
            rate_analyzer: The rate analyzer to get thresholds from
            check_interval: How often to check thresholds (seconds)
        """
        self.rate_monitor = rate_monitor
        self.rate_analyzer = rate_analyzer
        self.check_interval = check_interval
        
        # Create adaptive threshold manager
        self.adaptive_manager = AdaptiveThresholdManager(
            rate_monitor, rate_analyzer
        )
        
        # Initialize rules and action handlers
        self.rules: List[ThresholdRule] = []
        self.action_handlers: Dict[str, ActionHandler] = {}
        
        # Initialize default action handlers
        self.action_handlers["log"] = LogActionHandler()
        
        # Thread control
        self.running = False
        self.thread = None
    
    def add_rule(self, rule: ThresholdRule) -> None:
        """Add a rule to the manager."""
        self.rules.append(rule)
        logger.info(f"Added rule '{rule.name}' for detector '{rule.detector_name}'")
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove a rule by name."""
        for i, rule in enumerate(self.rules):
            if rule.name == rule_name:
                self.rules.pop(i)
                logger.info(f"Removed rule '{rule_name}'")
                return True
        logger.warning(f"Rule '{rule_name}' not found")
        return False
    
    def get_rule(self, rule_name: str) -> Optional[ThresholdRule]:
        """Get a rule by name."""
        for rule in self.rules:
            if rule.name == rule_name:
                return rule
        return None
    
    def register_action_handler(self, action_type: str, handler: ActionHandler) -> None:
        """Register an action handler for a specific action type."""
        self.action_handlers[action_type] = handler
        logger.info(f"Registered action handler for '{action_type}'")
    
    def check_thresholds(self) -> List[Tuple[ThresholdRule, Dict[str, Any]]]:
        """
        Check all rules against current values and thresholds.
        
        Returns:
            List of tuples (rule, context) for triggered rules
        """
        triggered_rules = []
        current_time = time.time()
        
        # Get current status from rate monitor
        monitor_status = self.rate_monitor.get_status()
        
        # Get current thresholds from rate analyzer
        analyzer_results = {
            detector: self.rate_analyzer.analyze_detector(detector)
            for detector in monitor_status.keys()
        }
        
        # Check each rule
        for rule in self.rules:
            detector_name = rule.detector_name
            
            # Skip if detector not found
            if detector_name not in monitor_status:
                continue
                
            # Get current value and threshold
            detector_status = monitor_status[detector_name].get("detector_status", {})
            stats = detector_status.get("stats", {})
            current_value = stats.get("current", 0)
            
            # Get threshold value
            detector_results = analyzer_results.get(detector_name, {})
            threshold_value = detector_results.get(rule.threshold_type, 0)
            
            # Check if rule is violated
            if rule.check_violation(current_value, threshold_value, current_time):
                # Rule triggered
                context = {
                    "value": current_value,
                    "threshold": threshold_value,
                    "detector_status": detector_status,
                    "analyzer_results": detector_results
                }
                triggered_rules.append((rule, context))
                logger.debug(
                    f"Rule '{rule.name}' triggered: {current_value} {rule.condition} "
                    f"{threshold_value} [{rule.threshold_type}]"
                )
                
        return triggered_rules
    
    def execute_actions(self, triggered_rules: List[Tuple[ThresholdRule, Dict[str, Any]]]) -> None:
        """Execute actions for triggered rules."""
        for rule, context in triggered_rules:
            action_type = rule.action.split(':')[0] if ':' in rule.action else rule.action
            
            # Get action handler
            handler = self.action_handlers.get(action_type)
            if not handler:
                logger.warning(f"No handler for action type '{action_type}'")
                continue
                
            # Execute action
            handler.execute(rule, context)
    
    def run_once(self) -> None:
        """Run a single check cycle."""
        try:
            # Update analyzer from monitor
            self.rate_analyzer.update_from_monitor()
            
            # Check thresholds and execute actions
            triggered_rules = self.check_thresholds()
            self.execute_actions(triggered_rules)
        except Exception as e:
            logger.error(f"Error in threshold check cycle: {e}")
    
    def run(self) -> None:
        """Run the threshold checker thread."""
        while self.running:
            self.run_once()
            time.sleep(self.check_interval)
    
    def start(self) -> None:
        """Start the threshold manager."""
        if self.running:
            logger.warning("Threshold manager already running")
            return
            
        # Start adaptive threshold manager
        self.adaptive_manager.start()
        
        # Start threshold checker thread
        self.running = True
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        logger.info("Threshold manager started")
    
    def stop(self) -> None:
        """Stop the threshold manager."""
        if not self.running:
            logger.warning("Threshold manager not running")
            return
            
        # Stop adaptive threshold manager
        self.adaptive_manager.stop()
        
        # Stop threshold checker thread
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
            self.thread = None
        logger.info("Threshold manager stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """Get status of the threshold manager."""
        return {
            "running": self.running,
            "check_interval": self.check_interval,
            "rules_count": len(self.rules),
            "rules": [rule.to_dict() for rule in self.rules],
            "adaptive_manager": self.adaptive_manager.get_status()
        }
    
    def create_default_rules(self) -> None:
        """Create default threshold rules."""
        # High rate rule for each detector
        for detector_name in self.rate_monitor.detectors.keys():
            # High rate rule
            self.add_rule(ThresholdRule(
                name=f"{detector_name}_high_rate",
                detector_name=detector_name,
                threshold_type="high_rate",
                action="log",
                duration=5,
                cooldown=60,
                condition=">="
            ))
            
            # Critical rate rule
            self.add_rule(ThresholdRule(
                name=f"{detector_name}_critical_rate",
                detector_name=detector_name,
                threshold_type="critical_rate",
                action="alert:high",
                duration=2,
                cooldown=120,
                condition=">="
            ))
            
            # Sustained high rate rule
            self.add_rule(ThresholdRule(
                name=f"{detector_name}_sustained_high",
                detector_name=detector_name,
                threshold_type="high_rate",
                action="alert:medium",
                duration=60,
                cooldown=300,
                condition=">="
            ))
            
            # Low rate rule (could indicate network outage)
            self.add_rule(ThresholdRule(
                name=f"{detector_name}_low_rate",
                detector_name=detector_name,
                threshold_type="low_rate",
                action="log",
                duration=30,
                cooldown=600,
                condition="<="
            )) 