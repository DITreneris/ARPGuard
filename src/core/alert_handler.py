import logging
import time
from typing import Dict, Any, List, Callable, Optional
from threading import Thread, Event
from .alert import Alert, AlertType, AlertPriority, AlertManager
from .alert_config import AlertConfig

class AlertAction:
    """Base class for alert response actions."""
    
    def __init__(self, name: str):
        """
        Initialize action.
        
        Args:
            name: Action name
        """
        self.name = name
        self.logger = logging.getLogger(f'alert_action.{name}')
        
    def execute(self, alert: Alert) -> bool:
        """
        Execute the action for an alert.
        
        Args:
            alert: The alert to respond to
            
        Returns:
            True if action was executed successfully, False otherwise
        """
        raise NotImplementedError("Subclasses must implement execute()")


class LogAction(AlertAction):
    """Action to log alert details."""
    
    def __init__(self, log_path: str = "logs/alerts.log"):
        """
        Initialize logging action.
        
        Args:
            log_path: Path to log file
        """
        super().__init__("log_action")
        self.log_path = log_path
        
        # Create log directory if it doesn't exist
        import os
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        
    def execute(self, alert: Alert) -> bool:
        """Log alert details to file."""
        try:
            with open(self.log_path, 'a') as f:
                f.write(f"[{alert.timestamp}] {alert.priority.name} {alert.type.value}: {alert.message}\n")
                f.write(f"  Source: {alert.source}\n")
                f.write(f"  Details: {alert.details}\n")
                f.write("-" * 80 + "\n")
            return True
        except Exception as e:
            self.logger.error(f"Failed to log alert: {e}")
            return False


class BlockMacAction(AlertAction):
    """Action to block a MAC address."""
    
    def __init__(self, execute_command: Callable[[str], bool]):
        """
        Initialize block MAC action.
        
        Args:
            execute_command: Function to execute system commands
        """
        super().__init__("block_mac_action")
        self.execute_command = execute_command
        
    def execute(self, alert: Alert) -> bool:
        """Block MAC address involved in the alert."""
        try:
            if alert.type != AlertType.ARP_SPOOFING:
                self.logger.warning(f"BlockMacAction not applicable for {alert.type.value} alerts")
                return False
                
            mac_address = alert.details.get("mac_address")
            if not mac_address:
                self.logger.warning("No MAC address found in alert details")
                return False
                
            command = f"arpguard block {mac_address} --reason 'Automated block due to ARP spoofing alert {alert.id}'"
            success = self.execute_command(command)
            
            if success:
                self.logger.info(f"Blocked MAC address {mac_address}")
                return True
            else:
                self.logger.error(f"Failed to block MAC address {mac_address}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error in BlockMacAction: {e}")
            return False


class ThrottleAction(AlertAction):
    """Action to throttle network traffic."""
    
    def __init__(self, execute_command: Callable[[str], bool]):
        """
        Initialize throttle action.
        
        Args:
            execute_command: Function to execute system commands
        """
        super().__init__("throttle_action")
        self.execute_command = execute_command
        
    def execute(self, alert: Alert) -> bool:
        """Throttle traffic based on alert type."""
        try:
            if alert.type != AlertType.RATE_ANOMALY:
                self.logger.warning(f"ThrottleAction not applicable for {alert.type.value} alerts")
                return False
                
            # Get rate from alert details
            current_rate = alert.details.get("current_rate")
            if not current_rate:
                self.logger.warning("No rate information found in alert details")
                return False
                
            # Calculate throttle rate based on severity
            # For critical alerts, throttle to 30% of current rate
            # For high alerts, throttle to 50% of current rate
            # For medium alerts, throttle to 70% of current rate
            if alert.priority == AlertPriority.CRITICAL:
                throttle_rate = int(current_rate * 0.3)
            elif alert.priority == AlertPriority.HIGH:
                throttle_rate = int(current_rate * 0.5)
            else:
                throttle_rate = int(current_rate * 0.7)
                
            # Execute throttling command
            command = f"arpguard throttle {throttle_rate} --duration 300 --reason 'Automated throttle due to rate anomaly alert {alert.id}'"
            success = self.execute_command(command)
            
            if success:
                self.logger.info(f"Throttled traffic to {throttle_rate} packets/second for 5 minutes")
                return True
            else:
                self.logger.error("Failed to throttle traffic")
                return False
                
        except Exception as e:
            self.logger.error(f"Error in ThrottleAction: {e}")
            return False


class AlertRule:
    """Rule for matching alerts and executing actions."""
    
    def __init__(self, 
                rule_id: str,
                description: str,
                alert_types: List[AlertType],
                min_priority: AlertPriority = AlertPriority.LOW,
                conditions: Dict[str, Any] = None):
        """
        Initialize alert rule.
        
        Args:
            rule_id: Unique rule identifier
            description: Rule description
            alert_types: Types of alerts this rule applies to
            min_priority: Minimum priority level for this rule
            conditions: Additional conditions for matching
        """
        self.rule_id = rule_id
        self.description = description
        self.alert_types = alert_types
        self.min_priority = min_priority
        self.conditions = conditions or {}
        self.actions: List[AlertAction] = []
        self.logger = logging.getLogger(f'alert_rule.{rule_id}')
        
    def add_action(self, action: AlertAction) -> None:
        """
        Add an action to this rule.
        
        Args:
            action: Action to add
        """
        self.actions.append(action)
        
    def matches(self, alert: Alert) -> bool:
        """
        Check if an alert matches this rule.
        
        Args:
            alert: Alert to check
            
        Returns:
            True if alert matches rule, False otherwise
        """
        # Check alert type
        if alert.type not in self.alert_types:
            return False
            
        # Check priority
        priority_value = alert.priority.value
        min_priority_value = self.min_priority.value
        if priority_value < min_priority_value:
            return False
            
        # Check additional conditions
        if self.conditions:
            for key, value in self.conditions.items():
                if key == 'source':
                    if alert.source != value:
                        return False
                elif key.startswith('details.'):
                    # Check fields in the details dictionary
                    detail_key = key.split('.', 1)[1]
                    if detail_key not in alert.details or alert.details[detail_key] != value:
                        return False
                        
        return True
        
    def execute(self, alert: Alert) -> bool:
        """
        Execute all actions for this rule on an alert.
        
        Args:
            alert: Alert to execute actions for
            
        Returns:
            True if all actions succeeded, False otherwise
        """
        if not self.actions:
            self.logger.warning(f"No actions defined for rule {self.rule_id}")
            return False
            
        success = True
        for action in self.actions:
            try:
                action_result = action.execute(alert)
                if not action_result:
                    self.logger.warning(f"Action {action.name} failed for alert {alert.id}")
                    success = False
            except Exception as e:
                self.logger.error(f"Error executing action {action.name}: {e}")
                success = False
                
        return success


class AlertHandler:
    """Processes alerts and executes appropriate actions based on rules."""
    
    def __init__(self, alert_manager: AlertManager, config: AlertConfig = None):
        """
        Initialize alert handler.
        
        Args:
            alert_manager: Alert manager to get alerts from
            config: Optional alert configuration
        """
        self.alert_manager = alert_manager
        self.config = config
        self.rules: Dict[str, AlertRule] = {}
        self.logger = logging.getLogger('alert_handler')
        self.stop_event = Event()
        self.processing_thread = None
        self.processed_alerts: List[str] = []
        
    def add_rule(self, rule: AlertRule) -> None:
        """
        Add a rule to the handler.
        
        Args:
            rule: Rule to add
        """
        self.rules[rule.rule_id] = rule
        self.logger.info(f"Added rule: {rule.rule_id} - {rule.description}")
        
    def remove_rule(self, rule_id: str) -> None:
        """
        Remove a rule from the handler.
        
        Args:
            rule_id: ID of rule to remove
        """
        if rule_id in self.rules:
            del self.rules[rule_id]
            self.logger.info(f"Removed rule: {rule_id}")
        
    def execute_command(self, command: str) -> bool:
        """
        Execute a system command.
        
        Args:
            command: Command to execute
            
        Returns:
            True if command succeeded, False otherwise
        """
        try:
            import subprocess
            result = subprocess.run(command, shell=True, check=True, 
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.logger.debug(f"Command executed: {command}")
            return True
        except Exception as e:
            self.logger.error(f"Command failed: {command}, Error: {e}")
            return False
            
    def process_alert(self, alert: Alert) -> None:
        """
        Process an alert through all matching rules.
        
        Args:
            alert: Alert to process
        """
        if alert.id in self.processed_alerts:
            return
            
        self.logger.info(f"Processing alert: {alert.id}")
        matched = False
        
        for rule in self.rules.values():
            if rule.matches(alert):
                matched = True
                self.logger.info(f"Alert {alert.id} matches rule {rule.rule_id}")
                rule.execute(alert)
                
        if not matched:
            self.logger.info(f"No rules matched for alert {alert.id}")
            
        self.processed_alerts.append(alert.id)
        
        # Prevent the processed alerts list from growing too large
        if len(self.processed_alerts) > 1000:
            self.processed_alerts = self.processed_alerts[-500:]
            
    def start_processing(self, interval: int = 5) -> None:
        """
        Start processing alerts in a background thread.
        
        Args:
            interval: Polling interval in seconds
        """
        if self.processing_thread and self.processing_thread.is_alive():
            self.logger.warning("Alert processing thread is already running")
            return
            
        self.stop_event.clear()
        self.processing_thread = Thread(target=self._processing_loop, args=(interval,))
        self.processing_thread.daemon = True
        self.processing_thread.start()
        self.logger.info("Started alert processing thread")
        
    def stop_processing(self) -> None:
        """Stop processing alerts."""
        if self.processing_thread and self.processing_thread.is_alive():
            self.stop_event.set()
            self.processing_thread.join(timeout=10)
            self.logger.info("Stopped alert processing thread")
        
    def _processing_loop(self, interval: int) -> None:
        """
        Main processing loop.
        
        Args:
            interval: Polling interval in seconds
        """
        while not self.stop_event.is_set():
            try:
                # Get all active alerts
                active_alerts = self.alert_manager.get_active_alerts()
                
                # Process each alert
                for alert in active_alerts:
                    self.process_alert(alert)
                    
            except Exception as e:
                self.logger.error(f"Error in alert processing loop: {e}")
                
            # Wait for next interval
            self.stop_event.wait(interval)
            
    def create_default_rules(self) -> None:
        """Create default alert handling rules."""
        
        # Create actions
        log_action = LogAction()
        block_mac_action = BlockMacAction(self.execute_command)
        throttle_action = ThrottleAction(self.execute_command)
        
        # Rule 1: Log all alerts
        rule_log = AlertRule(
            rule_id="log_all_alerts",
            description="Log all alerts to file",
            alert_types=list(AlertType),
            min_priority=AlertPriority.LOW
        )
        rule_log.add_action(log_action)
        self.add_rule(rule_log)
        
        # Rule 2: Block MAC address for high priority ARP spoofing alerts
        rule_block = AlertRule(
            rule_id="block_arp_spoof",
            description="Block MAC addresses involved in ARP spoofing",
            alert_types=[AlertType.ARP_SPOOFING],
            min_priority=AlertPriority.HIGH
        )
        rule_block.add_action(block_mac_action)
        self.add_rule(rule_block)
        
        # Rule 3: Throttle traffic for high rate anomalies
        rule_throttle = AlertRule(
            rule_id="throttle_rate_anomaly",
            description="Throttle traffic during high rate anomalies",
            alert_types=[AlertType.RATE_ANOMALY],
            min_priority=AlertPriority.HIGH
        )
        rule_throttle.add_action(throttle_action)
        self.add_rule(rule_throttle)
        
        self.logger.info("Created default alert handling rules") 