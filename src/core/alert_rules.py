from typing import Dict, Any, List
from .alert import AlertType, AlertPriority
from .alert_handler import AlertRule, AlertAction, LogAction, BlockMacAction, ThrottleAction

class RuleLibrary:
    """Library of predefined alert rules."""
    
    @staticmethod
    def get_all_rules(execute_command_func) -> Dict[str, AlertRule]:
        """
        Get all predefined rules.
        
        Args:
            execute_command_func: Function for executing system commands
            
        Returns:
            Dictionary of rule_id to AlertRule
        """
        rules = {}
        
        # Add basic rules
        basic_rules = RuleLibrary.get_basic_rules(execute_command_func)
        rules.update(basic_rules)
        
        # Add ARP spoofing rules
        arp_rules = RuleLibrary.get_arp_spoofing_rules(execute_command_func)
        rules.update(arp_rules)
        
        # Add rate anomaly rules
        rate_rules = RuleLibrary.get_rate_anomaly_rules(execute_command_func)
        rules.update(rate_rules)
        
        # Add pattern match rules
        pattern_rules = RuleLibrary.get_pattern_match_rules(execute_command_func)
        rules.update(pattern_rules)
        
        return rules
        
    @staticmethod
    def get_basic_rules(execute_command_func) -> Dict[str, AlertRule]:
        """Get basic alert rules that apply to all alert types."""
        rules = {}
        
        # Common actions
        log_action = LogAction()
        
        # Rule: Log all alerts
        rule_log_all = AlertRule(
            rule_id="log_all_alerts",
            description="Log all alerts to file",
            alert_types=list(AlertType),
            min_priority=AlertPriority.LOW
        )
        rule_log_all.add_action(log_action)
        rules[rule_log_all.rule_id] = rule_log_all
        
        # Rule: Log critical alerts with special format
        rule_log_critical = AlertRule(
            rule_id="log_critical_alerts",
            description="Log critical alerts with special format",
            alert_types=list(AlertType),
            min_priority=AlertPriority.CRITICAL
        )
        # Using custom log path for critical alerts
        log_critical_action = LogAction(log_path="logs/critical_alerts.log")
        rule_log_critical.add_action(log_critical_action)
        rules[rule_log_critical.rule_id] = rule_log_critical
        
        return rules
        
    @staticmethod
    def get_arp_spoofing_rules(execute_command_func) -> Dict[str, AlertRule]:
        """Get rules specific to ARP spoofing detection."""
        rules = {}
        
        # Actions
        log_action = LogAction()
        block_mac_action = BlockMacAction(execute_command_func)
        
        # Rule: Block MAC for ARP spoofing (high priority)
        rule_block_arp_high = AlertRule(
            rule_id="block_arp_spoof_high",
            description="Block MAC addresses involved in high priority ARP spoofing",
            alert_types=[AlertType.ARP_SPOOFING],
            min_priority=AlertPriority.HIGH
        )
        rule_block_arp_high.add_action(log_action)
        rule_block_arp_high.add_action(block_mac_action)
        rules[rule_block_arp_high.rule_id] = rule_block_arp_high
        
        # Rule: Detect multiple IPs for same MAC
        rule_detect_multi_ip = AlertRule(
            rule_id="detect_multi_ip_mac",
            description="Detect when a MAC address is associated with multiple IPs",
            alert_types=[AlertType.ARP_SPOOFING],
            min_priority=AlertPriority.MEDIUM,
            conditions={"details.mac_changes": True}
        )
        rule_detect_multi_ip.add_action(log_action)
        rules[rule_detect_multi_ip.rule_id] = rule_detect_multi_ip
        
        # Rule: Gateway ARP spoofing (critical)
        rule_gateway_spoof = AlertRule(
            rule_id="gateway_arp_spoof",
            description="Detect and block ARP spoofing targeting the gateway",
            alert_types=[AlertType.ARP_SPOOFING],
            min_priority=AlertPriority.CRITICAL,
            conditions={"details.is_gateway": True}
        )
        rule_gateway_spoof.add_action(log_action)
        rule_gateway_spoof.add_action(block_mac_action)
        rules[rule_gateway_spoof.rule_id] = rule_gateway_spoof
        
        return rules
        
    @staticmethod
    def get_rate_anomaly_rules(execute_command_func) -> Dict[str, AlertRule]:
        """Get rules specific to rate anomaly detection."""
        rules = {}
        
        # Actions
        log_action = LogAction()
        throttle_action = ThrottleAction(execute_command_func)
        
        # Rule: Throttle traffic for high rate anomalies
        rule_throttle_high = AlertRule(
            rule_id="throttle_rate_high",
            description="Throttle traffic during high rate anomalies",
            alert_types=[AlertType.RATE_ANOMALY],
            min_priority=AlertPriority.HIGH
        )
        rule_throttle_high.add_action(log_action)
        rule_throttle_high.add_action(throttle_action)
        rules[rule_throttle_high.rule_id] = rule_throttle_high
        
        # Rule: Super high rate anomalies (critical)
        rule_critical_rate = AlertRule(
            rule_id="critical_rate_anomaly",
            description="Handle critical rate anomalies",
            alert_types=[AlertType.RATE_ANOMALY],
            min_priority=AlertPriority.CRITICAL
        )
        rule_critical_rate.add_action(log_action)
        rule_critical_rate.add_action(throttle_action)
        # Could add additional actions for critical rate anomalies
        rules[rule_critical_rate.rule_id] = rule_critical_rate
        
        # Rule: Sustained rate anomalies
        rule_sustained_rate = AlertRule(
            rule_id="sustained_rate_anomaly",
            description="Handle sustained rate anomalies",
            alert_types=[AlertType.RATE_ANOMALY],
            min_priority=AlertPriority.MEDIUM,
            conditions={"details.sustained": True}
        )
        rule_sustained_rate.add_action(log_action)
        rule_sustained_rate.add_action(throttle_action)
        rules[rule_sustained_rate.rule_id] = rule_sustained_rate
        
        return rules
        
    @staticmethod
    def get_pattern_match_rules(execute_command_func) -> Dict[str, AlertRule]:
        """Get rules specific to pattern matching."""
        rules = {}
        
        # Actions
        log_action = LogAction()
        
        # Rule: Known attack patterns
        rule_known_attack = AlertRule(
            rule_id="known_attack_pattern",
            description="Handle known attack patterns",
            alert_types=[AlertType.PATTERN_MATCH],
            min_priority=AlertPriority.HIGH,
            conditions={"details.pattern_type": "known_attack"}
        )
        rule_known_attack.add_action(log_action)
        # Could add more actions for known attacks
        rules[rule_known_attack.rule_id] = rule_known_attack
        
        # Rule: Suspicious behavior patterns
        rule_suspicious = AlertRule(
            rule_id="suspicious_behavior",
            description="Handle suspicious behavior patterns",
            alert_types=[AlertType.PATTERN_MATCH],
            min_priority=AlertPriority.MEDIUM,
            conditions={"details.pattern_type": "suspicious"}
        )
        rule_suspicious.add_action(log_action)
        rules[rule_suspicious.rule_id] = rule_suspicious
        
        return rules


class CustomRuleBuilder:
    """Helper class to build custom alert rules."""
    
    def __init__(self, execute_command_func):
        """
        Initialize rule builder.
        
        Args:
            execute_command_func: Function for executing system commands
        """
        self.execute_command_func = execute_command_func
        
    def create_rule(self, 
                   rule_id: str,
                   description: str,
                   alert_types: List[AlertType],
                   min_priority: AlertPriority = AlertPriority.LOW,
                   conditions: Dict[str, Any] = None,
                   log_enabled: bool = True,
                   block_mac_enabled: bool = False,
                   throttle_enabled: bool = False,
                   log_path: str = None) -> AlertRule:
        """
        Create a custom alert rule.
        
        Args:
            rule_id: Unique rule identifier
            description: Rule description
            alert_types: Types of alerts this rule applies to
            min_priority: Minimum priority level for this rule
            conditions: Additional conditions for matching
            log_enabled: Whether to enable logging action
            block_mac_enabled: Whether to enable MAC blocking action
            throttle_enabled: Whether to enable throttling action
            log_path: Custom log path for logging action
            
        Returns:
            Created alert rule
        """
        rule = AlertRule(
            rule_id=rule_id,
            description=description,
            alert_types=alert_types,
            min_priority=min_priority,
            conditions=conditions
        )
        
        # Add actions based on flags
        if log_enabled:
            log_action = LogAction(log_path=log_path) if log_path else LogAction()
            rule.add_action(log_action)
            
        if block_mac_enabled:
            block_action = BlockMacAction(self.execute_command_func)
            rule.add_action(block_action)
            
        if throttle_enabled:
            throttle_action = ThrottleAction(self.execute_command_func)
            rule.add_action(throttle_action)
            
        return rule
        
    def from_dict(self, rule_dict: Dict[str, Any]) -> AlertRule:
        """
        Create a rule from a dictionary.
        
        Args:
            rule_dict: Dictionary with rule configuration
            
        Returns:
            Created alert rule
        """
        # Convert string alert types to enum values
        alert_type_strings = rule_dict.get("alert_types", [])
        alert_types = []
        for type_str in alert_type_strings:
            try:
                alert_types.append(AlertType(type_str))
            except ValueError:
                # Skip invalid alert types
                pass
                
        # Convert string priority to enum value
        priority_str = rule_dict.get("min_priority", "LOW")
        try:
            min_priority = AlertPriority[priority_str]
        except KeyError:
            min_priority = AlertPriority.LOW
            
        # Create rule
        rule = self.create_rule(
            rule_id=rule_dict.get("rule_id", f"custom_rule_{len(rule_dict)}"),
            description=rule_dict.get("description", "Custom rule"),
            alert_types=alert_types or list(AlertType),
            min_priority=min_priority,
            conditions=rule_dict.get("conditions"),
            log_enabled=rule_dict.get("log_enabled", True),
            block_mac_enabled=rule_dict.get("block_mac_enabled", False),
            throttle_enabled=rule_dict.get("throttle_enabled", False),
            log_path=rule_dict.get("log_path")
        )
        
        return rule 