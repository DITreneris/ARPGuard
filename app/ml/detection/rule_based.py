from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class RuleResult:
    """Result of a rule evaluation"""
    rule_id: str
    confidence: float
    evidence: Dict[str, Any]
    timestamp: datetime
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL

class Rule:
    """Base class for all detection rules"""
    def __init__(self, rule_id: str, description: str, severity: str):
        self.rule_id = rule_id
        self.description = description
        self.severity = severity
        
    def evaluate(self, packet_data: Dict[str, Any]) -> Optional[RuleResult]:
        """Evaluate the rule against packet data"""
        raise NotImplementedError
        
    def get_metadata(self) -> Dict[str, Any]:
        """Get rule metadata"""
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity
        }

class RuleEngine:
    """Engine for managing and evaluating rules"""
    def __init__(self):
        self.rules: Dict[str, Rule] = {}
        
    def add_rule(self, rule: Rule) -> None:
        """Add a rule to the engine"""
        self.rules[rule.rule_id] = rule
        
    def evaluate_packet(self, packet_data: Dict[str, Any]) -> List[RuleResult]:
        """Evaluate all rules against packet data"""
        results = []
        for rule in self.rules.values():
            result = rule.evaluate(packet_data)
            if result:
                results.append(result)
        return results 