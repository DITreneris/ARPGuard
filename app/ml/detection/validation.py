from typing import List, Dict, Any
from .rule_based import Rule

class RuleValidator:
    """Validates rules before they are added to the engine"""
    def __init__(self):
        self.required_fields = ["rule_id", "description", "severity"]
        self.allowed_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        
    def validate_rule(self, rule: Rule) -> List[str]:
        """Validate a rule and return list of errors"""
        errors = []
        
        # Check required fields
        metadata = rule.get_metadata()
        for field in self.required_fields:
            if not metadata.get(field):
                errors.append(f"Missing required field: {field}")
                
        # Validate severity
        if metadata.get("severity") not in self.allowed_severities:
            errors.append(f"Invalid severity: {metadata.get('severity')}")
            
        # Validate rule_id format
        if not self._is_valid_rule_id(metadata.get("rule_id", "")):
            errors.append("Invalid rule_id format")
            
        return errors
        
    def _is_valid_rule_id(self, rule_id: str) -> bool:
        # Rule ID format: TYPE_NUMBER (e.g., ARP_SPOOFING_001)
        if not rule_id:
            return False
        parts = rule_id.split("_")
        return len(parts) >= 2 and parts[-1].isdigit() 