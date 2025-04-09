---
version: 6
last_modified: '2025-04-06T07:28:37.828346'
git_history: []
---

# Rule-Based Detection Layer Documentation
**Version: 1.0**
**Last Updated: April 6, 2024**

## Overview

The rule-based detection layer provides the first line of defense against ARP-based attacks in ARPGuard. It utilizes a combination of predefined rules to detect suspicious network activity based on well-known attack patterns.

This layer is part of ARPGuard's Two-Layer Hybrid Architecture, working alongside the ML-based detection layer. The rule-based layer focuses on detecting known attack patterns with high precision, while the ML-based layer is designed to identify novel or variant attacks.

## Architecture

The rule-based detection system consists of the following components:

1. **RuleEngine**: Central component that manages all rules and evaluates network packets.
2. **Rule**: Base class for all detection rules with common functionality.
3. **RuleResult**: Data structure that contains the result of a rule evaluation.
4. **RuleValidator**: Ensures rules conform to expected standards.
5. **RuleConfig**: Manages rule configuration and parameters.

## Rule Types

The rule-based detection layer currently includes the following ARP-specific rules:

### 1. ARP Spoofing Rule (ARP_SPOOFING_001)

Detects ARP spoofing attempts by monitoring ARP responses and identifying suspicious changes in IP-MAC mappings. An attacker attempting to impersonate another host will typically send ARP packets with the target's IP address but the attacker's MAC address.

**Detection Method**: Tracking IP-MAC mappings and detecting changes.

**Severity**: HIGH

### 2. Gratuitous ARP Rule (ARP_GRATUITOUS_001)

Detects suspicious gratuitous ARP packets. Gratuitous ARP packets (where source and target IP are the same) are sometimes used legitimately but can also be used in attacks. This rule detects unusual rates of gratuitous ARP packets from a single source.

**Detection Method**: Tracking gratuitous ARP packet rates over time.

**Severity**: MEDIUM

### 3. ARP Flood Rule (ARP_FLOOD_001)

Detects ARP flooding attacks where an attacker sends a high rate of ARP packets to overwhelm network devices or as part of a reconnaissance effort.

**Detection Method**: Tracking ARP packet rates per source within time windows.

**Severity**: HIGH

## Configuration

Rules can be configured through the `rules_config.yaml` file in the data directory:

```yaml
ARP_SPOOFING_001:
  enabled: true
  threshold: 0.8
  action: alert

ARP_GRATUITOUS_001:
  enabled: true
  threshold: 0.7
  action: log
  rate_threshold: 10

ARP_FLOOD_001:
  enabled: true
  threshold: 0.8
  action: alert
  packets_per_second_threshold: 20
```

### Configuration Options

- **enabled**: Whether the rule is active (true/false)
- **threshold**: Confidence threshold required for a result to be considered valid (0.0-1.0)
- **action**: Action to take when a rule matches (alert, log, block)
- **rule-specific parameters**: Thresholds and parameters specific to individual rules

## Usage

### Basic Rule Engine Usage

```python
from app.ml.detection.rule_based import RuleEngine
from app.ml.detection.rules.arp_spoofing import ARPSpoofingRule, ARPGratuitousRule, ARPFloodRule

# Create rule engine
engine = RuleEngine()

# Add rules
engine.add_rule(ARPSpoofingRule())
engine.add_rule(ARPGratuitousRule())
engine.add_rule(ARPFloodRule())

# Process a packet
packet_data = {
    "protocol": "ARP",
    "source_mac": "00:11:22:33:44:55",
    "source_ip": "192.168.1.100",
    "target_ip": "192.168.1.1",
    "packet_type": "reply"
}

# Evaluate packet against all rules
results = engine.evaluate_packet(packet_data)

# Process results
for result in results:
    print(f"Rule match: {result.rule_id}, Confidence: {result.confidence}, Severity: {result.severity}")
    print(f"Evidence: {result.evidence}")
```

### Using Rule Configuration

```python
from app.ml.detection.config import RuleConfig

# Load rule configuration
config = RuleConfig()

# Get configuration for a specific rule
spoofing_config = config.get_rule_config("ARP_SPOOFING_001")

# Check if rule is enabled
if spoofing_config.get("enabled", False):
    # Use rule
    # ...
    
# Update rule configuration
config.update_rule_config("ARP_SPOOFING_001", {
    "enabled": True,
    "threshold": 0.9,
    "action": "block"
})
```

## Creating Custom Rules

To create a custom rule:

1. Inherit from the `Rule` base class
2. Implement the `evaluate()` method to check for specific patterns
3. Return a `RuleResult` object when a match is found

Example:

```python
from app.ml.detection.rule_based import Rule, RuleResult
from datetime import datetime

class CustomRule(Rule):
    def __init__(self):
        super().__init__(
            rule_id="CUSTOM_RULE_001",
            description="A custom rule for detecting specific network behavior",
            severity="MEDIUM"
        )
        
    def evaluate(self, packet_data):
        # Implement your detection logic here
        if self._matches_pattern(packet_data):
            return RuleResult(
                rule_id=self.rule_id,
                confidence=0.85,
                evidence={"reason": "Pattern matched", "data": packet_data},
                timestamp=datetime.now(),
                severity=self.severity
            )
        return None
        
    def _matches_pattern(self, packet_data):
        # Implement pattern matching logic
        return False
```

## Testing

Run the unit tests to verify the functionality of the rule-based detection system:

```
pytest tests/ml/detection/test_rule_based.py
pytest tests/ml/detection/test_config.py
```

## Future Enhancements

1. **Additional Rules**: Development of rules for additional attack types
2. **Rule Performance Metrics**: Track rule performance and false positive rates
3. **Rule Priority**: Implement priority-based rule evaluation
4. **Compound Rules**: Allow rules to build on the results of other rules
5. **Rule Categories**: Group rules by attack type or severity

**Last Updated: April 6, 2024** 