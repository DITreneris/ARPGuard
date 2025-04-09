# ARPGuard Lite Tier Alert System Design

## Overview

The Lite Tier of ARPGuard introduces an expanded alert system that builds upon the basic alerting capabilities of the Demo Tier. This enhanced system provides more comprehensive threat detection, persistent alert storage, customizable notification options, and a structured approach to managing security incidents on the network.

## Design Goals

- **Comprehensive Detection**: Identify a broader range of ARP-related security threats
- **Contextual Awareness**: Provide detailed information about detected threats and their context
- **Actionable Intelligence**: Include specific remediation steps for each alert type
- **Persistent Storage**: Maintain alert history for forensic analysis and reporting
- **Customizable Sensitivity**: Allow users to adjust detection thresholds based on their environment
- **Multi-channel Notifications**: Support various notification methods for timely awareness

## Alert Model

### Alert Structure

Each alert in the system will contain the following information:

```json
{
  "id": "uuid-string",
  "timestamp": "ISO-8601 datetime",
  "type": "alert_type_identifier",
  "severity": "critical|high|medium|low|info",
  "title": "Human-readable alert title",
  "description": "Detailed description of the alert",
  "source": {
    "ip": "ip_address",
    "mac": "mac_address",
    "hostname": "device_hostname",
    "vendor": "device_vendor"
  },
  "target": {
    "ip": "ip_address",
    "mac": "mac_address",
    "hostname": "device_hostname",
    "vendor": "device_vendor"
  },
  "evidence": [
    {
      "timestamp": "ISO-8601 datetime",
      "data": "evidence_data_object"
    }
  ],
  "suggestions": [
    "Suggested action 1",
    "Suggested action 2"
  ],
  "status": "new|in_progress|resolved|false_positive",
  "resolution": {
    "timestamp": "ISO-8601 datetime",
    "action_taken": "Description of resolution action",
    "notes": "Additional notes about resolution"
  },
  "related_alerts": ["related-alert-id-1", "related-alert-id-2"]
}
```

### Alert Types

The Lite Tier will detect and categorize the following alert types:

| Alert Type ID | Title | Description |
|---------------|-------|-------------|
| `arp_spoof_gateway` | Gateway Impersonation | A device is responding to ARP requests for the gateway |
| `arp_spoof_host` | Host Impersonation | A device is responding to ARP requests for another host |
| `mac_flapping` | MAC Address Flapping | An IP address is rapidly changing between different MAC addresses |
| `gateway_mac_changed` | Gateway MAC Change | The gateway MAC address has changed from its known value |
| `new_device` | New Device Detected | A previously unseen device has appeared on the network |
| `rogue_dhcp` | Rogue DHCP Server | An unauthorized DHCP server is operating on the network |
| `incomplete_arp` | Incomplete ARP Entries | Unusually high number of incomplete ARP entries detected |
| `arp_broadcast_storm` | ARP Broadcast Storm | Excessive ARP broadcast packets detected |
| `gratuitous_arp` | Suspicious Gratuitous ARP | Unusual pattern of gratuitous ARP packets |
| `trusted_device_changed` | Trusted Device Change | A trusted device's MAC address has unexpectedly changed |

### Severity Levels

Alerts are categorized into severity levels to help prioritize response:

| Severity | Color | Description |
|----------|-------|-------------|
| Critical | Red | Immediate action required; active attack likely in progress |
| High | Orange | Urgent attention needed; high confidence of malicious activity |
| Medium | Yellow | Notable security concern; requires investigation |
| Low | Blue | Potential issue; should be reviewed when time permits |
| Info | Gray | Informational alert; no immediate security concern |

### Default Severity Mappings

Each alert type has a default severity level, which can be customized by the user:

| Alert Type | Default Severity |
|------------|------------------|
| arp_spoof_gateway | Critical |
| arp_spoof_host | High |
| mac_flapping | High |
| gateway_mac_changed | Medium |
| new_device | Info |
| rogue_dhcp | Critical |
| incomplete_arp | Low |
| arp_broadcast_storm | Medium |
| gratuitous_arp | Medium |
| trusted_device_changed | High |

## Alert Detection Logic

### Gateway Impersonation Detection

1. Monitor ARP responses claiming to be the gateway
2. Compare MAC addresses to known gateway MAC
3. Alert if a non-gateway MAC responds as the gateway IP
4. Track frequency and persistence of impersonation attempts

### MAC Flapping Detection

1. Maintain history of MAC-to-IP mappings
2. Track changes in mappings over time
3. Calculate rate of changes for each IP address
4. Alert if change rate exceeds threshold
5. Consider legitimate DHCP lease changes vs. rapid flapping

### New Device Detection

1. Maintain inventory of known devices
2. Compare newly discovered devices against inventory
3. Generate alerts for devices not in inventory
4. Include device fingerprinting data when available

### Advanced Detection Methods

The Lite Tier will implement more sophisticated detection methods:

1. **Temporal Pattern Analysis**: Identifying suspicious patterns in the timing of ARP packets
2. **Behavioral Baselining**: Establishing normal ARP behavior for the network and alerting on deviations
3. **Relationship Mapping**: Analyzing relationships between devices to identify inconsistent behavior
4. **Historical Comparison**: Comparing current ARP activity with historical patterns

## Alert Storage and Persistence

### Database Schema

Alerts will be stored in a SQLite database with the following schema:

```sql
CREATE TABLE alerts (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    source_ip TEXT,
    source_mac TEXT,
    source_hostname TEXT,
    source_vendor TEXT,
    target_ip TEXT,
    target_mac TEXT,
    target_hostname TEXT,
    target_vendor TEXT,
    evidence TEXT,
    suggestions TEXT,
    status TEXT NOT NULL,
    resolution_timestamp TEXT,
    resolution_action TEXT,
    resolution_notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE related_alerts (
    alert_id TEXT,
    related_alert_id TEXT,
    relationship_type TEXT,
    PRIMARY KEY (alert_id, related_alert_id),
    FOREIGN KEY (alert_id) REFERENCES alerts(id),
    FOREIGN KEY (related_alert_id) REFERENCES alerts(id)
);

CREATE INDEX idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX idx_alerts_type ON alerts(type);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_status ON alerts(status);
```

### Retention Policy

The alert retention policy will be configurable with the following defaults:

- Critical alerts: 180 days
- High alerts: 90 days
- Medium alerts: 60 days
- Low alerts: 30 days
- Info alerts: 15 days

### Export Functionality

Alerts can be exported in the following formats:
- JSON (complete alert data)
- CSV (summary information)
- PDF (formatted report for sharing)

## Notification System

### Notification Channels

The Lite Tier will support the following notification channels:

1. **In-Application Alerts**: Real-time display within the application UI
2. **Desktop Notifications**: System notifications using the OS notification system
3. **Sound Alerts**: Audible alerts for critical notifications
4. **Email Notifications**: Configurable email alerts for specific severity levels
5. **Log File**: All alerts recorded in application logs
6. **Export to SIEM**: Optional integration with Security Information and Event Management systems

### Notification Configuration

Users can configure notifications based on:

- Alert type
- Severity level
- Time of day
- Specific devices or subnets

### Notification Throttling

To prevent alert fatigue, the system implements intelligent throttling:

1. Similar alerts are grouped into a single notification
2. Repeated alerts of the same type are throttled after a configurable threshold
3. Summary notifications are sent periodically for lower-priority alerts

## Alert Lifecycle Management

### Alert States

Alerts progress through the following states:

1. **New**: Recently detected, not yet acknowledged
2. **In Progress**: Acknowledged and being investigated
3. **Resolved**: Issue has been addressed
4. **False Positive**: Alert determined to be incorrect

### Alert Workflow

1. System detects potential security issue and generates alert
2. Alert is stored in database and notifications are sent
3. User acknowledges alert and begins investigation
4. User documents investigation findings
5. User resolves alert with resolution notes
6. System maintains alert in database according to retention policy

### Alert Correlation

The system will automatically correlate related alerts:

1. Identify alerts from the same source device
2. Group alerts of the same type occurring within a time window
3. Link alerts involving the same target device
4. Associate alerts that might be part of a larger attack pattern

## User Interaction Design

### Alert Review Interface

The alert review interface will provide:

1. Sorting and filtering by severity, time, status, and type
2. Detailed view of selected alert with all relevant information
3. Quick actions for common responses
4. History of previous occurrences of similar alerts

### Alert Response Actions

Users can take the following actions on alerts:

1. **Acknowledge**: Mark the alert as being investigated
2. **Escalate**: Increase alert severity if threat is determined to be more serious
3. **Resolve**: Mark the alert as resolved with notes
4. **False Positive**: Indicate the alert was incorrect
5. **Block Device**: Initiate blocking of the offending device (if integration available)
6. **Export**: Export the alert details for external use

### Alert Settings Management

Users can customize the alert system via:

1. Alert threshold configuration
2. Severity level adjustments
3. Notification preferences
4. Custom alert rules (advanced)

## Implementation Approach

### Component Architecture

The alert system will be implemented with the following components:

1. **Alert Generator**: Analyzes ARP monitoring data to detect issues
2. **Alert Database**: Stores and manages alert records
3. **Notification Engine**: Dispatches alerts through configured channels
4. **Alert UI Manager**: Controls the presentation of alerts in the interface
5. **Alert Configuration Manager**: Manages user preferences for alerting

### Classes and Interfaces

Key classes in the implementation:

```python
class AlertManager:
    """Central management of the alert system"""
    def generate_alert(self, alert_type, source, target, evidence, **kwargs)
    def update_alert_status(self, alert_id, status, notes=None)
    def get_alerts(self, filters=None, limit=None, offset=None)
    def correlate_alerts(self, alert_id)
    def purge_old_alerts(self)

class AlertRepository:
    """Data access layer for alert storage"""
    def save_alert(self, alert)
    def update_alert(self, alert)
    def find_alerts(self, criteria)
    def get_alert_by_id(self, alert_id)
    def delete_alert(self, alert_id)

class NotificationEngine:
    """Handles sending alert notifications"""
    def send_notification(self, alert, channels=None)
    def should_throttle(self, alert)
    def format_notification(self, alert, channel)
```

### Integration Points

The alert system will integrate with:

1. **ARP Cache Monitor**: Primary source of raw data for alert generation
2. **Device Discovery**: Provides device context for alerts
3. **Configuration Manager**: Sources alert preferences
4. **User Interface**: Displays alerts and accepts user input
5. **Logging System**: Records alert activity
6. **Operating System**: For desktop notifications

## Testing Strategy

### Unit Tests

Test individual components:
- Alert generation logic
- Database operations
- Notification formatting

### Integration Tests

Test component interactions:
- End-to-end alert generation and storage
- Notification dispatch
- UI updates in response to alerts

### Scenario-Based Tests

Test specific security scenarios:
- Gateway impersonation detection
- MAC address flapping
- New device alerts

### Performance Tests

- Test with high alert volume
- Measure database performance under load
- Assess notification system throughput

## Future Enhancements

### Planned for Next Release

1. **Machine Learning Detection**: Use ML to improve false positive reduction
2. **Custom Alert Rules**: Allow users to define custom alert conditions
3. **Webhook Notifications**: Enable integration with external systems
4. **Mobile Notifications**: Add support for mobile app notifications
5. **Alert Dashboards**: Customizable alert visualization dashboards
6. **Automated Response Actions**: Configure automatic responses to specific alerts

## Conclusion

The ARPGuard Lite Tier Alert System provides a robust framework for detecting, managing, and responding to ARP-based security threats. By offering comprehensive detection capabilities, persistent storage, and flexible notification options, it enables users to effectively monitor their networks and respond quickly to potential security incidents. 