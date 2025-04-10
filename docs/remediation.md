# ARP Guard Remediation Module

The Remediation Module provides automated response capabilities for detected ARP spoofing attacks. This document describes its features, configuration, and usage.

## Features

- **Automatic Host Blocking**: Block malicious hosts from the network
- **Whitelist Management**: Define trusted MAC-IP pairs
- **Admin Notifications**: Email alerts for detected attacks
- **Configurable Block Duration**: Set how long hosts remain blocked
- **Cross-Platform Support**: Works on both Linux and Windows

## Configuration

The module can be configured through the CLI or by editing the configuration file at `config/remediation_config.json`.

### Available Settings

- `auto_block`: Enable/disable automatic blocking (default: true)
- `block_duration`: Duration of blocks in seconds (default: 1800)
- `notify_admin`: Enable/disable admin notifications (default: true)
- `notification_email`: Email address for notifications
- `notification_threshold`: Number of detections before notification
- `whitelist`: List of trusted MAC-IP pairs

### Example Configuration

```json
{
    "auto_block": true,
    "block_duration": 1800,
    "notify_admin": true,
    "notification_email": "admin@example.com",
    "notification_threshold": 3,
    "whitelist": [
        "00:11:22:33:44:55:192.168.1.100"
    ]
}
```

## CLI Commands

### Show Settings
```bash
arp_guard remediation show
```
Displays current remediation settings and blocked hosts.

### Configure Settings
```bash
arp_guard remediation set <setting> <value>
```
Modify a remediation setting. Available settings:
- `auto_block`: true/false
- `block_duration`: seconds
- `notify_admin`: true/false
- `notification_email`: email address
- `notification_threshold`: number

### Manage Whitelist
```bash
# Add to whitelist
arp_guard remediation whitelist add <mac> <ip>

# Remove from whitelist
arp_guard remediation whitelist remove <mac>

# List whitelist entries
arp_guard remediation whitelist list
```

## Implementation Details

### Host Blocking

#### Linux
- Uses `iptables` to block hosts by MAC and IP address
- Creates INPUT and FORWARD chain rules
- Blocks both incoming and forwarded traffic

#### Windows
- Uses Windows Firewall to block hosts by IP address
- Creates inbound rules with descriptive names
- Blocks all protocols for the specified IP

### Notifications

- Sends email notifications via SMTP
- Includes detailed information about the attack
- Configurable notification threshold
- Supports multiple notification recipients

### Whitelist

- Format: `MAC:IP` (e.g., "00:11:22:33:44:55:192.168.1.100")
- Whitelisted hosts are never blocked
- Supports multiple whitelist entries
- Persisted across restarts

## Best Practices

1. **Whitelist Management**
   - Regularly review and update whitelist entries
   - Remove unused or outdated entries
   - Document the purpose of each whitelist entry

2. **Block Duration**
   - Set appropriate block duration based on your network
   - Consider shorter durations for testing
   - Longer durations for production environments

3. **Notifications**
   - Configure a dedicated email address for alerts
   - Set appropriate notification thresholds
   - Monitor notification delivery

4. **Security Considerations**
   - Run with appropriate privileges for network operations
   - Secure the configuration file
   - Regularly backup whitelist entries

## Troubleshooting

### Common Issues

1. **Host Not Blocked**
   - Check if host is whitelisted
   - Verify network interface permissions
   - Check firewall/iptables rules

2. **Notifications Not Sent**
   - Verify SMTP server configuration
   - Check email address format
   - Review notification threshold

3. **Configuration Not Saved**
   - Check file permissions
   - Verify configuration directory exists
   - Review error logs

### Logging

The module logs all operations to the system log. Check the logs for:
- Block/unblock operations
- Configuration changes
- Notification attempts
- Error conditions

## API Reference

### RemediationModule Class

```python
class RemediationModule:
    def __init__(self, config: Optional[RemediationConfig] = None)
    def initialize(self) -> bool
    def shutdown(self) -> bool
    def handle_detection(self, mac: str, ip: str, threat_level: str, details: Dict) -> bool
    def block_host(self, mac: str, ip: str, reason: str) -> bool
    def unblock_host(self, mac: str) -> bool
    def is_whitelisted(self, mac: str, ip: str) -> bool
    def get_status(self) -> Dict
    def get_blocked_hosts(self) -> List[Dict]
```

### RemediationConfig Class

```python
@dataclass
class RemediationConfig:
    auto_block: bool
    block_duration: int
    notify_admin: bool
    notification_email: str
    notification_threshold: int
    whitelist: List[str]
    blocked_hosts: Dict[str, Dict]
``` 