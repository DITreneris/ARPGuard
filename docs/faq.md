# ARP Guard Frequently Asked Questions

## General Questions

### What is ARP Guard?
ARP Guard is a security tool designed to detect and prevent ARP spoofing attacks on your network. It monitors ARP traffic, identifies suspicious activity, and can automatically take remediation actions to protect your network.

### How does ARP Guard work?
ARP Guard captures and analyzes ARP packets on your network, maintaining a database of legitimate MAC-to-IP mappings. When it detects inconsistencies or suspicious changes that could indicate ARP spoofing, it alerts you and optionally blocks the suspicious hosts.

### Is ARP Guard free?
ARP Guard comes in multiple tiers:
- **Demo Tier**: Free with basic detection capabilities
- **Lite Tier**: Low-cost option with essential features
- **Pro Tier**: Full-featured professional version with advanced remediation and reporting

### What platforms does ARP Guard support?
ARP Guard runs on:
- Linux (Ubuntu, Debian, CentOS, and most other distributions)
- Windows 10 and 11
- Windows Server 2016/2019/2022
- macOS (limited support in beta)

### What are the system requirements?
Minimum requirements:
- 2 GB RAM
- 100 MB disk space
- Python 3.7 or higher
- Network interface with promiscuous mode support
- Administrator/root privileges

## Technical Questions

### What is ARP spoofing?
ARP spoofing (or ARP poisoning) is a type of attack where an attacker sends falsified ARP messages over a local network. This results in linking the attacker's MAC address with the IP address of a legitimate network resource, allowing the attacker to intercept, modify, or stop data in transit.

### How effective is ARP Guard at detecting attacks?
ARP Guard has proven highly effective in controlled testing environments, detecting over 99% of common ARP spoofing attacks with a low false positive rate. Its effectiveness can be adjusted through sensitivity settings to balance between detection rates and false positives.

### Will ARP Guard slow down my network?
ARP Guard is designed to be lightweight and efficient. In most environments, the impact on network performance is negligible. For high-traffic networks, you can adjust settings like packet sampling rate to further reduce any impact.

### How does ARP Guard compare to other ARP spoofing tools?
Unlike many other solutions, ARP Guard:
- Provides real-time detection with minimal latency
- Offers automated remediation options
- Features a user-friendly interface alongside powerful CLI tools
- Includes cross-platform support with consistent behavior
- Maintains detailed telemetry and logs for forensic analysis

### Can I use ARP Guard with a VPN?
Yes, ARP Guard works with most VPN configurations. However, for VPN clients that modify network routes or use TAP/TUN interfaces, you may need to adjust the monitoring interface settings to focus on your physical network adapter.

## Installation & Configuration

### Do I need to install anything else for ARP Guard to work?
ARP Guard requires:
- Python 3.7+
- Libpcap (Linux) or Npcap (Windows)
- Several Python packages (automatically installed during setup)

### How do I configure ARP Guard for optimal security?
For optimal security, we recommend:
1. Running the initial learning phase for at least 24 hours
2. Adding known-good devices to the whitelist
3. Setting up email notifications
4. Enabling automatic blocking for high-confidence detections
5. Running periodic security audits with `arp_guard audit`

### Can I monitor multiple network interfaces?
Yes, ARP Guard Pro can monitor multiple interfaces simultaneously. Use the `--interface` option with comma-separated values or configure multiple interfaces in the configuration file.

### Where are configuration files stored?
Configuration files are stored in:
- Linux: `~/.config/arp_guard/`
- Windows: `%APPDATA%\ARP Guard\`
- Custom location: Specify with `--config-dir` option

### How do I back up my ARP Guard configuration?
Use the export command to back up your configuration:
```bash
arp_guard export --config --whitelist --output backup.json
```

## Usage Questions

### How do I start monitoring my network?
To start monitoring, run:
```bash
arp_guard start
```

For more options, use:
```bash
arp_guard start --help
```

### How do I view detected threats?
View detected threats with:
```bash
arp_guard status --threats
```

Or access the web dashboard at http://localhost:5000 after starting it with:
```bash
arp_guard dashboard
```

### Can ARP Guard automatically block attackers?
Yes, enable automatic blocking with:
```bash
arp_guard remediation set auto_block true
```

You can also configure blocking duration and sensitivity:
```bash
arp_guard remediation set block_duration 3600  # Block for 1 hour
arp_guard remediation set block_threshold 7    # Block at threat level 7+
```

### How do I whitelist a device?
To whitelist a device:
```bash
arp_guard remediation whitelist add 00:11:22:33:44:55 192.168.1.100
```

You can also add a description:
```bash
arp_guard remediation whitelist add 00:11:22:33:44:55 192.168.1.100 "Office Printer"
```

### How do I interpret the threat levels?
ARP Guard uses a 1-10 threat level scale:
- **1-3**: Low threat - potential anomaly, but likely benign
- **4-6**: Medium threat - suspicious activity that warrants attention
- **7-8**: High threat - likely malicious, recommended for blocking
- **9-10**: Critical threat - active attack detected, immediate action required

## Remediation Features

### What happens when ARP Guard blocks a device?
When ARP Guard blocks a device, it:
1. Creates firewall rules to block the suspicious IP and/or MAC
2. Sends ARP correction packets to affected hosts (Pro version)
3. Logs the action with timestamp and reason
4. Sends notifications if configured
5. Displays the block in the dashboard

### How long do blocks last?
By default, blocks last for 1 hour, but this is configurable:
```bash
arp_guard remediation set block_duration 86400  # 24 hours in seconds
```

You can also set permanent blocks for confirmed attackers:
```bash
arp_guard block 00:11:22:33:44:55 --permanent
```

### Can I get notified when attacks are detected?
Yes, ARP Guard supports email notifications:
```bash
arp_guard remediation set notification_email admin@example.com
arp_guard remediation set notification_threshold 5  # Notify on threat level 5+
```

The Pro version also supports:
- Slack/Teams integration
- SMS notifications
- Syslog/SIEM integration
- Custom webhook notifications

### Does ARP Guard integrate with other security tools?
The Pro version integrates with:
- SIEM systems via syslog
- Firewall solutions
- Network monitoring tools
- Custom security workflows via API

## Troubleshooting & Support

### ARP Guard isn't detecting any packets. What should I check?
Check the following:
1. Ensure you're running with administrator/root privileges
2. Verify the network interface is correct (`arp_guard list-interfaces`)
3. Confirm Npcap/libpcap is correctly installed
4. Check if other security software is blocking packet capture
5. Verify your network adapter supports promiscuous mode

### How do I report false positives?
If you encounter false positives:
1. Add the legitimate device to the whitelist
2. Consider lowering the sensitivity setting
3. Submit the false positive report with:
   ```bash
   arp_guard report false-positive --mac 00:11:22:33:44:55 --ip 192.168.1.100
   ```

### Where can I find log files?
Log files are located at:
- Linux: `/var/log/arp_guard.log` or `~/.config/arp_guard/logs/`
- Windows: `%APPDATA%\ARP Guard\logs\`

### How do I get support?
Support options include:
- Documentation: https://arp-guard.example.com/docs
- Community forum: https://community.arp-guard.example.com
- GitHub issues: https://github.com/arp-guard/arp-guard/issues
- Email support: support@arp-guard.example.com (Pro tier)
- Priority support line: +1-555-ARP-GUARD (Pro tier)

### How often is ARP Guard updated?
We release:
- Security updates: As needed
- Bug fixes: Monthly
- Feature updates: Quarterly
- Major versions: Annually

## Advanced Features

### Can ARP Guard run as a system service?
Yes, to install as a service:

On Linux:
```bash
sudo arp_guard service install
sudo systemctl enable arp-guard
sudo systemctl start arp-guard
```

On Windows:
```powershell
arp_guard service install
Start-Service ARPGuard
```

### Does ARP Guard support remote monitoring?
The Pro version supports remote monitoring through:
- Secure API access
- Remote dashboard connectivity
- Agent-server architecture for enterprise deployments
- Cloud reporting options

### Is there an API for custom integrations?
Yes, the Pro version includes a comprehensive REST API for integration with:
- Custom security dashboards
- Automation tools
- Orchestration platforms
- Enterprise security frameworks

Access the API documentation with:
```bash
arp_guard api-docs
```

### Can ARP Guard perform network mapping?
Yes, use the network mapping feature:
```bash
arp_guard map-network --output network-map.html
```

This generates a visual representation of your network showing all discovered devices and their relationships.

### How can I analyze historical data?
ARP Guard keeps historical data that can be analyzed with:
```bash
arp_guard analytics --from 2023-01-01 --to 2023-01-31
```

Export historical data with:
```bash
arp_guard export --history --output arp-history.csv
```

## Privacy & Compliance

### What data does ARP Guard collect?
ARP Guard collects:
- ARP packet data on your local network
- MAC and IP address mappings
- Detection events and metrics
- System performance data

All data remains on your local system unless you explicitly enable telemetry sharing.

### Does ARP Guard send any data to external servers?
By default, no data is sent externally. The optional telemetry program only sends:
- Anonymous usage statistics
- Detection effectiveness metrics
- Error reports

You can disable telemetry with:
```bash
arp_guard config set telemetry.enabled false
```

### Is ARP Guard compliant with privacy regulations?
ARP Guard is designed with privacy in mind:
- No personal data is collected beyond network identifiers
- All data processing happens locally
- Data retention periods are configurable
- Export and deletion functions are available for compliance

### Can ARP Guard be used in enterprise environments with strict compliance requirements?
Yes, the Pro version includes:
- Role-based access control
- Audit logging for compliance
- Data retention policies
- Encryption for stored data
- Compliance reporting tools 