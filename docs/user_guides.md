# ARPGuard User Guides

## Table of Contents
1. [Basic Setup Guide](#basic-setup-guide)
   - [Installation Steps](#installation-steps)
   - [Configuration](#configuration)
   - [Initial Setup](#initial-setup)
2. [Feature Documentation](#feature-documentation)
   - [Attack Detection](#attack-detection)
   - [Threat Intelligence](#threat-intelligence)
   - [Monitoring Features](#monitoring-features)

## Basic Setup Guide

### Installation Steps

#### System Requirements
- Operating System: Windows 10/11, Linux (Ubuntu 20.04+), macOS 10.15+
- Python 3.8 or higher
- 4GB RAM minimum (8GB recommended)
- 1GB free disk space
- Network interface with promiscuous mode support

#### Installation Methods

##### Method 1: Using pip
```bash
# Create a virtual environment (recommended)
python -m venv arpguard-env
source arpguard-env/bin/activate  # On Windows: arpguard-env\Scripts\activate

# Install ARPGuard
pip install arpguard
```

##### Method 2: From Source
```bash
# Clone the repository
git clone https://github.com/your-org/arpguard.git
cd arpguard

# Install dependencies
pip install -r requirements.txt

# Install ARPGuard
python setup.py install
```

##### Method 3: Using Docker
```bash
# Pull the Docker image
docker pull arpguard/arpguard:latest

# Run the container
docker run -d --name arpguard \
  --network host \
  -v /path/to/config:/etc/arpguard \
  arpguard/arpguard:latest
```

### Configuration

#### Initial Configuration File
Create a configuration file at `/etc/arpguard/config.yaml`:

```yaml
network:
  interface: eth0  # Your network interface
  mode: protect    # monitor or protect
  promiscuous_mode: true
  packet_timeout: 1000

security:
  arp_rate_threshold: 100
  mac_changes_threshold: 10
  block_attacks: true
  alert_admin: true
  log_events: true

notification:
  email_enabled: true
  sms_enabled: false
  desktop_enabled: true
  email_settings:
    address: admin@example.com
    smtp_server: smtp.example.com
    smtp_port: 587
```

#### Configuration Wizard
Run the configuration wizard:
```bash
arpguard config-wizard
```

This will guide you through:
1. Network interface selection
2. Security settings
3. Notification preferences
4. Advanced options

### Initial Setup

#### First Run
1. Start ARPGuard:
   ```bash
   arpguard start
   ```

2. Access the web interface:
   - Open your browser
   - Navigate to `http://localhost:8080`
   - Default credentials:
     - Username: admin
     - Password: admin (change on first login)

3. Complete the initial setup:
   - Change the default password
   - Configure network interfaces
   - Set up notification preferences
   - Review and adjust security thresholds

#### Post-Installation Checklist
- [ ] Verify network interface permissions
- [ ] Test email notifications
- [ ] Configure backup settings
- [ ] Set up logging preferences
- [ ] Review security thresholds
- [ ] Test attack detection

## Feature Documentation

### Attack Detection

#### ARP Spoofing Detection
ARPGuard monitors for:
- Unusual ARP request rates
- MAC address changes
- IP address conflicts
- Suspicious ARP replies

##### Configuration Options
```yaml
security:
  arp_rate_threshold: 100  # Max ARP requests per second
  mac_changes_threshold: 10  # Max MAC changes per minute
  block_attacks: true  # Automatically block detected attacks
  alert_admin: true  # Send alerts for detected attacks
```

##### Response Actions
When an attack is detected:
1. Alert is generated with severity level
2. Attack details are logged
3. Optional automatic blocking
4. Administrator notification

#### Port Scanning Detection
- Monitors for suspicious port scanning patterns
- Detects both horizontal and vertical scans
- Identifies stealth scanning techniques

##### Configuration
```yaml
security:
  port_scan:
    threshold: 50  # Connections per minute
    timeout: 300   # Detection window in seconds
    alert_level: medium
```

### Threat Intelligence

#### Features
- Real-time threat updates
- IP reputation checking
- Malicious domain detection
- Attack signature database

#### Configuration
```yaml
threat_intelligence:
  update_interval: 3600  # Update every hour
  sources:
    - local_database
    - external_feed
    - custom_source
  min_confidence: 80  # Minimum confidence score
```

#### Usage
1. Access the Threat Intelligence panel
2. View current threats
3. Check specific IPs or domains
4. Export threat data
5. Configure update settings

### Monitoring Features

#### Network Statistics
Real-time monitoring of:
- Packets processed
- Attacks detected
- False positives
- Response times
- Network throughput
- System resource usage

##### Dashboard Features
- Real-time graphs
- Historical data
- Custom time ranges
- Export capabilities

#### Alert Management
- Severity-based alerting
- Custom alert rules
- Multiple notification methods
- Alert history

##### Alert Configuration
```yaml
alerts:
  severity_levels:
    critical:
      email: true
      sms: true
      desktop: true
    high:
      email: true
      sms: false
      desktop: true
    medium:
      email: true
      sms: false
      desktop: false
    low:
      email: false
      sms: false
      desktop: true
```

#### Log Management
- Centralized logging
- Log rotation
- Search and filter
- Export capabilities

##### Log Configuration
```yaml
logging:
  level: INFO
  max_size: 10485760  # 10MB
  backup_count: 5
  format: "%(asctime)s - %(levelname)s - %(message)s"
```

## Troubleshooting

### Common Issues

#### Network Interface Problems
1. Check interface permissions:
   ```bash
   sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/arpguard
   ```

2. Verify promiscuous mode:
   ```bash
   ip link show <interface>
   ```

#### Performance Issues
1. Adjust packet timeout:
   ```yaml
   network:
     packet_timeout: 2000  # Increase if experiencing packet loss
   ```

2. Optimize thresholds:
   ```yaml
   security:
     arp_rate_threshold: 150  # Adjust based on network size
     mac_changes_threshold: 15
   ```

#### Alert Configuration
1. Test email notifications:
   ```bash
   arpguard test-notification --type email
   ```

2. Verify SMTP settings:
   ```yaml
   notification:
     email_settings:
       smtp_server: smtp.example.com
       smtp_port: 587
       use_tls: true
   ```

## Best Practices

### Security Recommendations
1. Change default credentials immediately
2. Use strong passwords
3. Enable HTTPS in production
4. Regular updates
5. Backup configurations

### Performance Optimization
1. Adjust thresholds based on network size
2. Monitor system resources
3. Configure appropriate logging levels
4. Regular maintenance
5. Database optimization

### Maintenance
1. Regular updates
2. Log rotation
3. Configuration backups
4. Performance monitoring
5. Security audits 