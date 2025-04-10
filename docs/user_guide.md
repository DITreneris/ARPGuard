# ARP Guard User Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Getting Started](#getting-started)
4. [Command Line Interface](#command-line-interface)
5. [Web Dashboard](#web-dashboard)
6. [Configuration](#configuration)
7. [Remediation Features](#remediation-features)
8. [Troubleshooting](#troubleshooting)
9. [FAQ](#faq)

## Introduction

ARP Guard is a powerful network security tool designed to detect and prevent ARP spoofing attacks on your network. ARP spoofing (also known as ARP poisoning) is a type of attack where an attacker sends falsified ARP messages over a local network, linking their MAC address with the IP address of a legitimate computer or server on the network. This allows them to intercept, modify, or stop data in transit.

### Key Features

- **Real-time Detection**: Continuously monitors network traffic for suspicious ARP packets
- **Automated Remediation**: Blocks malicious hosts to prevent attacks
- **Cross-Platform Support**: Works on both Linux and Windows
- **Web Dashboard**: Provides visual monitoring of network security status
- **Customizable Alerts**: Configure notifications based on threat levels
- **Whitelist Management**: Maintain trusted devices to prevent false positives

## Installation

### Prerequisites

- Python 3.8 or higher
- Administrative privileges (required for packet capturing and host blocking)
- For Linux: `iptables` for host blocking
- For Windows: Windows Firewall enabled

### Installing on Linux

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y python3-pip python3-dev libpcap-dev

# Download and install ARP Guard
git clone https://github.com/yourorg/arp-guard.git
cd arp-guard
pip3 install -r requirements.txt
sudo python3 setup.py install
```

### Installing on Windows

1. Download and install [Python 3.8+](https://www.python.org/downloads/)
2. Download and install [Npcap](https://npcap.com/#download)
3. Download ARP Guard:
   ```
   git clone https://github.com/yourorg/arp-guard.git
   cd arp-guard
   pip install -r requirements.txt
   python setup.py install
   ```

Alternatively, you can use the automated installer script:
```
powershell -ExecutionPolicy Bypass -File scripts/install_windows.ps1
```

## Getting Started

### Basic Usage

Start ARP Guard with default settings:

```bash
arp_guard start
```

This will start the detection module and begin monitoring for ARP spoofing attacks.

### Checking Status

To check the current status of ARP Guard:

```bash
arp_guard status
```

This will display:
- Current running state
- Detection statistics
- Blocked hosts (if any)
- System resource usage

### Stopping ARP Guard

To stop ARP Guard:

```bash
arp_guard stop
```

## Command Line Interface

ARP Guard provides a comprehensive CLI for controlling all aspects of the application.

### General Commands

| Command | Description |
|---------|-------------|
| `arp_guard --help` | Display help information |
| `arp_guard --version` | Display version information |
| `arp_guard start` | Start detection and monitoring |
| `arp_guard stop` | Stop all services |
| `arp_guard status` | Show current status |
| `arp_guard export` | Export logs and statistics |

### Configuration Commands

| Command | Description |
|---------|-------------|
| `arp_guard config show` | Show current configuration |
| `arp_guard config set <key> <value>` | Set configuration parameter |
| `arp_guard config reset` | Reset to default configuration |

### Remediation Commands

| Command | Description |
|---------|-------------|
| `arp_guard remediation show` | Show remediation settings |
| `arp_guard remediation set <setting> <value>` | Modify remediation settings |
| `arp_guard remediation whitelist add <mac> <ip>` | Add to whitelist |
| `arp_guard remediation whitelist remove <mac>` | Remove from whitelist |
| `arp_guard remediation whitelist list` | Show all whitelist entries |

## Web Dashboard

ARP Guard includes a web-based dashboard for monitoring and managing your network security.

### Starting the Dashboard

```bash
arp_guard dashboard
```

This will start the dashboard server on http://localhost:5000 by default.

### Dashboard Features

- **Real-time Monitoring**: View live detection and remediation statistics
- **Threat Visualization**: See threat levels and attack patterns
- **Blocked Hosts Management**: View and manage blocked hosts
- **Performance Metrics**: Monitor system resource usage
- **Whitelist Management**: Add or remove trusted devices

### Accessing from Other Devices

To access the dashboard from other devices on your network:

```bash
arp_guard dashboard --host 0.0.0.0 --port 5000
```

**Note**: Be sure to secure access to the dashboard, as it provides control over your network security.

## Configuration

ARP Guard's behavior can be customized through configuration settings.

### Configuration File Location

- Linux: `/etc/arp_guard/config.json` or `~/.config/arp_guard/config.json`
- Windows: `%APPDATA%\ARP Guard\config.json`

### Important Configuration Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `detection.enabled` | Enable/disable detection | `true` |
| `detection.sensitivity` | Detection sensitivity (1-10) | `5` |
| `remediation.auto_block` | Automatically block attackers | `true` |
| `remediation.block_duration` | Duration to block (seconds) | `1800` |
| `remediation.notify_admin` | Send notifications | `true` |
| `remediation.notification_email` | Email for notifications | `""` |
| `logging.level` | Logging verbosity | `"INFO"` |
| `dashboard.enabled` | Enable web dashboard | `true` |

### Sample Configuration

```json
{
  "detection": {
    "enabled": true,
    "sensitivity": 7,
    "check_interval": 5
  },
  "remediation": {
    "auto_block": true,
    "block_duration": 3600,
    "notify_admin": true,
    "notification_email": "admin@example.com"
  },
  "logging": {
    "level": "INFO",
    "file": "/var/log/arp_guard.log"
  }
}
```

## Remediation Features

ARP Guard provides automated remediation to protect your network from ARP spoofing attacks.

### Host Blocking

When a malicious host is detected, ARP Guard can automatically block it:

- **Linux**: Uses `iptables` to block both MAC and IP addresses
- **Windows**: Uses Windows Firewall to create blocking rules

### Whitelist Management

To prevent false positives, you can whitelist trusted devices:

```bash
# Add a device to whitelist
arp_guard remediation whitelist add 00:11:22:33:44:55 192.168.1.100

# Remove a device from whitelist
arp_guard remediation whitelist remove 00:11:22:33:44:55

# List all whitelisted devices
arp_guard remediation whitelist list
```

### Notification System

ARP Guard can send notifications when attacks are detected:

- Email notifications to specified address
- Severity-based notifications (high-threat attacks only, etc.)
- Configurable notification thresholds

## Troubleshooting

### Common Issues

#### ARP Guard Won't Start

- Check that you're running with administrative privileges
- Verify that the required dependencies are installed
- Check log files for specific error messages

#### No Packets Detected

- Ensure the network interface is properly configured
- Verify that Npcap/libpcap is correctly installed
- Check firewall settings that might block packet capture

#### Remediation Not Working

- Verify that you have administrative privileges
- Check that iptables/Windows Firewall is enabled
- Review the logs for blocking errors

### Log Files

Log files are essential for troubleshooting:

- Linux: `/var/log/arp_guard.log` or `~/.local/share/arp_guard/logs/`
- Windows: `%APPDATA%\ARP Guard\logs\`

### Diagnostic Commands

```bash
# Run diagnostic tests
arp_guard diagnose

# Show verbose logs
arp_guard --verbose status

# Export diagnostics information
arp_guard export --format json --output diagnostics.json
```

## FAQ

### General Questions

**Q: How does ARP Guard detect ARP spoofing?**  
A: ARP Guard monitors network traffic and uses several detection methods:
- Detects inconsistencies in MAC-IP mappings
- Identifies suspicious ARP packet patterns
- Monitors for unusual rate of ARP responses
- Detects gateway impersonation attempts

**Q: Will ARP Guard affect my network performance?**  
A: ARP Guard is designed to have minimal impact on network performance. It uses efficient packet filtering and processing algorithms to ensure overhead is kept to a minimum.

**Q: Can I use ARP Guard with a VPN?**  
A: Yes, ARP Guard works with VPNs. However, you may need to add your VPN adapter's MAC-IP pairs to the whitelist to prevent false positives.

### Technical Questions

**Q: How does the remediation system work?**  
A: When a suspicious host is detected, ARP Guard analyzes the threat level and, if configured, automatically blocks the host using platform-specific firewall rules.

**Q: Can ARP Guard protect against other types of attacks?**  
A: ARP Guard is specifically designed for ARP spoofing detection. It does not directly protect against other types of attacks, though preventing ARP spoofing helps secure against man-in-the-middle attacks.

**Q: Does ARP Guard work in virtualized environments?**  
A: Yes, ARP Guard works in virtualized environments, but special configuration may be required depending on the network configuration of the virtual machine.

**Q: Can I run ARP Guard on a Raspberry Pi?**  
A: Yes, ARP Guard can run on Raspberry Pi devices running Raspberry Pi OS or other Linux distributions that meet the prerequisites. 