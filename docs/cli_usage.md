# ARPGuard CLI Usage Guide

## Overview

The ARPGuard Command Line Interface (CLI) provides robust tools for network scanning, ARP spoofing detection, and security monitoring. This guide details how to use the CLI effectively.

## Installation

Ensure you have Python 3.8+ installed, then install ARPGuard:

```bash
# Install from PyPI
pip install arpguard

# Or install from source
git clone https://github.com/arpguard/arpguard.git
cd arpguard
pip install -e .
```

## Basic Commands

ARPGuard CLI provides the following main commands:

- `scan` - Scan network for devices
- `monitor` - Monitor for ARP spoofing attacks
- `analyze` - Analyze network traffic patterns (coming soon)
- `export` - Export scan or monitor results
- `config` - Manage configuration
- `help` - Show help information

Run `arpguard help` to view general help, or `arpguard help <command>` for command-specific help.

## Network Scanning

Scan your local network to identify connected devices:

```bash
# Basic scan with automatic subnet detection
arpguard scan

# Scan a specific subnet with a 3-second timeout
arpguard scan -s 192.168.1.0/24 -t 3

# Scan with specific ports and classify devices
arpguard scan -p 22,80,443,8080 -c

# Output results in different formats
arpguard scan -o json > devices.json
arpguard scan -o csv > devices.csv
```

### Scan Command Options

- `-i, --interface` - Network interface to use
- `-t, --timeout` - Timeout in seconds (default: 2)
- `-s, --subnet` - Subnet to scan (CIDR format)
- `-p, --ports` - Comma-separated list of ports to scan
- `-c, --classify` - Classify devices by type
- `-o, --output-format` - Output format (table, json, csv)

## ARP Cache Monitoring

Monitor your network for potential ARP spoofing attacks:

```bash
# Start monitoring with default settings
arpguard monitor

# Monitor with specific alert level and interface
arpguard monitor -a high -i eth0

# Monitor for a specific duration (in seconds)
arpguard monitor -d 300

# Output alerts in JSON format
arpguard monitor -o json > alerts.json
```

### Monitor Command Options

- `-i, --interface` - Network interface to monitor
- `-a, --alert-level` - Alert level (low, medium, high)
- `-d, --duration` - Duration in seconds (0 for continuous)
- `-o, --output-format` - Output format (normal, json)

## Configuration Management

ARPGuard uses a comprehensive configuration system that allows you to customize its behavior. The configuration is stored in YAML format and organized into sections.

### Managing Configuration

```bash
# List all configuration sections
arpguard config list

# List configuration for a specific section
arpguard config list scan

# Get a specific configuration value
arpguard config get scan default_timeout

# Set a configuration value
arpguard config set scan default_timeout 5

# Save the current configuration
arpguard config save

# Save to a specific file
arpguard config save -f ~/my_arpguard_config.yaml

# Reset a specific section to defaults
arpguard config reset -s scan

# Reset all configuration to defaults
arpguard config reset

# Create a default configuration file
arpguard config create -f ~/arpguard_default.yaml
```

### Configuration Structure

The configuration is organized into these main sections:

1. **general** - General application settings
   - `log_level` - Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
   - `log_file` - Log file path
   - `color_output` - Enable/disable colored output
   - `progress_indicators` - Enable/disable progress indicators

2. **scan** - Network scanning settings
   - `default_interface` - Default network interface
   - `default_timeout` - Default scan timeout in seconds
   - `default_ports` - Default ports to scan
   - `default_subnet` - Default subnet to scan
   - `classify_devices` - Enable/disable device classification
   - `output_format` - Default output format

3. **monitor** - ARP monitoring settings
   - `default_interface` - Default network interface
   - `alert_level` - Default alert level
   - `check_interval` - Interval between checks in seconds
   - `output_format` - Default output format
   - `known_devices_file` - File to store known devices

4. **analyze** - Traffic analysis settings
   - `pcap_dir` - Directory for PCAP files
   - `max_packets` - Maximum packets to analyze
   - `filter_expression` - Default filter expression
   - `output_format` - Default output format

5. **export** - Export settings
   - `default_format` - Default export format
   - `default_dir` - Default export directory
   - `include_metadata` - Include metadata in exports

### Configuration File Locations

ARPGuard searches for configuration files in the following locations (in order):

1. Path specified via the command line
2. `~/.config/arpguard/config.yaml`
3. `~/.arpguard/config.yaml`
4. `./config.yaml` (current directory)

If no configuration file is found, default values are used.

## Using Environment Variables

ARPGuard automatically detects certain environment variables:

- `ARPGUARD_CONFIG` - Path to configuration file
- `ARPGUARD_DEBUG` - Enable debug mode (set to any value)
- `ARPGUARD_NO_COLOR` - Disable colored output (set to any value)

## Examples

### Basic Network Security Audit

```bash
# 1. Scan the network and save results
arpguard scan -c -o json > network_inventory.json

# 2. Monitor for ARP spoofing for 10 minutes
arpguard monitor -a high -d 600 -o json > potential_threats.json

# 3. Analyze results (future functionality)
arpguard analyze -f potential_threats.json
```

### Continuous Network Monitoring

```bash
# Create a custom configuration
arpguard config set monitor alert_level high
arpguard config set monitor check_interval 1
arpguard config save

# Start continuous monitoring in the background
nohup arpguard monitor > arpguard_monitor.log 2>&1 &
```

## Troubleshooting

If you encounter issues:

1. Ensure you're running with sufficient permissions (admin/root)
2. Check your network interfaces with `arpguard scan --list-interfaces`
3. Enable debug logging with `arpguard config set general log_level DEBUG`
4. Review the logs in the location specified by your configuration

For further assistance, visit our GitHub repository or contact support. 