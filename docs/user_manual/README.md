---
version: 2
last_modified: '2025-04-06T06:34:37.206187'
git_history:
- hash: 9084c731e73afe38f3a7b9ad5028d553d3efa4eb
  author: DITreneris
  date: '2025-04-06T06:16:52+03:00'
  message: 'Initial commit: Project setup with ML components'
---

# ARPGuard User Manual

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Getting Started](#getting-started)
4. [Main Features](#main-features)
   - [Network Scanning](#network-scanning)
   - [ARP Spoofing Detection](#arp-spoofing-detection)
   - [Packet Capture and Analysis](#packet-capture-and-analysis)
   - [Attack Pattern Recognition](#attack-pattern-recognition)
   - [Threat Intelligence](#threat-intelligence)
   - [Network Topology Visualization](#network-topology-visualization)
   - [Vulnerability Scanning](#vulnerability-scanning)
   - [Defense Mechanisms](#defense-mechanisms)
   - [Reporting](#reporting)
5. [User Interface Guide](#user-interface-guide)
6. [Configuration Options](#configuration-options)
7. [Command Line Interface](#command-line-interface)
8. [Troubleshooting](#troubleshooting)
9. [Security Best Practices](#security-best-practices)
10. [FAQ](#faq)

## Introduction

ARPGuard is a comprehensive network security tool designed to protect your local network against ARP spoofing attacks and other network-based threats. This desktop application provides real-time monitoring, threat detection, and defense capabilities to ensure your network remains secure.

Key capabilities include:
- Network device discovery and monitoring
- ARP spoofing simulation and detection
- Comprehensive packet capture and analysis
- Attack pattern recognition
- Threat intelligence integration
- Network topology visualization
- Vulnerability scanning
- Automated defense mechanisms
- Detailed reporting and statistics

This user manual provides detailed information on installing, configuring, and using ARPGuard to secure your network.

## Installation

### System Requirements

- **Operating System**: Windows 10/11, Ubuntu 20.04+, Debian 11+, macOS 11+
- **Processor**: Dual-core 2GHz or better
- **Memory**: 4GB RAM minimum (8GB recommended)
- **Disk Space**: 200MB for application, plus additional space for packet captures
- **Network**: Ethernet or Wi-Fi adapter with promiscuous mode support
- **Dependencies**: Python 3.8 or later, WinPcap/Npcap (Windows), libpcap (Linux/macOS)

### Installation Steps

#### Windows

1. Download the latest installer from the [official website](https://arpguard.example.com/download).
2. Run the installer and follow the on-screen instructions.
3. If prompted, install Npcap if not already installed.
4. Launch ARPGuard from the Start menu.

#### Linux

1. Install dependencies:
   ```bash
   sudo apt update
   sudo apt install -y python3 python3-pip libpcap-dev
   ```

2. Install ARPGuard:
   ```bash
   sudo pip3 install arpguard
   ```

3. Launch the application:
   ```bash
   arpguard
   ```

#### macOS

1. Install dependencies via Homebrew:
   ```bash
   brew install python3 libpcap
   ```

2. Install ARPGuard:
   ```bash
   pip3 install arpguard
   ```

3. Launch the application:
   ```bash
   arpguard
   ```

#### From Source

1. Clone the repository:
   ```bash
   git clone https://github.com/arpguard/arpguard.git
   ```

2. Install dependencies:
   ```bash
   cd arpguard
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python run.py
   ```

## Getting Started

When you first launch ARPGuard, you'll be presented with a welcome screen and guided setup:

1. **Initial Configuration**: Set your preferences for automatic scanning, alerts, and data storage.
2. **Network Interface Selection**: Choose the network interface to monitor.
3. **Dashboard View**: The main dashboard will appear, showing the network status overview.

To perform your first network scan:

1. Click the "Scan Network" button in the toolbar.
2. Wait for the scan to complete (typically 10-30 seconds depending on network size).
3. Review the discovered devices in the device list.

## Main Features

### Network Scanning

ARPGuard provides advanced network scanning capabilities to discover and monitor devices on your local network.

**Using the Network Scanner:**

1. Click "Scan Network" in the toolbar or select "Scan" from the File menu.
2. The scan progress will be displayed in the status bar.
3. Once complete, all discovered devices will appear in the device list.

**Features:**
- Optimized batch scanning for large networks
- Device caching for faster repeat scans
- Customizable scan timeout
- Hostname resolution
- MAC vendor identification

![Network Scanning](screenshots/network_scanning.png)

### ARP Spoofing Detection

ARPGuard continuously monitors your network for signs of ARP spoofing attacks.

**Enabling ARP Spoofing Detection:**

1. Go to the "Threats" tab.
2. Click "Start Detection" in the toolbar.
3. ARPGuard will begin monitoring ARP traffic for suspicious activities.

**Features:**
- Real-time monitoring of ARP traffic
- Gateway protection
- MAC-IP binding verification
- Alerting on suspicious ARP activity
- Detailed evidence collection

![ARP Spoofing Detection](screenshots/arp_detection.png)

### Packet Capture and Analysis

The packet capture functionality allows detailed inspection of network traffic.

**Starting Packet Capture:**

1. Go to the "Packets" tab.
2. Select the interface and optional filter.
3. Click "Start Capture" to begin collecting packets.

**Features:**
- BPF filtering support
- Protocol detection and parsing
- Detailed packet inspection
- Hex view for raw packet data
- Protocol statistics and visualization

![Packet Analysis](screenshots/packet_analysis.png)

### Attack Pattern Recognition

ARPGuard can detect various attack patterns beyond simple ARP spoofing.

**Enabling Attack Recognition:**

1. Go to the "Attacks" tab.
2. Select the attack patterns to monitor.
3. Click "Start Pattern Detection" to begin.

**Detectable Attack Types:**
- ARP spoofing
- Port scanning
- DNS poisoning
- MAC flooding
- TCP SYN flooding
- Brute force attempts (SSH, SMB)
- MITM attacks

![Attack Recognition](screenshots/attack_recognition.png)

### Threat Intelligence

ARPGuard integrates with cloud-based threat intelligence sources to enhance threat detection.

**Using Threat Intelligence:**

1. Go to the "Intelligence" tab.
2. Click "Update Intelligence Data" to get the latest threat data.
3. Review malicious IPs, domains, and attack signatures.

**Intelligence Sources:**
- AbuseIPDB
- VirusTotal
- AlienVault OTX
- Emerging Threats

![Threat Intelligence](screenshots/threat_intelligence.png)

### Network Topology Visualization

Visualize your network layout and relationships between devices.

**Viewing Network Topology:**

1. Go to the "Topology" tab.
2. Choose a layout algorithm from the dropdown.
3. Hover over nodes to see device details.

**Features:**
- Multiple layout algorithms
- Device relationship visualization
- Gateway highlighting
- Threat highlighting
- Interactive node selection

![Network Topology](screenshots/network_topology.png)

### Vulnerability Scanning

Identify potential vulnerabilities in network devices.

**Running a Vulnerability Scan:**

1. Go to the "Vulnerabilities" tab.
2. Select scan targets from the device list.
3. Choose scan intensity.
4. Click "Start Scan" to begin.

**Scan Types:**
- Port scanning
- Service identification
- Common vulnerability checking
- Default credential testing
- SSH/SMB security verification

![Vulnerability Scanning](screenshots/vulnerability_scanning.png)

### Defense Mechanisms

ARPGuard offers various defense mechanisms to protect against detected threats.

**Activating Defenses:**

1. Go to the "Defense" tab.
2. Choose the defense strategy.
3. Click "Deploy Defense" to activate.

**Defense Types:**
- ARP spoofing countermeasures
- Static ARP entries
- Port isolation
- Traffic filtering
- Attack source blocking

![Defense Mechanisms](screenshots/defense_mechanisms.png)

### Reporting

Generate comprehensive reports on network status, threats, and security posture.

**Creating Reports:**

1. Go to the "Reports" tab.
2. Select report type and time period.
3. Click "Generate Report" to create.

**Report Types:**
- Network inventory
- Threat summary
- Traffic analysis
- Vulnerability assessment
- Security posture overview

![Reporting](screenshots/reporting.png)

## User Interface Guide

ARPGuard's interface is organized into several key areas:

### Main Window Components

- **Toolbar**: Quick access to common functions
- **Device List**: Shows all discovered network devices
- **Status Bar**: Displays current status and progress
- **Tab Panel**: Access different tool functions

### Tab Overview

- **Dashboard**: Overview of network status and security metrics
- **Network**: Device discovery and management
- **Packets**: Packet capture and analysis
- **Attacks**: Attack pattern detection
- **Intelligence**: Threat intelligence data
- **Topology**: Network visualization
- **Vulnerabilities**: Vulnerability scanning
- **Defense**: Deploy protective measures
- **Reports**: Generate and view reports
- **History**: View historical data and sessions

### Context Menus

Right-click on devices in the device list to access additional options:
- Device details
- Scan specific device
- Test vulnerability
- View traffic
- Apply defenses

## Configuration Options

ARPGuard provides extensive configuration options accessible through Settings.

### Accessing Settings

Click the "Settings" button in the toolbar or select "Settings" from the File menu.

### Configuration Categories

- **General**: Application behavior, UI options, startup preferences
- **Scanner**: Scan timeout, batch size, cache settings
- **Detection**: Sensitivity, alert thresholds, pattern matching settings
- **Capture**: Packet buffer size, BPF filters, storage options
- **Display**: Theme selection, table appearance, visualization options
- **Reports**: Default report settings, export formats, logo options
- **Advanced**: Performance tuning, debug options, custom command settings

## Command Line Interface

ARPGuard includes a command-line interface for automation and headless operation.

### Basic Usage

```bash
arpguard-cli [command] [options]
```

### Available Commands

- `scan`: Perform network scan
- `monitor`: Continuous network monitoring
- `detect`: ARP spoofing detection
- `capture`: Packet capture
- `report`: Generate reports
- `check`: Run vulnerability check

### Examples

Scan network and export results to CSV:
```bash
arpguard-cli scan --output=scan.csv
```

Monitor network for changes:
```bash
arpguard-cli monitor --interval=60 --alert-on-change
```

Detect ARP spoofing:
```bash
arpguard-cli detect --duration=300 --output=threats.json
```

## Troubleshooting

### Common Issues

#### Application Won't Start

- Verify Python version (3.8+)
- Check dependency installation
- Ensure WinPcap/Npcap is installed (Windows)
- Run with administrator/root privileges

#### Network Scan Not Finding Devices

- Check network interface selection
- Ensure promiscuous mode is supported
- Verify firewall settings
- Try increasing scan timeout

#### Packet Capture Not Working

- Verify permissions (admin/root required)
- Check interface selection
- Ensure packet capture library is installed
- Verify BPF filter syntax if using filters

#### Slow Performance

- Reduce scan batch size
- Disable unnecessary detection patterns
- Limit packet capture with specific filters
- Close unused tabs
- Check CPU and memory usage

### Diagnostic Tools

ARPGuard includes built-in diagnostic tools:

1. **Environment Check**: Verifies system requirements and dependencies
   - Go to Help > Check Environment

2. **Logging**: Enable detailed logging for troubleshooting
   - Go to Settings > Advanced > Enable Debug Logging

3. **Test Mode**: Run functionality tests
   - Go to Help > Run Diagnostics

## Security Best Practices

### Network Security Recommendations

1. **Keep Gateway Secured**
   - Change default passwords
   - Update firmware regularly
   - Enable available security features

2. **Device Management**
   - Maintain inventory of all network devices
   - Remove or isolate unknown devices
   - Use static IP assignments for critical devices

3. **Traffic Monitoring**
   - Regularly review network traffic patterns
   - Investigate unusual traffic spikes
   - Monitor for unauthorized access attempts

4. **Defense in Depth**
   - Combine multiple security measures
   - Segment network with VLANs where possible
   - Use encryption for sensitive traffic

### ARPGuard Best Practices

1. **Regular Scanning**
   - Schedule daily network scans
   - Compare results to identify changes

2. **Continuous Monitoring**
   - Enable automatic threat detection
   - Configure alert thresholds appropriately

3. **Response Planning**
   - Develop procedures for responding to alerts
   - Test defense mechanisms proactively
   - Document and review security incidents

4. **Keep Updated**
   - Update threat intelligence regularly
   - Apply application updates when available

## FAQ

### General Questions

**Q: Is ARPGuard free to use?**  
A: ARPGuard has both free and premium versions. The free version includes basic scanning and detection, while the premium version adds advanced features like threat intelligence integration and automated defenses.

**Q: Can ARPGuard protect my entire network?**  
A: Yes, when installed on a single computer with appropriate network visibility, ARPGuard can monitor and protect the entire local network.

**Q: Does ARPGuard work on wireless networks?**  
A: Yes, ARPGuard works on both wired and wireless networks, provided your wireless adapter supports monitor mode.

### Technical Questions

**Q: Can ARPGuard run without administrator privileges?**  
A: Some features like packet capture and defense mechanisms require administrator/root privileges, but basic scanning can run with regular user privileges.

**Q: Does ARPGuard work with VPNs?**  
A: Yes, but ARPGuard can only monitor the network traffic that passes through the monitored interface. If you're connected to a VPN, it will primarily monitor the VPN traffic.

**Q: Can ARPGuard detect all types of network attacks?**  
A: ARPGuard specializes in ARP-related attacks and common network threats. While it detects many attack types, no single tool can detect all possible attacks.

**Q: What data does ARPGuard collect?**  
A: ARPGuard collects network device information, packet headers for analysis, and detected threat data. Full packet contents are only captured temporarily for analysis and can be configured not to be stored. 