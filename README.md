# ARP Guard

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/guardsandrobbers/arpguard/ci.yml)](https://github.com/guardsandrobbers/arpguard/actions)
[![Coverage](https://img.shields.io/codecov/c/github/guardsandrobbers/arpguard)](https://codecov.io/gh/guardsandrobbers/arpguard)
[![Version](https://img.shields.io/github/v/release/guardsandrobbers/arpguard)](https://github.com/guardsandrobbers/arpguard/releases)

ARP Guard is an advanced network security solution specializing in real-time ARP spoofing detection and prevention. It leverages machine learning to identify and mitigate ARP-based attacks, providing comprehensive protection against man-in-the-middle attacks, ARP poisoning, and other network layer threats.

## Features

### Core Security
- 🔒 Real-time ARP spoofing detection with <1ms latency
- 🧠 AI-powered anomaly detection using machine learning
- 🛡️ Automated prevention mechanisms
- 📊 Comprehensive network monitoring
- 🔍 Deep packet inspection for ARP traffic

### Advanced Capabilities
- 🌐 Multi-tier deployment support
- 🔄 Real-time threat visualization
- 📈 Detailed attack analytics
- 🚨 Automated alerting system
- 🔗 SIEM platform integration

### Product Tiers
- **Demo Tier (Free)**: Basic functionality for testing and learning
- **Lite Tier ($49)**: Essential protection for small networks
- **Pro Tier ($149/year)**: Advanced features for SOC teams
- **Enterprise Tier (Custom)**: Full-scale deployment with premium support

## Quick Start

### Prerequisites
- Node.js 18.x or later
- Python 3.9 or later
- Network interface with promiscuous mode support
- Root/Administrator privileges

### Installation

1. Clone the repository:
```bash
git clone https://github.com/guardsandrobbers/arpguard.git
cd arpguard
```

2. Install dependencies:
```bash
# Install frontend dependencies
cd src/frontend
npm install

# Install backend dependencies
cd ../backend
pip install -r requirements.txt
```

3. Configure the application:
```bash
# Copy and edit configuration files
cp config.example.yaml config.yaml
cp .env.example .env
```

4. Start the services:
```bash
# Start backend service
python src/backend/main.py

# In a new terminal, start frontend service
cd src/frontend
npm start
```

## Configuration

### Network Settings
```yaml
network:
  interface: eth0
  promiscuous_mode: true
  detection_threshold: 0.8
  prevention_mode: auto
```

### Security Settings
```yaml
security:
  encryption: true
  authentication: true
  alert_threshold: high
  log_level: info
```

## Usage

ARP Guard provides a comprehensive command-line interface (CLI) for monitoring, configuring, and managing network security.

### CLI Commands Overview

```bash
# Show help and available commands
cmd /c run_arpguard.bat --help

# Show help for specific command
cmd /c run_arpguard.bat <command> --help
```

### Core Commands

#### Monitoring Commands

```bash
# Start ARP Guard monitoring
cmd /c run_arpguard.bat start [--interface INTERFACE] [--duration SECONDS] [--filter EXPRESSION]

# Start monitoring on specific interface for 5 minutes
cmd /c run_arpguard.bat start --interface eth0 --duration 300

# Stop ARP Guard monitoring
cmd /c run_arpguard.bat stop

# Show current ARP Guard status
cmd /c run_arpguard.bat status
```

#### Statistics and Analysis

```bash
# Show basic statistics
cmd /c run_arpguard.bat stats

# Show detailed statistics 
cmd /c run_arpguard.bat stats --detailed

# Export detection results
cmd /c run_arpguard.bat export --format csv --output results.csv
# Supported formats: csv, json, xml
```

#### Configuration Management

```bash
# Show current configuration
cmd /c run_arpguard.bat config show

# Update configuration setting
cmd /c run_arpguard.bat config set <key> <value>

# Example: Set detection sensitivity
cmd /c run_arpguard.bat config set detection.sensitivity high
```

#### Remediation Management

```bash
# Show remediation settings
cmd /c run_arpguard.bat remediation show

# Configure remediation settings
cmd /c run_arpguard.bat remediation set auto_block true
cmd /c run_arpguard.bat remediation set block_duration 3600

# Manage whitelist entries
cmd /c run_arpguard.bat remediation whitelist add 00:11:22:33:44:55 192.168.1.100
cmd /c run_arpguard.bat remediation whitelist list
cmd /c run_arpguard.bat remediation whitelist remove 00:11:22:33:44:55
```

#### Telemetry Management

```bash
# Show telemetry status
cmd /c run_arpguard.bat telemetry show

# Enable telemetry collection
cmd /c run_arpguard.bat telemetry enable

# Disable telemetry collection
cmd /c run_arpguard.bat telemetry disable
```

### CLI Options

ARP Guard supports several global options that can be used with any command:

```bash
# Show version information
cmd /c run_arpguard.bat --version

# Change output format
cmd /c run_arpguard.bat --output-format json status
# Supported formats: json, csv, table, pretty, text

# Run in interactive mode
cmd /c run_arpguard.bat --interactive
```

### Performance Options

These options help optimize the application for your environment:

```bash
# Run with performance optimization
cmd /c run_arpguard.bat --optimize-perf

# Disable packet sampling to analyze all packets
cmd /c run_arpguard.bat --disable-sampling

# Set custom sampling ratio (0.1 to 1.0)
cmd /c run_arpguard.bat --sampling-ratio 0.25

# Specify number of worker threads
cmd /c run_arpguard.bat --threads 2
```

You can combine performance options with CLI commands:

```bash
# Run with performance optimization and start monitoring
cmd /c run_arpguard.bat --optimize-perf start --interface eth0
```

### Examples

Here are some common usage scenarios:

```bash
# Start monitoring on default interface with optimized performance
cmd /c run_arpguard.bat --optimize-perf start

# Show current status in JSON format
cmd /c run_arpguard.bat --output-format json status

# Export detection results to CSV file
cmd /c run_arpguard.bat export --format csv --output arp_threats.csv

# Configure auto-blocking and check remediation settings
cmd /c run_arpguard.bat remediation set auto_block true
cmd /c run_arpguard.bat remediation show

# Run monitoring for 10 minutes then automatically stop
cmd /c run_arpguard.bat start --duration 600
```

## API Integration

### REST API Endpoints
```bash
# Get network status
GET /api/v1/network/status

# Get detected threats
GET /api/v1/threats

# Configure prevention rules
POST /api/v1/rules
```

### WebSocket Events
```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  // Handle real-time updates
};
```

## Development

### Project Structure
```
arpguard/
├── src/
│   ├── frontend/          # React frontend
│   ├── backend/           # Python backend
│   ├── core/              # Core security logic
│   └── tests/             # Test suite
├── docs/                  # Documentation
└── config/               # Configuration files
```

### Running Tests
```bash
# Run all tests
npm test

# Run specific test suite
npm test -- --testPathPattern=network
```

## Security

### Best Practices
1. Run ARP Guard with minimal required privileges
2. Regularly update to the latest version
3. Monitor system logs for suspicious activity
4. Configure appropriate alert thresholds
5. Use strong authentication for API access

### Reporting Issues
Please report security vulnerabilities to info@guardsandrobbers.com

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 📧 Email: info@guardsandrobbers.com
- 📖 Web: https://www.guardsandrobbers.com
- 💬 Discord: [Guards & Robbers Community](https://discord.gg/guardsandrobbers)

## Acknowledgments

- Network security researchers
- Open-source community
- Beta testers and contributors

---

Made with ❤️ by the Guards & Robbers Team 