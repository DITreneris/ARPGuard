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

### Basic Monitoring
```bash
# Start ARP Guard in monitoring mode
arpguard monitor --interface eth0
```

### Attack Prevention
```bash
# Enable prevention mode
arpguard prevent --interface eth0
```

### View Statistics
```bash
# Display network statistics
arpguard stats
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