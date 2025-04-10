# ARPGuard

## Overview

ARPGuard is a network security tool designed to scan networks, detect ARP spoofing attacks, and improve local network security. It offers both GUI and CLI interfaces for different use cases, with a focus on real-time monitoring and automated threat detection.

## Project Vision

ARPGuard aims to be the go-to platform for comprehensive, easily deployable, and highly scalable network threat detection and prevention. The platform focuses on:

* Unified Controller: Central management for distributed deployments
* Advanced Threat Detection: Machine learning and threat intelligence integration
* Ease of Adoption: Intuitive interfaces for all user levels
* Enterprise Readiness: Scalable architecture with enterprise-grade features

## Current Status

* **Product Version**: 0.3 (Enhanced UI and Core Features)
* **ML Components Version**: 0.3.0 (ML Enhancement Release)
* **Status**: Beta
* **Last Updated**: April 10, 2025

## Key Features

### Core Detection
* ARP spoofing detection with >97% accuracy
* Network scanning and topology discovery
* Advanced threat detection
* Performance monitoring with resource controls
* Comprehensive logging system
* Automated discovery features

### Machine Learning
* Anomaly detection
* Feature extraction
* Rule-based detection
* Model training framework
* Performance monitoring
* Test suite implementation

### User Interface
* Modern React-based GUI
* Real-time monitoring with WebSocket integration
* Role-based access control (RBAC)
* Advanced alert system with scheduling
* Configuration management
* Network topology visualization
* Data compression for efficient updates

### Security Features
* User authentication and authorization
* Role-based access control
* Secure WebSocket communication
* License validation and feature activation
* Automated threat response

## Technology Readiness Level (TRL)
* **Overall TRL**: 7
* **Core Components**: 7-8
* **ML Components**: 6-7
* **Integration**: 7
* **Documentation**: 8

## Technical Maturity
* Core functionality: 95%
* ML integration: 85%
* UI/UX: 95%
* Testing: 90%
* Documentation: 95%

## Requirements
* Python >= 3.8
* React >= 18.0
* FastAPI >= 0.68.0
* Scapy >= 2.4.5
* scikit-learn >= 1.0.2
* tensorflow >= 2.8.0
* SQLite >= 3.35.0

## Installation

```bash
# Clone the repository
git clone https://github.com/DITreneris/ARPGuard.git

# Install backend dependencies
pip install -r requirements.txt

# Install frontend dependencies
cd frontend
npm install

# Run the application
# Backend
python run.py

# Frontend (in separate terminal)
cd frontend
npm start
```

## Documentation
* [User Manual](docs/user_manual.md)
* [API Documentation](docs/api.md)
* [Architecture Overview](docs/architecture.md)
* [ML Integration Guide](docs/ml_integration.md)
* [Installation Guide](docs/installation.md)
* [Configuration Guide](docs/configuration.md)

## Contributing
We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

## Support
* [GitHub Issues](https://github.com/DITreneris/ARPGuard/issues)
* [Email Support](mailto:info@guardsandrobbers.com)
* [Website](https://www.guardsandrobbers.com)
* [Discord Community](https://discord.gg/arpguard)

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact
For questions or support, please:
* Open an issue in the [GitHub repository](https://github.com/DITreneris/ARPGuard/issues)
* Email us at [info@guardsandrobbers.com](mailto:info@guardsandrobbers.com)
* Visit our [website](https://www.guardsandrobbers.com)
* Join our [Discord community](https://discord.gg/arpguard)

## About
ARPGuard is developed and maintained by the Guards & Robbers team, focusing on providing robust network security solutions for organizations of all sizes.

## Features

- **Real-time Detection**: Monitors network traffic in real-time to detect ARP spoofing attempts
- **Multi-threaded Analysis**: Efficiently processes packets using a priority-based multi-threaded approach
- **Advanced Alert System**: Provides immediate alerts with scheduling and prioritization
- **Protection Mechanisms**: Offers various countermeasures to mitigate detected attacks
- **Resource-Aware**: Dynamically adjusts resource usage based on system load
- **Lite Mode**: Optimized for low-resource environments like IoT devices or older hardware
- **Extensible**: Modular design allows for easy extension with additional detection methods
- **Role-Based Access Control**: Secure user management with granular permissions
- **Network Topology Visualization**: Real-time network map with device discovery
- **Automated Discovery**: Automatic network device detection and classification
- **License Management**: Feature activation and validation system

## Installation

### Prerequisites

- Python 3.8 or higher
- Node.js 16 or higher
- Scapy library
- SQLite 3.35 or higher
- (Optional) psutil for resource monitoring

### Install from PyPI

```bash
pip install arpguard
```

### Install from Source

```bash
git clone https://github.com/DITreneris/arpguard.git
cd arpguard

# Install backend
pip install -e .

# Install frontend
cd frontend
npm install
```

## Quick Start

1. Start the backend server:

```bash
python -m arpguard
```

2. Start the frontend development server:

```bash
cd frontend
npm start
```

3. Access the web interface at http://localhost:3000

## Configuration

ARP Guard can be configured using a JSON configuration file:

```bash
python -m arpguard -c config.json
```

Example configuration:

```json
{
  "interface": "eth0",
  "detection_interval": 5,
  "auto_protect": false,
  "worker_threads": 4,
  "use_lite_version": false,
  "lite_mode_memory_threshold": 500,
  "websocket_port": 8080,
  "max_connections": 100,
  "enable_rbac": true,
  "license_key": "your_license_key"
}
```

See [Configuration Guide](docs/configuration.md) for all available options.

## Detection Modes

### Standard Mode
- Multi-threaded packet analysis
- Full heuristic detection capabilities
- Detailed statistics and reporting
- Adaptive resource management
- Real-time WebSocket updates
- Network topology visualization

### Lite Mode
- Single-threaded with minimal resource footprint
- Core detection capabilities for essential protection
- 5-10x lower memory usage than standard mode
- Ideal for IoT devices, resource-constrained systems, or background operation
- Basic real-time monitoring
- Essential alerting capabilities

See [Lite Mode Documentation](docs/lite_mode.md) for details.

## Usage Examples

### Background Monitoring

```bash
python -m arpguard --daemon
```

### Save Results to File

```bash
python -m arpguard -o results.json
```

### Enable Automatic Protection

```bash
python -m arpguard --auto-protect
```

### Start with WebSocket Support

```bash
python -m arpguard --websocket
```

## Documentation

- [User Guide](docs/user_guide.md)
- [Configuration Options](docs/configuration.md)
- [Detection Methods](docs/detection.md)
- [Lite Mode](docs/lite_mode.md)
- [API Reference](docs/api.md)
- [RBAC Guide](docs/rbac.md)
- [Network Topology Guide](docs/topology.md)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. See our [Contributing Guidelines](CONTRIBUTING.md) for more details.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 