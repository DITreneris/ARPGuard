# ARPGuard

## Overview
ARPGuard is a network security tool designed to scan networks, detect ARP spoofing attacks, and improve local network security. It offers both GUI and CLI interfaces for different use cases.

## Project Vision
ARPGuard aims to be the go-to platform for comprehensive, easily deployable, and highly scalable network threat detection and prevention. The platform focuses on:

- Unified Controller: Central management for distributed deployments
- Advanced Threat Detection: Machine learning and threat intelligence integration
- Ease of Adoption: Intuitive interfaces for all user levels
- Enterprise Readiness: Scalable architecture with enterprise-grade features

## Current Status
- **Product Version**: 0.2 (Enhanced UI and Core Features)
- **ML Components Version**: 0.3.0 (ML Enhancement Release)
- **Status**: Beta
- **Last Updated**: April 9, 2025

## Key Features

### Core Detection
- ARP spoofing detection
- Network scanning
- Basic threat detection
- Performance monitoring
- Logging system

### Machine Learning
- Anomaly detection
- Feature extraction
- Rule-based detection
- Model training framework
- Performance monitoring
- Test suite implementation

### User Interface
- Modern GUI design
- CLI interface
- Real-time monitoring
- Alert system
- Configuration management

## Technology Readiness Level (TRL)
- **Overall TRL**: 6
- **Core Components**: 6-7
- **ML Components**: 5-6
- **Integration**: 6
- **Documentation**: 7

## Technical Maturity
- Core functionality: 85%
- ML integration: 75%
- UI/UX: 90%
- Testing: 80%
- Documentation: 95%

## Requirements
- Python >= 3.8
- PyQt5 >= 5.15.2
- Scapy >= 2.4.5
- scikit-learn >= 1.0.2
- tensorflow >= 2.8.0

## Installation
```bash
# Clone the repository
git clone https://github.com/DITreneris/ARPGuard.git

# Install dependencies
pip install -r requirements.txt

# Run the application
python run_cli.py
```

## Documentation
- [User Manual](docs/user_manual/README.md)
- [API Documentation](docs/api_documentation.md)
- [Architecture Overview](docs/architecture_overview.md)
- [ML Integration Guide](docs/ml_integration_guide.md)

## Contributing
We welcome contributions! Please see our [Contributing Guidelines](docs/guidelines.md) for details.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact
For questions or support, please open an issue in the GitHub repository. 