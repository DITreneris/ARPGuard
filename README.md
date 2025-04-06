# ARPGuard - Network Security Tool
**Version: 2.4**
**Last Updated: April 6, 2025**

ARPGuard is a network security tool designed to scan networks, detect ARP spoofing attacks, and improve local network security. It offers both GUI and CLI interfaces for different use cases.

## Project Vision

ARPGuard aims to be the go-to platform for comprehensive, easily deployable, and highly scalable network threat detection and prevention. The platform focuses on:

- **Unified Controller**: Central management for distributed deployments
- **Advanced Threat Detection**: Machine learning and threat intelligence integration
- **Ease of Adoption**: Intuitive interfaces for all user levels
- **Enterprise Readiness**: Scalable architecture with enterprise-grade features

## Version Status

- **Current Version:** 0.2 (Enhanced UI and Core Features)
- **Next Release:** 0.3 (Comprehensive Packet Analysis) - Coming Q3 2024
- **Development Status:** 92.7% test coverage achieved
- **Roadmap Phase:** Phase 1 (Q2-Q4 2025) - Strengthening Core & Building Foundations
- **ML Development:** Hybrid model architecture implemented with dual detection approach
- **Documentation:** Comprehensive version-controlled documentation with timestamps

## Key Features

- Network scanning to identify all devices
- ARP spoofing detection and prevention
- Packet analysis and visualization
- Attack pattern recognition
- Defense mechanisms against network attacks
- Vulnerability scanning
- Threat intelligence integration
- Network topology visualization
- Statistical analysis of traffic patterns
- Multiple export formats (HTML, PDF, CSV, JSON)
- Light/Dark theme support
- Comprehensive documentation system with version tracking
- **NEW: Machine Learning based attack detection**

## Performance Metrics

- Sub-second response time for UI operations
- < 5% CPU utilization during monitoring
- < 500MB memory usage for base installation
- Support for 10,000+ devices in enterprise deployments
- Packet processing rate > 100,000 packets/second

## Security KPIs

- 95% detection rate for known attack vectors
- < 30 seconds mean time to detect critical threats
- < 5 minutes mean time to respond to threats
- < 5% false positive rate
- 99.9% system uptime

## Current Development Focus (Q2 2025)

- Hybrid ML model architecture implementation
- Two-layer detection approach (rules + ML)
- Ensemble methods (Random Forest, Decision Trees)
- Performance optimization for real-time processing
- Comprehensive documentation management system

## Machine Learning Detection Layer

ARPGuard now includes a sophisticated ML-based detection layer that complements traditional rule-based detection:

### Key ML Features:

- **Dual Detection Approach**: Anomaly detection + attack classification
- **Multiple Attack Type Detection**: Identifies spoofing, MITM, DoS, and reconnaissance
- **Automatic Learning**: Adapts to your network's specific traffic patterns
- **Zero-Day Detection**: Identifies previously unknown attack variants
- **Feature Importance Analysis**: Explains why traffic was flagged as malicious
- **Interactive ML Dashboard**: Visualize and manage ML detection capabilities

### ML-Based Detection Types:

- **Anomaly Detection**: Identifies statistical outliers using Isolation Forest
- **Classification**: Categorizes attacks using Random Forest classifier
- **Confidence Scoring**: Provides probability estimates for each detection
- **Severity Assessment**: Automatically assigns severity based on attack type

For more details, see the [ML Detection documentation](docs/ml_detection.md).

## ML KPI Monitoring Tool

ARPGuard includes a comprehensive ML KPI monitoring system to track the development, technical performance, operational health, and business impact of the machine learning module. The system is designed to align with the project health assessment documented in `docs/project_health.md`.

### Key Features:

- Track development progress of ML components
- Monitor technical performance metrics (accuracy, latency, resource usage)
- Assess operational integration and stability
- Measure business impact and adoption
- Generate visual dashboards and trend analysis
- Support data-driven decision making for ML development

### Usage:

```bash
# Import KPI data from YAML file
python scripts/monitor_ml_kpis.py import --file data/ml_kpis_sample.yaml

# Update a specific KPI
python scripts/monitor_ml_kpis.py update --category development_kpis --name ml_environment --value 20.0

# Generate reports
python scripts/monitor_ml_kpis.py report

# Generate specific charts
python scripts/monitor_ml_kpis.py chart --category technical_kpis
```

The tool stores KPI data in JSON format and generates HTML dashboards with interactive charts. Reports are saved to the `reports/ml_kpis` directory.

## Memory Management

ARPGuard implements an advanced memory management system for packet capture operations, ensuring optimal performance and stability even during intensive network monitoring sessions.

### Key Features

- **Adaptive Memory Management**: Automatically adjusts behavior based on system memory conditions
- **Packet Sampling**: Intelligently samples packets during high memory pressure situations
- **Memory-Aware Storage**: Dynamically adjusts buffer sizes and history retention based on available memory
- **Packet Deduplication**: Identifies and eliminates duplicate packets to reduce memory usage
- **Proactive Memory Optimization**: Runs garbage collection and memory reclamation at optimal intervals
- **Memory Pressure Monitoring**: Provides real-time monitoring and alerting for memory usage
- **Configurable Memory Strategies**: Supports different memory management strategies (Aggressive, Balanced, Conservative, Adaptive)

### Configuration

Memory management settings can be customized in `config/memory_config.yml`.

For detailed information, see the [Memory Management documentation](docs/memory_management.md).

## Installation

### Prerequisites

1. Python 3.7 or higher
2. WinPcap/Npcap (for packet capture on Windows)
   - Download and install Npcap from https://npcap.com/#download
   - Make sure to select "Install Npcap in WinPcap API-compatible Mode" during installation
3. Required Python packages

### Installing Dependencies

```bash
# Install all dependencies from requirements.txt
python -m pip install -r requirements.txt

# Or install core dependencies manually
python -m pip install scapy netifaces psutil netaddr

# For GUI version (required for all advanced features)
python -m pip install PyQt5==5.15.2 pyqtwebengine matplotlib pyqtgraph

# For development and testing
python -m pip install pytest pytest-qt pytest-cov mock psutil
```

## Usage

### CLI Version

The command-line interface version works without GUI dependencies and is ideal for headless servers or quick scans.

```bash
# Show help
python cli_tool.py --help

# Scan the network
python cli_tool.py --scan

# Specify a custom network range
python cli_tool.py --scan --network 192.168.1.0/24

# Monitor for ARP spoofing attacks
python cli_tool.py --monitor

# Monitor for 60 seconds
python cli_tool.py --monitor --duration 60

# Enable debug logging
python cli_tool.py --scan --debug

# Enable ML-based detection
python cli_tool.py --monitor --ml-detection

# Test ML detection with sample data
python scripts/test_ml_detection.py
```

### Layer 3 CLI Version (No WinPcap/Npcap Required)

If you're experiencing issues with WinPcap/Npcap or receiving "No libpcap provider available" errors, you can use the Layer 3 version of the CLI tool which works without packet capture drivers:

```bash
# Show help
python cli_tool_l3.py --help

# Basic network scan (device discovery only)
python cli_tool_l3.py --scan

# Scan with common port checks
python cli_tool_l3.py --scan --scan-type ports

# Full scan with port scanning, latency, traceroute
python cli_tool_l3.py --scan --scan-type full --max-ports 1000

# Scan with custom ports
python cli_tool_l3.py --scan --ports "22,80,443"

# Scan with port ranges
python cli_tool_l3.py --scan --ports "20-25,80,443-445"

# Continuous network monitoring (detects new/changed/missing devices)
python cli_tool_l3.py --monitor

# Set custom monitoring interval (in seconds)
python cli_tool_l3.py --monitor --monitor-interval 30

# Monitor specific network range with export to JSON
python cli_tool_l3.py --monitor --network 192.168.1.0/24 --export json

# Specify a custom network range
python cli_tool_l3.py --scan --network 192.168.1.0/24

# Export results to JSON or CSV
python cli_tool_l3.py --scan --export json
python cli_tool_l3.py --scan --export csv --output my_scan.csv

# Enable debug logging
python cli_tool_l3.py --scan --debug
```

### GUI Version

The GUI version provides a comprehensive interface with visualization and advanced features.

```bash
# Launch the GUI application
python run.py

# Run the test suite
python run.py test

# Run the test suite with coverage report
python run.py test --coverage

# Update MAC vendor database
python run.py update --mac-vendors

# Show current configuration
python run.py config --show

# Set configuration value
python run.py config --set detector.start_on_launch true
```

## Documentation

ARPGuard features a comprehensive documentation system with:

- Version control and timestamps
- Status tracking for documentation files
- Automatic validation and quality checks
- Multi-language support
- Searchable technical and user documentation

To view documentation:

```bash
# Generate documentation
python scripts/generate_docs.py

# Check document status
python scripts/version_docs.py scan

# View version history of a document
python scripts/version_docs.py history docs/path/to/document.md

# Generate status report
python scripts/generate_status_report.py
```

## Documentation Management

The ARPGuard project includes several scripts to help manage documentation:

- **version_docs.py**: Tracks document versions and updates
- **validate_docs.py**: Validates documentation files for formatting issues
- **fix_doc_dates.py**: Fixes date inconsistencies across documentation files
- **generate_status_report.py**: Generates project status reports

## Development

### Project Structure

```
ARPGuard/
├── app/
│   ├── components/  # Core components
│   ├── ml/          # Machine learning models
│   └── utils/       # Utility functions
├── docs/            # Documentation
├── scripts/         # Utility scripts
├── tests/           # Test suite
└── run.py           # Main entry point
```

### Testing

ARPGuard has an extensive test suite covering core components, UI elements, and performance:

```bash
# Run all tests
python -m pytest

# Run specific test category
python -m pytest tests/test_ui_components.py
python -m pytest tests/test_performance_benchmarks.py 

# Run tests with coverage
python -m pytest --cov=app --cov-report=term-missing

# Check the test environment setup
python tests/check_environment.py
```

Current test coverage:
- Core Component Tests: 100% (15/15)
- Intelligence Component Tests: 100% (6/6)  
- UI Component Tests: 79% (33/42)
- Integration Tests: 100% (16/16)
- System Tests: 100% (15/15)
- Performance Benchmarks: 100% (12/12)

Overall test coverage: 92.7% (114/123 tests)

## Roadmap Highlights

### Phase 1 (Q2-Q4 2024)
- ✅ Core security enhancements
- ✅ Performance and stability improvements
- ✅ Robust testing and QA
- 🔄 Controller MVP development
- ✅ Refined user experience
- 🔄 Hybrid ML model architecture

### Phase 2 (Q1-Q3 2025)
- 🔄 Multi-site management
- ✅ Auto-discovery and topology mapping
- ✅ ML-based anomaly detection
- ✅ Threat feeds integration
- 🔄 Enterprise integrations
- 🔄 Scalability improvements

### Phase 3 (Q4 2025-Q2 2026)
- 🔄 Product tiers and pricing
- 🔄 Professional services
- 🔄 Global reach and compliance
- 🔄 Developer community

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- Scapy project for packet manipulation
- PyQt5 for the GUI framework
- Open threat intelligence sources

## Official Resources

* **GitHub Repository**: [ARPGuard on GitHub](https://github.com/DITreneris/ARPGuard)
* **Official Website**: [Guards and Robbers](https://guardsandrobbers.com/)
* **Documentation**: [ARPGuard Documentation](https://guardsandrobbers.com/docs)
* **Support**: [Contact Support](https://guardsandrobbers.com/support)

## Website Integration

ARPGuard is officially supported and documented on [guardsandrobbers.com](https://guardsandrobbers.com/). The website provides:

* Latest product updates and announcements
* Comprehensive documentation and tutorials
* Community support and forums
* Enterprise support options
* Professional services information

**Last Updated: April 6, 2024** 