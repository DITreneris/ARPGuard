---
version: 10
last_modified: '2025-04-06T07:28:37.504882'
git_history:
- hash: 6a86e9ce0eddba890b90c8b1f9c8d192aaedae82
  author: User
  date: '2025-04-06T07:06:49+03:00'
  message: 'Initial commit: ARPGuard project with ML KPI monitoring system'
- hash: ef3989ccbe50479c66e030aaee698d8d2e12ac0d
  author: User
  date: '2025-04-06T06:36:00+03:00'
  message: Initial commit
- hash: 9084c731e73afe38f3a7b9ad5028d553d3efa4eb
  author: DITreneris
  date: '2025-04-06T06:16:52+03:00'
  message: 'Initial commit: Project setup with ML components'
---

# ARPGuard Architecture Overview

## System Architecture

ARPGuard is designed as a modular, extensible network security monitoring system with a focus on ARP spoofing detection and prevention. This document provides an overview of the architecture, components, and data flows.

```
┌───────────────────────────────────────────────────────────────┐
│                      User Interfaces                          │
│                                                               │
│  ┌───────────────┐               ┌───────────────────────┐    │
│  │ Command Line  │               │ Graphical Interface   │    │
│  │ Interface     │◄──────────────►  (Future)             │    │
│  └───────┬───────┘               └───────────────────────┘    │
│          │                                                     │
└──────────┼─────────────────────────────────────────────────────┘
           │
┌──────────▼─────────────────────────────────────────────────────┐
│                      Core Components                           │
│                                                                │
│  ┌────────────────┐   ┌─────────────────┐   ┌───────────────┐  │
│  │ Network        │   │ ARP Cache       │   │ Packet        │  │
│  │ Scanner        │◄──►  Monitor        │◄──►  Analyzer     │  │
│  └────────┬───────┘   └────────┬────────┘   └───────┬───────┘  │
│           │                    │                    │          │
│  ┌────────▼───────┐   ┌────────▼────────┐   ┌──────▼────────┐  │
│  │ Device         │   │ Threat          │   │ Traffic       │  │
│  │ Discovery      │◄──►  Detector       │◄──►  Analyzer     │  │
│  └────────────────┘   └─────────────────┘   └───────────────┘  │
│                                                                │
└────────────────────────────────┬───────────────────────────────┘
                                 │
┌────────────────────────────────▼───────────────────────────────┐
│                      Support Services                          │
│                                                                │
│  ┌────────────────┐   ┌─────────────────┐   ┌───────────────┐  │
│  │ Configuration  │   │ Logging &       │   │ Data          │  │
│  │ Manager        │   │ Monitoring      │   │ Storage       │  │
│  └────────────────┘   └─────────────────┘   └───────────────┘  │
│                                                                │
└────────────────────────────────┬───────────────────────────────┘
                                 │
┌────────────────────────────────▼───────────────────────────────┐
│                      ML Components (Future)                    │
│                                                                │
│  ┌────────────────┐   ┌─────────────────┐   ┌───────────────┐  │
│  │ Feature        │   │ ML Model        │   │ Anomaly       │  │
│  │ Extraction     │◄──►  Pipeline       │◄──►  Detection    │  │
│  └────────────────┘   └─────────────────┘   └───────────────┘  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

## Component Descriptions

### User Interfaces

#### Command Line Interface (CLI)
- Provides command-based access to all ARPGuard functionality
- Supports network scanning, monitoring, analysis, and configuration
- Offers various output formats (table, JSON, CSV)
- Implements progress reporting and colorized output
- Located in `app/components/cli.py`

#### Graphical Interface (Future)
- Will provide a dashboard-based view of network security status
- Planned for Lite Tier and above
- Will include real-time monitoring and alerts

### Core Components

#### Network Scanner
- Discovers devices on the network using ARP requests
- Maps IP addresses to MAC addresses
- Detects network topology and gateway devices
- Located in `app/components/network_scanner.py`

#### Device Discovery
- Builds on the Network Scanner to identify and classify devices
- Performs port scanning and OS fingerprinting
- Identifies device types based on open ports and MAC OUI
- Located in `app/components/device_discovery.py`

#### ARP Cache Monitor
- Monitors the ARP cache for changes and anomalies
- Detects ARP poisoning attempts
- Identifies MAC address conflicts and changes
- Located in `app/components/arp_cache_monitor.py`

#### Threat Detector
- Analyzes network traffic patterns for suspicious behavior
- Identifies known attack signatures
- Correlates multiple indicators for threat detection
- Located in `app/components/threat_detector.py`

#### Packet Analyzer
- Captures and analyzes network packets 
- Performs deep packet inspection
- Reconstructs network flows and sessions
- Located in `app/components/packet_analyzer.py`

#### Traffic Analyzer
- Analyzes traffic patterns over time
- Detects bandwidth anomalies and unusual connections
- Provides statistical analysis of network traffic
- Located in `app/components/traffic_analyzer.py`

### Support Services

#### Configuration Manager
- Manages application configurations using YAML format
- Provides validation and schema enforcement
- Supports multiple configuration locations
- Offers CLI interface for configuration management
- Located in `app/utils/config.py`

#### Logging & Monitoring
- Provides structured logging capabilities
- Supports multiple log levels and formats
- Enables performance monitoring and telemetry
- Located in `app/utils/logger.py`

#### Data Storage
- Stores scan results, monitoring data, and alerts
- Supports various export formats (JSON, CSV)
- Manages historical data and trend analysis
- Located in `app/utils/database.py`

### ML Components (Future)

#### Feature Extraction
- Extracts relevant features from network traffic
- Processes raw packet data into ML-ready formats
- Implements dimensionality reduction and feature selection
- Located in `app/ml/features/extractor.py`

#### ML Model Pipeline
- Implements the machine learning workflow
- Trains, validates, and deploys models
- Supports online learning for adaptive detection
- Located in `app/ml/pipeline/`

#### Anomaly Detection
- Detects unusual network patterns
- Identifies zero-day attacks without signatures
- Adapts to evolving network conditions
- Located in `app/ml/models/`

## Data Flows

### Network Scanning Flow

```
┌──────────────┐     ┌────────────────┐     ┌─────────────────┐
│ User         │     │ Network        │     │ Device          │
│ Interface    │────►│ Scanner        │────►│ Discovery       │
└──────────────┘     └────────────────┘     └─────────┬───────┘
                                                      │
┌──────────────┐     ┌────────────────┐     ┌─────────▼───────┐
│ Export       │◄────│ Data           │◄────│ Result          │
│ Format       │     │ Storage        │     │ Processing      │
└──────────────┘     └────────────────┘     └─────────────────┘
```

1. User initiates a scan through the CLI with parameters (subnet, timeout, etc.)
2. Network Scanner sends ARP requests and collects responses
3. Device Discovery classifies devices and performs additional probing
4. Results are processed, enhanced with metadata, and stored
5. Data is formatted according to user preferences and presented

### Monitoring Flow

```
┌──────────────┐     ┌────────────────┐     ┌─────────────────┐
│ User         │     │ ARP Cache      │     │ Threat          │
│ Interface    │────►│ Monitor        │────►│ Detector        │
└──────────────┘     └────────┬───────┘     └─────────┬───────┘
                              │                       │
                     ┌────────▼───────┐     ┌─────────▼───────┐
                     │ Alert          │◄────│ Analysis        │
                     │ System         │     │ Engine          │
                     └────────────────┘     └─────────────────┘
```

1. User starts monitoring through the CLI with parameters (interface, alert level, etc.)
2. ARP Cache Monitor continuously checks the system ARP cache for changes
3. Suspicious changes are passed to the Threat Detector for analysis
4. Threat Detector correlates information and determines threat level
5. Alerts are generated based on severity and user preferences

### Configuration Flow

```
┌──────────────┐     ┌────────────────┐     ┌─────────────────┐
│ User         │     │ CLI Config     │     │ Config          │
│ Interface    │────►│ Commands       │────►│ Manager         │
└──────────────┘     └────────────────┘     └─────────┬───────┘
                                                      │
                                            ┌─────────▼───────┐
                                            │ Config          │
                                            │ File (YAML)     │
                                            └─────────────────┘
```

1. User manages configuration through the CLI
2. Config commands process and validate input
3. Configuration Manager updates the configuration data
4. Changes are persisted to the configuration file in YAML format
5. Components access configuration via the Configuration Manager

## Component Interactions

### CLI and Core Components
The CLI acts as the primary interface between the user and the core components. It:
- Parses command-line arguments and validates input
- Routes commands to the appropriate component
- Formats output for user presentation
- Handles signals and interrupts

### Core Component Integration
Core components interact with each other through well-defined interfaces:
- Network Scanner provides device information to the Device Discovery module
- ARP Cache Monitor feeds data to the Threat Detector for analysis
- Packet Analyzer supplies processed packets to the Traffic Analyzer
- All components use Support Services for configuration, logging, and data storage

### Data Sharing
Components share data through standardized data structures:
- Device information is shared as dictionaries with consistent keys
- Alerts follow a standard format with severity, source, and message
- Network packets are shared using common packet representation formats
- Results are serializable to common formats like JSON for persistence

## Tiered Architecture

ARPGuard implements a tiered product strategy, with each tier building on the previous one:

### Demo Tier
- Core CLI interface
- Basic network scanning and device discovery
- ARP cache monitoring for spoofing detection
- Configuration management and export capabilities

### Lite Tier
- Basic GUI dashboard
- Single subnet monitoring and management
- Basic alert system with email notifications
- Port scanning and service identification

### Pro Tier
- Advanced dashboard with visualization
- Multi-subnet monitoring
- Machine learning integration for anomaly detection
- Threat intelligence system

### Enterprise Tier
- Controller platform for distributed deployment
- Role-based access control
- Integration framework for SIEM and other security tools
- Advanced reporting and compliance features

## Security Considerations

ARPGuard is designed with security in mind:
- All components run with the minimum required privileges
- User input is strictly validated to prevent injection attacks
- Sensitive information is handled securely and not exposed in logs
- Configuration files use proper permissions to prevent unauthorized access

## Performance Considerations

ARPGuard is optimized for efficient resource usage:
- Network scanning uses configurable timeouts and parallel processing
- Packet processing is optimized for high throughput
- Resource-intensive operations use threading for responsiveness
- Configuration options allow tuning for different environments

## Extensibility

The architecture is designed for extensibility:
- Modular design allows new components to be added easily
- Component interfaces are well-defined and documented
- Common utilities reduce code duplication
- Configuration-driven behavior enables adaptation without code changes

## Future Enhancements

Planned architectural improvements include:
- Plugin system for custom detection rules
- Distributed architecture for enterprise deployments
- Real-time analytics pipeline
- Enhanced machine learning capabilities
- API for third-party integration 