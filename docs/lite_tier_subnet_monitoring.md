# ARPGuard Lite Tier: Single-Subnet Monitoring Design

## Overview

The ARPGuard Lite Tier enhances the Demo Tier's basic monitoring capabilities with comprehensive single-subnet monitoring. This functionality provides continuous visibility into network devices, their relationships, and potential security threats within a focused network segment. This document outlines the design, components, and implementation approach for effective subnet monitoring.

## Design Goals

- **Complete Visibility**: Maintain a comprehensive inventory of all subnet devices
- **Real-Time Awareness**: Provide up-to-date status and activity information
- **Historical Tracking**: Record device presence and behavior over time
- **Relationship Mapping**: Identify and visualize device interactions
- **Resource Efficiency**: Minimize network and system resource usage
- **Automatic Discovery**: Continuously discover new devices joining the subnet
- **User Accessibility**: Present monitoring data in an intuitive, actionable format

## Components and Functionality

### 1. Network Topology Management

The subnet monitoring system will maintain and visualize the network topology:

#### Subnet Configuration

- Support for standard CIDR notation (e.g., 192.168.1.0/24)
- Automatic gateway detection
- Support for IPv4 (with planned IPv6 support in future releases)
- Subnet boundary enforcement

#### Topology Discovery

- Automatic mapping of network structure
- Identification of key infrastructure (routers, switches, servers)
- Detection of network segments and VLANs
- Identification of connectivity patterns and bottlenecks

#### Visualization

- Interactive network map with device relationships
- Hierarchical view of network structure
- Filtering by device type, status, or activity
- Heat mapping for traffic or threat visualization

### 2. Device Inventory System

The device inventory will track all hosts on the subnet:

#### Device Records

Each device record will contain:

```json
{
  "device_id": "unique-identifier",
  "ip_address": "192.168.1.10",
  "mac_address": "00:11:22:33:44:55",
  "hostname": "device-hostname",
  "vendor": "Device Manufacturer",
  "device_type": "server|workstation|mobile|iot|infrastructure|unknown",
  "first_seen": "ISO-8601 timestamp",
  "last_seen": "ISO-8601 timestamp",
  "status": "online|offline|intermittent",
  "open_ports": [22, 80, 443],
  "os_info": "Operating System information",
  "tags": ["trusted", "critical", "guest"],
  "notes": "User-provided notes about this device",
  "location": "Physical location information",
  "risk_score": 25,
  "trust_level": "trusted|known|unknown|suspicious",
  "history": [
    {
      "timestamp": "ISO-8601 timestamp",
      "ip_address": "192.168.1.15",
      "mac_address": "00:11:22:33:44:55",
      "status": "online"
    }
  ]
}
```

#### Device Classification

- Automatic categorization based on fingerprinting
- Rule-based classification system
- User-defined tagging and classification
- Trust level assignment and management

#### Inventory Management

- Persistent storage of device information
- Aging and archiving of inactive devices
- Correlation of devices across IP changes
- Import/export of inventory data

### 3. Continuous Monitoring

The continuous monitoring system will provide real-time awareness:

#### Active Monitoring

- Configurable ping sweeps for presence detection
- Port scanning for service discovery
- Service identification and fingerprinting
- Performance metrics collection (response time, stability)

#### Passive Monitoring

- ARP traffic monitoring
- Device behavior pattern analysis
- Communication relationship mapping
- Bandwidth utilization tracking

#### Monitoring Schedules

- Configurable scan intervals (default: 5 minutes)
- Adaptive monitoring based on device type and importance
- Low-impact monitoring for sensitive devices
- Immediate scanning of new devices

### 4. Historical Data Management

The historical data system will track changes over time:

#### Change Tracking

- IP address changes
- MAC address changes
- Status changes (online/offline)
- Service/port availability changes
- Trust level changes

#### Timeline Visualization

- Device history timeline
- Network-wide activity timeline
- Correlation of events across devices
- Pattern identification in historical data

#### Data Retention

- Configurable retention periods by data type
- Data summarization for long-term storage
- Export of historical data for external analysis
- Backup and restore functionality

### 5. Traffic Analysis

The traffic analysis system will provide insights into network communications:

#### Traffic Monitoring

- ARP traffic patterns
- Device communication relationships
- Bandwidth utilization by device
- Protocol distribution analysis

#### Anomaly Detection

- Unusual traffic patterns
- Unexpected device communications
- Bandwidth spikes or anomalies
- Protocol violations or misuse

#### Visualization

- Communication matrices showing device interactions
- Traffic flow diagrams
- Bandwidth utilization graphs
- Protocol distribution charts

## Implementation Architecture

### Component Structure

The single-subnet monitoring functionality will be implemented with these components:

1. **SubnetManager**: Defines and manages the subnet boundary
2. **DeviceInventory**: Maintains the database of known devices
3. **ActiveScanner**: Performs active discovery and monitoring
4. **PassiveMonitor**: Listens for network traffic and device activities
5. **TopologyMapper**: Maps and visualizes network relationships
6. **HistoryTracker**: Records and manages historical data
7. **TrafficAnalyzer**: Analyzes communication patterns

### Class Design

Key classes and their responsibilities:

```python
class SubnetManager:
    """Manages the target subnet for monitoring"""
    def set_target_subnet(self, cidr)
    def get_subnet_info()
    def is_ip_in_subnet(self, ip_address)
    def get_gateway_info()
    def estimate_subnet_size()

class DeviceInventory:
    """Manages the device database"""
    def add_device(self, device_data)
    def update_device(self, device_id, updates)
    def get_device(self, identifier)  # by IP, MAC, or ID
    def get_all_devices(self, filters=None)
    def set_device_status(self, device_id, status)
    def set_trust_level(self, device_id, level)
    def add_device_tag(self, device_id, tag)
    def calculate_risk_score(self, device_id)

class ActiveScanner:
    """Performs active network scanning"""
    def start_scanning(self, interval=300)
    def stop_scanning()
    def scan_subnet(self, scan_type="quick")
    def scan_device(self, device_id, scan_type="full")
    def discover_services(self, device_id)
    def fingerprint_device(self, device_id)

class PassiveMonitor:
    """Performs passive monitoring of network traffic"""
    def start_monitoring(self, interface)
    def stop_monitoring()
    def register_packet_handler(self, protocol, handler)
    def get_traffic_statistics()
    
class TopologyMapper:
    """Maps network topology and relationships"""
    def generate_network_map()
    def identify_infrastructure_devices()
    def map_device_relationships()
    def get_communication_matrix()
    def export_topology(self, format="json")

class HistoryTracker:
    """Tracks historical device and network data"""
    def record_device_change(self, device_id, change_type, data)
    def get_device_history(self, device_id, start_time=None, end_time=None)
    def get_network_timeline(self, start_time=None, end_time=None)
    def purge_old_records(self, older_than)
    def export_history(self, device_id=None, format="json")

class TrafficAnalyzer:
    """Analyzes network traffic patterns"""
    def analyze_traffic_pattern(self, device_id=None)
    def detect_traffic_anomalies()
    def get_bandwidth_usage(self, device_id=None)
    def identify_communication_groups()
```

### Database Schema

The single-subnet monitoring will use an SQLite database with the following tables:

```sql
-- Device inventory table
CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,
    ip_address TEXT,
    mac_address TEXT,
    hostname TEXT,
    vendor TEXT,
    device_type TEXT,
    first_seen TEXT,
    last_seen TEXT,
    status TEXT,
    os_info TEXT,
    risk_score INTEGER,
    trust_level TEXT,
    notes TEXT,
    location TEXT,
    created_at TEXT,
    updated_at TEXT
);

-- Device ports table
CREATE TABLE device_ports (
    port_id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT,
    port_number INTEGER,
    protocol TEXT,
    service TEXT,
    version TEXT,
    first_seen TEXT,
    last_seen TEXT,
    status TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(device_id)
);

-- Device history table
CREATE TABLE device_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT,
    timestamp TEXT,
    change_type TEXT,
    old_value TEXT,
    new_value TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(device_id)
);

-- Device tags table
CREATE TABLE device_tags (
    device_id TEXT,
    tag TEXT,
    PRIMARY KEY (device_id, tag),
    FOREIGN KEY (device_id) REFERENCES devices(device_id)
);

-- Communication relationships table
CREATE TABLE device_communications (
    communication_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_device_id TEXT,
    target_device_id TEXT,
    first_seen TEXT,
    last_seen TEXT,
    protocol TEXT,
    port INTEGER,
    frequency INTEGER,
    bytes_transferred INTEGER,
    FOREIGN KEY (source_device_id) REFERENCES devices(device_id),
    FOREIGN KEY (target_device_id) REFERENCES devices(device_id)
);

-- Network scan logs
CREATE TABLE scan_logs (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT,
    start_time TEXT,
    end_time TEXT,
    devices_found INTEGER,
    new_devices INTEGER,
    changed_devices INTEGER
);

-- Create indexes for performance
CREATE INDEX idx_devices_ip ON devices(ip_address);
CREATE INDEX idx_devices_mac ON devices(mac_address);
CREATE INDEX idx_devices_status ON devices(status);
CREATE INDEX idx_device_history_device_id ON device_history(device_id);
CREATE INDEX idx_device_history_timestamp ON device_history(timestamp);
CREATE INDEX idx_device_communications_source ON device_communications(source_device_id);
CREATE INDEX idx_device_communications_target ON device_communications(target_device_id);
```

## User Interface Integration

### Subnet Dashboard

The Subnet Dashboard will provide an overview of the monitored subnet:

- Subnet summary statistics
- Online/offline device counts
- Recent network changes
- Current scanning status
- Key metrics and indicators

### Network Map View

The Network Map will visualize the subnet topology:

- Interactive device node graph
- Color-coded device status
- Relationship lines showing communications
- Filtering and focusing options
- Device grouping and organization

### Device Inventory View

The Device Inventory will list and manage all subnet devices:

- Sortable and filterable device list
- Detailed device information panel
- Trust level management
- Tagging and categorization
- Historical timeline view

### Communication Matrix

The Communication Matrix will show device interactions:

- Grid view of device-to-device communications
- Heat mapping by frequency or volume
- Filtering by protocol or time range
- Anomaly highlighting
- Drill-down capability for details

## Monitoring Workflow

### Initial Subnet Discovery

1. User configures target subnet (CIDR notation)
2. System performs initial comprehensive scan
3. Discovered devices are added to inventory
4. Initial network topology is mapped
5. Baseline traffic patterns are established

### Continuous Monitoring Cycle

1. Regular ping sweeps verify device presence
2. Port scans check for service changes
3. Passive monitoring captures traffic patterns
4. Changes are recorded to history database
5. Anomalies trigger alerts via alert system

### New Device Detection

1. System detects unrecognized MAC or IP
2. Immediate detailed scan is performed
3. Device is added to inventory as "unknown"
4. User is notified of new device discovery
5. User can classify and set trust level

### Device Status Changes

1. System detects device going offline/online
2. Status is updated in the inventory
3. History record is created for the change
4. Status change appears in timeline
5. Alerts are generated if configured

## Performance Considerations

### Network Impact Management

- Staggered scanning to distribute network load
- Scan rate limiting to prevent performance impact
- Configurable scan depth and frequency
- Low-impact passive monitoring as primary method
- Active scanning scheduled during low-usage periods

### System Resource Management

- Efficient database queries with proper indexing
- Data pruning and archiving for long-term storage
- Memory-efficient data structures for real-time analysis
- Threaded architecture for responsive UI during scans
- Resource usage limits and monitoring

### Scalability Limits

- Recommended limit of 254 devices (Class C subnet)
- Performance degradation expected beyond 500 devices
- UI optimizations for large device counts
- Data summarization for historical analysis of large networks
- Pagination and lazy loading for large datasets

## Security Considerations

### Scan Authorization

- Warning about active scanning legal implications
- Confirmation required before starting monitoring
- Option to exclude sensitive devices from active scanning
- Documentation of scanning methodology for compliance

### Data Protection

- Encryption of device inventory database
- Access controls for monitoring data
- Secure storage of user-provided notes and tags
- Option to anonymize exported data

### Monitoring System Protection

- Self-protection from ARP spoofing attacks
- Validation of collected data to prevent poisoning
- Detection of attempts to manipulate the monitor
- Regular integrity checks of the device database

## Testing Strategy

### Functionality Testing

- Verify accurate device discovery across subnet
- Confirm correct identification of device types
- Test historical tracking of device changes
- Validate relationship mapping accuracy

### Performance Testing

- Measure scan duration at various subnet sizes
- Benchmark database operations under load
- Evaluate UI responsiveness during active scanning
- Test resource usage during continuous monitoring

### Security Testing

- Verify protection against false data injection
- Test resistance to ARP cache poisoning
- Validate data isolation and protection
- Assess scanning footprint detectability

## Future Enhancements

### Planned for Next Releases

1. **IPv6 Support**: Full monitoring capability for IPv6 subnets
2. **Multiple Subnet Monitoring**: Monitor several subnets simultaneously
3. **Network Segmentation Analysis**: Identify and visualize network segments
4. **Wireless Device Tracking**: Special handling for wireless clients
5. **Device Profiling**: Enhanced fingerprinting and behavior profiling
6. **Application Layer Visibility**: Identify applications by traffic patterns

## Conclusion

The Single-Subnet Monitoring functionality for ARPGuard Lite Tier provides comprehensive visibility into network devices and their behavior. By combining active scanning, passive monitoring, and historical tracking, it enables users to maintain awareness of their network environment, detect unauthorized devices, and identify potential security threats before they can cause damage. 