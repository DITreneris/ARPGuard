# ARP Guard Monitoring Service Design

## Background Monitoring Architecture

### Overall Architecture

```
+------------------------------------------------------------------+
|                    ARP Guard Monitoring Service                   |
+------------------------------------------------------------------+
|                                                                  |
|  +----------------+      +----------------+      +-------------+ |
|  | Packet Capture |----->| Packet Analysis|----->| Alert Engine| |
|  +----------------+      +----------------+      +-------------+ |
|          ^                       |                      |        |
|          |                       v                      v        |
|  +----------------+      +----------------+      +-------------+ |
|  | Network Scanner|<---->| Device Registry|----->|Alert Storage| |
|  +----------------+      +----------------+      +-------------+ |
|          ^                       ^                      ^        |
|          |                       |                      |        |
|  +----------------+      +----------------+      +-------------+ |
|  |Scheduler Service|---->|Resource Monitor|----->|Notification | |
|  +----------------+      +----------------+      |Service      | |
|                                                  +-------------+ |
+------------------------------------------------------------------+
           ^                       ^                      ^
           |                       |                      |
+------------------------------------------------------------------+
|                     External Integration Layer                    |
+------------------------------------------------------------------+
```

### Core Components

1. **Packet Capture Service**
   - Captures ARP packets from network interfaces
   - Implements lite and full capture modes
   - Handles packet buffering and filtering
   - Configurable packet sampling rates

2. **Packet Analysis Engine**
   - Processes captured packets for ARP spoofing detection
   - Implements detection algorithms for various attack patterns
   - Maintains statistical analysis of network traffic
   - Supports both real-time and batch processing

3. **Alert Engine**
   - Evaluates detection results against alert thresholds
   - Classifies alerts by severity and type
   - Performs alert deduplication and correlation
   - Triggers appropriate response actions

4. **Network Scanner**
   - Performs periodic active network scans
   - Identifies new devices on the network
   - Validates MAC-IP mappings in ARP tables
   - Detects network configuration changes

5. **Device Registry**
   - Maintains inventory of network devices
   - Tracks device history and behavior patterns
   - Associates devices with security risk levels
   - Provides device categorization and tagging

6. **Alert Storage**
   - Persists alerts with full context
   - Implements efficient storage and retrieval
   - Supports alert lifecycle management
   - Provides historical analysis capabilities

7. **Scheduler Service**
   - Manages all periodic tasks
   - Implements adaptive scheduling based on system load
   - Provides centralized task queuing and prioritization
   - Handles task dependencies and constraints

8. **Resource Monitor**
   - Tracks system resource usage
   - Implements dynamic resource allocation
   - Provides automatic mode switching between lite/full
   - Warns about performance bottlenecks

9. **Notification Service**
   - Delivers alerts through multiple channels
   - Supports customizable notification rules
   - Implements batching and rate limiting
   - Tracks notification delivery and acknowledgment

10. **External Integration Layer**
    - Provides REST API for external integrations
    - Supports webhook callbacks for events
    - Enables integration with SIEM systems
    - Provides extensibility points for custom integrations

### Process Flow

1. **Initialization**
   - System loads configuration
   - Validates environment and permissions
   - Initializes core services
   - Performs initial network scan
   - Establishes baseline network behavior

2. **Continuous Monitoring**
   - Packet capture processes network traffic
   - Analysis engine processes packets in real-time
   - Alerts are generated for suspicious activity
   - Network scans validate ARP table integrity
   - Resource monitor adjusts system parameters

3. **Alert Processing**
   - Suspicious activity triggers alerts
   - Alerts are enriched with device context
   - Notifications are dispatched
   - Alerts are stored for historical analysis
   - Response actions may be triggered

## Subnet Scanning Scheduler

### Scheduling Architecture

```
+--------------------------------------------------------------------+
|                          Scheduler Service                          |
+--------------------------------------------------------------------+
|                                                                    |
|  +------------------+     +-----------------+     +---------------+ |
|  | Task Definitions |---->| Task Scheduler  |---->| Task Executor | |
|  +------------------+     +-----------------+     +---------------+ |
|       ^    ^    ^               |                        |         |
|       |    |    |               v                        v         |
|  +---------+    |        +-----------------+     +---------------+ |
|  | Default |    |        | Schedule        |     | Task Results  | |
|  | Tasks   |    |        | Optimization    |     | Processor     | |
|  +---------+    |        +-----------------+     +---------------+ |
|                 |                |                        |        |
|            +---------+           v                        v        |
|            | Custom  |    +-----------------+     +---------------+ |
|            | Tasks   |    | Resource        |     | Metrics       | |
|            +---------+    | Allocation      |     | Collector     | |
|                 |         +-----------------+     +---------------+ |
|                 |                |                        |        |
|            +---------+           v                        v        |
|            | User    |    +-----------------+     +---------------+ |
|            | Tasks   |    | Conflict        |     | Status        | |
|            +---------+    | Resolution      |     | Reporting     | |
|                           +-----------------+     +---------------+ |
|                                                                    |
+--------------------------------------------------------------------+
```

### Task Types

#### Network Scanning Tasks

| Task Type | Description | Default Schedule | Resource Impact |
|-----------|-------------|------------------|----------------|
| Quick Scan | Basic ARP check of known hosts | Every 5 minutes | Low |
| Full Subnet Scan | Complete scan of all configured subnets | Every 1 hour | Medium |
| Deep Scan | Comprehensive scan with OS detection | Every 24 hours | High |
| Gateway Verification | Verify gateway MAC address | Every 2 minutes | Very Low |
| New Device Detection | Scan for new devices only | Every 15 minutes | Low |

#### Maintenance Tasks

| Task Type | Description | Default Schedule | Resource Impact |
|-----------|-------------|------------------|----------------|
| Database Cleanup | Purge old data | Every 24 hours | Medium |
| Log Rotation | Rotate and compress logs | Every 6 hours | Low |
| Cache Refresh | Refresh internal caches | Every 1 hour | Low |
| Config Validation | Validate current configuration | Every 8 hours | Low |
| Self-Test | Run internal diagnostics | Every 12 hours | Medium |

### Adaptive Scheduling

The scheduler implements adaptive timing based on:

1. **System Load**
   - Decreases scan frequency under high CPU/memory load
   - Defers resource-intensive tasks when system is busy
   - Prioritizes critical security tasks over maintenance

2. **Network Activity Patterns**
   - Increases scan frequency during business hours
   - Runs heavy scans during detected low-usage periods
   - Adapts to learned network usage patterns

3. **Security Incidents**
   - Increases scan frequency after detecting suspicious activity
   - Performs targeted scans of affected subnet segments
   - Returns to normal schedule after safety period

4. **Mode Awareness**
   - Lite Mode: Optimizes for lower resource usage
   - Full Mode: Maximizes detection capabilities
   - Auto Mode: Dynamically switches based on conditions

### Scheduler Implementation

```python
class ScanScheduler:
    def __init__(self, config):
        self.config = config
        self.tasks = {}
        self.queue = PriorityQueue()
        self.executor = ThreadPoolExecutor(max_workers=config.max_workers)
        self.resource_monitor = ResourceMonitor()
        
    def register_task(self, task_id, task_func, schedule, priority, resource_impact):
        """Register a task with the scheduler"""
        self.tasks[task_id] = {
            'function': task_func,
            'schedule': schedule,
            'last_run': None,
            'next_run': self._calculate_next_run(schedule),
            'priority': priority,
            'resource_impact': resource_impact,
            'enabled': True
        }
        
    def adjust_schedule(self, task_id, new_schedule):
        """Adjust schedule for a task"""
        if task_id in self.tasks:
            self.tasks[task_id]['schedule'] = new_schedule
            self.tasks[task_id]['next_run'] = self._calculate_next_run(new_schedule)
            
    def run(self):
        """Main scheduler loop"""
        while not self.should_stop:
            # Check system resources
            resources = self.resource_monitor.get_status()
            
            # Adjust task priorities based on resources
            self._adjust_for_resources(resources)
            
            # Get due tasks
            due_tasks = self._get_due_tasks()
            
            # Execute tasks
            for task_id in due_tasks:
                task = self.tasks[task_id]
                if self._can_run_task(task, resources):
                    self._execute_task(task_id)
                    
            # Sleep until next task is due
            self._sleep_until_next_task()
```

## Alert Persistence Layer Design

### Data Model

```
+-----------------+     +------------------+     +------------------+
| Alert           |     | Device           |     | Evidence         |
+-----------------+     +------------------+     +------------------+
| alert_id        |     | device_id        |     | evidence_id      |
| alert_type      |     | ip_address       |     | alert_id (FK)    |
| severity        |     | mac_address      |     | evidence_type    |
| status          |     | first_seen       |     | timestamp        |
| created_at      |     | last_seen        |     | data             |
| updated_at      |     | hostname         |     | metadata         |
| source_device   |1---*| risk_score       |*---*| hash             |
| target_device   |     | is_gateway       |     +------------------+
| description     |     | device_type      |            |
| resolution      |     | vendor           |            |
| expires_at      |     | notes            |     +------------------+
+-----------------+     +------------------+     | RawPacket        |
        |                       |                +------------------+
        |                       |                | packet_id        |
+------------------+   +------------------+      | evidence_id (FK) |
| AlertHistory     |   | NetworkScan      |      | timestamp        |
+------------------+   +------------------+      | direction        |
| history_id       |   | scan_id          |      | protocol         |
| alert_id (FK)    |   | scan_type        |      | payload          |
| timestamp        |   | start_time       |      | source_ip        |
| changed_by       |   | end_time         |      | destination_ip   |
| action           |   | devices_found    |      | source_mac       |
| old_status       |   | status           |      | destination_mac  |
| new_status       |   | results          |      +------------------+
| notes            |   | triggered_by     |
+------------------+   +------------------+
```

### Storage Strategy

The alert persistence layer uses a tiered storage approach:

1. **Hot Storage (In-Memory)**
   - Recent and active alerts (last 24 hours)
   - Optimized for quick access and real-time analysis
   - Background flushing to persistent storage
   - Memory-efficient data structures

2. **Warm Storage (Local Database)**
   - Recent historical alerts (last 30 days)
   - SQLite or embedded database for lite installations
   - PostgreSQL or MySQL for full installations
   - Local caching and indexing for fast retrieval

3. **Cold Storage (Long-term Archive)**
   - Complete alert history (beyond 30 days)
   - Compressed storage format
   - Option for cloud storage integration
   - Batch retrieval with async processing

### Data Lifecycle

1. **Alert Creation**
   - Alert is generated by detection engine
   - Enriched with device and network context
   - Assigned unique identifier and timestamp
   - Written to hot storage immediately
   - Notification sent if configured

2. **Alert Processing**
   - Alert status updated as processed
   - Related evidence linked to alert
   - Correlated with other recent alerts
   - Alert history record created
   - Moved to appropriate storage tier

3. **Alert Resolution**
   - Resolution status and details recorded
   - Final evidence and notes attached
   - Alert history updated
   - Notifications sent if configured
   - Eventually moved to cold storage

4. **Data Retention**
   - Based on configurable retention policy
   - Critical alerts retained longer
   - Evidence may be pruned before alerts
   - Anonymization option for long-term storage
   - Compliance with relevant data regulations

### Implementation Considerations

1. **Performance Optimization**
   - Indexes on frequently queried fields
   - Denormalization for common query patterns
   - Pagination for large result sets
   - Bulk operations for batch processing
   - Lazy loading for detailed alert data

2. **Scalability**
   - Horizontal scaling of storage components
   - Sharding for large deployments
   - Read replicas for report generation
   - Connection pooling for concurrent access
   - Query optimization for large datasets

3. **Resilience**
   - Transaction support for data consistency
   - Background synchronization for offline operation
   - Auto-recovery from storage errors
   - Periodic integrity checks
   - Corruption detection and repair

4. **Security**
   - Encrypted storage for sensitive data
   - Access control at row and column level
   - Audit logging for all data modifications
   - Secure deletion processes
   - Tamper detection for evidence data

### API Overview

```typescript
interface AlertRepository {
  // Create and retrieve alerts
  createAlert(alertData: AlertCreateDTO): Promise<Alert>;
  getAlertById(alertId: string): Promise<Alert | null>;
  searchAlerts(criteria: AlertSearchCriteria): Promise<PaginatedResult<Alert>>;
  
  // Alert lifecycle
  updateAlertStatus(alertId: string, status: AlertStatus, notes?: string): Promise<void>;
  resolveAlert(alertId: string, resolution: ResolutionDetails): Promise<void>;
  mergeAlerts(sourceAlertIds: string[], targetAlertId: string): Promise<void>;
  
  // Evidence management
  addEvidenceToAlert(alertId: string, evidence: Evidence): Promise<void>;
  getAlertEvidence(alertId: string): Promise<Evidence[]>;
  
  // Analytics
  getAlertStatistics(timeframe: TimeRange): Promise<AlertStatistics>;
  getAlertsTimeline(timeframe: TimeRange, groupBy: string): Promise<TimeSeriesData>;
  getTopAlertSources(limit: number): Promise<AlertSourceCount[]>;
}
```

## Integration with Lite Mode

The monitoring service is designed to work seamlessly with both full and lite operation modes:

### Lite Mode Optimizations

1. **Reduced Scan Frequency**
   - Less frequent network scans
   - Focused on critical network segments
   - Optimized scan depth and breadth

2. **Minimal Data Collection**
   - Collects only essential alert data
   - Limited historical retention
   - Minimized evidence collection

3. **Simplified Storage**
   - Uses embedded database instead of full RDBMS
   - Reduced indexing for lower write overhead
   - In-memory caching disabled or reduced

4. **Resource Awareness**
   - Dynamic task scheduling based on available resources
   - Background tasks yield to active detection
   - CPU and memory usage limits enforced

5. **Detection Focus**
   - Prioritizes critical threats over edge cases
   - Reduced sensitivity to minimize false positives
   - Focus on gateway and critical device protection

### Mode Switching Strategy

The monitoring service supports dynamic switching between lite and full modes:

1. **Automatic Mode Detection**
   - Monitors system resources
   - Switches to lite mode under resource constraints
   - Returns to full mode when resources are available

2. **Scheduled Mode Switching**
   - Allows scheduling full mode during off-hours
   - Can be configured for specific days/times
   - Supports business hours optimization

3. **Triggered Mode Switching**
   - Switches to full mode on suspicious activity
   - Returns to lite mode after investigation period
   - Supports manual override for incident response

4. **Persistent State Management**
   - Maintains alert continuity during mode switches
   - Preserves detection context across mode changes
   - Handles interrupted operations during switching 