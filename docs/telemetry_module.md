# Telemetry Module Documentation

## Overview

The Telemetry Module is a key component of ARP Guard's modular architecture, designed to collect anonymous usage data to help improve the application and track feature usage. The module is completely opt-in, respecting user privacy while providing valuable insights for development.

## Features

- **Opt-in Data Collection**: Telemetry is disabled by default and requires explicit user consent
- **Anonymized Data**: User identifiable information is not collected
- **Transparent Collection**: Users can view what data is being collected
- **Local Storage**: Telemetry data is stored locally before transmission
- **Configurable Retention**: Data retention periods can be adjusted
- **Data Management**: Users can delete collected data at any time

## Architecture

The Telemetry Module follows the modular architecture pattern used throughout ARP Guard:

```
┌────────────────────┐
│  Telemetry Module  │
├────────────────────┤
│  - Events          │
│  - Configuration   │
│  - Storage         │
│  - Collection      │
└─────────┬──────────┘
          │
┌─────────▼──────────┐     ┌────────────────────┐
│     CLI Module     │────▶│  Detection Module  │
└────────────────────┘     └────────────────────┘
```

### Components

- **TelemetryEvent**: Represents a single telemetry event with event type, timestamp, and properties
- **TelemetryModuleConfig**: Configuration for the telemetry module
- **TelemetryModule**: Main module class implementing the Module interface

## Data Collection Policy

### What is collected

The telemetry module collects the following types of information:

- **Application usage**: Start/stop events, uptime
- **Feature usage**: Which features are being used
- **Detection runs**: Number and duration of detection operations
- **Alert information**: Types and frequency of alerts
- **Error events**: Non-personal error information to improve stability
- **Configuration changes**: Changes to settings (values are not recorded)

### What is NOT collected

- **Personal information**: User names, email addresses, or other identifiers
- **Network content**: Packet payloads or sensitive network information
- **IP addresses**: Internal or external IP addresses from the monitored network
- **Credentials**: Passwords or authentication tokens

## Installation ID

To maintain anonymity while still being able to differentiate between different installations, a random installation ID is generated. This ID:

- Is a random UUID created during first initialization
- Is not linked to any personal information
- Allows aggregating data from the same installation
- Can be regenerated if the user deletes all telemetry data

## Command Line Interface

The telemetry module can be controlled through the CLI using the following commands:

```bash
# Show current telemetry status
arpguard telemetry status

# Enable telemetry collection (requires confirmation)
arpguard telemetry enable --confirm

# Disable telemetry collection
arpguard telemetry disable

# Delete all collected telemetry data (requires confirmation)
arpguard telemetry delete-data --confirm
```

## Integration with Other Modules

The telemetry module integrates with other modules through the event tracking system:

```python
# Example of tracking a feature usage event
telemetry_module.track_event(
    "feature_usage", 
    {
        "feature_name": "arp_scan",
        "duration_ms": 1250
    }
)

# Example of tracking an alert event
telemetry_module.track_event(
    "alert_generated",
    {
        "alert_type": "arp_spoofing",
        "severity": "high"
    }
)
```

## Configuration

The telemetry module can be configured through the TelemetryModuleConfig class:

| Option                | Description                           | Default Value      |
|-----------------------|---------------------------------------|-------------------|
| enabled               | Enable/disable telemetry              | False (opt-in)    |
| anonymize_data        | Anonymize collected data              | True              |
| collection_interval   | Hours between data uploads            | 24 hours          |
| storage_path          | Path to store telemetry data          | ~/.arpguard/telemetry |
| storage_retention_days | Days to retain local data            | 30 days           |
| upload_url            | URL for data uploads                  | None (no uploads) |
| max_events_per_batch  | Maximum events per batch              | 100               |
| allowed_event_types   | List of allowed event types           | ["app_start", "app_stop", "feature_usage", "detection_run", "alert_generated", "error", "config_change"] |

## Implementation Details

### Event Lifecycle

1. **Creation**: Events are created using the `track_event()` method
2. **Storage**: Events are stored in memory until saved
3. **Saving**: Events are periodically saved to local storage
4. **Upload**: Events are uploaded according to the collection interval
5. **Cleanup**: Old events are removed based on retention policy

### Thread Safety

The telemetry module uses thread locks to ensure thread safety when:
- Adding events to the event queue
- Saving events to disk
- Accessing shared resources

### Fault Tolerance

The module is designed to be fault-tolerant:
- Failed uploads are retried on the next cycle
- Saved files are marked as uploaded to prevent duplicate submissions
- Errors during event tracking are logged but don't affect application operation

## Best Practices

When using the telemetry module, follow these best practices:

1. **Respect privacy**: Only track necessary information
2. **Be transparent**: Make it clear what is being tracked
3. **Provide value**: Use telemetry to improve user experience
4. **Make it optional**: Never require telemetry for core functionality
5. **Provide controls**: Allow users to view and manage their data

## Example: Implementing Telemetry in a New Feature

```python
from core.telemetry_module import TelemetryModule

def perform_scan(telemetry_module: TelemetryModule, options: dict):
    start_time = time.time()
    
    try:
        # Perform scanning operation
        results = do_scan(options)
        
        # Track successful scan
        if telemetry_module:
            telemetry_module.track_event("feature_usage", {
                "feature": "network_scan",
                "duration_ms": int((time.time() - start_time) * 1000),
                "hosts_found": len(results),
                "scan_type": options.get("scan_type", "default")
            })
            
        return results
    
    except Exception as e:
        # Track error (without sensitive details)
        if telemetry_module:
            telemetry_module.track_event("error", {
                "feature": "network_scan",
                "error_type": type(e).__name__
            })
        raise
```

## Future Enhancements

- **Event Batching**: Improve efficiency by batching events
- **Compression**: Compress data before upload
- **Selective Uploads**: Allow users to review and select what is uploaded
- **Usage Dashboard**: Provide a local dashboard of usage patterns
- **Bandwidth Limiting**: Cap the amount of data uploaded

## Conclusion

The Telemetry Module provides a privacy-focused way to collect usage data that helps improve ARP Guard while giving users complete control over their data. By following the modular architecture pattern, it seamlessly integrates with other components while maintaining clear boundaries and responsibilities. 