---
version: 1
last_modified: '2024-04-06T14:00:00.000000'
---

# Memory Management for Packet Capture

## Overview

ARPGuard's Memory Management system is designed to optimize memory usage during high-volume packet capture sessions. The system implements adaptive strategies that respond to different levels of memory pressure, ensuring stable operation even under heavy traffic conditions.

## Architecture

The memory management architecture consists of two primary components:

```
┌─────────────────────────────────┐    ┌─────────────────────────────────────┐
│          MemoryManager          │    │        PacketMemoryOptimizer        │
├─────────────────────────────────┤    ├─────────────────────────────────────┤
│ - Monitors memory usage         │    │ - Optimizes packet storage          │
│ - Determines pressure levels    │◄───►│ - Deduplicates common values       │
│ - Adapts capture strategies     │    │ - Manages payload truncation        │
│ - Manages garbage collection    │    │ - Tracks memory optimization stats  │
└─────────────────────────────────┘    └─────────────────────────────────────┘
            ▲                                         ▲
            │                                         │
            └─────────────┬─────────────────────────┬─┘
                          │                         │
                ┌─────────▼─────────┐     ┌─────────▼─────────┐
                │   PacketAnalyzer  │     │   Other System    │
                │    Component      │     │    Components     │
                └───────────────────┘     └───────────────────┘
```

### MemoryManager

The `MemoryManager` class monitors system memory usage and adjusts capture behavior based on current conditions. Key features include:

- Real-time memory usage monitoring
- Memory pressure level classification (LOW, MEDIUM, HIGH, CRITICAL)
- Adaptive strategy adjustment based on pressure levels
- Callback notification system for pressure changes
- Configurable thresholds and behavior

### PacketMemoryOptimizer

The `PacketMemoryOptimizer` class focuses on optimizing how packets are stored in memory:

- Field deduplication for common values (IP addresses, MAC addresses)
- Payload size management based on memory pressure
- Raw packet storage optimization
- Memory usage estimation and tracking

## Memory Pressure Levels

ARPGuard's memory management system defines four levels of memory pressure:

| Pressure Level | Default Threshold | Description |
|----------------|-------------------|-------------|
| LOW | < 70% | Normal operation with minimal optimization |
| MEDIUM | 70-85% | Moderate optimization with some sampling |
| HIGH | 85-95% | Aggressive optimization with significant sampling |
| CRITICAL | > 95% | Maximum optimization to prevent system instability |

## Adaptive Strategies

The system implements several adaptive strategies that trigger at different memory pressure levels:

### 1. Packet Sampling

As memory pressure increases, the system gradually reduces the percentage of packets that are fully processed:

| Pressure Level | Default Sampling Rate |
|----------------|------------------------|
| LOW | 100% (all packets) |
| MEDIUM | 75% |
| HIGH | 50% |
| CRITICAL | 25% |

### 2. Buffer Size Management

The system dynamically adjusts the packet buffer size based on memory pressure:

| Pressure Level | Default Buffer Size |
|----------------|---------------------|
| LOW | 10,000 packets |
| MEDIUM | 5,000 packets |
| HIGH | 2,500 packets |
| CRITICAL | 1,000 packets |

### 3. Payload Truncation

To reduce memory usage, packet payloads are truncated at different thresholds:

| Pressure Level | Default Max Payload Size |
|----------------|---------------------------|
| LOW | 1,500 bytes (full Ethernet frame) |
| MEDIUM | 512 bytes |
| HIGH | 256 bytes |
| CRITICAL | 64 bytes (headers only) |

### 4. Garbage Collection

The system manages garbage collection frequency based on memory pressure:

| Pressure Level | Default GC Interval |
|----------------|---------------------|
| LOW | 600 seconds (10 minutes) |
| MEDIUM | 300 seconds (5 minutes) |
| HIGH | 120 seconds (2 minutes) |
| CRITICAL | 60 seconds (1 minute) |

### 5. String Deduplication

The system implements string deduplication for common network identifiers:

- IP addresses
- MAC addresses
- Protocol names

This is particularly effective for high-volume captures where the same addresses appear repeatedly.

## Configuration

Memory management behavior can be customized through the `config/memory_config.yml` file:

```yaml
# Memory pressure thresholds (percentage)
low_threshold: 50      # Below this is considered LOW pressure
medium_threshold: 70   # Below this is considered MEDIUM pressure
high_threshold: 85     # Below this is considered HIGH pressure
critical_threshold: 95 # Above this is considered CRITICAL pressure

# Memory monitoring settings
monitoring_interval: 15  # Seconds between memory checks
memory_overhead_factor: 1.5  # Factor applied to estimate memory usage

# LOW pressure settings
low_sampling_rate: 1.0     # Process all packets
low_buffer_size: 10000     # Maximum packet buffer size
low_gc_interval: 600       # Garbage collection interval (seconds)

# MEDIUM pressure settings
medium_sampling_rate: 0.75  # Process 75% of packets
medium_buffer_size: 5000    # Maximum packet buffer size
medium_gc_interval: 300     # Garbage collection interval (seconds)

# HIGH pressure settings
high_sampling_rate: 0.5     # Process 50% of packets
high_buffer_size: 2500      # Maximum packet buffer size
high_gc_interval: 120       # Garbage collection interval (seconds)

# CRITICAL pressure settings
critical_sampling_rate: 0.25  # Process 25% of packets
critical_buffer_size: 1000    # Maximum packet buffer size
critical_gc_interval: 60      # Garbage collection interval (seconds)

# Packet optimization settings
max_packet_payload: 1500    # Maximum packet payload size in bytes
deduplication_enabled: true  # Enable string deduplication for common values
```

## Integration with Packet Analyzer

The memory management system is tightly integrated with ARPGuard's `PacketAnalyzer` component:

1. **Memory Monitoring**: The `MemoryManager` continuously monitors system memory usage during packet capture
2. **Pressure Callbacks**: The `PacketAnalyzer` registers callbacks to be notified of pressure changes
3. **Buffer Adjustments**: The packet buffer size is dynamically adjusted based on memory conditions
4. **Packet Processing**: Each packet is first checked against the current sampling rate
5. **Optimization**: Captured packets are optimized before storage using the `PacketMemoryOptimizer`
6. **Metrics Tracking**: Memory usage metrics are collected and logged for analysis

## Performance Metrics

The memory management system tracks several performance metrics:

### Memory Manager Metrics

- Current memory usage percentage
- Peak memory usage
- Memory pressure level changes
- Garbage collection invocations
- Packets dropped due to sampling
- Adaptive actions taken

### Packet Optimizer Metrics

- Packets optimized
- Bytes saved through optimization
- Duplicate IP addresses found
- Duplicate MAC addresses found
- Payloads truncated
- Cache sizes

These metrics can be accessed programmatically through the `get_metrics()` method of both classes, or viewed in the log files after a capture session.

## Implementation Details

### Memory Pressure Detection

```python
def check_memory_pressure(self) -> MemoryPressureLevel:
    """
    Check current memory pressure level based on usage.
    
    Returns:
        MemoryPressureLevel: Current memory pressure level
    """
    usage_percent = self.get_memory_usage()
    
    # Determine pressure level based on thresholds
    new_level = MemoryPressureLevel.LOW
    
    if usage_percent >= self.thresholds[MemoryPressureLevel.CRITICAL]:
        new_level = MemoryPressureLevel.CRITICAL
    elif usage_percent >= self.thresholds[MemoryPressureLevel.HIGH]:
        new_level = MemoryPressureLevel.HIGH
    elif usage_percent >= self.thresholds[MemoryPressureLevel.MEDIUM]:
        new_level = MemoryPressureLevel.MEDIUM
    
    # Check if pressure level changed
    if new_level != self.current_pressure_level:
        # Update metrics and notify callbacks
        # ...
    
    return new_level
```

### Packet Sampling

```python
def should_process_packet(self) -> bool:
    """
    Determine if a packet should be processed based on sampling rate.
    
    Returns:
        bool: True if packet should be processed, False otherwise
    """
    strategy = self.get_current_strategy()
    sampling_rate = strategy["sampling_rate"]
    
    # Always process if sampling rate is 1.0
    if sampling_rate >= 1.0:
        return True
        
    # Randomly sample based on configured rate
    should_process = random.random() < sampling_rate
    
    # Update metrics if packet is dropped
    if not should_process:
        self.metrics["packets_dropped"] += 1
        
    return should_process
```

### Packet Optimization

```python
def optimize_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
    """
    Optimize a packet dictionary to reduce memory usage.
    
    Args:
        packet: Raw packet dictionary
        
    Returns:
        Dict: Optimized packet dictionary
    """
    # Create a copy that we'll optimize
    optimized = dict(packet)
    
    # Apply deduplication for common values
    self._deduplicate_packet_fields(optimized)
    
    # Apply payload optimization if needed
    if 'payload' in optimized and not self.store_full_payload:
        if len(optimized['payload']) > self.max_payload_size:
            optimized['payload'] = optimized['payload'][:self.max_payload_size]
            optimized['payload_truncated'] = True
    
    # Remove raw packet data if not storing
    if 'raw_packet' in optimized and not self.store_raw_packet:
        del optimized['raw_packet']
    
    # Update metrics
    # ...
    
    return optimized
```

## Best Practices

For optimal memory management during packet capture:

1. **Monitor Memory Usage**: Keep an eye on memory metrics during large captures
2. **Adjust Thresholds**: Fine-tune the pressure thresholds based on your specific environment
3. **Consider Hardware**: On systems with limited RAM, use more aggressive sampling rates
4. **Use Filtering**: Apply BPF filters to reduce the volume of packets before memory management
5. **Regular Reset**: For very long captures, consider periodically resetting the capture session
6. **Optimize Deduplication**: If capturing from a limited set of hosts, enable aggressive deduplication

## Troubleshooting

### High Memory Usage

If you observe consistently high memory usage:

1. Reduce buffer sizes in the configuration
2. Increase sampling rates at lower pressure levels
3. Consider enabling more aggressive payload truncation
4. Check if your BPF filters are effective at reducing packet volume

### Packet Loss

If you're experiencing high packet drop rates:

1. Verify that the sampling rate is appropriate for your use case
2. Consider upgrading hardware for high-volume captures
3. Use more specific BPF filters to target only the traffic you need
4. Split long capture sessions into multiple shorter sessions

## Conclusion

ARPGuard's memory management system ensures efficient packet capture even in high-traffic environments by implementing adaptive strategies based on system memory conditions. By dynamically adjusting packet processing, buffer sizes, and optimization techniques, the system maintains stability while maximizing the amount of useful information captured. 