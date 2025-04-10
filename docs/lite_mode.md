# ARP Guard Lite Mode

## Overview

ARP Guard offers a lightweight "Lite Mode" designed for systems with limited resources or where a lower system footprint is desired. This mode provides essential ARP spoofing protection while consuming significantly fewer system resources.

## Key Features

- **Lower Memory Footprint**: Uses simpler data structures and fewer caches
- **Single Worker Thread**: Replaces the multi-threaded architecture with a single worker
- **Simplified Detection Logic**: Focuses on the most critical detection patterns
- **Essential Functionality**: Maintains core protection against ARP spoofing attacks
- **Automatic Resource Detection**: Can automatically switch to lite mode on systems with limited memory

## When to Use Lite Mode

Consider using Lite Mode in the following scenarios:

- On systems with limited RAM (less than 500MB available)
- On older or low-power devices (IoT devices, embedded systems, etc.)
- When running alongside other resource-intensive applications
- For long-term background monitoring where minimal footprint is desired
- In virtual machines with constrained resources

## Technical Differences

| Feature | Full Mode | Lite Mode |
|---------|-----------|-----------|
| Worker Threads | Multiple (2-8) | Single |
| Packet Prioritization | 3 levels (high/medium/low) | 2 levels (high/low) |
| Queue Size | 1000+ packets | 200 packets |
| Packet Cache | TTL-based with large capacity | Simple, limited capacity |
| Analysis Depth | Detailed with multiple heuristics | Focused on essential patterns |
| Vendor Detection | Full MAC vendor database | Minimal vendor detection |
| Statistics Tracking | Comprehensive metrics | Essential metrics only |
| Memory Usage | 50-200MB | 10-30MB |

## Enabling Lite Mode

### Command Line

```bash
# Explicitly enable lite mode
python arp_guard.py --lite

# Or set a custom memory threshold
python arp_guard.py --lite-threshold 800
```

### Configuration File

```json
{
  "use_lite_version": true,
  "lite_mode_memory_threshold": 500
}
```

### Automatic Detection

By default, ARP Guard will automatically switch to Lite Mode if available system memory is below 500MB. You can customize this threshold in the configuration.

## Performance Comparison

| Metric | Full Mode | Lite Mode |
|--------|-----------|-----------|
| CPU Usage | 5-15% | 1-5% |
| Memory Usage | 50-200MB | 10-30MB |
| Packets/sec | Up to 10,000 | Up to 3,000 |
| Detection Rate | ~99% | ~95% |
| False Positives | Very Low | Low |

## Limitations

When using Lite Mode, be aware of these limitations:

1. Reduced detection of sophisticated attacks that require complex pattern analysis
2. Lower packet processing throughput in high-traffic situations
3. Limited historical data for forensic analysis
4. Fewer detailed statistics and metrics
5. No adaptive resource management

## Best Practices

- For critical infrastructure, use Full Mode when resources permit
- For long-term monitoring of stable networks, Lite Mode is often sufficient
- Consider running periodic Full Mode scans alongside continuous Lite Mode monitoring
- Customize the memory threshold based on your specific system resources
- Monitor CPU usage even in Lite Mode to ensure system stability

## Use Cases

### Home Network Protection

Lite Mode is ideal for home networks where you can run ARP Guard on an always-on device like a Raspberry Pi without consuming excessive resources.

### IoT Environment Monitoring

Deploy on resource-constrained IoT gateways to monitor for ARP-based attacks in IoT environments where devices are particularly vulnerable.

### Enterprise Background Monitoring

Run in Lite Mode on workstations as a background service, with periodic Full Mode scans or dedicated Full Mode instances on security monitoring servers. 