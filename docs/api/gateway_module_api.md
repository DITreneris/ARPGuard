# Gateway Detection Module API Reference

This document provides a comprehensive API reference for developers integrating with the Gateway Detection module of ARP Guard.

## Table of Contents

- [Overview](#overview)
- [Module Classes](#module-classes)
- [Configuration API](#configuration-api)
- [Gateway Information API](#gateway-information-api)
- [Event Callbacks](#event-callbacks)
- [Integration Examples](#integration-examples)
- [Error Handling](#error-handling)

## Overview

The Gateway Detection Module API provides interfaces for:

- Retrieving gateway device information
- Configuring gateway detection settings
- Receiving notifications about gateway-related events
- Integrating gateway detection with custom detection logic

## Module Classes

### DetectionModule

The primary class for full-featured gateway detection.

```python
from src.core.detection_module import DetectionModule, DetectionModuleConfig

# Create configuration
config = DetectionModuleConfig(storage_path="./data")

# Create detection module
detection_module = DetectionModule(config)
```

### LiteDetectionModule

A lightweight implementation with lower resource usage.

```python
from src.core.lite_detection_module import LiteDetectionModule

# Create lite detection module with existing config
lite_module = LiteDetectionModule(config)
```

## Configuration API

### DetectionModuleConfig

Configuration class for gateway detection settings.

#### Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| storage_path | str | "./data" | Directory for storing gateway information |
| default_gateway_ip | str | "192.168.1.1" | Default gateway IP if none detected |
| default_gateway_mac | str | "00:00:00:00:00:00" | Default gateway MAC if none detected |
| detection_interval | int | 5 | Seconds between detection cycles |
| enable_sampling | bool | True | Enable packet sampling for efficiency |
| auto_protect | bool | False | Automatically protect detected gateway |

#### Example

```python
config = DetectionModuleConfig(
    storage_path="./custom_data",
    default_gateway_ip="10.0.0.1",
    default_gateway_mac="aa:bb:cc:dd:ee:ff",
    detection_interval=10,
    auto_protect=True
)
```

## Gateway Information API

### Getting Gateway Information

```python
# Get gateway IPs
gateway_ips = detection_module._get_gateway_ips()

# Get gateway MACs
gateway_macs = detection_module._get_gateway_macs()

# Get raw gateway info dictionary
gateway_info = detection_module.gateway_info
```

### Updating Gateway Information

```python
# Update gateway info
detection_module.gateway_info = {
    "ip": "192.168.1.254",
    "mac": "aa:bb:cc:dd:ee:ff",
    "last_seen": time.time(),
    "verified": True
}

# Save to persistent storage
detection_module._save_gateway_info()
```

### Checking Gateway Status

```python
# Check if a device is a gateway
is_gateway = (device_ip in detection_module._get_gateway_ips() or 
              device_mac in detection_module._get_gateway_macs())

# Verify gateway is reachable
is_reachable = detection_module.verify_gateway_reachable()
```

## Event Callbacks

Register callbacks to receive gateway-related events.

### Gateway Change Events

```python
def on_gateway_changed(old_gateway, new_gateway):
    print(f"Gateway changed from {old_gateway} to {new_gateway}")

# Register callback
detection_module.register_gateway_callback(on_gateway_changed)
```

### Gateway Attack Events

```python
def on_gateway_attack(attack_details):
    print(f"Gateway attack detected: {attack_details}")

# Register callback
detection_module.register_attack_callback(on_gateway_attack)
```

## Integration Examples

### Integrating with Custom Packet Analysis

```python
def analyze_packet(packet):
    # Load gateway info if needed
    if not detection_module._gateway_info_loaded:
        detection_module._load_gateway_info()
    
    # Check if packet involves gateway
    if packet.src_ip in detection_module._get_gateway_ips():
        # This packet came from the gateway
        if packet.src_mac not in detection_module._get_gateway_macs():
            # Potential spoofing attack!
            return {
                "type": "spoofing",
                "severity": "high",
                "details": f"Gateway IP {packet.src_ip} with unexpected MAC {packet.src_mac}"
            }
    
    return None  # No issue detected
```

### Custom Gateway Detection

```python
def detect_gateway():
    """Custom gateway detection logic"""
    # Your custom detection logic here
    gateway_ip = "192.168.1.1"  # Example result
    gateway_mac = "aa:bb:cc:dd:ee:ff"  # Example result
    
    # Update detection module with results
    detection_module.gateway_info = {
        "ip": gateway_ip,
        "mac": gateway_mac,
        "last_seen": time.time(),
        "verified": True,
        "detection_method": "custom"
    }
    
    # Save the updated info
    detection_module._save_gateway_info()
    
    return gateway_ip, gateway_mac
```

### Extending for Multiple Gateways

```python
class MultiGatewayDetector:
    def __init__(self, config):
        self.detection_module = DetectionModule(config)
        self.gateways = []
    
    def add_gateway(self, ip, mac):
        """Add a gateway to the tracking list"""
        self.gateways.append({"ip": ip, "mac": mac})
        
        # Update the detection module with the list
        self.detection_module.gateway_info = {
            "ip": [g["ip"] for g in self.gateways],
            "mac": [g["mac"] for g in self.gateways],
            "last_seen": time.time(),
            "verified": True
        }
        
        # Save the updated configuration
        self.detection_module._save_gateway_info()
    
    def is_gateway_ip(self, ip):
        """Check if an IP is a known gateway"""
        return ip in [g["ip"] for g in self.gateways]
    
    def is_gateway_mac(self, mac):
        """Check if a MAC is a known gateway"""
        return mac in [g["mac"] for g in self.gateways]
```

## Error Handling

### Common Exceptions

| Exception | Description | Handling Strategy |
|-----------|-------------|-------------------|
| `FileNotFoundError` | Gateway info file not found | Use defaults and create file |
| `PermissionError` | Insufficient permissions | Use in-memory only mode |
| `JSONDecodeError` | Malformed gateway data | Use defaults and recreate file |
| `KeyError` | Missing required fields | Add missing fields with defaults |

### Error Handling Example

```python
try:
    detection_module._load_gateway_info()
except FileNotFoundError:
    print("Gateway info file not found, using defaults")
    detection_module.gateway_info = {
        "ip": config.default_gateway_ip,
        "mac": config.default_gateway_mac,
        "last_seen": time.time(),
        "verified": False
    }
    detection_module._save_gateway_info()
except json.JSONDecodeError:
    print("Gateway info file corrupt, resetting to defaults")
    detection_module.gateway_info = {
        "ip": config.default_gateway_ip,
        "mac": config.default_gateway_mac,
        "last_seen": time.time(),
        "verified": False
    }
    detection_module._save_gateway_info()
except Exception as e:
    print(f"Unexpected error: {e}")
    # Use in-memory only mode
    detection_module._gateway_info_loaded = True
```

## API Versioning

The Gateway Detection module follows semantic versioning:

- **Major version**: Incompatible API changes
- **Minor version**: New features in backwards-compatible manner
- **Patch version**: Backwards-compatible bug fixes

Current version: 2.1.0

### Version History

| Version | Changes |
|---------|---------|
| 2.1.0   | Added support for multiple gateways |
| 2.0.0   | Introduced LiteDetectionModule |
| 1.2.0   | Added gateway verification API |
| 1.1.0   | Added gateway change callbacks |
| 1.0.0   | Initial stable API |

## Thread Safety

The Gateway Detection module is designed with thread safety in mind:
- Read operations are always thread-safe
- Write operations use locks to prevent race conditions
- `_save_gateway_info()` uses file locking to prevent corruption

When using in multi-threaded environments, consider:
```python
# Thread-safe gateway detection
with detection_module.lock:
    gateway_ips = detection_module._get_gateway_ips()
    gateway_macs = detection_module._get_gateway_macs()
    # Do something with the gateway information
``` 