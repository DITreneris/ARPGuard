# API Version Migration Guide

## Overview

This document provides information on migrating between different versions of the ARPGuard API. It includes compatibility information, breaking changes, and code examples to help you upgrade your applications.

## API Versioning

ARPGuard API uses semantic versioning (MAJOR.MINOR.PATCH) where:

- **MAJOR**: Breaking changes 
- **MINOR**: New features with backward compatibility
- **PATCH**: Bug fixes and non-breaking changes

## Supported Versions

| Version | Status | Support End Date |
|---------|--------|-----------------|
| 1.0.0   | Current | Active |
| 0.9.0   | Deprecated | 2023-07-21 |

## Version Headers

You can specify which API version to use in your requests by including one of these headers:

```
X-API-Version: 1.0.0
```

or

```
Accept: application/json; version=1.0.0
```

Multiple versions can be specified with quality values:

```
Accept: application/json; version=1.0.0; q=0.9, application/json; version=0.9.0; q=0.8
```

## Version Migration Paths

### 0.9.0 → 1.0.0

#### Request Changes

No breaking changes in request formats.

#### Response Changes

Several endpoints have changed their response structure:

1. **GET /api/v1/monitor/stats**

   **0.9.0 Response:**
   ```json
   {
     "data": {
       "packets": {
         "total": 1000,
         "analyzed": 950
       },
       "alerts": 5,
       "attacks": 2,
       "blocked": 10,
       "uptime": 3600,
       "interfaces": ["eth0", "wlan0"],
       "time": "2023-04-22T16:00:00"
     },
     "version": "0.9.0"
   }
   ```

   **1.0.0 Response:**
   ```json
   {
     "statistics": {
       "packets": {
         "captured": 1000,
         "analyzed": 950,
         "blocked": 10
       },
       "security": {
         "alerts": 5,
         "attacks": 2
       },
       "system": {
         "uptime_seconds": 3600,
         "monitored_interfaces": ["eth0", "wlan0"]
       }
     },
     "timestamp": "2023-04-22T16:00:00",
     "api_version": "1.0.0"
   }
   ```

2. **GET /api/v1/config/current**

   The `config_version` field has been renamed to `version` in 1.0.0.

#### New Features in 1.0.0

1. **Improved Rate Limiting**
   - More detailed rate limit headers
   - Burst allowance for temporary high traffic

2. **Enhanced Security Headers**
   - Addition of security-related response headers
   - Improved error messages

## Migration Examples

### Python Example

```python
import requests

# Function supporting both API versions
def get_network_stats(api_key, api_version="1.0.0"):
    headers = {
        "Authorization": f"Bearer {api_key}",
        "X-API-Version": api_version
    }
    
    response = requests.get(
        "https://api.arpguard.example.com/api/v1/monitor/stats",
        headers=headers
    )
    
    data = response.json()
    
    # Handle different response structures based on version
    if api_version == "0.9.0":
        packet_data = data["data"]["packets"]
        return {
            "total_packets": packet_data["total"],
            "analyzed_packets": packet_data["analyzed"],
            "alerts": data["data"]["alerts"]
        }
    else:  # 1.0.0
        packet_data = data["statistics"]["packets"]
        return {
            "total_packets": packet_data["captured"],
            "analyzed_packets": packet_data["analyzed"],
            "alerts": data["statistics"]["security"]["alerts"]
        }
```

### JavaScript Example

```javascript
// Function supporting both API versions
async function getNetworkStats(apiKey, apiVersion = "1.0.0") {
  const headers = {
    "Authorization": `Bearer ${apiKey}`,
    "X-API-Version": apiVersion
  };
  
  const response = await fetch(
    "https://api.arpguard.example.com/api/v1/monitor/stats",
    { headers }
  );
  
  const data = await response.json();
  
  // Handle different response structures based on version
  if (apiVersion === "0.9.0") {
    const packetData = data.data.packets;
    return {
      totalPackets: packetData.total,
      analyzedPackets: packetData.analyzed,
      alerts: data.data.alerts
    };
  } else {  // 1.0.0
    const packetData = data.statistics.packets;
    return {
      totalPackets: packetData.captured,
      analyzedPackets: packetData.analyzed,
      alerts: data.statistics.security.alerts
    };
  }
}
```

## Version Compatibility Matrix

| Feature | 0.9.0 | 1.0.0 |
|---------|-------|-------|
| Authentication | ✅ | ✅ |
| Network Monitoring | ✅ | ✅ |
| Configuration Management | ✅ | ✅ |
| Backup/Restore | ❌ | ✅ |
| Rate Limiting | ✅ (basic) | ✅ (advanced) |
| Real-time Monitoring | ✅ | ✅ |
| Version Headers | ✅ | ✅ |

## Best Practices

1. **Always specify a version** in your API requests to ensure consistent behavior.
2. **Test your application against both versions** during migration.
3. **Update your code incrementally** when migrating from 0.9.0 to 1.0.0.
4. **Monitor deprecation warnings** in API responses to prepare for future changes.
5. **Subscribe to the API changelog** for updates on new versions and deprecations.

## Need Help?

If you encounter issues during migration or have questions about version compatibility, please contact our support team at support@arpguard.example.com. 