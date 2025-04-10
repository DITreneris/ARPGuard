# ARPGuard Integration Guide

## Overview

This document provides comprehensive instructions for integrating ARPGuard with external systems, including SIEM platforms and third-party security tools via API endpoints. ARPGuard offers flexible integration options to fit into your existing security infrastructure.

## Table of Contents

- [SIEM Integration](#siem-integration)
  - [Supported SIEM Platforms](#supported-siem-platforms)
  - [Configuration Steps](#siem-configuration-steps)
  - [Event Format](#siem-event-format)
  - [Testing SIEM Integration](#testing-siem-integration)
- [API Integration](#api-integration)
  - [API Overview](#api-overview)
  - [Authentication](#authentication)
  - [API Endpoints](#api-endpoints)
  - [Rate Limiting](#rate-limiting)
  - [Example Requests](#example-requests)
- [Troubleshooting](#troubleshooting)
  - [Common Issues](#common-issues)
  - [Validation Tests](#validation-tests)
- [Advanced Integration](#advanced-integration)
  - [Custom Integrations](#custom-integrations)
  - [High Availability Considerations](#high-availability-considerations)

## SIEM Integration

ARPGuard can forward security events to SIEM (Security Information and Event Management) platforms to provide centralized visibility of ARP-based threats alongside other security data.

### Supported SIEM Platforms

ARPGuard has been tested with the following SIEM platforms:

- Splunk Enterprise
- IBM QRadar
- Elastic Security
- Microsoft Sentinel
- ArcSight ESM
- Graylog

### SIEM Configuration Steps

#### 1. Configure ARPGuard SIEM Settings

Edit the `/etc/arpguard/config.yaml` file (or use the web interface) to configure SIEM integration:

```yaml
siem:
  enabled: true
  protocol: "tcp" # tcp or udp
  format: "syslog" # syslog or cef
  host: "siem.example.com"
  port: 514
  facility: 16 # Local use 0
  severity_mapping:
    critical: 2 # Critical
    high: 3 # Error
    medium: 4 # Warning
    low: 5 # Notice
  batch_size: 100
  retry_attempts: 3
  retry_delay: 5
```

#### 2. Configure Your SIEM Platform

**For Splunk:**

1. Ensure a UDP or TCP input is configured on your Splunk instance
2. Create a source type for ARPGuard events
3. Configure field extractions for ARPGuard JSON data

**For ELK Stack:**

1. Configure Logstash to listen on the specified port
2. Create a filter to parse ARPGuard events
3. Define an output to Elasticsearch

#### 3. Restart ARPGuard Service

```bash
sudo systemctl restart arpguard
```

### SIEM Event Format

ARPGuard sends events in the following format:

**Syslog Format:**
```
<priority>1 ISO8601TIMESTAMP HOSTNAME ARPGuard - - - {"event_id":"EVENT-123","timestamp":"2025-04-09T12:34:56.789Z","source_ip":"192.168.1.100","source_mac":"00:11:22:33:44:55","event_type":"arp_spoofing","severity":"high","description":"ARP spoofing attack detected","details":{...}}
```

**CEF Format:**
```
CEF:0|ARPGuard|ARPGuard|1.0|100|ARP Spoofing Attack|7|src=192.168.1.100 spt=0 dst=192.168.1.1 dpt=0 cs1=00:11:22:33:44:55 cs1Label=SourceMAC cs2=00:aa:bb:cc:dd:ee cs2Label=TargetMAC
```

### Testing SIEM Integration

ARPGuard provides a test utility to verify SIEM integration:

```bash
python scripts/p1_high_priority_tests.py
```

For testing without an actual SIEM instance, use mock mode:

```bash
python scripts/p1_high_priority_tests.py --mock
```

## API Integration

ARPGuard provides a RESTful API for integration with third-party tools and custom applications.

### API Overview

The API allows:
- Retrieving ARP monitoring data
- Managing protection rules
- Configuring system settings
- Retrieving alerts and events
- Triggering actions

### Authentication

The API uses API key authentication. Generate an API key in the ARPGuard web interface:

1. Navigate to Settings > API
2. Click "Generate New API Key"
3. Save the key securely - it will only be shown once

Include the API key in your requests using the `X-API-Key` header:

```
X-API-Key: your_api_key_here
```

### API Endpoints

#### Monitoring Endpoints

| Method | Endpoint                      | Description                               |
|--------|-------------------------------|-------------------------------------------|
| GET    | `/api/v1/arp-table`           | Retrieve current ARP table                |
| GET    | `/api/v1/statistics`          | Get system statistics                     |
| GET    | `/api/v1/alerts`              | Retrieve ARP-related alerts               |
| GET    | `/api/v1/network-interfaces`  | List available network interfaces         |

#### Configuration Endpoints

| Method | Endpoint                      | Description                               |
|--------|-------------------------------|-------------------------------------------|
| GET    | `/api/v1/config`              | Retrieve current configuration            |
| PUT    | `/api/v1/config`              | Update configuration                      |
| GET    | `/api/v1/protection-rules`    | List protection rules                     |
| POST   | `/api/v1/protection-rules`    | Create a new protection rule              |
| DELETE | `/api/v1/protection-rules/{id}` | Delete a protection rule                |

#### Action Endpoints

| Method | Endpoint                      | Description                               |
|--------|-------------------------------|-------------------------------------------|
| POST   | `/api/v1/actions/scan`        | Trigger an ARP network scan               |
| POST   | `/api/v1/actions/reset`       | Reset ARP cache                           |
| POST   | `/api/v1/actions/protect/{ip}` | Add protection for a specific IP          |

### Rate Limiting

API requests are rate-limited by default:
- 60 requests per minute per IP address
- 1000 requests per day per API key

Rate limit headers are included in responses:
- `X-RateLimit-Limit`: Max requests per time window
- `X-RateLimit-Remaining`: Remaining requests in current window
- `X-RateLimit-Reset`: Time when limit resets (Unix timestamp)

### Example Requests

**Retrieve ARP Table:**

```bash
curl -X GET http://localhost:8080/api/v1/arp-table \
  -H "X-API-Key: your_api_key_here"
```

**Add Protection Rule:**

```bash
curl -X POST http://localhost:8080/api/v1/protection-rules \
  -H "X-API-Key: your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "192.168.1.1", "mac_address": "00:11:22:33:44:55", "description": "Gateway protection"}'
```

## Troubleshooting

### Common Issues

#### SIEM Connection Issues

1. **Connection Refused**
   - Verify the SIEM host and port are correct
   - Check firewall rules between ARPGuard and SIEM
   - Ensure the SIEM service is running

2. **Events Not Appearing**
   - Check ARPGuard logs for delivery errors
   - Verify format configuration matches SIEM expectations
   - Ensure proper field mappings in SIEM configuration

3. **Incorrect Event Format**
   - Check that the configured format (syslog/CEF) is supported by your SIEM
   - Verify that timestamp formats are parsed correctly

#### API Issues

1. **Authentication Errors**
   - Verify API key is valid and not expired
   - Ensure the key is sent in the correct header format

2. **Rate Limiting**
   - Implement exponential backoff in integrations
   - Consider requesting increased limits for production use

### Validation Tests

ARPGuard includes validation tests to verify integration:

```bash
# Test SIEM integration
python scripts/p1_high_priority_tests.py

# Test API endpoints
python scripts/test_api_endpoints.py
```

## Advanced Integration

### Custom Integrations

For custom integration needs, ARPGuard supports:

1. **Webhook Notifications**
   - Configure in `/etc/arpguard/config.yaml`
   - Define custom HTTP endpoints for event delivery
   - Specify event filtering criteria

2. **Custom Event Processors**
   - Create plugins using the ARPGuard SDK
   - Place Python modules in `/etc/arpguard/plugins/`
   - Configure in the web interface under Integrations > Custom

### High Availability Considerations

When integrating ARPGuard in HA configurations:

1. **SIEM Integration**
   - Configure identical SIEM settings on all nodes
   - Enable event deduplication on SIEM side

2. **API Access**
   - Use a load balancer for API endpoints
   - Configure session persistence if needed
   - Share API keys across the cluster 