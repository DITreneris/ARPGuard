# Real-time Monitoring

This document describes the real-time monitoring features of the ARPGuard application.

## Overview

The ARPGuard real-time monitoring system provides continuous visibility into network traffic, potential threats, and system performance. It utilizes WebSockets for efficient bi-directional communication, enabling real-time updates without the need for polling.

## API Endpoints

### REST Endpoints

The following REST API endpoints are available for monitoring:

#### Network Statistics
```http
GET /api/v1/monitor/stats
Authorization: Bearer <token>
```

Response:
```json
{
  "packets_processed": 1500,
  "attacks_detected": 5,
  "network_throughput": 1200.5,
  "cpu_usage": 65.2,
  "memory_usage": 45.3,
  "response_time": 45.0,
  "timestamp": "2024-04-20T12:00:00Z"
}
```

#### Alerts
```http
GET /api/v1/monitor/alerts
Authorization: Bearer <token>
```

Optional query parameters:
- `severity`: Filter by severity (critical, high, medium, low)
- `time_range`: Filter by time range (1h, 6h, 24h, 7d)
- `status`: Filter by status (active, acknowledged, ignored)

Response:
```json
{
  "alerts": [
    {
      "id": "alert-001",
      "type": "arp_spoofing",
      "severity": "critical",
      "timestamp": "2024-04-20T12:00:00Z",
      "status": "active",
      "source_ip": "192.168.1.100",
      "source_mac": "00:11:22:33:44:55",
      "target_ip": "192.168.1.1",
      "target_mac": "aa:bb:cc:dd:ee:ff",
      "description": "ARP spoofing attack detected"
    }
  ]
}
```

#### Network Topology
```http
GET /api/v1/monitor/topology
Authorization: Bearer <token>
```

Optional query parameters:
- `details`: Whether to include detailed node information (true/false)

Response:
```json
{
  "nodes": [
    {
      "id": "node1",
      "ip": "192.168.1.1",
      "mac": "00:11:22:33:44:55",
      "status": "online",
      "last_seen": "2024-04-20T12:00:00Z",
      "device_type": "router",
      "hostname": "gateway",
      "is_gateway": true
    }
  ],
  "edges": [
    {
      "source": "node1",
      "target": "node2",
      "packets": 1500,
      "bytes": 1500000
    }
  ]
}
```

#### Historical Data
```http
GET /api/v1/monitor/historical?metric=packets_processed&start_date=2024-04-19T00:00:00&end_date=2024-04-20T00:00:00&interval=1h
Authorization: Bearer <token>
```

Required query parameters:
- `metric`: Metric to analyze (packets_processed, attacks_detected, network_throughput, cpu_usage, memory_usage, response_time)
- `start_date`: Start date in ISO format
- `end_date`: End date in ISO format

Optional query parameters:
- `interval`: Interval for data points (1h, 6h, 1d), default: 1h

Response:
```json
{
  "metric": "packets_processed",
  "start_date": "2024-04-19T00:00:00",
  "end_date": "2024-04-20T00:00:00",
  "interval": "1h",
  "data_points": [
    {
      "timestamp": "2024-04-19T00:00:00",
      "value": 1500
    },
    {
      "timestamp": "2024-04-19T01:00:00",
      "value": 1550
    }
  ]
}
```

### WebSocket Endpoint

Real-time updates are available through the WebSocket endpoint:

```
ws://server:8000/api/v1/monitor/ws
```

After connecting to the WebSocket, clients will automatically receive updates for:
- Network statistics (every second)
- New alerts (as they occur)
- Topology changes (as they occur)

#### Message Format

All messages follow this format:
```json
{
  "type": "stats_update|alert|topology_update",
  "data": {
    // Type-specific data
  }
}
```

## Client Integration Examples

### JavaScript WebSocket Example

```javascript
// Connect to the WebSocket
const socket = new WebSocket('ws://server:8000/api/v1/monitor/ws');

// Handle connection open
socket.onopen = function(e) {
  console.log('Connection established');
};

// Handle messages
socket.onmessage = function(event) {
  const message = JSON.parse(event.data);
  
  switch(message.type) {
    case 'stats_update':
      updateDashboardMetrics(message.data);
      break;
    case 'alert':
      displayNewAlert(message.data);
      break;
    case 'topology_update':
      updateNetworkTopology(message.data);
      break;
  }
};

// Handle errors
socket.onerror = function(error) {
  console.error('WebSocket error:', error);
};

// Handle connection close
socket.onclose = function(e) {
  console.log('Connection closed');
};
```

### Python WebSocket Example

```python
import asyncio
import websockets
import json

async def monitor():
    uri = "ws://server:8000/api/v1/monitor/ws"
    async with websockets.connect(uri) as websocket:
        while True:
            message = await websocket.recv()
            data = json.loads(message)
            
            if data['type'] == 'stats_update':
                print(f"Stats update: {data['data']}")
            elif data['type'] == 'alert':
                print(f"New alert: {data['data']}")
            elif data['type'] == 'topology_update':
                print(f"Topology updated")

asyncio.run(monitor())
```

## Performance Considerations

- The WebSocket connection sends updates every second by default
- Consider implementing client-side throttling for high-volume dashboards
- For historical data analysis, use appropriate time intervals to limit data points
- WebSocket connections are stateful and maintained for each client 