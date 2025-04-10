import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query, status, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import json
import random

from app.core.auth import get_current_user
from app.utils.performance import PerformanceMonitor
from app.utils.version_helpers import (
    get_api_version, 
    requires_version,
    versioned_response,
    deprecated_since
)
from app.components.network_topology import topology_ws_handler

# Initialize performance monitor for real-time stats
performance_monitor = PerformanceMonitor()

# Create router for monitoring endpoints
router = APIRouter(prefix="/api/v1/monitor", tags=["monitoring"])

# Models for monitoring data
class Alert(BaseModel):
    id: str
    type: str
    severity: str
    timestamp: str
    status: str = "active"
    source_ip: Optional[str] = None
    source_mac: Optional[str] = None
    target_ip: Optional[str] = None
    target_mac: Optional[str] = None
    description: Optional[str] = None

class NetworkStats(BaseModel):
    packets_processed: int
    attacks_detected: int
    network_throughput: float
    cpu_usage: float = Field(..., description="CPU usage in percent")
    memory_usage: float = Field(..., description="Memory usage in percent")
    response_time: float = Field(..., description="Average response time in ms")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())

class NetworkNode(BaseModel):
    id: str
    ip: str
    mac: str
    status: str
    last_seen: str
    device_type: Optional[str] = None
    hostname: Optional[str] = None
    is_gateway: bool = False

class NetworkEdge(BaseModel):
    source: str
    target: str
    packets: int = 0
    bytes: int = 0

class NetworkTopology(BaseModel):
    nodes: List[NetworkNode]
    edges: List[NetworkEdge]

# In-memory storage for websocket connections
active_connections: List[WebSocket] = []

# In-memory cache for alerts (in a real app, this would be in a database)
# For demo purposes only
sample_alerts = [
    Alert(
        id="alert-001",
        type="arp_spoofing",
        severity="critical",
        timestamp=datetime.now().isoformat(),
        source_ip="192.168.1.100",
        source_mac="00:11:22:33:44:55",
        target_ip="192.168.1.1",
        target_mac="aa:bb:cc:dd:ee:ff",
        description="ARP spoofing attack detected"
    ),
    Alert(
        id="alert-002",
        type="mac_flooding",
        severity="medium",
        timestamp=(datetime.now() - timedelta(minutes=10)).isoformat(),
        source_ip="192.168.1.150",
        source_mac="00:11:22:33:66:77",
        description="MAC flooding attack detected"
    ),
]

# Sample network topology for demo purposes
sample_topology = NetworkTopology(
    nodes=[
        NetworkNode(
            id="node1",
            ip="192.168.1.1",
            mac="00:11:22:33:44:55",
            status="online",
            last_seen=datetime.now().isoformat(),
            device_type="router",
            hostname="gateway",
            is_gateway=True
        ),
        NetworkNode(
            id="node2",
            ip="192.168.1.100",
            mac="aa:bb:cc:dd:ee:ff",
            status="online",
            last_seen=datetime.now().isoformat(),
            device_type="workstation",
            hostname="user-pc"
        ),
    ],
    edges=[
        NetworkEdge(
            source="node1",
            target="node2",
            packets=1500,
            bytes=1500000
        )
    ]
)

# Endpoint for getting network statistics
@router.get("/stats")
async def get_network_stats(
    request: Request,
    version: str = Depends(requires_version("0.9.0")),
    current_user = Depends(get_current_user)
):
    """Get network monitoring statistics."""
    # Get basic statistics
    stats = {
        "packets_captured": 1000,
        "packets_analyzed": 950,
        "alerts_triggered": 5,
        "attack_attempts": 2,
        "blocked_packets": 10,
        "monitoring_time": 3600,  # seconds
        "interfaces": ["eth0", "wlan0"],
        "timestamp": datetime.now().isoformat()
    }
    
    # Transform response based on API version
    return versioned_response(
        request,
        stats,
        {
            "0.9.0": lambda d: {
                "data": {
                    "packets": {
                        "total": d["packets_captured"],
                        "analyzed": d["packets_analyzed"]
                    },
                    "alerts": d["alerts_triggered"],
                    "attacks": d["attack_attempts"],
                    "blocked": d["blocked_packets"],
                    "uptime": d["monitoring_time"],
                    "interfaces": d["interfaces"],
                    "time": d["timestamp"]
                },
                "version": "0.9.0"
            },
            "1.0.0": lambda d: {
                "statistics": {
                    "packets": {
                        "captured": d["packets_captured"],
                        "analyzed": d["packets_analyzed"],
                        "blocked": d["blocked_packets"]
                    },
                    "security": {
                        "alerts": d["alerts_triggered"],
                        "attacks": d["attack_attempts"]
                    },
                    "system": {
                        "uptime_seconds": d["monitoring_time"],
                        "monitored_interfaces": d["interfaces"],
                    }
                },
                "timestamp": d["timestamp"],
                "api_version": "1.0.0"
            }
        }
    )

@router.get("/stats/legacy", deprecated=True)
@deprecated_since("1.0.0", use_instead="/api/v1/monitor/stats")
async def get_legacy_stats(
    request: Request,
    current_user = Depends(get_current_user)
):
    """Legacy endpoint for network statistics (deprecated)."""
    return await get_network_stats(request, current_user=current_user)

# Endpoint for getting alerts with filters
@router.get("/alerts", response_model=Dict[str, List[Alert]])
async def get_alerts(
    current_user = Depends(get_current_user),
    severity: Optional[str] = None,
    time_range: Optional[str] = None,
    status: Optional[str] = None
):
    """Get alerts with optional filters"""
    # Validate filters
    valid_severities = ["critical", "high", "medium", "low"]
    valid_time_ranges = ["1h", "6h", "24h", "7d"]
    valid_statuses = ["active", "acknowledged", "ignored"]
    
    if severity and severity.lower() not in valid_severities:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid severity. Must be one of {valid_severities}"
        )
    
    if time_range and time_range not in valid_time_ranges:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid time range. Must be one of {valid_time_ranges}"
        )
    
    if status and status.lower() not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of {valid_statuses}"
        )
    
    # Filter alerts based on criteria
    filtered_alerts = sample_alerts
    
    if severity:
        filtered_alerts = [a for a in filtered_alerts if a.severity.lower() == severity.lower()]
    
    if status:
        filtered_alerts = [a for a in filtered_alerts if a.status.lower() == status.lower()]
    
    if time_range:
        # Parse time range
        hours = 1
        if time_range == "6h":
            hours = 6
        elif time_range == "24h":
            hours = 24
        elif time_range == "7d":
            hours = 24 * 7
        
        time_threshold = datetime.now() - timedelta(hours=hours)
        filtered_alerts = [
            a for a in filtered_alerts 
            if datetime.fromisoformat(a.timestamp) >= time_threshold
        ]
    
    return {"alerts": filtered_alerts}

# Endpoint for getting network topology
@router.get("/topology", response_model=NetworkTopology)
async def get_topology(
    current_user = Depends(get_current_user),
    details: bool = Query(False, description="Whether to include detailed node information")
):
    """Get network topology data"""
    if not details:
        # Remove detailed information if not requested
        simplified_nodes = []
        for node in sample_topology.nodes:
            simplified_node = NetworkNode(
                id=node.id,
                ip=node.ip,
                mac=node.mac,
                status=node.status,
                last_seen=node.last_seen
            )
            simplified_nodes.append(simplified_node)
        
        return NetworkTopology(nodes=simplified_nodes, edges=sample_topology.edges)
    
    return sample_topology

# WebSocket endpoint for real-time monitoring
@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time monitoring updates"""
    await websocket.accept()
    active_connections.append(websocket)
    
    try:
        # Add client to topology handler
        topology_ws_handler.add_client(websocket)
        
        while True:
            # Wait for messages from client
            data = await websocket.receive_text()
            
            try:
                message = json.loads(data)
                message_type = message.get("type", "")
                
                # Process different message types
                if message_type == "request_topology_update":
                    # Client is requesting current topology data
                    await websocket.send_json({
                        "type": "topology_update",
                        "data": {
                            "devices": sample_topology.nodes,
                            "connections": sample_topology.edges
                        },
                        "timestamp": datetime.now().isoformat()
                    })
                
                elif message_type == "subscribe":
                    # Client is subscribing to a topic
                    topic = message.get("topic", "")
                    if topic:
                        # In a real implementation, we'd track subscriptions
                        await websocket.send_json({
                            "type": "subscription_confirmed",
                            "topic": topic,
                            "timestamp": datetime.now().isoformat()
                        })
                
                elif message_type == "unsubscribe":
                    # Client is unsubscribing from a topic
                    topic = message.get("topic", "")
                    if topic:
                        # In a real implementation, we'd remove subscription
                        await websocket.send_json({
                            "type": "unsubscription_confirmed",
                            "topic": topic,
                            "timestamp": datetime.now().isoformat()
                        })
                
                elif message_type == "ping":
                    # Client ping
                    await websocket.send_json({
                        "type": "pong",
                        "timestamp": datetime.now().isoformat()
                    })
                
                else:
                    # Unknown message type
                    await websocket.send_json({
                        "type": "error",
                        "message": f"Unknown message type: {message_type}",
                        "timestamp": datetime.now().isoformat()
                    })
            
            except json.JSONDecodeError:
                # Not a valid JSON message
                await websocket.send_json({
                    "type": "error",
                    "message": "Invalid JSON message",
                    "timestamp": datetime.now().isoformat()
                })
                
    except WebSocketDisconnect:
        # Remove client from topology handler
        topology_ws_handler.remove_client(websocket)
        active_connections.remove(websocket)

# Backend function to broadcast monitoring updates to all connected clients
async def broadcast_monitoring_updates():
    """Send real-time updates to all connected WebSocket clients"""
    if not active_connections:
        return
    
    # Get current network stats
    metrics = performance_monitor.get_metrics()
    stats = {
        "type": "stats_update",
        "data": {
            "packets_processed": metrics.get("packets_processed", 0),
            "attacks_detected": len(sample_alerts),
            "network_throughput": metrics.get("network_traffic", 0),
            "cpu_usage": metrics.get("cpu_usage", 0),
            "memory_usage": metrics.get("memory_usage", 0),
            "response_time": metrics.get("response_time", 0),
            "timestamp": datetime.now().isoformat()
        }
    }
    
    # Send to all connected clients
    for connection in active_connections:
        try:
            await connection.send_json(stats)
        except Exception:
            # Remove closed connections
            if connection in active_connections:
                active_connections.remove(connection)

# Function to start the background task for real-time updates
def start_background_tasks(app):
    """Start background tasks for the monitoring system"""
    @app.on_event("startup")
    async def start_scheduler():
        """Start the background monitoring task"""
        # Start the topology WebSocket handler update thread
        topology_ws_handler.start_update_thread(update_interval=1.0)
        
        # Start the monitor task
        asyncio.create_task(monitor_background_task())
    
    @app.on_event("shutdown")
    async def shutdown_event():
        """Clean up on shutdown"""
        # Stop the topology WebSocket handler
        topology_ws_handler.stop_update_thread()
        
        # Close all websocket connections
        for connection in active_connections:
            try:
                await connection.close()
            except Exception:
                pass
        
        active_connections.clear()

# Update the background task to send topology updates
async def monitor_background_task():
    """Background task to send updates to clients"""
    while True:
        # Send monitoring updates to clients
        await broadcast_monitoring_updates()
        
        # Update topology data periodically (simulated changes)
        # In a real implementation, this would come from actual network scanning
        if random.random() < 0.2:  # 20% chance of a topology update each cycle
            # Generate a random topology update
            simulate_topology_changes()
        
        # Sleep for a short interval to avoid flooding clients
        await asyncio.sleep(1)

# Add function to simulate topology changes
def simulate_topology_changes():
    """Simulate changes to the network topology for testing real-time updates"""
    # Get current data
    devices = [
        {
            "id": node.id,
            "name": f"Device-{node.id}",
            "ip": node.ip,
            "mac": node.mac,
            "isGateway": node.id == "1",  # Assume node 1 is gateway
            "deviceType": "router" if node.id == "1" else random.choice(["computer", "server", "iot", "mobile"])
        }
        for node in sample_topology.nodes
    ]
    
    connections = [
        {
            "id": f"{edge.source}-{edge.target}",
            "source": edge.source,
            "target": edge.target
        }
        for edge in sample_topology.edges
    ]
    
    # Randomly modify the topology
    random_action = random.choice(["add_device", "update_device", "remove_device", "add_connection", "remove_connection"])
    
    if random_action == "add_device" and len(devices) < 10:
        # Add a new device
        new_id = str(int(max([int(device["id"]) for device in devices])) + 1)
        new_device = {
            "id": new_id,
            "name": f"Device-{new_id}",
            "ip": f"192.168.1.{random.randint(10, 250)}",
            "mac": ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)]),
            "isGateway": False,
            "deviceType": random.choice(["computer", "server", "iot", "mobile"])
        }
        
        # Add it to the global topology handler
        topology_ws_handler.add_device(new_device)
        
        # Also add a connection to the gateway
        new_connection = {
            "id": f"1-{new_id}",
            "source": "1",  # Gateway
            "target": new_id
        }
        topology_ws_handler.add_connection(new_connection)
    
    elif random_action == "update_device" and devices:
        # Update a random device
        device_to_update = random.choice(devices)
        updates = {
            "ip": f"192.168.1.{random.randint(10, 250)}",
            "deviceType": random.choice(["computer", "server", "iot", "mobile"])
        }
        topology_ws_handler.update_device(device_to_update["id"], updates)
    
    elif random_action == "remove_device" and len(devices) > 5:
        # Remove a random device (but not the gateway)
        non_gateway_devices = [d for d in devices if not d["isGateway"]]
        if non_gateway_devices:
            device_to_remove = random.choice(non_gateway_devices)
            topology_ws_handler.remove_device(device_to_remove["id"])
    
    elif random_action == "add_connection" and len(devices) >= 2:
        # Add a new connection between two devices
        available_devices = [d["id"] for d in devices]
        source = random.choice(available_devices)
        available_targets = [d for d in available_devices if d != source]
        
        if available_targets:
            target = random.choice(available_targets)
            # Check if this connection already exists
            connection_exists = any(
                (c["source"] == source and c["target"] == target) or
                (c["source"] == target and c["target"] == source)
                for c in connections
            )
            
            if not connection_exists:
                new_connection = {
                    "id": f"{source}-{target}",
                    "source": source,
                    "target": target
                }
                topology_ws_handler.add_connection(new_connection)
    
    elif random_action == "remove_connection" and connections:
        # Remove a random connection (but keep the graph connected)
        # For simplicity, we'll just ensure all nodes have at least one connection
        # by preserving connections to the gateway
        non_gateway_connections = [
            c for c in connections
            if not (c["source"] == "1" or c["target"] == "1")
        ]
        
        if non_gateway_connections:
            connection_to_remove = random.choice(non_gateway_connections)
            topology_ws_handler.remove_connection(connection_to_remove["id"])

# API route to trigger a test alert (for development purposes)
@router.post("/trigger-test-alert", status_code=status.HTTP_201_CREATED)
async def trigger_test_alert(
    current_user = Depends(get_current_user),
    alert_type: str = "arp_spoofing",
    severity: str = "critical"
):
    """Trigger a test alert for development purposes"""
    new_alert = Alert(
        id=f"alert-{len(sample_alerts) + 1:03d}",
        type=alert_type,
        severity=severity,
        timestamp=datetime.now().isoformat(),
        source_ip="192.168.1.200",
        source_mac="00:11:22:33:99:88",
        target_ip="192.168.1.1",
        target_mac="aa:bb:cc:dd:ee:ff",
        description=f"Test {alert_type} alert"
    )
    
    sample_alerts.append(new_alert)
    
    # In a real implementation, this would trigger a notification to all clients
    return {"status": "success", "message": "Test alert triggered", "alert_id": new_alert.id}

# API route for historical data analysis
@router.get("/historical", status_code=status.HTTP_200_OK)
async def get_historical_data(
    current_user = Depends(get_current_user),
    metric: str = Query(..., description="Metric to analyze"),
    start_date: str = Query(..., description="Start date in ISO format"),
    end_date: str = Query(..., description="End date in ISO format"),
    interval: str = Query("1h", description="Interval for data points (1h, 6h, 1d)")
):
    """Get historical data for analysis"""
    try:
        # Parse dates
        start = datetime.fromisoformat(start_date)
        end = datetime.fromisoformat(end_date)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid date format. Use ISO format (YYYY-MM-DDTHH:MM:SS)"
        )
    
    # Validate metric
    valid_metrics = ["packets_processed", "attacks_detected", "network_throughput", 
                    "cpu_usage", "memory_usage", "response_time"]
    
    if metric not in valid_metrics:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid metric. Must be one of {valid_metrics}"
        )
    
    # In a real implementation, this would query a time-series database
    # For demo purposes, generate synthetic data
    current = start
    data_points = []
    
    # Set interval in hours
    interval_hours = 1
    if interval == "6h":
        interval_hours = 6
    elif interval == "1d":
        interval_hours = 24
    
    while current <= end:
        # Generate random value for demo
        if metric == "packets_processed":
            value = int(time.time() * 10) % 1000 + 500
        elif metric == "attacks_detected":
            value = int(time.time()) % 10
        elif metric == "network_throughput":
            value = int(time.time() * 5) % 100 + 50
        elif metric == "cpu_usage":
            value = int(time.time() * 2) % 30 + 10
        elif metric == "memory_usage":
            value = int(time.time() * 3) % 40 + 20
        else:  # response_time
            value = int(time.time() * 4) % 50 + 30
        
        data_points.append({
            "timestamp": current.isoformat(),
            "value": value
        })
        
        current += timedelta(hours=interval_hours)
    
    return {
        "metric": metric,
        "start_date": start_date,
        "end_date": end_date,
        "interval": interval,
        "data_points": data_points
    } 