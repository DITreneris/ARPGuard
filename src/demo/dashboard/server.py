import os
import json
import asyncio
import random
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import scapy.all as scapy
from scapy.layers.l2 import ARP

# Initialize FastAPI app
app = FastAPI(title="ARP Guard Demo Dashboard")

# Mount static files and templates
current_dir = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(current_dir, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(current_dir, "static")), name="static")

# Store active WebSocket connections
active_connections: Set[WebSocket] = set()

# Packet capture state
is_capturing = False
packet_count = 0
alerts_triggered = 0
arp_cache = {}  # MAC to IP mapping
detected_anomalies = []

# System metrics (simulated for demo)
system_metrics = {
    "cpu_usage": 10,
    "memory_usage": 15,
    "disk_usage": 25,
    "packet_rate": 0,
    "threat_level": {"level": "Low", "value": 10}
}

# Network topology (will be populated during packet capture)
network_topology = {
    "nodes": [],
    "links": []
}

@app.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    """Serve the dashboard HTML page."""
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.websocket("/ws/dashboard")
async def websocket_endpoint(websocket: WebSocket):
    """Handle WebSocket connections for real-time updates."""
    await websocket.accept()
    active_connections.add(websocket)
    
    try:
        # Send initial state
        await send_system_status(websocket)
        await send_network_activity(websocket)
        await send_threat_level(websocket)
        await send_network_topology(websocket)
        
        # Handle incoming messages (like start/stop capture commands)
        while True:
            data = await websocket.receive_text()
            await process_websocket_message(websocket, data)
    except WebSocketDisconnect:
        active_connections.remove(websocket)
    except Exception as e:
        print(f"WebSocket error: {e}")
        if websocket in active_connections:
            active_connections.remove(websocket)

async def process_websocket_message(websocket: WebSocket, message: str):
    """Process incoming WebSocket messages."""
    try:
        data = json.loads(message)
        if data.get("type") == "start_capture":
            await start_packet_capture()
        elif data.get("type") == "stop_capture":
            await stop_packet_capture()
        elif data.get("type") == "acknowledge_alert":
            # Handle alert acknowledgment
            alert_id = data.get("alert_id")
            # In a real implementation, mark the alert as acknowledged in a database
            print(f"Alert {alert_id} acknowledged")
    except Exception as e:
        print(f"Error processing message: {e}")

async def broadcast_to_clients(message_type: str, data: dict):
    """Broadcast a message to all connected WebSocket clients."""
    message = json.dumps({"type": message_type, "data": data})
    for connection in active_connections:
        try:
            await connection.send_text(message)
        except Exception as e:
            print(f"Error broadcasting to client: {e}")

async def send_system_status(websocket: Optional[WebSocket] = None):
    """Send system status information."""
    if websocket:
        await websocket.send_text(json.dumps({
            "type": "system_status",
            "data": {
                "cpu_usage": system_metrics["cpu_usage"],
                "memory_usage": system_metrics["memory_usage"],
                "disk_usage": system_metrics["disk_usage"]
            }
        }))
    else:
        await broadcast_to_clients("system_status", {
            "cpu_usage": system_metrics["cpu_usage"],
            "memory_usage": system_metrics["memory_usage"],
            "disk_usage": system_metrics["disk_usage"]
        })

async def send_network_activity(websocket: Optional[WebSocket] = None):
    """Send network activity information."""
    global packet_count, alerts_triggered
    
    if websocket:
        await websocket.send_text(json.dumps({
            "type": "network_activity",
            "data": {
                "packets_processed": packet_count,
                "alerts_triggered": alerts_triggered,
                "active_connections": len(active_connections),
                "packet_rate": system_metrics["packet_rate"]
            }
        }))
    else:
        await broadcast_to_clients("network_activity", {
            "packets_processed": packet_count,
            "alerts_triggered": alerts_triggered,
            "active_connections": len(active_connections),
            "packet_rate": system_metrics["packet_rate"]
        })

async def send_threat_level(websocket: Optional[WebSocket] = None):
    """Send threat level information."""
    if websocket:
        await websocket.send_text(json.dumps({
            "type": "threat_level",
            "data": system_metrics["threat_level"]
        }))
    else:
        await broadcast_to_clients("threat_level", system_metrics["threat_level"])

async def send_network_topology(websocket: Optional[WebSocket] = None):
    """Send network topology information."""
    if websocket:
        await websocket.send_text(json.dumps({
            "type": "network_topology",
            "data": network_topology
        }))
    else:
        await broadcast_to_clients("network_topology", network_topology)

async def send_alert(alert_data: dict):
    """Send a new alert to all clients."""
    global alerts_triggered
    alerts_triggered += 1
    await broadcast_to_clients("alert", alert_data)
    await send_network_activity()

# Packet capture functionality
def packet_handler(packet):
    """Process captured packets."""
    global packet_count, arp_cache, network_topology
    
    # Increment packet counter
    packet_count += 1
    
    # Update packet rate
    system_metrics["packet_rate"] = random.randint(50, 200)  # Simulated for demo
    
    # Check if it's an ARP packet
    if ARP in packet:
        arp = packet[ARP]
        
        # Add to network topology if new
        src_mac = arp.hwsrc
        src_ip = arp.psrc
        dst_mac = arp.hwdst
        dst_ip = arp.pdst
        
        # Check for potential ARP spoofing
        if src_ip in arp_cache and arp_cache[src_ip] != src_mac:
            # Potential ARP spoofing detected!
            asyncio.run_coroutine_threadsafe(
                send_alert({
                    "id": f"alert-{int(time.time())}",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "High", 
                    "source": f"{src_ip} ({src_mac})",
                    "message": f"Potential ARP spoofing: IP {src_ip} changed MAC from {arp_cache[src_ip]} to {src_mac}"
                }),
                asyncio.get_event_loop()
            )
            
            # Update threat level
            system_metrics["threat_level"] = {"level": "High", "value": 80}
            asyncio.run_coroutine_threadsafe(
                send_threat_level(),
                asyncio.get_event_loop()
            )
        
        # Update ARP cache
        arp_cache[src_ip] = src_mac
        
        # Update network topology
        node_ids = []
        for device in [(src_ip, src_mac), (dst_ip, dst_mac)]:
            ip, mac = device
            if ip == "0.0.0.0" or mac == "00:00:00:00:00:00":
                continue
                
            # Check if node already exists
            node_exists = False
            for node in network_topology["nodes"]:
                if node["id"] == mac:
                    node_exists = True
                    break
            
            if not node_exists and ip and mac:
                network_topology["nodes"].append({
                    "id": mac,
                    "label": ip,
                    "group": "normal"
                })
            
            node_ids.append(mac)
        
        # Add link if both nodes exist and link doesn't already exist
        if len(node_ids) == 2:
            link_exists = False
            for link in network_topology["links"]:
                if (link["source"] == node_ids[0] and link["target"] == node_ids[1]) or \
                   (link["source"] == node_ids[1] and link["target"] == node_ids[0]):
                    link_exists = True
                    break
            
            if not link_exists:
                network_topology["links"].append({
                    "source": node_ids[0],
                    "target": node_ids[1],
                    "value": 1
                })

        # Broadcast updated network topology
        asyncio.run_coroutine_threadsafe(
            send_network_topology(),
            asyncio.get_event_loop()
        )
    
    # Update network activity stats every 10 packets
    if packet_count % 10 == 0:
        asyncio.run_coroutine_threadsafe(
            send_network_activity(),
            asyncio.get_event_loop()
        )
        
        # Simulate system metrics changes
        system_metrics["cpu_usage"] = min(95, max(5, system_metrics["cpu_usage"] + random.randint(-5, 5)))
        system_metrics["memory_usage"] = min(95, max(5, system_metrics["memory_usage"] + random.randint(-3, 3)))
        
        asyncio.run_coroutine_threadsafe(
            send_system_status(),
            asyncio.get_event_loop()
        )

# Packet capture thread
capture_thread = None
sniffer = None

async def start_packet_capture():
    """Start packet capture process."""
    global is_capturing, capture_thread, sniffer
    
    if is_capturing:
        return
    
    is_capturing = True
    
    # Use scapy to sniff packets
    def start_sniffer():
        global sniffer
        try:
            print("Starting packet capture...")
            # In a production environment, specify the appropriate interface
            sniffer = scapy.sniff(prn=packet_handler, store=False, filter="arp")
        except Exception as e:
            print(f"Error in packet capture: {e}")
        finally:
            is_capturing = False
    
    capture_thread = threading.Thread(target=start_sniffer)
    capture_thread.daemon = True
    capture_thread.start()
    
    # Send alert that capture started
    await send_alert({
        "id": f"alert-{int(time.time())}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity": "Info",
        "source": "System",
        "message": "Packet capture started"
    })

async def stop_packet_capture():
    """Stop the packet capture process."""
    global is_capturing, sniffer
    
    if not is_capturing:
        return
    
    # Stop the sniffer
    if sniffer:
        try:
            # This is not a clean way to stop scapy sniffer, but it works for demo
            is_capturing = False
            print("Stopping packet capture...")
        except Exception as e:
            print(f"Error stopping packet capture: {e}")
    
    # Send alert that capture stopped
    await send_alert({
        "id": f"alert-{int(time.time())}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity": "Info",
        "source": "System",
        "message": "Packet capture stopped"
    })

# Background task to simulate activity when no real packets are captured
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(simulate_activity())

async def simulate_activity():
    """Simulate network activity and system metrics for demo purposes."""
    while True:
        await asyncio.sleep(3)
        
        # Only simulate if not capturing real packets
        if not is_capturing:
            # Simulate packet processing
            global packet_count
            packet_count += random.randint(5, 20)
            
            # Simulate system metrics changes
            system_metrics["cpu_usage"] = min(95, max(5, system_metrics["cpu_usage"] + random.randint(-5, 5)))
            system_metrics["memory_usage"] = min(95, max(5, system_metrics["memory_usage"] + random.randint(-3, 3)))
            system_metrics["disk_usage"] = min(95, max(5, system_metrics["disk_usage"] + random.randint(-2, 2)))
            system_metrics["packet_rate"] = random.randint(10, 50)
            
            # Random chance to change threat level
            if random.random() < 0.1:
                level_options = [
                    {"level": "Low", "value": random.randint(0, 30)},
                    {"level": "Medium", "value": random.randint(31, 70)},
                    {"level": "High", "value": random.randint(71, 100)}
                ]
                system_metrics["threat_level"] = random.choice(level_options)
            
            # Broadcast updates
            await send_system_status()
            await send_network_activity()
            await send_threat_level()
            
            # Random chance to generate an alert
            if random.random() < 0.2:
                alert_types = [
                    {"severity": "Low", "message": "Unusual network traffic detected"},
                    {"severity": "Medium", "message": "Repeated ARP requests from unknown device"},
                    {"severity": "High", "message": "Potential ARP spoofing attempt detected"}
                ]
                alert_type = random.choice(alert_types)
                
                await send_alert({
                    "id": f"alert-{int(time.time())}",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": alert_type["severity"],
                    "source": f"192.168.1.{random.randint(1, 254)}",
                    "message": alert_type["message"]
                })

# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 