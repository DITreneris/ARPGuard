import os
import json
import logging
import threading
import time
from pathlib import Path
from typing import Dict, Any, List, Optional

import websockets
import asyncio
from aiohttp import web

from .alert import AlertManager, Alert, AlertType, AlertPriority, AlertStatus
from .ui_notifier import UINotifier, WebUIConnector

class AlertDashboard:
    """Web dashboard for monitoring and managing alerts."""
    
    def __init__(self, 
                alert_manager: AlertManager, 
                ui_notifier: UINotifier,
                host: str = "localhost", 
                port: int = 8080,
                static_dir: str = None):
        """
        Initialize the alert dashboard.
        
        Args:
            alert_manager: Alert manager instance
            ui_notifier: UI notifier instance
            host: Host to bind the server to
            port: Port to bind the server to
            static_dir: Directory containing static web files
        """
        self.alert_manager = alert_manager
        self.ui_notifier = ui_notifier
        self.host = host
        self.port = port
        
        # Set default static directory if none provided
        if static_dir is None:
            current_file = Path(__file__).resolve()
            self.static_dir = current_file.parent.parent.parent / "web" / "dashboard"
        else:
            self.static_dir = Path(static_dir)
            
        # Create static directory if it doesn't exist
        os.makedirs(self.static_dir, exist_ok=True)
        
        self.logger = logging.getLogger('alert_dashboard')
        self.app = web.Application()
        self.websocket_server = None
        self.web_ui_connector = None
        self.connected_ws_clients = set()
        
        # Set up routes
        self.setup_routes()
        
    def setup_routes(self):
        """Set up HTTP routes for the dashboard."""
        # API routes
        self.app.router.add_get('/api/alerts', self.handle_get_alerts)
        self.app.router.add_get('/api/alerts/{alert_id}', self.handle_get_alert)
        self.app.router.add_post('/api/alerts/{alert_id}/acknowledge', self.handle_acknowledge_alert)
        self.app.router.add_post('/api/alerts/{alert_id}/resolve', self.handle_resolve_alert)
        self.app.router.add_get('/api/stats', self.handle_get_stats)
        
        # WebSocket route
        self.app.router.add_get('/ws', self.handle_websocket)
        
        # Static files
        self.app.router.add_static('/', self.static_dir)
        
        # Default route - serve index.html
        self.app.router.add_get('/', self.handle_index)
        
    async def handle_index(self, request):
        """Handle requests to the root path."""
        index_path = self.static_dir / "index.html"
        
        # Create a basic index.html if it doesn't exist
        if not index_path.exists():
            self.create_default_index_html()
            
        return web.FileResponse(index_path)
        
    def create_default_index_html(self):
        """Create a default index.html file if none exists."""
        index_html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>ARP Guard Alert Dashboard</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f5f5f5;
                }
                header {
                    background-color: #2c3e50;
                    color: white;
                    padding: 1rem;
                    text-align: center;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 1rem;
                }
                .alert-container {
                    margin-top: 2rem;
                }
                .alert {
                    background-color: white;
                    border-radius: 4px;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.12);
                    margin-bottom: 1rem;
                    padding: 1rem;
                }
                .alert-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 0.5rem;
                }
                .alert-id {
                    font-size: 0.8rem;
                    color: #7f8c8d;
                }
                .alert-type {
                    font-weight: bold;
                }
                .alert-priority {
                    padding: 0.25rem 0.5rem;
                    border-radius: 4px;
                    font-size: 0.8rem;
                    font-weight: bold;
                }
                .priority-LOW {
                    background-color: #2ecc71;
                    color: white;
                }
                .priority-MEDIUM {
                    background-color: #f39c12;
                    color: white;
                }
                .priority-HIGH {
                    background-color: #e67e22;
                    color: white;
                }
                .priority-CRITICAL {
                    background-color: #e74c3c;
                    color: white;
                }
                .alert-message {
                    font-size: 1.1rem;
                    margin: 0.5rem 0;
                }
                .alert-source {
                    font-size: 0.9rem;
                    color: #7f8c8d;
                }
                .alert-time {
                    font-size: 0.9rem;
                    color: #7f8c8d;
                }
                .alert-details {
                    background-color: #f5f5f5;
                    padding: 0.5rem;
                    border-radius: 4px;
                    margin-top: 0.5rem;
                    font-family: monospace;
                }
                .alert-actions {
                    display: flex;
                    justify-content: flex-end;
                    margin-top: 1rem;
                }
                button {
                    padding: 0.5rem 1rem;
                    border: none;
                    border-radius: 4px;
                    margin-left: 0.5rem;
                    cursor: pointer;
                }
                .acknowledge-btn {
                    background-color: #3498db;
                    color: white;
                }
                .resolve-btn {
                    background-color: #2ecc71;
                    color: white;
                }
                .stats-container {
                    display: flex;
                    justify-content: space-between;
                    margin-bottom: 2rem;
                }
                .stat-card {
                    background-color: white;
                    border-radius: 4px;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.12);
                    padding: 1rem;
                    flex: 1;
                    margin: 0 0.5rem;
                    text-align: center;
                }
                .stat-value {
                    font-size: 2rem;
                    font-weight: bold;
                    margin: 0.5rem 0;
                }
                .stat-label {
                    font-size: 0.9rem;
                    color: #7f8c8d;
                }
                .status-indicator {
                    display: inline-block;
                    width: 10px;
                    height: 10px;
                    border-radius: 50%;
                    margin-right: 5px;
                }
                .status-ACTIVE {
                    background-color: #e74c3c;
                }
                .status-ACKNOWLEDGED {
                    background-color: #f39c12;
                }
                .status-RESOLVED {
                    background-color: #2ecc71;
                }
                .alert-status {
                    display: flex;
                    align-items: center;
                }
                #no-alerts-message {
                    text-align: center;
                    margin-top: 2rem;
                    color: #7f8c8d;
                }
                .hidden {
                    display: none;
                }
            </style>
        </head>
        <body>
            <header>
                <h1>ARP Guard Alert Dashboard</h1>
            </header>
            
            <div class="container">
                <div class="stats-container">
                    <div class="stat-card">
                        <div class="stat-value" id="total-alerts">0</div>
                        <div class="stat-label">Total Alerts</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="active-alerts">0</div>
                        <div class="stat-label">Active Alerts</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="critical-alerts">0</div>
                        <div class="stat-label">Critical Alerts</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="arp-spoofing-alerts">0</div>
                        <div class="stat-label">ARP Spoofing Alerts</div>
                    </div>
                </div>
                
                <div class="alert-container" id="alert-container">
                    <div id="no-alerts-message">No alerts to display</div>
                </div>
            </div>
            
            <script>
                // WebSocket connection
                const socket = new WebSocket(`ws://${window.location.host}/ws`);
                let alerts = [];
                
                // Connection opened
                socket.addEventListener('open', (event) => {
                    console.log('Connected to WebSocket server');
                });
                
                // Listen for messages
                socket.addEventListener('message', (event) => {
                    const data = JSON.parse(event.data);
                    if (data.type === 'alert') {
                        handleAlertNotification(data);
                    }
                });
                
                // Connection closed
                socket.addEventListener('close', (event) => {
                    console.log('Disconnected from WebSocket server');
                });
                
                // Handle alert notifications
                function handleAlertNotification(alert) {
                    const existingAlertIndex = alerts.findIndex(a => a.alert_id === alert.alert_id);
                    
                    if (existingAlertIndex >= 0) {
                        // Update existing alert
                        alerts[existingAlertIndex] = alert;
                    } else {
                        // Add new alert
                        alerts.unshift(alert);
                    }
                    
                    renderAlerts();
                    updateStats();
                }
                
                // Fetch all alerts
                async function fetchAlerts() {
                    try {
                        const response = await fetch('/api/alerts');
                        const data = await response.json();
                        alerts = data.alerts;
                        renderAlerts();
                        updateStats();
                    } catch (error) {
                        console.error('Error fetching alerts:', error);
                    }
                }
                
                // Render alerts
                function renderAlerts() {
                    const container = document.getElementById('alert-container');
                    const noAlertsMessage = document.getElementById('no-alerts-message');
                    
                    if (alerts.length === 0) {
                        noAlertsMessage.classList.remove('hidden');
                        return;
                    }
                    
                    noAlertsMessage.classList.add('hidden');
                    
                    // Clear container
                    container.innerHTML = '';
                    
                    // Add alerts
                    alerts.forEach(alert => {
                        const alertEl = document.createElement('div');
                        alertEl.className = 'alert';
                        alertEl.innerHTML = `
                            <div class="alert-header">
                                <div>
                                    <span class="alert-type">${formatAlertType(alert.alert_type)}</span>
                                    <span class="alert-id">#${alert.alert_id.substring(0, 8)}</span>
                                </div>
                                <span class="alert-priority priority-${alert.priority}">${alert.priority}</span>
                            </div>
                            <div class="alert-message">${alert.message}</div>
                            <div class="alert-source">Source: ${alert.source}</div>
                            <div class="alert-time">Time: ${formatTime(alert.timestamp)}</div>
                            <div class="alert-status">
                                Status: 
                                <span class="status-indicator status-${alert.status}"></span>
                                ${alert.status}
                            </div>
                            <div class="alert-details">${formatDetails(alert.details)}</div>
                            <div class="alert-actions">
                                ${alert.status === 'ACTIVE' ? 
                                    `<button class="acknowledge-btn" onclick="acknowledgeAlert('${alert.alert_id}')">Acknowledge</button>` : ''}
                                ${alert.status !== 'RESOLVED' ? 
                                    `<button class="resolve-btn" onclick="resolveAlert('${alert.alert_id}')">Resolve</button>` : ''}
                            </div>
                        `;
                        container.appendChild(alertEl);
                    });
                }
                
                // Update dashboard stats
                function updateStats() {
                    document.getElementById('total-alerts').textContent = alerts.length;
                    document.getElementById('active-alerts').textContent = alerts.filter(a => a.status === 'ACTIVE').length;
                    document.getElementById('critical-alerts').textContent = alerts.filter(a => a.priority === 'CRITICAL').length;
                    document.getElementById('arp-spoofing-alerts').textContent = alerts.filter(a => a.alert_type === 'arp_spoofing').length;
                }
                
                // Format alert type
                function formatAlertType(type) {
                    return type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
                }
                
                // Format timestamp
                function formatTime(timestamp) {
                    return new Date(timestamp * 1000).toLocaleString();
                }
                
                // Format alert details
                function formatDetails(details) {
                    return JSON.stringify(details, null, 2);
                }
                
                // Acknowledge alert
                async function acknowledgeAlert(alertId) {
                    try {
                        const response = await fetch(`/api/alerts/${alertId}/acknowledge`, {
                            method: 'POST'
                        });
                        
                        if (response.ok) {
                            const alertIndex = alerts.findIndex(a => a.alert_id === alertId);
                            if (alertIndex >= 0) {
                                alerts[alertIndex].status = 'ACKNOWLEDGED';
                                renderAlerts();
                                updateStats();
                            }
                        }
                    } catch (error) {
                        console.error('Error acknowledging alert:', error);
                    }
                }
                
                // Resolve alert
                async function resolveAlert(alertId) {
                    try {
                        const response = await fetch(`/api/alerts/${alertId}/resolve`, {
                            method: 'POST'
                        });
                        
                        if (response.ok) {
                            const alertIndex = alerts.findIndex(a => a.alert_id === alertId);
                            if (alertIndex >= 0) {
                                alerts[alertIndex].status = 'RESOLVED';
                                renderAlerts();
                                updateStats();
                            }
                        }
                    } catch (error) {
                        console.error('Error resolving alert:', error);
                    }
                }
                
                // Initial fetch
                fetchAlerts();
                
                // Fetch alerts every 30 seconds
                setInterval(fetchAlerts, 30000);
            </script>
        </body>
        </html>
        """
        
        index_path = self.static_dir / "index.html"
        with open(index_path, 'w') as f:
            f.write(index_html)
            
        self.logger.info(f"Created default index.html at {index_path}")
        
    async def handle_get_alerts(self, request):
        """Handle GET request for alerts."""
        alerts = self.alert_manager.get_all_alerts()
        return web.json_response({
            "alerts": [alert.to_dict() for alert in alerts]
        })
        
    async def handle_get_alert(self, request):
        """Handle GET request for a specific alert."""
        alert_id = request.match_info['alert_id']
        alert = self.alert_manager.get_alert(alert_id)
        
        if alert:
            return web.json_response(alert.to_dict())
        return web.json_response({"error": "Alert not found"}, status=404)
        
    async def handle_acknowledge_alert(self, request):
        """Handle POST request to acknowledge an alert."""
        alert_id = request.match_info['alert_id']
        success = self.alert_manager.acknowledge_alert(alert_id)
        
        if success:
            return web.json_response({"status": "success"})
        return web.json_response({"error": "Failed to acknowledge alert"}, status=400)
        
    async def handle_resolve_alert(self, request):
        """Handle POST request to resolve an alert."""
        alert_id = request.match_info['alert_id']
        success = self.alert_manager.resolve_alert(alert_id)
        
        if success:
            return web.json_response({"status": "success"})
        return web.json_response({"error": "Failed to resolve alert"}, status=400)
        
    async def handle_get_stats(self, request):
        """Handle GET request for alert statistics."""
        all_alerts = self.alert_manager.get_all_alerts()
        active_alerts = self.alert_manager.get_active_alerts()
        
        # Count alerts by type
        type_counts = {}
        for alert in all_alerts:
            alert_type = alert.type.value
            if alert_type not in type_counts:
                type_counts[alert_type] = 0
            type_counts[alert_type] += 1
            
        # Count alerts by priority
        priority_counts = {}
        for alert in all_alerts:
            priority = alert.priority.name
            if priority not in priority_counts:
                priority_counts[priority] = 0
            priority_counts[priority] += 1
            
        # Count alerts by status
        status_counts = {}
        for alert in all_alerts:
            status = alert.status.name
            if status not in status_counts:
                status_counts[status] = 0
            status_counts[status] += 1
            
        return web.json_response({
            "total_alerts": len(all_alerts),
            "active_alerts": len(active_alerts),
            "by_type": type_counts,
            "by_priority": priority_counts,
            "by_status": status_counts
        })
        
    async def handle_websocket(self, request):
        """Handle WebSocket connections."""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        self.connected_ws_clients.add(ws)
        self.logger.info(f"WebSocket client connected, total: {len(self.connected_ws_clients)}")
        
        try:
            async for msg in ws:
                if msg.type == web.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        # Handle any client commands here
                        if data.get('action') == 'get_alerts':
                            alerts = self.alert_manager.get_all_alerts()
                            await ws.send_json({
                                "type": "alerts",
                                "alerts": [alert.to_dict() for alert in alerts]
                            })
                    except json.JSONDecodeError:
                        self.logger.warning(f"Received invalid JSON: {msg.data}")
                        
                elif msg.type == web.WSMsgType.ERROR:
                    self.logger.error(f"WebSocket connection closed with exception: {ws.exception()}")
        finally:
            self.connected_ws_clients.discard(ws)
            self.logger.info(f"WebSocket client disconnected, remaining: {len(self.connected_ws_clients)}")
            
        return ws
        
    async def broadcast_to_websocket_clients(self, message):
        """Broadcast a message to all connected WebSocket clients."""
        if not self.connected_ws_clients:
            return
            
        disconnected = set()
        for ws in self.connected_ws_clients:
            try:
                if isinstance(message, dict):
                    await ws.send_json(message)
                else:
                    await ws.send_str(message)
            except Exception as e:
                self.logger.error(f"Error sending message to WebSocket client: {e}")
                disconnected.add(ws)
                
        # Remove disconnected clients
        for ws in disconnected:
            self.connected_ws_clients.discard(ws)
            
    class MockWebSocketServer:
        """Mock WebSocket server for use with WebUIConnector."""
        
        def __init__(self, dashboard):
            self.dashboard = dashboard
            self.logger = logging.getLogger('mock_websocket_server')
            
        def broadcast(self, message):
            """Broadcast a message to all WebSocket clients."""
            if asyncio.iscoroutinefunction(self.dashboard.broadcast_to_websocket_clients):
                asyncio.create_task(self.dashboard.broadcast_to_websocket_clients(message))
            else:
                self.logger.error("broadcast_to_websocket_clients is not a coroutine function")
        
    def start(self):
        """Start the dashboard server."""
        # Create and configure WebSocket server for UI notifier
        self.websocket_server = self.MockWebSocketServer(self)
        
        # Connect WebUI to UI notifier
        self.web_ui_connector = WebUIConnector(self.ui_notifier, self.websocket_server)
        self.web_ui_connector.connect()
        
        # Run the web server
        self.runner = web.AppRunner(self.app)
        return web.run_app(self.app, host=self.host, port=self.port)
        
    def stop(self):
        """Stop the dashboard server."""
        if self.web_ui_connector:
            self.web_ui_connector.disconnect()
            
        if hasattr(self, 'runner') and self.runner:
            return self.runner.cleanup()
        
        return None 