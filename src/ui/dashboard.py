#!/usr/bin/env python3
"""
ARP Guard Dashboard
Web-based UI for monitoring ARP Guard status and detections
"""

import os
import sys
import json
import time
import logging
from datetime import datetime
import threading
from typing import Dict, List, Any

# Add the parent directory to sys.path to import core modules
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

try:
    from flask import Flask, render_template, jsonify, request, Response
    from flask_socketio import SocketIO
except ImportError:
    logging.error("Flask or Flask-SocketIO not found. Install with: pip install flask flask-socketio")
    sys.exit(1)

from core.detection_module import DetectionModule
from core.remediation_module import RemediationModule

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask application
app = Flask(__name__, 
            static_folder='static',
            template_folder='templates')
app.config['SECRET_KEY'] = 'arpguard-dashboard-key'
socketio = SocketIO(app)

# Initialize modules
detection_module = DetectionModule()
remediation_module = RemediationModule()

# Global state
dashboard_state = {
    'started_at': time.time(),
    'last_update': time.time(),
    'detection_running': False,
    'total_detections': 0,
    'alert_history': [],
    'performance_history': []
}

# Maximum history size
MAX_HISTORY_SIZE = 100

def initialize_modules() -> bool:
    """Initialize ARP Guard modules."""
    logger.info("Initializing ARP Guard modules")
    try:
        detection_module.initialize()
        detection_module.remediation = remediation_module
        return True
    except Exception as e:
        logger.error(f"Failed to initialize modules: {e}")
        return False

def start_detection() -> bool:
    """Start detection process."""
    logger.info("Starting detection")
    try:
        if detection_module.start_detection():
            dashboard_state['detection_running'] = True
            return True
        return False
    except Exception as e:
        logger.error(f"Failed to start detection: {e}")
        return False

def stop_detection() -> bool:
    """Stop detection process."""
    logger.info("Stopping detection")
    try:
        if detection_module.stop_detection():
            dashboard_state['detection_running'] = False
            return True
        return False
    except Exception as e:
        logger.error(f"Failed to stop detection: {e}")
        return False

def get_dashboard_data() -> Dict[str, Any]:
    """Get current data for dashboard."""
    try:
        # Get detection module stats
        detection_stats = detection_module.get_stats()
        
        # Get remediation module stats
        remediation_stats = remediation_module.get_status()
        blocked_hosts = remediation_module.get_blocked_hosts()
        
        # Update dashboard state
        dashboard_state['last_update'] = time.time()
        
        # Calculate uptime
        uptime_seconds = time.time() - dashboard_state['started_at']
        hours = int(uptime_seconds // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        seconds = int(uptime_seconds % 60)
        uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        
        return {
            'timestamp': time.time(),
            'uptime': uptime_str,
            'detection': {
                'running': dashboard_state['detection_running'],
                'packets_processed': detection_stats.get('packets_processed', 0),
                'suspicious_packets': detection_stats.get('suspicious_packets', 0),
                'cache_sizes': detection_stats.get('cache_sizes', {}),
                'detections': detection_stats.get('detections', 0)
            },
            'remediation': {
                'auto_block': remediation_stats.get('auto_block', False),
                'block_duration': remediation_stats.get('block_duration', 0),
                'blocked_hosts_count': remediation_stats.get('blocked_hosts_count', 0),
                'whitelist_count': remediation_stats.get('whitelist_count', 0)
            },
            'performance': {
                'memory_usage': detection_stats.get('performance', {}).get('memory_usage', 0),
                'cpu_usage': detection_stats.get('performance', {}).get('cpu_usage', 0),
                'avg_packet_time': detection_stats.get('performance', {}).get('avg_packet_time', 0)
            },
            'blocked_hosts': blocked_hosts
        }
    except Exception as e:
        logger.error(f"Error getting dashboard data: {e}")
        return {
            'timestamp': time.time(),
            'error': str(e)
        }

def update_dashboard_loop():
    """Background thread to update dashboard data and emit to clients."""
    while True:
        try:
            data = get_dashboard_data()
            
            # Store performance history
            if len(dashboard_state['performance_history']) >= MAX_HISTORY_SIZE:
                dashboard_state['performance_history'].pop(0)
                
            dashboard_state['performance_history'].append({
                'timestamp': data['timestamp'],
                'memory_usage': data['performance']['memory_usage'],
                'cpu_usage': data['performance']['cpu_usage']
            })
            
            socketio.emit('dashboard_update', data)
            time.sleep(2)  # Update every 2 seconds
        except Exception as e:
            logger.error(f"Error in dashboard update loop: {e}")
            time.sleep(5)  # Wait longer on error

@app.route('/')
def index():
    """Render main dashboard page."""
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    """API endpoint for status."""
    return jsonify(get_dashboard_data())

@app.route('/api/toggle_detection', methods=['POST'])
def api_toggle_detection():
    """API endpoint to start/stop detection."""
    if dashboard_state['detection_running']:
        success = stop_detection()
        action = 'stop'
    else:
        success = start_detection()
        action = 'start'
        
    return jsonify({
        'success': success,
        'action': action,
        'running': dashboard_state['detection_running']
    })

@app.route('/api/unblock_host', methods=['POST'])
def api_unblock_host():
    """API endpoint to unblock a host."""
    data = request.json
    mac_address = data.get('mac_address')
    
    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address is required'})
        
    success = remediation_module.unblock_host(mac_address)
    return jsonify({'success': success})

@app.route('/api/add_whitelist', methods=['POST'])
def api_add_whitelist():
    """API endpoint to add a whitelist entry."""
    data = request.json
    mac_address = data.get('mac_address')
    ip_address = data.get('ip_address')
    
    if not mac_address or not ip_address:
        return jsonify({'success': False, 'error': 'MAC and IP addresses are required'})
        
    # Add to whitelist
    entry = f"{mac_address}:{ip_address}"
    if entry not in remediation_module.config.whitelist:
        remediation_module.config.whitelist.append(entry)
        remediation_module._rebuild_whitelist_set()
        remediation_module._save_config()
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Entry already in whitelist'})

@app.route('/api/performance_history')
def api_performance_history():
    """API endpoint for performance history."""
    return jsonify(dashboard_state['performance_history'])

@socketio.on('connect')
def socket_connect():
    """Handle SocketIO client connection."""
    logger.info(f"Client connected: {request.sid}")
    
@socketio.on('disconnect')
def socket_disconnect():
    """Handle SocketIO client disconnection."""
    logger.info(f"Client disconnected: {request.sid}")

def create_templates():
    """Create template files if they don't exist."""
    os.makedirs(os.path.join(os.path.dirname(__file__), 'templates'), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), 'static'), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), 'static', 'js'), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), 'static', 'css'), exist_ok=True)
    
    # Create index.html template
    index_template_path = os.path.join(os.path.dirname(__file__), 'templates', 'index.html')
    if not os.path.exists(index_template_path):
        with open(index_template_path, 'w') as f:
            f.write("""<!DOCTYPE html>
<html>
<head>
    <title>ARP Guard Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <script src="https://cdn.socket.io/4.4.1/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <header>
            <h1>ARP Guard Dashboard</h1>
            <div class="status-bar">
                <div class="status-item" id="uptime">Uptime: 00:00:00</div>
                <div class="status-item">
                    <span id="detection-status" class="status-indicator">⚫</span>
                    Detection Status
                </div>
                <button id="toggle-detection" class="btn">Start Detection</button>
            </div>
        </header>
        
        <div class="dashboard">
            <div class="dashboard-row">
                <div class="dashboard-card">
                    <h2>Detection Stats</h2>
                    <div class="stat-grid">
                        <div class="stat-item">
                            <div class="stat-value" id="packets-processed">0</div>
                            <div class="stat-label">Packets Processed</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value" id="suspicious-packets">0</div>
                            <div class="stat-label">Suspicious Packets</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value" id="detection-count">0</div>
                            <div class="stat-label">Detections</div>
                        </div>
                    </div>
                </div>
                
                <div class="dashboard-card">
                    <h2>Remediation Stats</h2>
                    <div class="stat-grid">
                        <div class="stat-item">
                            <div class="stat-value" id="blocked-hosts">0</div>
                            <div class="stat-label">Blocked Hosts</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value" id="whitelist-count">0</div>
                            <div class="stat-label">Whitelist Entries</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value" id="block-duration">0</div>
                            <div class="stat-label">Block Duration (s)</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="dashboard-row">
                <div class="dashboard-card">
                    <h2>Performance Metrics</h2>
                    <canvas id="performance-chart"></canvas>
                </div>
            </div>
            
            <div class="dashboard-row">
                <div class="dashboard-card">
                    <h2>Blocked Hosts</h2>
                    <div class="table-container">
                        <table id="blocked-hosts-table">
                            <thead>
                                <tr>
                                    <th>MAC Address</th>
                                    <th>IP Address</th>
                                    <th>Reason</th>
                                    <th>Blocked At</th>
                                    <th>Expires At</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                <!-- Blocked hosts will be listed here -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <div class="dashboard-row">
                <div class="dashboard-card">
                    <h2>Add to Whitelist</h2>
                    <div class="form-container">
                        <div class="form-group">
                            <label for="mac-address">MAC Address:</label>
                            <input type="text" id="mac-address" placeholder="00:11:22:33:44:55">
                        </div>
                        <div class="form-group">
                            <label for="ip-address">IP Address:</label>
                            <input type="text" id="ip-address" placeholder="192.168.1.100">
                        </div>
                        <button id="add-whitelist" class="btn">Add to Whitelist</button>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="{{ url_for('static', filename='js/dashboard.js') }}"></script>
</body>
</html>""")
    
    # Create CSS file
    css_path = os.path.join(os.path.dirname(__file__), 'static', 'css', 'style.css')
    if not os.path.exists(css_path):
        with open(css_path, 'w') as f:
            f.write("""* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

body {
    background-color: #f0f2f5;
    color: #333;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

header {
    background-color: #fff;
    border-radius: 8px;
    padding: 20px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    margin-bottom: 20px;
}

header h1 {
    color: #1a73e8;
    margin-bottom: 15px;
}

.status-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.status-item {
    display: flex;
    align-items: center;
    margin-right: 20px;
}

.status-indicator {
    display: inline-block;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    margin-right: 8px;
}

.btn {
    background-color: #1a73e8;
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 4px;
    cursor: pointer;
    font-weight: 500;
    transition: background-color 0.2s;
}

.btn:hover {
    background-color: #0d65db;
}

.dashboard-row {
    display: flex;
    margin-bottom: 20px;
    gap: 20px;
}

.dashboard-card {
    background-color: white;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    padding: 20px;
    flex: 1;
}

.dashboard-card h2 {
    color: #1a73e8;
    font-size: 1.2rem;
    margin-bottom: 15px;
    border-bottom: 1px solid #eee;
    padding-bottom: 10px;
}

.stat-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 15px;
}

.stat-item {
    text-align: center;
}

.stat-value {
    font-size: 2rem;
    font-weight: bold;
    color: #1a73e8;
}

.stat-label {
    color: #666;
    font-size: 0.9rem;
    margin-top: 5px;
}

.table-container {
    overflow-x: auto;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th, td {
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid #eee;
}

th {
    background-color: #f9f9f9;
    font-weight: 500;
    color: #666;
}

tbody tr:hover {
    background-color: #f5f5f5;
}

.form-container {
    display: flex;
    flex-wrap: wrap;
    gap: 15px;
    align-items: flex-end;
}

.form-group {
    flex: 1;
    min-width: 200px;
}

label {
    display: block;
    margin-bottom: 5px;
    color: #666;
}

input[type="text"] {
    width: 100%;
    padding: 8px;
    border: 1px solid #ddd;
    border-radius: 4px;
}

#detection-status.running {
    color: #4caf50;
}

#detection-status.stopped {
    color: #f44336;
}

@media (max-width: 768px) {
    .dashboard-row {
        flex-direction: column;
    }
    
    .stat-grid {
        grid-template-columns: repeat(2, 1fr);
    }
}""")
    
    # Create JavaScript file
    js_path = os.path.join(os.path.dirname(__file__), 'static', 'js', 'dashboard.js')
    if not os.path.exists(js_path):
        with open(js_path, 'w') as f:
            f.write("""// Connect to SocketIO server
const socket = io();

// Charts
let performanceChart;

// DOM Elements
const toggleDetectionBtn = document.getElementById('toggle-detection');
const detectionStatus = document.getElementById('detection-status');
const uptimeElement = document.getElementById('uptime');
const packetsProcessedElement = document.getElementById('packets-processed');
const suspiciousPacketsElement = document.getElementById('suspicious-packets');
const detectionCountElement = document.getElementById('detection-count');
const blockedHostsElement = document.getElementById('blocked-hosts');
const whitelistCountElement = document.getElementById('whitelist-count');
const blockDurationElement = document.getElementById('block-duration');
const blockedHostsTable = document.getElementById('blocked-hosts-table').querySelector('tbody');
const addWhitelistBtn = document.getElementById('add-whitelist');
const macAddressInput = document.getElementById('mac-address');
const ipAddressInput = document.getElementById('ip-address');

// Initialize performance chart
function initializePerformanceChart() {
    const ctx = document.getElementById('performance-chart').getContext('2d');
    performanceChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Memory Usage (MB)',
                    data: [],
                    borderColor: '#1a73e8',
                    backgroundColor: 'rgba(26, 115, 232, 0.1)',
                    borderWidth: 2,
                    fill: true
                },
                {
                    label: 'CPU Usage (%)',
                    data: [],
                    borderColor: '#34a853',
                    backgroundColor: 'rgba(52, 168, 83, 0.1)',
                    borderWidth: 2,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                },
                tooltip: {
                    mode: 'index',
                    intersect: false
                }
            },
            scales: {
                x: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Time'
                    }
                },
                y: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Value'
                    },
                    suggestedMin: 0
                }
            }
        }
    });
    
    // Initial load of performance history
    fetchPerformanceHistory();
}

// Update dashboard with data
function updateDashboard(data) {
    // Update detection status
    if (data.detection.running) {
        detectionStatus.textContent = '🟢';
        detectionStatus.classList.add('running');
        detectionStatus.classList.remove('stopped');
        toggleDetectionBtn.textContent = 'Stop Detection';
    } else {
        detectionStatus.textContent = '🔴';
        detectionStatus.classList.add('stopped');
        detectionStatus.classList.remove('running');
        toggleDetectionBtn.textContent = 'Start Detection';
    }
    
    // Update uptime
    uptimeElement.textContent = `Uptime: ${data.uptime}`;
    
    // Update detection stats
    packetsProcessedElement.textContent = data.detection.packets_processed.toLocaleString();
    suspiciousPacketsElement.textContent = data.detection.suspicious_packets.toLocaleString();
    detectionCountElement.textContent = data.detection.detections.toLocaleString();
    
    // Update remediation stats
    blockedHostsElement.textContent = data.remediation.blocked_hosts_count.toLocaleString();
    whitelistCountElement.textContent = data.remediation.whitelist_count.toLocaleString();
    blockDurationElement.textContent = data.remediation.block_duration.toLocaleString();
    
    // Update blocked hosts table
    updateBlockedHostsTable(data.blocked_hosts);
    
    // Update performance chart
    updatePerformanceChart(data);
}

// Update blocked hosts table
function updateBlockedHostsTable(hosts) {
    blockedHostsTable.innerHTML = '';
    
    if (hosts.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = '<td colspan="6" class="text-center">No hosts currently blocked</td>';
        blockedHostsTable.appendChild(row);
        return;
    }
    
    hosts.forEach(host => {
        const row = document.createElement('tr');
        
        // Format dates
        const blockedAt = new Date(host.blocked_at).toLocaleString();
        const expiresAt = new Date(host.expires_at).toLocaleString();
        
        row.innerHTML = `
            <td>${host.mac_address}</td>
            <td>${host.ip_address}</td>
            <td>${host.reason}</td>
            <td>${blockedAt}</td>
            <td>${expiresAt}</td>
            <td><button class="btn unblock-btn" data-mac="${host.mac_address}">Unblock</button></td>
        `;
        
        blockedHostsTable.appendChild(row);
    });
    
    // Add event listeners to unblock buttons
    document.querySelectorAll('.unblock-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const mac = this.getAttribute('data-mac');
            unblockHost(mac);
        });
    });
}

// Update performance chart
function updatePerformanceChart(data) {
    // Add data for memory usage
    performanceChart.data.datasets[0].data.push(data.performance.memory_usage);
    
    // Add data for CPU usage
    performanceChart.data.datasets[1].data.push(data.performance.cpu_usage);
    
    // Add timestamp label
    const now = new Date();
    performanceChart.data.labels.push(now.toLocaleTimeString());
    
    // Limit data points (keep last 20)
    if (performanceChart.data.labels.length > 20) {
        performanceChart.data.labels.shift();
        performanceChart.data.datasets.forEach(dataset => {
            dataset.data.shift();
        });
    }
    
    // Update chart
    performanceChart.update();
}

// Fetch performance history
function fetchPerformanceHistory() {
    fetch('/api/performance_history')
        .then(response => response.json())
        .then(data => {
            // Clear existing data
            performanceChart.data.labels = [];
            performanceChart.data.datasets[0].data = [];
            performanceChart.data.datasets[1].data = [];
            
            // Add historical data
            data.forEach(point => {
                performanceChart.data.labels.push(new Date(point.timestamp * 1000).toLocaleTimeString());
                performanceChart.data.datasets[0].data.push(point.memory_usage);
                performanceChart.data.datasets[1].data.push(point.cpu_usage);
            });
            
            // Update chart
            performanceChart.update();
        })
        .catch(error => console.error('Error fetching performance history:', error));
}

// Toggle detection
function toggleDetection() {
    fetch('/api/toggle_detection', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (!data.success) {
            alert('Failed to toggle detection');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error toggling detection');
    });
}

// Unblock host
function unblockHost(mac) {
    fetch('/api/unblock_host', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            mac_address: mac
        })
    })
    .then(response => response.json())
    .then(data => {
        if (!data.success) {
            alert('Failed to unblock host');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error unblocking host');
    });
}

// Add to whitelist
function addToWhitelist() {
    const mac = macAddressInput.value.trim();
    const ip = ipAddressInput.value.trim();
    
    if (!mac || !ip) {
        alert('MAC and IP addresses are required');
        return;
    }
    
    fetch('/api/add_whitelist', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            mac_address: mac,
            ip_address: ip
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            macAddressInput.value = '';
            ipAddressInput.value = '';
            alert('Added to whitelist');
        } else {
            alert(data.error || 'Failed to add to whitelist');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error adding to whitelist');
    });
}

// Socket.io event handlers
socket.on('connect', () => {
    console.log('Connected to server');
});

socket.on('dashboard_update', data => {
    updateDashboard(data);
});

socket.on('disconnect', () => {
    console.log('Disconnected from server');
});

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    // Initialize charts
    initializePerformanceChart();
    
    // Event listeners
    toggleDetectionBtn.addEventListener('click', toggleDetection);
    addWhitelistBtn.addEventListener('click', addToWhitelist);
});""")

def run_dashboard(host='127.0.0.1', port=5000, debug=False):
    """Run the dashboard application."""
    # Create template files
    create_templates()
    
    # Initialize modules
    initialize_modules()
    
    # Start background update thread
    update_thread = threading.Thread(target=update_dashboard_loop, daemon=True)
    update_thread.start()
    
    # Run Flask application
    logger.info(f"Starting ARP Guard Dashboard on http://{host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug)

if __name__ == '__main__':
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description='ARP Guard Dashboard')
    parser.add_argument('--host', default='127.0.0.1', help='Host address to listen on')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    args = parser.parse_args()
    
    run_dashboard(host=args.host, port=args.port, debug=args.debug) 