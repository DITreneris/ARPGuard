// Initialize WebSocket connection
let ws = null;
let charts = {};

// Initialize dashboard when document is ready
document.addEventListener('DOMContentLoaded', function() {
    initializeWebSocket();
    initializeCharts();
    setupEventListeners();
});

// WebSocket connection management
function initializeWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/dashboard`;
    
    ws = new WebSocket(wsUrl);
    
    ws.onopen = function() {
        console.log('WebSocket connection established');
        updateConnectionStatus(true);
    };
    
    ws.onclose = function() {
        console.log('WebSocket connection closed');
        updateConnectionStatus(false);
        // Attempt to reconnect after 5 seconds
        setTimeout(initializeWebSocket, 5000);
    };
    
    ws.onmessage = function(event) {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
    };
}

// Update connection status indicator
function updateConnectionStatus(connected) {
    const statusIndicator = document.getElementById('connection-status');
    if (connected) {
        statusIndicator.classList.remove('text-danger');
        statusIndicator.classList.add('text-success');
        statusIndicator.textContent = 'Connected';
    } else {
        statusIndicator.classList.remove('text-success');
        statusIndicator.classList.add('text-danger');
        statusIndicator.textContent = 'Disconnected';
    }
}

// Handle incoming WebSocket messages
function handleWebSocketMessage(data) {
    switch(data.type) {
        case 'system_status':
            updateSystemStatus(data.data);
            break;
        case 'network_activity':
            updateNetworkActivity(data.data);
            break;
        case 'threat_level':
            updateThreatLevel(data.data);
            break;
        case 'network_topology':
            updateNetworkTopology(data.data);
            break;
        case 'alert':
            addNewAlert(data.data);
            break;
        case 'metrics':
            updateMetrics(data.data);
            break;
    }
}

// Initialize Chart.js charts
function initializeCharts() {
    // Packet Rate Chart
    charts.packetRate = new Chart(
        document.getElementById('packetRateChart'),
        {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets/sec',
                    data: [],
                    borderColor: '#007bff',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        }
    );

    // Threat Level Chart
    charts.threatLevel = new Chart(
        document.getElementById('threatLevelChart'),
        {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Threat Level',
                    data: [],
                    borderColor: '#dc3545',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        }
    );
}

// Update system status information
function updateSystemStatus(data) {
    document.getElementById('cpu-usage').textContent = `${data.cpu_usage}%`;
    document.getElementById('memory-usage').textContent = `${data.memory_usage}%`;
    document.getElementById('disk-usage').textContent = `${data.disk_usage}%`;
    
    // Update progress bars
    updateProgressBar('cpu-progress', data.cpu_usage);
    updateProgressBar('memory-progress', data.memory_usage);
    updateProgressBar('disk-progress', data.disk_usage);
}

// Update network activity information
function updateNetworkActivity(data) {
    document.getElementById('packets-processed').textContent = data.packets_processed;
    document.getElementById('alerts-triggered').textContent = data.alerts_triggered;
    document.getElementById('active-connections').textContent = data.active_connections;
    
    // Update packet rate chart
    updateChart(charts.packetRate, data.packet_rate);
}

// Update threat level information
function updateThreatLevel(data) {
    const threatLevelElement = document.getElementById('threat-level');
    threatLevelElement.textContent = data.level;
    threatLevelElement.className = `badge bg-${getThreatLevelClass(data.level)}`;
    
    // Update threat level chart
    updateChart(charts.threatLevel, data.value);
    
    // Update threat progress bar
    updateProgressBar('threat-progress', data.value);
    document.getElementById('threat-progress').className = `progress-bar bg-${getThreatLevelClass(data.level)}`;
}

// Update network topology visualization
function updateNetworkTopology(data) {
    const networkGraph = document.getElementById('network-graph');
    
    // Clear previous content
    networkGraph.innerHTML = '';
    
    // If we have nodes, create a simple visualization
    if (data.nodes.length > 0) {
        // In a real implementation, we would use a library like vis.js or d3.js
        // For the demo, we'll create a simple representation
        const container = document.createElement('div');
        container.className = 'network-container';
        
        // Add nodes
        const nodeContainer = document.createElement('div');
        nodeContainer.className = 'node-container';
        
        data.nodes.forEach(node => {
            const nodeElement = document.createElement('div');
            nodeElement.className = `network-node ${node.group}`;
            nodeElement.setAttribute('data-id', node.id);
            nodeElement.setAttribute('title', `${node.label} (${node.id})`);
            
            const nodeLabel = document.createElement('div');
            nodeLabel.className = 'node-label';
            nodeLabel.textContent = node.label;
            
            nodeElement.appendChild(nodeLabel);
            nodeContainer.appendChild(nodeElement);
        });
        
        // Add description
        const description = document.createElement('div');
        description.className = 'network-description';
        description.innerHTML = `<strong>Network Topology:</strong><br>
            ${data.nodes.length} devices detected<br>
            ${data.links.length} connections mapped`;
        
        container.appendChild(nodeContainer);
        container.appendChild(description);
        networkGraph.appendChild(container);
    } else {
        networkGraph.textContent = 'No network topology data available yet. Start packet capture to begin mapping.';
    }
}

// Add new alert to the alerts table
function addNewAlert(alert) {
    const alertsTable = document.getElementById('alerts-table');
    const newRow = alertsTable.insertRow(1);
    
    newRow.innerHTML = `
        <td>${alert.timestamp}</td>
        <td class="severity-${alert.severity.toLowerCase()}">${alert.severity}</td>
        <td>${alert.source}</td>
        <td>${alert.message}</td>
        <td>
            <button class="btn btn-sm btn-primary" onclick="acknowledgeAlert('${alert.id}')">
                Acknowledge
            </button>
        </td>
    `;
    
    // Add animation class
    newRow.classList.add('status-update');
}

// Update metrics charts
function updateMetrics(data) {
    // Update various metrics charts based on the received data
    // This is a placeholder for the actual implementation
    console.log('Updating metrics:', data);
}

// Helper function to update progress bars
function updateProgressBar(elementId, value) {
    const progressBar = document.getElementById(elementId);
    progressBar.style.width = `${value}%`;
    progressBar.setAttribute('aria-valuenow', value);
}

// Helper function to update chart data
function updateChart(chart, newValue) {
    const now = new Date();
    const time = `${now.getHours()}:${now.getMinutes()}:${now.getSeconds()}`;
    
    chart.data.labels.push(time);
    chart.data.datasets[0].data.push(newValue);
    
    // Keep only last 20 data points
    if (chart.data.labels.length > 20) {
        chart.data.labels.shift();
        chart.data.datasets[0].data.shift();
    }
    
    chart.update();
}

// Helper function to get threat level CSS class
function getThreatLevelClass(level) {
    switch(level.toLowerCase()) {
        case 'low': return 'success';
        case 'medium': return 'warning';
        case 'high': return 'danger';
        default: return 'secondary';
    }
}

// Start packet capture
function startCapture() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'start_capture'
        }));
        
        // Update UI
        document.getElementById('start-demo').disabled = true;
        document.getElementById('stop-demo').disabled = false;
    } else {
        console.error('WebSocket not connected');
    }
}

// Stop packet capture
function stopCapture() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'stop_capture'
        }));
        
        // Update UI
        document.getElementById('start-demo').disabled = false;
        document.getElementById('stop-demo').disabled = true;
    } else {
        console.error('WebSocket not connected');
    }
}

// Setup event listeners
function setupEventListeners() {
    // Navigation links
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            // Handle navigation
            const target = this.getAttribute('data-target');
            showSection(target);
        });
    });
    
    // Start/Stop demo buttons
    document.getElementById('start-demo').addEventListener('click', startCapture);
    document.getElementById('stop-demo').addEventListener('click', stopCapture);
    
    // Initially disable stop button
    document.getElementById('stop-demo').disabled = true;
}

// Show specific section
function showSection(sectionId) {
    // Hide all sections
    document.querySelectorAll('.dashboard-section').forEach(section => {
        section.classList.add('d-none');
    });
    
    // Show selected section
    document.getElementById(sectionId).classList.remove('d-none');
    
    // Update active nav link
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('data-target') === sectionId) {
            link.classList.add('active');
        }
    });
}

// Acknowledge alert
function acknowledgeAlert(alertId) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'acknowledge_alert',
            alert_id: alertId
        }));
    }
} 