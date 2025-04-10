import React, { useState, useEffect } from 'react';
import NetworkGraph from './NetworkGraph';
import './NetworkMapView.css';
import analyticsWebSocket from '../../services/websocketService';

/**
 * NetworkMapView Component
 * 
 * Container component for the network visualization that integrates
 * the network graph with controls and filtering options
 */
const NetworkMapView = ({ isLiteMode = false }) => {
  const [devices, setDevices] = useState([]);
  const [connections, setConnections] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [filter, setFilter] = useState({
    showAlertedOnly: false,
    deviceTypes: [],
    searchQuery: ''
  });
  const [view, setView] = useState('full'); // 'full', 'compact', 'minimal'
  const [connected, setConnected] = useState(false);

  // Connect to WebSocket and handle network data
  useEffect(() => {
    const fetchInitialData = async () => {
      try {
        setLoading(true);
        
        // For demo purposes, load initial sample data
        // In production, this would be an API call
        setTimeout(() => {
          // Sample data
          const sampleDevices = [
            { id: '1', name: 'Gateway', ipAddress: '192.168.1.1', macAddress: '00:11:22:33:44:55', isGateway: true, deviceType: 'router' },
            { id: '2', name: 'Workstation 1', ipAddress: '192.168.1.100', macAddress: 'AA:BB:CC:DD:EE:FF', deviceType: 'computer' },
            { id: '3', name: 'Server', ipAddress: '192.168.1.50', macAddress: 'AA:BB:CC:11:22:33', deviceType: 'server' },
            { id: '4', name: 'Mobile Device', ipAddress: '192.168.1.120', macAddress: 'FF:EE:DD:CC:BB:AA', deviceType: 'mobile' },
            { id: '5', name: 'Smart TV', ipAddress: '192.168.1.150', macAddress: '11:22:33:44:55:66', deviceType: 'iot' }
          ];
          
          const sampleConnections = [
            { id: '1-2', source: '1', target: '2' },
            { id: '1-3', source: '1', target: '3' },
            { id: '1-4', source: '1', target: '4' },
            { id: '1-5', source: '1', target: '5' },
            { id: '2-3', source: '2', target: '3' }
          ];
          
          const sampleAlerts = [
            { 
              id: 'alert1', 
              sourceDeviceId: '2', 
              targetDeviceId: '1', 
              severityLevel: 2, 
              description: 'Possible ARP spoofing attempt',
              timestamp: Date.now() - 300000 // 5 minutes ago
            }
          ];
          
          setDevices(sampleDevices);
          setConnections(sampleConnections);
          setAlerts(sampleAlerts);
          setLoading(false);
        }, 500);
        
      } catch (err) {
        console.error('Error fetching initial network data:', err);
        setError('Failed to load network data. Please try again later.');
        setLoading(false);
      }
    };

    // Set up WebSocket event handlers
    const setupWebSocket = async () => {
      // Connect to WebSocket server
      try {
        await analyticsWebSocket.connect();
        setConnected(true);
        
        // Subscribe to relevant topics
        analyticsWebSocket.subscribe('network_topology');
        analyticsWebSocket.subscribe('network_alerts');
        
        // Set up event listeners
        analyticsWebSocket.on('topology_update', handleTopologyUpdate);
        analyticsWebSocket.on('device_added', handleDeviceAdded);
        analyticsWebSocket.on('device_updated', handleDeviceUpdated);
        analyticsWebSocket.on('device_removed', handleDeviceRemoved);
        analyticsWebSocket.on('connection_added', handleConnectionAdded);
        analyticsWebSocket.on('connection_removed', handleConnectionRemoved);
        analyticsWebSocket.on('alerts', handleAlertsUpdate);
        
        // Connection status events
        analyticsWebSocket.on('connected', () => setConnected(true));
        analyticsWebSocket.on('disconnected', () => setConnected(false));
        analyticsWebSocket.on('error', handleWebSocketError);
        
      } catch (err) {
        console.error('WebSocket connection error:', err);
        setError('Failed to establish real-time connection. Falling back to static data.');
        // Continue with initial data even if WebSocket fails
      }
    };
    
    // Load initial data
    fetchInitialData();
    
    // Set up WebSocket
    setupWebSocket();
    
    // Cleanup on unmount
    return () => {
      analyticsWebSocket.off('topology_update', handleTopologyUpdate);
      analyticsWebSocket.off('device_added', handleDeviceAdded);
      analyticsWebSocket.off('device_updated', handleDeviceUpdated);
      analyticsWebSocket.off('device_removed', handleDeviceRemoved);
      analyticsWebSocket.off('connection_added', handleConnectionAdded);
      analyticsWebSocket.off('connection_removed', handleConnectionRemoved);
      analyticsWebSocket.off('alerts', handleAlertsUpdate);
      
      analyticsWebSocket.unsubscribe('network_topology');
      analyticsWebSocket.unsubscribe('network_alerts');
    };
  }, []);

  // WebSocket event handlers
  const handleTopologyUpdate = (data) => {
    if (data.devices) setDevices(data.devices);
    if (data.connections) setConnections(data.connections);
  };
  
  const handleDeviceAdded = (device) => {
    setDevices(prev => [...prev, device]);
  };
  
  const handleDeviceUpdated = (updatedDevice) => {
    setDevices(prev => 
      prev.map(device => device.id === updatedDevice.id ? updatedDevice : device)
    );
  };
  
  const handleDeviceRemoved = (deviceId) => {
    setDevices(prev => prev.filter(device => device.id !== deviceId));
  };
  
  const handleConnectionAdded = (connection) => {
    setConnections(prev => [...prev, connection]);
  };
  
  const handleConnectionRemoved = (connectionId) => {
    setConnections(prev => prev.filter(conn => conn.id !== connectionId));
  };
  
  const handleAlertsUpdate = (newAlerts) => {
    setAlerts(newAlerts);
  };
  
  const handleWebSocketError = (error) => {
    console.error('WebSocket error:', error);
    // Don't set error state to avoid blocking the UI
    // Just log to console since we have fallback data
  };

  // Apply filters to devices
  const filteredDevices = React.useMemo(() => {
    return devices.filter(device => {
      // Filter by alert status
      if (filter.showAlertedOnly) {
        const hasAlert = alerts.some(
          alert => alert.sourceDeviceId === device.id || alert.targetDeviceId === device.id
        );
        if (!hasAlert) return false;
      }
      
      // Filter by device type
      if (filter.deviceTypes.length > 0 && !filter.deviceTypes.includes(device.deviceType)) {
        return false;
      }
      
      // Filter by search query
      if (filter.searchQuery) {
        const query = filter.searchQuery.toLowerCase();
        return (
          device.name?.toLowerCase().includes(query) ||
          device.ipAddress.toLowerCase().includes(query) ||
          device.macAddress.toLowerCase().includes(query)
        );
      }
      
      return true;
    });
  }, [devices, alerts, filter]);

  // Filter connections based on filtered devices
  const filteredConnections = React.useMemo(() => {
    const deviceIds = new Set(filteredDevices.map(d => d.id));
    return connections.filter(
      conn => deviceIds.has(conn.source) && deviceIds.has(conn.target)
    );
  }, [filteredDevices, connections]);

  // Handle device selection
  const handleDeviceSelect = (device) => {
    setSelectedDevice(device);
  };

  // Handle filter changes
  const handleFilterChange = (name, value) => {
    setFilter(prev => ({
      ...prev,
      [name]: value
    }));
  };

  // Determine graph dimensions based on view mode and container size
  const getGraphDimensions = () => {
    // This could be improved to use actual container measurements
    switch (view) {
      case 'compact':
        return { width: 600, height: 400 };
      case 'minimal':
        return { width: 400, height: 300 };
      case 'full':
      default:
        return { width: 800, height: 600 };
    }
  };

  // Function to refresh data manually
  const handleRefresh = () => {
    if (analyticsWebSocket.isConnected()) {
      // Request fresh data through WebSocket
      analyticsWebSocket.send({
        type: 'request_topology_update'
      });
    } else {
      // Fallback to page reload if WebSocket is not connected
      window.location.reload();
    }
  };

  // Render optimizations for lite mode
  const renderOptimized = isLiteMode || view === 'minimal';

  return (
    <div className={`network-map-view ${isLiteMode ? 'lite-mode' : ''}`}>
      <div className="map-header">
        <h2>Network Map {connected && <span className="realtime-badge">LIVE</span>}</h2>
        <div className="map-controls">
          <div className="search-container">
            <input
              type="text"
              placeholder="Search devices..."
              value={filter.searchQuery}
              onChange={(e) => handleFilterChange('searchQuery', e.target.value)}
              className="search-input"
            />
          </div>
          
          <div className="filter-controls">
            <label className="filter-checkbox">
              <input 
                type="checkbox" 
                checked={filter.showAlertedOnly}
                onChange={(e) => handleFilterChange('showAlertedOnly', e.target.checked)}
              />
              Show alerted only
            </label>
            
            <select 
              value={view}
              onChange={(e) => setView(e.target.value)}
              className="view-selector"
            >
              <option value="full">Full View</option>
              <option value="compact">Compact</option>
              <option value="minimal">Minimal</option>
            </select>
          </div>
          
          <button className="refresh-button" onClick={handleRefresh}>
            ↻ Refresh
          </button>
        </div>
      </div>
      
      <div className="map-container">
        {loading ? (
          <div className="loading-indicator">
            <div className="spinner"></div>
            <p>Loading network data...</p>
          </div>
        ) : error ? (
          <div className="error-message">
            <p>{error}</p>
            <button onClick={handleRefresh}>Try Again</button>
          </div>
        ) : (
          <>
            <NetworkGraph
              devices={filteredDevices}
              connections={filteredConnections}
              alerts={alerts}
              onNodeSelect={handleDeviceSelect}
              {...getGraphDimensions()}
              lite={renderOptimized}
            />
            
            <div className="stats-footer">
              <div className="stat-item">
                <span className="stat-label">Devices:</span>
                <span className="stat-value">{filteredDevices.length}</span>
              </div>
              <div className="stat-item">
                <span className="stat-label">Connections:</span>
                <span className="stat-value">{filteredConnections.length}</span>
              </div>
              <div className="stat-item">
                <span className="stat-label">Alerts:</span>
                <span className="stat-value">{alerts.length}</span>
              </div>
              {isLiteMode && (
                <div className="mode-indicator">
                  Lite Mode
                </div>
              )}
              {connected && (
                <div className="connection-status connected">
                  Live Updates
                </div>
              )}
              {!connected && (
                <div className="connection-status disconnected">
                  Static Data
                </div>
              )}
            </div>
          </>
        )}
      </div>
      
      {selectedDevice && !loading && (
        <div className="device-details-panel">
          <div className="panel-header">
            <h3>{selectedDevice.name || selectedDevice.ipAddress}</h3>
            <button className="close-button" onClick={() => setSelectedDevice(null)}>×</button>
          </div>
          <div className="panel-content">
            <div className="detail-section">
              <h4>Basic Information</h4>
              <table className="details-table">
                <tbody>
                  <tr>
                    <td>IP Address:</td>
                    <td>{selectedDevice.ipAddress}</td>
                  </tr>
                  <tr>
                    <td>MAC Address:</td>
                    <td>{selectedDevice.macAddress}</td>
                  </tr>
                  <tr>
                    <td>Type:</td>
                    <td>{selectedDevice.deviceType}</td>
                  </tr>
                  <tr>
                    <td>Status:</td>
                    <td>{selectedDevice.isGateway ? 'Gateway' : 'Host'}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            
            {!renderOptimized && (
              <div className="detail-section">
                <h4>Connected Devices</h4>
                <ul className="connected-devices-list">
                  {filteredConnections
                    .filter(conn => conn.source === selectedDevice.id || conn.target === selectedDevice.id)
                    .map(conn => {
                      const connectedDeviceId = conn.source === selectedDevice.id ? conn.target : conn.source;
                      const connectedDevice = devices.find(d => d.id === connectedDeviceId);
                      return connectedDevice ? (
                        <li key={connectedDeviceId}>
                          {connectedDevice.name || connectedDevice.ipAddress}
                        </li>
                      ) : null;
                    })
                  }
                </ul>
              </div>
            )}
            
            <div className="detail-section">
              <h4>Alerts</h4>
              {alerts.filter(
                alert => alert.sourceDeviceId === selectedDevice.id || alert.targetDeviceId === selectedDevice.id
              ).length > 0 ? (
                <ul className="device-alerts-list">
                  {alerts
                    .filter(alert => alert.sourceDeviceId === selectedDevice.id || alert.targetDeviceId === selectedDevice.id)
                    .map(alert => (
                      <li key={alert.id} className={`alert-item severity-${alert.severityLevel}`}>
                        <div className="alert-header">
                          <span className="alert-title">{alert.description}</span>
                          <span className="alert-time">
                            {new Date(alert.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                      </li>
                    ))
                  }
                </ul>
              ) : (
                <p className="no-alerts-message">No alerts for this device</p>
              )}
            </div>
            
            {!renderOptimized && (
              <div className="detail-section">
                <h4>Actions</h4>
                <div className="action-buttons">
                  <button className="action-button">Scan Device</button>
                  <button className="action-button">Block Device</button>
                  <button className="action-button">View History</button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default NetworkMapView; 