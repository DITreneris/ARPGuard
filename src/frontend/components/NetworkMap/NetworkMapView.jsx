import React, { useState, useEffect, useRef } from 'react';
import { useSelector } from 'react-redux';
import analyticsWebSocket from '../../services/websocketService';
import './NetworkMapView.css';

/**
 * Network Map component that displays network topology visualization
 */
const NetworkMapView = () => {
  const [devices, setDevices] = useState([]);
  const [connections, setConnections] = useState([]);
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState('standard');
  const [showAlertedOnly, setShowAlertedOnly] = useState(false);
  const [loading, setLoading] = useState(true);
  
  const canvasRef = useRef(null);
  
  // Get app mode from Redux store
  const isLiteMode = useSelector(state => state.app.isLiteMode);
  
  // Load initial data and set up WebSocket listeners
  useEffect(() => {
    // Fetch initial network topology data
    fetchNetworkData();
    
    // Set up WebSocket event listeners
    analyticsWebSocket.on('topology_update', handleTopologyUpdate);
    analyticsWebSocket.on('device_status_change', handleDeviceStatusChange);
    
    // Clean up on component unmount
    return () => {
      analyticsWebSocket.off('topology_update', handleTopologyUpdate);
      analyticsWebSocket.off('device_status_change', handleDeviceStatusChange);
    };
  }, []);
  
  // Fetch network data from API
  const fetchNetworkData = async () => {
    setLoading(true);
    
    try {
      // API call would go here in a real implementation
      // For now, simulate with mock data
      const mockDevices = [
        { id: 1, name: 'Device 1', ipAddress: '192.168.1.1', macAddress: '00:11:22:33:44:55', status: 'normal' },
        { id: 2, name: 'Device 2', ipAddress: '192.168.1.2', macAddress: '00:11:22:33:44:56', status: 'normal' },
        { id: 3, name: 'Device 3', ipAddress: '192.168.1.3', macAddress: '00:11:22:33:44:57', status: 'alerted' }
      ];
      
      const mockConnections = [
        { source: '192.168.1.1', target: '192.168.1.2' },
        { source: '192.168.1.1', target: '192.168.1.3' }
      ];
      
      setDevices(mockDevices);
      setConnections(mockConnections);
    } catch (error) {
      console.error('Error fetching network data:', error);
    } finally {
      setLoading(false);
    }
  };
  
  // Handle WebSocket topology update
  const handleTopologyUpdate = (data) => {
    if (data.devices) setDevices(data.devices);
    if (data.connections) setConnections(data.connections);
  };
  
  // Handle WebSocket device status change
  const handleDeviceStatusChange = (data) => {
    setDevices(prev => 
      prev.map(device => 
        device.ipAddress === data.ipAddress 
          ? { ...device, status: data.status } 
          : device
      )
    );
  };
  
  // Handle refresh button click
  const handleRefresh = () => {
    fetchNetworkData();
    analyticsWebSocket.send({
      type: 'request_topology_update'
    });
  };
  
  // Handle search input change
  const handleSearchChange = (e) => {
    setSearchQuery(e.target.value);
  };
  
  // Handle view mode change
  const handleViewModeChange = (e) => {
    setViewMode(e.target.value);
  };
  
  // Handle alert filter toggle
  const handleAlertFilterToggle = () => {
    setShowAlertedOnly(!showAlertedOnly);
  };
  
  // Handle device selection
  const handleDeviceSelect = (device) => {
    setSelectedDevice(device);
  };
  
  // Filter devices based on search query and filter settings
  const filteredDevices = devices.filter(device => {
    // Filter by search query
    const matchesSearch = 
      device.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      device.ipAddress.includes(searchQuery);
    
    // Filter by alert status
    const matchesAlertFilter = !showAlertedOnly || device.status === 'alerted';
    
    return matchesSearch && matchesAlertFilter;
  });
  
  // Calculate stats
  const stats = {
    devices: devices.length,
    connections: connections.length,
    alerts: devices.filter(d => d.status === 'alerted').length
  };
  
  return (
    <div 
      className={`network-map-container ${isLiteMode ? 'lite-mode' : ''}`}
      data-testid="network-map-view"
    >
      <div className="map-header">
        <h2>Network Map</h2>
        {analyticsWebSocket.isConnected() && (
          <span className="live-indicator">LIVE</span>
        )}
      </div>
      
      <div className="map-controls">
        <div className="search-control">
          <input
            type="text"
            placeholder="Search devices..."
            value={searchQuery}
            onChange={handleSearchChange}
          />
        </div>
        
        <div className="view-control">
          <select value={viewMode} onChange={handleViewModeChange}>
            <option value="standard">Standard View</option>
            <option value="compact">Compact View</option>
            <option value="detailed">Detailed View</option>
          </select>
        </div>
        
        <div className="filter-control">
          <label>
            <input
              type="checkbox"
              checked={showAlertedOnly}
              onChange={handleAlertFilterToggle}
            />
            Show alerted only
          </label>
        </div>
        
        <button className="refresh-button" onClick={handleRefresh}>
          ↻ Refresh
        </button>
      </div>
      
      <div className="map-visualization">
        {loading ? (
          <div className="loading-indicator">Loading network map...</div>
        ) : (
          <>
            <div className="network-canvas-container">
              <canvas ref={canvasRef} width={800} height={500} />
            </div>
            
            <div className="device-list">
              {filteredDevices.map(device => (
                <div
                  key={device.id}
                  className={`device-item ${device.status} ${selectedDevice?.id === device.id ? 'selected' : ''}`}
                  onClick={() => handleDeviceSelect(device)}
                >
                  <div className="device-name">{device.name}</div>
                  <div className="device-ip">{device.ipAddress}</div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
      
      {selectedDevice && (
        <div className="device-details">
          <h3>Device Details</h3>
          <div className="detail-item">
            <span className="detail-label">Name:</span>
            <span className="detail-value">{selectedDevice.name}</span>
          </div>
          <div className="detail-item">
            <span className="detail-label">IP Address:</span>
            <span className="detail-value">{selectedDevice.ipAddress}</span>
          </div>
          <div className="detail-item">
            <span className="detail-label">MAC Address:</span>
            <span className="detail-value">{selectedDevice.macAddress}</span>
          </div>
          <div className="detail-item">
            <span className="detail-label">Status:</span>
            <span className={`detail-value status-${selectedDevice.status}`}>
              {selectedDevice.status}
            </span>
          </div>
        </div>
      )}
      
      <div className="network-stats">
        <div className="stat-item">
          <span className="stat-label">Devices:</span>
          <span className="stat-value">{stats.devices}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">Connections:</span>
          <span className="stat-value">{stats.connections}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">Alerts:</span>
          <span className="stat-value">{stats.alerts}</span>
        </div>
      </div>
    </div>
  );
};

export default NetworkMapView; 