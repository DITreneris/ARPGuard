import React, { useState, useEffect } from 'react';
import { hasUserPermission } from '../../services/AuthService';
import { PERMISSIONS } from '../../services/RoleService';
import discoveryService from '../../services/discoveryService';
import './NetworkDiscovery.css';

/**
 * NetworkDiscovery Component
 * Provides UI for discovering and managing network devices
 */
const NetworkDiscovery = () => {
  // State for discovered devices
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  // State for active scan
  const [activeScan, setActiveScan] = useState(null);
  const [scanProgress, setScanProgress] = useState(0);
  
  // State for scheduled scans
  const [scheduledScans, setScheduledScans] = useState([]);
  
  // State for scan options form
  const [scanOptions, setScanOptions] = useState({
    range: '',
    timeout: 30,
    deepScan: false
  });

  // Check permissions
  const canRunScan = hasUserPermission(PERMISSIONS.DISCOVERY_RUN);
  const canConfigureScan = hasUserPermission(PERMISSIONS.DISCOVERY_CONFIGURE);
  
  // Handle form input changes
  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    setScanOptions({
      ...scanOptions,
      [name]: type === 'checkbox' ? checked : value
    });
  };
  
  // Load devices and scheduled scans on component mount
  useEffect(() => {
    const loadData = async () => {
      try {
        setLoading(true);
        setError(null);
        
        // Load devices
        const devices = await discoveryService.getDevices();
        setDevices(devices);
        
        // Load scheduled scans
        const scheduledScans = discoveryService.getScheduledScans();
        setScheduledScans(scheduledScans);
        
        setLoading(false);
      } catch (error) {
        console.error('Error loading discovery data:', error);
        setError('Failed to load discovery data. Please try again.');
        setLoading(false);
      }
    };
    
    loadData();
    
    // Set up event listeners
    discoveryService.on('scanStarted', handleScanStarted);
    discoveryService.on('scanProgress', handleScanProgress);
    discoveryService.on('scanCompleted', handleScanCompleted);
    discoveryService.on('scanError', handleScanError);
    discoveryService.on('scanCancelled', handleScanCancelled);
    discoveryService.on('scanScheduled', handleScanScheduled);
    discoveryService.on('scanScheduleUpdated', handleScanScheduleUpdated);
    discoveryService.on('scanScheduleDeleted', handleScanScheduleDeleted);
    
    return () => {
      // Clean up event listeners
      discoveryService.removeListener('scanStarted', handleScanStarted);
      discoveryService.removeListener('scanProgress', handleScanProgress);
      discoveryService.removeListener('scanCompleted', handleScanCompleted);
      discoveryService.removeListener('scanError', handleScanError);
      discoveryService.removeListener('scanCancelled', handleScanCancelled);
      discoveryService.removeListener('scanScheduled', handleScanScheduled);
      discoveryService.removeListener('scanScheduleUpdated', handleScanScheduleUpdated);
      discoveryService.removeListener('scanScheduleDeleted', handleScanScheduleDeleted);
    };
  }, []);
  
  // Event handlers for discovery service events
  const handleScanStarted = (data) => {
    setActiveScan({
      id: data.scanId,
      startTime: data.timestamp,
      options: data.options
    });
    setScanProgress(0);
    setError(null);
  };
  
  const handleScanProgress = (data) => {
    setScanProgress(data.progress);
    
    // Update active scan with devices found
    setActiveScan(prev => ({
      ...prev,
      devicesFound: data.devicesFound
    }));
  };
  
  const handleScanCompleted = (data) => {
    // Reset active scan
    setActiveScan(null);
    setScanProgress(0);
    
    // Update devices list
    setDevices(data.devices);
    
    // Show toast or notification (could be added later)
    console.log(`Scan completed, found ${data.devices.length} devices`);
  };
  
  const handleScanError = (data) => {
    setActiveScan(null);
    setScanProgress(0);
    setError(`Scan failed: ${data.error}`);
  };
  
  const handleScanCancelled = () => {
    setActiveScan(null);
    setScanProgress(0);
  };
  
  const handleScanScheduled = (data) => {
    setScheduledScans(prev => [...prev, data]);
  };
  
  const handleScanScheduleUpdated = (data) => {
    setScheduledScans(prev => 
      prev.map(scan => scan.id === data.id ? data : scan)
    );
  };
  
  const handleScanScheduleDeleted = (data) => {
    setScheduledScans(prev => 
      prev.filter(scan => scan.id !== data.id)
    );
  };
  
  // Start a new scan
  const handleStartScan = async (e) => {
    e.preventDefault();
    
    if (!canRunScan) {
      setError('You do not have permission to run scans');
      return;
    }
    
    // Validate IP range if provided
    if (scanOptions.range && !isValidIpRange(scanOptions.range)) {
      setError('Invalid IP range format. Use CIDR notation (e.g., 192.168.1.0/24) or IP range (e.g., 192.168.1.1-254)');
      return;
    }
    
    try {
      setLoading(true);
      setError(null);
      
      const result = await discoveryService.startScan(scanOptions);
      
      if (result.status === 'error') {
        setError(result.error);
      }
      
      setLoading(false);
    } catch (error) {
      console.error('Error starting scan:', error);
      setError('Failed to start scan. Please try again.');
      setLoading(false);
    }
  };
  
  // Cancel an active scan
  const handleCancelScan = async () => {
    if (!activeScan) return;
    
    try {
      await discoveryService.cancelScan(activeScan.id);
    } catch (error) {
      console.error('Error cancelling scan:', error);
      setError('Failed to cancel scan');
    }
  };
  
  // Schedule a recurring scan
  const handleScheduleScan = (frequency) => {
    if (!canConfigureScan) {
      setError('You do not have permission to schedule scans');
      return;
    }
    
    discoveryService.scheduleRecurringScan({
      frequency,
      options: scanOptions
    });
  };
  
  // Toggle a scheduled scan
  const handleToggleScheduledScan = (id, enabled) => {
    discoveryService.toggleScheduledScan(id, enabled);
  };
  
  // Delete a scheduled scan
  const handleDeleteScheduledScan = (id) => {
    discoveryService.deleteScheduledScan(id);
  };
  
  // Validate IP range
  const isValidIpRange = (range) => {
    // Simple validation - a more robust implementation would be needed in production
    // This checks for common CIDR notation like 192.168.1.0/24
    const cidrPattern = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    // Or range notation like 192.168.1.1-255
    const rangePattern = /^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$/;
    
    return range === 'auto' || cidrPattern.test(range) || rangePattern.test(range);
  };
  
  // Format timestamp
  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };
  
  // Determine device type icon
  const getDeviceTypeIcon = (type) => {
    switch (type?.toLowerCase()) {
      case 'router':
        return 'fas fa-network-wired';
      case 'switch':
        return 'fas fa-sitemap';
      case 'server':
        return 'fas fa-server';
      case 'workstation':
        return 'fas fa-desktop';
      case 'mobile':
        return 'fas fa-mobile-alt';
      case 'iot':
        return 'fas fa-microchip';
      default:
        return 'fas fa-laptop';
    }
  };
  
  return (
    <div className="network-discovery">
      <h1>Network Discovery</h1>
      
      {error && <div className="error-message">{error}</div>}
      
      <div className="discovery-grid">
        {/* Scan Control Panel */}
        <div className="discovery-card scan-controls">
          <h2>Scan Controls</h2>
          
          {activeScan ? (
            <div className="active-scan">
              <h3>Scan in Progress</h3>
              <div className="progress-bar">
                <div 
                  className="progress-bar-fill" 
                  style={{ width: `${scanProgress}%` }}
                ></div>
              </div>
              <div className="progress-text">
                {scanProgress}% Complete
                {activeScan.devicesFound && ` - ${activeScan.devicesFound} devices found`}
              </div>
              <button 
                className="cancel-scan-button"
                onClick={handleCancelScan}
                disabled={!canRunScan}
              >
                Cancel Scan
              </button>
            </div>
          ) : (
            <form onSubmit={handleStartScan} className="scan-form">
              <div className="form-group">
                <label htmlFor="range">IP Range:</label>
                <input
                  type="text"
                  id="range"
                  name="range"
                  value={scanOptions.range}
                  onChange={handleInputChange}
                  placeholder="auto (detect network) or 192.168.1.0/24"
                  disabled={!canRunScan}
                />
                <small className="form-help">
                  Leave empty for automatic detection
                </small>
              </div>
              
              <div className="form-group">
                <label htmlFor="timeout">Timeout (seconds):</label>
                <input
                  type="number"
                  id="timeout"
                  name="timeout"
                  min="5"
                  max="300"
                  value={scanOptions.timeout}
                  onChange={handleInputChange}
                  disabled={!canRunScan}
                />
              </div>
              
              <div className="form-group checkbox">
                <input
                  type="checkbox"
                  id="deepScan"
                  name="deepScan"
                  checked={scanOptions.deepScan}
                  onChange={handleInputChange}
                  disabled={!canRunScan}
                />
                <label htmlFor="deepScan">Deep Scan (OS & Service Detection)</label>
              </div>
              
              <div className="scan-actions">
                <button 
                  type="submit" 
                  className="start-scan-button"
                  disabled={loading || !canRunScan}
                >
                  {loading ? 'Starting...' : 'Start Scan'}
                </button>
                
                {canConfigureScan && (
                  <div className="schedule-buttons">
                    <button 
                      type="button"
                      onClick={() => handleScheduleScan('hourly')}
                      disabled={loading}
                    >
                      Schedule Hourly
                    </button>
                    <button 
                      type="button"
                      onClick={() => handleScheduleScan('daily')}
                      disabled={loading}
                    >
                      Schedule Daily
                    </button>
                    <button 
                      type="button"
                      onClick={() => handleScheduleScan('weekly')}
                      disabled={loading}
                    >
                      Schedule Weekly
                    </button>
                  </div>
                )}
              </div>
            </form>
          )}
        </div>
        
        {/* Scheduled Scans */}
        {canConfigureScan && scheduledScans.length > 0 && (
          <div className="discovery-card scheduled-scans">
            <h2>Scheduled Scans</h2>
            <div className="scheduled-scans-list">
              {scheduledScans.map(scan => (
                <div key={scan.id} className="scheduled-scan-item">
                  <div className="scheduled-scan-info">
                    <span className="scheduled-scan-frequency">
                      {scan.schedule.frequency.charAt(0).toUpperCase() + scan.schedule.frequency.slice(1)}
                    </span>
                    <span className="scheduled-scan-created">
                      Created: {formatTimestamp(scan.createdAt)}
                    </span>
                  </div>
                  <div className="scheduled-scan-actions">
                    <label className="toggle-switch">
                      <input
                        type="checkbox"
                        checked={scan.enabled}
                        onChange={() => handleToggleScheduledScan(scan.id, !scan.enabled)}
                      />
                      <span className="toggle-slider"></span>
                    </label>
                    <button 
                      className="delete-scheduled-scan"
                      onClick={() => handleDeleteScheduledScan(scan.id)}
                    >
                      <i className="fas fa-trash"></i>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
        
        {/* Discovered Devices */}
        <div className="discovery-card device-list">
          <h2>Discovered Devices</h2>
          
          {loading && !activeScan ? (
            <div className="loading">Loading devices...</div>
          ) : devices.length > 0 ? (
            <div className="devices-table-container">
              <table className="devices-table">
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>MAC Address</th>
                    <th>Device Type</th>
                    <th>Hostname</th>
                    <th>Last Seen</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((device, index) => (
                    <tr key={index} className="device-row">
                      <td>{device.ipAddress}</td>
                      <td>{device.macAddress}</td>
                      <td>
                        <i className={getDeviceTypeIcon(device.type)}></i>
                        {device.type || 'Unknown'}
                      </td>
                      <td>{device.hostname || '-'}</td>
                      <td>{device.lastSeen ? formatTimestamp(device.lastSeen) : '-'}</td>
                      <td>
                        <span className={`device-status ${device.status?.toLowerCase()}`}>
                          {device.status || 'Unknown'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="no-devices">
              <p>No devices discovered yet.</p>
              {canRunScan && (
                <p>Click "Start Scan" to discover devices on your network.</p>
              )}
            </div>
          )}
          
          {!loading && devices.length > 0 && (
            <div className="discovery-stats">
              <div className="stat-item">
                <span className="stat-label">Total Devices:</span>
                <span className="stat-value">{devices.length}</span>
              </div>
              <div className="stat-item">
                <span className="stat-label">Last Scan:</span>
                <span className="stat-value">
                  {discoveryService.getLastScanTime() 
                    ? formatTimestamp(discoveryService.getLastScanTime()) 
                    : 'Never'}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default NetworkDiscovery; 