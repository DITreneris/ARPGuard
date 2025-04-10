import React, { useState, useEffect } from 'react';
import { useSelector } from 'react-redux';
import './AlertDashboard.css';

/**
 * Alert Dashboard Component
 * 
 * Displays a list of alerts with filtering and sorting capabilities
 */
const AlertDashboard = () => {
  // State for alerts and UI
  const [alerts, setAlerts] = useState([]);
  const [filteredAlerts, setFilteredAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [timeframe, setTimeframe] = useState('24h');
  const [activeSeverityFilters, setActiveSeverityFilters] = useState([
    'critical', 'high', 'medium', 'low'
  ]);
  
  // Get app mode from Redux store
  const isLiteMode = useSelector(state => state.app.isLiteMode);
  
  // Fetch alerts data
  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        setLoading(true);
        
        // In a real app, this would be an API call
        // For now we'll simulate with a timeout
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Mock data for demonstration
        const mockAlerts = generateMockAlerts(isLiteMode);
        setAlerts(mockAlerts);
        setFilteredAlerts(mockAlerts);
        setLoading(false);
      } catch (err) {
        console.error('Error fetching alerts:', err);
        setError('Failed to load alerts. Please try again.');
        setLoading(false);
      }
    };

    fetchAlerts();
  }, [isLiteMode]);

  // Apply filters when search query, timeframe or severity filters change
  useEffect(() => {
    if (!alerts.length) return;
    
    const filtered = alerts.filter(alert => {
      // Apply severity filter
      if (!activeSeverityFilters.includes(alert.severity)) {
        return false;
      }
      
      // Apply search query
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        return (
          alert.title.toLowerCase().includes(query) ||
          alert.description.toLowerCase().includes(query) ||
          (alert.sourceIp && alert.sourceIp.includes(query)) ||
          (alert.targetIp && alert.targetIp.includes(query)) ||
          (alert.sourceMac && alert.sourceMac.toLowerCase().includes(query)) ||
          (alert.targetMac && alert.targetMac.toLowerCase().includes(query))
        );
      }
      
      // Apply timeframe filter
      const now = Date.now();
      switch (timeframe) {
        case '1h':
          return (now - alert.timestamp) <= 3600000;
        case '6h':
          return (now - alert.timestamp) <= 21600000;
        case '24h':
          return (now - alert.timestamp) <= 86400000;
        case '7d':
          return (now - alert.timestamp) <= 604800000;
        case 'all':
          return true;
        default:
          return true;
      }
    });
    
    setFilteredAlerts(filtered);
  }, [alerts, searchQuery, timeframe, activeSeverityFilters]);

  // Handle search input
  const handleSearchChange = (e) => {
    setSearchQuery(e.target.value);
  };

  // Handle timeframe selection
  const handleTimeframeChange = (e) => {
    setTimeframe(e.target.value);
  };

  // Toggle severity filter
  const toggleSeverityFilter = (severity) => {
    if (activeSeverityFilters.includes(severity)) {
      // Don't allow deselecting all filters
      if (activeSeverityFilters.length > 1) {
        setActiveSeverityFilters(activeSeverityFilters.filter(s => s !== severity));
      }
    } else {
      setActiveSeverityFilters([...activeSeverityFilters, severity]);
    }
  };

  // Handle alert selection
  const handleAlertClick = (alert) => {
    setSelectedAlert(alert.id === selectedAlert?.id ? null : alert);
  };

  // Handle refresh button click
  const handleRefresh = () => {
    setLoading(true);
    // In a real app, re-fetch data here
    setTimeout(() => {
      const mockAlerts = generateMockAlerts(isLiteMode);
      setAlerts(mockAlerts);
      setFilteredAlerts(mockAlerts);
      setLoading(false);
    }, 1000);
  };

  // Format timestamp
  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  // Calculate stats
  const alertStats = {
    critical: filteredAlerts.filter(a => a.severity === 'critical').length,
    high: filteredAlerts.filter(a => a.severity === 'high').length,
    medium: filteredAlerts.filter(a => a.severity === 'medium').length,
    low: filteredAlerts.filter(a => a.severity === 'low').length,
    total: filteredAlerts.length
  };

  return (
    <div className={`alert-dashboard ${isLiteMode ? 'lite-mode' : ''}`}>
      <div className="dashboard-header">
        <h2>Alerts Dashboard</h2>
        <div className="filter-controls">
          <div className="search-container">
            <input
              type="text"
              className="search-input"
              placeholder="Search alerts..."
              value={searchQuery}
              onChange={handleSearchChange}
            />
          </div>
          
          <div className="timeframe-selector">
            <label>Timeframe:</label>
            <select 
              className="timeframe-select"
              value={timeframe}
              onChange={handleTimeframeChange}
            >
              <option value="1h">Last hour</option>
              <option value="6h">Last 6 hours</option>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
              <option value="all">All time</option>
            </select>
          </div>
          
          <div className="severity-filters">
            {['critical', 'high', 'medium', 'low'].map(severity => (
              <button
                key={severity}
                className={`severity-filter ${severity} ${activeSeverityFilters.includes(severity) ? 'active' : ''}`}
                onClick={() => toggleSeverityFilter(severity)}
              >
                {severity}
              </button>
            ))}
          </div>
          
          <button className="refresh-button" onClick={handleRefresh}>
            Refresh
          </button>
        </div>
      </div>
      
      {/* Stats section - hide in lite mode if screen is small */}
      {(!isLiteMode || window.innerWidth > 768) && (
        <div className="stats-section">
          <div className="stat-card critical">
            <h3>Critical</h3>
            <div className="stat-value">{alertStats.critical}</div>
          </div>
          <div className="stat-card high">
            <h3>High</h3>
            <div className="stat-value">{alertStats.high}</div>
          </div>
          <div className="stat-card medium">
            <h3>Medium</h3>
            <div className="stat-value">{alertStats.medium}</div>
          </div>
          <div className="stat-card low">
            <h3>Low</h3>
            <div className="stat-value">{alertStats.low}</div>
          </div>
        </div>
      )}
      
      <div className="alerts-container">
        {loading ? (
          <div className="loading-indicator">
            <div className="spinner"></div>
            <p>Loading alerts...</p>
          </div>
        ) : error ? (
          <div className="error-message">
            <p>{error}</p>
            <button onClick={handleRefresh}>Try Again</button>
          </div>
        ) : filteredAlerts.length === 0 ? (
          <div className="no-alerts-message">
            <p>No alerts found matching your filters.</p>
            <button onClick={() => {
              setSearchQuery('');
              setActiveSeverityFilters(['critical', 'high', 'medium', 'low']);
              setTimeframe('24h');
            }}>Reset Filters</button>
          </div>
        ) : (
          <table className="alerts-table">
            <thead>
              <tr>
                <th className="severity-column">Sev</th>
                <th className="title-column">Alert</th>
                <th className="source-column">Source</th>
                {!isLiteMode && <th className="target-column">Target</th>}
                <th className="time-column">Time</th>
                <th className="status-column">Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map(alert => (
                <tr 
                  key={alert.id} 
                  className={`alert-row ${alert.severity} ${selectedAlert?.id === alert.id ? 'selected' : ''}`}
                  onClick={() => handleAlertClick(alert)}
                >
                  <td className="severity-column">
                    <div className={`severity-indicator ${alert.severity}`}></div>
                  </td>
                  <td className="title-column">
                    <div className="alert-title">{alert.title}</div>
                    <div className="alert-description">{alert.description}</div>
                  </td>
                  <td className="source-column">
                    {alert.sourceIp ? (
                      <>
                        <div>{alert.sourceIp}</div>
                        <div className="mac-address">{alert.sourceMac}</div>
                      </>
                    ) : (
                      <span className="na-text">N/A</span>
                    )}
                  </td>
                  {!isLiteMode && (
                    <td className="target-column">
                      {alert.targetIp ? (
                        <>
                          <div>{alert.targetIp}</div>
                          <div className="mac-address">{alert.targetMac}</div>
                        </>
                      ) : (
                        <span className="na-text">N/A</span>
                      )}
                    </td>
                  )}
                  <td className="time-column">
                    {formatTimestamp(alert.timestamp)}
                  </td>
                  <td className="status-column">
                    <div className={`status-badge ${alert.status}`}>
                      {alert.status}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      
      {/* Alert details panel */}
      {selectedAlert && (
        <div className="alert-details-panel">
          <div className="panel-header">
            <h3>Alert Details</h3>
            <button className="close-button" onClick={() => setSelectedAlert(null)}>×</button>
          </div>
          <div className="panel-content">
            <div className="detail-section">
              <div className="detail-header">
                <div className={`severity-badge ${selectedAlert.severity}`}>
                  {selectedAlert.severity}
                </div>
                <div className="alert-time">
                  {formatTimestamp(selectedAlert.timestamp)}
                </div>
              </div>
              <h3>{selectedAlert.title}</h3>
              <div className="alert-description-block">
                <p>{selectedAlert.description}</p>
                <p className="alert-details">{selectedAlert.details}</p>
              </div>
            </div>
            
            <div className="detail-section">
              <h4>Source</h4>
              <table className="details-table">
                <tbody>
                  <tr>
                    <td>IP Address</td>
                    <td>{selectedAlert.sourceIp || 'N/A'}</td>
                  </tr>
                  <tr>
                    <td>MAC Address</td>
                    <td>{selectedAlert.sourceMac || 'N/A'}</td>
                  </tr>
                  <tr>
                    <td>Hostname</td>
                    <td>{selectedAlert.sourceHostname || 'Unknown'}</td>
                  </tr>
                  <tr>
                    <td>Vendor</td>
                    <td>{selectedAlert.sourceVendor || 'Unknown'}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            
            <div className="detail-section">
              <h4>Target</h4>
              <table className="details-table">
                <tbody>
                  <tr>
                    <td>IP Address</td>
                    <td>{selectedAlert.targetIp || 'N/A'}</td>
                  </tr>
                  <tr>
                    <td>MAC Address</td>
                    <td>{selectedAlert.targetMac || 'N/A'}</td>
                  </tr>
                  <tr>
                    <td>Hostname</td>
                    <td>{selectedAlert.targetHostname || 'Unknown'}</td>
                  </tr>
                  <tr>
                    <td>Vendor</td>
                    <td>{selectedAlert.targetVendor || 'Unknown'}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            
            {/* Show packet details in non-lite mode only */}
            {!isLiteMode && (
              <div className="detail-section">
                <h4>Packet Analysis</h4>
                <table className="details-table">
                  <tbody>
                    <tr>
                      <td>Protocol</td>
                      <td>{selectedAlert.protocol || 'Unknown'}</td>
                    </tr>
                    <tr>
                      <td>Packet Count</td>
                      <td>{selectedAlert.packetCount || 0}</td>
                    </tr>
                    <tr>
                      <td>First Seen</td>
                      <td>{selectedAlert.firstSeen ? formatTimestamp(selectedAlert.firstSeen) : 'N/A'}</td>
                    </tr>
                    <tr>
                      <td>Last Seen</td>
                      <td>{selectedAlert.lastSeen ? formatTimestamp(selectedAlert.lastSeen) : 'N/A'}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            )}
            
            <div className="actions-section">
              <h4>Actions</h4>
              <div className="action-buttons">
                <button className="action-button">Acknowledge</button>
                <button className="action-button">Investigate</button>
                <button className="action-button primary">Block Source</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Helper function to generate mock alerts for demo purposes
const generateMockAlerts = (isLiteMode) => {
  const severities = ['critical', 'high', 'medium', 'low'];
  const statuses = ['new', 'acknowledged', 'resolved'];
  const mockAlerts = [];
  
  // Generate fewer alerts for lite mode
  const alertCount = isLiteMode ? 10 : 25;
  
  for (let i = 1; i <= alertCount; i++) {
    const severity = severities[Math.floor(Math.random() * severities.length)];
    const status = statuses[Math.floor(Math.random() * statuses.length)];
    const now = Date.now();
    const randomTimeInPast = Math.floor(Math.random() * 604800000); // Random time in the past week
    
    // More critical alerts are more likely to be new
    const adjustedStatus = severity === 'critical' && Math.random() > 0.3 ? 'new' : status;
    
    mockAlerts.push({
      id: `alert-${i}`,
      severity,
      status: adjustedStatus,
      timestamp: now - randomTimeInPast,
      firstSeen: now - randomTimeInPast - Math.floor(Math.random() * 3600000),
      lastSeen: now - Math.floor(Math.random() * 1800000),
      title: getRandomAlertTitle(severity),
      description: getRandomAlertDescription(severity),
      details: "Additional details about this alert would be shown here.",
      sourceIp: `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
      sourceMac: generateRandomMac(),
      sourceHostname: `device-${Math.floor(Math.random() * 100)}`,
      sourceVendor: getRandomVendor(),
      targetIp: `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
      targetMac: generateRandomMac(),
      targetHostname: `device-${Math.floor(Math.random() * 100)}`,
      targetVendor: getRandomVendor(),
      protocol: "ARP",
      packetCount: Math.floor(Math.random() * 100) + 1
    });
  }
  
  // Sort by severity and timestamp
  return mockAlerts.sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    if (severityOrder[a.severity] !== severityOrder[b.severity]) {
      return severityOrder[a.severity] - severityOrder[b.severity];
    }
    // If same severity, sort by most recent first
    return b.timestamp - a.timestamp;
  });
};

// Helper functions for generating realistic looking mock data
const getRandomAlertTitle = (severity) => {
  const titles = {
    critical: [
      "ARP Cache Poisoning Attack Detected",
      "Gateway Impersonation Attack",
      "MITM Attack in Progress",
      "Critical ARP Spoofing Attack"
    ],
    high: [
      "Suspicious ARP Reply Detected",
      "Multiple MAC Addresses for IP",
      "Unauthorized ARP Announcements",
      "Potential ARP Spoofing Activity"
    ],
    medium: [
      "Unusual ARP Traffic Pattern",
      "IP-MAC Mapping Changed",
      "Gateway MAC Address Changed",
      "Duplicate IP Address Detected"
    ],
    low: [
      "New Device on Network",
      "MAC Address Change",
      "Minor ARP Table Inconsistency",
      "Infrequent ARP Request Pattern"
    ]
  };
  
  const options = titles[severity];
  return options[Math.floor(Math.random() * options.length)];
};

const getRandomAlertDescription = (severity) => {
  const descriptions = {
    critical: [
      "A device is actively intercepting network traffic through ARP spoofing.",
      "The network gateway is being impersonated by an unauthorized device.",
      "Man-in-the-middle attack detected with high confidence.",
      "Critical security breach: unauthorized device intercepting all traffic."
    ],
    high: [
      "Multiple conflicting ARP replies detected for the same IP address.",
      "A single IP address is associated with multiple MAC addresses.",
      "Unauthorized device is sending ARP announcements for network gateway.",
      "Potential ARP cache poisoning attack detected."
    ],
    medium: [
      "Unusual pattern of ARP requests detected from a device.",
      "The MAC address for an IP has changed unexpectedly.",
      "The gateway's MAC address has changed from its expected value.",
      "Two devices are using the same IP address on the network."
    ],
    low: [
      "A new device has joined the network and sent its first ARP request.",
      "A device has changed its MAC address through normal means.",
      "Minor inconsistency detected in the network's ARP table.",
      "Device is sending ARP requests at an unusual frequency."
    ]
  };
  
  const options = descriptions[severity];
  return options[Math.floor(Math.random() * options.length)];
};

const generateRandomMac = () => {
  const hexDigits = "0123456789ABCDEF";
  let mac = "";
  
  for (let i = 0; i < 6; i++) {
    let part = "";
    for (let j = 0; j < 2; j++) {
      part += hexDigits.charAt(Math.floor(Math.random() * 16));
    }
    mac += part;
    if (i < 5) mac += ":";
  }
  
  return mac;
};

const getRandomVendor = () => {
  const vendors = [
    "Apple Inc.",
    "Cisco Systems",
    "Dell Inc.",
    "Intel Corporation",
    "Samsung Electronics",
    "Sony Corporation",
    "Huawei Technologies",
    "HP Inc.",
    "Lenovo Group Ltd.",
    "ASUS Tek Computer Inc.",
    "Microsoft Corporation",
    "Unknown"
  ];
  
  return vendors[Math.floor(Math.random() * vendors.length)];
};

export default AlertDashboard; 