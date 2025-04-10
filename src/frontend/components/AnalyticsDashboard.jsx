import React, { useEffect, useState, useRef, useCallback } from 'react';
import { Line, Bar, Doughnut } from 'react-chartjs-2';
import analyticsWebSocket from '../services/websocketService';
import WebSocketStatus from './common/WebSocketStatus';
import '../styles/AnalyticsDashboard.css';

const AnalyticsDashboard = () => {
  const [metrics, setMetrics] = useState({
    networkTraffic: [],
    threatDetections: [],
    systemPerformance: []
  });
  const [alerts, setAlerts] = useState([]);
  const [systemStatus, setSystemStatus] = useState({});
  const [wsConnectionStatus, setWsConnectionStatus] = useState({
    connected: false,
    connecting: false,
    reconnecting: false,
    error: null
  });
  const chartsRef = useRef({});
  
  // Handle metrics update with batching and filtering
  const handleMetricsUpdate = useCallback((data) => {
    setMetrics(prevMetrics => {
      const newMetrics = { ...prevMetrics };
      
      // Handle network traffic - maintain max 20 data points
      if (data.networkTraffic) {
        newMetrics.networkTraffic = [
          ...prevMetrics.networkTraffic,
          ...data.networkTraffic
        ].slice(-20);
      }
      
      // Handle threat detections - update counts
      if (data.threatDetections) {
        // Merge threat detections by type
        const threatMap = {};
        [...prevMetrics.threatDetections, ...data.threatDetections].forEach(item => {
          if (!threatMap[item.type]) {
            threatMap[item.type] = item;
          } else {
            threatMap[item.type].count += item.count;
          }
        });
        newMetrics.threatDetections = Object.values(threatMap);
      }
      
      // Handle system performance
      if (data.systemPerformance) {
        newMetrics.systemPerformance = data.systemPerformance;
      }
      
      return newMetrics;
    });
  }, []);

  // Handle alerts update
  const handleAlertsUpdate = useCallback((data) => {
    setAlerts(prevAlerts => {
      // Add new alerts, maintain max 50 alerts
      const newAlerts = [...prevAlerts, ...data].sort((a, b) => {
        return new Date(b.timestamp) - new Date(a.timestamp);
      }).slice(0, 50);
      
      return newAlerts;
    });
  }, []);

  // Handle system status update
  const handleSystemStatusUpdate = useCallback((data) => {
    setSystemStatus(data);
  }, []);

  // Handle WebSocket connection events
  const handleConnected = useCallback(() => {
    setWsConnectionStatus({
      connected: true,
      connecting: false,
      reconnecting: false,
      error: null
    });
  }, []);

  const handleDisconnected = useCallback(() => {
    setWsConnectionStatus(prev => ({
      ...prev,
      connected: false
    }));
  }, []);

  const handleReconnecting = useCallback((data) => {
    setWsConnectionStatus({
      connected: false,
      connecting: false,
      reconnecting: true,
      error: null,
      attempt: data.attempt,
      maxAttempts: data.maxAttempts
    });
  }, []);

  const handleError = useCallback((error) => {
    console.error('WebSocket error:', error);
    setWsConnectionStatus(prev => ({
      ...prev,
      error: error
    }));
  }, []);

  // Initialize WebSocket connection
  useEffect(() => {
    // Connect to WebSocket
    setWsConnectionStatus(prev => ({ ...prev, connecting: true }));
    
    analyticsWebSocket.connect()
      .then(() => {
        // Successfully connected
        handleConnected();
      })
      .catch(error => {
        // Failed to connect
        console.error('Failed to connect to WebSocket:', error);
        setWsConnectionStatus({
          connected: false,
          connecting: false,
          reconnecting: false,
          error: error
        });
      });

    // Subscribe to topics
    analyticsWebSocket.subscribe('metrics');
    analyticsWebSocket.subscribe('alerts');
    analyticsWebSocket.subscribe('system_status');

    // Set up event listeners
    analyticsWebSocket.on('metrics', handleMetricsUpdate);
    analyticsWebSocket.on('alerts', handleAlertsUpdate);
    analyticsWebSocket.on('systemStatus', handleSystemStatusUpdate);
    analyticsWebSocket.on('error', handleError);
    analyticsWebSocket.on('connected', handleConnected);
    analyticsWebSocket.on('disconnected', handleDisconnected);
    analyticsWebSocket.on('reconnecting', handleReconnecting);

    return () => {
      // Cleanup
      analyticsWebSocket.unsubscribe('metrics');
      analyticsWebSocket.unsubscribe('alerts');
      analyticsWebSocket.unsubscribe('system_status');
      
      analyticsWebSocket.removeListener('metrics', handleMetricsUpdate);
      analyticsWebSocket.removeListener('alerts', handleAlertsUpdate);
      analyticsWebSocket.removeListener('systemStatus', handleSystemStatusUpdate);
      analyticsWebSocket.removeListener('error', handleError);
      analyticsWebSocket.removeListener('connected', handleConnected);
      analyticsWebSocket.removeListener('disconnected', handleDisconnected);
      analyticsWebSocket.removeListener('reconnecting', handleReconnecting);
      
      analyticsWebSocket.disconnect();
    };
  }, [
    handleMetricsUpdate, 
    handleAlertsUpdate, 
    handleSystemStatusUpdate, 
    handleConnected,
    handleDisconnected,
    handleReconnecting,
    handleError
  ]);

  // Chart configurations
  const networkTrafficConfig = {
    labels: metrics.networkTraffic.map(item => {
      const date = new Date(item.timestamp);
      return date.toLocaleTimeString();
    }),
    datasets: [{
      label: 'Network Traffic (KB/s)',
      data: metrics.networkTraffic.map(item => item.value),
      borderColor: 'rgb(75, 192, 192)',
      backgroundColor: 'rgba(75, 192, 192, 0.2)',
      tension: 0.4,
      fill: true
    }]
  };

  const threatDetectionsConfig = {
    labels: metrics.threatDetections.map(item => item.type),
    datasets: [{
      label: 'Threat Detections',
      data: metrics.threatDetections.map(item => item.count),
      backgroundColor: [
        'rgba(255, 99, 132, 0.7)',
        'rgba(255, 159, 64, 0.7)',
        'rgba(255, 205, 86, 0.7)',
        'rgba(75, 192, 192, 0.7)',
        'rgba(54, 162, 235, 0.7)'
      ],
      borderColor: [
        'rgb(255, 99, 132)',
        'rgb(255, 159, 64)',
        'rgb(255, 205, 86)',
        'rgb(75, 192, 192)',
        'rgb(54, 162, 235)'
      ],
      borderWidth: 1
    }]
  };

  const systemPerformanceConfig = {
    labels: ['CPU', 'Memory', 'Network'],
    datasets: [{
      label: 'System Resource Usage (%)',
      data: [
        systemStatus.cpuUsage || 0,
        systemStatus.memoryUsage || 0,
        systemStatus.networkUsage || 0
      ],
      backgroundColor: [
        'rgba(255, 99, 132, 0.5)',
        'rgba(54, 162, 235, 0.5)',
        'rgba(255, 206, 86, 0.5)'
      ],
      borderWidth: 0,
      hoverOffset: 4
    }]
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top',
      },
      tooltip: {
        mode: 'index',
        intersect: false,
      }
    },
    scales: {
      y: {
        beginAtZero: true
      }
    }
  };

  return (
    <div className="analytics-dashboard">
      <div className="dashboard-header">
        <h1>ARP Guard Analytics Dashboard</h1>
        <div className="system-status">
          <span className={`status-indicator ${systemStatus.status || 'unknown'}`}>
            {systemStatus.status || 'Unknown'}
          </span>
        </div>
      </div>

      {!wsConnectionStatus.connected && (
        <div className={`connection-banner ${wsConnectionStatus.reconnecting ? 'warning' : 'error'}`}>
          {wsConnectionStatus.connecting && 'Connecting to server...'}
          {wsConnectionStatus.reconnecting && `Reconnecting (Attempt ${wsConnectionStatus.attempt}/${wsConnectionStatus.maxAttempts})...`}
          {!wsConnectionStatus.connecting && !wsConnectionStatus.reconnecting && 'Disconnected from server. Data may be stale.'}
        </div>
      )}

      <div className="metrics-grid">
        <div className="metric-card">
          <h3>Network Traffic</h3>
          {metrics.networkTraffic.length > 0 ? (
            <div className="chart-container">
              <Line 
                data={networkTrafficConfig} 
                options={chartOptions}
                ref={ref => chartsRef.current.networkTraffic = ref} 
              />
            </div>
          ) : (
            <div className="no-data">No network traffic data available</div>
          )}
        </div>

        <div className="metric-card">
          <h3>Threat Detections</h3>
          {metrics.threatDetections.length > 0 ? (
            <div className="chart-container">
              <Bar 
                data={threatDetectionsConfig} 
                options={chartOptions}
                ref={ref => chartsRef.current.threatDetections = ref} 
              />
            </div>
          ) : (
            <div className="no-data">No threat detection data available</div>
          )}
        </div>

        <div className="metric-card">
          <h3>System Performance</h3>
          <div className="chart-container">
            <Doughnut 
              data={systemPerformanceConfig} 
              options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  tooltip: {
                    callbacks: {
                      label: function(context) {
                        return `${context.label}: ${context.raw}%`;
                      }
                    }
                  }
                }
              }}
              ref={ref => chartsRef.current.systemPerformance = ref} 
            />
          </div>
        </div>
      </div>

      <div className="alerts-section">
        <h3>Recent Alerts</h3>
        {alerts.length > 0 ? (
          <div className="alerts-list">
            {alerts.map((alert, index) => (
              <div key={index} className={`alert-item ${alert.severity}`}>
                <span className="alert-timestamp">
                  {new Date(alert.timestamp).toLocaleString()}
                </span>
                <span className="alert-message">{alert.message}</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="no-data">No alerts</div>
        )}
      </div>
      
      <WebSocketStatus />
    </div>
  );
};

export default AnalyticsDashboard; 