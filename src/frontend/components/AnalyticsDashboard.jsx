import React, { useEffect, useState, useRef, useCallback } from 'react';
import { Line, Bar, Doughnut, Radar, Pie } from 'react-chartjs-2';
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
  // Add new state for enhanced metrics
  const [networkHealth, setNetworkHealth] = useState({
    connectivity: 0,
    latency_score: 0,
    packet_loss: 0,
    error_rate: 0,
    stability_index: 0
  });
  const [threatLevels, setThreatLevels] = useState({
    current_level: 'low',
    score: 0,
    trend: 'stable',
    attack_vectors: {
      arp_spoofing: 0,
      ddos: 0,
      mitm: 0,
      reconnaissance: 0
    }
  });
  const [performanceMetrics, setPerformanceMetrics] = useState({
    packet_processing_time: 0,
    analysis_time_per_packet: 0,
    rule_processing_time: 0,
    database_write_time: 0,
    alert_generation_time: 0
  });
  const [resourceUsage, setResourceUsage] = useState({
    cpu: { total: 0, by_component: {} },
    memory: { total: 0, by_component: {} },
    disk: { total: 0, database_size: 0, log_size: 0, temp_storage: 0 }
  });
  const [betaMetrics, setBetaMetrics] = useState({
    user_session_count: 0,
    feature_usage: {},
    error_counts: {},
    performance_issues: 0,
    crash_count: 0,
    uptime: 0,
    version: '',
    testing_phase: '',
    telemetry: { stability_score: 0 }
  });

  const chartsRef = useRef({});
  
  // Handle metrics update with batching and filtering
  const handleMetricsUpdate = useCallback((data) => {
    // Update original metrics
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

    // Update new metrics if they exist in the data
    if (data.network_health) {
      setNetworkHealth(data.network_health);
    }

    if (data.threat_levels) {
      setThreatLevels(data.threat_levels);
    }

    if (data.performance_metrics) {
      setPerformanceMetrics(data.performance_metrics);
    }

    if (data.resource_usage) {
      setResourceUsage(data.resource_usage);
    }

    if (data.beta_metrics) {
      setBetaMetrics(data.beta_metrics);
    }
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

  // New chart configurations for enhanced metrics
  
  // Network Health Radar Chart
  const networkHealthConfig = {
    labels: ['Connectivity', 'Latency Score', 'Stability', 'Error Rate', 'Packet Loss'],
    datasets: [{
      label: 'Network Health',
      data: [
        networkHealth.connectivity,
        networkHealth.latency_score,
        networkHealth.stability_index,
        100 - networkHealth.error_rate, // Invert error rate (higher is better)
        100 - networkHealth.packet_loss // Invert packet loss (higher is better)
      ],
      backgroundColor: 'rgba(75, 192, 192, 0.2)',
      borderColor: 'rgb(75, 192, 192)',
      pointBackgroundColor: 'rgb(75, 192, 192)',
      pointBorderColor: '#fff',
      pointHoverBackgroundColor: '#fff',
      pointHoverBorderColor: 'rgb(75, 192, 192)'
    }]
  };

  // Threat Level Chart
  const threatLevelConfig = {
    labels: Object.keys(threatLevels.attack_vectors),
    datasets: [{
      label: 'Threat Vectors',
      data: Object.values(threatLevels.attack_vectors),
      backgroundColor: 'rgba(255, 99, 132, 0.5)',
      borderColor: 'rgb(255, 99, 132)',
      borderWidth: 1
    }]
  };

  // Performance Metrics Chart
  const performanceMetricsConfig = {
    labels: [
      'Packet Processing',
      'Analysis',
      'Rule Processing',
      'Database Writes',
      'Alert Generation'
    ],
    datasets: [{
      label: 'Time (ms)',
      data: [
        performanceMetrics.packet_processing_time,
        performanceMetrics.analysis_time_per_packet,
        performanceMetrics.rule_processing_time,
        performanceMetrics.database_write_time,
        performanceMetrics.alert_generation_time
      ],
      backgroundColor: [
        'rgba(75, 192, 192, 0.7)',
        'rgba(54, 162, 235, 0.7)',
        'rgba(153, 102, 255, 0.7)',
        'rgba(255, 159, 64, 0.7)',
        'rgba(255, 99, 132, 0.7)'
      ],
      borderColor: [
        'rgb(75, 192, 192)',
        'rgb(54, 162, 235)',
        'rgb(153, 102, 255)',
        'rgb(255, 159, 64)',
        'rgb(255, 99, 132)'
      ],
      borderWidth: 1
    }]
  };

  // Resource Usage Chart (CPU)
  const resourceUsageConfig = {
    labels: resourceUsage.cpu.by_component ? Object.keys(resourceUsage.cpu.by_component) : [],
    datasets: [{
      label: 'CPU Usage by Component (%)',
      data: resourceUsage.cpu.by_component ? Object.values(resourceUsage.cpu.by_component) : [],
      backgroundColor: [
        'rgba(255, 99, 132, 0.7)',
        'rgba(54, 162, 235, 0.7)',
        'rgba(255, 206, 86, 0.7)',
        'rgba(75, 192, 192, 0.7)',
        'rgba(153, 102, 255, 0.7)'
      ],
      borderWidth: 1
    }]
  };

  // Beta Metrics - Feature Usage
  const betaFeatureUsageConfig = {
    labels: betaMetrics.feature_usage ? Object.keys(betaMetrics.feature_usage) : [],
    datasets: [{
      label: 'Feature Usage',
      data: betaMetrics.feature_usage ? Object.values(betaMetrics.feature_usage) : [],
      backgroundColor: 'rgba(54, 162, 235, 0.5)',
      borderColor: 'rgb(54, 162, 235)',
      borderWidth: 1
    }]
  };

  // Beta Metrics - Error Counts
  const betaErrorsConfig = {
    labels: betaMetrics.error_counts ? Object.keys(betaMetrics.error_counts) : [],
    datasets: [{
      label: 'Error Counts',
      data: betaMetrics.error_counts ? Object.values(betaMetrics.error_counts) : [],
      backgroundColor: [
        'rgba(255, 99, 132, 0.7)',  // Critical
        'rgba(255, 159, 64, 0.7)',  // Error
        'rgba(255, 205, 86, 0.7)',  // Warning
        'rgba(75, 192, 192, 0.7)'   // Info
      ],
      borderWidth: 0
    }]
  };

  // Chart options 
  const radarOptions = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      r: {
        angleLines: {
          display: true
        },
        suggestedMin: 0,
        suggestedMax: 100
      }
    }
  };

  return (
    <div className="analytics-dashboard">
      <header className="dashboard-header">
        <h1>Network Analytics Dashboard</h1>
        <div className="connection-status">
          <WebSocketStatus status={wsConnectionStatus} />
        </div>
      </header>

      {/* Beta Testing Badge */}
      <div className="beta-badge">
        <span className="beta-version">{betaMetrics.version}</span>
        <span className="beta-phase">{betaMetrics.testing_phase}</span>
        <span className="beta-uptime">Uptime: {betaMetrics.uptime}h</span>
        <span className="beta-stability">
          Stability: {betaMetrics.telemetry.stability_score.toFixed(1)}%
        </span>
      </div>

      <div className="dashboard-grid">
        {/* Original metrics section */}
        <div className="dashboard-card network-traffic">
          <h3>Network Traffic</h3>
          <div className="chart-container">
            <Line 
              data={networkTrafficConfig} 
              options={chartOptions}
              ref={el => chartsRef.current.networkTraffic = el}
            />
          </div>
        </div>

        <div className="dashboard-card threat-detections">
          <h3>Threat Detections</h3>
          <div className="chart-container">
            <Bar 
              data={threatDetectionsConfig} 
              options={chartOptions}
              ref={el => chartsRef.current.threatDetections = el}
            />
          </div>
        </div>

        <div className="dashboard-card system-performance">
          <h3>System Resources</h3>
          <div className="chart-container">
            <Doughnut 
              data={systemPerformanceConfig} 
              options={chartOptions}
              ref={el => chartsRef.current.systemPerformance = el}
            />
          </div>
        </div>

        {/* New metrics section - Network Health */}
        <div className="dashboard-card network-health">
          <h3>Network Health</h3>
          <div className="chart-container">
            <Radar
              data={networkHealthConfig}
              options={radarOptions}
              ref={el => chartsRef.current.networkHealth = el}
            />
          </div>
          <div className="metric-summary">
            <div className="metric-item">
              <span className="metric-label">Stability Index:</span>
              <span className="metric-value">{networkHealth.stability_index}%</span>
            </div>
            <div className="metric-item">
              <span className="metric-label">Packet Loss:</span>
              <span className="metric-value">{networkHealth.packet_loss}%</span>
            </div>
          </div>
        </div>

        {/* Threat Level Visualization */}
        <div className="dashboard-card threat-levels">
          <h3>Threat Level: <span className={`threat-level-${threatLevels.current_level}`}>
            {threatLevels.current_level.toUpperCase()}
          </span></h3>
          <div className="chart-container">
            <Bar
              data={threatLevelConfig}
              options={chartOptions}
              ref={el => chartsRef.current.threatLevel = el}
            />
          </div>
          <div className="metric-summary">
            <div className="metric-item">
              <span className="metric-label">Threat Score:</span>
              <span className="metric-value">{threatLevels.score}/100</span>
            </div>
            <div className="metric-item">
              <span className="metric-label">Trend:</span>
              <span className={`metric-value trend-${threatLevels.trend}`}>
                {threatLevels.trend}
              </span>
            </div>
          </div>
        </div>

        {/* Performance Metrics */}
        <div className="dashboard-card performance-metrics">
          <h3>Performance Metrics</h3>
          <div className="chart-container">
            <Bar
              data={performanceMetricsConfig}
              options={chartOptions}
              ref={el => chartsRef.current.performanceMetrics = el}
            />
          </div>
        </div>

        {/* Resource Usage Tracking */}
        <div className="dashboard-card resource-usage">
          <h3>Resource Usage by Component</h3>
          <div className="chart-container">
            <Pie
              data={resourceUsageConfig}
              options={chartOptions}
              ref={el => chartsRef.current.resourceUsage = el}
            />
          </div>
          <div className="metric-summary">
            <div className="metric-item">
              <span className="metric-label">Total CPU:</span>
              <span className="metric-value">{resourceUsage.cpu.total}%</span>
            </div>
            <div className="metric-item">
              <span className="metric-label">Total Memory:</span>
              <span className="metric-value">{resourceUsage.memory.total}%</span>
            </div>
            <div className="metric-item">
              <span className="metric-label">Disk Usage:</span>
              <span className="metric-value">{resourceUsage.disk.total}%</span>
            </div>
          </div>
        </div>

        {/* Beta Testing Metrics */}
        <div className="dashboard-card beta-metrics">
          <h3>Beta Testing Analytics</h3>
          <div className="beta-metrics-split">
            <div className="chart-container">
              <Bar
                data={betaFeatureUsageConfig}
                options={chartOptions}
                ref={el => chartsRef.current.betaFeatureUsage = el}
              />
              <h4>Feature Usage</h4>
            </div>
            <div className="chart-container">
              <Pie
                data={betaErrorsConfig}
                options={chartOptions}
                ref={el => chartsRef.current.betaErrors = el}
              />
              <h4>Error Distribution</h4>
            </div>
          </div>
          <div className="metric-summary">
            <div className="metric-item">
              <span className="metric-label">Active Sessions:</span>
              <span className="metric-value">{betaMetrics.user_session_count}</span>
            </div>
            <div className="metric-item">
              <span className="metric-label">Performance Issues:</span>
              <span className="metric-value">{betaMetrics.performance_issues}</span>
            </div>
            <div className="metric-item">
              <span className="metric-label">Crashes:</span>
              <span className="metric-value">{betaMetrics.crash_count}</span>
            </div>
          </div>
        </div>

        {/* Recent Alerts section */}
        <div className="dashboard-card recent-alerts">
          <h3>Recent Alerts</h3>
          <div className="alerts-list">
            {alerts.length === 0 ? (
              <p className="no-alerts">No recent alerts</p>
            ) : (
              alerts.slice(0, 5).map(alert => (
                <div key={alert.id} className={`alert-item severity-${alert.severity}`}>
                  <div className="alert-header">
                    <span className="alert-type">{alert.type}</span>
                    <span className="alert-time">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="alert-description">{alert.description}</p>
                  <div className="alert-details">
                    {alert.source_ip && (
                      <span className="alert-source">From: {alert.source_ip}</span>
                    )}
                    {alert.target_ip && (
                      <span className="alert-target">To: {alert.target_ip}</span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
          {alerts.length > 5 && (
            <div className="alerts-more">
              <button className="view-all-btn">View all {alerts.length} alerts</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AnalyticsDashboard; 