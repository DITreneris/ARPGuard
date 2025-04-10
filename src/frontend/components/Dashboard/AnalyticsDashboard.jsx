import React, { useState, useEffect, useContext } from 'react';
import { 
  fetchDashboardData, 
  exportDashboardCSV, 
  exportDashboardJSON,
  downloadFile,
  getSystemPerformance
} from '../../services/AnalyticsService';
import { Line, Bar, Pie } from 'react-chartjs-2';
import { Chart, registerables } from 'chart.js';
import AppContext from '../../context/AppContext';
import Spinner from '../common/Spinner';
import AlertCard from '../Alerts/AlertCard';
import './AnalyticsDashboard.css';

// Register Chart.js components
Chart.register(...registerables);

const AnalyticsDashboard = () => {
  const { isLiteMode } = useContext(AppContext);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dashboardData, setDashboardData] = useState(null);
  const [timePeriod, setTimePeriod] = useState('week');
  const [customDateRange, setCustomDateRange] = useState({ startDate: null, endDate: null });
  const [systemPerformance, setSystemPerformance] = useState(null);

  useEffect(() => {
    loadDashboardData();
  }, [timePeriod, customDateRange]);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Fetch dashboard data
      const data = await fetchDashboardData(
        timePeriod, 
        timePeriod === 'custom' ? customDateRange : null
      );
      setDashboardData(data);
      
      // Fetch system performance metrics
      const perfData = await getSystemPerformance();
      setSystemPerformance(perfData);
      
      setLoading(false);
    } catch (err) {
      setError('Failed to load dashboard data. Please try again later.');
      setLoading(false);
      console.error('Dashboard data loading error:', err);
    }
  };

  const handleExportCSV = () => {
    if (!dashboardData) return;
    
    try {
      const csvData = exportDashboardCSV(dashboardData);
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      downloadFile(csvData, `arp-guard-analytics-${timestamp}.csv`, 'text/csv');
    } catch (err) {
      console.error('Error exporting CSV:', err);
    }
  };

  const handleExportJSON = () => {
    if (!dashboardData) return;
    
    try {
      const jsonData = exportDashboardJSON(dashboardData);
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      downloadFile(jsonData, `arp-guard-analytics-${timestamp}.json`, 'application/json');
    } catch (err) {
      console.error('Error exporting JSON:', err);
    }
  };

  const handlePeriodChange = (e) => {
    setTimePeriod(e.target.value);
  };

  const handleCustomDateChange = (type, e) => {
    setCustomDateRange(prev => ({
      ...prev,
      [type]: e.target.value
    }));
  };

  if (loading) {
    return (
      <div className="analytics-dashboard loading">
        <Spinner size="large" />
        <p>Loading dashboard data...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="analytics-dashboard error">
        <p className="error-message">{error}</p>
        <button className="retry-button" onClick={loadDashboardData}>Retry</button>
      </div>
    );
  }

  if (!dashboardData) {
    return (
      <div className="analytics-dashboard empty">
        <p>No data available for the selected period.</p>
        <button className="retry-button" onClick={loadDashboardData}>Refresh</button>
      </div>
    );
  }

  // Chart configuration for network activity
  const networkActivityConfig = {
    labels: dashboardData.networkActivity.map(point => point.timestamp),
    datasets: [
      {
        label: 'Packets',
  const { stats, sessionInfo, alerts, networkActivity, systemPerformance } = dashboardData;

  return (
    <div className="analytics-dashboard">
      <div className="dashboard-header">
        <h1>ARP Guard Analytics</h1>
        <div className="dashboard-controls">
          <select 
            value={selectedPeriod} 
            onChange={handlePeriodChange}
            className="period-selector"
          >
            <option value="1h">Last Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
          <div className="export-buttons">
            <button onClick={handleExportCSV} className="export-button">
              Export CSV
            </button>
            <button onClick={handleExportJSON} className="export-button">
              Export JSON
            </button>
          </div>
        </div>
      </div>

      <div className="session-info-section">
        <div className="session-info-card">
          <h3>Session Information</h3>
          <div className="session-details">
            <p><strong>Start Time:</strong> {new Date(sessionInfo.startTime).toLocaleString()}</p>
            <p><strong>Duration:</strong> {sessionInfo.duration}</p>
            <p><strong>Version:</strong> {sessionInfo.version}</p>
            <p><strong>Mode:</strong> {sessionInfo.mode}</p>
          </div>
        </div>
      </div>

      <div className="stats-summary-section">
        <StatsCard 
          title="Packets Processed" 
          value={stats.packetsProcessed.toLocaleString()} 
          icon="network"
          change={stats.packetsProcessedChange}
        />
        <StatsCard 
          title="Threats Detected" 
          value={stats.threatsDetected.toLocaleString()} 
          icon="warning"
          change={stats.threatsDetectedChange}
          isNegative={true}
        />
        <StatsCard 
          title="Avg. Detection Time" 
          value={`${stats.avgDetectionTime} ms`}
          icon="time"
          change={stats.avgDetectionTimeChange}
          isNegative={false}
        />
        <StatsCard 
          title="Success Rate" 
          value={`${stats.successRate}%`}
          icon="check"
          change={stats.successRateChange}
        />
      </div>

      <div className="charts-grid">
        <div className="chart-container">
          <h3>Threat Detections Over Time</h3>
          <LineChart 
            data={networkActivity.threatOverTime} 
            xKey="timestamp" 
            yKey="count"
            color="#f44336"
          />
        </div>
        <div className="chart-container">
          <h3>Network Activity</h3>
          <LineChart 
            data={networkActivity.packetVolume} 
            xKey="timestamp" 
            yKey="count"
            color="#2196f3"
          />
        </div>
        <div className="chart-container">
          <h3>Threat Types</h3>
          <PieChart 
            data={networkActivity.threatTypes} 
            nameKey="type" 
            valueKey="count"
          />
        </div>
        <div className="chart-container">
          <h3>System Resource Usage</h3>
          <LineChart 
            data={systemPerformance.resourceUsage} 
            xKey="timestamp" 
            multipleYKeys={["cpu", "memory"]}
            colors={["#4caf50", "#ff9800"]}
          />
        </div>
      </div>

      <div className="alerts-section">
        <h2>Recent Alerts</h2>
        <AlertsTable alerts={alerts.recent} />
        {alerts.recent.length > 0 && (
          <div className="view-all-alerts">
            <a href="/alerts" className="view-all-link">View All Alerts</a>
          </div>
        )}
      </div>

      <div className="system-performance-section">
        <h2>System Performance</h2>
        <div className="performance-metrics">
          <div className="metric-card">
            <h3>CPU Usage</h3>
            <p className="metric-value">{systemPerformance.current.cpu}%</p>
            <p className="metric-label">Average: {systemPerformance.average.cpu}%</p>
          </div>
          <div className="metric-card">
            <h3>Memory Usage</h3>
            <p className="metric-value">{systemPerformance.current.memory}%</p>
            <p className="metric-label">Average: {systemPerformance.average.memory}%</p>
          </div>
          <div className="metric-card">
            <h3>Disk Usage</h3>
            <p className="metric-value">{systemPerformance.current.disk}%</p>
            <p className="metric-label">Average: {systemPerformance.average.disk}%</p>
          </div>
          <div className="metric-card">
            <h3>Network Throughput</h3>
            <p className="metric-value">{systemPerformance.current.network} Mbps</p>
            <p className="metric-label">Average: {systemPerformance.average.network} Mbps</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AnalyticsDashboard; 