import React, { useState, useEffect, useRef } from 'react';
import { Card, Button, Alert, Tabs, Tab, Table, Badge, ProgressBar, Spinner } from 'react-bootstrap';
import { Line, Bar } from 'react-chartjs-2';
import {
  takeCpuSnapshot,
  analyzeCpu,
  startCpuProfiling,
  stopCpuProfiling,
  setCpuBaseline,
  CpuProfilerSocket
} from '../../services/ProfilerService';
import './ProfilerDashboard.css';

const CpuProfilerDashboard = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [cpuData, setCpuData] = useState(null);
  const [snapshot, setSnapshot] = useState(null);
  const [hotspots, setHotspots] = useState([]);
  const [healthScore, setHealthScore] = useState(null);
  const [socketStatus, setSocketStatus] = useState({ connected: false });
  const [isProfiling, setIsProfiling] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const socketRef = useRef(null);
  const chartRef = useRef(null);

  useEffect(() => {
    // Initialize component
    initializeData();

    // Connect to CPU profiler WebSocket
    connectWebSocket();

    // Clean up on unmount
    return () => {
      if (socketRef.current) {
        socketRef.current.disconnect();
      }
    };
  }, []);

  const initializeData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Get CPU analysis data
      const data = await analyzeCpu();
      setCpuData(data.summary);
      setSnapshot(data.summary.current);
      setHealthScore(data.health_score);
      
      if (data.recommendations && data.recommendations.length > 0) {
        // Extract hotspots from recommendations if available
        const funcRec = data.recommendations.find(r => r.type === 'function_optimization');
        if (funcRec && funcRec.details) {
          setHotspots(funcRec.details);
        }
      }
      
      setLoading(false);
    } catch (err) {
      setError('Failed to load CPU profiling data: ' + (err.message || 'Unknown error'));
      setLoading(false);
      console.error('CPU profiler error:', err);
    }
  };

  const connectWebSocket = () => {
    // Create and connect WebSocket for real-time updates
    socketRef.current = new CpuProfilerSocket(
      handleSnapshotUpdate,
      handleAnalysisUpdate,
      handleHotspotsUpdate,
      handleHealthScoreUpdate,
      handleStatusUpdate
    );
    
    socketRef.current.connect();
  };

  const handleSnapshotUpdate = (data) => {
    setSnapshot(data);
  };

  const handleAnalysisUpdate = (data) => {
    setCpuData(data.summary);
    
    if (data.recommendations && data.recommendations.length > 0) {
      const funcRec = data.recommendations.find(r => r.type === 'function_optimization');
      if (funcRec && funcRec.details) {
        setHotspots(funcRec.details);
      }
    }
  };

  const handleHotspotsUpdate = (data) => {
    setHotspots(data);
  };

  const handleHealthScoreUpdate = (score) => {
    setHealthScore(score);
  };

  const handleStatusUpdate = (status) => {
    setSocketStatus(status);
    if (status.profiling !== undefined) {
      setIsProfiling(status.profiling);
    }
  };

  const handleTakeSnapshot = async () => {
    try {
      if (socketRef.current && socketRef.current.isConnected) {
        socketRef.current.requestSnapshot('manual_snapshot');
      } else {
        setLoading(true);
        const data = await takeCpuSnapshot('manual_snapshot');
        setSnapshot(data);
        setLoading(false);
      }
    } catch (err) {
      setError('Failed to take CPU snapshot: ' + (err.message || 'Unknown error'));
      setLoading(false);
    }
  };

  const handleSetBaseline = async () => {
    try {
      setLoading(true);
      await setCpuBaseline();
      await initializeData(); // Refresh all data
      setLoading(false);
    } catch (err) {
      setError('Failed to set CPU baseline: ' + (err.message || 'Unknown error'));
      setLoading(false);
    }
  };

  const handleStartProfiling = async () => {
    try {
      if (socketRef.current && socketRef.current.isConnected) {
        socketRef.current.startProfiling();
        setIsProfiling(true);
      } else {
        setLoading(true);
        await startCpuProfiling();
        setIsProfiling(true);
        setLoading(false);
      }
    } catch (err) {
      setError('Failed to start CPU profiling: ' + (err.message || 'Unknown error'));
      setIsProfiling(false);
      setLoading(false);
    }
  };

  const handleStopProfiling = async () => {
    try {
      if (socketRef.current && socketRef.current.isConnected) {
        socketRef.current.stopProfiling();
      } else {
        setLoading(true);
        const data = await stopCpuProfiling();
        if (data.hotspots) {
          setHotspots(data.hotspots);
        }
        setIsProfiling(false);
        setLoading(false);
      }
    } catch (err) {
      setError('Failed to stop CPU profiling: ' + (err.message || 'Unknown error'));
      setLoading(false);
    }
  };

  const handleRequestAnalysis = () => {
    if (socketRef.current && socketRef.current.isConnected) {
      socketRef.current.requestAnalysis();
    } else {
      initializeData();
    }
  };

  const handleRequestHotspots = () => {
    if (socketRef.current && socketRef.current.isConnected) {
      socketRef.current.requestHotspots();
    }
  };

  const renderCpuChart = () => {
    if (!cpuData || !cpuData.history || cpuData.history.length === 0) {
      return <div className="text-center">No CPU history data available</div>;
    }

    const chartData = {
      labels: cpuData.history.map(item => {
        const date = new Date(item.timestamp);
        return date.toLocaleTimeString();
      }),
      datasets: [
        {
          label: 'CPU Usage (%)',
          data: cpuData.history.map(item => item.cpu_percent),
          fill: false,
          backgroundColor: 'rgba(75, 192, 192, 0.2)',
          borderColor: 'rgba(75, 192, 192, 1)',
          tension: 0.1
        }
      ]
    };

    return (
      <Line
        data={chartData}
        options={{
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: {
              beginAtZero: true,
              max: 100,
              title: {
                display: true,
                text: 'CPU Usage (%)'
              }
            },
            x: {
              title: {
                display: true,
                text: 'Time'
              }
            }
          }
        }}
        ref={chartRef}
      />
    );
  };

  const renderHealthScore = () => {
    if (healthScore === null) return null;
    
    let color = 'success';
    if (healthScore < 50) {
      color = 'danger';
    } else if (healthScore < 75) {
      color = 'warning';
    }

    return (
      <div className="health-score-container">
        <h4>CPU Health Score</h4>
        <div className="health-score">
          <div className={`score-circle ${color}`}>
            <div className="score-value">{Math.round(healthScore)}</div>
          </div>
        </div>
        <ProgressBar 
          variant={color} 
          now={healthScore} 
          label={`${Math.round(healthScore)}%`} 
          className="health-progress"
        />
      </div>
    );
  };

  const renderHotspots = () => {
    if (!hotspots || hotspots.length === 0) {
      return <div className="text-center">No CPU hotspots detected</div>;
    }

    return (
      <Table striped bordered hover>
        <thead>
          <tr>
            <th>Function</th>
            <th>Time (s)</th>
            <th>Calls</th>
          </tr>
        </thead>
        <tbody>
          {hotspots.map((spot, index) => (
            <tr key={index}>
              <td>{spot.function}</td>
              <td>{spot.cumulative_time.toFixed(4)}</td>
              <td>{spot.calls}</td>
            </tr>
          ))}
        </tbody>
      </Table>
    );
  };

  const renderCoreUsage = () => {
    if (!snapshot || !snapshot.per_cpu_percent || snapshot.per_cpu_percent.length === 0) {
      return <div className="text-center">No per-core CPU data available</div>;
    }

    const chartData = {
      labels: snapshot.per_cpu_percent.map((_, index) => `Core ${index}`),
      datasets: [
        {
          label: 'Per-Core CPU Usage (%)',
          data: snapshot.per_cpu_percent,
          backgroundColor: snapshot.per_cpu_percent.map(value => 
            value > 90 ? 'rgba(255, 99, 132, 0.7)' :
            value > 70 ? 'rgba(255, 159, 64, 0.7)' :
            'rgba(75, 192, 192, 0.7)'
          ),
          borderColor: snapshot.per_cpu_percent.map(value => 
            value > 90 ? 'rgb(255, 99, 132)' :
            value > 70 ? 'rgb(255, 159, 64)' :
            'rgb(75, 192, 192)'
          ),
          borderWidth: 1
        }
      ]
    };

    return (
      <Bar
        data={chartData}
        options={{
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: {
              beginAtZero: true,
              max: 100,
              title: {
                display: true,
                text: 'Usage (%)'
              }
            }
          }
        }}
      />
    );
  };

  const renderConnectivity = () => {
    return (
      <div className="connectivity-status">
        <Badge bg={socketStatus.connected ? 'success' : 'danger'}>
          {socketStatus.connected ? 'Connected' : 'Disconnected'}
        </Badge>
        {socketStatus.connected && (
          <Badge bg={isProfiling ? 'warning' : 'secondary'} className="ms-2">
            {isProfiling ? 'Profiling Active' : 'Profiling Inactive'}
          </Badge>
        )}
      </div>
    );
  };

  const renderSystemInfo = () => {
    if (!cpuData || !cpuData.system_stats) {
      return <div className="text-center">No system information available</div>;
    }

    const stats = cpuData.system_stats;
    
    return (
      <Table bordered size="sm">
        <tbody>
          {stats.load_avg && (
            <tr>
              <td><strong>Load Average</strong></td>
              <td>{stats.load_avg.map(val => val.toFixed(2)).join(', ')}</td>
            </tr>
          )}
          {stats.context_switches !== undefined && (
            <tr>
              <td><strong>Context Switches</strong></td>
              <td>{stats.context_switches.toLocaleString()}</td>
            </tr>
          )}
          {stats.interrupts !== undefined && (
            <tr>
              <td><strong>Interrupts</strong></td>
              <td>{stats.interrupts.toLocaleString()}</td>
            </tr>
          )}
          {stats.syscalls !== undefined && (
            <tr>
              <td><strong>System Calls</strong></td>
              <td>{stats.syscalls.toLocaleString()}</td>
            </tr>
          )}
        </tbody>
      </Table>
    );
  };

  if (loading && !cpuData) {
    return (
      <div className="text-center p-5">
        <Spinner animation="border" role="status">
          <span className="visually-hidden">Loading...</span>
        </Spinner>
        <p className="mt-2">Loading CPU profiling data...</p>
      </div>
    );
  }

  return (
    <div className="profiler-dashboard cpu-profiler">
      <div className="d-flex justify-content-between align-items-center mb-3">
        <h2>CPU Profiler</h2>
        {renderConnectivity()}
      </div>

      {error && (
        <Alert variant="danger" onClose={() => setError(null)} dismissible>
          {error}
        </Alert>
      )}

      <div className="dashboard-controls mb-3">
        <Button 
          variant="primary" 
          onClick={handleTakeSnapshot}
          disabled={loading}
          className="me-2"
        >
          Take Snapshot
        </Button>
        <Button 
          variant="secondary" 
          onClick={handleSetBaseline}
          disabled={loading}
          className="me-2"
        >
          Set Baseline
        </Button>
        {isProfiling ? (
          <Button 
            variant="danger" 
            onClick={handleStopProfiling}
            disabled={loading}
            className="me-2"
          >
            Stop Profiling
          </Button>
        ) : (
          <Button 
            variant="success" 
            onClick={handleStartProfiling}
            disabled={loading}
            className="me-2"
          >
            Start Profiling
          </Button>
        )}
        <Button 
          variant="info" 
          onClick={handleRequestAnalysis}
          disabled={loading}
          className="me-2"
        >
          Analyze
        </Button>
      </div>

      <div className="dashboard-summary mb-3">
        <Card className="mb-3">
          <Card.Body>
            <div className="d-flex justify-content-between">
              <div>
                <h5>Current CPU Usage</h5>
                <h2>{snapshot ? `${snapshot.process_cpu_percent.toFixed(1)}%` : 'N/A'}</h2>
                <div className="text-muted">
                  Process CPU / {snapshot ? `${snapshot.total_cpu_percent.toFixed(1)}%` : 'N/A'} Total
                </div>
              </div>
              {renderHealthScore()}
            </div>
          </Card.Body>
        </Card>
      </div>

      <Tabs
        activeKey={activeTab}
        onSelect={(k) => setActiveTab(k)}
        className="mb-3"
      >
        <Tab eventKey="overview" title="Overview">
          <div className="tab-content">
            <div className="chart-container" style={{ height: '300px' }}>
              {renderCpuChart()}
            </div>
            {cpuData && cpuData.baseline && (
              <div className="baseline-info mt-3">
                <h5>Baseline Comparison</h5>
                <div>
                  <strong>Baseline:</strong> {cpuData.baseline.cpu_percent.toFixed(1)}% at {new Date(cpuData.baseline.timestamp).toLocaleString()}
                </div>
                <div>
                  <strong>Difference:</strong> 
                  <span className={cpuData.baseline_diff > 0 ? 'text-danger' : 'text-success'}>
                    {cpuData.baseline_diff > 0 ? '+' : ''}{cpuData.baseline_diff.toFixed(1)}%
                  </span>
                </div>
              </div>
            )}
          </div>
        </Tab>
        <Tab eventKey="cores" title="Core Distribution">
          <div className="tab-content">
            <div className="chart-container" style={{ height: '300px' }}>
              {renderCoreUsage()}
            </div>
          </div>
        </Tab>
        <Tab eventKey="hotspots" title="Hotspots">
          <div className="tab-content">
            <div className="mb-3">
              <Button 
                variant="outline-secondary" 
                size="sm"
                onClick={handleRequestHotspots}
                disabled={!socketRef.current || !socketRef.current.isConnected}
              >
                Refresh Hotspots
              </Button>
            </div>
            {renderHotspots()}
          </div>
        </Tab>
        <Tab eventKey="system" title="System Info">
          <div className="tab-content">
            {renderSystemInfo()}
          </div>
        </Tab>
      </Tabs>

      {loading && (
        <div className="loading-overlay">
          <Spinner animation="border" role="status">
            <span className="visually-hidden">Loading...</span>
          </Spinner>
        </div>
      )}
    </div>
  );
};

export default CpuProfilerDashboard; 