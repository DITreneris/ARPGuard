import React, { useState, useEffect } from 'react';
import { 
  Box, 
  Button, 
  Card, 
  CircularProgress, 
  Container, 
  Divider, 
  FormControl,
  FormControlLabel,
  Grid, 
  IconButton,
  InputLabel,
  LinearProgress,
  MenuItem,
  Paper, 
  Select,
  Switch,
  TextField, 
  Typography 
} from '@mui/material';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import StopIcon from '@mui/icons-material/Stop';
import RefreshIcon from '@mui/icons-material/Refresh';
import ScheduleIcon from '@mui/icons-material/Schedule';

import './DiscoveryPanel.css';
import DeviceList from './DeviceList';
import ScanHistory from './ScanHistory';
import analyticsWebSocket from '../../services/websocketService';
import { discoveryService } from '../../services/discoveryService';

/**
 * Discovery Panel Component
 * 
 * Main component for network discovery functionality that allows users
 * to initiate scans, view discovered devices, and manage scan schedules.
 */
const DiscoveryPanel = () => {
  // State for scan options
  const [scanOptions, setScanOptions] = useState({
    ipRange: '',
    timeout: 5,
    deepScan: false,
    includeHostnames: true
  });

  // State for scan status and results
  const [activeScan, setActiveScan] = useState(null);
  const [scanResults, setScanResults] = useState([]);
  const [scanHistory, setScanHistory] = useState([]);
  const [isLoadingDevices, setIsLoadingDevices] = useState(false);
  const [webSocketConnected, setWebSocketConnected] = useState(false);
  const [selectedTab, setSelectedTab] = useState('devices');

  // Connect to WebSocket for real-time updates when component mounts
  useEffect(() => {
    const setupWebSocket = async () => {
      try {
        // Connect to WebSocket if not already connected
        if (!analyticsWebSocket.isConnected()) {
          await analyticsWebSocket.connect();
        }
        
        // Subscribe to discovery topic
        analyticsWebSocket.subscribe('discovery');
        
        // Set up event listeners
        analyticsWebSocket.on('scan_update', handleScanUpdate);
        analyticsWebSocket.on('scan_completed', handleScanCompleted);
        analyticsWebSocket.on('scan_cancelled', handleScanCancelled);
        
        // Connection status events
        analyticsWebSocket.on('connected', () => setWebSocketConnected(true));
        analyticsWebSocket.on('disconnected', () => setWebSocketConnected(false));
        
        setWebSocketConnected(analyticsWebSocket.isConnected());
      } catch (error) {
        console.error('Error connecting to WebSocket:', error);
      }
    };
    
    // Load initial data and set up WebSocket
    const loadInitialData = async () => {
      try {
        setIsLoadingDevices(true);
        // Load devices from last scan
        const devices = await discoveryService.getDiscoveredDevices();
        setScanResults(devices);
        
        // Get scan history
        const history = await discoveryService.getScanHistory();
        setScanHistory(history);
      } catch (error) {
        console.error('Error loading discovery data:', error);
      } finally {
        setIsLoadingDevices(false);
      }
    };
    
    setupWebSocket();
    loadInitialData();
    
    // Cleanup on unmount
    return () => {
      analyticsWebSocket.off('scan_update', handleScanUpdate);
      analyticsWebSocket.off('scan_completed', handleScanCompleted);
      analyticsWebSocket.off('scan_cancelled', handleScanCancelled);
      analyticsWebSocket.unsubscribe('discovery');
    };
  }, []);
  
  // WebSocket event handlers
  const handleScanUpdate = (data) => {
    setActiveScan(data);
  };
  
  const handleScanCompleted = async (data) => {
    // Clear active scan
    setActiveScan(null);
    
    // Load the updated device list
    try {
      const devices = await discoveryService.getDiscoveredDevices(data.scan_id);
      setScanResults(devices);
      
      // Update scan history
      const history = await discoveryService.getScanHistory();
      setScanHistory(history);
    } catch (error) {
      console.error('Error loading completed scan data:', error);
    }
  };
  
  const handleScanCancelled = (data) => {
    setActiveScan(null);
  };

  // Handle form input changes
  const handleInputChange = (e) => {
    const { name, value, checked, type } = e.target;
    setScanOptions(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  // Start a new network scan
  const startScan = async () => {
    try {
      const response = await discoveryService.startScan(scanOptions);
      console.log('Scan started:', response);
      // The scan updates will come through WebSocket
    } catch (error) {
      console.error('Failed to start scan:', error);
    }
  };

  // Cancel the current scan
  const cancelScan = async () => {
    if (activeScan) {
      try {
        await discoveryService.cancelScan(activeScan.scan_id);
        console.log('Scan cancelled');
      } catch (error) {
        console.error('Failed to cancel scan:', error);
      }
    }
  };

  // Refresh the device list
  const refreshDevices = async () => {
    try {
      setIsLoadingDevices(true);
      const devices = await discoveryService.getDiscoveredDevices();
      setScanResults(devices);
    } catch (error) {
      console.error('Error refreshing device list:', error);
    } finally {
      setIsLoadingDevices(false);
    }
  };
  
  // Schedule a recurring scan
  const openScheduleDialog = () => {
    // This would be implemented to open a dialog for scheduling scans
    console.log('Schedule dialog would open here');
  };

  return (
    <Container maxWidth="xl" className="discovery-panel">
      <Typography variant="h4" component="h1" gutterBottom>
        Network Discovery
      </Typography>
      
      <Grid container spacing={3}>
        {/* Scan Controls */}
        <Grid item xs={12} md={4}>
          <Paper className="scan-controls-paper">
            <Typography variant="h6" component="h2" gutterBottom>
              Scan Controls
            </Typography>
            
            <form className="scan-form">
              <TextField
                label="IP Range"
                name="ipRange"
                value={scanOptions.ipRange}
                onChange={handleInputChange}
                fullWidth
                margin="normal"
                placeholder="e.g. 192.168.1.0/24 (leave blank for auto-detect)"
                variant="outlined"
              />
              
              <FormControl fullWidth margin="normal">
                <InputLabel>Scan Timeout</InputLabel>
                <Select
                  name="timeout"
                  value={scanOptions.timeout}
                  onChange={handleInputChange}
                  label="Scan Timeout"
                >
                  <MenuItem value={2}>2 seconds (Fastest, may miss devices)</MenuItem>
                  <MenuItem value={5}>5 seconds (Balanced)</MenuItem>
                  <MenuItem value={10}>10 seconds (Thorough)</MenuItem>
                  <MenuItem value={20}>20 seconds (Very thorough)</MenuItem>
                </Select>
              </FormControl>
              
              <Box mt={2}>
                <FormControlLabel
                  control={
                    <Switch
                      name="deepScan"
                      checked={scanOptions.deepScan}
                      onChange={handleInputChange}
                      color="primary"
                    />
                  }
                  label="Deep Scan (Includes port scanning)"
                />
              </Box>
              
              <Box mt={1}>
                <FormControlLabel
                  control={
                    <Switch
                      name="includeHostnames"
                      checked={scanOptions.includeHostnames}
                      onChange={handleInputChange}
                      color="primary"
                    />
                  }
                  label="Resolve Hostnames"
                />
              </Box>
              
              <Box mt={3} className="scan-buttons">
                <Button
                  variant="contained"
                  color="primary"
                  startIcon={<PlayArrowIcon />}
                  onClick={startScan}
                  disabled={!!activeScan}
                  fullWidth
                >
                  Start Scan
                </Button>
                
                <Box display="flex" mt={1} gap={1}>
                  <Button
                    variant="outlined"
                    color="secondary"
                    startIcon={<StopIcon />}
                    onClick={cancelScan}
                    disabled={!activeScan}
                    sx={{ flex: 1 }}
                  >
                    Cancel
                  </Button>
                  
                  <Button
                    variant="outlined"
                    color="primary"
                    startIcon={<ScheduleIcon />}
                    onClick={openScheduleDialog}
                    sx={{ flex: 1 }}
                  >
                    Schedule
                  </Button>
                </Box>
              </Box>
            </form>
            
            {/* Scan Status */}
            {activeScan && (
              <Box mt={3} className="scan-status">
                <Typography variant="subtitle1">
                  Scan in Progress
                </Typography>
                
                <Box display="flex" alignItems="center" mt={1}>
                  <Box width="100%" mr={1}>
                    <LinearProgress 
                      variant="determinate" 
                      value={activeScan.progress || 0} 
                      color="primary"
                    />
                  </Box>
                  <Box minWidth={35}>
                    <Typography variant="body2" color="textSecondary">
                      {Math.round(activeScan.progress || 0)}%
                    </Typography>
                  </Box>
                </Box>
                
                <Typography variant="body2" color="textSecondary" mt={1}>
                  {activeScan.message || 'Scanning network...'}
                </Typography>
                
                <Typography variant="body2" mt={1}>
                  Devices found: {activeScan.device_count || 0}
                </Typography>
              </Box>
            )}
            
            {/* WebSocket Status */}
            <Box mt={3} className="websocket-status">
              <Typography variant="body2" color="textSecondary">
                Real-time updates: 
                <span className={webSocketConnected ? 'status-connected' : 'status-disconnected'}>
                  {webSocketConnected ? ' Connected' : ' Disconnected'}
                </span>
              </Typography>
            </Box>
          </Paper>
        </Grid>
        
        {/* Results Area */}
        <Grid item xs={12} md={8}>
          <Paper className="results-paper">
            <Box className="results-header">
              <Box className="results-tabs">
                <Button 
                  className={selectedTab === 'devices' ? 'tab-active' : ''} 
                  onClick={() => setSelectedTab('devices')}
                >
                  Devices
                </Button>
                <Button 
                  className={selectedTab === 'history' ? 'tab-active' : ''} 
                  onClick={() => setSelectedTab('history')}
                >
                  Scan History
                </Button>
              </Box>
              
              <Box>
                <IconButton onClick={refreshDevices} disabled={isLoadingDevices}>
                  <RefreshIcon />
                </IconButton>
              </Box>
            </Box>
            
            <Divider />
            
            <Box className="results-content">
              {isLoadingDevices ? (
                <Box display="flex" justifyContent="center" alignItems="center" height="200px">
                  <CircularProgress />
                </Box>
              ) : (
                <>
                  {selectedTab === 'devices' && (
                    <DeviceList 
                      devices={scanResults.devices || []} 
                      total={scanResults.total || 0}
                      scanTime={scanResults.scan_time}
                    />
                  )}
                  
                  {selectedTab === 'history' && (
                    <ScanHistory 
                      history={scanHistory} 
                      onSelectScan={(scanId) => {
                        // Logic to load devices from specific scan
                        console.log(`Loading scan: ${scanId}`);
                      }}
                    />
                  )}
                </>
              )}
            </Box>
          </Paper>
        </Grid>
      </Grid>
    </Container>
  );
};

export default DiscoveryPanel; 