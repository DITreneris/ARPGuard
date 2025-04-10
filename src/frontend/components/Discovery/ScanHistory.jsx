import React from 'react';
import {
  Box,
  Button,
  Card,
  CardActionArea,
  CardContent,
  Divider,
  Grid,
  Typography
} from '@mui/material';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import DevicesIcon from '@mui/icons-material/Devices';
import NetworkCheckIcon from '@mui/icons-material/NetworkCheck';

import './ScanHistory.css';

/**
 * ScanHistory Component
 * 
 * Displays a history of previous network scans with their results
 * and allows loading results from a specific scan.
 */
const ScanHistory = ({ history = [], onSelectScan }) => {
  // Format timestamp
  const formatTime = (timestamp) => {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp);
    return date.toLocaleString();
  };
  
  // Calculate time ago
  const getTimeAgo = (timestamp) => {
    if (!timestamp) return '';
    
    const now = new Date();
    const scanTime = new Date(timestamp);
    const diffMs = now - scanTime;
    
    // Convert to seconds, minutes, hours, days
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHours = Math.floor(diffMin / 60);
    const diffDays = Math.floor(diffHours / 24);
    
    if (diffDays > 0) {
      return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    } else if (diffHours > 0) {
      return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    } else if (diffMin > 0) {
      return `${diffMin} minute${diffMin > 1 ? 's' : ''} ago`;
    } else {
      return 'Just now';
    }
  };
  
  // Get status color
  const getStatusColor = (status) => {
    switch (status) {
      case 'completed':
        return '#4caf50';
      case 'cancelled':
        return '#ff9800';
      case 'failed':
        return '#f44336';
      default:
        return '#9e9e9e';
    }
  };

  return (
    <Box className="scan-history">
      {history && history.length > 0 ? (
        <Grid container spacing={2}>
          {history.map((scan) => (
            <Grid item xs={12} sm={6} md={4} key={scan.scan_id}>
              <Card 
                className="scan-card"
                variant="outlined"
                sx={{ 
                  borderLeft: `4px solid ${getStatusColor(scan.status)}`,
                  transition: 'all 0.2s ease-in-out',
                  '&:hover': {
                    boxShadow: '0 4px 12px rgba(0,0,0,0.1)'
                  }
                }}
              >
                <CardActionArea onClick={() => onSelectScan(scan.scan_id)}>
                  <CardContent>
                    <Box className="scan-header">
                      <Typography variant="subtitle1" component="div" fontWeight="500">
                        Scan {scan.scan_id.split('_')[1]}
                      </Typography>
                      <Typography variant="caption" color="textSecondary">
                        {getTimeAgo(scan.timestamp)}
                      </Typography>
                    </Box>
                    
                    <Divider sx={{ my: 1 }} />
                    
                    <Box className="scan-details">
                      <Box className="scan-detail-item">
                        <AccessTimeIcon fontSize="small" color="action" />
                        <Typography variant="body2">
                          {formatTime(scan.timestamp)}
                        </Typography>
                      </Box>
                      
                      <Box className="scan-detail-item">
                        <DevicesIcon fontSize="small" color="action" />
                        <Typography variant="body2">
                          {scan.device_count} {scan.device_count === 1 ? 'Device' : 'Devices'}
                        </Typography>
                      </Box>
                      
                      <Box className="scan-detail-item">
                        <NetworkCheckIcon fontSize="small" color="action" />
                        <Typography variant="body2" sx={{ 
                          textTransform: 'capitalize',
                          color: getStatusColor(scan.status)
                        }}>
                          {scan.status}
                        </Typography>
                      </Box>
                    </Box>
                    
                    {scan.subnet && (
                      <Typography variant="body2" color="textSecondary" mt={1}>
                        Subnet: {scan.subnet}
                      </Typography>
                    )}
                  </CardContent>
                </CardActionArea>
              </Card>
            </Grid>
          ))}
        </Grid>
      ) : (
        <Box className="empty-history" textAlign="center" py={4}>
          <DevicesIcon sx={{ fontSize: 48, color: 'text.secondary', opacity: 0.5 }} />
          <Typography variant="subtitle1" mt={2} color="textSecondary">
            No scan history available
          </Typography>
          <Typography variant="body2" color="textSecondary">
            Start a network scan to discover devices and build scan history.
          </Typography>
        </Box>
      )}
    </Box>
  );
};

export default ScanHistory; 