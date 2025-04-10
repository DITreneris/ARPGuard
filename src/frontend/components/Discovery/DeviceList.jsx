import React, { useState } from 'react';
import {
  Box,
  Chip,
  IconButton,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  TextField,
  Tooltip,
  Typography
} from '@mui/material';
import InfoIcon from '@mui/icons-material/Info';
import WifiIcon from '@mui/icons-material/Wifi';
import RouterIcon from '@mui/icons-material/Router';
import ComputerIcon from '@mui/icons-material/Computer';
import SmartphoneIcon from '@mui/icons-material/Smartphone';
import PrintIcon from '@mui/icons-material/Print';
import DevicesIcon from '@mui/icons-material/Devices';
import HelpIcon from '@mui/icons-material/Help';

import './DeviceList.css';

/**
 * DeviceList Component
 * 
 * Displays a list of discovered network devices with pagination,
 * filtering, and sorting capabilities.
 */
const DeviceList = ({ devices = [], total = 0, scanTime = null }) => {
  // State for pagination
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [searchTerm, setSearchTerm] = useState('');
  
  // Format timestamp
  const formatTime = (timestamp) => {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  // Filter devices based on search term
  const filteredDevices = devices.filter(device => {
    const term = searchTerm.toLowerCase();
    return (
      device.ip?.toLowerCase().includes(term) ||
      device.mac?.toLowerCase().includes(term) ||
      device.hostname?.toLowerCase().includes(term) ||
      device.vendor?.toLowerCase().includes(term) ||
      device.device_type?.toLowerCase().includes(term)
    );
  });
  
  // Handle page change
  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };
  
  // Handle rows per page change
  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };
  
  // Get device icon based on type
  const getDeviceIcon = (device) => {
    if (device.is_gateway) {
      return <RouterIcon fontSize="small" style={{ color: '#2196f3' }} />;
    }
    
    switch (device.device_type?.toLowerCase()) {
      case 'computer':
        return <ComputerIcon fontSize="small" />;
      case 'mobile':
        return <SmartphoneIcon fontSize="small" />;
      case 'printer':
        return <PrintIcon fontSize="small" />;
      case 'iot':
        return <DevicesIcon fontSize="small" />;
      case 'router':
        return <RouterIcon fontSize="small" />;
      case 'wifi':
        return <WifiIcon fontSize="small" />;
      default:
        return <HelpIcon fontSize="small" />;
    }
  };
  
  // Get row style based on device status or type
  const getRowStyle = (device) => {
    if (device.is_gateway) {
      return { backgroundColor: 'rgba(33, 150, 243, 0.08)' };
    }
    return {};
  };

  return (
    <Box className="device-list">
      <Box className="device-list-header">
        <Typography variant="subtitle1">
          {total} {total === 1 ? 'Device' : 'Devices'} 
          {scanTime && (
            <Typography component="span" variant="body2" color="textSecondary" ml={1}>
              (Last scan: {formatTime(scanTime)})
            </Typography>
          )}
        </Typography>
        
        <TextField
          size="small"
          placeholder="Filter devices..."
          variant="outlined"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="search-field"
        />
      </Box>
      
      <TableContainer component={Paper} className="device-table-container">
        <Table size="small" aria-label="devices table">
          <TableHead>
            <TableRow>
              <TableCell width="40px"></TableCell>
              <TableCell>IP Address</TableCell>
              <TableCell>MAC Address</TableCell>
              <TableCell>Hostname</TableCell>
              <TableCell>Vendor</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>Last Seen</TableCell>
              <TableCell width="50px"></TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredDevices.length > 0 ? (
              filteredDevices
                .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                .map((device, index) => (
                  <TableRow 
                    key={device.ip || index} 
                    hover
                    style={getRowStyle(device)}
                  >
                    <TableCell>{getDeviceIcon(device)}</TableCell>
                    <TableCell>{device.ip}</TableCell>
                    <TableCell>{device.mac}</TableCell>
                    <TableCell>{device.hostname || '-'}</TableCell>
                    <TableCell>{device.vendor || '-'}</TableCell>
                    <TableCell>
                      {device.is_gateway ? (
                        <Chip size="small" label="Gateway" color="primary" />
                      ) : (
                        device.device_type || 'Unknown'
                      )}
                    </TableCell>
                    <TableCell>{formatTime(device.last_seen)}</TableCell>
                    <TableCell>
                      <Tooltip title="View Details">
                        <IconButton size="small">
                          <InfoIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))
            ) : (
              <TableRow>
                <TableCell colSpan={8} align="center" sx={{ py: 3 }}>
                  {devices.length === 0 ? (
                    <Typography color="textSecondary">
                      No devices discovered yet. Start a network scan to discover devices.
                    </Typography>
                  ) : (
                    <Typography color="textSecondary">
                      No devices match your filter criteria.
                    </Typography>
                  )}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
      
      <TablePagination
        rowsPerPageOptions={[5, 10, 25, 50]}
        component="div"
        count={filteredDevices.length}
        rowsPerPage={rowsPerPage}
        page={page}
        onPageChange={handleChangePage}
        onRowsPerPageChange={handleChangeRowsPerPage}
      />
    </Box>
  );
};

export default DeviceList; 