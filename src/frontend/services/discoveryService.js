/**
 * Network Discovery Service
 * Handles automated discovery of devices on the network
 */
import { EventEmitter } from 'events';
import api from './api';

class DiscoveryService extends EventEmitter {
  constructor() {
    super();
    this.devices = [];
    this.isScanning = false;
    this.lastScanTime = null;
    this.scanInterval = null;
    this.scheduledScans = [];
    this.activeScan = null;
    this.API_BASE_URL = '/api/discovery';
  }

  /**
   * Start a network discovery scan with the provided options
   * @param {Object} options - Scan options
   * @param {string} options.ipRange - IP range to scan (e.g., "192.168.1.0/24")
   * @param {number} options.timeout - Scan timeout in milliseconds
   * @param {boolean} options.deepScan - Whether to perform a deep scan
   * @param {boolean} options.scanPorts - Whether to scan for open ports
   * @returns {Promise<Object>} - Promise resolving to the scan ID
   */
  async startScan(options) {
    try {
      const response = await api.post(`${this.API_BASE_URL}/scan`, options);
      
      this.isScanning = true;
      this.activeScan = {
        id: response.data.scanId,
        progress: 0,
        startTime: new Date(),
        options,
        status: 'running'
      };
      
      // Simulate progress updates (in a real implementation, this would come from WebSocket)
      this._simulateProgressUpdates(response.data.scanId);
      
      this.emit('scanStarted', this.activeScan);
      
      return response.data;
    } catch (error) {
      this.emit('error', { 
        message: 'Failed to start network scan', 
        details: error.message 
      });
      throw error;
    }
  }
  
  /**
   * Cancel an active scan
   * @param {string} scanId - ID of the scan to cancel
   * @returns {Promise<Object>} - Promise resolving to the result
   */
  async cancelScan(scanId) {
    try {
      const response = await api.post(`${this.API_BASE_URL}/scan/${scanId}/cancel`);
      
      if (this.activeScan && this.activeScan.id === scanId) {
        this.activeScan.status = 'cancelled';
        this.isScanning = false;
        this.emit('scanCancelled', this.activeScan);
        this.activeScan = null;
      }
      
      return response.data;
    } catch (error) {
      this.emit('error', { 
        message: 'Failed to cancel scan', 
        details: error.message 
      });
      throw error;
    }
  }
  
  /**
   * Schedule a recurring scan
   * @param {Object} schedule - Schedule configuration
   * @param {string} schedule.frequency - Frequency of the scan ('hourly', 'daily', 'weekly')
   * @param {Object} schedule.options - Scan options for the scheduled scan
   * @returns {Promise<Object>} - Promise resolving to the schedule ID
   */
  async scheduleRecurringScan(schedule) {
    try {
      const response = await api.post(`${this.API_BASE_URL}/schedule`, schedule);
      
      const newSchedule = {
        id: response.data.scheduleId,
        frequency: schedule.frequency,
        options: schedule.options,
        enabled: true,
        createdAt: new Date(),
        intervalId: null
      };
      
      this.scheduledScans.push(newSchedule);
      this.setupScanSchedule(newSchedule);
      this.emit('scheduleAdded', newSchedule);
      
      return response.data;
    } catch (error) {
      this.emit('error', { 
        message: 'Failed to schedule scan', 
        details: error.message 
      });
      throw error;
    }
  }
  
  /**
   * Set up timer for scheduled scan
   * @param {Object} scheduledScan - Scheduled scan configuration
   * @private
   */
  setupScanSchedule(scheduledScan) {
    let intervalMs;
    
    switch (scheduledScan.frequency) {
      case 'hourly':
        intervalMs = 60 * 60 * 1000;
        break;
      case 'daily':
        intervalMs = 24 * 60 * 60 * 1000;
        break;
      case 'weekly':
        intervalMs = 7 * 24 * 60 * 60 * 1000;
        break;
      default:
        intervalMs = 24 * 60 * 60 * 1000; // Default to daily
    }
    
    // Create interval
    const intervalId = setInterval(() => {
      if (scheduledScan.enabled) {
        this.startScan(scheduledScan.options);
      }
    }, intervalMs);
    
    // Store interval ID for cleanup
    scheduledScan.intervalId = intervalId;
  }
  
  /**
   * Update a scheduled scan
   * @param {string} scheduleId - ID of the schedule to update
   * @param {Object} updates - Updates to apply
   * @returns {Promise<Object>} - Promise resolving to the updated schedule
   */
  async updateSchedule(scheduleId, updates) {
    try {
      const response = await api.put(`${this.API_BASE_URL}/schedule/${scheduleId}`, updates);
      
      const scheduleIndex = this.scheduledScans.findIndex(s => s.id === scheduleId);
      if (scheduleIndex !== -1) {
        const oldSchedule = this.scheduledScans[scheduleIndex];
        
        // If interval needs to be reset (frequency changed)
        if (updates.frequency && updates.frequency !== oldSchedule.frequency && oldSchedule.intervalId) {
          clearInterval(oldSchedule.intervalId);
          oldSchedule.intervalId = null;
        }
        
        this.scheduledScans[scheduleIndex] = {
          ...oldSchedule,
          ...updates
        };
        
        // Setup new schedule if needed
        if (!this.scheduledScans[scheduleIndex].intervalId) {
          this.setupScanSchedule(this.scheduledScans[scheduleIndex]);
        }
        
        this.emit('scheduleUpdated', this.scheduledScans[scheduleIndex]);
      }
      
      return response.data;
    } catch (error) {
      this.emit('error', { 
        message: 'Failed to update schedule', 
        details: error.message 
      });
      throw error;
    }
  }
  
  /**
   * Enable or disable a scheduled scan
   * @param {string} scheduleId - ID of the scheduled scan
   * @param {boolean} enabled - Whether to enable or disable
   * @returns {Promise<Object>} - Promise resolving to the updated schedule
   */
  async toggleScheduledScan(scheduleId, enabled) {
    return this.updateSchedule(scheduleId, { enabled });
  }
  
  /**
   * Delete a scheduled scan
   * @param {string} scheduleId - ID of the schedule to delete
   * @returns {Promise<Object>} - Promise resolving to the result
   */
  async deleteSchedule(scheduleId) {
    try {
      const response = await api.delete(`${this.API_BASE_URL}/schedule/${scheduleId}`);
      
      const scheduleIndex = this.scheduledScans.findIndex(s => s.id === scheduleId);
      if (scheduleIndex !== -1) {
        const scheduledScan = this.scheduledScans[scheduleIndex];
        
        // Clear interval
        if (scheduledScan.intervalId) {
          clearInterval(scheduledScan.intervalId);
        }
        
        this.scheduledScans.splice(scheduleIndex, 1);
        this.emit('scheduleDeleted', scheduledScan);
      }
      
      return response.data;
    } catch (error) {
      this.emit('error', { 
        message: 'Failed to delete schedule', 
        details: error.message 
      });
      throw error;
    }
  }
  
  /**
   * Get all scheduled scans
   * @returns {Promise<Array>} - Promise resolving to an array of scheduled scans
   */
  async getScheduledScans() {
    try {
      const response = await api.get(`${this.API_BASE_URL}/schedules`);
      this.scheduledScans = response.data;
      return response.data;
    } catch (error) {
      this.emit('error', { 
        message: 'Failed to fetch scheduled scans', 
        details: error.message 
      });
      throw error;
    }
  }
  
  /**
   * Get all discovered devices
   * @returns {Promise<Array>} - Promise resolving to an array of discovered devices
   */
  async getDiscoveredDevices() {
    try {
      const response = await api.get(`${this.API_BASE_URL}/devices`);
      this.devices = response.data;
      return response.data;
    } catch (error) {
      this.emit('error', { 
        message: 'Failed to fetch discovered devices', 
        details: error.message 
      });
      throw error;
    }
  }
  
  /**
   * Get detailed information about a specific device
   * @param {string} deviceId - ID of the device
   * @returns {Promise<Object>} - Promise resolving to the device details
   */
  async getDeviceDetails(deviceId) {
    try {
      const response = await api.get(`${this.API_BASE_URL}/device/${deviceId}`);
      return response.data;
    } catch (error) {
      this.emit('error', { 
        message: 'Failed to fetch device details', 
        details: error.message 
      });
      throw error;
    }
  }
  
  /**
   * Check if a scan is currently in progress
   * @returns {boolean} Whether a scan is in progress
   */
  isScanInProgress() {
    return this.isScanning;
  }

  /**
   * Get the last scan time
   * @returns {Date|null} Last scan time or null if no scan has been performed
   */
  getLastScanTime() {
    return this.lastScanTime;
  }
  
  /**
   * Simulate progress updates for a scan (for development/testing)
   * In a real implementation, this would be replaced by WebSocket events from the backend
   * @param {string} scanId - ID of the scan to simulate progress for
   * @private
   */
  _simulateProgressUpdates(scanId) {
    let progress = 0;
    
    // Generate a random scan duration between 10-20 seconds
    const totalDuration = 10000 + Math.random() * 10000;
    const updateInterval = totalDuration / 20; // 20 updates
    
    const interval = setInterval(() => {
      if (!this.activeScan || this.activeScan.id !== scanId || this.activeScan.status === 'cancelled') {
        clearInterval(interval);
        return;
      }
      
      progress += 5;
      if (progress > 100) {
        progress = 100;
        
        // Final progress update
        this.activeScan.progress = progress;
        this.emit('scanProgress', { 
          scanId, 
          progress, 
          message: 'Scan completed successfully' 
        });
        
        // Simulate found devices (between 5-15 devices)
        const deviceCount = 5 + Math.floor(Math.random() * 10);
        const devices = this._generateMockDevices(deviceCount);
        
        // Complete the scan
        setTimeout(() => {
          this.lastScanTime = new Date();
          this.isScanning = false;
          
          this.emit('scanCompleted', {
            scanId,
            devices,
            duration: (new Date() - this.activeScan.startTime) / 1000,
            deviceCount
          });
          
          this.activeScan = null;
        }, 500);
        
        clearInterval(interval);
      } else {
        // Regular progress update
        this.activeScan.progress = progress;
        
        let message;
        if (progress < 20) {
          message = 'Initializing scan...';
        } else if (progress < 40) {
          message = 'Discovering network devices...';
        } else if (progress < 60) {
          message = 'Identifying device types...';
        } else if (progress < 80) {
          message = 'Checking for vulnerabilities...';
        } else {
          message = 'Finalizing results...';
        }
        
        this.emit('scanProgress', { scanId, progress, message });
      }
    }, updateInterval);
  }
  
  /**
   * Generate mock devices for development/testing
   * @param {number} count - Number of devices to generate
   * @returns {Array} - Array of mock device objects
   * @private
   */
  _generateMockDevices(count) {
    const deviceTypes = ['router', 'switch', 'computer', 'phone', 'iot', 'printer', 'server'];
    const vendors = ['Cisco', 'HP', 'Dell', 'Apple', 'Samsung', 'Juniper', 'Netgear', 'D-Link'];
    const statuses = ['online', 'offline', 'vulnerable'];
    
    const devices = [];
    
    for (let i = 0; i < count; i++) {
      const type = deviceTypes[Math.floor(Math.random() * deviceTypes.length)];
      const vendor = vendors[Math.floor(Math.random() * vendors.length)];
      const status = statuses[Math.floor(Math.random() * statuses.length)];
      
      // Generate a random IP in the 192.168.1.x range
      const ip = `192.168.1.${Math.floor(Math.random() * 254) + 1}`;
      
      devices.push({
        id: `device-${i+1}`,
        ip,
        mac: this._generateRandomMac(),
        hostname: `${type}-${i+1}.local`,
        type,
        vendor,
        status,
        lastSeen: new Date().toISOString(),
        ports: this._generateRandomPorts(type),
        osInfo: this._generateOsInfo(type),
        vulnerabilities: status === 'vulnerable' ? this._generateVulnerabilities() : []
      });
    }
    
    return devices;
  }
  
  /**
   * Generate a random MAC address
   * @returns {string} - A random MAC address
   * @private
   */
  _generateRandomMac() {
    const hexDigits = '0123456789ABCDEF';
    let mac = '';
    
    for (let i = 0; i < 6; i++) {
      const byte = hexDigits[Math.floor(Math.random() * 16)] + hexDigits[Math.floor(Math.random() * 16)];
      mac += i < 5 ? byte + ':' : byte;
    }
    
    return mac;
  }
  
  /**
   * Generate random open ports based on device type
   * @param {string} deviceType - Type of device
   * @returns {Array} - Array of open port objects
   * @private
   */
  _generateRandomPorts(deviceType) {
    const ports = [];
    
    // Common ports by device type
    const commonPorts = {
      router: [80, 443, 22, 23],
      switch: [80, 443, 22, 23],
      server: [80, 443, 22, 21, 25, 3306],
      computer: [135, 139, 445],
      phone: [5060, 5061],
      printer: [9100, 515, 631],
      iot: [1883, 8883, 8080]
    };
    
    // Add common ports for this device type
    const devicePorts = commonPorts[deviceType] || [80, 443];
    for (const port of devicePorts) {
      if (Math.random() > 0.3) { // 70% chance the port is open
        ports.push({
          port,
          protocol: port === 22 ? 'ssh' : 
                   port === 80 ? 'http' : 
                   port === 443 ? 'https' : 
                   port === 23 ? 'telnet' : 
                   port === 21 ? 'ftp' : 'unknown',
          status: 'open'
        });
      }
    }
    
    return ports;
  }
  
  /**
   * Generate OS information based on device type
   * @param {string} deviceType - Type of device
   * @returns {Object} - OS information
   * @private
   */
  _generateOsInfo(deviceType) {
    const osOptions = {
      router: ['Cisco IOS', 'DD-WRT', 'Tomato', 'pfSense'],
      switch: ['Cisco IOS', 'Juniper Junos', 'HP ProCurve'],
      server: ['Windows Server 2019', 'Ubuntu Server 20.04', 'CentOS 8', 'Red Hat Enterprise Linux 8'],
      computer: ['Windows 10', 'macOS 11.0', 'Ubuntu 20.04', 'Fedora 34'],
      phone: ['Android 11', 'iOS 14.5'],
      printer: ['HP PrintOS', 'Canon UFRII', 'Brother Embedded'],
      iot: ['Embedded Linux', 'RTOS', 'Custom Firmware']
    };
    
    const options = osOptions[deviceType] || ['Unknown'];
    const os = options[Math.floor(Math.random() * options.length)];
    
    return {
      name: os,
      version: `${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 10)}`,
      architecture: Math.random() > 0.5 ? 'x64' : 'ARM'
    };
  }
  
  /**
   * Generate random vulnerabilities
   * @returns {Array} - Array of vulnerability objects
   * @private
   */
  _generateVulnerabilities() {
    const vulnerabilityCount = Math.floor(Math.random() * 3) + 1; // 1-3 vulnerabilities
    const vulnerabilities = [];
    
    const possibleVulnerabilities = [
      {
        id: 'CVE-2021-44228',
        name: 'Log4Shell',
        severity: 'Critical',
        description: 'Remote code execution vulnerability in Apache Log4j'
      },
      {
        id: 'CVE-2020-1472',
        name: 'Zerologon',
        severity: 'Critical',
        description: 'Authentication bypass in Microsoft Windows Netlogon Remote Protocol'
      },
      {
        id: 'CVE-2019-0708',
        name: 'BlueKeep',
        severity: 'Critical',
        description: 'Remote code execution vulnerability in Remote Desktop Services'
      },
      {
        id: 'CVE-2017-0144',
        name: 'EternalBlue',
        severity: 'Critical',
        description: 'SMB remote code execution vulnerability'
      },
      {
        id: 'CVE-2018-13379',
        name: 'FortiOS SSL VPN',
        severity: 'High',
        description: 'Path traversal in Fortinet FortiOS'
      },
      {
        id: 'CVE-2021-34527',
        name: 'PrintNightmare',
        severity: 'Critical',
        description: 'Windows Print Spooler remote code execution vulnerability'
      },
      {
        id: 'CVE-2021-26855',
        name: 'ProxyLogon',
        severity: 'Critical',
        description: 'Microsoft Exchange Server remote code execution vulnerability'
      }
    ];
    
    // Select random vulnerabilities
    const indices = new Set();
    while (indices.size < vulnerabilityCount) {
      indices.add(Math.floor(Math.random() * possibleVulnerabilities.length));
    }
    
    indices.forEach(index => {
      vulnerabilities.push({
        ...possibleVulnerabilities[index],
        detectedAt: new Date().toISOString()
      });
    });
    
    return vulnerabilities;
  }

  /**
   * Clean up resources
   */
  dispose() {
    // Clear all scheduled scans
    this.scheduledScans.forEach(scan => {
      if (scan.intervalId) {
        clearInterval(scan.intervalId);
      }
    });
    
    this.scheduledScans = [];
    this.removeAllListeners();
  }
}

// Create and export a singleton instance
const discoveryService = new DiscoveryService();
export default discoveryService; 