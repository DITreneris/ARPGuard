import axios from 'axios';
import { API_BASE_URL } from '../config';

// Memory profiling API
export const getMemorySnapshots = async (limit = 10) => {
  const response = await axios.get(`${API_BASE_URL}/api/profiling/memory/snapshots?limit=${limit}`);
  return response.data;
};

export const getMemorySnapshot = async (snapshotId) => {
  const response = await axios.get(`${API_BASE_URL}/api/profiling/memory/snapshots/${snapshotId}`);
  return response.data;
};

export const takeMemorySnapshot = async (label = null) => {
  const response = await axios.post(`${API_BASE_URL}/api/profiling/memory/snapshot`, 
    label ? { label } : {});
  return response.data;
};

export const analyzeMemory = async () => {
  const response = await axios.get(`${API_BASE_URL}/api/profiling/memory/analysis`);
  return response.data;
};

export const clearMemorySnapshots = async () => {
  const response = await axios.post(`${API_BASE_URL}/api/profiling/memory/clear`);
  return response.data;
};

export const forceGarbageCollection = async () => {
  const response = await axios.post(`${API_BASE_URL}/api/profiling/memory/gc`);
  return response.data;
};

// CPU profiling API
export const getCpuSnapshots = async (limit = 10) => {
  const response = await axios.get(`${API_BASE_URL}/api/profiling/cpu/snapshots?limit=${limit}`);
  return response.data;
};

export const getCpuSnapshot = async (snapshotId) => {
  const response = await axios.get(`${API_BASE_URL}/api/profiling/cpu/snapshots/${snapshotId}`);
  return response.data;
};

export const takeCpuSnapshot = async (label = null) => {
  const response = await axios.post(`${API_BASE_URL}/api/profiling/cpu/snapshot`, 
    label ? { label } : {});
  return response.data;
};

export const analyzeCpu = async () => {
  const response = await axios.get(`${API_BASE_URL}/api/profiling/cpu/analysis`);
  return response.data;
};

export const clearCpuSnapshots = async () => {
  const response = await axios.post(`${API_BASE_URL}/api/profiling/cpu/clear`);
  return response.data;
};

export const startCpuProfiling = async () => {
  const response = await axios.post(`${API_BASE_URL}/api/profiling/cpu/start-profiling`);
  return response.data;
};

export const stopCpuProfiling = async () => {
  const response = await axios.post(`${API_BASE_URL}/api/profiling/cpu/stop-profiling`);
  return response.data;
};

export const setCpuBaseline = async (snapshotId = null) => {
  const response = await axios.post(`${API_BASE_URL}/api/profiling/cpu/set-baseline`, 
    snapshotId ? { snapshot_id: snapshotId } : {});
  return response.data;
};

// WebSocket for real-time profiling
export class CpuProfilerSocket {
  constructor(onSnapshot, onAnalysis, onHotspots, onHealthScore, onStatus) {
    this.socket = null;
    this.isConnected = false;
    this.onSnapshot = onSnapshot;
    this.onAnalysis = onAnalysis;
    this.onHotspots = onHotspots;
    this.onHealthScore = onHealthScore;
    this.onStatus = onStatus;
    this.reconnectTimeout = null;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectDelay = 2000; // Start with 2 seconds
  }

  connect() {
    if (this.socket) {
      this.disconnect();
    }

    try {
      this.socket = new WebSocket(`${API_BASE_URL.replace('http', 'ws')}/api/profiling/ws/cpu`);
      
      this.socket.onopen = () => {
        this.isConnected = true;
        this.reconnectAttempts = 0;
        if (this.onStatus) {
          this.onStatus({ connected: true });
        }
        console.log('CPU profiler WebSocket connected');
      };
      
      this.socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          this.handleMessage(data);
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
        }
      };
      
      this.socket.onclose = (event) => {
        this.isConnected = false;
        if (this.onStatus) {
          this.onStatus({ connected: false });
        }
        console.log('CPU profiler WebSocket disconnected');
        
        // Only try to reconnect if we haven't exceeded max attempts
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
          this.scheduleReconnect();
        }
      };
      
      this.socket.onerror = (error) => {
        console.error('CPU profiler WebSocket error:', error);
        if (this.onStatus) {
          this.onStatus({ connected: false, error: true });
        }
      };
    } catch (error) {
      console.error('Error connecting to CPU profiler WebSocket:', error);
    }
  }
  
  scheduleReconnect() {
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
    }
    
    // Exponential backoff
    const delay = this.reconnectDelay * Math.pow(1.5, this.reconnectAttempts);
    
    this.reconnectTimeout = setTimeout(() => {
      this.reconnectAttempts++;
      console.log(`Attempting to reconnect CPU profiler WebSocket (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
      this.connect();
    }, delay);
  }

  disconnect() {
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    
    this.isConnected = false;
  }

  handleMessage(data) {
    const { type, data: messageData } = data;
    
    switch (type) {
      case 'snapshot':
        if (this.onSnapshot) {
          this.onSnapshot(messageData);
        }
        break;
      
      case 'analysis':
        if (this.onAnalysis) {
          this.onAnalysis(messageData);
        }
        break;
      
      case 'hotspots':
        if (this.onHotspots) {
          this.onHotspots(messageData.hotspots);
        }
        break;
      
      case 'health':
        if (this.onHealthScore) {
          this.onHealthScore(messageData.health_score);
        }
        break;
      
      case 'profiling_status':
      case 'profiling_results':
        if (this.onStatus) {
          this.onStatus({
            connected: true,
            profiling: messageData.is_profiling,
            status: messageData.status,
            ...(messageData.hotspots && { hotspots: messageData.hotspots })
          });
        }
        break;
      
      case 'pong':
        // Just a heartbeat response
        break;
      
      default:
        console.warn('Unknown CPU profiler WebSocket message type:', type);
    }
  }

  requestSnapshot(label = null) {
    if (!this.isConnected) {
      return false;
    }
    
    this.socket.send(JSON.stringify({
      command: 'snapshot',
      label
    }));
    
    return true;
  }

  requestAnalysis() {
    if (!this.isConnected) {
      return false;
    }
    
    this.socket.send(JSON.stringify({
      command: 'analyze'
    }));
    
    return true;
  }

  requestHotspots() {
    if (!this.isConnected) {
      return false;
    }
    
    this.socket.send(JSON.stringify({
      command: 'hotspots'
    }));
    
    return true;
  }

  startProfiling() {
    if (!this.isConnected) {
      return false;
    }
    
    this.socket.send(JSON.stringify({
      command: 'start_profiling'
    }));
    
    return true;
  }

  stopProfiling() {
    if (!this.isConnected) {
      return false;
    }
    
    this.socket.send(JSON.stringify({
      command: 'stop_profiling'
    }));
    
    return true;
  }

  ping() {
    if (!this.isConnected) {
      return false;
    }
    
    this.socket.send(JSON.stringify({
      command: 'ping',
      timestamp: new Date().toISOString()
    }));
    
    return true;
  }
} 