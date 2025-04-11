import { EventEmitter } from 'events';
import { inflate, deflate } from 'pako'; // For data compression

/**
 * WebSocket service for real-time analytics and monitoring data
 */
class AnalyticsWebSocket extends EventEmitter {
  constructor() {
    super();
    this.socket = null;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectDelay = 1000;
    this.subscribers = new Map();
    this.isConnected = false;
    this.url = process.env.REACT_APP_WS_URL || 'ws://localhost:8080/analytics';
    this.reconnectInterval = 2000; // Decreased from 5000
    this.maxReconnectInterval = 30000; // Max interval between retries
    this.pingInterval = 15000; // Decreased from 30000
    this.pingTimeout = 5000; // Time to wait for pong
    this.pingTimer = null;
    this.pongTimer = null;
    this.subscriptions = new Set(); // Track active subscriptions
    this.buffer = []; // Message buffer for disconnected state
    this.bufferSize = 100; // Max number of messages to buffer
    this.intentionalClose = false;
    this.useCompression = true; // Enable compression
    this.connectionStartTime = 0;
  }

  /**
   * Initialize the WebSocket connection
   */
  connect() {
    if (this.socket) {
      this.close();
    }

    try {
      this.socket = new WebSocket(this.url);
      
      this.socket.onopen = () => {
        this.isConnected = true;
        this.reconnectAttempts = 0;
        this._notifySubscribers('connection', { status: 'connected' });
      };
      
      this.socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data && data.type) {
            this._notifySubscribers(data.type, data.payload);
          }
        } catch (err) {
          console.error('Error parsing WebSocket message:', err);
        }
      };
      
      this.socket.onclose = () => {
        this.isConnected = false;
        this._notifySubscribers('connection', { status: 'disconnected' });
        this._attemptReconnect();
      };
      
      this.socket.onerror = (error) => {
        console.error('WebSocket error:', error);
        this._notifySubscribers('error', { message: 'Connection error' });
      };
      
    } catch (err) {
      console.error('Failed to create WebSocket connection:', err);
      throw new Error('Connection failed');
    }
  }

  /**
   * Send data to the WebSocket server
   * @param {string} type - Message type
   * @param {object} data - Message payload
   * @returns {boolean} - Whether the message was sent
   */
  send(type, data) {
    if (!this.isConnected || !this.socket) {
      return false;
    }
    
    try {
      const message = JSON.stringify({
        type,
        payload: data,
        timestamp: new Date().toISOString()
      });
      
      this.socket.send(message);
      return true;
    } catch (err) {
      console.error('Error sending message:', err);
      return false;
    }
  }

  /**
   * Subscribe to WebSocket events
   * @param {string} eventType - Event type to subscribe to
   * @param {function} callback - Callback function
   * @returns {string} - Subscription ID
   */
  subscribe(eventType, callback) {
    if (!this.subscribers.has(eventType)) {
      this.subscribers.set(eventType, new Map());
    }
    
    const id = this._generateId();
    this.subscribers.get(eventType).set(id, callback);
    
    return id;
  }

  /**
   * Unsubscribe from WebSocket events
   * @param {string} eventType - Event type
   * @param {string} id - Subscription ID
   * @returns {boolean} - Whether the unsubscription was successful
   */
  unsubscribe(eventType, id) {
    if (!this.subscribers.has(eventType)) {
      return false;
    }
    
    return this.subscribers.get(eventType).delete(id);
  }

  /**
   * Close the WebSocket connection
   */
  close() {
    if (this.socket) {
      this.socket.close();
      this.socket = null;
      this.isConnected = false;
    }
  }

  /**
   * Attempt to reconnect to the WebSocket server
   * @private
   */
  _attemptReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this._notifySubscribers('connection', { 
        status: 'failed', 
        message: 'Max reconnect attempts reached' 
      });
      return;
    }
    
    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
    
    setTimeout(() => {
      this.connect();
    }, delay);
  }

  /**
   * Notify all subscribers of an event
   * @param {string} eventType - Event type
   * @param {object} data - Event data
   * @private
   */
  _notifySubscribers(eventType, data) {
    if (!this.subscribers.has(eventType)) {
      return;
    }
    
    const eventSubscribers = this.subscribers.get(eventType);
    eventSubscribers.forEach(callback => {
      try {
        callback(data);
      } catch (err) {
        console.error('Error in subscriber callback:', err);
      }
    });
  }

  /**
   * Generate a unique ID for subscriptions
   * @returns {string} - Unique ID
   * @private
   */
  _generateId() {
    return `sub_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Start the ping interval for keepalive
   */
  startPingInterval() {
    this.stopPingInterval(); // Clear any existing interval
    
    this.pingTimer = setInterval(() => {
      if (this.socket && this.socket.readyState === WebSocket.OPEN) {
        this.socket.send(JSON.stringify({ type: 'ping', timestamp: Date.now() }));
        
        // Set a timeout for pong response
        this.resetPongTimer();
      }
    }, this.pingInterval);
  }

  /**
   * Reset the pong timeout timer
   */
  resetPongTimer() {
    if (this.pongTimer) {
      clearTimeout(this.pongTimer);
    }
    
    this.pongTimer = setTimeout(() => {
      console.warn('Pong timeout - connection may be dead');
      this.emit('pong_timeout');
      
      // Force reconnection
      if (this.socket) {
        this.socket.close();
      }
    }, this.pingTimeout);
  }

  /**
   * Stop the ping interval
   */
  stopPingInterval() {
    if (this.pingTimer) {
      clearInterval(this.pingTimer);
      this.pingTimer = null;
    }
    
    if (this.pongTimer) {
      clearTimeout(this.pongTimer);
      this.pongTimer = null;
    }
  }

  /**
   * Intentionally disconnect from the WebSocket server
   */
  disconnect() {
    this.intentionalClose = true;
    this.stopPingInterval();
    
    if (this.socket) {
      this.socket.close();
    }
    
    this.isConnected = false;
    this.subscriptions.clear();
    this.buffer = [];
  }

  /**
   * Subscribe to a topic
   * @param {string} topic - Topic to subscribe to
   */
  subscribeToTopic(topic) {
    // Add to subscriptions set
    this.subscriptions.add(topic);
    
    if (this.isConnected && this.socket && this.socket.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify({
        type: 'subscribe',
        topic: topic
      }));
    } else {
      // Buffer the subscription request
      this.addToBuffer({
        type: 'subscribe',
        topic: topic
      });
    }
  }

  /**
   * Unsubscribe from a topic
   * @param {string} topic - Topic to unsubscribe from
   */
  unsubscribeFromTopic(topic) {
    // Remove from subscriptions set
    this.subscriptions.delete(topic);
    
    if (this.isConnected && this.socket && this.socket.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify({
        type: 'unsubscribe',
        topic: topic
      }));
    } else {
      // Buffer the unsubscription request
      this.addToBuffer({
        type: 'unsubscribe',
        topic: topic
      });
    }
  }

  /**
   * Restore subscriptions after reconnection
   */
  restoreSubscriptions() {
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      this.subscriptions.forEach(topic => {
        this.socket.send(JSON.stringify({
          type: 'subscribe',
          topic: topic
        }));
      });
    }
  }

  /**
   * Add a message to the buffer for later sending
   * @param {Object} message - Message to buffer
   */
  addToBuffer(message) {
    // Maintain buffer size limit
    if (this.buffer.length >= this.bufferSize) {
      this.buffer.shift(); // Remove oldest message
    }
    
    this.buffer.push(message);
  }

  /**
   * Send all buffered messages
   */
  flushBuffer() {
    if (!this.isConnected || !this.socket || this.socket.readyState !== WebSocket.OPEN) {
      return;
    }
    
    while (this.buffer.length > 0) {
      const message = this.buffer.shift();
      this.socket.send(JSON.stringify(message));
    }
  }

  /**
   * Send a message with optional compression
   * @param {Object} data - Data to send
   */
  sendWithCompression(data) {
    if (!this.isConnected || !this.socket || this.socket.readyState !== WebSocket.OPEN) {
      this.addToBuffer(data);
      return;
    }
    
    if (this.useCompression && data && typeof data === 'object') {
      // Compress data
      try {
        const jsonStr = JSON.stringify(data);
        const compressed = deflate(jsonStr);
        this.socket.send(compressed.buffer);
      } catch (error) {
        console.error('Error compressing data:', error);
        // Fallback to uncompressed
        this.socket.send(JSON.stringify(data));
      }
    } else {
      // Send uncompressed
      this.socket.send(JSON.stringify(data));
    }
  }

  /**
   * Check if currently connected
   * @returns {boolean} Whether the WebSocket is connected
   */
  isConnected() {
    return this.isConnected && this.socket && this.socket.readyState === WebSocket.OPEN;
  }

  /**
   * Get connection status details
   * @returns {Object} Connection status information
   */
  getStatus() {
    return {
      connected: this.isConnected(),
      reconnectAttempts: this.reconnectAttempts,
      subscriptions: Array.from(this.subscriptions),
      bufferSize: this.buffer.length,
      readyState: this.socket ? this.socket.readyState : null
    };
  }
}

// Create a singleton instance
const analyticsWebSocket = new AnalyticsWebSocket();

export default analyticsWebSocket; 