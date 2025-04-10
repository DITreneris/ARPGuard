import { EventEmitter } from 'events';
import { inflate, deflate } from 'pako'; // For data compression

class AnalyticsWebSocket extends EventEmitter {
  constructor() {
    super();
    this.socket = null;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 10; // Increased from 5
    this.reconnectInterval = 2000; // Decreased from 5000
    this.maxReconnectInterval = 30000; // Max interval between retries
    this.pingInterval = 15000; // Decreased from 30000
    this.pingTimeout = 5000; // Time to wait for pong
    this.pingTimer = null;
    this.pongTimer = null;
    this.subscriptions = new Set(); // Track active subscriptions
    this.buffer = []; // Message buffer for disconnected state
    this.bufferSize = 100; // Max number of messages to buffer
    this.connected = false;
    this.intentionalClose = false;
    this.useCompression = true; // Enable compression
    this.connectionStartTime = 0;
  }

  /**
   * Connect to the WebSocket server
   * @param {string} [url] - Optional WebSocket URL override
   * @returns {Promise} Promise that resolves when connected
   */
  connect(url) {
    return new Promise((resolve, reject) => {
      // Clear any existing connection
      if (this.socket) {
        this.socket.onclose = null; // Prevent auto-reconnect for intentional disconnect
        this.socket.close();
      }

      this.intentionalClose = false;
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = url || `${protocol}//${window.location.host}/ws/analytics`;

      try {
        this.socket = new WebSocket(wsUrl);
        this.connectionStartTime = Date.now();

        // Set up one-time event handlers for this connection attempt
        const onOpen = () => {
          console.log('WebSocket connection established');
          const connectionTime = Date.now() - this.connectionStartTime;
          console.log(`Connection established in ${connectionTime}ms`);
          
          this.connected = true;
          this.reconnectAttempts = 0;
          this.startPingInterval();
          
          // Restore subscriptions
          this.restoreSubscriptions();
          
          // Send buffered messages if any
          this.flushBuffer();
          
          this.emit('connected');
          resolve();

          // Remove one-time handlers
          this.socket.removeEventListener('open', onOpen);
          this.socket.removeEventListener('error', onError);
        };

        const onError = (error) => {
          console.error('WebSocket connection error:', error);
          reject(error);
          
          // Remove one-time handlers
          this.socket.removeEventListener('open', onOpen);
          this.socket.removeEventListener('error', onError);
        };

        // Add one-time event listeners
        this.socket.addEventListener('open', onOpen);
        this.socket.addEventListener('error', onError);

        // Regular event handlers
        this.socket.onmessage = this.handleMessage.bind(this);
        this.socket.onclose = this.handleClose.bind(this);
        this.socket.onerror = this.handleError.bind(this);
      } catch (error) {
        console.error('Error creating WebSocket connection:', error);
        this.handleReconnect();
        reject(error);
      }
    });
  }

  /**
   * Handle incoming WebSocket messages
   * @param {MessageEvent} event - WebSocket message event
   */
  handleMessage(event) {
    try {
      // Check if it's a binary message (compressed)
      let data;
      if (event.data instanceof Blob) {
        // Handle binary data
        const reader = new FileReader();
        reader.onload = () => {
          try {
            // Decompress the data
            const decompressed = inflate(new Uint8Array(reader.result), { to: 'string' });
            const parsed = JSON.parse(decompressed);
            this.processMessage(parsed);
          } catch (error) {
            console.error('Error processing binary WebSocket message:', error);
          }
        };
        reader.readAsArrayBuffer(event.data);
        return;
      } else {
        // Handle text data
        data = JSON.parse(event.data);
        this.processMessage(data);
      }
    } catch (error) {
      console.error('Error parsing WebSocket message:', error);
      this.emit('error', { type: 'parse_error', error });
    }
  }

  /**
   * Process parsed WebSocket message
   * @param {Object} data - Parsed message data
   */
  processMessage(data) {
    // Reset pong timer if we get any message (implicit pong)
    this.resetPongTimer();

    switch (data.type) {
      case 'metrics_update':
        this.emit('metrics', data.data);
        break;
      case 'alerts_update':
        this.emit('alerts', data.data);
        break;
      case 'system_status':
        this.emit('systemStatus', data.data);
        break;
      case 'pong':
        // Explicit pong response
        break;
      case 'error':
        console.error('Server error:', data.message);
        this.emit('error', { type: 'server_error', message: data.message });
        break;
      default:
        console.warn('Unknown message type:', data.type);
    }
  }

  /**
   * Handle WebSocket connection closure
   * @param {CloseEvent} event - WebSocket close event
   */
  handleClose(event) {
    this.connected = false;
    this.stopPingInterval();
    console.log(`WebSocket connection closed: ${event.code} ${event.reason}`);
    
    // Don't attempt to reconnect if the closure was intentional
    if (!this.intentionalClose) {
      this.handleReconnect();
    }
    
    this.emit('disconnected', { code: event.code, reason: event.reason });
  }

  /**
   * Handle WebSocket errors
   * @param {Event} error - WebSocket error event
   */
  handleError(error) {
    console.error('WebSocket error:', error);
    this.emit('error', { type: 'connection_error', error });
  }

  /**
   * Attempt to reconnect to the WebSocket server
   */
  handleReconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      
      // Exponential backoff with jitter
      const baseDelay = Math.min(
        this.reconnectInterval * Math.pow(1.5, this.reconnectAttempts - 1),
        this.maxReconnectInterval
      );
      const jitter = Math.random() * 0.5 + 0.75; // Random between 0.75 and 1.25
      const delay = Math.floor(baseDelay * jitter);
      
      console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts}) in ${delay}ms...`);
      
      this.emit('reconnecting', { 
        attempt: this.reconnectAttempts, 
        maxAttempts: this.maxReconnectAttempts,
        delay 
      });
      
      setTimeout(() => this.connect(), delay);
    } else {
      console.error('Max reconnection attempts reached');
      this.emit('reconnect_failed');
    }
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
    
    this.connected = false;
    this.subscriptions.clear();
    this.buffer = [];
  }

  /**
   * Subscribe to a topic
   * @param {string} topic - Topic to subscribe to
   */
  subscribe(topic) {
    // Add to subscriptions set
    this.subscriptions.add(topic);
    
    if (this.connected && this.socket && this.socket.readyState === WebSocket.OPEN) {
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
  unsubscribe(topic) {
    // Remove from subscriptions set
    this.subscriptions.delete(topic);
    
    if (this.connected && this.socket && this.socket.readyState === WebSocket.OPEN) {
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
    if (!this.connected || !this.socket || this.socket.readyState !== WebSocket.OPEN) {
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
  send(data) {
    if (!this.connected || !this.socket || this.socket.readyState !== WebSocket.OPEN) {
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
    return this.connected && this.socket && this.socket.readyState === WebSocket.OPEN;
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

// Create and export a singleton instance
const analyticsWebSocket = new AnalyticsWebSocket();
export default analyticsWebSocket; 