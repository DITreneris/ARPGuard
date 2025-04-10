import React, { useState, useEffect } from 'react';
import analyticsWebSocket from '../../services/websocketService';
import './WebSocketStatus.css';

/**
 * WebSocketStatus Component
 * Displays the current status of the WebSocket connection with detailed metrics
 */
const WebSocketStatus = () => {
  const [status, setStatus] = useState({
    connected: false,
    reconnectAttempts: 0,
    subscriptions: [],
    bufferSize: 0,
    readyState: null
  });
  const [expanded, setExpanded] = useState(false);
  const [lastPing, setLastPing] = useState(null);
  const [messageStats, setMessageStats] = useState({
    received: 0,
    errors: 0,
    reconnects: 0
  });

  useEffect(() => {
    // Get initial status
    setStatus(analyticsWebSocket.getStatus());

    // Add event listeners
    const handleConnected = () => {
      setStatus(analyticsWebSocket.getStatus());
      setMessageStats(prev => ({ ...prev, reconnects: prev.reconnects + 1 }));
    };

    const handleDisconnected = () => {
      setStatus(analyticsWebSocket.getStatus());
    };

    const handleError = () => {
      setStatus(analyticsWebSocket.getStatus());
      setMessageStats(prev => ({ ...prev, errors: prev.errors + 1 }));
    };

    const handleMessage = () => {
      setMessageStats(prev => ({ ...prev, received: prev.received + 1 }));
      setLastPing(new Date());
    };

    const handleReconnecting = () => {
      setStatus(analyticsWebSocket.getStatus());
    };

    // Add event listeners
    analyticsWebSocket.on('connected', handleConnected);
    analyticsWebSocket.on('disconnected', handleDisconnected);
    analyticsWebSocket.on('error', handleError);
    analyticsWebSocket.on('metrics', handleMessage);
    analyticsWebSocket.on('alerts', handleMessage);
    analyticsWebSocket.on('systemStatus', handleMessage);
    analyticsWebSocket.on('reconnecting', handleReconnecting);

    // Update status every 3 seconds
    const statusInterval = setInterval(() => {
      setStatus(analyticsWebSocket.getStatus());
    }, 3000);

    return () => {
      // Remove event listeners
      analyticsWebSocket.removeListener('connected', handleConnected);
      analyticsWebSocket.removeListener('disconnected', handleDisconnected);
      analyticsWebSocket.removeListener('error', handleError);
      analyticsWebSocket.removeListener('metrics', handleMessage);
      analyticsWebSocket.removeListener('alerts', handleMessage);
      analyticsWebSocket.removeListener('systemStatus', handleMessage);
      analyticsWebSocket.removeListener('reconnecting', handleReconnecting);

      clearInterval(statusInterval);
    };
  }, []);

  // Handle manual reconnect
  const handleReconnect = () => {
    analyticsWebSocket.connect();
  };

  // Map readyState to readable text
  const getReadyStateText = (state) => {
    switch (state) {
      case 0: return 'Connecting';
      case 1: return 'Open';
      case 2: return 'Closing';
      case 3: return 'Closed';
      default: return 'Unknown';
    }
  };

  return (
    <div className={`websocket-status ${expanded ? 'expanded' : ''}`}>
      <div 
        className={`websocket-indicator ${status.connected ? 'connected' : 'disconnected'}`}
        onClick={() => setExpanded(!expanded)}
      >
        <div className="indicator-dot"></div>
        <span className="indicator-text">
          {status.connected ? 'Connected' : 'Disconnected'}
        </span>
      </div>

      {expanded && (
        <div className="websocket-details">
          <h4>WebSocket Connection</h4>
          
          <div className="status-row">
            <span className="status-label">Status:</span>
            <span className={`status-value ${status.connected ? 'status-ok' : 'status-error'}`}>
              {status.connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          
          <div className="status-row">
            <span className="status-label">Ready State:</span>
            <span className="status-value">
              {getReadyStateText(status.readyState)}
            </span>
          </div>
          
          <div className="status-row">
            <span className="status-label">Reconnect Attempts:</span>
            <span className="status-value">
              {status.reconnectAttempts}
            </span>
          </div>
          
          <div className="status-row">
            <span className="status-label">Buffered Messages:</span>
            <span className="status-value">
              {status.bufferSize}
            </span>
          </div>
          
          <div className="status-row">
            <span className="status-label">Subscriptions:</span>
            <span className="status-value">
              {status.subscriptions.length > 0 
                ? status.subscriptions.join(', ') 
                : 'None'}
            </span>
          </div>
          
          <div className="status-row">
            <span className="status-label">Messages Received:</span>
            <span className="status-value">
              {messageStats.received}
            </span>
          </div>
          
          <div className="status-row">
            <span className="status-label">Errors:</span>
            <span className="status-value">
              {messageStats.errors}
            </span>
          </div>
          
          <div className="status-row">
            <span className="status-label">Reconnections:</span>
            <span className="status-value">
              {messageStats.reconnects}
            </span>
          </div>
          
          {lastPing && (
            <div className="status-row">
              <span className="status-label">Last Message:</span>
              <span className="status-value">
                {lastPing.toLocaleTimeString()}
              </span>
            </div>
          )}
          
          <div className="websocket-actions">
            <button 
              className="reconnect-button"
              onClick={handleReconnect}
              disabled={status.connected}
            >
              Reconnect
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default WebSocketStatus; 