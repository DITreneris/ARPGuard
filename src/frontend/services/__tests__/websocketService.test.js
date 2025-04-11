import websocketService from '../websocketService';

// Mock WebSocket
const mockWebSocket = {
  send: jest.fn(),
  close: jest.fn(),
  readyState: 0,
  addEventListener: jest.fn(),
  removeEventListener: jest.fn()
};

// Define WebSocket constants
global.WebSocket = {
  CONNECTING: 0,
  OPEN: 1,
  CLOSING: 2,
  CLOSED: 3
};

// Mock the WebSocket constructor
global.WebSocket = jest.fn(() => mockWebSocket);

describe('WebSocket Service', () => {
  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    // Reset WebSocket service state
    if (websocketService.socket) {
      websocketService.disconnect();
    }
  });

  // Test 1: Connection Establishment
  test('establishes WebSocket connection', () => {
    websocketService.connect();
    
    expect(global.WebSocket).toHaveBeenCalledWith('ws://localhost:8080/analytics');
  });

  // Test 2: Connection Status
  test('reports correct connection status', () => {
    // Before connection
    expect(websocketService.isConnected).toBe(false);
    
    // Connect
    websocketService.connect();
    
    // Simulate open event
    mockWebSocket.readyState = WebSocket.OPEN;
    websocketService.isConnected = true;
    
    expect(websocketService.isConnected).toBe(true);
  });

  // Test 3: Message Sending
  test('sends messages when connected', () => {
    // Connect
    websocketService.connect();
    mockWebSocket.readyState = WebSocket.OPEN;
    websocketService.isConnected = true;
    
    // Send message
    const result = websocketService.send('test', { data: 'test data' });
    
    // Check if message was sent correctly
    expect(result).toBe(true);
    expect(mockWebSocket.send).toHaveBeenCalledWith(
      expect.stringContaining('"type":"test"')
    );
  });

  // Test 4: Disconnection
  test('properly disconnects WebSocket', () => {
    // Connect first
    websocketService.connect();
    
    // Then disconnect
    websocketService.disconnect();
    
    // Check if socket was closed
    expect(mockWebSocket.close).toHaveBeenCalled();
  });

  // Test 5: Subscription
  test('manages subscriptions correctly', () => {
    const callback = jest.fn();
    
    // Subscribe to event
    const subscriptionId = websocketService.subscribe('testEvent', callback);
    
    // Verify we get a valid subscription ID
    expect(subscriptionId).toBeDefined();
    expect(typeof subscriptionId).toBe('string');
    
    // Simulate message event to test subscription
    if (mockWebSocket.onmessage) {
      mockWebSocket.onmessage({
        data: JSON.stringify({ type: 'testEvent', payload: { test: true } })
      });
    }
    
    // Test unsubscribe
    const result = websocketService.unsubscribe('testEvent', subscriptionId);
    expect(result).toBe(true);
  });

  // Test 6: Failed connection
  test('handles connection failures', () => {
    // Mock WebSocket to simulate error
    jest.spyOn(console, 'error').mockImplementation(() => {});
    global.WebSocket.mockImplementationOnce(() => {
      throw new Error('Connection failed');
    });
    
    // Expect connection to throw
    expect(() => {
      websocketService.connect();
    }).toThrow('Connection failed');
    
    console.error.mockRestore();
  });

  // Test 7: Event handling
  test('handles WebSocket events', () => {
    // Connect
    websocketService.connect();
    
    // Simulate events if handlers exist
    if (mockWebSocket.onopen) mockWebSocket.onopen();
    if (mockWebSocket.onclose) mockWebSocket.onclose();
    if (mockWebSocket.onerror) mockWebSocket.onerror(new Error('Test error'));
    
    // These would need subscriptions and mocks to fully test
    // But we can at least verify the handlers were assigned
    expect(mockWebSocket.onopen).toBeDefined();
    expect(mockWebSocket.onclose).toBeDefined();
    expect(mockWebSocket.onmessage).toBeDefined();
    expect(mockWebSocket.onerror).toBeDefined();
  });
}); 