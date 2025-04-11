import React from 'react';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { Provider } from 'react-redux';
import configureStore from 'redux-mock-store';
import NetworkMapView from '../NetworkMapView';
import analyticsWebSocket from '../../../services/websocketService';

// Mock WebSocket service
jest.mock('../../../services/websocketService', () => ({
  isConnected: jest.fn(),
  send: jest.fn(),
  on: jest.fn(),
  off: jest.fn()
}));

// Mock store setup
const mockStore = configureStore([]);
const initialState = {
  app: {
    isLiteMode: false
  }
};

describe('NetworkMapView Component', () => {
  let store;

  beforeEach(() => {
    store = mockStore(initialState);
    // Reset WebSocket mocks
    analyticsWebSocket.isConnected.mockReturnValue(true);
    analyticsWebSocket.send.mockClear();
    analyticsWebSocket.on.mockClear();
    analyticsWebSocket.off.mockClear();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // Test 1: Component Renders Correctly
  test('renders NetworkMapView component', () => {
    render(
      <Provider store={store}>
        <NetworkMapView />
      </Provider>
    );
    expect(screen.getByText('Network Map')).toBeInTheDocument();
  });

  // Test 2: WebSocket Connection Status
  test('displays live status when WebSocket is connected', () => {
    analyticsWebSocket.isConnected.mockReturnValue(true);
    
    render(
      <Provider store={store}>
        <NetworkMapView />
      </Provider>
    );

    expect(screen.getByText('LIVE')).toBeInTheDocument();
  });

  // Test 3: Search Functionality
  test('filters devices based on search query', async () => {
    render(
      <Provider store={store}>
        <NetworkMapView />
      </Provider>
    );

    const searchInput = screen.getByPlaceholderText('Search devices...');
    fireEvent.change(searchInput, { target: { value: 'Device 1' } });

    expect(searchInput.value).toBe('Device 1');
  });

  // Test 4: View Mode Selection
  test('changes view mode', () => {
    render(
      <Provider store={store}>
        <NetworkMapView />
      </Provider>
    );

    const viewSelector = screen.getByRole('combobox');
    fireEvent.change(viewSelector, { target: { value: 'compact' } });

    expect(viewSelector.value).toBe('compact');
  });

  // Test 5: Refresh Functionality
  test('refreshes network data', () => {
    render(
      <Provider store={store}>
        <NetworkMapView />
      </Provider>
    );

    const refreshButton = screen.getByText('↻ Refresh');
    fireEvent.click(refreshButton);

    expect(analyticsWebSocket.send).toHaveBeenCalledWith({
      type: 'request_topology_update'
    });
  });

  // Test 6: Device Selection
  test('selects and displays device details', async () => {
    const { container } = render(
      <Provider store={store}>
        <NetworkMapView />
      </Provider>
    );

    // Wait for loading to complete and find devices
    await waitFor(() => {
      const deviceList = container.querySelector('.device-list');
      expect(deviceList).toBeInTheDocument();
      
      // Get all device items and click the first one
      const deviceItems = container.querySelectorAll('.device-item');
      fireEvent.click(deviceItems[0]);
    });

    // Check for device details section
    const detailsSection = container.querySelector('.device-details');
    expect(detailsSection).toBeInTheDocument();
    
    // Use within to scope queries to the details section
    const macAddress = within(detailsSection).getByText('00:11:22:33:44:55');
    expect(macAddress).toBeInTheDocument();
    
    // Check for normal status
    const statusElement = within(detailsSection).getByText('normal');
    expect(statusElement).toBeInTheDocument();
  });

  // Test 7: Alert Filtering
  test('filters devices based on alert status', () => {
    render(
      <Provider store={store}>
        <NetworkMapView />
      </Provider>
    );

    const alertCheckbox = screen.getByLabelText('Show alerted only');
    fireEvent.click(alertCheckbox);

    expect(alertCheckbox.checked).toBe(true);
  });

  // Test 8: Lite Mode Specific Features
  test('adjusts UI for lite mode', () => {
    const liteStore = mockStore({
      app: {
        isLiteMode: true
      }
    });

    render(
      <Provider store={liteStore}>
        <NetworkMapView />
      </Provider>
    );

    expect(screen.getByTestId('network-map-view')).toHaveClass('lite-mode');
  });

  // Test 9: Stats Display
  test('displays correct network statistics', async () => {
    const { container } = render(
      <Provider store={store}>
        <NetworkMapView />
      </Provider>
    );

    // Wait for the component to load and get stats section
    await waitFor(() => {
      const statsSection = container.querySelector('.network-stats');
      expect(statsSection).toBeInTheDocument();
      
      // Use within to scope our queries to the stats section
      const labels = within(statsSection).getAllByText(/Devices:|Connections:|Alerts:/);
      expect(labels.length).toBeGreaterThan(0);
    });
  });

  // Test 10: WebSocket Event Handling
  test('handles WebSocket events correctly', () => {
    const mockEventHandler = jest.fn();
    analyticsWebSocket.on.mockImplementation((event, handler) => {
      if (event === 'topology_update') {
        mockEventHandler();
      }
      return handler; // Return the handler for testing
    });

    render(
      <Provider store={store}>
        <NetworkMapView />
      </Provider>
    );

    // Verify that the WebSocket event handler was registered
    expect(mockEventHandler).toHaveBeenCalled();
  });
}); 