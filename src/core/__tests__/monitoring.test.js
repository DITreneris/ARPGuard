import { MonitoringService, DeviceScanner, AlertGenerator } from '../monitoring';

describe('Monitoring System', () => {
  let monitoringService;
  let deviceScanner;
  let alertGenerator;

  beforeEach(() => {
    monitoringService = new MonitoringService();
    deviceScanner = new DeviceScanner();
    alertGenerator = new AlertGenerator();
  });

  // Test 1: Device Discovery
  test('discovers network devices', async () => {
    const devices = await deviceScanner.scanSubnet('192.168.1.0/24');
    
    expect(devices).toBeInstanceOf(Array);
    expect(devices[0]).toHaveProperty('ipAddress');
    expect(devices[0]).toHaveProperty('macAddress');
    expect(devices[0]).toHaveProperty('hostname');
  });

  // Test 2: Continuous Monitoring
  test('maintains continuous monitoring', async () => {
    const startTime = Date.now();
    monitoringService.startMonitoring();
    
    // Wait for monitoring cycle
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    const devices = monitoringService.getDiscoveredDevices();
    expect(devices.length).toBeGreaterThan(0);
    
    monitoringService.stopMonitoring();
    expect(monitoringService.isMonitoring()).toBe(false);
  });

  // Test 3: Alert Generation
  test('generates alerts for suspicious activity', async () => {
    const mockDevice = {
      ipAddress: '192.168.1.100',
      macAddress: '00:11:22:33:44:55',
      hostname: 'test-device'
    };

    const alerts = await alertGenerator.checkDevice(mockDevice);
    expect(alerts).toBeInstanceOf(Array);
    
    if (alerts.length > 0) {
      expect(alerts[0]).toHaveProperty('severity');
      expect(alerts[0]).toHaveProperty('type');
      expect(alerts[0]).toHaveProperty('description');
    }
  });

  // Test 4: Resource Usage Control
  test('maintains resource usage within limits', async () => {
    monitoringService.startMonitoring();
    
    // Monitor resource usage
    const initialCpu = process.cpuUsage();
    const initialMemory = process.memoryUsage();
    
    // Wait for monitoring cycle
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    const currentCpu = process.cpuUsage(initialCpu);
    const currentMemory = process.memoryUsage();
    
    // CPU usage should be less than 20%
    expect(currentCpu.user / 1000000).toBeLessThan(20);
    
    // Memory usage should be less than 100MB
    expect(currentMemory.heapUsed / 1024 / 1024).toBeLessThan(100);
    
    monitoringService.stopMonitoring();
  });

  // Test 5: Device History Tracking
  test('tracks device history', async () => {
    const device = {
      ipAddress: '192.168.1.100',
      macAddress: '00:11:22:33:44:55'
    };

    monitoringService.startMonitoring();
    await monitoringService.updateDeviceHistory(device);
    
    const history = monitoringService.getDeviceHistory(device.ipAddress);
    expect(history).toBeInstanceOf(Array);
    expect(history[0]).toHaveProperty('timestamp');
    expect(history[0]).toHaveProperty('status');
    
    monitoringService.stopMonitoring();
  });

  // Test 6: Alert Prioritization
  test('prioritizes alerts correctly', () => {
    const alerts = [
      { severity: 'low', type: 'info' },
      { severity: 'high', type: 'warning' },
      { severity: 'critical', type: 'error' }
    ];

    const prioritized = alertGenerator.prioritizeAlerts(alerts);
    expect(prioritized[0].severity).toBe('critical');
    expect(prioritized[1].severity).toBe('high');
    expect(prioritized[2].severity).toBe('low');
  });

  // Test 7: Network Topology Mapping
  test('maps network topology', async () => {
    const topology = await monitoringService.mapTopology();
    
    expect(topology).toHaveProperty('devices');
    expect(topology).toHaveProperty('connections');
    expect(topology.devices).toBeInstanceOf(Array);
    expect(topology.connections).toBeInstanceOf(Array);
  });

  // Test 8: Scheduled Scanning
  test('executes scheduled scans', async () => {
    const scanResults = [];
    
    monitoringService.on('scanComplete', (results) => {
      scanResults.push(results);
    });

    monitoringService.startScheduledScanning(60); // 60 second interval
    
    // Wait for scan cycle but reduce timeout to avoid jest timeout
    await new Promise(resolve => setTimeout(resolve, 500));
    
    expect(scanResults.length).toBeGreaterThan(0);
    expect(scanResults[0]).toHaveProperty('timestamp');
    expect(scanResults[0]).toHaveProperty('devices');
    
    monitoringService.stopScheduledScanning();
  }, 5000); // Add explicit timeout of 5 seconds

  // Test 9: Alert Correlation
  test('correlates related alerts', () => {
    const alerts = [
      {
        id: 1,
        sourceIp: '192.168.1.100',
        type: 'arp_spoof',
        timestamp: Date.now() - 1000
      },
      {
        id: 2,
        sourceIp: '192.168.1.100',
        type: 'mac_flapping',
        timestamp: Date.now()
      }
    ];

    const correlated = alertGenerator.correlateAlerts(alerts);
    expect(correlated).toBeInstanceOf(Array);
    expect(correlated[0]).toHaveProperty('relatedAlerts');
  });

  // Test 10: Performance Optimization
  test('optimizes monitoring performance', async () => {
    const startTime = Date.now();
    monitoringService.startMonitoring();
    
    // Simulate high load
    for (let i = 0; i < 1000; i++) {
      await monitoringService.updateDeviceHistory({
        ipAddress: `192.168.1.${i}`,
        macAddress: `00:11:22:33:44:${i}`
      });
    }
    
    const endTime = Date.now();
    const duration = endTime - startTime;
    
    // Processing should complete within 5 seconds
    expect(duration).toBeLessThan(5000);
    
    monitoringService.stopMonitoring();
  });
}); 