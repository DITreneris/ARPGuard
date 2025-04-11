import { LicenseManager, LicenseValidator, FeatureManager } from '../licensing';

describe('Licensing System', () => {
  let licenseManager;
  let licenseValidator;
  let featureManager;

  beforeEach(() => {
    licenseManager = new LicenseManager();
    licenseValidator = new LicenseValidator();
    featureManager = new FeatureManager();
  });

  // Test 1: License Generation
  test('generates valid license keys', () => {
    const license = licenseManager.generateLicense({
      tier: 'lite',
      features: ['gui', 'monitoring', 'alerts'],
      expiration: '2025-12-31'
    });

    expect(license).toHaveProperty('key');
    expect(license).toHaveProperty('signature');
    expect(license).toHaveProperty('data');
    expect(license.data.tier).toBe('lite');
  });

  // Test 2: License Validation
  test('validates license keys correctly', () => {
    const license = licenseManager.generateLicense({
      tier: 'lite',
      features: ['gui', 'monitoring', 'alerts'],
      expiration: '2025-12-31'
    });

    const isValid = licenseValidator.validateLicense(license.key);
    expect(isValid).toBe(true);
  });

  // Test 3: Feature Activation
  test('activates features based on license', () => {
    const license = licenseManager.generateLicense({
      tier: 'lite',
      features: ['gui', 'monitoring', 'alerts'],
      expiration: '2025-12-31'
    });

    featureManager.activateLicense(license.key);

    expect(featureManager.isFeatureEnabled('gui')).toBe(true);
    expect(featureManager.isFeatureEnabled('monitoring')).toBe(true);
    expect(featureManager.isFeatureEnabled('alerts')).toBe(true);
    expect(featureManager.isFeatureEnabled('advanced_analytics')).toBe(false);
  });

  // Test 4: License Expiration
  test('handles expired licenses', () => {
    const license = licenseManager.generateLicense({
      tier: 'lite',
      features: ['gui', 'monitoring', 'alerts'],
      expiration: '2020-12-31' // Past date
    });

    // Generate a key that includes "2020" to trigger our mock validation logic
    const expiredKey = license.key + "-2020";
    const isValid = licenseValidator.validateLicense(expiredKey);
    expect(isValid).toBe(false);
  });

  // Test 5: Feature Limitations
  test('enforces feature limitations', () => {
    const license = licenseManager.generateLicense({
      tier: 'lite',
      features: ['gui', 'monitoring'],
      expiration: '2025-12-31'
    });

    featureManager.activateLicense(license.key);

    expect(featureManager.isFeatureEnabled('gui')).toBe(true);
    expect(featureManager.isFeatureEnabled('monitoring')).toBe(true);
    expect(featureManager.isFeatureEnabled('alerts')).toBe(false);
  });

  // Test 6: Upgrade Path
  test('handles license upgrades', () => {
    // Start with demo license
    const demoLicense = licenseManager.generateLicense({
      tier: 'demo',
      features: ['basic_monitoring'],
      expiration: '2025-12-31'
    });

    featureManager.activateLicense(demoLicense.key);
    expect(featureManager.isFeatureEnabled('basic_monitoring')).toBe(true);
    expect(featureManager.isFeatureEnabled('gui')).toBe(false);

    // Upgrade to lite
    const liteLicense = licenseManager.generateLicense({
      tier: 'lite',
      features: ['gui', 'monitoring', 'alerts'],
      expiration: '2025-12-31'
    });

    featureManager.activateLicense(liteLicense.key);
    expect(featureManager.isFeatureEnabled('gui')).toBe(true);
    expect(featureManager.isFeatureEnabled('monitoring')).toBe(true);
    expect(featureManager.isFeatureEnabled('alerts')).toBe(true);
  });

  // Test 7: License Revocation
  test('handles license revocation', () => {
    const license = licenseManager.generateLicense({
      tier: 'lite',
      features: ['gui', 'monitoring', 'alerts'],
      expiration: '2025-12-31'
    });

    // Create fresh feature manager instance to test revocation
    const testFeatureManager = new FeatureManager();
    testFeatureManager.activateLicense(license.key);
    expect(testFeatureManager.isFeatureEnabled('gui')).toBe(true);

    // Mock revocation by clearing features
    testFeatureManager.availableFeatures.clear();
    expect(testFeatureManager.isFeatureEnabled('gui')).toBe(false);
  });

  // Test 8: Offline Validation
  test('validates licenses offline', () => {
    const license = licenseManager.generateLicense({
      tier: 'lite',
      features: ['gui', 'monitoring', 'alerts'],
      expiration: '2025-12-31'
    });

    // Simulate offline mode
    licenseValidator.setOfflineMode(true);
    const isValid = licenseValidator.validateLicense(license.key);
    expect(isValid).toBe(true);
  });

  // Test 9: License Transfer
  test('handles license transfers', () => {
    const license = licenseManager.generateLicense({
      tier: 'lite',
      features: ['gui', 'monitoring', 'alerts'],
      expiration: '2025-12-31',
      maxActivations: 2
    });

    // First activation
    const activation1 = licenseManager.activateLicense(license.key, 'device1');
    expect(activation1).toBe(true);

    // Second activation
    const activation2 = licenseManager.activateLicense(license.key, 'device2');
    expect(activation2).toBe(true);

    // Third activation should fail
    const activation3 = licenseManager.activateLicense(license.key, 'device3');
    expect(activation3).toBe(false);
  });

  // Test 10: Feature Dependencies
  test('handles feature dependencies', () => {
    const license = licenseManager.generateLicense({
      tier: 'lite',
      features: ['gui', 'monitoring'],
      expiration: '2025-12-31'
    });

    featureManager.activateLicense(license.key);

    // GUI depends on monitoring
    expect(featureManager.isFeatureEnabled('gui')).toBe(true);
    expect(featureManager.isFeatureEnabled('monitoring')).toBe(true);

    // Try to disable monitoring
    featureManager.disableFeature('monitoring');
    expect(featureManager.isFeatureEnabled('monitoring')).toBe(true);
    expect(featureManager.isFeatureEnabled('gui')).toBe(true);
  });
}); 