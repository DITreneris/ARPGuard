#!/usr/bin/env python3
"""
Tests for the License Management System
"""

import unittest
from datetime import datetime, timedelta
import tempfile
import os
from src.core.license_manager import LicenseManager, License, LicenseType, LicenseStatus

class TestLicenseManager(unittest.TestCase):
    def setUp(self):
        # Create a temporary file for testing
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file.close()
        self.license_manager = LicenseManager(self.temp_file.name)

    def tearDown(self):
        # Clean up the temporary file
        os.unlink(self.temp_file.name)

    def test_create_and_validate_demo_license(self):
        """Test creating and validating a demo license."""
        # Create demo license
        license_key = self.license_manager.create_demo_license(duration_days=7)
        
        # Validate license
        validation = self.license_manager.validate_license(license_key)
        
        # Check validation results
        self.assertTrue(validation["valid"])
        self.assertEqual(validation["type"], LicenseType.DEMO)
        self.assertEqual(validation["max_devices"], 1)
        self.assertIn("basic_monitoring", validation["features"])
        self.assertIn("network_scan", validation["features"])

    def test_create_and_validate_lite_license(self):
        """Test creating and validating a Lite tier license."""
        # Create Lite license
        license_key = self.license_manager.create_lite_license(
            customer_id="test_customer",
            duration_days=365,
            max_devices=5
        )
        
        # Validate license
        validation = self.license_manager.validate_license(license_key)
        
        # Check validation results
        self.assertTrue(validation["valid"])
        self.assertEqual(validation["type"], LicenseType.LITE)
        self.assertEqual(validation["max_devices"], 5)
        self.assertIn("email_alerts", validation["features"])
        self.assertIn("custom_actions", validation["features"])
        self.assertIn("report_generation", validation["features"])

    def test_license_expiration(self):
        """Test license expiration handling."""
        # Create a license that expires in 1 day
        license_key = self.license_manager.create_demo_license(duration_days=1)
        
        # Validate immediately (should be valid)
        validation = self.license_manager.validate_license(license_key)
        self.assertTrue(validation["valid"])
        
        # Simulate time passing (1 day + 1 second)
        license = self.license_manager.licenses[license_key]
        license.expiry_date = datetime.now() - timedelta(seconds=1)
        
        # Validate again (should be expired)
        validation = self.license_manager.validate_license(license_key)
        self.assertFalse(validation["valid"])
        self.assertEqual(validation["status"], LicenseStatus.EXPIRED)

    def test_license_revocation(self):
        """Test license revocation."""
        # Create and validate a license
        license_key = self.license_manager.create_demo_license()
        validation = self.license_manager.validate_license(license_key)
        self.assertTrue(validation["valid"])
        
        # Revoke the license
        self.assertTrue(self.license_manager.revoke_license(license_key))
        
        # Validate again (should be revoked)
        validation = self.license_manager.validate_license(license_key)
        self.assertFalse(validation["valid"])
        self.assertEqual(validation["status"], LicenseStatus.REVOKED)

    def test_feature_access(self):
        """Test feature access control."""
        # Create a Lite license
        license_key = self.license_manager.create_lite_license("test_customer")
        
        # Check feature access
        self.assertTrue(self.license_manager.get_feature_access(license_key, "email_alerts"))
        self.assertTrue(self.license_manager.get_feature_access(license_key, "custom_actions"))
        self.assertFalse(self.license_manager.get_feature_access(license_key, "enterprise_features"))

    def test_invalid_license(self):
        """Test handling of invalid license keys."""
        validation = self.license_manager.validate_license("invalid_key")
        self.assertFalse(validation["valid"])
        self.assertEqual(validation["status"], LicenseStatus.INVALID)

    def test_persistence(self):
        """Test license persistence across manager instances."""
        # Create a license with first manager
        license_key = self.license_manager.create_demo_license()
        
        # Create a new manager instance with the same config file
        new_manager = LicenseManager(self.temp_file.name)
        
        # Validate license with new manager
        validation = new_manager.validate_license(license_key)
        self.assertTrue(validation["valid"])

if __name__ == '__main__':
    unittest.main() 