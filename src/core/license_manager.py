#!/usr/bin/env python3
"""
License Management System

This module handles license key generation, validation, and feature management
for ARP Guard's tiered product model.
"""

import json
import hashlib
import base64
from datetime import datetime, timedelta
from typing import Dict, Optional, List
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class LicenseType:
    DEMO = "demo"
    LITE = "lite"
    PRO = "pro"
    ENTERPRISE = "enterprise"

class LicenseStatus:
    VALID = "valid"
    EXPIRED = "expired"
    INVALID = "invalid"
    REVOKED = "revoked"

class License:
    def __init__(
        self,
        license_type: str,
        features: List[str],
        expiry_date: datetime,
        customer_id: str,
        max_devices: int = 1
    ):
        self.license_type = license_type
        self.features = features
        self.expiry_date = expiry_date
        self.customer_id = customer_id
        self.max_devices = max_devices
        self.status = LicenseStatus.VALID
        self.created_at = datetime.now()
        self.last_validated = None

    def to_dict(self) -> Dict:
        """Convert license to dictionary for serialization."""
        return {
            "license_type": self.license_type,
            "features": self.features,
            "expiry_date": self.expiry_date.isoformat(),
            "customer_id": self.customer_id,
            "max_devices": self.max_devices,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "last_validated": self.last_validated.isoformat() if self.last_validated else None
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'License':
        """Create license from dictionary."""
        license = cls(
            license_type=data["license_type"],
            features=data["features"],
            expiry_date=datetime.fromisoformat(data["expiry_date"]),
            customer_id=data["customer_id"],
            max_devices=data["max_devices"]
        )
        license.status = data["status"]
        license.created_at = datetime.fromisoformat(data["created_at"])
        if data["last_validated"]:
            license.last_validated = datetime.fromisoformat(data["last_validated"])
        return license

class LicenseManager:
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "license_config.json"
        self.licenses: Dict[str, License] = {}
        self._load_config()

    def _load_config(self):
        """Load license configuration from file."""
        try:
            if Path(self.config_path).exists():
                with open(self.config_path, 'r') as f:
                    data = json.load(f)
                    self.licenses = {
                        key: License.from_dict(value)
                        for key, value in data.items()
                    }
        except Exception as e:
            logger.error(f"Failed to load license config: {str(e)}")
            self.licenses = {}

    def _save_config(self):
        """Save license configuration to file."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(
                    {key: license.to_dict() for key, license in self.licenses.items()},
                    f,
                    indent=2
                )
        except Exception as e:
            logger.error(f"Failed to save license config: {str(e)}")

    def generate_license_key(self, license: License) -> str:
        """Generate a license key from license data."""
        data = {
            "type": license.license_type,
            "customer_id": license.customer_id,
            "expiry": license.expiry_date.isoformat(),
            "features": license.features,
            "max_devices": license.max_devices
        }
        
        # Create a hash of the license data
        data_str = json.dumps(data, sort_keys=True)
        hash_obj = hashlib.sha256(data_str.encode())
        
        # Encode the license data and hash
        license_data = base64.b64encode(data_str.encode()).decode()
        license_hash = base64.b64encode(hash_obj.digest()).decode()
        
        # Combine into a license key
        license_key = f"{license_data}.{license_hash}"
        
        # Store the license
        self.licenses[license_key] = license
        self._save_config()
        
        return license_key

    def validate_license(self, license_key: str) -> Dict:
        """Validate a license key and return its status."""
        if license_key not in self.licenses:
            return {"valid": False, "status": LicenseStatus.INVALID, "message": "License key not found"}
        
        license = self.licenses[license_key]
        
        # Check if license is revoked
        if license.status == LicenseStatus.REVOKED:
            return {"valid": False, "status": LicenseStatus.REVOKED, "message": "License has been revoked"}
        
        # Check if license is expired
        if datetime.now() > license.expiry_date:
            license.status = LicenseStatus.EXPIRED
            self._save_config()
            return {"valid": False, "status": LicenseStatus.EXPIRED, "message": "License has expired"}
        
        # Update last validation time
        license.last_validated = datetime.now()
        self._save_config()
        
        return {
            "valid": True,
            "status": LicenseStatus.VALID,
            "type": license.license_type,
            "features": license.features,
            "expiry_date": license.expiry_date,
            "max_devices": license.max_devices
        }

    def revoke_license(self, license_key: str) -> bool:
        """Revoke a license key."""
        if license_key in self.licenses:
            self.licenses[license_key].status = LicenseStatus.REVOKED
            self._save_config()
            return True
        return False

    def get_feature_access(self, license_key: str, feature: str) -> bool:
        """Check if a license has access to a specific feature."""
        validation = self.validate_license(license_key)
        if not validation["valid"]:
            return False
        
        return feature in validation["features"]

    def create_demo_license(self, duration_days: int = 30) -> str:
        """Create a demo license with limited features."""
        license = License(
            license_type=LicenseType.DEMO,
            features=["basic_monitoring", "network_scan"],
            expiry_date=datetime.now() + timedelta(days=duration_days),
            customer_id="demo_user",
            max_devices=1
        )
        return self.generate_license_key(license)

    def create_lite_license(
        self,
        customer_id: str,
        duration_days: int = 365,
        max_devices: int = 5
    ) -> str:
        """Create a Lite tier license."""
        license = License(
            license_type=LicenseType.LITE,
            features=[
                "basic_monitoring",
                "network_scan",
                "email_alerts",
                "custom_actions",
                "report_generation"
            ],
            expiry_date=datetime.now() + timedelta(days=duration_days),
            customer_id=customer_id,
            max_devices=max_devices
        )
        return self.generate_license_key(license) 