"""
License management service for handling license operations.
"""

from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
import json
import logging

from app.models.license import License, LicenseActivation, LicenseValidationLog
from app.utils.license_helper import (
    generate_license_key,
    validate_license_key,
    validate_license_data,
    get_hardware_fingerprint
)
from app.schemas.license import LicenseCreate, LicenseUpdate, LicenseActivationCreate

logger = logging.getLogger(__name__)

class LicenseService:
    def __init__(self, db: Session):
        self.db = db
    
    def create_license(
        self, 
        organization_name: str,
        organization_email: str,
        license_type: str = "standard",
        expiry_days: int = 365,
        max_devices: int = 5,
        max_users: int = 10,
        is_trial: bool = False
    ) -> License:
        """
        Create a new license in the database.
        
        Args:
            organization_name: Name of the organization
            organization_email: Email of the organization
            license_type: Type of license (standard, professional, enterprise)
            expiry_days: Number of days until license expires
            max_devices: Maximum number of devices allowed
            max_users: Maximum number of users allowed
            is_trial: Whether this is a trial license
            
        Returns:
            The created License object
        """
        # Generate license key and data
        license_data = generate_license_key(
            org_name=organization_name,
            license_type=license_type,
            expiry_days=expiry_days
        )
        
        # Create license object
        license_obj = License(
            license_key=license_data["license_key"],
            organization_name=organization_name,
            organization_email=organization_email,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=expiry_days),
            license_type=license_type,
            max_devices=max_devices,
            max_users=max_users,
            is_active=True,
            is_trial=is_trial,
            features=json.dumps(license_data["features"])
        )
        
        # Save to database
        self.db.add(license_obj)
        self.db.commit()
        self.db.refresh(license_obj)
        
        logger.info(f"Created new license: {license_obj.license_key} for {organization_name}")
        return license_obj
    
    def create_trial_license(
        self, 
        organization_name: str,
        organization_email: str
    ) -> License:
        """
        Create a new trial license.
        
        Args:
            organization_name: Name of the organization
            organization_email: Email of the organization
            
        Returns:
            The created trial License object
        """
        return self.create_license(
            organization_name=organization_name,
            organization_email=organization_email,
            license_type="trial",
            expiry_days=30,
            max_devices=3,
            max_users=3,
            is_trial=True
        )
    
    def get_license_by_key(self, license_key: str) -> Optional[License]:
        """
        Get a license by its key.
        
        Args:
            license_key: The license key to look up
            
        Returns:
            The License object or None if not found
        """
        return self.db.query(License).filter(License.license_key == license_key).first()
    
    def get_active_license(self) -> Optional[License]:
        """
        Get the currently active license.
        
        Returns:
            The active License object or None if not found
        """
        return self.db.query(License).filter(
            License.is_active == True
        ).order_by(License.created_at.desc()).first()
    
    def activate_license(self, license_key: str, device_name: str, ip_address: str) -> Tuple[bool, str, Optional[License]]:
        """
        Activate a license for a specific device.
        
        Args:
            license_key: The license key to activate
            device_name: Name of the device
            ip_address: IP address of the device
            
        Returns:
            Tuple of (success, message, license_obj)
        """
        # Validate license key format
        is_valid, error_msg = validate_license_key(license_key)
        if not is_valid:
            return False, error_msg, None
        
        # Find license in database
        license_obj = self.get_license_by_key(license_key)
        if not license_obj:
            return False, "License key not found", None
        
        # Check if license is valid
        if not license_obj.is_active:
            return False, "License is not active", license_obj
        
        if license_obj.is_expired():
            return False, "License has expired", license_obj
        
        # Get hardware fingerprint
        hardware_fingerprint = get_hardware_fingerprint()
        
        # Check if this device has already activated this license
        existing_activation = self.db.query(LicenseActivation).filter(
            LicenseActivation.license_id == license_obj.id,
            LicenseActivation.device_id == hardware_fingerprint
        ).first()
        
        if existing_activation:
            # Update existing activation
            existing_activation.activation_date = datetime.utcnow()
            existing_activation.ip_address = ip_address
            existing_activation.is_active = True
            self.db.commit()
            
            # Update license with hardware information if not set
            if not license_obj.hardware_fingerprint:
                license_obj.hardware_fingerprint = hardware_fingerprint
                license_obj.activated_at = datetime.utcnow()
                self.db.commit()
                self.db.refresh(license_obj)
                
            return True, "License re-activated successfully", license_obj
        
        # Check if we've reached the maximum number of devices
        active_activations = self.db.query(LicenseActivation).filter(
            LicenseActivation.license_id == license_obj.id,
            LicenseActivation.is_active == True
        ).count()
        
        if active_activations >= license_obj.max_devices:
            return False, f"Maximum number of devices ({license_obj.max_devices}) reached", license_obj
        
        # Create new activation record
        activation = LicenseActivation(
            license_id=license_obj.id,
            activation_date=datetime.utcnow(),
            device_name=device_name,
            device_id=hardware_fingerprint,
            ip_address=ip_address,
            is_active=True
        )
        
        self.db.add(activation)
        
        # Update license with hardware information if not set
        if not license_obj.hardware_fingerprint:
            license_obj.hardware_fingerprint = hardware_fingerprint
            license_obj.activated_at = datetime.utcnow()
        
        # Update validation info
        license_obj.update_validation(ip_address)
        
        self.db.commit()
        self.db.refresh(license_obj)
        
        logger.info(f"Activated license {license_key} for device {device_name}")
        return True, "License activated successfully", license_obj
    
    def deactivate_license(self, license_key: str) -> Tuple[bool, str]:
        """
        Deactivate a license.
        
        Args:
            license_key: The license key to deactivate
            
        Returns:
            Tuple of (success, message)
        """
        license_obj = self.get_license_by_key(license_key)
        if not license_obj:
            return False, "License key not found"
        
        license_obj.is_active = False
        
        # Deactivate all activations
        activations = self.db.query(LicenseActivation).filter(
            LicenseActivation.license_id == license_obj.id,
            LicenseActivation.is_active == True
        ).all()
        
        for activation in activations:
            activation.is_active = False
        
        self.db.commit()
        logger.info(f"Deactivated license {license_key}")
        return True, "License deactivated successfully"
    
    def validate_current_license(self) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Validate the currently active license.
        
        Returns:
            Tuple of (is_valid, message, license_data)
        """
        license_obj = self.get_active_license()
        if not license_obj:
            return False, "No active license found", None
        
        # Check if license is expired
        if license_obj.is_expired():
            return False, "License has expired", {
                "license_key": license_obj.license_key,
                "expires_at": license_obj.expires_at.isoformat() if license_obj.expires_at else None,
                "days_left": 0,
                "license_type": license_obj.license_type
            }
        
        # Update validation count and time
        license_obj.update_validation()
        self.db.commit()
        
        # Return license information
        license_data = {
            "license_key": license_obj.license_key,
            "organization": license_obj.organization_name,
            "email": license_obj.organization_email,
            "created_at": license_obj.created_at.isoformat() if license_obj.created_at else None,
            "activated_at": license_obj.activated_at.isoformat() if license_obj.activated_at else None,
            "expires_at": license_obj.expires_at.isoformat() if license_obj.expires_at else None,
            "days_left": license_obj.days_until_expiration(),
            "license_type": license_obj.license_type,
            "max_devices": license_obj.max_devices,
            "max_users": license_obj.max_users,
            "is_trial": license_obj.is_trial,
            "features": json.loads(license_obj.features) if license_obj.features else {}
        }
        
        return True, "License is valid", license_data
    
    def check_feature_availability(self, feature_name: str) -> bool:
        """
        Check if a specific feature is available in the current license.
        
        Args:
            feature_name: Name of the feature to check
            
        Returns:
            True if the feature is available, False otherwise
        """
        license_obj = self.get_active_license()
        if not license_obj:
            return False
        
        if license_obj.is_expired() or not license_obj.is_active:
            return False
        
        return license_obj.has_feature(feature_name)
    
    def get_license_status(self) -> Dict[str, Any]:
        """
        Get the current license status information.
        
        Returns:
            Dictionary with license status information
        """
        license_obj = self.get_active_license()
        if not license_obj:
            return {
                "has_license": False,
                "status": "No license",
                "type": None,
                "expires_in": None,
                "features_available": []
            }
        
        features = json.loads(license_obj.features) if license_obj.features else {}
        enabled_features = features.get("enabled_features", [])
        
        status = "Valid"
        if license_obj.is_expired():
            status = "Expired"
        elif not license_obj.is_active:
            status = "Inactive"
        
        return {
            "has_license": True,
            "status": status,
            "type": license_obj.license_type,
            "is_trial": license_obj.is_trial,
            "expires_in": license_obj.days_until_expiration(),
            "organization": license_obj.organization_name,
            "features_available": enabled_features
        }

    def get_license_activations(self, license_key: str) -> List[Dict[str, Any]]:
        """
        Get all activations for a license.
        
        Args:
            license_key: The license key to get activations for
            
        Returns:
            List of activation dictionaries
        """
        license_obj = self.get_license_by_key(license_key)
        if not license_obj:
            return []
        
        activations = self.db.query(LicenseActivation).filter(
            LicenseActivation.license_id == license_obj.id
        ).all()
        
        return [
            {
                "id": activation.id,
                "device_name": activation.device_name,
                "device_id": activation.device_id,
                "ip_address": activation.ip_address,
                "activation_date": activation.activation_date.isoformat() if activation.activation_date else None,
                "is_active": activation.is_active
            }
            for activation in activations
        ]

    @staticmethod
    def get_license(db: Session, license_id: int) -> Optional[License]:
        """Get license by ID"""
        return db.query(License).filter(License.id == license_id).first()
    
    @staticmethod
    def get_licenses(
        db: Session, 
        skip: int = 0, 
        limit: int = 100,
        is_active: Optional[bool] = None,
        is_trial: Optional[bool] = None,
        organization_name: Optional[str] = None,
        license_type: Optional[str] = None
    ) -> List[License]:
        """Get list of licenses with optional filters"""
        query = db.query(License)
        
        if is_active is not None:
            query = query.filter(License.is_active == is_active)
        
        if is_trial is not None:
            query = query.filter(License.is_trial == is_trial)
            
        if organization_name:
            query = query.filter(License.organization_name.ilike(f"%{organization_name}%"))
            
        if license_type:
            query = query.filter(License.license_type == license_type)
            
        return query.order_by(License.created_at.desc()).offset(skip).limit(limit).all()
    
    @staticmethod
    def create_license(db: Session, license_data: LicenseCreate) -> License:
        """Create a new license"""
        license_dict = license_data.dict(exclude_unset=True)
        
        # Handle expiry_days to calculate expires_at
        expiry_days = license_dict.pop("expiry_days", 365)
        expires_at = datetime.utcnow() + timedelta(days=expiry_days)
        license_dict["expires_at"] = expires_at
        
        db_license = License(**license_dict)
        db.add(db_license)
        db.commit()
        db.refresh(db_license)
        return db_license
    
    @staticmethod
    def update_license(db: Session, license_id: int, license_data: LicenseUpdate) -> Optional[License]:
        """Update an existing license"""
        db_license = LicenseService.get_license(db, license_id)
        if not db_license:
            return None
            
        # Update license fields
        update_data = license_data.dict(exclude_unset=True)
        
        # Handle expiry_days if present
        if "expiry_days" in update_data:
            expiry_days = update_data.pop("expiry_days")
            update_data["expires_at"] = datetime.utcnow() + timedelta(days=expiry_days)
            
        for field, value in update_data.items():
            setattr(db_license, field, value)
            
        db.add(db_license)
        db.commit()
        db.refresh(db_license)
        return db_license
    
    @staticmethod
    def delete_license(db: Session, license_id: int) -> bool:
        """Delete a license"""
        db_license = LicenseService.get_license(db, license_id)
        if not db_license:
            return False
            
        db.delete(db_license)
        db.commit()
        return True
    
    @staticmethod
    def validate_license(
        db: Session, 
        license_key: str, 
        device_id: str,
        device_name: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> Tuple[bool, str, Optional[License]]:
        """
        Validate a license key
        
        Returns:
            Tuple of (is_valid, message, license_object)
        """
        db_license = LicenseService.get_license_by_key(db, license_key)
        
        # Log the validation attempt
        validation_log = LicenseValidationLog(
            license_id=db_license.id if db_license else None,
            device_id=device_id,
            ip_address=ip_address,
            validation_date=datetime.utcnow()
        )
        
        if not db_license:
            validation_log.success = False
            validation_log.validation_message = "License key not found"
            db.add(validation_log)
            db.commit()
            return False, "Invalid license key", None
            
        # Check if license is active
        if not db_license.is_active:
            validation_log.success = False
            validation_log.validation_message = "License is inactive"
            db.add(validation_log)
            db.commit()
            return False, "License is inactive", db_license
            
        # Check if license is expired
        if db_license.is_expired:
            validation_log.success = False
            validation_log.validation_message = "License is expired"
            db.add(validation_log)
            db.commit()
            return False, "License has expired", db_license
            
        # Update license validation stats
        db_license.last_validated = datetime.utcnow()
        db_license.validation_count += 1
            
        # Success case
        validation_log.success = True
        validation_log.validation_message = "License validated successfully"
        db.add(validation_log)
        db.add(db_license)
        db.commit()
        
        return True, "License validated successfully", db_license
    
    @staticmethod
    def activate_license(
        db: Session,
        license_key: str,
        activation_data: LicenseActivationCreate
    ) -> Tuple[bool, str, Optional[LicenseActivation]]:
        """
        Activate a license for a device
        
        Returns:
            Tuple of (success, message, activation_object)
        """
        db_license = LicenseService.get_license_by_key(db, license_key)
        
        if not db_license:
            return False, "Invalid license key", None
            
        # Check if license is active
        if not db_license.is_active:
            return False, "License is inactive", None
            
        # Check if license is expired
        if db_license.is_expired:
            return False, "License has expired", None
            
        # Check if device already activated
        existing_activation = (
            db.query(LicenseActivation)
            .filter(
                LicenseActivation.license_id == db_license.id,
                LicenseActivation.device_id == activation_data.device_id
            )
            .first()
        )
        
        if existing_activation:
            # Update last seen
            existing_activation.last_seen = datetime.utcnow()
            
            # If inactive, reactivate
            if not existing_activation.is_active:
                existing_activation.is_active = True
                existing_activation.device_name = activation_data.device_name
                existing_activation.ip_address = activation_data.ip_address
                db.add(existing_activation)
                db.commit()
                db.refresh(existing_activation)
                return True, "Device reactivated successfully", existing_activation
                
            # Already active
            db.add(existing_activation)
            db.commit()
            return True, "Device already activated", existing_activation
            
        # Check if max devices reached
        active_count = sum(1 for a in db_license.activations if a.is_active)
        if active_count >= db_license.max_devices:
            return False, f"Maximum devices ({db_license.max_devices}) reached", None
            
        # Create new activation
        activation = LicenseActivation(
            license_id=db_license.id,
            device_id=activation_data.device_id,
            device_name=activation_data.device_name,
            ip_address=activation_data.ip_address,
            is_active=True,
            last_seen=datetime.utcnow()
        )
        
        db.add(activation)
        db.commit()
        db.refresh(activation)
        
        return True, "Device activated successfully", activation
    
    @staticmethod
    def deactivate_device(db: Session, license_key: str, device_id: str) -> bool:
        """Deactivate a device for a license"""
        db_license = LicenseService.get_license_by_key(db, license_key)
        
        if not db_license:
            return False
            
        activation = (
            db.query(LicenseActivation)
            .filter(
                LicenseActivation.license_id == db_license.id,
                LicenseActivation.device_id == device_id,
                LicenseActivation.is_active == True
            )
            .first()
        )
        
        if not activation:
            return False
            
        activation.is_active = False
        db.add(activation)
        db.commit()
        
        return True
    
    @staticmethod
    def get_license_activations(db: Session, license_id: int, active_only: bool = False) -> List[LicenseActivation]:
        """Get all activations for a license"""
        query = db.query(LicenseActivation).filter(LicenseActivation.license_id == license_id)
        
        if active_only:
            query = query.filter(LicenseActivation.is_active == True)
            
        return query.all()
    
    @staticmethod
    def get_license_validation_logs(
        db: Session, 
        license_id: int, 
        skip: int = 0, 
        limit: int = 100
    ) -> List[LicenseValidationLog]:
        """Get validation logs for a license"""
        return (
            db.query(LicenseValidationLog)
            .filter(LicenseValidationLog.license_id == license_id)
            .order_by(LicenseValidationLog.validation_date.desc())
            .offset(skip)
            .limit(limit)
            .all()
        ) 