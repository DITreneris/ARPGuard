"""
Repository for license-related database operations.
"""
from typing import List, Optional, Dict, Any, Union
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func

from app.models.license import License, LicenseActivation, LicenseValidationLog
from app.schemas.license import LicenseCreate, LicenseUpdate, LicenseActivate


class LicenseRepository:
    """Repository for license management operations."""
    
    @staticmethod
    def create_license(db: Session, *, license_in: LicenseCreate) -> License:
        """Create a new license."""
        license_obj = License(
            organization_name=license_in.organization_name,
            organization_email=license_in.organization_email,
            license_type=license_in.license_type,
            max_devices=license_in.max_devices,
            max_users=license_in.max_users,
            is_trial=license_in.is_trial,
            is_active=True,
            allowed_features=license_in.allowed_features
        )
        
        # Set expiry date
        license_obj.set_expiry_days(license_in.expiry_days)
        
        db.add(license_obj)
        db.commit()
        db.refresh(license_obj)
        return license_obj
    
    @staticmethod
    def get_license_by_id(db: Session, license_id: int) -> Optional[License]:
        """Get license by ID."""
        return db.query(License).filter(License.id == license_id).first()
    
    @staticmethod
    def get_license_by_key(db: Session, license_key: str) -> Optional[License]:
        """Get license by license key."""
        return db.query(License).filter(License.license_key == license_key).first()
    
    @staticmethod
    def get_licenses(
        db: Session, 
        *,
        skip: int = 0, 
        limit: int = 100,
        organization_name: Optional[str] = None,
        license_type: Optional[str] = None,
        is_active: Optional[bool] = None,
        is_trial: Optional[bool] = None
    ) -> List[License]:
        """Get all licenses with optional filtering."""
        query = db.query(License)
        
        # Apply filters if provided
        if organization_name:
            query = query.filter(License.organization_name.ilike(f"%{organization_name}%"))
        if license_type:
            query = query.filter(License.license_type == license_type)
        if is_active is not None:
            query = query.filter(License.is_active == is_active)
        if is_trial is not None:
            query = query.filter(License.is_trial == is_trial)
            
        return query.offset(skip).limit(limit).all()
    
    @staticmethod
    def update_license(
        db: Session,
        *,
        db_obj: License,
        obj_in: Union[LicenseUpdate, Dict[str, Any]]
    ) -> License:
        """Update a license."""
        if isinstance(obj_in, dict):
            update_data = obj_in
        else:
            update_data = obj_in.dict(exclude_unset=True)
            
        # Handle special case for expiry_days
        if "expiry_days" in update_data:
            db_obj.set_expiry_days(update_data.pop("expiry_days"))
            
        for field in update_data:
            if hasattr(db_obj, field):
                setattr(db_obj, field, update_data[field])
                
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj
    
    @staticmethod
    def delete_license(db: Session, *, license_id: int) -> bool:
        """Delete a license."""
        license_obj = db.query(License).filter(License.id == license_id).first()
        if not license_obj:
            return False
            
        db.delete(license_obj)
        db.commit()
        return True
    
    @staticmethod
    def activate_license(
        db: Session,
        *,
        license_obj: License,
        device_name: str,
        device_id: str,
        ip_address: Optional[str] = None
    ) -> LicenseActivation:
        """Activate a license for a device."""
        # Check if this device is already activated
        existing_activation = (
            db.query(LicenseActivation)
            .filter(
                LicenseActivation.license_id == license_obj.id,
                LicenseActivation.device_id == device_id
            )
            .first()
        )
        
        if existing_activation:
            # Update the existing activation
            existing_activation.is_active = True
            existing_activation.last_seen = datetime.utcnow()
            db.add(existing_activation)
            db.commit()
            db.refresh(existing_activation)
            return existing_activation
            
        # Create a new activation
        activation = LicenseActivation(
            license_id=license_obj.id,
            device_name=device_name,
            device_id=device_id,
            ip_address=ip_address,
            is_active=True,
            last_seen=datetime.utcnow()
        )
        
        db.add(activation)
        db.commit()
        db.refresh(activation)
        return activation
    
    @staticmethod
    def deactivate_device(db: Session, *, license_id: int, device_id: str) -> bool:
        """Deactivate a device."""
        activation = (
            db.query(LicenseActivation)
            .filter(
                LicenseActivation.license_id == license_id,
                LicenseActivation.device_id == device_id
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
    def get_device_activations(db: Session, *, license_id: int) -> List[LicenseActivation]:
        """Get all device activations for a license."""
        return (
            db.query(LicenseActivation)
            .filter(LicenseActivation.license_id == license_id)
            .all()
        )
    
    @staticmethod
    def log_validation(
        db: Session,
        *,
        license_id: int,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        success: bool = True,
        message: Optional[str] = None
    ) -> LicenseValidationLog:
        """Log a license validation attempt."""
        # Update the license validation count
        license_obj = db.query(License).filter(License.id == license_id).first()
        if license_obj:
            license_obj.last_validated_at = datetime.utcnow()
            license_obj.validation_count += 1
            db.add(license_obj)
            
        # Create validation log
        log_entry = LicenseValidationLog(
            license_id=license_id,
            device_id=device_id,
            ip_address=ip_address,
            success=success,
            validation_message=message
        )
        
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)
        return log_entry
    
    @staticmethod
    def validate_license(
        db: Session,
        *,
        license_key: str,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """Validate a license and return status."""
        license_obj = db.query(License).filter(License.license_key == license_key).first()
        
        if not license_obj:
            return {
                "valid": False,
                "message": "License key not found",
                "license": None
            }
            
        # Check if license is active
        if not license_obj.is_active:
            LicenseRepository.log_validation(
                db, 
                license_id=license_obj.id, 
                device_id=device_id, 
                ip_address=ip_address,
                success=False,
                message="License is not active"
            )
            return {
                "valid": False,
                "message": "License is not active",
                "license": license_obj
            }
            
        # Check if license is expired
        if license_obj.is_expired:
            LicenseRepository.log_validation(
                db, 
                license_id=license_obj.id, 
                device_id=device_id, 
                ip_address=ip_address,
                success=False,
                message="License has expired"
            )
            return {
                "valid": False,
                "message": "License has expired",
                "license": license_obj
            }
            
        # Check device limit if device_id is provided
        if device_id:
            active_count = sum(1 for a in license_obj.activations if a.is_active)
            device_exists = any(a.device_id == device_id for a in license_obj.activations)
            
            if active_count >= license_obj.max_devices and not device_exists:
                LicenseRepository.log_validation(
                    db, 
                    license_id=license_obj.id, 
                    device_id=device_id, 
                    ip_address=ip_address,
                    success=False,
                    message=f"Maximum device limit reached ({license_obj.max_devices})"
                )
                return {
                    "valid": False,
                    "message": f"Maximum device limit reached ({license_obj.max_devices})",
                    "license": license_obj
                }
                
        # License is valid
        LicenseRepository.log_validation(
            db, 
            license_id=license_obj.id, 
            device_id=device_id, 
            ip_address=ip_address,
            success=True,
            message="License is valid"
        )
        
        return {
            "valid": True,
            "message": "License is valid",
            "license": license_obj
        } 