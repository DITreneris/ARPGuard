"""
CRUD operations for license management.
"""
from typing import List, Optional, Dict, Any, Union
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, func

from app.models.license import License, LicenseActivation, LicenseValidationLog
from app.schemas.license import LicenseCreate, LicenseUpdate


def get_license(db: Session, license_id: int) -> Optional[License]:
    """Get a license by ID."""
    return db.query(License).filter(License.id == license_id).first()


def get_license_by_key(db: Session, license_key: str) -> Optional[License]:
    """Get a license by license key."""
    return db.query(License).filter(License.license_key == license_key).first()


def get_licenses(
    db: Session, 
    skip: int = 0, 
    limit: int = 100, 
    filter_params: Optional[Dict[str, Any]] = None
) -> List[License]:
    """
    Get a list of licenses with optional filtering.
    
    Args:
        db: Database session
        skip: Number of records to skip
        limit: Maximum number of records to return
        filter_params: Optional dictionary with filter parameters:
            - organization_name: Filter by organization name (case insensitive)
            - license_type: Filter by license type
            - is_active: Filter by active status
            - is_expired: Filter by expiration status
            - is_trial: Filter by trial status
    """
    query = db.query(License)
    
    if filter_params:
        if organization_name := filter_params.get("organization_name"):
            query = query.filter(License.organization_name.ilike(f"%{organization_name}%"))
        
        if license_type := filter_params.get("license_type"):
            query = query.filter(License.license_type == license_type)
        
        if "is_active" in filter_params:
            query = query.filter(License.is_active == filter_params["is_active"])
        
        if "is_expired" in filter_params:
            now = datetime.utcnow()
            if filter_params["is_expired"]:
                query = query.filter(License.expires_at < now)
            else:
                query = query.filter(License.expires_at >= now)
        
        if "is_trial" in filter_params:
            query = query.filter(License.is_trial == filter_params["is_trial"])
    
    return query.order_by(License.created_at.desc()).offset(skip).limit(limit).all()


def create_license(db: Session, license_data: LicenseCreate) -> License:
    """
    Create a new license.
    
    Args:
        db: Database session
        license_data: License creation data
    
    Returns:
        The newly created license
    """
    # Calculate expiration date based on days
    expiry_date = datetime.utcnow() + timedelta(days=license_data.expiry_days)
    
    # Create dictionary from license_data excluding 'expiry_days'
    db_license = License(
        organization_name=license_data.organization_name,
        organization_email=license_data.organization_email,
        license_type=license_data.license_type,
        is_trial=license_data.is_trial,
        max_devices=license_data.max_devices,
        max_users=license_data.max_users,
        allowed_features=license_data.allowed_features,
        expires_at=expiry_date,
    )
    
    db.add(db_license)
    db.commit()
    db.refresh(db_license)
    return db_license


def update_license(
    db: Session, 
    license_id: int, 
    license_update: LicenseUpdate
) -> Optional[License]:
    """
    Update an existing license.
    
    Args:
        db: Database session
        license_id: ID of the license to update
        license_update: License update data
    
    Returns:
        The updated license or None if not found
    """
    db_license = get_license(db, license_id)
    if not db_license:
        return None
    
    update_data = license_update.dict(exclude_unset=True)
    
    # Handle expiry_days special case
    if "expiry_days" in update_data:
        expiry_days = update_data.pop("expiry_days")
        update_data["expires_at"] = datetime.utcnow() + timedelta(days=expiry_days)
    
    # Update fields
    for field, value in update_data.items():
        setattr(db_license, field, value)
    
    db.commit()
    db.refresh(db_license)
    return db_license


def delete_license(db: Session, license_id: int) -> bool:
    """
    Delete a license.
    
    Args:
        db: Database session
        license_id: ID of the license to delete
    
    Returns:
        True if license was deleted, False if not found
    """
    db_license = get_license(db, license_id)
    if not db_license:
        return False
    
    db.delete(db_license)
    db.commit()
    return True


def activate_license(
    db: Session, 
    license_key: str, 
    device_name: str,
    device_id: str, 
    ip_address: Optional[str] = None
) -> Dict[str, Any]:
    """
    Activate a license for a specific device.
    
    Args:
        db: Database session
        license_key: License key
        device_name: Name of the device
        device_id: Unique identifier for the device
        ip_address: IP address of the device
    
    Returns:
        Dictionary with activation results
    """
    result = {
        "success": False,
        "message": "",
        "activation": None,
    }
    
    # Find the license
    license = get_license_by_key(db, license_key)
    if not license:
        result["message"] = "Invalid license key"
        return result
    
    # Check if license is active
    if not license.is_active:
        result["message"] = "License is not active"
        return result
    
    # Check if license is expired
    if license.is_expired:
        result["message"] = "License has expired"
        return result
    
    # Check if we've reached the device limit
    if license.activation_count >= license.max_devices:
        # Check if this device is already activated
        existing = db.query(LicenseActivation).filter(
            LicenseActivation.license_id == license.id,
            LicenseActivation.device_id == device_id,
            LicenseActivation.is_active == True
        ).first()
        
        if not existing:
            result["message"] = "Maximum device limit reached"
            return result
    
    # Check if device already has an activation for this license
    activation = db.query(LicenseActivation).filter(
        LicenseActivation.license_id == license.id,
        LicenseActivation.device_id == device_id
    ).first()
    
    if activation:
        # Update existing activation
        activation.is_active = True
        activation.device_name = device_name
        activation.last_seen = datetime.utcnow()
        if ip_address:
            activation.ip_address = ip_address
    else:
        # Create new activation
        activation = LicenseActivation(
            license_id=license.id,
            device_name=device_name,
            device_id=device_id,
            ip_address=ip_address,
            is_active=True,
            last_seen=datetime.utcnow()
        )
        db.add(activation)
    
    db.commit()
    db.refresh(activation)
    
    result["success"] = True
    result["message"] = "License activated successfully"
    result["activation"] = activation
    return result


def deactivate_license(
    db: Session, 
    license_key: str, 
    device_id: str
) -> Dict[str, Any]:
    """
    Deactivate a license for a specific device.
    
    Args:
        db: Database session
        license_key: License key
        device_id: Unique identifier for the device
    
    Returns:
        Dictionary with deactivation results
    """
    result = {
        "success": False,
        "message": "",
    }
    
    # Find the license
    license = get_license_by_key(db, license_key)
    if not license:
        result["message"] = "Invalid license key"
        return result
    
    # Find the activation
    activation = db.query(LicenseActivation).filter(
        LicenseActivation.license_id == license.id,
        LicenseActivation.device_id == device_id
    ).first()
    
    if not activation:
        result["message"] = "No active license found for this device"
        return result
    
    # Deactivate
    activation.is_active = False
    db.commit()
    
    result["success"] = True
    result["message"] = "License deactivated successfully"
    return result


def validate_license(
    db: Session, 
    license_key: str, 
    device_id: Optional[str] = None,
    ip_address: Optional[str] = None
) -> Dict[str, Any]:
    """
    Validate a license and record the validation attempt.
    
    Args:
        db: Database session
        license_key: License key
        device_id: Optional device ID
        ip_address: Optional IP address
    
    Returns:
        Dictionary with validation results
    """
    result = {
        "success": False,
        "message": "",
        "license": None,
    }
    
    # Find the license
    license = get_license_by_key(db, license_key)
    if not license:
        # Log failed validation
        log = LicenseValidationLog(
            license_id=None,
            device_id=device_id,
            ip_address=ip_address,
            success=False,
            validation_message="Invalid license key"
        )
        db.add(log)
        db.commit()
        result["message"] = "Invalid license key"
        return result
    
    # Check if license is active
    if not license.is_active:
        message = "License is not active"
        # Log failed validation
        log = LicenseValidationLog(
            license_id=license.id,
            device_id=device_id,
            ip_address=ip_address,
            success=False,
            validation_message=message
        )
        db.add(log)
        db.commit()
        result["message"] = message
        return result
    
    # Check if license is expired
    if license.is_expired:
        message = "License has expired"
        # Log failed validation
        log = LicenseValidationLog(
            license_id=license.id,
            device_id=device_id,
            ip_address=ip_address,
            success=False,
            validation_message=message
        )
        db.add(log)
        db.commit()
        result["message"] = message
        return result
    
    # Check if device is activated (if device_id is provided)
    if device_id:
        activation = db.query(LicenseActivation).filter(
            LicenseActivation.license_id == license.id,
            LicenseActivation.device_id == device_id,
            LicenseActivation.is_active == True
        ).first()
        
        if not activation:
            message = "Device not activated for this license"
            # Log failed validation
            log = LicenseValidationLog(
                license_id=license.id,
                device_id=device_id,
                ip_address=ip_address,
                success=False,
                validation_message=message
            )
            db.add(log)
            db.commit()
            result["message"] = message
            return result
        
        # Update last_seen timestamp
        activation.last_seen = datetime.utcnow()
        
        # Update IP if provided
        if ip_address:
            activation.ip_address = ip_address
    
    # Update license validation information
    license.last_validated_at = datetime.utcnow()
    license.validation_count += 1
    
    # Log successful validation
    log = LicenseValidationLog(
        license_id=license.id,
        device_id=device_id,
        ip_address=ip_address,
        success=True,
        validation_message="License validated successfully"
    )
    db.add(log)
    
    db.commit()
    db.refresh(license)
    
    result["success"] = True
    result["message"] = "License validated successfully"
    result["license"] = license
    return result


def get_license_activations(
    db: Session, 
    license_id: int, 
    active_only: bool = False
) -> List[LicenseActivation]:
    """
    Get all activations for a specific license.
    
    Args:
        db: Database session
        license_id: ID of the license
        active_only: If True, return only active activations
    
    Returns:
        List of license activations
    """
    query = db.query(LicenseActivation).filter(LicenseActivation.license_id == license_id)
    
    if active_only:
        query = query.filter(LicenseActivation.is_active == True)
    
    return query.order_by(LicenseActivation.last_seen.desc()).all()


def get_license_validation_logs(
    db: Session, 
    license_id: int, 
    skip: int = 0, 
    limit: int = 100
) -> List[LicenseValidationLog]:
    """
    Get validation logs for a specific license.
    
    Args:
        db: Database session
        license_id: ID of the license
        skip: Number of records to skip
        limit: Maximum number of records to return
    
    Returns:
        List of license validation logs
    """
    return db.query(LicenseValidationLog)\
        .filter(LicenseValidationLog.license_id == license_id)\
        .order_by(LicenseValidationLog.validation_date.desc())\
        .offset(skip)\
        .limit(limit)\
        .all() 