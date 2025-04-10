"""
API endpoints for license management.
"""
from typing import List, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query, Path
from sqlalchemy.orm import Session

from app.api import deps
from app.schemas.license import (
    License, LicenseCreate, LicenseUpdate, LicenseWithDetails,
    LicenseActivation, LicenseActivationCreate, LicenseValidationLog,
    LicenseActivationRequest, LicenseValidationRequest, GenericResponse
)
from app.crud.license import license_crud, activation_crud, validation_log_crud
from app.core.security import validate_admin_access

router = APIRouter()


@router.post("/", response_model=License, status_code=201)
def create_license(
    license_in: LicenseCreate,
    db: Session = Depends(deps.get_db),
    _: bool = Depends(validate_admin_access)
):
    """
    Create a new license.
    Requires admin access.
    """
    return license_crud.create(db, obj_in=license_in)


@router.get("/", response_model=List[License])
def list_licenses(
    skip: int = 0,
    limit: int = 100,
    is_active: Optional[bool] = None,
    is_trial: Optional[bool] = None,
    license_type: Optional[str] = None,
    organization_name: Optional[str] = None,
    db: Session = Depends(deps.get_db),
    _: bool = Depends(validate_admin_access)
):
    """
    Retrieve all licenses with optional filtering.
    Requires admin access.
    """
    filters = {}
    if is_active is not None:
        filters["is_active"] = is_active
    if is_trial is not None:
        filters["is_trial"] = is_trial
    if license_type:
        filters["license_type"] = license_type
    if organization_name:
        filters["organization_name"] = {"ilike": f"%{organization_name}%"}
    
    return license_crud.get_multi(db, skip=skip, limit=limit, filters=filters)


@router.get("/{license_id}", response_model=LicenseWithDetails)
def get_license(
    license_id: int = Path(..., title="The ID of the license to get"),
    db: Session = Depends(deps.get_db),
    _: bool = Depends(validate_admin_access)
):
    """
    Get details of a specific license.
    Requires admin access.
    """
    license = license_crud.get(db, id=license_id)
    if not license:
        raise HTTPException(status_code=404, detail="License not found")
    return license


@router.put("/{license_id}", response_model=License)
def update_license(
    license_in: LicenseUpdate,
    license_id: int = Path(..., title="The ID of the license to update"),
    db: Session = Depends(deps.get_db),
    _: bool = Depends(validate_admin_access)
):
    """
    Update a license.
    Requires admin access.
    """
    license = license_crud.get(db, id=license_id)
    if not license:
        raise HTTPException(status_code=404, detail="License not found")
    return license_crud.update(db, db_obj=license, obj_in=license_in)


@router.delete("/{license_id}", response_model=GenericResponse)
def delete_license(
    license_id: int = Path(..., title="The ID of the license to delete"),
    db: Session = Depends(deps.get_db),
    _: bool = Depends(validate_admin_access)
):
    """
    Delete a license.
    Requires admin access.
    """
    license = license_crud.get(db, id=license_id)
    if not license:
        raise HTTPException(status_code=404, detail="License not found")
    license_crud.remove(db, id=license_id)
    return {"success": True, "message": "License deleted successfully"}


@router.post("/validate", response_model=GenericResponse)
def validate_license(
    validation_request: LicenseValidationRequest,
    db: Session = Depends(deps.get_db)
):
    """
    Validate a license key.
    """
    # Find the license by key
    license = license_crud.get_by_key(db, license_key=validation_request.license_key)
    if not license:
        validation_log_crud.create_validation_log(
            db, 
            license_id=None,
            device_id=validation_request.device_id,
            ip_address=validation_request.ip_address,
            success=False,
            message="Invalid license key"
        )
        raise HTTPException(status_code=400, detail="Invalid license key")
    
    # Check if license is active
    if not license.is_active:
        validation_log_crud.create_validation_log(
            db, 
            license_id=license.id,
            device_id=validation_request.device_id,
            ip_address=validation_request.ip_address,
            success=False,
            message="License is not active"
        )
        raise HTTPException(status_code=400, detail="License is not active")
    
    # Check if license is expired
    if license.is_expired:
        validation_log_crud.create_validation_log(
            db, 
            license_id=license.id,
            device_id=validation_request.device_id,
            ip_address=validation_request.ip_address,
            success=False,
            message="License has expired"
        )
        raise HTTPException(status_code=400, detail="License has expired")
    
    # Update license validation count and last validated date
    license_crud.update_validation_stats(db, license_id=license.id)
    
    # Log successful validation
    validation_log_crud.create_validation_log(
        db, 
        license_id=license.id,
        device_id=validation_request.device_id,
        ip_address=validation_request.ip_address,
        success=True,
        message="License validated successfully"
    )
    
    return {
        "success": True,
        "message": "License validated successfully",
        "data": {
            "license_type": license.license_type,
            "organization_name": license.organization_name,
            "expires_at": license.expires_at,
            "days_remaining": license.days_remaining,
            "allowed_features": license.allowed_features
        }
    }


@router.post("/activate", response_model=LicenseActivation)
def activate_license(
    activation_request: LicenseActivationRequest,
    db: Session = Depends(deps.get_db)
):
    """
    Activate a license for a specific device.
    """
    # Find the license by key
    license = license_crud.get_by_key(db, license_key=activation_request.license_key)
    if not license:
        raise HTTPException(status_code=400, detail="Invalid license key")
    
    # Check if license is active and not expired
    if not license.is_active:
        raise HTTPException(status_code=400, detail="License is not active")
    
    if license.is_expired:
        raise HTTPException(status_code=400, detail="License has expired")
    
    # Check if maximum device limit is reached
    if license.activation_count >= license.max_devices:
        # Check if this device is already activated
        existing_activation = activation_crud.get_by_license_and_device(
            db, license_id=license.id, device_id=activation_request.device_id
        )
        if not existing_activation:
            raise HTTPException(
                status_code=400, 
                detail=f"Maximum device limit reached ({license.max_devices})"
            )
        
        # If device is already activated but deactivated, reactivate it
        if not existing_activation.is_active:
            return activation_crud.update(
                db, 
                db_obj=existing_activation, 
                obj_in={"is_active": True, "last_seen": datetime.utcnow()}
            )
        
        # Update last seen time for existing activation
        return activation_crud.update(
            db, 
            db_obj=existing_activation, 
            obj_in={"last_seen": datetime.utcnow()}
        )
    
    # Create a new activation
    activation_data = LicenseActivationCreate(
        license_id=license.id,
        device_name=activation_request.device_name,
        device_id=activation_request.device_id,
        ip_address=activation_request.ip_address
    )
    
    return activation_crud.create(db, obj_in=activation_data)


@router.post("/deactivate", response_model=GenericResponse)
def deactivate_license(
    deactivation_request: LicenseActivationRequest,
    db: Session = Depends(deps.get_db)
):
    """
    Deactivate a license for a specific device.
    """
    # Find the license by key
    license = license_crud.get_by_key(db, license_key=deactivation_request.license_key)
    if not license:
        raise HTTPException(status_code=400, detail="Invalid license key")
    
    # Find the activation
    activation = activation_crud.get_by_license_and_device(
        db, license_id=license.id, device_id=deactivation_request.device_id
    )
    
    if not activation:
        raise HTTPException(status_code=404, detail="Device not found in activated devices")
    
    # Deactivate the license for this device
    activation_crud.update(db, db_obj=activation, obj_in={"is_active": False})
    
    return {"success": True, "message": "License deactivated successfully"}


@router.get("/{license_id}/activations", response_model=List[LicenseActivation])
def get_license_activations(
    license_id: int = Path(..., title="The ID of the license"),
    active_only: bool = Query(False, title="Filter by active status"),
    db: Session = Depends(deps.get_db),
    _: bool = Depends(validate_admin_access)
):
    """
    Get all activations for a specific license.
    Requires admin access.
    """
    license = license_crud.get(db, id=license_id)
    if not license:
        raise HTTPException(status_code=404, detail="License not found")
    
    filters = {"license_id": license_id}
    if active_only:
        filters["is_active"] = True
        
    return activation_crud.get_multi(db, filters=filters)


@router.get("/{license_id}/validation-logs", response_model=List[LicenseValidationLog])
def get_license_validation_logs(
    license_id: int = Path(..., title="The ID of the license"),
    success_only: Optional[bool] = Query(None, title="Filter by validation success"),
    days: int = Query(7, title="Number of days to look back"),
    db: Session = Depends(deps.get_db),
    _: bool = Depends(validate_admin_access)
):
    """
    Get all validation logs for a specific license.
    Requires admin access.
    """
    license = license_crud.get(db, id=license_id)
    if not license:
        raise HTTPException(status_code=404, detail="License not found")
    
    filters = {
        "license_id": license_id,
        "validation_date": {">=": datetime.utcnow() - timedelta(days=days)}
    }
    
    if success_only is not None:
        filters["success"] = success_only
        
    return validation_log_crud.get_multi(db, filters=filters) 