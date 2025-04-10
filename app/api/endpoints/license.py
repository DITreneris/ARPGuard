"""
License management API endpoints
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api import deps
from app.schemas.license import (
    License, LicenseCreate, LicenseUpdate,
    LicenseActivationResponse, LicenseActivation,
    LicenseValidationRequest, LicenseValidationResponse,
    LicenseActivationRequest, LicenseDeactivationRequest, 
    LicenseDeactivationResponse
)
from app.crud.license import (
    create_license, get_license, get_licenses, update_license, 
    delete_license, validate_license, activate_license, 
    deactivate_license
)

router = APIRouter()


@router.post("/", response_model=License, status_code=status.HTTP_201_CREATED)
def create_new_license(
    license_in: LicenseCreate,
    db: Session = Depends(deps.get_db),
    current_user: dict = Depends(deps.get_current_active_admin)
):
    """
    Create a new license.
    Only administrators can create licenses.
    """
    return create_license(db=db, license_in=license_in)


@router.get("/", response_model=List[License])
def read_licenses(
    skip: int = 0,
    limit: int = 100,
    is_active: Optional[bool] = None,
    is_trial: Optional[bool] = None,
    license_type: Optional[str] = None,
    db: Session = Depends(deps.get_db),
    current_user: dict = Depends(deps.get_current_active_admin)
):
    """
    Retrieve licenses.
    Only administrators can view all licenses.
    """
    filters = {}
    if is_active is not None:
        filters["is_active"] = is_active
    if is_trial is not None:
        filters["is_trial"] = is_trial
    if license_type:
        filters["license_type"] = license_type
        
    return get_licenses(db=db, skip=skip, limit=limit, filters=filters)


@router.get("/{license_id}", response_model=License)
def read_license(
    license_id: int,
    db: Session = Depends(deps.get_db),
    current_user: dict = Depends(deps.get_current_active_admin)
):
    """
    Get license by ID.
    Only administrators can view license details.
    """
    db_license = get_license(db=db, license_id=license_id)
    if not db_license:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="License not found"
        )
    return db_license


@router.put("/{license_id}", response_model=License)
def update_existing_license(
    license_id: int,
    license_in: LicenseUpdate,
    db: Session = Depends(deps.get_db),
    current_user: dict = Depends(deps.get_current_active_admin)
):
    """
    Update a license.
    Only administrators can update licenses.
    """
    db_license = get_license(db=db, license_id=license_id)
    if not db_license:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="License not found"
        )
    return update_license(db=db, db_license=db_license, license_in=license_in)


@router.delete("/{license_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_existing_license(
    license_id: int,
    db: Session = Depends(deps.get_db),
    current_user: dict = Depends(deps.get_current_active_admin)
):
    """
    Delete a license.
    Only administrators can delete licenses.
    """
    db_license = get_license(db=db, license_id=license_id)
    if not db_license:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="License not found"
        )
    delete_license(db=db, license_id=license_id)
    return None


@router.post("/validate", response_model=LicenseValidationResponse)
def validate_license_key(
    validation: LicenseValidationRequest,
    db: Session = Depends(deps.get_db)
):
    """
    Validate a license key.
    This endpoint is publicly accessible but logs validation attempts.
    """
    result = validate_license(db=db, validation_data=validation)
    return result


@router.post("/activate", response_model=LicenseActivationResponse)
def activate_license_key(
    activation: LicenseActivationRequest,
    db: Session = Depends(deps.get_db)
):
    """
    Activate a license on a device.
    This endpoint is publicly accessible but requires a valid license key.
    """
    result = activate_license(db=db, activation_data=activation)
    return result


@router.post("/deactivate", response_model=LicenseDeactivationResponse)
def deactivate_license_key(
    deactivation: LicenseDeactivationRequest,
    db: Session = Depends(deps.get_db)
):
    """
    Deactivate a license on a device.
    This endpoint is publicly accessible but requires a valid license key and device ID.
    """
    result = deactivate_license(db=db, deactivation_data=deactivation)
    return result


@router.get("/{license_id}/activations", response_model=List[LicenseActivation])
def read_license_activations(
    license_id: int,
    db: Session = Depends(deps.get_db),
    current_user: dict = Depends(deps.get_current_active_admin)
):
    """
    Retrieve all activations for a specific license.
    Only administrators can view license activations.
    """
    db_license = get_license(db=db, license_id=license_id)
    if not db_license:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="License not found"
        )
    return db_license.activations 