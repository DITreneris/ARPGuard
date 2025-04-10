"""
Pydantic schemas for license management.
"""
from typing import List, Dict, Optional, Any, Union
from datetime import datetime
from pydantic import BaseModel, Field, EmailStr, validator


class GenericResponse(BaseModel):
    """Generic response model for success/error messages"""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None


# Base License Schemas
class LicenseBase(BaseModel):
    """Base schema for License data"""
    license_key: Optional[str] = None
    organization_name: str
    organization_email: EmailStr
    license_type: str = Field(default="standard")
    is_active: bool = Field(default=True)
    is_trial: bool = Field(default=False)
    allowed_features: List[str] = Field(default_factory=list)
    max_devices: int = Field(default=5)
    max_users: int = Field(default=10)
    notes: Optional[str] = None


class LicenseCreate(LicenseBase):
    """Schema for License creation"""
    expiry_days: Optional[int] = Field(default=365)
    
    @validator('expiry_days')
    def validate_expiry_days(cls, v):
        if v is not None and v <= 0:
            raise ValueError("Expiry days must be positive")
        return v


class LicenseUpdate(BaseModel):
    """Schema for License updates"""
    organization_name: Optional[str] = None
    organization_email: Optional[EmailStr] = None
    license_type: Optional[str] = None
    is_active: Optional[bool] = None
    allowed_features: Optional[List[str]] = None
    max_devices: Optional[int] = None
    max_users: Optional[int] = None
    expires_at: Optional[datetime] = None
    notes: Optional[str] = None


class License(LicenseBase):
    """Schema for License response"""
    id: int
    license_key: str
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    validation_count: int = 0
    last_validated: Optional[datetime] = None
    is_expired: bool = False
    days_remaining: int = 0
    
    class Config:
        orm_mode = True


class LicenseWithDetails(License):
    """License schema with activation details"""
    activation_count: int = 0
    active_activation_count: int = 0
    
    class Config:
        orm_mode = True


# License Activation Schemas
class LicenseActivationBase(BaseModel):
    """Base schema for License Activation"""
    license_id: int
    device_name: str
    device_id: str
    ip_address: Optional[str] = None
    is_active: bool = True


class LicenseActivationCreate(LicenseActivationBase):
    """Schema for License Activation creation"""
    pass


class LicenseActivation(LicenseActivationBase):
    """Schema for License Activation response"""
    id: int
    created_at: datetime
    updated_at: datetime
    last_seen: datetime
    
    class Config:
        orm_mode = True


# License Validation Log Schemas
class LicenseValidationLogBase(BaseModel):
    """Base schema for License Validation Log"""
    license_id: Optional[int] = None
    device_id: str
    ip_address: Optional[str] = None
    success: bool = True
    validation_message: Optional[str] = None


class LicenseValidationLogCreate(LicenseValidationLogBase):
    """Schema for License Validation Log creation"""
    pass


class LicenseValidationLog(LicenseValidationLogBase):
    """Schema for License Validation Log response"""
    id: int
    validation_date: datetime
    
    class Config:
        orm_mode = True


# API Request Schemas
class LicenseActivationRequest(BaseModel):
    """Schema for License Activation/Deactivation request"""
    license_key: str
    device_name: str
    device_id: str
    ip_address: Optional[str] = None


class LicenseValidationRequest(BaseModel):
    """Schema for License Validation request"""
    license_key: str
    device_id: str
    ip_address: Optional[str] = None


class LicenseActivationResponse(BaseModel):
    """Schema for license activation response"""
    success: bool
    message: str
    activation: Optional[LicenseActivation] = None


class LicenseDeactivationRequest(BaseModel):
    """Schema for license deactivation request"""
    license_key: str
    device_id: str


class LicenseDeactivationResponse(BaseModel):
    """Schema for license deactivation response"""
    success: bool
    message: str


class LicenseValidationResponse(BaseModel):
    """Schema for license validation response"""
    is_valid: bool
    message: str
    license_data: Optional[Dict[str, Any]] = None 