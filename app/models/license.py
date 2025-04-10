"""
License database models for ARP Guard
"""
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, func
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
import uuid

from app.database.base_class import Base


def generate_license_key():
    """Generate a unique license key"""
    return str(uuid.uuid4()).upper().replace("-", "")


class License(Base):
    """License database model"""
    __tablename__ = "licenses"

    id = Column(Integer, primary_key=True, index=True)
    license_key = Column(String(255), unique=True, index=True, nullable=False, default=generate_license_key)
    organization_name = Column(String(255), nullable=False)
    organization_email = Column(String(255), nullable=False)
    license_type = Column(String(50), nullable=False)
    allowed_features = Column(Text, nullable=True)  # Stored as JSON string
    is_active = Column(Boolean, default=True)
    is_trial = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_validated = Column(DateTime, nullable=True)
    validation_count = Column(Integer, default=0)
    max_devices = Column(Integer, default=1)
    max_users = Column(Integer, default=1)
    notes = Column(Text, nullable=True)

    # Relationships
    activations = relationship("LicenseActivation", back_populates="license", cascade="all, delete-orphan")
    validation_logs = relationship("LicenseValidationLog", back_populates="license", cascade="all, delete-orphan")

    @property
    def days_remaining(self):
        """Calculate days remaining until license expires"""
        if not self.expires_at:
            return 0
        
        now = datetime.utcnow()
        if now > self.expires_at:
            return 0
            
        delta = self.expires_at - now
        return delta.days

    @property
    def is_expired(self):
        """Check if license is expired"""
        if not self.expires_at:
            return True
            
        return datetime.utcnow() > self.expires_at

    @property
    def active_device_count(self):
        """Count active device activations"""
        if not self.activations:
            return 0
            
        return sum(1 for a in self.activations if a.is_active)
        
    @property
    def available_activations(self):
        """Calculate available device activations"""
        return max(0, self.max_devices - self.active_device_count)


class LicenseActivation(Base):
    """License activation database model"""
    __tablename__ = "license_activations"

    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(Integer, ForeignKey("licenses.id"), nullable=False)
    device_id = Column(String(255), nullable=False, index=True)
    device_name = Column(String(255), nullable=False)
    ip_address = Column(String(50), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_seen = Column(DateTime, nullable=True)

    # Relationships
    license = relationship("License", back_populates="activations")

    class Config:
        unique_together = (("license_id", "device_id"),)


class LicenseValidationLog(Base):
    """License validation log database model"""
    __tablename__ = "license_validation_logs"

    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(Integer, ForeignKey("licenses.id"), nullable=True)
    device_id = Column(String(255), nullable=False)
    ip_address = Column(String(50), nullable=True)
    validation_date = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean, default=False)
    validation_message = Column(Text, nullable=True)

    # Relationships
    license = relationship("License", back_populates="validation_logs") 