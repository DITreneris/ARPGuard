from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.database import Base

class User(Base):
    """
    Database model for users
    """
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    disabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # MFA related fields
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String, nullable=True)
    backup_codes = Column(Text, nullable=True)  # Stored as JSON string
    
    # Failed login attempts tracking
    failed_login_attempts = Column(Integer, default=0)
    last_failed_login = Column(DateTime, nullable=True)
    locked_until = Column(DateTime, nullable=True)
    
    # Relationships
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    
    def is_active(self) -> bool:
        """Check if the user account is active"""
        return not self.disabled
        
    def is_locked(self) -> bool:
        """Check if the account is temporarily locked due to failed login attempts"""
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until 