from sqlalchemy import Column, String, DateTime, ForeignKey, Boolean, Text, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.database import Base

class Session(Base):
    """
    Database model for user sessions
    """
    __tablename__ = "sessions"

    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_activity = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    token_hash = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    mfa_verified = Column(Boolean, default=False)
    
    # Relationship to User model
    user = relationship("User", back_populates="sessions")
    # Relationship to SessionActivity model
    activities = relationship("SessionActivity", back_populates="session", cascade="all, delete-orphan")

    def is_valid(self) -> bool:
        """Check if the session is valid"""
        return self.is_active and datetime.utcnow() < self.expires_at


class SessionActivity(Base):
    """
    Database model for tracking session activities
    """
    __tablename__ = "session_activities"

    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("sessions.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action = Column(String, nullable=False)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    details = Column(JSON, nullable=True)
    
    # Relationship to Session model
    session = relationship("Session", back_populates="activities") 