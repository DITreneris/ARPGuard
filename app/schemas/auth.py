from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

class Token(BaseModel):
    """
    Token response model after authentication
    """
    access_token: str
    token_type: str
    session_id: str
    mfa_required: bool = False

class User(BaseModel):
    """
    User model
    """
    id: str
    username: str
    email: str
    full_name: Optional[str] = None
    disabled: bool = False
    mfa_enabled: bool = False
    
    class Config:
        from_attributes = True

class MFAVerifyRequest(BaseModel):
    """
    Request model for MFA verification
    """
    session_id: str
    code: str

class MFAVerifyResponse(BaseModel):
    """
    Response model for MFA verification
    """
    verified: bool
    session_id: str

class MFASetupResponse(BaseModel):
    """
    Response model for MFA setup
    """
    secret: str
    qr_code: str
    backup_codes: List[str]

class SessionActivity(BaseModel):
    """
    Session activity model
    """
    activity_id: str
    session_id: str
    timestamp: datetime
    action: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

class SessionResponse(BaseModel):
    """
    Session response model
    """
    session_id: str
    created_at: datetime
    last_activity: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    status: str = "active"
    current: bool = False

class SessionListResponse(BaseModel):
    """
    Response model for listing sessions
    """
    sessions: List[SessionResponse]

class SessionActivityResponse(BaseModel):
    """
    Response model for session activities
    """
    activities: List[SessionActivity]

class SessionCreate(BaseModel):
    user_id: str
    ip_address: str
    user_agent: str

class SessionUpdate(BaseModel):
    status: Optional[str] = None
    mfa_verified: Optional[bool] = None

class SessionActivityCreate(BaseModel):
    action: str
    ip_address: str 