from datetime import datetime, timedelta
from typing import Dict, List, Optional
import secrets
import pyotp
import qrcode
from fastapi import HTTPException, status, Request, Depends
from pydantic import BaseModel
from app.core.config import settings
import os
import time
import uuid
import base64
import hashlib
import jwt
from io import BytesIO
from fastapi.security import OAuth2PasswordBearer

# Configure JWT settings
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")  # In production, use environment variable
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 configuration
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# In-memory storage (in a real app, this would be a database)
users_db = {
    "test_user": {
        "id": "user-1",
        "username": "test_user",
        "password": "test_password",  # In real app, store hashed passwords
        "email": "test@example.com",
        "mfa_enabled": False,
        "mfa_secret": None,
        "backup_codes": []
    }
}

class Session(BaseModel):
    session_id: str
    user_id: str
    created_at: datetime
    last_activity: datetime
    ip_address: str
    user_agent: str
    status: str
    mfa_verified: bool = False

class SessionManager:
    def __init__(self):
        self.sessions: Dict[str, Session] = {}
        self.session_timeout = timedelta(hours=1)
        self.activity_log: Dict[str, List[Dict]] = {}
        self.user_sessions = {}

    def create_session(self, user_id: str, ip_address: str, user_agent: str) -> Session:
        session_id = str(uuid.uuid4())
        now = datetime.utcnow()
        
        session = Session(
            session_id=session_id,
            user_id=user_id,
            created_at=now,
            last_activity=now,
            ip_address=ip_address,
            user_agent=user_agent,
            status="active"
        )
        
        self.sessions[session_id] = session
        self.activity_log[session_id] = [{
            "timestamp": now,
            "action": "login",
            "ip_address": ip_address
        }]
        
        # Track sessions by user
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = []
        self.user_sessions[user_id].append(session)
        
        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        session = self.sessions.get(session_id)
        if session and self._is_session_valid(session):
            return session
        return None

    def update_session_activity(self, session_id: str, action: str, ip_address: str):
        session = self.get_session(session_id)
        if session:
            session.last_activity = datetime.utcnow()
            self.activity_log[session_id].append({
                "timestamp": session.last_activity,
                "action": action,
                "ip_address": ip_address
            })

    def revoke_session(self, session_id: str):
        if session_id in self.sessions:
            self.sessions[session_id].status = "revoked"

    def get_user_sessions(self, user_id: str) -> List[Session]:
        if user_id not in self.user_sessions:
            return []
            
        # Filter out inactive/expired sessions
        active_sessions = [
            session for session in self.user_sessions[user_id]
            if session.user_id == user_id and session.status == "active" and session.expires_at >= datetime.now()
        ]
        
        return active_sessions

    def get_session_activity(self, session_id: str) -> List[Dict]:
        return self.activity_log.get(session_id, [])

    def _is_session_valid(self, session: Session) -> bool:
        if session.status != "active":
            return False
        if datetime.utcnow() - session.last_activity > self.session_timeout:
            session.status = "expired"
            return False
        return True

class MFAManager:
    def __init__(self):
        self.totp = pyotp.TOTP(settings.MFA_SECRET_KEY)
        self.backup_codes: Dict[str, List[str]] = {}
        self.issuer = "ARPGuard"

    def generate_mfa_secret(self, user_id: str) -> str:
        secret = pyotp.random_base32()
        
        # In a real app, store this in the database
        if user_id in users_db:
            users_db[user_id]["mfa_secret"] = secret
            users_db[user_id]["mfa_enabled"] = True
        
        return secret

    def generate_qr_code(self, user_id: str, secret: str) -> str:
        user = users_db.get(user_id, {})
        username = user.get("username", user_id)
        
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(username, issuer_name=self.issuer)
        
        # Generate QR code
        img = qrcode.make(provisioning_uri)
        buffer = BytesIO()
        img.save(buffer)
        
        # Return as base64 string
        return base64.b64encode(buffer.getvalue()).decode("utf-8")

    def verify_mfa_code(self, user_id: str, code: str) -> bool:
        return self.totp.verify(code)

    def generate_backup_codes(self, user_id: str, count=10) -> List[str]:
        backup_codes = []
        
        for _ in range(count):
            # Generate a random 8-character code
            code = base64.b32encode(os.urandom(5)).decode("utf-8")[:8]
            backup_codes.append(code)
        
        # In a real app, store these hashed in the database
        if user_id in users_db:
            users_db[user_id]["backup_codes"] = backup_codes
        
        return backup_codes

    def verify_backup_code(self, user_id: str, code: str) -> bool:
        if user_id in self.backup_codes and code in self.backup_codes[user_id]:
            self.backup_codes[user_id].remove(code)
            return True
        return False

    def verify_code(self, user_id: str, code: str) -> bool:
        """Verify an MFA code"""
        user = users_db.get(user_id)
        if not user or not user.get("mfa_enabled") or not user.get("mfa_secret"):
            return False
        
        # Check TOTP code
        totp = pyotp.TOTP(user["mfa_secret"])
        if totp.verify(code):
            return True
        
        # Check backup codes
        if code in user.get("backup_codes", []):
            # In a real app, remove the used backup code
            user["backup_codes"].remove(code)
            return True
        
        return False

# Global instances
session_manager = SessionManager()
mfa_manager = MFAManager()

def create_access_token(data: dict, expires_delta: timedelta = None):
    """Create a JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> dict:
    # ... existing token verification code ...
    pass

def get_current_user(token: str = Depends(oauth2_scheme)):
    """Get the current user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        
        user = users_db.get(username)
        if user is None:
            raise credentials_exception
            
        return user
    except jwt.PyJWTError:
        raise credentials_exception

def require_mfa(user = Depends(get_current_user), session_id: str = None):
    """Require MFA verification for the current user"""
    if not user.get("mfa_enabled"):
        return user
    
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session ID required for MFA verification"
        )
    
    session = session_manager.get_session(session_id)
    if not session or session.user_id != user["id"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    if not session.mfa_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA verification required",
            headers={"X-MFA-Required": "true"},
        )
    
    return user

def verify_mfa(user_id: str, code: str) -> bool:
    if not require_mfa(user_id):
        return True
    
    if mfa_manager.verify_code(user_id, code):
        return True
    
    if mfa_manager.verify_backup_code(user_id, code):
        return True
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid MFA code"
    )

def authenticate_user(request: Request, username: str, password: str):
    """Authenticate a user and create a session"""
    user = users_db.get(username)
    
    if not user:
        return None
    
    # In a real app, use secure password verification
    if user["password"] != password:
        return None
        
    # Create session
    ip_address = request.client.host
    user_agent = request.headers.get("User-Agent", "")
    session = session_manager.create_session(user["id"], ip_address, user_agent)
    
    # Create token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": username, "session_id": session.session_id},
        expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "session_id": session.session_id,
        "mfa_required": user.get("mfa_enabled", False)
    } 