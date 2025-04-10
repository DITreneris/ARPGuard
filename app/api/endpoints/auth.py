from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from typing import List
from datetime import datetime
from app.core.auth import (
    session_manager,
    mfa_manager,
    verify_mfa,
    get_current_user,
    require_mfa
)
from app.schemas.auth import (
    SessionResponse,
    SessionActivityResponse,
    MFASetupResponse,
    MFAVerifyRequest
)

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    current_user: dict = Depends(get_current_user)
):
    """Setup MFA for the current user"""
    secret = mfa_manager.generate_mfa_secret(current_user["id"])
    qr_code = mfa_manager.generate_qr_code(current_user["id"], secret)
    backup_codes = mfa_manager.generate_backup_codes(current_user["id"])
    
    return {
        "secret": secret,
        "qr_code": qr_code,
        "backup_codes": backup_codes
    }

@router.post("/mfa/verify")
async def verify_mfa_code(
    request: MFAVerifyRequest,
    current_user: dict = Depends(get_current_user)
):
    """Verify MFA code"""
    if verify_mfa(current_user["id"], request.code):
        session = session_manager.get_session(request.session_id)
        if session:
            session.mfa_verified = True
            return {"status": "success", "message": "MFA verification successful"}
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid MFA code"
    )

@router.get("/sessions", response_model=List[SessionResponse])
async def get_sessions(
    current_user: dict = Depends(get_current_user)
):
    """Get all active sessions for the current user"""
    sessions = session_manager.get_user_sessions(current_user["id"])
    return [
        {
            "session_id": session.session_id,
            "created_at": session.created_at,
            "last_activity": session.last_activity,
            "ip_address": session.ip_address,
            "user_agent": session.user_agent,
            "status": session.status,
            "mfa_verified": session.mfa_verified
        }
        for session in sessions
    ]

@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Revoke a specific session"""
    session = session_manager.get_session(session_id)
    if not session or session.user_id != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    session_manager.revoke_session(session_id)
    return {"status": "success", "message": "Session revoked successfully"}

@router.get("/sessions/{session_id}/activity", response_model=List[SessionActivityResponse])
async def get_session_activity(
    session_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get activity log for a specific session"""
    session = session_manager.get_session(session_id)
    if not session or session.user_id != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    activities = session_manager.get_session_activity(session_id)
    return [
        {
            "timestamp": activity["timestamp"],
            "action": activity["action"],
            "ip_address": activity["ip_address"]
        }
        for activity in activities
    ]

@router.post("/sessions/{session_id}/activity")
async def log_session_activity(
    session_id: str,
    action: str,
    ip_address: str,
    current_user: dict = Depends(get_current_user)
):
    """Log activity for a specific session"""
    session = session_manager.get_session(session_id)
    if not session or session.user_id != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    session_manager.update_session_activity(session_id, action, ip_address)
    return {"status": "success", "message": "Activity logged successfully"} 