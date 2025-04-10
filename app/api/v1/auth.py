from fastapi import APIRouter, Depends, HTTPException, Request, Body, status
from fastapi.security import OAuth2PasswordRequestForm
from typing import List, Dict, Any, Optional

from app.core.auth import (
    authenticate_user,
    get_current_user,
    create_access_token,
    verify_mfa,
    require_mfa,
    session_manager,
    mfa_manager
)
from app.schemas.auth import (
    Token,
    User,
    MFASetupResponse,
    MFAVerifyRequest,
    MFAVerifyResponse,
    SessionResponse,
    SessionActivityResponse,
    SessionListResponse
)

router = APIRouter(prefix="/auth", tags=["authentication"])

@router.post("/login", response_model=Token)
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends()
):
    """
    Authenticate user and create a new session
    """
    user = authenticate_user(
        form_data.username, 
        form_data.password,
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent", "")
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token = create_access_token(data={"sub": user.username})
    
    # Get the latest session
    session = session_manager.get_latest_user_session(user.id)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "session_id": session.session_id,
        "mfa_required": user.mfa_enabled and not session.mfa_verified
    }

@router.post("/mfa/verify", response_model=MFAVerifyResponse)
async def verify_mfa_code(
    request: MFAVerifyRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Verify MFA code and update session status
    """
    # Verify the session exists and belongs to the current user
    session = session_manager.get_session(request.session_id)
    if not session or session.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    # Verify the MFA code
    if mfa_manager.verify_code(current_user.id, request.code):
        session_manager.update_session(
            request.session_id,
            {"mfa_verified": True}
        )
        return {
            "verified": True,
            "session_id": request.session_id
        }
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid MFA code"
    )

@router.get("/sessions", response_model=SessionListResponse)
async def list_sessions(
    current_user: User = Depends(get_current_user)
):
    """
    List all active sessions for the current user
    """
    sessions = session_manager.get_user_sessions(current_user.id)
    
    # Determine which session is the current one
    current_session = session_manager.get_current_session()
    
    session_list = []
    for session in sessions:
        session_data = {
            "session_id": session.session_id,
            "created_at": session.created_at,
            "last_activity": session.last_activity,
            "ip_address": session.ip_address,
            "user_agent": session.user_agent,
            "status": "active" if session.status == "active" else "inactive",
            "current": session.session_id == current_session.session_id if current_session else False
        }
        session_list.append(session_data)
    
    return {"sessions": session_list}

@router.post("/sessions/{session_id}/revoke", status_code=status.HTTP_200_OK)
async def revoke_session(
    session_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Revoke a specific session
    """
    session = session_manager.get_session(session_id)
    if not session or session.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    session_manager.revoke_session(session_id)
    return {"success": True, "message": "Session revoked successfully"}

@router.get("/sessions/{session_id}/activity", response_model=SessionActivityResponse)
async def get_session_activity(
    session_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get activity log for a specific session
    """
    session = session_manager.get_session(session_id)
    if not session or session.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    activities = session_manager.get_session_activity(session_id)
    return {"activities": activities}

@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    current_user: User = Depends(get_current_user)
):
    """
    Set up MFA for the user
    """
    secret = mfa_manager.generate_secret(current_user.id)
    qr_code = mfa_manager.generate_qr_code(current_user.id, current_user.username)
    backup_codes = mfa_manager.generate_backup_codes(current_user.id)
    
    return {
        "secret": secret,
        "qr_code": qr_code,
        "backup_codes": backup_codes
    }

@router.post("/mfa/disable", status_code=status.HTTP_200_OK)
async def disable_mfa(
    code: str = Body(..., embed=True),
    current_user: User = Depends(get_current_user)
):
    """
    Disable MFA for the user
    """
    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled for this user"
        )
    
    if mfa_manager.verify_code(current_user.id, code) or mfa_manager.verify_backup_code(current_user.id, code):
        mfa_manager.disable_mfa(current_user.id)
        return {"success": True, "message": "MFA disabled successfully"}
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid MFA code"
    )

@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(
    current_user: User = Depends(get_current_user)
):
    """
    Log out the current user by revoking the current session
    """
    current_session = session_manager.get_current_session()
    if current_session:
        session_manager.revoke_session(current_session.session_id)
        return {"success": True, "message": "Logged out successfully"}
    
    return {"success": False, "message": "No active session found"} 