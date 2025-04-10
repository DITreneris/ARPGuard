"""
Analytics Authentication Module

Provides authentication services for the analytics dashboard and API.
Integrates with the main ARP Guard authentication system.
"""

import os
import jwt
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, List, Union

# Configure logging
logger = logging.getLogger("arp_guard.analytics.auth")

# JWT settings
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "analytics-secret-key")  # In production, use environment variable
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION = 30  # minutes

class AnalyticsAuth:
    """Authentication handler for Analytics API and Dashboard"""
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize the analytics authentication system
        
        Args:
            db_path: Path to SQLite database (optional)
        """
        self.db_path = db_path
        self.active_tokens = {}  # In-memory token store (would be DB in production)
        self.session_timeout = 30  # minutes
        logger.info("Initialized AnalyticsAuth module")
        
    def authenticate(self, username: str, password: str, user_agent: str, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate a user with username and password
        
        Args:
            username: User's username
            password: User's password
            user_agent: Client user agent
            ip_address: Client IP address
            
        Returns:
            Authentication result with token or None if authentication fails
        """
        # In production, this would validate against the main auth system
        # For now, use simple validation
        from app.core.auth import authenticate_user, create_access_token
        
        try:
            # Try to use the main auth system if available
            user = authenticate_user({"client": user_agent, "ip": ip_address}, username, password)
            if user:
                # Generate JWT token for analytics
                token_data = {
                    "sub": username,
                    "name": user.get("username", username),
                    "role": user.get("role", "viewer"),
                    "iat": datetime.utcnow(),
                    "analytics_access": True
                }
                
                token = create_access_token(
                    token_data, 
                    expires_delta=timedelta(minutes=self.session_timeout)
                )
                
                # Store token (in production, this would be in Redis or another store)
                token_id = self._generate_token_id(username)
                self.active_tokens[token_id] = {
                    "token": token,
                    "user": username,
                    "created_at": datetime.utcnow(),
                    "expires_at": datetime.utcnow() + timedelta(minutes=self.session_timeout),
                    "ip_address": ip_address,
                    "user_agent": user_agent,
                    "last_activity": datetime.utcnow()
                }
                
                return {
                    "access_token": token,
                    "token_type": "bearer",
                    "expires_in": self.session_timeout * 60,  # seconds
                    "user": {
                        "username": username,
                        "name": user.get("username", username),
                        "role": user.get("role", "viewer")
                    }
                }
            
            return None
            
        except (ImportError, AttributeError):
            # Fallback to simple auth if main system not available
            # This is only for development - production should always use main auth
            if username == "admin" and password == "admin":  # DEMO ONLY, NOT FOR PRODUCTION
                token = self._generate_jwt_token(username, "admin")
                
                return {
                    "access_token": token,
                    "token_type": "bearer",
                    "expires_in": self.session_timeout * 60,  # seconds
                    "user": {
                        "username": username,
                        "name": "Admin User",
                        "role": "admin"
                    }
                }
                
            return None
            
    def validate_token(self, token: str, ip_address: str = None) -> Optional[Dict[str, Any]]:
        """
        Validate a JWT token
        
        Args:
            token: JWT token
            ip_address: Client IP address (optional)
            
        Returns:
            User data if token is valid, None otherwise
        """
        if not token:
            return None
            
        try:
            # Decode and validate the token
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            
            # Check if the token is expired
            if payload.get("exp", 0) < time.time():
                logger.warning(f"Token expired for user {payload.get('sub')}")
                return None
                
            # Check if token has analytics access
            if not payload.get("analytics_access", False):
                logger.warning(f"Token lacks analytics access for user {payload.get('sub')}")
                return None
                
            # Update last activity if we have the token in our store and IP is provided
            username = payload.get("sub")
            token_id = self._generate_token_id(username)
            
            if token_id in self.active_tokens and ip_address:
                self.active_tokens[token_id]["last_activity"] = datetime.utcnow()
                
            return {
                "username": username,
                "name": payload.get("name", username),
                "role": payload.get("role", "viewer"),
                "exp": payload.get("exp")
            }
            
        except jwt.PyJWTError as e:
            logger.warning(f"Token validation failed: {str(e)}")
            return None
            
    def revoke_token(self, token: str) -> bool:
        """
        Revoke a token
        
        Args:
            token: JWT token to revoke
            
        Returns:
            True if token was revoked, False otherwise
        """
        try:
            # Decode token to get username
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            username = payload.get("sub")
            
            # Remove from active tokens
            token_id = self._generate_token_id(username)
            if token_id in self.active_tokens:
                del self.active_tokens[token_id]
                return True
                
            return False
            
        except jwt.PyJWTError:
            return False
            
    def get_user_permissions(self, username: str) -> List[str]:
        """
        Get permissions for a user
        
        Args:
            username: Username
            
        Returns:
            List of permission strings
        """
        # In production, this would query the main auth system
        # For now, return basic permissions based on role
        if username == "admin":
            return [
                "dashboard:view", "dashboard:edit",
                "analytics:view", "analytics:export",
                "settings:view", "settings:edit"
            ]
        else:
            return ["dashboard:view", "analytics:view"]
            
    def _generate_jwt_token(self, username: str, role: str = "viewer") -> str:
        """
        Generate a JWT token
        
        Args:
            username: Username to include in token
            role: User role
            
        Returns:
            JWT token string
        """
        expiration = datetime.utcnow() + timedelta(minutes=self.session_timeout)
        
        payload = {
            "sub": username,
            "name": username,
            "role": role,
            "iat": datetime.utcnow(),
            "exp": expiration,
            "analytics_access": True
        }
        
        return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        
    def _generate_token_id(self, username: str) -> str:
        """Generate a unique token ID for a user"""
        return f"analytics_token_{username}"


# Create global instance
analytics_auth = AnalyticsAuth() 