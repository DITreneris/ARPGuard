import os
from typing import Dict, Any
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """Application settings"""
    # Base
    APP_NAME: str = "User Management System"
    API_V1_PREFIX: str = "/api/v1"
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-for-development")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    MFA_CODE_EXPIRE_SECONDS: int = 300
    
    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        "sqlite:///./app.db"
    )
    DATABASE_CONNECT_ARGS: Dict[str, Any] = {"check_same_thread": False}
    
    # Security settings
    PASSWORD_MIN_LENGTH: int = 8
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 15
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings() 