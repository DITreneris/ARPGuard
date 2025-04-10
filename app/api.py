from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import yaml
import os
from pathlib import Path

from app.api.endpoints import auth, monitoring, configuration, discovery
from app.api.endpoints.monitoring import start_background_tasks
from app.middleware.versioning import APIVersionMiddleware
from app.middleware.rate_limiting import TokenRateLimitMiddleware

# Create FastAPI application
app = FastAPI(
    title="ARPGuard API",
    description="API for ARPGuard network monitoring system",
    version="1.0.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load rate limiting configuration
rate_limit_config_path = Path("app/config/rate_limits.yaml")
rate_limit_config = {}
if rate_limit_config_path.exists():
    with open(rate_limit_config_path, "r") as f:
        rate_limit_config = yaml.safe_load(f)

# Add middleware in correct order (last added is executed first)
# Rate limiting middleware comes before version middleware
app.add_middleware(TokenRateLimitMiddleware, config=rate_limit_config)
app.add_middleware(APIVersionMiddleware)

# Include routers
app.include_router(auth.router)
app.include_router(monitoring.router)
app.include_router(configuration.router)
app.include_router(discovery.router)

# Start background tasks for real-time monitoring
start_background_tasks(app)

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "Welcome to ARPGuard API",
        "documentation": "/docs",
        "version": "1.0.0"
    } 