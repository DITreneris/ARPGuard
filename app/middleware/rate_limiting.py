from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from typing import Dict, Tuple, Optional, List, Union
import time
import json
from datetime import datetime, timedelta
import asyncio
import hashlib
from pydantic import BaseModel
import logging

logger = logging.getLogger(__name__)

class TokenBucket:
    """
    Token Bucket implementation for rate limiting.
    
    Attributes:
        capacity: Maximum number of tokens the bucket can hold
        tokens: Current number of tokens in the bucket
        refill_rate: Tokens added per second
        last_refill: Timestamp of the last refill
    """
    
    def __init__(self, capacity: int, refill_rate: float):
        """
        Initialize a token bucket.
        
        Args:
            capacity: Maximum number of tokens
            refill_rate: Tokens per second refill rate
        """
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.last_refill = time.time()
    
    def refill(self):
        """Refill tokens based on time elapsed since last refill."""
        now = time.time()
        elapsed = now - self.last_refill
        
        # Calculate tokens to add
        new_tokens = elapsed * self.refill_rate
        
        # Update token count and last_refill time
        self.tokens = min(self.capacity, self.tokens + new_tokens)
        self.last_refill = now
    
    def consume(self, tokens: int = 1) -> bool:
        """
        Attempt to consume tokens from the bucket.
        
        Args:
            tokens: Number of tokens to consume (default: 1)
            
        Returns:
            bool: True if tokens were consumed, False if not enough tokens
        """
        self.refill()
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        
        return False
    
    def get_wait_time(self, tokens: int = 1) -> float:
        """
        Calculate wait time until enough tokens are available.
        
        Args:
            tokens: Number of tokens needed (default: 1)
            
        Returns:
            float: Time in seconds to wait for tokens to be available
        """
        self.refill()
        
        if self.tokens >= tokens:
            return 0
        
        # Calculate time needed to refill
        tokens_needed = tokens - self.tokens
        return tokens_needed / self.refill_rate

class RateLimitConfig(BaseModel):
    """Configuration for a rate limit rule."""
    
    limit: int
    window: int  # in seconds
    burst_factor: float = 1.0
    cost_function: Optional[str] = None  # Optional function name to calculate cost
    
    def get_token_rate(self) -> float:
        """Calculate token refill rate based on window."""
        return self.limit / self.window
    
    def get_burst_capacity(self) -> int:
        """Get burst capacity based on limit and burst factor."""
        return int(self.limit * self.burst_factor)

class RateLimitIdentifier:
    """Handles the identification of rate limit subjects (IP, User, etc.)."""
    
    @staticmethod
    def get_client_ip(request: Request) -> str:
        """Get client IP address from request."""
        # Check for forwarded IP first
        forwarded = request.headers.get("X-Forwarded-For")
        
        if forwarded:
            return forwarded.split(",")[0].strip()
        
        # Fall back to client.host
        return request.client.host if request.client else "unknown"
    
    @staticmethod
    def get_user_id(request: Request) -> Optional[str]:
        """Get user ID from request state if authenticated."""
        return getattr(request.state, "user_id", None)
    
    @staticmethod
    def get_endpoint_id(request: Request) -> str:
        """Get endpoint identifier from request path and method."""
        return f"{request.method}:{request.url.path}"
    
    @staticmethod
    def get_token_id(request: Request) -> Optional[str]:
        """Get token ID from authorization header."""
        auth_header = request.headers.get("Authorization", "")
        
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            # Create hash of token for storage rather than the token itself
            return hashlib.sha256(token.encode()).hexdigest()
        
        return None

class RateLimitHandler:
    """Handles rate limit checking and enforcement."""
    
    def __init__(self):
        """Initialize the rate limit handler."""
        self.buckets: Dict[str, TokenBucket] = {}
        self.global_config = RateLimitConfig(limit=100, window=60)  # Default global limit
        self.ip_config = RateLimitConfig(limit=60, window=60)  # Default IP limit
        self.user_config = RateLimitConfig(limit=100, window=60)  # Default user limit
        self.token_config = RateLimitConfig(limit=120, window=60)  # Default token limit
        self.endpoint_configs: Dict[str, RateLimitConfig] = {}  # Per-endpoint limits
    
    def load_config(self, config: Dict):
        """
        Load rate limit configuration.
        
        Args:
            config: Rate limiting configuration dictionary
        """
        if "global" in config:
            self.global_config = RateLimitConfig(**config["global"])
        
        if "ip" in config:
            self.ip_config = RateLimitConfig(**config["ip"])
        
        if "user" in config:
            self.user_config = RateLimitConfig(**config["user"])
        
        if "token" in config:
            self.token_config = RateLimitConfig(**config["token"])
        
        if "endpoints" in config:
            for endpoint, settings in config["endpoints"].items():
                self.endpoint_configs[endpoint] = RateLimitConfig(**settings)
    
    def get_bucket_key(self, identifier_type: str, identifier: str) -> str:
        """
        Generate a bucket key for a specific identifier.
        
        Args:
            identifier_type: Type of identifier (ip, user, token, etc.)
            identifier: The identifier value
        
        Returns:
            str: Bucket key
        """
        return f"{identifier_type}:{identifier}"
    
    def get_or_create_bucket(self, key: str, config: RateLimitConfig) -> TokenBucket:
        """
        Get or create a token bucket for the given key.
        
        Args:
            key: Bucket key
            config: Rate limit configuration for this bucket
        
        Returns:
            TokenBucket: The token bucket
        """
        if key not in self.buckets:
            self.buckets[key] = TokenBucket(
                capacity=config.get_burst_capacity(),
                refill_rate=config.get_token_rate()
            )
        
        return self.buckets[key]
    
    def check_rate_limit(self, request: Request) -> Tuple[bool, Dict[str, Union[int, float, str]]]:
        """
        Check if a request should be rate limited.
        
        Args:
            request: FastAPI request object
        
        Returns:
            Tuple[bool, Dict]: (allowed, rate_limit_info)
            - allowed: True if request is allowed, False if rate limited
            - rate_limit_info: Dictionary with rate limit information
        """
        # Get identifiers
        ip = RateLimitIdentifier.get_client_ip(request)
        user_id = RateLimitIdentifier.get_user_id(request)
        endpoint_id = RateLimitIdentifier.get_endpoint_id(request)
        token_id = RateLimitIdentifier.get_token_id(request)
        
        # Get endpoint config (or default to global)
        endpoint_config = self.endpoint_configs.get(endpoint_id, self.global_config)
        
        # Cost for this request (default: 1 token)
        cost = 1
        
        # Check token bucket for IP
        ip_key = self.get_bucket_key("ip", ip)
        ip_bucket = self.get_or_create_bucket(ip_key, self.ip_config)
        
        if not ip_bucket.consume(cost):
            return False, {
                "limit": self.ip_config.limit,
                "remaining": 0,
                "reset": ip_bucket.get_wait_time(cost),
                "type": "ip"
            }
        
        # If authenticated, check user rate limit
        if user_id:
            user_key = self.get_bucket_key("user", user_id)
            user_bucket = self.get_or_create_bucket(user_key, self.user_config)
            
            if not user_bucket.consume(cost):
                return False, {
                    "limit": self.user_config.limit,
                    "remaining": 0,
                    "reset": user_bucket.get_wait_time(cost),
                    "type": "user"
                }
        
        # If using a token, check token rate limit
        if token_id:
            token_key = self.get_bucket_key("token", token_id)
            token_bucket = self.get_or_create_bucket(token_key, self.token_config)
            
            if not token_bucket.consume(cost):
                return False, {
                    "limit": self.token_config.limit,
                    "remaining": 0,
                    "reset": token_bucket.get_wait_time(cost),
                    "type": "token"
                }
        
        # Check endpoint rate limit
        endpoint_key = self.get_bucket_key("endpoint", endpoint_id)
        endpoint_bucket = self.get_or_create_bucket(endpoint_key, endpoint_config)
        
        if not endpoint_bucket.consume(cost):
            return False, {
                "limit": endpoint_config.limit,
                "remaining": 0,
                "reset": endpoint_bucket.get_wait_time(cost),
                "type": "endpoint"
            }
        
        # If all checks pass, determine the most restrictive limit
        # (for the rate limit headers)
        most_restrictive = min(
            (self.ip_config.limit, ip_bucket.tokens, "ip"),
            (self.user_config.limit, user_bucket.tokens if user_id else float('inf'), "user"),
            (self.token_config.limit, token_bucket.tokens if token_id else float('inf'), "token"),
            (endpoint_config.limit, endpoint_bucket.tokens, "endpoint"),
            key=lambda x: x[1]  # Compare by remaining tokens
        )
        
        limit, remaining, limit_type = most_restrictive
        
        # Get the corresponding bucket for reset time
        if limit_type == "ip":
            bucket = ip_bucket
        elif limit_type == "user" and user_id:
            bucket = user_bucket
        elif limit_type == "token" and token_id:
            bucket = token_bucket
        else:  # endpoint
            bucket = endpoint_bucket
        
        return True, {
            "limit": limit,
            "remaining": int(remaining),
            "reset": bucket.get_wait_time(cost),
            "type": limit_type
        }
    
    def cleanup_old_buckets(self, max_age: int = 3600):
        """
        Remove buckets that haven't been used for a while.
        
        Args:
            max_age: Maximum age in seconds before removing a bucket
        """
        now = time.time()
        to_remove = []
        
        for key, bucket in self.buckets.items():
            if now - bucket.last_refill > max_age:
                to_remove.append(key)
        
        for key in to_remove:
            del self.buckets[key]

class TokenRateLimitMiddleware(BaseHTTPMiddleware):
    """Token-based rate limiting middleware for FastAPI."""
    
    def __init__(self, app: ASGIApp, config: Dict = None):
        """
        Initialize the rate limiting middleware.
        
        Args:
            app: ASGI application
            config: Rate limiting configuration
        """
        super().__init__(app)
        self.handler = RateLimitHandler()
        
        if config:
            self.handler.load_config(config)
        
        # Start cleanup task in background
        asyncio.create_task(self._background_cleanup())
    
    async def _background_cleanup(self):
        """Background task to periodically clean up old buckets."""
        while True:
            await asyncio.sleep(300)  # Run every 5 minutes
            self.handler.cleanup_old_buckets()
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process requests, applying rate limiting.
        
        Args:
            request: FastAPI request
            call_next: ASGI application callable
        
        Returns:
            Response: Either the original response or rate limit exceeded response
        """
        # Skip rate limiting for certain paths (if needed)
        # if request.url.path in EXEMPT_PATHS:
        #     return await call_next(request)
        
        # Check rate limits
        allowed, rate_limit_info = self.handler.check_rate_limit(request)
        
        if not allowed:
            # Return rate limit response
            content = {
                "error": "Rate limit exceeded",
                "limit": rate_limit_info["limit"],
                "remaining": rate_limit_info["remaining"],
                "retry_after": int(rate_limit_info["reset"]),
                "type": rate_limit_info["type"]
            }
            
            response = Response(
                content=json.dumps(content),
                status_code=429,
                media_type="application/json",
                headers={
                    "X-RateLimit-Limit": str(rate_limit_info["limit"]),
                    "X-RateLimit-Remaining": str(rate_limit_info["remaining"]),
                    "X-RateLimit-Reset": str(int(time.time() + rate_limit_info["reset"])),
                    "Retry-After": str(int(rate_limit_info["reset"])),
                    "X-RateLimit-Type": rate_limit_info["type"]
                }
            )
            
            return response
        
        # Process the request normally
        response = await call_next(request)
        
        # Add rate limit headers to response
        response.headers["X-RateLimit-Limit"] = str(rate_limit_info["limit"])
        response.headers["X-RateLimit-Remaining"] = str(rate_limit_info["remaining"])
        response.headers["X-RateLimit-Reset"] = str(int(time.time() + rate_limit_info["reset"]))
        
        return response 