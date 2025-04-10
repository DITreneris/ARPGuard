import unittest
import time
import asyncio
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch
import pytest

from app.middleware.rate_limiting import (
    TokenBucket, 
    RateLimitConfig, 
    RateLimitIdentifier, 
    RateLimitHandler,
    TokenRateLimitMiddleware
)

class TestTokenBucket(unittest.TestCase):
    """Tests for the TokenBucket class."""
    
    def test_init(self):
        """Test token bucket initialization."""
        bucket = TokenBucket(capacity=10, refill_rate=1)
        self.assertEqual(bucket.capacity, 10)
        self.assertEqual(bucket.tokens, 10)
        self.assertEqual(bucket.refill_rate, 1)
        self.assertTrue(hasattr(bucket, "last_refill"))
    
    def test_consume(self):
        """Test token consumption."""
        bucket = TokenBucket(capacity=10, refill_rate=1)
        
        # Consume 5 tokens
        self.assertTrue(bucket.consume(5))
        self.assertEqual(bucket.tokens, 5)
        
        # Consume 6 tokens (should fail)
        self.assertFalse(bucket.consume(6))
        self.assertEqual(bucket.tokens, 5)  # Tokens unchanged
        
        # Consume 5 more tokens
        self.assertTrue(bucket.consume(5))
        self.assertEqual(bucket.tokens, 0)
        
        # Consume 1 more token (should fail)
        self.assertFalse(bucket.consume(1))
        self.assertEqual(bucket.tokens, 0)
    
    def test_refill(self):
        """Test token refill."""
        bucket = TokenBucket(capacity=10, refill_rate=1)
        
        # Consume 5 tokens
        bucket.consume(5)
        self.assertEqual(bucket.tokens, 5)
        
        # Set last_refill to 3 seconds ago
        bucket.last_refill = time.time() - 3
        
        # Refill
        bucket.refill()
        
        # Should have 8 tokens now (5 + 3)
        self.assertAlmostEqual(bucket.tokens, 8, delta=0.1)
        
        # Set last_refill to 10 seconds ago
        bucket.tokens = 5
        bucket.last_refill = time.time() - 10
        
        # Refill
        bucket.refill()
        
        # Should be capped at capacity (10)
        self.assertEqual(bucket.tokens, 10)
    
    def test_get_wait_time(self):
        """Test wait time calculation."""
        bucket = TokenBucket(capacity=10, refill_rate=2)  # 2 tokens per second
        
        # Consume 8 tokens
        bucket.consume(8)
        self.assertEqual(bucket.tokens, 2)
        
        # Wait time for 1 token
        self.assertEqual(bucket.get_wait_time(1), 0)  # No wait needed
        
        # Wait time for 3 tokens
        wait_time = bucket.get_wait_time(3)
        self.assertEqual(wait_time, 0.5)  # Need 1 more token, at 2/sec = 0.5 sec
        
        # Consume all tokens
        bucket.consume(2)
        self.assertEqual(bucket.tokens, 0)
        
        # Wait time for 1 token
        wait_time = bucket.get_wait_time(1)
        self.assertEqual(wait_time, 0.5)  # 1 token at 2/sec = 0.5 sec

class TestRateLimitConfig(unittest.TestCase):
    """Tests for the RateLimitConfig class."""
    
    def test_init(self):
        """Test rate limit config initialization."""
        config = RateLimitConfig(limit=100, window=60)
        self.assertEqual(config.limit, 100)
        self.assertEqual(config.window, 60)
        self.assertEqual(config.burst_factor, 1.0)  # Default
        
        # With burst factor
        config = RateLimitConfig(limit=100, window=60, burst_factor=1.5)
        self.assertEqual(config.burst_factor, 1.5)
    
    def test_get_token_rate(self):
        """Test token rate calculation."""
        config = RateLimitConfig(limit=100, window=60)
        self.assertAlmostEqual(config.get_token_rate(), 100/60)
        
        config = RateLimitConfig(limit=30, window=10)
        self.assertEqual(config.get_token_rate(), 3.0)
    
    def test_get_burst_capacity(self):
        """Test burst capacity calculation."""
        config = RateLimitConfig(limit=100, window=60, burst_factor=1.5)
        self.assertEqual(config.get_burst_capacity(), 150)
        
        config = RateLimitConfig(limit=100, window=60, burst_factor=2.0)
        self.assertEqual(config.get_burst_capacity(), 200)

class TestRateLimitIdentifier:
    """Tests for the RateLimitIdentifier class."""
    
    def test_get_client_ip(self):
        """Test getting client IP from request."""
        # Test with X-Forwarded-For
        request = MagicMock()
        request.headers = {"X-Forwarded-For": "192.168.1.1, 10.0.0.1"}
        ip = RateLimitIdentifier.get_client_ip(request)
        assert ip == "192.168.1.1"
        
        # Test with client.host
        request = MagicMock()
        request.headers = {}
        request.client.host = "127.0.0.1"
        ip = RateLimitIdentifier.get_client_ip(request)
        assert ip == "127.0.0.1"
        
        # Test with no client info
        request = MagicMock()
        request.headers = {}
        request.client = None
        ip = RateLimitIdentifier.get_client_ip(request)
        assert ip == "unknown"
    
    def test_get_user_id(self):
        """Test getting user ID from request."""
        # Test with user_id in state
        request = MagicMock()
        request.state.user_id = "user123"
        user_id = RateLimitIdentifier.get_user_id(request)
        assert user_id == "user123"
        
        # Test without user_id
        request = MagicMock()
        request.state = MagicMock(spec=[])  # No user_id attribute
        user_id = RateLimitIdentifier.get_user_id(request)
        assert user_id is None
    
    def test_get_endpoint_id(self):
        """Test getting endpoint ID."""
        request = MagicMock()
        request.method = "GET"
        request.url.path = "/api/v1/monitor/stats"
        endpoint_id = RateLimitIdentifier.get_endpoint_id(request)
        assert endpoint_id == "GET:/api/v1/monitor/stats"
    
    def test_get_token_id(self):
        """Test getting token ID from authorization header."""
        # Test with bearer token
        request = MagicMock()
        request.headers = {"Authorization": "Bearer abc123"}
        token_id = RateLimitIdentifier.get_token_id(request)
        assert token_id is not None  # We don't care about the exact hash
        
        # Test without authorization
        request = MagicMock()
        request.headers = {}
        token_id = RateLimitIdentifier.get_token_id(request)
        assert token_id is None
        
        # Test with wrong format
        request = MagicMock()
        request.headers = {"Authorization": "Basic xyz"}
        token_id = RateLimitIdentifier.get_token_id(request)
        assert token_id is None

class TestRateLimitHandler:
    """Tests for the RateLimitHandler class."""
    
    def test_init(self):
        """Test handler initialization."""
        handler = RateLimitHandler()
        assert isinstance(handler.buckets, dict)
        assert isinstance(handler.global_config, RateLimitConfig)
    
    def test_load_config(self):
        """Test loading configuration."""
        handler = RateLimitHandler()
        config = {
            "global": {"limit": 200, "window": 30, "burst_factor": 1.5},
            "ip": {"limit": 100, "window": 60, "burst_factor": 1.2},
            "endpoints": {
                "GET:/api/v1/test": {"limit": 10, "window": 60}
            }
        }
        handler.load_config(config)
        
        assert handler.global_config.limit == 200
        assert handler.global_config.window == 30
        assert handler.ip_config.limit == 100
        assert "GET:/api/v1/test" in handler.endpoint_configs
        assert handler.endpoint_configs["GET:/api/v1/test"].limit == 10
    
    def test_get_bucket_key(self):
        """Test generating bucket keys."""
        handler = RateLimitHandler()
        key = handler.get_bucket_key("ip", "127.0.0.1")
        assert key == "ip:127.0.0.1"
        
        key = handler.get_bucket_key("user", "user123")
        assert key == "user:user123"
    
    def test_get_or_create_bucket(self):
        """Test getting or creating token buckets."""
        handler = RateLimitHandler()
        config = RateLimitConfig(limit=100, window=60, burst_factor=1.5)
        
        # First call creates a bucket
        key = "test:123"
        bucket = handler.get_or_create_bucket(key, config)
        assert isinstance(bucket, TokenBucket)
        assert bucket.capacity == 150  # Based on burst factor
        assert key in handler.buckets
        
        # Second call returns existing bucket
        bucket2 = handler.get_or_create_bucket(key, config)
        assert bucket is bucket2  # Same object
    
    def test_cleanup_old_buckets(self):
        """Test cleaning up old buckets."""
        handler = RateLimitHandler()
        config = RateLimitConfig(limit=100, window=60)
        
        # Create buckets
        bucket1 = handler.get_or_create_bucket("test:1", config)
        bucket2 = handler.get_or_create_bucket("test:2", config)
        
        # Set one bucket's last_refill to the past
        bucket1.last_refill = time.time() - 7200  # 2 hours ago
        
        # Cleanup with 1 hour max age
        handler.cleanup_old_buckets(max_age=3600)
        
        # Bucket1 should be removed, bucket2 should remain
        assert "test:1" not in handler.buckets
        assert "test:2" in handler.buckets
    
    def test_check_rate_limit(self):
        """Test rate limit checking."""
        handler = RateLimitHandler()
        
        # Configure smaller limits for testing
        handler.global_config = RateLimitConfig(limit=5, window=60)
        handler.ip_config = RateLimitConfig(limit=3, window=60)
        
        # Create a mock request
        request = MagicMock()
        request.headers = {}
        request.client.host = "127.0.0.1"
        request.method = "GET"
        request.url.path = "/api/v1/test"
        request.state = MagicMock(spec=[])  # No user_id
        
        # First request should be allowed
        allowed, info = handler.check_rate_limit(request)
        assert allowed is True
        assert info["limit"] == 3  # IP is most restrictive
        assert info["remaining"] == 2
        
        # Make more requests to hit the IP limit
        handler.check_rate_limit(request)
        allowed, info = handler.check_rate_limit(request)
        
        # Third request should be the last allowed
        assert allowed is True
        assert info["remaining"] == 0
        
        # Fourth request should be rate limited
        allowed, info = handler.check_rate_limit(request)
        assert allowed is False
        assert info["type"] == "ip"

@pytest.mark.asyncio
async def test_middleware():
    """Test the rate limiting middleware."""
    # Create a simple FastAPI app
    app = FastAPI()
    
    # Define a test endpoint
    @app.get("/test")
    def test_endpoint():
        return {"message": "Test"}
    
    # Add the middleware with test config
    config = {
        "global": {"limit": 5, "window": 60},
        "ip": {"limit": 3, "window": 60}
    }
    app.add_middleware(TokenRateLimitMiddleware, config=config)
    
    # Create a test client
    client = TestClient(app)
    
    # First request should succeed
    response = client.get("/test")
    assert response.status_code == 200
    assert "X-RateLimit-Limit" in response.headers
    assert "X-RateLimit-Remaining" in response.headers
    
    # Make more requests to hit the limit
    client.get("/test")
    response = client.get("/test")
    assert response.status_code == 200
    assert response.headers["X-RateLimit-Remaining"] == "0"
    
    # Next request should be rate limited
    response = client.get("/test")
    assert response.status_code == 429
    assert "error" in response.json()
    assert response.json()["type"] == "ip"
    assert "Retry-After" in response.headers
    
if __name__ == "__main__":
    unittest.main() 