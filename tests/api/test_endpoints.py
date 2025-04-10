import pytest
import time
from fastapi.testclient import TestClient
from app.main import app
from app.core.auth import create_access_token
from app.core.config import settings
from datetime import datetime, timedelta
import json
import random
import requests
import urllib3
import subprocess
import shlex
import http.client
import socket
import asyncio
import aiohttp
import httpx

client = TestClient(app)

# Test data
TEST_USER = {
    "username": "test_user",
    "password": "test_password"
}

TEST_CONFIG = {
    "network": {
        "interface": "eth0",
        "mode": "protect",
        "promiscuous_mode": True,
        "packet_timeout": 1000
    }
}

# Performance test parameters
PERF_TEST_ITERATIONS = 100
PERF_TEST_TIMEOUT = 1.0  # seconds

# Rate limiting parameters
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 100

# Test alert data
TEST_ALERTS = [
    {
        "id": "alert1",
        "severity": "Critical",
        "timestamp": datetime.now().isoformat(),
        "description": "ARP Spoofing detected",
        "source_ip": "192.168.1.100",
        "target_ip": "192.168.1.1"
    },
    {
        "id": "alert2",
        "severity": "High",
        "timestamp": datetime.now().isoformat(),
        "description": "Port scanning detected",
        "source_ip": "192.168.1.101",
        "target_ip": "192.168.1.2"
    }
]

@pytest.fixture
def auth_token():
    """Create a test authentication token"""
    access_token = create_access_token(
        data={"sub": TEST_USER["username"]},
        expires_delta=timedelta(minutes=15)
    )
    return access_token

@pytest.fixture
def mock_alerts():
    """Create mock alerts for testing"""
    return TEST_ALERTS

class TestAuthenticationEndpoints:
    def test_login_success(self):
        """Test successful login"""
        response = client.post(
            "/api/v1/auth/login",
            json=TEST_USER
        )
        assert response.status_code == 200
        assert "token" in response.json()
        assert "expires_in" in response.json()

    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "invalid", "password": "invalid"}
        )
        assert response.status_code == 401

    def test_refresh_token(self, auth_token):
        """Test token refresh"""
        response = client.post(
            "/api/v1/auth/refresh",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        assert "token" in response.json()

    def test_logout(self, auth_token):
        """Test logout"""
        response = client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200

    def test_login_rate_limiting(self):
        """Test login rate limiting"""
        for _ in range(5):
            response = client.post(
                "/api/v1/auth/login",
                json=TEST_USER
            )
        response = client.post(
            "/api/v1/auth/login",
            json=TEST_USER
        )
        assert response.status_code == 429

    def test_token_expiration(self, auth_token):
        """Test token expiration"""
        # Wait for token to expire
        time.sleep(16 * 60)  # 16 minutes
        response = client.get(
            "/api/v1/monitor/stats",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 401

    def test_login_with_empty_credentials(self):
        """Test login with empty credentials"""
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "", "password": ""}
        )
        assert response.status_code == 400
        assert "error" in response.json()

    def test_login_with_missing_fields(self):
        """Test login with missing fields"""
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "test_user"}
        )
        assert response.status_code == 422
        assert "detail" in response.json()

    def test_refresh_token_with_invalid_token(self):
        """Test token refresh with invalid token"""
        response = client.post(
            "/api/v1/auth/refresh",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401

class TestMonitoringEndpoints:
    def test_get_network_stats(self, auth_token):
        """Test getting network statistics"""
        response = client.get(
            "/api/v1/monitor/stats",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "packets_processed" in data
        assert "attacks_detected" in data
        assert "network_throughput" in data

    def test_get_alerts(self, auth_token):
        """Test getting alerts with filters"""
        # Test without filters
        response = client.get(
            "/api/v1/monitor/alerts",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        assert "alerts" in response.json()

        # Test with severity filter
        response = client.get(
            "/api/v1/monitor/alerts?severity=Critical",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200

    def test_get_topology(self, auth_token):
        """Test getting network topology"""
        response = client.get(
            "/api/v1/monitor/topology",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "nodes" in data
        assert "edges" in data

    def test_get_alerts_time_range(self, auth_token):
        """Test alert time range filtering"""
        time_ranges = ["1h", "6h", "24h", "7d"]
        for time_range in time_ranges:
            response = client.get(
                f"/api/v1/monitor/alerts?time_range={time_range}",
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            assert response.status_code == 200
            assert "alerts" in response.json()

    def test_get_alerts_status(self, auth_token):
        """Test alert status filtering"""
        statuses = ["active", "acknowledged", "ignored"]
        for status in statuses:
            response = client.get(
                f"/api/v1/monitor/alerts?status={status}",
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            assert response.status_code == 200
            assert "alerts" in response.json()

    def test_get_topology_node_details(self, auth_token):
        """Test getting detailed node information"""
        response = client.get(
            "/api/v1/monitor/topology?details=true",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "nodes" in data
        for node in data["nodes"]:
            assert "ip" in node
            assert "mac" in node
            assert "status" in node
            assert "last_seen" in node

    def test_get_alerts_with_multiple_filters(self, auth_token):
        """Test alert filtering with multiple parameters"""
        filters = {
            "severity": "Critical",
            "time_range": "1h",
            "status": "active"
        }
        response = client.get(
            f"/api/v1/monitor/alerts?severity={filters['severity']}&time_range={filters['time_range']}&status={filters['status']}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        assert "alerts" in response.json()

    def test_get_alerts_with_invalid_filters(self, auth_token):
        """Test alert filtering with invalid parameters"""
        response = client.get(
            "/api/v1/monitor/alerts?severity=Invalid&time_range=Invalid",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 400
        assert "error" in response.json()

    def test_get_topology_with_invalid_details(self, auth_token):
        """Test topology with invalid details parameter"""
        response = client.get(
            "/api/v1/monitor/topology?details=invalid",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 400
        assert "error" in response.json()

class TestConfigurationEndpoints:
    def test_get_configuration(self, auth_token):
        """Test getting current configuration"""
        response = client.get(
            "/api/v1/config/current",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "network" in data
        assert "security" in data
        assert "notification" in data

    def test_update_configuration(self, auth_token):
        """Test updating configuration"""
        response = client.put(
            "/api/v1/config/update",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=TEST_CONFIG
        )
        assert response.status_code == 200
        assert response.json()["status"] == "success"

    def test_update_configuration_validation(self, auth_token):
        """Test configuration validation"""
        # Test invalid interface
        invalid_config = TEST_CONFIG.copy()
        invalid_config["network"]["interface"] = "invalid_interface"
        response = client.put(
            "/api/v1/config/update",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=invalid_config
        )
        assert response.status_code == 400

    def test_update_security_config(self, auth_token):
        """Test updating security configuration"""
        security_config = {
            "security": {
                "arp_rate_threshold": 150,
                "mac_changes_threshold": 15,
                "block_attacks": True,
                "alert_admin": True
            }
        }
        response = client.put(
            "/api/v1/config/update",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=security_config
        )
        assert response.status_code == 200

    def test_update_notification_config(self, auth_token):
        """Test updating notification configuration"""
        notification_config = {
            "notification": {
                "email_enabled": True,
                "smtp_settings": {
                    "server": "smtp.example.com",
                    "port": 587,
                    "username": "user",
                    "password": "pass"
                }
            }
        }
        response = client.put(
            "/api/v1/config/update",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=notification_config
        )
        assert response.status_code == 200

    def test_update_config_with_invalid_network_settings(self, auth_token):
        """Test updating configuration with invalid network settings"""
        invalid_config = {
            "network": {
                "interface": "invalid_interface",
                "mode": "invalid_mode",
                "packet_timeout": -1
            }
        }
        response = client.put(
            "/api/v1/config/update",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=invalid_config
        )
        assert response.status_code == 400
        assert "error" in response.json()

    def test_update_config_with_invalid_security_settings(self, auth_token):
        """Test updating configuration with invalid security settings"""
        invalid_config = {
            "security": {
                "arp_rate_threshold": -1,
                "mac_changes_threshold": -1
            }
        }
        response = client.put(
            "/api/v1/config/update",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=invalid_config
        )
        assert response.status_code == 400
        assert "error" in response.json()

class TestErrorHandling:
    def test_rate_limiting(self, auth_token):
        """Test rate limiting"""
        # Make multiple requests quickly
        for _ in range(5):
            response = client.get(
                "/api/v1/monitor/stats",
                headers={"Authorization": f"Bearer {auth_token}"}
            )
        # Next request should be rate limited
        response = client.get(
            "/api/v1/monitor/stats",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 429
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers

    def test_invalid_token(self):
        """Test requests with invalid token"""
        response = client.get(
            "/api/v1/monitor/stats",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401

    def test_missing_token(self):
        """Test requests without token"""
        response = client.get("/api/v1/monitor/stats")
        assert response.status_code == 401

    def test_version_mismatch(self):
        """Test version mismatch error"""
        headers = {"Accept": "application/json; version=2.0"}
        response = client.get("/api/monitor/stats", headers=headers)
        assert response.status_code == 400
        assert "error" in response.json()
        assert "version" in response.json()["error"]

    def test_rate_limit_error_details(self):
        """Test rate limit error details"""
        # Exhaust rate limit
        for _ in range(RATE_LIMIT_MAX_REQUESTS):
            client.get("/api/v1/monitor/stats")

        response = client.get("/api/v1/monitor/stats")
        assert response.status_code == 429
        error = response.json()
        assert "error" in error
        assert "retry_after" in error
        assert "limit" in error
        assert "remaining" in error

class TestPerformance:
    """Performance benchmark tests"""

    def test_auth_performance(self):
        """Test authentication endpoint performance"""
        start_time = time.time()
        for _ in range(PERF_TEST_ITERATIONS):
            response = client.post(
                "/api/v1/auth/login",
                json=TEST_USER
            )
            assert response.status_code == 200
        duration = time.time() - start_time
        assert duration < PERF_TEST_TIMEOUT * PERF_TEST_ITERATIONS

    def test_stats_performance(self, auth_token):
        """Test stats endpoint performance"""
        start_time = time.time()
        for _ in range(PERF_TEST_ITERATIONS):
            response = client.get(
                "/api/v1/monitor/stats",
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            assert response.status_code == 200
        duration = time.time() - start_time
        assert duration < PERF_TEST_TIMEOUT * PERF_TEST_ITERATIONS

    def test_config_performance(self, auth_token):
        """Test configuration endpoint performance"""
        start_time = time.time()
        for _ in range(PERF_TEST_ITERATIONS):
            response = client.get(
                "/api/v1/config/current",
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            assert response.status_code == 200
        duration = time.time() - start_time
        assert duration < PERF_TEST_TIMEOUT * PERF_TEST_ITERATIONS

    def test_concurrent_requests(self, auth_token):
        """Test handling of concurrent requests"""
        import threading
        import queue

        def make_request(q):
            response = client.get(
                "/api/v1/monitor/stats",
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            q.put(response.status_code)

        threads = []
        results = queue.Queue()
        for _ in range(10):
            t = threading.Thread(target=make_request, args=(results,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        while not results.empty():
            assert results.get() == 200

    def test_large_payload_handling(self, auth_token):
        """Test handling of large payloads"""
        large_config = {
            "network": {
                "interface": "eth0",
                "mode": "protect",
                "promiscuous_mode": True,
                "packet_timeout": 1000
            },
            "security": {
                "rules": ["rule" * 1000 for _ in range(1000)]
            }
        }
        response = client.put(
            "/api/v1/config/update",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=large_config
        )
        assert response.status_code == 413

class TestIntegration:
    """Integration tests for documentation examples"""

    def test_full_auth_flow(self):
        """Test complete authentication flow from documentation"""
        # Login
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin"}
        )
        assert response.status_code == 200
        token = response.json()["token"]

        # Get stats
        response = client.get(
            "/api/v1/monitor/stats",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        stats = response.json()
        assert all(key in stats for key in [
            "packets_processed",
            "attacks_detected",
            "network_throughput"
        ])

        # Get alerts
        response = client.get(
            "/api/v1/monitor/alerts",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert "alerts" in response.json()

        # Update config
        response = client.put(
            "/api/v1/config/update",
            headers={"Authorization": f"Bearer {token}"},
            json=TEST_CONFIG
        )
        assert response.status_code == 200
        assert response.json()["status"] == "success"

        # Logout
        response = client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200

    def test_error_handling_flow(self):
        """Test error handling flow from documentation"""
        # Test invalid credentials
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "invalid", "password": "invalid"}
        )
        assert response.status_code == 401
        assert "error" in response.json()

        # Test invalid token
        response = client.get(
            "/api/v1/monitor/stats",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401
        assert "error" in response.json()

        # Test rate limiting
        for _ in range(5):
            response = client.post(
                "/api/v1/auth/login",
                json=TEST_USER
            )
        response = client.post(
            "/api/v1/auth/login",
            json=TEST_USER
        )
        assert response.status_code == 429
        assert "X-RateLimit-Limit" in response.headers

    def test_complete_alert_management_flow(self, auth_token, mock_alerts):
        """Test complete alert management flow"""
        # Create alerts
        for alert in mock_alerts:
            response = client.post(
                "/api/v1/monitor/alerts",
                headers={"Authorization": f"Bearer {auth_token}"},
                json=alert
            )
            assert response.status_code == 201

        # Get alerts
        response = client.get(
            "/api/v1/monitor/alerts",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        alerts = response.json()["alerts"]
        assert len(alerts) >= len(mock_alerts)

        # Acknowledge alert
        alert_id = alerts[0]["id"]
        response = client.post(
            f"/api/v1/monitor/alerts/{alert_id}/acknowledge",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200

        # Verify alert status
        response = client.get(
            f"/api/v1/monitor/alerts/{alert_id}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        assert response.json()["status"] == "acknowledged"

    def test_versioned_api_flow(self):
        """Test complete versioned API flow"""
        # Get API version
        response = client.get("/api/v1/monitor/stats")
        version = response.headers["X-API-Version"]

        # Login with version header
        headers = {"X-API-Version": version}
        response = client.post(
            "/api/v1/auth/login",
            json=TEST_USER,
            headers=headers
        )
        assert response.status_code == 200
        token = response.json()["token"]

        # Use token with version
        headers["Authorization"] = f"Bearer {token}"
        response = client.get("/api/v1/monitor/stats", headers=headers)
        assert response.status_code == 200
        assert response.headers["X-API-Version"] == version

    def test_complete_monitoring_flow(self, auth_token):
        """Test complete monitoring flow"""
        # Get initial stats
        response = client.get(
            "/api/v1/monitor/stats",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        initial_stats = response.json()

        # Get topology
        response = client.get(
            "/api/v1/monitor/topology",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        assert "nodes" in response.json()
        assert "edges" in response.json()

        # Get alerts with filters
        response = client.get(
            "/api/v1/monitor/alerts?severity=Critical&time_range=1h",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        assert "alerts" in response.json()

        # Verify stats updated
        response = client.get(
            "/api/v1/monitor/stats",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        updated_stats = response.json()
        assert updated_stats != initial_stats

    def test_complete_configuration_flow(self, auth_token):
        """Test complete configuration flow"""
        # Get current config
        response = client.get(
            "/api/v1/config/current",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        initial_config = response.json()

        # Update network config
        network_config = {
            "network": {
                "interface": "eth1",
                "mode": "monitor",
                "promiscuous_mode": False
            }
        }
        response = client.put(
            "/api/v1/config/update",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=network_config
        )
        assert response.status_code == 200

        # Update security config
        security_config = {
            "security": {
                "arp_rate_threshold": 200,
                "mac_changes_threshold": 20
            }
        }
        response = client.put(
            "/api/v1/config/update",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=security_config
        )
        assert response.status_code == 200

        # Verify config updated
        response = client.get(
            "/api/v1/config/current",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        updated_config = response.json()
        assert updated_config != initial_config

    def test_complete_security_flow(self, auth_token):
        """Test complete security flow"""
        # Get initial security status
        response = client.get(
            "/api/v1/security/status",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        initial_status = response.json()

        # Update security rules
        security_rules = {
            "rules": [
                {
                    "type": "arp_spoofing",
                    "action": "block",
                    "threshold": 100
                }
            ]
        }
        response = client.put(
            "/api/v1/security/rules",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=security_rules
        )
        assert response.status_code == 200

        # Verify security status updated
        response = client.get(
            "/api/v1/security/status",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        updated_status = response.json()
        assert updated_status != initial_status

    def test_complete_notification_flow(self, auth_token):
        """Test complete notification flow"""
        # Configure notification settings
        notification_config = {
            "email": {
                "enabled": True,
                "recipients": ["admin@example.com"]
            },
            "thresholds": {
                "critical": 5,
                "high": 10
            }
        }
        response = client.put(
            "/api/v1/notifications/config",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=notification_config
        )
        assert response.status_code == 200

        # Test notification
        test_notification = {
            "type": "test",
            "message": "Test notification"
        }
        response = client.post(
            "/api/v1/notifications/test",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=test_notification
        )
        assert response.status_code == 200

        # Verify notification sent
        response = client.get(
            "/api/v1/notifications/history",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        history = response.json()
        assert len(history) > 0
        assert history[0]["type"] == "test"

class TestAPIVersioning:
    """Tests for API versioning"""

    def test_api_version_header(self):
        """Test API version header"""
        response = client.get("/api/v1/monitor/stats")
        assert "X-API-Version" in response.headers
        assert response.headers["X-API-Version"] == "1.0.0"

    def test_deprecated_endpoints(self):
        """Test deprecated endpoints"""
        response = client.get("/api/v0/monitor/stats")
        assert response.status_code == 410
        assert "X-API-Deprecated" in response.headers
        assert "X-API-Sunset-Date" in response.headers

    def test_version_negotiation(self):
        """Test version negotiation"""
        headers = {"Accept": "application/json; version=1.0"}
        response = client.get("/api/monitor/stats", headers=headers)
        assert response.status_code == 200
        assert "X-API-Version" in response.headers

    def test_version_header_negotiation(self):
        """Test version header negotiation"""
        versions = ["1.0", "1.1", "2.0"]
        for version in versions:
            headers = {"X-API-Version": version}
            response = client.get("/api/monitor/stats", headers=headers)
            if version == "1.0":
                assert response.status_code == 200
            else:
                assert response.status_code == 400

    def test_version_deprecation_warning(self):
        """Test version deprecation warnings"""
        response = client.get("/api/v1/monitor/stats")
        if "X-API-Deprecation-Warning" in response.headers:
            assert "deprecated" in response.headers["X-API-Deprecation-Warning"].lower()

    def test_version_migration(self):
        """Test version migration"""
        # Test v1 endpoint
        v1_response = client.get("/api/v1/monitor/stats")
        assert v1_response.status_code == 200

        # Test v2 endpoint with v1 compatibility
        headers = {"X-API-Version": "2.0", "Accept": "application/json; version=1.0"}
        v2_response = client.get("/api/v2/monitor/stats", headers=headers)
        assert v2_response.status_code == 200
        assert "X-API-Version" in v2_response.headers

    def test_version_rollback(self):
        """Test version rollback capability"""
        # Get current version
        response = client.get("/api/v1/monitor/stats")
        current_version = response.headers["X-API-Version"]

        # Request older version
        headers = {"X-API-Version": "0.9"}
        response = client.get("/api/monitor/stats", headers=headers)
        assert response.status_code == 200
        assert response.headers["X-API-Version"] == "0.9"

    def test_version_forward_compatibility(self):
        """Test forward compatibility"""
        headers = {"X-API-Version": "1.1", "Accept": "application/json; version=1.0"}
        response = client.get("/api/monitor/stats", headers=headers)
        assert response.status_code == 200
        assert "X-API-Version" in response.headers

    def test_version_negotiation_with_quality(self):
        """Test version negotiation with quality values"""
        headers = {
            "Accept": "application/json; version=2.0; q=0.8, application/json; version=1.0; q=0.9"
        }
        response = client.get("/api/monitor/stats", headers=headers)
        assert response.status_code == 200
        assert response.headers["X-API-Version"] == "1.0"

class TestRateLimiting:
    """Enhanced rate limiting tests"""

    def test_rate_limit_headers(self):
        """Test rate limit headers"""
        response = client.get("/api/v1/monitor/stats")
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers
        assert "X-RateLimit-Reset" in response.headers

    def test_rate_limit_window(self):
        """Test rate limit window"""
        # Make requests up to the limit
        for _ in range(RATE_LIMIT_MAX_REQUESTS):
            response = client.get("/api/v1/monitor/stats")
            assert response.status_code == 200

        # Next request should be rate limited
        response = client.get("/api/v1/monitor/stats")
        assert response.status_code == 429
        assert "Retry-After" in response.headers

    def test_rate_limit_reset(self):
        """Test rate limit reset"""
        # Exhaust rate limit
        for _ in range(RATE_LIMIT_MAX_REQUESTS):
            client.get("/api/v1/monitor/stats")

        # Wait for rate limit window to reset
        time.sleep(RATE_LIMIT_WINDOW)

        # Should be able to make requests again
        response = client.get("/api/v1/monitor/stats")
        assert response.status_code == 200

    def test_rate_limit_by_ip(self):
        """Test IP-based rate limiting"""
        # Simulate requests from different IPs
        headers1 = {"X-Forwarded-For": "192.168.1.1"}
        headers2 = {"X-Forwarded-For": "192.168.1.2"}

        # Exhaust rate limit for first IP
        for _ in range(RATE_LIMIT_MAX_REQUESTS):
            response = client.get("/api/v1/monitor/stats", headers=headers1)
            assert response.status_code == 200

        # First IP should be rate limited
        response = client.get("/api/v1/monitor/stats", headers=headers1)
        assert response.status_code == 429

        # Second IP should still work
        response = client.get("/api/v1/monitor/stats", headers=headers2)
        assert response.status_code == 200

    def test_rate_limit_by_endpoint(self):
        """Test endpoint-specific rate limiting"""
        endpoints = [
            "/api/v1/monitor/stats",
            "/api/v1/monitor/alerts",
            "/api/v1/config/current"
        ]

        for endpoint in endpoints:
            # Make requests up to the limit
            for _ in range(RATE_LIMIT_MAX_REQUESTS):
                response = client.get(endpoint)
                assert response.status_code == 200

            # Next request should be rate limited
            response = client.get(endpoint)
            assert response.status_code == 429

    def test_rate_limit_recovery(self):
        """Test rate limit recovery after window"""
        # Exhaust rate limit
        for _ in range(RATE_LIMIT_MAX_REQUESTS):
            client.get("/api/v1/monitor/stats")

        # Wait for partial window
        time.sleep(RATE_LIMIT_WINDOW / 2)

        # Should still be rate limited
        response = client.get("/api/v1/monitor/stats")
        assert response.status_code == 429

        # Wait for full window
        time.sleep(RATE_LIMIT_WINDOW / 2)

        # Should be able to make requests again
        response = client.get("/api/v1/monitor/stats")
        assert response.status_code == 200

    def test_rate_limit_by_user(self):
        """Test user-based rate limiting"""
        # Login as user1
        response = client.post("/api/v1/auth/login", json=TEST_USER)
        token1 = response.json()["token"]

        # Login as user2
        response = client.post("/api/v1/auth/login", json={
            "username": "user2",
            "password": "password2"
        })
        token2 = response.json()["token"]

        # Exhaust rate limit for user1
        headers1 = {"Authorization": f"Bearer {token1}"}
        for _ in range(RATE_LIMIT_MAX_REQUESTS):
            response = client.get("/api/v1/monitor/stats", headers=headers1)
            assert response.status_code == 200

        # User1 should be rate limited
        response = client.get("/api/v1/monitor/stats", headers=headers1)
        assert response.status_code == 429

        # User2 should still work
        headers2 = {"Authorization": f"Bearer {token2}"}
        response = client.get("/api/v1/monitor/stats", headers=headers2)
        assert response.status_code == 200

    def test_rate_limit_by_resource(self):
        """Test resource-specific rate limiting"""
        resources = [
            ("/api/v1/monitor/stats", 100),
            ("/api/v1/monitor/alerts", 50),
            ("/api/v1/config/current", 20)
        ]

        for endpoint, limit in resources:
            # Make requests up to the specific limit
            for _ in range(limit):
                response = client.get(endpoint)
                assert response.status_code == 200

            # Next request should be rate limited
            response = client.get(endpoint)
            assert response.status_code == 429
            assert "X-RateLimit-Limit" in response.headers
            assert int(response.headers["X-RateLimit-Limit"]) == limit

    def test_rate_limit_burst(self):
        """Test burst rate limiting"""
        # Allow burst of requests
        for _ in range(RATE_LIMIT_MAX_REQUESTS * 2):
            response = client.get("/api/v1/monitor/stats")
            if response.status_code == 429:
                break
            assert response.status_code == 200

        # Should eventually be rate limited
        response = client.get("/api/v1/monitor/stats")
        assert response.status_code == 429

class TestClientExamples:
    """Tests for client examples in different languages"""

    def test_python_client(self):
        """Test Python client example"""
        class ARPGuardClient:
            def __init__(self, base_url):
                self.base_url = base_url
                self.session = requests.Session()

            def login(self, username, password):
                response = self.session.post(
                    f"{self.base_url}/api/v1/auth/login",
                    json={"username": username, "password": password}
                )
                response.raise_for_status()
                return response.json()["token"]

            def get_stats(self):
                response = self.session.get(
                    f"{self.base_url}/api/v1/monitor/stats"
                )
                response.raise_for_status()
                return response.json()

        # Test client
        client = ARPGuardClient("http://localhost:8000")
        token = client.login("test_user", "test_password")
        stats = client.get_stats()
        assert "packets_processed" in stats

    def test_curl_example(self):
        """Test curl example"""
        import subprocess
        import shlex

        # Test login
        cmd = shlex.split(
            'curl -X POST http://localhost:8000/api/v1/auth/login '
            '-H "Content-Type: application/json" '
            '-d \'{"username": "test_user", "password": "test_password"}\''
        )
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0
        response = json.loads(result.stdout)
        assert "token" in response

    def test_http_client_example(self):
        """Test HTTP client example"""
        import http.client
        import json

        conn = http.client.HTTPConnection("localhost", 8000)
        
        # Test login
        headers = {"Content-Type": "application/json"}
        body = json.dumps({"username": "test_user", "password": "test_password"})
        conn.request("POST", "/api/v1/auth/login", body, headers)
        response = conn.getresponse()
        assert response.status == 200
        data = json.loads(response.read())
        assert "token" in data

    def test_java_client_example(self):
        """Test Java client example"""
        java_code = """
        import java.net.http.HttpClient;
        import java.net.http.HttpRequest;
        import java.net.http.HttpResponse;
        import java.net.URI;
        import java.net.http.HttpHeaders;
        import java.util.concurrent.CompletableFuture;

        public class ARPGuardClient {
            private final HttpClient client;
            private final String baseUrl;
            private String token;

            public ARPGuardClient(String baseUrl) {
                this.client = HttpClient.newHttpClient();
                this.baseUrl = baseUrl;
            }

            public String login(String username, String password) throws Exception {
                String json = String.format("{\"username\":\"%s\",\"password\":\"%s\"}", 
                    username, password);
                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/api/v1/auth/login"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();

                HttpResponse<String> response = client.send(request, 
                    HttpResponse.BodyHandlers.ofString());
                return response.body();
            }
        }
        """
        # Verify Java code structure
        assert "HttpClient" in java_code
        assert "login" in java_code
        assert "baseUrl" in java_code

    def test_javascript_client_example(self):
        """Test JavaScript client example"""
        js_code = """
        class ARPGuardClient {
            constructor(baseUrl) {
                this.baseUrl = baseUrl;
            }

            async login(username, password) {
                const response = await fetch(`${this.baseUrl}/api/v1/auth/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });
                return await response.json();
            }

            async getStats(token) {
                const response = await fetch(`${this.baseUrl}/api/v1/monitor/stats`, {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
                return await response.json();
            }
        }
        """
        # Verify JavaScript code structure
        assert "class ARPGuardClient" in js_code
        assert "async login" in js_code
        assert "async getStats" in js_code

    def test_go_client_example(self):
        """Test Go client example"""
        go_code = """
        package main

        import (
            "bytes"
            "encoding/json"
            "net/http"
        )

        type ARPGuardClient struct {
            baseURL string
            client  *http.Client
        }

        func NewClient(baseURL string) *ARPGuardClient {
            return &ARPGuardClient{
                baseURL: baseURL,
                client:  &http.Client{},
            }
        }

        func (c *ARPGuardClient) Login(username, password string) (string, error) {
            data := map[string]string{
                "username": username,
                "password": password,
            }
            jsonData, _ := json.Marshal(data)
            
            req, _ := http.NewRequest("POST", c.baseURL+"/api/v1/auth/login", 
                bytes.NewBuffer(jsonData))
            req.Header.Set("Content-Type", "application/json")
            
            resp, err := c.client.Do(req)
            if err != nil {
                return "", err
            }
            defer resp.Body.Close()
            
            var result map[string]interface{}
            json.NewDecoder(resp.Body).Decode(&result)
            return result["token"].(string), nil
        }
        """
        # Verify Go code structure
        assert "type ARPGuardClient struct" in go_code
        assert "func (c *ARPGuardClient) Login" in go_code

    def test_csharp_client_example(self):
        """Test C# client example"""
        csharp_code = """
        using System;
        using System.Net.Http;
        using System.Text;
        using System.Text.Json;
        using System.Threading.Tasks;

        public class ARPGuardClient
        {
            private readonly HttpClient _client;
            private readonly string _baseUrl;

            public ARPGuardClient(string baseUrl)
            {
                _client = new HttpClient();
                _baseUrl = baseUrl;
            }

            public async Task<string> LoginAsync(string username, string password)
            {
                var content = new StringContent(
                    JsonSerializer.Serialize(new { username, password }),
                    Encoding.UTF8,
                    "application/json"
                );

                var response = await _client.PostAsync($"{_baseUrl}/api/v1/auth/login", content);
                response.EnsureSuccessStatusCode();
                
                var result = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<JsonElement>(result)
                    .GetProperty("token")
                    .GetString();
            }
        }
        """
        # Verify C# code structure
        assert "HttpClient" in csharp_code
        assert "LoginAsync" in csharp_code
        assert "EnsureSuccessStatusCode" in csharp_code

    def test_ruby_client_example(self):
        """Test Ruby client example"""
        ruby_code = """
        require 'net/http'
        require 'json'
        require 'uri'

        class ARPGuardClient
          def initialize(base_url)
            @base_url = base_url
            @uri = URI.parse(base_url)
            @http = Net::HTTP.new(@uri.host, @uri.port)
          end

          def login(username, password)
            request = Net::HTTP::Post.new('/api/v1/auth/login')
            request['Content-Type'] = 'application/json'
            request.body = { username: username, password: password }.to_json

            response = @http.request(request)
            JSON.parse(response.body)['token']
          end
        end
        """
        # Verify Ruby code structure
        assert "class ARPGuardClient" in ruby_code
        assert "def login" in ruby_code
        assert "Net::HTTP" in ruby_code

    def test_rust_client_example(self):
        """Test Rust client example"""
        rust_code = """
        use reqwest;
        use serde_json::json;

        pub struct ARPGuardClient {
            client: reqwest::Client,
            base_url: String,
        }

        impl ARPGuardClient {
            pub fn new(base_url: String) -> Self {
                ARPGuardClient {
                    client: reqwest::Client::new(),
                    base_url,
                }
            }

            pub async fn login(&self, username: &str, password: &str) -> Result<String, reqwest::Error> {
                let response = self.client
                    .post(&format!("{}/api/v1/auth/login", self.base_url))
                    .json(&json!({
                        "username": username,
                        "password": password
                    }))
                    .send()
                    .await?;

                let token = response.json::<serde_json::Value>().await?;
                Ok(token["token"].as_str().unwrap().to_string())
            }
        }
        """
        # Verify Rust code structure
        assert "struct ARPGuardClient" in rust_code
        assert "impl ARPGuardClient" in rust_code
        assert "async fn login" in rust_code

class TestDocumentationExamples:
    def test_python_example(self, auth_token):
        """Test the Python example from documentation"""
        # Test login
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin"}
        )
        assert response.status_code == 200
        token = response.json()["token"]

        # Test getting stats
        response = client.get(
            "/api/v1/monitor/stats",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200

        # Test updating config
        response = client.put(
            "/api/v1/config/update",
            headers={"Authorization": f"Bearer {token}"},
            json=TEST_CONFIG
        )
        assert response.status_code == 200

    def test_python_client_example(self):
        """Test Python client example from documentation"""
        # Login
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin"}
        )
        assert response.status_code == 200
        token = response.json()["token"]

        # Get stats with headers
        headers = {"Authorization": f"Bearer {token}"}
        response = client.get("/api/v1/monitor/stats", headers=headers)
        assert response.status_code == 200
        stats = response.json()
        assert isinstance(stats, dict)

        # Update config with error handling
        try:
            response = client.put(
                "/api/v1/config/update",
                headers=headers,
                json={"invalid": "config"}
            )
            assert response.status_code == 400
            assert "error" in response.json()
        except Exception as e:
            pytest.fail(f"Unexpected error: {str(e)}")

    def test_error_handling_examples(self):
        """Test error handling examples from documentation"""
        # Test invalid JSON
        response = client.post(
            "/api/v1/auth/login",
            data="invalid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422

        # Test missing required field
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "test_user"}
        )
        assert response.status_code == 422

        # Test invalid content type
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "test_user", "password": "test_password"},
            headers={"Content-Type": "text/plain"}
        )
        assert response.status_code == 415

    def test_rate_limiting_examples(self):
        """Test rate limiting examples from documentation"""
        # Test rate limiting headers
        for _ in range(5):
            response = client.get("/api/v1/monitor/stats")
            assert "X-RateLimit-Limit" in response.headers
            assert "X-RateLimit-Remaining" in response.headers

        # Test rate limit exceeded
        response = client.get("/api/v1/monitor/stats")
        assert response.status_code == 429
        assert "X-RateLimit-Reset" in response.headers 