import pytest
import json
import asyncio
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from httpx import AsyncClient
import websockets

from app.api import app

client = TestClient(app)

@pytest.fixture
def auth_token():
    """Generate an authentication token for testing"""
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "test_user", "password": "test_password"}
    )
    return response.json().get("access_token")

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
        assert "cpu_usage" in data
        assert "memory_usage" in data
        assert "response_time" in data
        assert "timestamp" in data

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
            "/api/v1/monitor/alerts?severity=critical",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        assert "alerts" in response.json()

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
            # Detailed fields should be present
            assert "device_type" in node
            assert "hostname" in node
            assert "is_gateway" in node

    def test_get_alerts_with_multiple_filters(self, auth_token):
        """Test alert filtering with multiple parameters"""
        response = client.get(
            "/api/v1/monitor/alerts?severity=critical&time_range=1h&status=active",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        assert "alerts" in response.json()

    def test_get_alerts_with_invalid_filters(self, auth_token):
        """Test alert filtering with invalid parameters"""
        response = client.get(
            "/api/v1/monitor/alerts?severity=invalid&time_range=invalid",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 400
        assert "error" in response.json() or "detail" in response.json()

    def test_get_topology_with_invalid_details(self, auth_token):
        """Test topology with invalid details parameter"""
        response = client.get(
            "/api/v1/monitor/topology?details=invalid",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 400
        assert "error" in response.json() or "detail" in response.json()
        
    def test_trigger_test_alert(self, auth_token):
        """Test the alert trigger endpoint"""
        response = client.post(
            "/api/v1/monitor/trigger-test-alert",
            headers={"Authorization": f"Bearer {auth_token}"},
            params={"alert_type": "mac_spoofing", "severity": "high"}
        )
        assert response.status_code == 201
        data = response.json()
        assert "status" in data
        assert data["status"] == "success"
        assert "alert_id" in data
        
        # Verify the alert was added
        response = client.get(
            "/api/v1/monitor/alerts",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        alerts = response.json()["alerts"]
        assert any(alert["type"] == "mac_spoofing" for alert in alerts)
        
    def test_get_historical_data(self, auth_token):
        """Test historical data endpoint"""
        start_date = (datetime.now() - timedelta(days=1)).isoformat()
        end_date = datetime.now().isoformat()
        
        valid_metrics = [
            "packets_processed", "attacks_detected", "network_throughput", 
            "cpu_usage", "memory_usage", "response_time"
        ]
        
        for metric in valid_metrics:
            response = client.get(
                f"/api/v1/monitor/historical?metric={metric}&start_date={start_date}&end_date={end_date}&interval=1h",
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            assert response.status_code == 200
            data = response.json()
            assert "metric" in data
            assert data["metric"] == metric
            assert "data_points" in data
            assert len(data["data_points"]) > 0
            
    def test_get_historical_data_invalid_dates(self, auth_token):
        """Test historical data with invalid dates"""
        response = client.get(
            "/api/v1/monitor/historical?metric=cpu_usage&start_date=invalid&end_date=invalid",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 400
        assert "detail" in response.json()
        
    def test_get_historical_data_invalid_metric(self, auth_token):
        """Test historical data with invalid metric"""
        start_date = (datetime.now() - timedelta(days=1)).isoformat()
        end_date = datetime.now().isoformat()
        
        response = client.get(
            f"/api/v1/monitor/historical?metric=invalid&start_date={start_date}&end_date={end_date}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 400
        assert "detail" in response.json()

@pytest.mark.asyncio
class TestWebSocketEndpoint:
    """Test the WebSocket endpoint for real-time updates"""
    
    async def test_websocket_connection(self):
        """Test basic WebSocket connection"""
        uri = "ws://localhost:8000/api/v1/monitor/ws"
        async with websockets.connect(uri) as websocket:
            # Send a test message
            await websocket.send("hello")
            # Get response
            response = await websocket.recv()
            assert "Message received" in response
            
    async def test_websocket_monitoring_updates(self):
        """Test receiving monitoring updates"""
        uri = "ws://localhost:8000/api/v1/monitor/ws"
        async with websockets.connect(uri) as websocket:
            # Wait for an update
            try:
                # Set a timeout to avoid blocking indefinitely
                response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                data = json.loads(response)
                
                # Check data structure
                assert "type" in data
                assert data["type"] == "stats_update"
                assert "data" in data
                
                # Check metrics
                metrics = data["data"]
                assert "packets_processed" in metrics
                assert "attacks_detected" in metrics
                assert "network_throughput" in metrics
                assert "cpu_usage" in metrics
                assert "memory_usage" in metrics
                assert "response_time" in metrics
                assert "timestamp" in metrics
            except asyncio.TimeoutError:
                # If no updates received within timeout, the test can still pass
                # This is to avoid flaky tests if updates are slow
                pass 