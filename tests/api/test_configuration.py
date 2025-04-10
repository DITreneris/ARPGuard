import pytest
import os
import json
import shutil
import tempfile
import zipfile
from io import BytesIO
from fastapi.testclient import TestClient

from app.api import app
from app.api.endpoints.configuration import CONFIG_DIR, BACKUP_DIR

client = TestClient(app)

@pytest.fixture
def auth_token():
    """Generate an authentication token for testing"""
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "test_user", "password": "test_password"}
    )
    return response.json().get("access_token")

@pytest.fixture(autouse=True)
def setup_test_config():
    """Set up test configuration directory"""
    # Create test config directory
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)
    
    # Create a test config file
    test_config = {
        "network": {
            "interface": "eth0",
            "monitoring_mode": "promiscuous",
            "promiscuous_mode": True,
            "packet_buffer_size": 1024,
            "packet_timeout": 1.0
        },
        "security": {
            "arp_spoofing": {
                "enabled": True,
                "threshold": 100,
                "alert_level": "high"
            },
            "mac_flooding_enabled": True,
            "mac_flooding_threshold": 50,
            "ip_spoofing_detection": True,
            "block_attacks": False,
            "alert_admin": True
        },
        "notification": {
            "email_enabled": False,
            "webhook_enabled": False,
            "webhook_url": None,
            "smtp_settings": None
        },
        "backup": {
            "auto_backup": False,
            "backup_interval_hours": 24,
            "max_backups": 10,
            "include_logs": False
        }
    }
    
    with open(os.path.join(CONFIG_DIR, "config.yaml"), "w") as f:
        import yaml
        yaml.dump(test_config, f, default_flow_style=False)
    
    yield
    
    # Clean up (comment this out if you want to keep the test artifacts)
    try:
        shutil.rmtree(BACKUP_DIR)
    except:
        pass

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
        assert "backup" in data
        assert data["network"]["interface"] == "eth0"

    def test_update_configuration(self, auth_token):
        """Test updating configuration"""
        config_update = {
            "network": {
                "interface": "eth1",
                "monitoring_mode": "passive",
                "promiscuous_mode": False,
                "packet_buffer_size": 2048,
                "packet_timeout": 2.0
            }
        }
        
        response = client.put(
            "/api/v1/config/update",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=config_update
        )
        assert response.status_code == 200
        assert response.json()["status"] == "success"
        
        # Verify update
        response = client.get(
            "/api/v1/config/current",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["network"]["interface"] == "eth1"
        assert data["network"]["monitoring_mode"] == "passive"
        assert data["network"]["promiscuous_mode"] == False
        assert data["network"]["packet_buffer_size"] == 2048
        assert data["network"]["packet_timeout"] == 2.0

    def test_create_backup(self, auth_token):
        """Test creating a configuration backup"""
        response = client.post(
            "/api/v1/config/backup",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "success"
        assert "backup_id" in data
        
        # Verify backup exists
        backup_id = data["backup_id"]
        backup_path = os.path.join(BACKUP_DIR, f"{backup_id}.zip")
        assert os.path.exists(backup_path)
        
        # Verify backup file is a valid zip file with config.yaml
        with zipfile.ZipFile(backup_path, "r") as zipf:
            assert "config.yaml" in zipf.namelist()

    def test_list_backups(self, auth_token):
        """Test listing configuration backups"""
        # First create a backup
        client.post(
            "/api/v1/config/backup",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        response = client.get(
            "/api/v1/config/backup",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        assert "id" in data[0]
        assert "timestamp" in data[0]
        assert "size_bytes" in data[0]
        assert "filename" in data[0]

    def test_download_backup(self, auth_token):
        """Test downloading a configuration backup"""
        # First create a backup
        response = client.post(
            "/api/v1/config/backup",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        backup_id = response.json()["backup_id"]
        
        # Download the backup
        response = client.get(
            f"/api/v1/config/backup/{backup_id}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/zip"
        assert response.headers["content-disposition"] == f'filename="{backup_id}.zip"'
        
        # Verify the content is a valid zip file with config.yaml
        content = BytesIO(response.content)
        with zipfile.ZipFile(content, "r") as zipf:
            assert "config.yaml" in zipf.namelist()

    def test_restore_backup(self, auth_token):
        """Test restoring configuration from backup"""
        # First create a backup
        response = client.post(
            "/api/v1/config/backup",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        backup_id = response.json()["backup_id"]
        
        # Update the configuration
        config_update = {
            "network": {
                "interface": "eth2",
                "monitoring_mode": "passive"
            }
        }
        client.put(
            "/api/v1/config/update",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=config_update
        )
        
        # Verify update
        response = client.get(
            "/api/v1/config/current",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.json()["network"]["interface"] == "eth2"
        
        # Restore the backup
        response = client.post(
            f"/api/v1/config/restore/{backup_id}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        assert response.json()["status"] == "success"
        
        # Verify restoration
        response = client.get(
            "/api/v1/config/current",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.json()["network"]["interface"] == "eth0"  # Original value

    def test_export_configuration(self, auth_token):
        """Test exporting configuration"""
        response = client.get(
            "/api/v1/config/export",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/x-yaml"
        assert "arpguard_config.yaml" in response.headers["content-disposition"]
        
        # Verify content is valid YAML
        import yaml
        config_data = yaml.safe_load(response.content)
        assert "network" in config_data
        assert "security" in config_data
        assert "notification" in config_data
        assert "backup" in config_data

    def test_export_backup(self, auth_token):
        """Test exporting configuration as backup"""
        response = client.get(
            "/api/v1/config/export/backup",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/zip"
        assert "backup_" in response.headers["content-disposition"]
        
        # Verify the content is a valid zip file with config.yaml
        content = BytesIO(response.content)
        with zipfile.ZipFile(content, "r") as zipf:
            assert "config.yaml" in zipf.namelist()

    def test_import_yaml_configuration(self, auth_token):
        """Test importing YAML configuration"""
        # Create a test YAML file
        config_data = {
            "network": {
                "interface": "eth3",
                "monitoring_mode": "promiscuous",
                "promiscuous_mode": True,
                "packet_buffer_size": 4096,
                "packet_timeout": 0.5
            },
            "security": {
                "arp_spoofing": {
                    "enabled": False,
                    "threshold": 200,
                    "alert_level": "medium"
                },
                "mac_flooding_enabled": False,
                "mac_flooding_threshold": 100,
                "ip_spoofing_detection": False,
                "block_attacks": True,
                "alert_admin": False
            },
            "notification": {
                "email_enabled": True,
                "webhook_enabled": True,
                "webhook_url": "https://example.com/webhook",
                "smtp_settings": {
                    "server": "smtp.example.com",
                    "port": 587,
                    "username": "user",
                    "password": "pass",
                    "use_tls": True
                }
            },
            "backup": {
                "auto_backup": True,
                "backup_interval_hours": 12,
                "max_backups": 5,
                "include_logs": True
            }
        }
        
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as temp_file:
            import yaml
            yaml.dump(config_data, temp_file)
            temp_file_path = temp_file.name
        
        try:
            # Import the configuration
            with open(temp_file_path, "rb") as f:
                response = client.post(
                    "/api/v1/config/import",
                    headers={"Authorization": f"Bearer {auth_token}"},
                    files={"file": ("test_config.yaml", f, "application/x-yaml")}
                )
            assert response.status_code == 200
            assert response.json()["status"] == "success"
            
            # Verify import
            response = client.get(
                "/api/v1/config/current",
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            assert response.json()["network"]["interface"] == "eth3"
            assert response.json()["security"]["arp_spoofing"]["enabled"] == False
            assert response.json()["notification"]["email_enabled"] == True
            assert response.json()["notification"]["smtp_settings"]["server"] == "smtp.example.com"
            assert response.json()["backup"]["auto_backup"] == True
        finally:
            # Clean up
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)

    def test_import_zip_configuration(self, auth_token):
        """Test importing ZIP configuration backup"""
        # First create a backup
        response = client.post(
            "/api/v1/config/backup",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        backup_id = response.json()["backup_id"]
        backup_path = os.path.join(BACKUP_DIR, f"{backup_id}.zip")
        
        # Update the configuration
        config_update = {
            "network": {
                "interface": "eth4",
                "monitoring_mode": "passive"
            }
        }
        client.put(
            "/api/v1/config/update",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=config_update
        )
        
        # Import the backup
        with open(backup_path, "rb") as f:
            response = client.post(
                "/api/v1/config/import",
                headers={"Authorization": f"Bearer {auth_token}"},
                files={"file": (f"{backup_id}.zip", f, "application/zip")}
            )
        assert response.status_code == 200
        assert response.json()["status"] == "success"
        
        # Verify import
        response = client.get(
            "/api/v1/config/current",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.json()["network"]["interface"] == "eth0"  # Original value

    def test_invalid_import_format(self, auth_token):
        """Test importing with invalid format"""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as temp_file:
            temp_file.write(b"This is not a valid config file")
            temp_file_path = temp_file.name
        
        try:
            # Try to import invalid file
            with open(temp_file_path, "rb") as f:
                response = client.post(
                    "/api/v1/config/import",
                    headers={"Authorization": f"Bearer {auth_token}"},
                    files={"file": ("invalid.txt", f, "text/plain")}
                )
            assert response.status_code == 400
            assert "Invalid file format" in response.json()["detail"]
        finally:
            # Clean up
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path) 