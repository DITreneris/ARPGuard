#!/usr/bin/env python
"""
Integration tests for the backup and restore functionality.
Tests the complete backup and restore flow across different components.
"""
import os
import sys
import json
import tempfile
import unittest
import zipfile
from io import StringIO, BytesIO
from contextlib import redirect_stdout
from unittest.mock import Mock, patch, MagicMock

from fastapi.testclient import TestClient

from app.api import app
from app.api.endpoints.configuration import CONFIG_DIR, BACKUP_DIR
from app.utils.config import ConfigManager, get_config_manager


class TestBackupRestoreIntegration(unittest.TestCase):
    """
    Integration tests for the backup and restore functionality.
    Tests across UI, API, CLI, and utility components.
    """
    
    def setUp(self):
        """Set up the test case."""
        self.client = TestClient(app)
        
        # Create a temporary directory for test files
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.temp_dir.name, "config.yaml")
        self.backup_dir = os.path.join(self.temp_dir.name, "backups")
        
        # Create backup directory
        os.makedirs(self.backup_dir, exist_ok=True)
        
        # Create a test token
        self.auth_token = "test_token"
        
        # Apply patches for testing
        self.patches = [
            patch('app.api.endpoints.configuration.CONFIG_DIR', self.temp_dir.name),
            patch('app.api.endpoints.configuration.BACKUP_DIR', self.backup_dir),
            patch('app.api.endpoints.auth.verify_token', return_value={"sub": "test_user"}),
        ]
        
        for p in self.patches:
            p.start()
            
        # Create a test config file
        self.test_config = {
            "network": {
                "interface": "eth0",
                "monitoring_mode": "promiscuous",
                "promiscuous_mode": True,
                "packet_buffer_size": 1024
            },
            "security": {
                "arp_spoofing": {
                    "enabled": True,
                    "threshold": 100,
                    "alert_level": "high"
                },
                "mac_flooding_enabled": True
            }
        }
        
        # Write test config to file
        with open(os.path.join(self.temp_dir.name, "config.yaml"), "w") as f:
            import yaml
            yaml.dump(self.test_config, f, default_flow_style=False)
    
    def tearDown(self):
        """Clean up after the test case."""
        # Stop all patches
        for p in self.patches:
            p.stop()
            
        # Clean up temp directory
        self.temp_dir.cleanup()
    
    def test_complete_backup_restore_flow(self):
        """Test a complete backup and restore flow between components."""
        # 1. Create a backup via API
        response = self.client.post(
            "/api/v1/config/backup",
            headers={"Authorization": f"Bearer {self.auth_token}"}
        )
        assert response.status_code == 201
        backup_data = response.json()
        backup_id = backup_data["backup_id"]
        
        # Verify backup exists
        backup_path = os.path.join(self.backup_dir, f"{backup_id}.zip")
        assert os.path.exists(backup_path)
        
        # 2. Modify the configuration
        config_update = {
            "network": {
                "interface": "eth1",
                "monitoring_mode": "passive"
            }
        }
        response = self.client.put(
            "/api/v1/config/update",
            headers={"Authorization": f"Bearer {self.auth_token}"},
            json=config_update
        )
        assert response.status_code == 200
        
        # Verify the update was applied
        response = self.client.get(
            "/api/v1/config/current",
            headers={"Authorization": f"Bearer {self.auth_token}"}
        )
        assert response.status_code == 200
        updated_config = response.json()
        assert updated_config["network"]["interface"] == "eth1"
        assert updated_config["network"]["monitoring_mode"] == "passive"
        
        # 3. Restore from backup
        response = self.client.post(
            f"/api/v1/config/restore/{backup_id}",
            headers={"Authorization": f"Bearer {self.auth_token}"}
        )
        assert response.status_code == 200
        
        # 4. Verify the restore was successful
        response = self.client.get(
            "/api/v1/config/current",
            headers={"Authorization": f"Bearer {self.auth_token}"}
        )
        assert response.status_code == 200
        restored_config = response.json()
        
        # Configuration should be back to original values
        assert restored_config["network"]["interface"] == "eth0"
        assert restored_config["network"]["monitoring_mode"] == "promiscuous"
    
    def test_backup_restore_with_file_import_export(self):
        """Test backup and restore using file import/export capabilities."""
        # 1. Export the current configuration
        response = self.client.get(
            "/api/v1/config/export/backup",
            headers={"Authorization": f"Bearer {self.auth_token}"}
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/zip"
        
        # Save the exported file
        exported_zip = BytesIO(response.content)
        
        # 2. Modify the configuration
        config_update = {
            "network": {
                "interface": "eth2",
                "packet_buffer_size": 2048
            }
        }
        response = self.client.put(
            "/api/v1/config/update",
            headers={"Authorization": f"Bearer {self.auth_token}"},
            json=config_update
        )
        assert response.status_code == 200
        
        # 3. Import the previously exported configuration
        response = self.client.post(
            "/api/v1/config/import",
            headers={"Authorization": f"Bearer {self.auth_token}"},
            files={"file": ("backup.zip", exported_zip, "application/zip")}
        )
        assert response.status_code == 200
        
        # 4. Verify the configuration was restored
        response = self.client.get(
            "/api/v1/config/current",
            headers={"Authorization": f"Bearer {self.auth_token}"}
        )
        assert response.status_code == 200
        restored_config = response.json()
        
        assert restored_config["network"]["interface"] == "eth0"
        assert restored_config["network"]["packet_buffer_size"] == 1024
    
    def test_backup_list_management(self):
        """Test backup listing and management."""
        # 1. Create multiple backups
        backup_ids = []
        for _ in range(3):
            response = self.client.post(
                "/api/v1/config/backup",
                headers={"Authorization": f"Bearer {self.auth_token}"}
            )
            assert response.status_code == 201
            backup_ids.append(response.json()["backup_id"])
        
        # 2. List all backups
        response = self.client.get(
            "/api/v1/config/backup",
            headers={"Authorization": f"Bearer {self.auth_token}"}
        )
        assert response.status_code == 200
        backups = response.json()
        
        # Verify we have the expected number of backups
        assert len(backups) >= 3
        
        # Verify our backup IDs are in the list
        listed_ids = [b["id"] for b in backups]
        for bid in backup_ids:
            assert bid in listed_ids
        
        # 3. Download a specific backup
        response = self.client.get(
            f"/api/v1/config/backup/{backup_ids[0]}",
            headers={"Authorization": f"Bearer {self.auth_token}"}
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/zip"
        
        # 4. Verify the backup file structure
        content = BytesIO(response.content)
        with zipfile.ZipFile(content, "r") as zipf:
            assert "config.yaml" in zipf.namelist()
    
    def test_backup_restore_error_handling(self):
        """Test error handling during backup and restore operations."""
        # 1. Attempt to restore a non-existent backup
        response = self.client.post(
            "/api/v1/config/restore/non_existent_backup_id",
            headers={"Authorization": f"Bearer {self.auth_token}"}
        )
        assert response.status_code == 404
        
        # 2. Attempt to download a non-existent backup
        response = self.client.get(
            "/api/v1/config/backup/non_existent_backup_id",
            headers={"Authorization": f"Bearer {self.auth_token}"}
        )
        assert response.status_code == 404
        
        # 3. Attempt to import an invalid file format
        with tempfile.NamedTemporaryFile(suffix=".txt") as tmp:
            tmp.write(b"This is not a valid config file")
            tmp.seek(0)
            
            response = self.client.post(
                "/api/v1/config/import",
                headers={"Authorization": f"Bearer {self.auth_token}"},
                files={"file": ("invalid.txt", tmp, "text/plain")}
            )
            assert response.status_code == 400


if __name__ == "__main__":
    unittest.main() 