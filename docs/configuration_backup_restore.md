# Configuration Backup and Restore

This document describes the configuration backup and restore features of the ARPGuard application.

## Overview

ARPGuard provides a comprehensive system for managing, backing up, and restoring system configurations. This ensures that you can:

- Maintain multiple configuration versions
- Roll back to a previous working configuration
- Transfer configurations between deployments
- Safely test new configurations with the ability to revert changes

## API Endpoints

### Configuration Management

#### Get Current Configuration
```http
GET /api/v1/config/current
Authorization: Bearer <token>
```

Response:
```json
{
  "network": {
    "interface": "eth0",
    "monitoring_mode": "promiscuous",
    "promiscuous_mode": true,
    "packet_buffer_size": 1024,
    "packet_timeout": 1.0
  },
  "security": {
    "arp_spoofing": {
      "enabled": true,
      "threshold": 100,
      "alert_level": "high"
    },
    "mac_flooding_enabled": true,
    "mac_flooding_threshold": 50,
    "ip_spoofing_detection": true,
    "block_attacks": false,
    "alert_admin": true
  },
  "notification": {
    "email_enabled": false,
    "webhook_enabled": false,
    "webhook_url": null,
    "smtp_settings": null
  },
  "backup": {
    "auto_backup": false,
    "backup_interval_hours": 24,
    "max_backups": 10,
    "include_logs": false
  }
}
```

#### Update Configuration
```http
PUT /api/v1/config/update
Authorization: Bearer <token>
Content-Type: application/json

{
  "network": {
    "interface": "eth1",
    "monitoring_mode": "passive"
  }
}
```

Response:
```json
{
  "status": "success",
  "message": "Configuration updated successfully"
}
```

Note: You only need to include the sections you want to update in the request body.

### Backup Management

#### List Available Backups
```http
GET /api/v1/config/backup
Authorization: Bearer <token>
```

Response:
```json
[
  {
    "id": "backup_20240420_120000",
    "timestamp": "2024-04-20T12:00:00",
    "size_bytes": 1024,
    "filename": "backup_20240420_120000.zip",
    "config_version": "1.0"
  },
  {
    "id": "backup_20240419_120000",
    "timestamp": "2024-04-19T12:00:00",
    "size_bytes": 1024,
    "filename": "backup_20240419_120000.zip",
    "config_version": "1.0"
  }
]
```

#### Create a New Backup
```http
POST /api/v1/config/backup
Authorization: Bearer <token>
```

Response:
```json
{
  "status": "success",
  "message": "Backup created successfully",
  "backup_id": "backup_20240420_120000"
}
```

#### Download a Backup
```http
GET /api/v1/config/backup/{backup_id}
Authorization: Bearer <token>
```

Response: A ZIP file containing the configuration backup.

#### Restore from a Backup
```http
POST /api/v1/config/restore/{backup_id}
Authorization: Bearer <token>
```

Response:
```json
{
  "status": "success",
  "message": "Configuration restored successfully"
}
```

### Import/Export

#### Export Current Configuration
```http
GET /api/v1/config/export
Authorization: Bearer <token>
```

Response: A YAML file containing the current configuration.

#### Export Current Configuration as Backup
```http
GET /api/v1/config/export/backup
Authorization: Bearer <token>
```

Response: A ZIP file containing the current configuration as a backup.

#### Import Configuration
```http
POST /api/v1/config/import
Authorization: Bearer <token>
Content-Type: multipart/form-data

file: <configuration file>
```

Response:
```json
{
  "status": "success",
  "message": "Configuration imported successfully"
}
```

Accepted file formats:
- `.yaml` or `.yml`: Single configuration file
- `.zip`: Complete backup package

## Usage Examples

### Python Client Example

```python
import requests
import json
import os

class ARPGuardConfigClient:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {token}"
        }
        
    def get_current_config(self):
        """Get current configuration"""
        response = requests.get(
            f"{self.base_url}/api/v1/config/current",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()
        
    def update_config(self, config_update):
        """Update configuration"""
        response = requests.put(
            f"{self.base_url}/api/v1/config/update",
            headers=self.headers,
            json=config_update
        )
        response.raise_for_status()
        return response.json()
        
    def create_backup(self):
        """Create a new backup"""
        response = requests.post(
            f"{self.base_url}/api/v1/config/backup",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()
        
    def list_backups(self):
        """List available backups"""
        response = requests.get(
            f"{self.base_url}/api/v1/config/backup",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()
        
    def download_backup(self, backup_id, output_path):
        """Download a backup"""
        response = requests.get(
            f"{self.base_url}/api/v1/config/backup/{backup_id}",
            headers=self.headers,
            stream=True
        )
        response.raise_for_status()
        
        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                
        return output_path
        
    def restore_backup(self, backup_id):
        """Restore from a backup"""
        response = requests.post(
            f"{self.base_url}/api/v1/config/restore/{backup_id}",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()
        
    def export_config(self, output_path):
        """Export current configuration"""
        response = requests.get(
            f"{self.base_url}/api/v1/config/export",
            headers=self.headers,
            stream=True
        )
        response.raise_for_status()
        
        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                
        return output_path
        
    def import_config(self, file_path):
        """Import configuration"""
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = requests.post(
                f"{self.base_url}/api/v1/config/import",
                headers=self.headers,
                files=files
            )
            response.raise_for_status()
            return response.json()
```

### Usage Example

```python
# Initialize client
client = ARPGuardConfigClient("http://localhost:8000", "your_token_here")

# Get current configuration
config = client.get_current_config()
print(f"Current network interface: {config['network']['interface']}")

# Create a backup before making changes
backup = client.create_backup()
print(f"Created backup: {backup['backup_id']}")

# Update configuration
update = {
    "network": {
        "interface": "eth1",
        "monitoring_mode": "passive"
    }
}
result = client.update_config(update)
print(f"Update result: {result['message']}")

# List available backups
backups = client.list_backups()
print(f"Available backups: {len(backups)}")

# Restore from backup if needed
if input("Restore from backup? (y/n): ").lower() == 'y':
    result = client.restore_backup(backup['backup_id'])
    print(f"Restore result: {result['message']}")
```

## Best Practices

1. **Regular Backups**: Enable auto-backup or create manual backups before making significant changes.

2. **Version Control**: Keep multiple backup versions to ensure you can roll back to various points in time.

3. **Documentation**: Add meaningful descriptions to your configurations to understand the purpose of each version.

4. **Testing**: Test restored configurations in a non-production environment when possible.

5. **Security**: Protect backup files as they may contain sensitive information like API keys or credentials.

6. **Storage Management**: Regularly clean up old backups to prevent excessive disk usage.

## Troubleshooting

### Common Issues

1. **Backup creation fails**
   - Check disk space availability
   - Verify write permissions to the config/backups directory

2. **Import fails with validation errors**
   - Ensure the configuration file follows the correct schema
   - Check for mandatory fields or type mismatches

3. **Restore doesn't apply all settings**
   - Backup might be from an older version with different schema
   - Some settings may require service restart to take effect

### Recovery Options

1. If you can't restore through the API, manual recovery options include:
   - Directly extracting ZIP backups to the config directory
   - Editing configuration files manually following the schema

2. For emergency recovery:
   - The system maintains at least one automatic backup before changes
   - Default configuration is always available if all backups fail 