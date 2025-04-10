import os
import json
import yaml
import shutil
import zipfile
import tempfile
from datetime import datetime
from typing import Dict, List, Optional, Union, Any
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field, validator

from app.core.auth import get_current_user

# Create router for configuration endpoints
router = APIRouter(prefix="/api/v1/config", tags=["configuration"])

# Config directory
CONFIG_DIR = "config"
BACKUP_DIR = "config/backups"
TEMPLATE_DIR = "config/templates"

# Ensure directories exist
os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(TEMPLATE_DIR, exist_ok=True)

# Models for configuration
class NetworkConfig(BaseModel):
    interface: str
    monitoring_mode: str = "promiscuous"
    promiscuous_mode: bool = True
    packet_buffer_size: int = 1024
    packet_timeout: float = 1.0

class ArpSpoofingConfig(BaseModel):
    enabled: bool = True
    threshold: int = 100
    alert_level: str = "high"

class SecurityConfig(BaseModel):
    arp_spoofing: ArpSpoofingConfig
    mac_flooding_enabled: bool = True
    mac_flooding_threshold: int = 50
    ip_spoofing_detection: bool = True
    block_attacks: bool = False
    alert_admin: bool = True

class SmtpSettings(BaseModel):
    server: str
    port: int
    username: str
    password: str
    use_tls: bool = True

class NotificationConfig(BaseModel):
    email_enabled: bool = False
    webhook_enabled: bool = False
    webhook_url: Optional[str] = None
    smtp_settings: Optional[SmtpSettings] = None

class BackupConfig(BaseModel):
    auto_backup: bool = False
    backup_interval_hours: int = 24
    max_backups: int = 10
    include_logs: bool = False

class CompleteConfig(BaseModel):
    network: NetworkConfig
    security: SecurityConfig
    notification: NotificationConfig
    backup: BackupConfig = Field(default_factory=BackupConfig)

class ConfigUpdateRequest(BaseModel):
    network: Optional[NetworkConfig] = None
    security: Optional[SecurityConfig] = None
    notification: Optional[NotificationConfig] = None
    backup: Optional[BackupConfig] = None

class BackupInfo(BaseModel):
    id: str
    timestamp: str
    size_bytes: int
    filename: str
    config_version: str = "1.0"

class TemplateInfo(BaseModel):
    id: str
    name: str
    description: str
    timestamp: str
    size_bytes: int
    filename: str
    tags: List[str] = []

class TemplateCreateRequest(BaseModel):
    name: str
    description: str
    tags: List[str] = []
    config_sections: Optional[List[str]] = None

class TemplateApplyRequest(BaseModel):
    sections: Optional[List[str]] = None

# Sample configuration (in a real implementation, this would be loaded from a file)
sample_config = CompleteConfig(
    network=NetworkConfig(
        interface="eth0",
        monitoring_mode="promiscuous",
        promiscuous_mode=True,
        packet_buffer_size=1024,
        packet_timeout=1.0
    ),
    security=SecurityConfig(
        arp_spoofing=ArpSpoofingConfig(
            enabled=True,
            threshold=100,
            alert_level="high"
        ),
        mac_flooding_enabled=True,
        mac_flooding_threshold=50,
        ip_spoofing_detection=True,
        block_attacks=False,
        alert_admin=True
    ),
    notification=NotificationConfig(
        email_enabled=False,
        webhook_enabled=False
    ),
    backup=BackupConfig(
        auto_backup=False,
        backup_interval_hours=24,
        max_backups=10,
        include_logs=False
    )
)

# Predefined configuration templates
PREDEFINED_TEMPLATES = {
    "high_security": {
        "name": "High Security",
        "description": "Maximum security settings for high-risk environments",
        "tags": ["security", "enterprise"],
        "config": {
            "security": {
                "arp_spoofing": {
                    "enabled": True,
                    "threshold": 50,
                    "alert_level": "critical"
                },
                "mac_flooding_enabled": True,
                "mac_flooding_threshold": 20,
                "ip_spoofing_detection": True,
                "block_attacks": True,
                "alert_admin": True
            }
        }
    },
    "low_resource": {
        "name": "Low Resource Usage",
        "description": "Optimized for systems with limited resources",
        "tags": ["performance", "iot"],
        "config": {
            "network": {
                "packet_buffer_size": 512,
                "packet_timeout": 0.5
            },
            "security": {
                "arp_spoofing": {
                    "enabled": True,
                    "threshold": 200,
                    "alert_level": "medium"
                },
                "mac_flooding_enabled": True,
                "mac_flooding_threshold": 100,
                "ip_spoofing_detection": False,
                "block_attacks": False,
                "alert_admin": True
            }
        }
    },
    "monitoring_only": {
        "name": "Monitoring Only",
        "description": "Non-intrusive monitoring without blocking capabilities",
        "tags": ["monitoring", "passive"],
        "config": {
            "network": {
                "monitoring_mode": "passive",
                "promiscuous_mode": True
            },
            "security": {
                "arp_spoofing": {
                    "enabled": True,
                    "threshold": 100,
                    "alert_level": "medium"
                },
                "mac_flooding_enabled": True,
                "mac_flooding_threshold": 50,
                "ip_spoofing_detection": True,
                "block_attacks": False,
                "alert_admin": True
            }
        }
    }
}

# Initialize predefined templates if they don't exist
def initialize_predefined_templates():
    """Create predefined templates if they don't exist"""
    for template_id, template_data in PREDEFINED_TEMPLATES.items():
        template_path = os.path.join(TEMPLATE_DIR, f"{template_id}.yaml")
        
        if not os.path.exists(template_path):
            with open(template_path, "w") as f:
                yaml.dump({
                    "name": template_data["name"],
                    "description": template_data["description"],
                    "tags": template_data["tags"],
                    "timestamp": datetime.now().isoformat(),
                    "config": template_data["config"]
                }, f, default_flow_style=False)

# Call this at startup
initialize_predefined_templates()

# Helper functions for configuration management
def load_config() -> CompleteConfig:
    """Load configuration from file or return default config if file doesn't exist"""
    config_path = os.path.join(CONFIG_DIR, "config.yaml")
    
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                config_data = yaml.safe_load(f)
                return CompleteConfig(**config_data)
        except Exception as e:
            # Log the error in a real implementation
            pass
    
    return sample_config

def save_config(config: CompleteConfig) -> bool:
    """Save configuration to file"""
    config_path = os.path.join(CONFIG_DIR, "config.yaml")
    
    try:
        with open(config_path, "w") as f:
            yaml.dump(config.dict(), f, default_flow_style=False)
        return True
    except Exception as e:
        # Log the error in a real implementation
        return False

def list_backups() -> List[BackupInfo]:
    """List all available configuration backups"""
    backups = []
    
    if not os.path.exists(BACKUP_DIR):
        return backups
        
    for filename in os.listdir(BACKUP_DIR):
        if filename.endswith(".zip"):
            backup_path = os.path.join(BACKUP_DIR, filename)
            stat_info = os.stat(backup_path)
            
            # Parse timestamp from filename (backup_YYYYMMDD_HHMMSS.zip)
            try:
                timestamp_str = filename.replace("backup_", "").replace(".zip", "")
                timestamp = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S").isoformat()
            except ValueError:
                timestamp = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
                
            backups.append(BackupInfo(
                id=filename.replace(".zip", ""),
                timestamp=timestamp,
                size_bytes=stat_info.st_size,
                filename=filename
            ))
    
    # Sort by timestamp (newest first)
    backups.sort(key=lambda x: x.timestamp, reverse=True)
    return backups

def list_templates() -> List[TemplateInfo]:
    """List all available configuration templates"""
    templates = []
    
    if not os.path.exists(TEMPLATE_DIR):
        return templates
        
    for filename in os.listdir(TEMPLATE_DIR):
        if filename.endswith((".yaml", ".yml")):
            template_path = os.path.join(TEMPLATE_DIR, filename)
            stat_info = os.stat(template_path)
            
            # Load template metadata
            try:
                with open(template_path, "r") as f:
                    template_data = yaml.safe_load(f)
                    
                template_id = os.path.splitext(filename)[0]
                templates.append(TemplateInfo(
                    id=template_id,
                    name=template_data.get("name", template_id),
                    description=template_data.get("description", ""),
                    timestamp=template_data.get("timestamp", datetime.fromtimestamp(stat_info.st_mtime).isoformat()),
                    size_bytes=stat_info.st_size,
                    filename=filename,
                    tags=template_data.get("tags", [])
                ))
            except Exception as e:
                # Log the error in a real implementation
                pass
    
    # Sort by name
    templates.sort(key=lambda x: x.name)
    return templates

def get_template(template_id: str) -> Optional[Dict[str, Any]]:
    """Get a template by ID"""
    template_path = os.path.join(TEMPLATE_DIR, f"{template_id}.yaml")
    
    if not os.path.exists(template_path):
        return None
        
    try:
        with open(template_path, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        # Log the error in a real implementation
        return None

def create_template(template_name: str, template_description: str, tags: List[str], config_data: Dict[str, Any], config_sections: Optional[List[str]] = None) -> str:
    """Create a new template from the current configuration"""
    current_config = load_config().dict()
    
    # If config_sections is specified, only include those sections
    if config_sections:
        template_config = {}
        for section in config_sections:
            if section in current_config:
                template_config[section] = current_config[section]
    else:
        template_config = current_config
    
    # Generate a template ID based on the name
    template_id = template_name.lower().replace(" ", "_").replace("-", "_")
    template_path = os.path.join(TEMPLATE_DIR, f"{template_id}.yaml")
    
    # Check if template already exists
    if os.path.exists(template_path):
        # Append a number to make the ID unique
        count = 1
        while os.path.exists(os.path.join(TEMPLATE_DIR, f"{template_id}_{count}.yaml")):
            count += 1
        template_id = f"{template_id}_{count}"
        template_path = os.path.join(TEMPLATE_DIR, f"{template_id}.yaml")
    
    # Save the template
    template_data = {
        "name": template_name,
        "description": template_description,
        "tags": tags,
        "timestamp": datetime.now().isoformat(),
        "config": template_config
    }
    
    try:
        with open(template_path, "w") as f:
            yaml.dump(template_data, f, default_flow_style=False)
        return template_id
    except Exception as e:
        # Log the error in a real implementation
        return None

def apply_template(template_id: str, sections: Optional[List[str]] = None) -> bool:
    """Apply a template to the current configuration"""
    template_data = get_template(template_id)
    
    if not template_data or "config" not in template_data:
        return False
    
    current_config = load_config().dict()
    template_config = template_data["config"]
    
    # If sections is specified, only apply those sections
    if sections:
        for section in sections:
            if section in template_config:
                current_config[section] = template_config[section]
    else:
        # Apply all sections from the template
        for section, config in template_config.items():
            if section in current_config:
                current_config[section] = config
    
    # Validate and save the updated configuration
    try:
        new_config = CompleteConfig(**current_config)
        return save_config(new_config)
    except Exception as e:
        # Log the error in a real implementation
        return False

def delete_template(template_id: str) -> bool:
    """Delete a template"""
    template_path = os.path.join(TEMPLATE_DIR, f"{template_id}.yaml")
    
    if not os.path.exists(template_path):
        return False
    
    try:
        os.remove(template_path)
        return True
    except Exception as e:
        # Log the error in a real implementation
        return False

def create_backup() -> Optional[str]:
    """Create a backup of the current configuration"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"backup_{timestamp}.zip"
    backup_path = os.path.join(BACKUP_DIR, backup_filename)
    
    try:
        with zipfile.ZipFile(backup_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            # Add main configuration file
            config_path = os.path.join(CONFIG_DIR, "config.yaml")
            if os.path.exists(config_path):
                zipf.write(config_path, os.path.basename(config_path))
                
            # Add other configuration files in the config directory
            for root, _, files in os.walk(CONFIG_DIR):
                for file in files:
                    if file != "config.yaml" and not file.startswith("backup_") and not file.endswith(".zip"):
                        file_path = os.path.join(root, file)
                        zipf.write(file_path, os.path.relpath(file_path, CONFIG_DIR))
                        
        # Cleanup old backups if needed
        cleanup_old_backups()
        
        return backup_filename
    except Exception as e:
        # Log the error in a real implementation
        if os.path.exists(backup_path):
            os.remove(backup_path)
        return None

def cleanup_old_backups():
    """Clean up old backups based on max_backups setting"""
    config = load_config()
    max_backups = config.backup.max_backups
    
    backups = list_backups()
    if len(backups) > max_backups:
        # Remove oldest backups
        for backup in backups[max_backups:]:
            try:
                os.remove(os.path.join(BACKUP_DIR, backup.filename))
            except Exception:
                # Log the error in a real implementation
                pass

def restore_backup(backup_id: str) -> bool:
    """Restore configuration from backup"""
    backup_path = os.path.join(BACKUP_DIR, f"{backup_id}.zip")
    
    if not os.path.exists(backup_path):
        return False
        
    try:
        # Create a temporary directory for extraction
        with tempfile.TemporaryDirectory() as temp_dir:
            # Extract backup
            with zipfile.ZipFile(backup_path, "r") as zipf:
                zipf.extractall(temp_dir)
                
            # Check if config.yaml exists in the backup
            temp_config_path = os.path.join(temp_dir, "config.yaml")
            if not os.path.exists(temp_config_path):
                return False
                
            # Validate configuration (you can add more validation here)
            try:
                with open(temp_config_path, "r") as f:
                    config_data = yaml.safe_load(f)
                    CompleteConfig(**config_data)
            except Exception:
                return False
                
            # Backup current configuration before restoring
            create_backup()
                
            # Copy restored configuration to config directory
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    src_path = os.path.join(root, file)
                    rel_path = os.path.relpath(src_path, temp_dir)
                    dst_path = os.path.join(CONFIG_DIR, rel_path)
                    
                    # Create directory if it doesn't exist
                    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                    
                    # Copy file
                    shutil.copy2(src_path, dst_path)
                    
        return True
    except Exception as e:
        # Log the error in a real implementation
        return False

# API Endpoints
@router.get("/current", response_model=CompleteConfig)
async def get_current_configuration(current_user = Depends(get_current_user)):
    """Get current configuration"""
    return load_config()

@router.put("/update", status_code=status.HTTP_200_OK)
async def update_configuration(
    config_update: ConfigUpdateRequest,
    current_user = Depends(get_current_user),
    background_tasks: BackgroundTasks = None
):
    """Update configuration"""
    current_config = load_config()
    
    # Update configuration with provided values
    updated_config = current_config.dict()
    
    if config_update.network:
        updated_config["network"] = config_update.network.dict()
        
    if config_update.security:
        updated_config["security"] = config_update.security.dict()
        
    if config_update.notification:
        updated_config["notification"] = config_update.notification.dict()
        
    if config_update.backup:
        updated_config["backup"] = config_update.backup.dict()
    
    # Convert back to model for validation
    try:
        new_config = CompleteConfig(**updated_config)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid configuration: {str(e)}"
        )
    
    # Save configuration
    if save_config(new_config):
        # Create backup in background if auto-backup is enabled
        if background_tasks and new_config.backup.auto_backup:
            background_tasks.add_task(create_backup)
            
        return {"status": "success", "message": "Configuration updated successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save configuration"
        )

@router.get("/backup", response_model=List[BackupInfo])
async def get_backups(current_user = Depends(get_current_user)):
    """Get list of available backups"""
    return list_backups()

@router.post("/backup", status_code=status.HTTP_201_CREATED)
async def create_configuration_backup(current_user = Depends(get_current_user)):
    """Create a new configuration backup"""
    backup_filename = create_backup()
    
    if backup_filename:
        backup_id = backup_filename.replace(".zip", "")
        return {
            "status": "success", 
            "message": "Backup created successfully", 
            "backup_id": backup_id
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create backup"
        )

@router.get("/backup/{backup_id}")
async def download_backup(backup_id: str, current_user = Depends(get_current_user)):
    """Download a specific backup"""
    backup_path = os.path.join(BACKUP_DIR, f"{backup_id}.zip")
    
    if not os.path.exists(backup_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Backup not found"
        )
        
    return FileResponse(
        path=backup_path,
        filename=f"{backup_id}.zip",
        media_type="application/zip"
    )

@router.post("/restore/{backup_id}", status_code=status.HTTP_200_OK)
async def restore_configuration(backup_id: str, current_user = Depends(get_current_user)):
    """Restore configuration from backup"""
    if restore_backup(backup_id):
        return {
            "status": "success", 
            "message": "Configuration restored successfully"
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to restore configuration"
        )

@router.post("/import", status_code=status.HTTP_200_OK)
async def import_configuration(
    file: UploadFile = File(...),
    current_user = Depends(get_current_user)
):
    """Import configuration from uploaded file"""
    if not file.filename.endswith((".yaml", ".yml", ".zip")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Must be YAML or ZIP."
        )
    
    # Create a temporary directory for processing
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_file_path = os.path.join(temp_dir, file.filename)
        
        # Save uploaded file
        with open(temp_file_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        # Handle ZIP file (backup format)
        if file.filename.endswith(".zip"):
            try:
                # Extract ZIP file
                with zipfile.ZipFile(temp_file_path, "r") as zipf:
                    zipf.extractall(temp_dir)
                
                # Check if config.yaml exists in the backup
                temp_config_path = os.path.join(temp_dir, "config.yaml")
                if not os.path.exists(temp_config_path):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid backup file: config.yaml not found."
                    )
                
                # Validate configuration
                with open(temp_config_path, "r") as f:
                    config_data = yaml.safe_load(f)
                    CompleteConfig(**config_data)
                
                # Create backup of current configuration
                create_backup()
                
                # Copy imported configuration to config directory
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        if file != os.path.basename(temp_file_path):  # Skip the original zip file
                            src_path = os.path.join(root, file)
                            rel_path = os.path.relpath(src_path, temp_dir)
                            dst_path = os.path.join(CONFIG_DIR, rel_path)
                            
                            # Create directory if it doesn't exist
                            os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                            
                            # Copy file
                            shutil.copy2(src_path, dst_path)
            except zipfile.BadZipFile:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid ZIP file format."
                )
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Failed to process backup: {str(e)}"
                )
        
        # Handle YAML file (single config file)
        else:
            try:
                # Validate configuration
                with open(temp_file_path, "r") as f:
                    config_data = yaml.safe_load(f)
                    new_config = CompleteConfig(**config_data)
                
                # Create backup of current configuration
                create_backup()
                
                # Save new configuration
                save_config(new_config)
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid configuration file: {str(e)}"
                )
    
    return {
        "status": "success", 
        "message": "Configuration imported successfully"
    }

@router.get("/export")
async def export_configuration(current_user = Depends(get_current_user)):
    """Export current configuration as a YAML file"""
    config_path = os.path.join(CONFIG_DIR, "config.yaml")
    
    if not os.path.exists(config_path):
        # If config file doesn't exist, create it
        current_config = load_config()
        save_config(current_config)
    
    return FileResponse(
        path=config_path,
        filename="arpguard_config.yaml",
        media_type="application/x-yaml"
    )

@router.get("/export/backup")
async def export_configuration_backup(current_user = Depends(get_current_user)):
    """Export current configuration as a backup ZIP file"""
    backup_filename = create_backup()
    
    if not backup_filename:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create backup for export"
        )
    
    backup_path = os.path.join(BACKUP_DIR, backup_filename)
    
    return FileResponse(
        path=backup_path,
        filename=backup_filename,
        media_type="application/zip"
    )

# Template endpoints
@router.get("/templates", response_model=List[TemplateInfo])
async def get_templates(
    current_user = Depends(get_current_user),
    tag: Optional[str] = None
):
    """Get list of available configuration templates"""
    templates = list_templates()
    
    # Filter by tag if specified
    if tag:
        templates = [t for t in templates if tag.lower() in [t.lower() for t in t.tags]]
        
    return templates

@router.get("/templates/{template_id}")
async def get_template_by_id(template_id: str, current_user = Depends(get_current_user)):
    """Get a specific template"""
    template_data = get_template(template_id)
    
    if not template_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template not found"
        )
        
    return template_data

@router.post("/templates", status_code=status.HTTP_201_CREATED)
async def create_configuration_template(
    template_request: TemplateCreateRequest,
    current_user = Depends(get_current_user)
):
    """Create a new configuration template from the current configuration"""
    template_id = create_template(
        template_request.name,
        template_request.description,
        template_request.tags,
        {},
        template_request.config_sections
    )
    
    if template_id:
        return {
            "status": "success",
            "message": "Template created successfully",
            "template_id": template_id
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create template"
        )

@router.post("/templates/{template_id}/apply", status_code=status.HTTP_200_OK)
async def apply_configuration_template(
    template_id: str,
    apply_request: TemplateApplyRequest = None,
    current_user = Depends(get_current_user),
    background_tasks: BackgroundTasks = None
):
    """Apply a template to the current configuration"""
    # Create backup before applying template
    if background_tasks:
        background_tasks.add_task(create_backup)
    
    sections = apply_request.sections if apply_request else None
    
    if apply_template(template_id, sections):
        return {
            "status": "success",
            "message": "Template applied successfully"
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to apply template"
        )

@router.delete("/templates/{template_id}", status_code=status.HTTP_200_OK)
async def delete_configuration_template(template_id: str, current_user = Depends(get_current_user)):
    """Delete a configuration template"""
    # Prevent deletion of predefined templates
    if template_id in PREDEFINED_TEMPLATES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot delete predefined template"
        )
    
    if delete_template(template_id):
        return {
            "status": "success",
            "message": "Template deleted successfully"
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template not found"
        ) 