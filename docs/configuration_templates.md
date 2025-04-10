# Configuration Templates

This document describes the configuration template features of the ARPGuard application.

## Overview

ARPGuard Configuration Templates provide a way to store, manage, and apply pre-defined configurations for different deployment scenarios or security requirements. Templates allow you to:

- Save common configuration patterns for reuse
- Quickly deploy standardized configurations
- Maintain consistency across multiple deployments
- Apply partial configurations to specific system components

## Predefined Templates

ARPGuard comes with several predefined templates for common use cases:

1. **High Security**
   - Maximum security settings for high-risk environments
   - Stricter thresholds for attack detection
   - Automatic attack blocking enabled
   - Immediate administrator notifications

2. **Low Resource Usage**
   - Optimized for systems with limited resources
   - Reduced buffer sizes and timeouts
   - Selective detection mechanisms
   - Minimal performance impact

3. **Monitoring Only**
   - Non-intrusive monitoring without blocking capabilities
   - Passive network monitoring
   - Detection without intervention
   - Comprehensive logging and alerting

## API Endpoints

### Template Management

#### List Available Templates
```http
GET /api/v1/config/templates
Authorization: Bearer <token>
```

Optional query parameters:
- `tag`: Filter templates by tag

Response:
```json
[
  {
    "id": "high_security",
    "name": "High Security",
    "description": "Maximum security settings for high-risk environments",
    "timestamp": "2024-04-21T12:00:00",
    "size_bytes": 1024,
    "filename": "high_security.yaml",
    "tags": ["security", "enterprise"]
  },
  {
    "id": "low_resource",
    "name": "Low Resource Usage",
    "description": "Optimized for systems with limited resources",
    "timestamp": "2024-04-21T12:00:00",
    "size_bytes": 1024,
    "filename": "low_resource.yaml",
    "tags": ["performance", "iot"]
  }
]
```

#### Get Template Details
```http
GET /api/v1/config/templates/{template_id}
Authorization: Bearer <token>
```

Response:
```json
{
  "name": "High Security",
  "description": "Maximum security settings for high-risk environments",
  "tags": ["security", "enterprise"],
  "timestamp": "2024-04-21T12:00:00",
  "config": {
    "security": {
      "arp_spoofing": {
        "enabled": true,
        "threshold": 50,
        "alert_level": "critical"
      },
      "mac_flooding_enabled": true,
      "mac_flooding_threshold": 20,
      "ip_spoofing_detection": true,
      "block_attacks": true,
      "alert_admin": true
    }
  }
}
```

#### Create a New Template
```http
POST /api/v1/config/templates
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Custom Template",
  "description": "My custom configuration template",
  "tags": ["custom", "test"],
  "config_sections": ["network", "security"]
}
```

Response:
```json
{
  "status": "success",
  "message": "Template created successfully",
  "template_id": "custom_template"
}
```

The `config_sections` field is optional. If provided, only those sections of the current configuration will be included in the template. If not provided, the entire configuration will be included.

#### Apply a Template
```http
POST /api/v1/config/templates/{template_id}/apply
Authorization: Bearer <token>
Content-Type: application/json

{
  "sections": ["security"]
}
```

Response:
```json
{
  "status": "success",
  "message": "Template applied successfully"
}
```

The `sections` field is optional. If provided, only those sections of the template will be applied. If not provided, all sections in the template will be applied.

#### Delete a Template
```http
DELETE /api/v1/config/templates/{template_id}
Authorization: Bearer <token>
```

Response:
```json
{
  "status": "success",
  "message": "Template deleted successfully"
}
```

Note: Predefined templates cannot be deleted.

## Usage Examples

### Python Client Example

```python
import requests
import json

class ARPGuardTemplateClient:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {token}"
        }
        
    def list_templates(self, tag=None):
        """List available templates, optionally filtered by tag"""
        params = {}
        if tag:
            params["tag"] = tag
            
        response = requests.get(
            f"{self.base_url}/api/v1/config/templates",
            headers=self.headers,
            params=params
        )
        response.raise_for_status()
        return response.json()
        
    def get_template(self, template_id):
        """Get a specific template"""
        response = requests.get(
            f"{self.base_url}/api/v1/config/templates/{template_id}",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()
        
    def create_template(self, name, description, tags=None, config_sections=None):
        """Create a new template from the current configuration"""
        data = {
            "name": name,
            "description": description
        }
        
        if tags:
            data["tags"] = tags
            
        if config_sections:
            data["config_sections"] = config_sections
            
        response = requests.post(
            f"{self.base_url}/api/v1/config/templates",
            headers=self.headers,
            json=data
        )
        response.raise_for_status()
        return response.json()
        
    def apply_template(self, template_id, sections=None):
        """Apply a template to the current configuration"""
        data = {}
        if sections:
            data["sections"] = sections
            
        response = requests.post(
            f"{self.base_url}/api/v1/config/templates/{template_id}/apply",
            headers=self.headers,
            json=data
        )
        response.raise_for_status()
        return response.json()
        
    def delete_template(self, template_id):
        """Delete a template"""
        response = requests.delete(
            f"{self.base_url}/api/v1/config/templates/{template_id}",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()
```

### Usage Example

```python
# Initialize client
client = ARPGuardTemplateClient("http://localhost:8000", "your_token_here")

# List all available templates
templates = client.list_templates()
print(f"Available templates: {len(templates)}")
for template in templates:
    print(f"- {template['name']}: {template['description']}")

# Get details for a specific template
high_security = client.get_template("high_security")
print(f"High Security template settings: {high_security['config']}")

# Create a new template with only network settings
result = client.create_template(
    name="Custom Network Settings",
    description="My custom network configuration",
    tags=["network", "custom"],
    config_sections=["network"]
)
print(f"Template creation result: {result['message']}")
print(f"New template ID: {result['template_id']}")

# Apply the high security template, but only the security section
result = client.apply_template("high_security", sections=["security"])
print(f"Template application result: {result['message']}")

# Delete a custom template
try:
    result = client.delete_template("custom_network_settings")
    print(f"Template deletion result: {result['message']}")
except requests.HTTPError as e:
    print(f"Failed to delete template: {e}")
```

## Best Practices

1. **Template Organization**:
   - Use meaningful names and descriptions for templates
   - Apply consistent tagging to make templates easy to find
   - Group related settings into logical templates

2. **Partial Templates**:
   - Create focused templates for specific subsystems
   - Use the `config_sections` parameter to create targeted templates
   - Apply only needed sections using the `sections` parameter

3. **Template Management**:
   - Regularly review and update templates
   - Remove unused or outdated templates
   - Document the purpose and use case for each template

4. **Deployment Strategy**:
   - Test templates in non-production environments first
   - Create backup before applying templates
   - Consider creating environment-specific templates (dev, test, prod)

## Integration with Configuration Backup

Templates and backups work together to provide a comprehensive configuration management system:

1. **Backups** provide point-in-time snapshots of your entire configuration
2. **Templates** provide reusable patterns for specific configuration sections

Best practices for using both:
- Create a backup before applying a template
- Create templates from known-good configurations
- Use templates for standardization, backups for recovery

## Advanced Template Usage

### Combining Templates

You can apply multiple templates in sequence to build a composite configuration:

```python
# Apply network settings from one template
client.apply_template("network_template", sections=["network"])

# Apply security settings from another template
client.apply_template("security_template", sections=["security"])

# Apply notification settings from a third template
client.apply_template("notification_template", sections=["notification"])
```

### Environment-Specific Templates

Create templates for different deployment environments:

1. **Development**:
   - Lower security thresholds
   - Extensive logging
   - No attack blocking

2. **Testing**:
   - Moderate security settings
   - Testing-specific notification endpoints
   - Simulated attack responses

3. **Production**:
   - High security settings
   - Production notification endpoints
   - Full attack mitigation

### Role-Based Templates

Create templates based on system roles:

1. **Gateway**:
   - Focused on perimeter security
   - External interface monitoring
   - Traffic filtering configurations

2. **Internal Server**:
   - Internal network monitoring
   - Server-specific protections
   - Resource-optimized settings

3. **Client-facing System**:
   - Client protection settings
   - User authentication security
   - Data protection configurations 