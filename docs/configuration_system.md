# ARPGuard Configuration System

## Overview

The ARPGuard Configuration System provides a robust, flexible way to manage application settings across different components. This document details the design, implementation, and usage of the configuration system.

## Design Goals

The configuration system was designed with the following goals:

1. **Flexibility**: Support multiple configuration sources and formats
2. **Validation**: Ensure configuration values are valid and consistent
3. **Centralization**: Provide a single point of access for all configuration
4. **Usability**: Offer intuitive interfaces for both users and developers
5. **Security**: Handle sensitive configuration data appropriately
6. **Extensibility**: Allow easy addition of new configuration parameters

## Architecture

The configuration system follows a layered architecture:

```
┌─────────────────────────────────────────────────────┐
│                 User Interfaces                     │
│  ┌───────────────────┐    ┌────────────────────┐    │
│  │ CLI Config        │    │ GUI Config         │    │
│  │ Commands          │    │ Panel (Future)     │    │
│  └─────────┬─────────┘    └────────────────────┘    │
│            │                                        │
└────────────┼────────────────────────────────────────┘
             │
┌────────────▼────────────────────────────────────────┐
│                 Configuration Manager               │
│  ┌───────────────────┐    ┌────────────────────┐    │
│  │ Loading &         │    │ Validation &       │    │
│  │ Saving            │    │ Schema Checking    │    │
│  └───────────────────┘    └────────────────────┘    │
│                                                     │
└─────────────────────────┬───────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────┐
│                 Storage Formats                     │
│  ┌───────────────────┐    ┌────────────────────┐    │
│  │ YAML              │    │ Environment        │    │
│  │ Files             │    │ Variables          │    │
│  └───────────────────┘    └────────────────────┘    │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## Implementation Details

### Configuration Manager

The `ConfigManager` class in `app/utils/config.py` serves as the core of the configuration system:

```python
class ConfigManager:
    """
    Manages configuration loading, validation, and saving for ARPGuard.
    """
    def __init__(self, config_file=None):
        self.config = None
        self.config_file = config_file
        self.load_config()
    
    def load_config(self):
        """Load configuration from file or use defaults."""
        # Implementation details...
    
    def validate_config(self, config):
        """Validate configuration against schema."""
        # Implementation details...
    
    def save_config(self, file_path=None):
        """Save configuration to file."""
        # Implementation details...
    
    def get(self, section, key=None, default=None):
        """Get configuration value."""
        # Implementation details...
    
    def set(self, section, key, value):
        """Set configuration value."""
        # Implementation details...
```

### Configuration Schema

The configuration schema is defined using JSON Schema, which allows for rich validation:

```python
CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "general": {
            "type": "object",
            "properties": {
                "log_level": {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]},
                "log_file": {"type": "string"},
                "color_output": {"type": "boolean"},
                "progress_indicators": {"type": "boolean"}
            },
            "required": ["log_level", "color_output", "progress_indicators"]
        },
        # Other sections...
    },
    "required": ["general", "scan", "monitor", "analyze", "export"]
}
```

### Default Configuration

A default configuration is provided to ensure the application works out-of-the-box:

```python
DEFAULT_CONFIG = {
    "general": {
        "log_level": "INFO",
        "log_file": "arpguard.log",
        "color_output": True,
        "progress_indicators": True
    },
    # Other sections with default values...
}
```

### Configuration Storage

Configurations are stored in YAML format, which provides a good balance of human readability and structure:

```yaml
general:
  log_level: INFO
  log_file: arpguard.log
  color_output: true
  progress_indicators: true

scan:
  default_interface: eth0
  default_timeout: 2
  default_ports:
    - 22
    - 80
    - 443
    - 3389
    - 5900
  default_subnet: 192.168.1.0/24
  classify_devices: true
  output_format: table
```

## Configuration Sections

The configuration is divided into logical sections that correspond to different areas of functionality:

### General

Controls application-wide settings:

| Key | Type | Description | Default |
|-----|------|-------------|---------|
| `log_level` | String | Logging verbosity | `"INFO"` |
| `log_file` | String | Path to log file | `"arpguard.log"` |
| `color_output` | Boolean | Enable colorized output | `true` |
| `progress_indicators` | Boolean | Show progress indicators | `true` |

### Scan

Controls network scanning behavior:

| Key | Type | Description | Default |
|-----|------|-------------|---------|
| `default_interface` | String | Network interface | Auto-detected |
| `default_timeout` | Integer | Scan timeout in seconds | `2` |
| `default_ports` | Array of Integers | Ports to scan | `[22, 80, 443, 3389, 5900]` |
| `default_subnet` | String | Subnet to scan | Auto-detected |
| `classify_devices` | Boolean | Classify devices by type | `true` |
| `output_format` | String | Output format (table, json, csv) | `"table"` |

### Monitor

Controls ARP monitoring behavior:

| Key | Type | Description | Default |
|-----|------|-------------|---------|
| `default_interface` | String | Network interface | Auto-detected |
| `alert_level` | String | Alert sensitivity (low, medium, high) | `"medium"` |
| `check_interval` | Integer | Seconds between checks | `2` |
| `output_format` | String | Output format (normal, json) | `"normal"` |
| `known_devices_file` | String | Path to known devices file | `"known_devices.json"` |

### Analyze

Controls packet analysis behavior:

| Key | Type | Description | Default |
|-----|------|-------------|---------|
| `pcap_dir` | String | Directory for packet captures | `"captures"` |
| `max_packets` | Integer | Maximum packets to analyze | `10000` |
| `filter_expression` | String | Packet filter expression | `""` |
| `output_format` | String | Output format (table, json, csv) | `"table"` |

### Export

Controls data export behavior:

| Key | Type | Description | Default |
|-----|------|-------------|---------|
| `default_format` | String | Export format (json, csv, html, pdf) | `"json"` |
| `default_dir` | String | Directory for exports | `"exports"` |
| `include_metadata` | Boolean | Include metadata in exports | `true` |

## Configuration File Locations

The configuration system searches for configurations in the following locations, in order:

1. Path explicitly specified via constructor or environment variable
2. `~/.config/arpguard/config.yaml` (XDG Base Directory standard)
3. `~/.arpguard/config.yaml` (legacy location)
4. `./config.yaml` (current working directory)

If no configuration file is found, the default configuration is used.

## Command Line Interface

ARPGuard provides a comprehensive CLI for managing configurations:

| Command | Description | Example |
|---------|-------------|---------|
| `config list` | List all configuration sections | `arpguard config list` |
| `config list <section>` | List a specific section | `arpguard config list scan` |
| `config get <section> <key>` | Get a specific value | `arpguard config get scan default_timeout` |
| `config set <section> <key> <value>` | Set a value | `arpguard config set scan default_timeout 5` |
| `config save` | Save configuration | `arpguard config save` |
| `config save -f <file>` | Save to specific file | `arpguard config save -f my_config.yaml` |
| `config reset` | Reset to defaults | `arpguard config reset` |
| `config reset -s <section>` | Reset section | `arpguard config reset -s scan` |
| `config create -f <file>` | Create default config | `arpguard config create -f default_config.yaml` |

## Value Type Conversion

The CLI `config set` command automatically converts values to appropriate types:

- Numbers: `config set scan default_timeout 5` → Integer `5`
- Booleans: `config set general color_output true` → Boolean `true`
- Lists: `config set scan default_ports 22,80,443` → List `[22, 80, 443]`
- Strings: `config set general log_file app.log` → String `"app.log"`

## Environment Variables

ARPGuard respects the following environment variables:

- `ARPGUARD_CONFIG`: Path to configuration file
- `ARPGUARD_DEBUG`: Enable debug mode if set to any value
- `ARPGUARD_NO_COLOR`: Disable colored output if set to any value

## Configuration Validation

The configuration system performs two types of validation:

1. **Schema Validation**: Using JSON Schema to validate types, required fields, and value constraints
2. **Custom Validation**: Additional checks for specific fields, such as:
   - Validating subnet format using the `ipaddress` module
   - Ensuring port numbers are in valid ranges
   - Checking that file paths are valid

## Best Practices

### For Users

1. Create a configuration file in your home directory:
   ```bash
   arpguard config create -f ~/.config/arpguard/config.yaml
   ```

2. Edit settings for your environment:
   ```bash
   arpguard config set scan default_subnet 192.168.1.0/24
   arpguard config set scan default_interface eth0
   ```

3. Save your configuration:
   ```bash
   arpguard config save
   ```

### For Developers

1. Always access configuration through the ConfigManager:
   ```python
   from app.utils.config import get_config_manager
   
   config = get_config_manager()
   timeout = config.get('scan', 'default_timeout', 2)  # Provide defaults
   ```

2. Add new configuration options to both the schema and default config

3. Validate user input before setting configuration values

4. Use descriptive section and key names that reflect their purpose

## Extending the Configuration System

To add new configuration sections or keys:

1. Update the `CONFIG_SCHEMA` in `app/utils/config.py` with the new schema elements
2. Add default values to `DEFAULT_CONFIG`
3. Update documentation to reflect the new options
4. Implement any custom validation needed in `_validate_custom_rules`

## Testing

The configuration system includes comprehensive unit tests in `tests/test_config.py`:

- Testing default configuration loading
- Testing configuration saving and loading
- Testing validation with valid and invalid configurations
- Testing section and key access
- Testing value type handling

## Troubleshooting

### Common Issues

1. **Configuration Not Found**: Ensure the file exists at one of the search paths or explicitly specify the path.

2. **Validation Errors**: Check that your configuration values match the expected types and constraints.

3. **Permission Issues**: Ensure you have appropriate permissions to read/write the configuration file.

### Debugging Tips

1. Set the log level to DEBUG:
   ```bash
   arpguard config set general log_level DEBUG
   ```

2. Use the `config list` command to view current configuration:
   ```bash
   arpguard config list
   ```

3. Check for validation errors by deliberately using an invalid configuration and observing the error messages.

## Conclusion

The ARPGuard configuration system provides a flexible, robust way to customize application behavior. By using a well-defined schema, standardized storage format, and intuitive CLI, it ensures a consistent experience for both users and developers while maintaining configuration integrity through validation. 