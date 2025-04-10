# ARP Guard Modular Architecture

## Overview

ARP Guard is built using a modular architecture pattern, which enhances maintainability, scalability, and flexibility. This document describes the architectural principles, module structure, and integration patterns used throughout the application.

## Architecture Principles

The modular architecture of ARP Guard follows these key principles:

1. **Separation of Concerns**: Each module has a specific responsibility
2. **Loose Coupling**: Modules interact through well-defined interfaces
3. **High Cohesion**: Related functionality is grouped within modules
4. **Extensibility**: New functionality can be added via new modules
5. **Feature Isolation**: Features can be enabled/disabled at the module level
6. **Testability**: Modules can be tested in isolation

## System Architecture

At a high level, ARP Guard is organized into core modules, each with a specific responsibility:

```
┌─────────────────────────────────────────────────────────────┐
│                       ARP Guard                             │
├─────────────┬──────────────┬────────────────┬──────────────┤
│ CLI Module  │ Detection    │ Telemetry      │ Notification │
│             │ Module       │ Module         │ Module       │
├─────────────┼──────────────┼────────────────┼──────────────┤
│ Feature     │ Pattern      │ Alert          │ Configuration│
│ Flags       │ Recognition  │ Management     │ Module       │
└─────────────┴──────────────┴────────────────┴──────────────┘
```

### Module Dependencies

The following diagram shows the primary dependencies between modules:

```
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│  CLI Module   │────▶│  Detection    │────▶│  Notification │
└───────┬───────┘     │  Module       │     │  Module       │
        │             └───────┬───────┘     └───────────────┘
        │                     │                      ▲
        │                     │                      │
        │                     ▼                      │
        │             ┌───────────────┐              │
        └───────────▶│  Alert        │──────────────┘
                     │  Management   │
                     └───────────────┘
                            ▲
                            │
┌───────────────┐          │
│  Telemetry    │──────────┘
│  Module       │
└───────────────┘
```

## Module Interface

All modules in ARP Guard implement a common interface defined in `module_interface.py`:

```python
class Module:
    """
    Base interface for all modules in the system
    """
    
    def __init__(self, name: str, description: str, config: Optional[ModuleConfig] = None):
        """Initialize the module"""
        self.name = name
        self.description = description
        self.config = config
        self.logger = logging.getLogger(f"{name}_module")
    
    def initialize(self) -> bool:
        """Initialize the module"""
        return True
    
    def shutdown(self) -> bool:
        """Shutdown the module"""
        return True
```

### Module Configuration

Each module has its own configuration class that inherits from `ModuleConfig`:

```python
@dataclass
class ModuleConfig:
    """Base class for module configuration"""
    # Common configuration properties
    enabled: bool = True
    log_level: str = "INFO"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ModuleConfig':
        """Create configuration from dictionary"""
        return cls(**data)
```

## Module Lifecycle

### Initialization Phase

1. Module instance is created with configuration
2. `initialize()` method is called:
   - Resources are allocated
   - Connections are established
   - Background threads are started
   - Registration with other modules occurs

### Operational Phase

- Module performs its core functionality
- Interacts with other modules as needed
- Processes inputs and produces outputs

### Shutdown Phase

1. `shutdown()` method is called:
   - Resources are released
   - Connections are closed
   - Background threads are stopped
   - State is persisted if needed

## Creating a New Module

To create a new module for ARP Guard, follow these steps:

1. **Define Module Configuration**

```python
@dataclass
class NewModuleConfig(ModuleConfig):
    """Configuration for new module"""
    custom_setting: str = "default"
    enable_feature: bool = True
```

2. **Implement Module Class**

```python
class NewModule(Module):
    """New module implementation"""
    
    def __init__(self, config: Optional[NewModuleConfig] = None):
        super().__init__("new_module", "Description of new module")
        self.config = config or NewModuleConfig()
    
    def initialize(self) -> bool:
        """Initialize the module"""
        try:
            # Implementation
            self.logger.info("New module initialized")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize: {e}")
            return False
    
    def shutdown(self) -> bool:
        """Shutdown the module"""
        try:
            # Implementation
            self.logger.info("New module shutdown")
            return True
        except Exception as e:
            self.logger.error(f"Failed to shutdown: {e}")
            return False
    
    def custom_method(self) -> Any:
        """Custom module functionality"""
        # Module-specific implementation
```

3. **Register with Main Application**

In `src/main.py`:

```python
def initialize_modules() -> Dict[str, Any]:
    # ... existing modules
    
    # Initialize new module
    new_module_config = NewModuleConfig(custom_setting="value")
    new_module = NewModule(new_module_config)
    
    if new_module.initialize():
        modules["new_module"] = new_module
        logger.info("New module initialized successfully")
    else:
        logger.error("Failed to initialize new module")
    
    return modules
```

## Feature Flag Integration

Modules can integrate with the feature flag system to enable tier-based functionality:

```python
from core.feature_flags import feature_required, FeatureDisabledException

class TieredModule(Module):
    @feature_required("premium.custom_feature")
    def premium_method(self):
        """This method only runs if premium.custom_feature is enabled"""
        # Implementation for premium tier
```

## Inter-Module Communication

Modules can communicate in several ways:

### 1. Direct Method Calls

```python
# In CLI module
def handle_command(self, command: str):
    if command == "detect":
        # Get detection module from registry
        detection_module = self.module_registry.get("detection")
        # Call method directly
        detection_module.start_detection()
```

### 2. Event-Based Communication

```python
# In Detection module
def detect_threat(self, threat_info: dict):
    # Emit event for other modules
    self.event_bus.emit("threat_detected", threat_info)

# In Notification module
def initialize(self):
    # Subscribe to events
    self.event_bus.subscribe("threat_detected", self.handle_threat)
```

### 3. Shared Configuration

```python
# In Configuration module
def update_setting(self, key: str, value: Any):
    self.settings[key] = value
    # Notify all modules of configuration change
    self.notify_modules("config_changed", {"key": key, "value": value})
```

## Dependency Injection

ARP Guard uses a simple dependency injection pattern to manage module dependencies:

```python
# Main application creates and initializes modules
def initialize_application():
    # Create modules
    config_module = ConfigModule()
    detection_module = DetectionModule()
    alert_module = AlertModule()
    
    # Wire dependencies
    detection_module.set_alert_module(alert_module)
    alert_module.set_config_module(config_module)
```

## Thread Safety

Modules that manage shared state should implement thread safety:

```python
class ThreadSafeModule(Module):
    def __init__(self, config: Optional[ModuleConfig] = None):
        super().__init__("thread_safe", "Thread-safe module")
        self.config = config
        self.lock = threading.Lock()
        self.shared_state = {}
    
    def update_state(self, key: str, value: Any):
        with self.lock:
            self.shared_state[key] = value
```

## Testing Modules

Each module should be testable in isolation:

```python
class TestNewModule(unittest.TestCase):
    def setUp(self):
        self.config = NewModuleConfig(custom_setting="test")
        self.module = NewModule(self.config)
        self.module.initialize()
    
    def tearDown(self):
        self.module.shutdown()
    
    def test_custom_method(self):
        result = self.module.custom_method()
        self.assertIsNotNone(result)
```

## Module Documentation

Each module should include the following documentation:

1. **Purpose**: The primary responsibility of the module
2. **Features**: Key functionality provided
3. **Configuration**: Available configuration options
4. **Dependencies**: Required modules and external dependencies
5. **API**: Public methods and interfaces
6. **Events**: Events emitted and subscribed to
7. **Usage Examples**: How to use the module

## Best Practices

When working with ARP Guard's modular architecture:

1. **Keep modules focused**: Each module should have a single responsibility
2. **Minimize dependencies**: Avoid circular dependencies between modules
3. **Use interfaces**: Interact with other modules through well-defined interfaces
4. **Handle failures gracefully**: Modules should recover from errors when possible
5. **Document interfaces**: Clearly document public APIs and event contracts
6. **Consider thread safety**: Be aware of concurrent access to shared state
7. **Test extensively**: Write unit tests for each module in isolation

## Core Modules Reference

### CLI Module
- **Purpose**: Command-line interface for user interaction
- **Features**: Command parsing, output formatting, interactive mode
- **API**: `run()`, `register_command()`, `format_output()`

### Detection Module
- **Purpose**: Detect ARP spoofing and other attacks
- **Features**: Packet analysis, anomaly detection, alert generation
- **API**: `start_detection()`, `stop_detection()`, `get_stats()`

### Telemetry Module
- **Purpose**: Collect usage data for product improvement
- **Features**: Event tracking, local storage, data upload
- **API**: `track_event()`, `enable_telemetry()`, `disable_telemetry()`

### Alert Module
- **Purpose**: Manage and dispatch alerts
- **Features**: Alert prioritization, notification, history
- **API**: `create_alert()`, `acknowledge_alert()`, `get_active_alerts()`

## Conclusion

The modular architecture of ARP Guard provides a solid foundation for building, maintaining, and extending the application. By following the patterns and best practices outlined in this document, developers can create modules that integrate seamlessly with the existing system while maintaining code quality and testability. 