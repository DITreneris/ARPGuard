from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Set
import logging
import json
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ModuleConfig:
    """Base class for module configuration"""
    
    def __init__(self, **kwargs):
        """Initialize with dynamic attributes"""
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {k: v for k, v in self.__dict__.items() if not k.startswith('_')}
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'ModuleConfig':
        """Create configuration from dictionary"""
        return cls(**config_dict)
    
    def save_to_file(self, file_path: str) -> None:
        """Save configuration to file"""
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=4)
    
    @classmethod
    def load_from_file(cls, file_path: str) -> 'ModuleConfig':
        """Load configuration from file"""
        if not os.path.exists(file_path):
            logger.warning(f"Configuration file {file_path} not found, using defaults")
            return cls()
        
        with open(file_path, 'r') as f:
            config_dict = json.load(f)
            return cls.from_dict(config_dict)


class Module(ABC):
    """Base abstract class for all modules"""
    
    def __init__(self, module_id: str, name: str, config: Optional[ModuleConfig] = None):
        """Initialize the module with basic properties
        
        Args:
            module_id: Unique identifier for the module
            name: Human-readable name for the module
            config: Module configuration object
        """
        self.module_id = module_id
        self.name = name
        self.config = config or ModuleConfig()
        self.enabled = True
        self.dependencies: Set[str] = set()
        self.logger = logging.getLogger(f"{__name__}.{module_id}")
    
    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the module, return success status"""
        pass
    
    @abstractmethod
    def shutdown(self) -> bool:
        """Clean shutdown of the module, return success status"""
        pass
    
    def add_dependency(self, module_id: str) -> None:
        """Add a module dependency
        
        Args:
            module_id: ID of the module this module depends on
        """
        self.dependencies.add(module_id)
    
    def remove_dependency(self, module_id: str) -> None:
        """Remove a module dependency
        
        Args:
            module_id: ID of the module to remove dependency for
        """
        if module_id in self.dependencies:
            self.dependencies.remove(module_id)
    
    def get_dependencies(self) -> Set[str]:
        """Get all module dependencies
        
        Returns:
            Set of module IDs this module depends on
        """
        return self.dependencies
    
    def enable(self) -> None:
        """Enable the module"""
        self.enabled = True
        self.logger.info(f"Module {self.name} enabled")
    
    def disable(self) -> None:
        """Disable the module"""
        self.enabled = False
        self.logger.info(f"Module {self.name} disabled")
    
    def is_enabled(self) -> bool:
        """Check if module is enabled
        
        Returns:
            True if module is enabled, False otherwise
        """
        return self.enabled
    
    def get_status(self) -> Dict[str, Any]:
        """Get module status information
        
        Returns:
            Dictionary with module status information
        """
        return {
            "module_id": self.module_id,
            "name": self.name,
            "enabled": self.enabled,
            "dependencies": list(self.dependencies)
        }


class ModuleRegistry:
    """Registry for managing modules"""
    
    def __init__(self):
        """Initialize the module registry"""
        self.modules: Dict[str, Module] = {}
        self.logger = logging.getLogger(f"{__name__}.registry")
    
    def register_module(self, module: Module) -> bool:
        """Register a module in the registry
        
        Args:
            module: Module instance to register
            
        Returns:
            True if registration was successful, False otherwise
        """
        if module.module_id in self.modules:
            self.logger.warning(f"Module with ID {module.module_id} already registered")
            return False
        
        self.modules[module.module_id] = module
        self.logger.info(f"Module {module.name} (ID: {module.module_id}) registered")
        return True
    
    def unregister_module(self, module_id: str) -> bool:
        """Unregister a module from the registry
        
        Args:
            module_id: ID of the module to unregister
            
        Returns:
            True if unregistration was successful, False otherwise
        """
        if module_id not in self.modules:
            self.logger.warning(f"No module with ID {module_id} registered")
            return False
        
        module = self.modules[module_id]
        del self.modules[module_id]
        self.logger.info(f"Module {module.name} (ID: {module_id}) unregistered")
        return True
    
    def get_module(self, module_id: str) -> Optional[Module]:
        """Get a module by ID
        
        Args:
            module_id: ID of the module to get
            
        Returns:
            Module instance if found, None otherwise
        """
        return self.modules.get(module_id)
    
    def get_all_modules(self) -> List[Module]:
        """Get all registered modules
        
        Returns:
            List of all registered module instances
        """
        return list(self.modules.values())
    
    def get_enabled_modules(self) -> List[Module]:
        """Get all enabled modules
        
        Returns:
            List of all enabled module instances
        """
        return [module for module in self.modules.values() if module.is_enabled()]
    
    def initialize_all(self) -> bool:
        """Initialize all registered modules
        
        Returns:
            True if all modules initialized successfully, False otherwise
        """
        success = True
        
        # Sort modules by dependencies
        modules_to_initialize = self._get_dependency_sorted_modules()
        
        for module in modules_to_initialize:
            if not module.initialize():
                self.logger.error(f"Failed to initialize module {module.name}")
                success = False
        
        return success
    
    def shutdown_all(self) -> bool:
        """Shutdown all registered modules
        
        Returns:
            True if all modules shut down successfully, False otherwise
        """
        success = True
        
        # Shutdown in reverse dependency order
        modules_to_shutdown = self._get_dependency_sorted_modules()
        modules_to_shutdown.reverse()
        
        for module in modules_to_shutdown:
            if not module.shutdown():
                self.logger.error(f"Failed to shutdown module {module.name}")
                success = False
        
        return success
    
    def _get_dependency_sorted_modules(self) -> List[Module]:
        """Sort modules according to dependency order
        
        Returns:
            List of modules sorted by dependency (dependencies first)
        """
        # TODO: Implement topological sort for module dependencies
        # For now, return in simple list
        return list(self.modules.values()) 