#!/usr/bin/env python3
"""
Module base class for ARP Guard
Base class for all ARP Guard modules
"""

from typing import Dict, Any


class Module:
    """Base class for ARP Guard modules"""
    
    def __init__(self, name: str, description: str, config: Any = None):
        """
        Initialize the module
        
        Args:
            name: Module name
            description: Module description
            config: Module configuration
        """
        self.name = name
        self.description = description
        self.config = config
        self.initialized = False
    
    def initialize(self) -> bool:
        """
        Initialize the module
        
        Returns:
            True if initialization successful, False otherwise
        """
        self.initialized = True
        return True
    
    def shutdown(self) -> bool:
        """
        Shutdown the module
        
        Returns:
            True if shutdown successful, False otherwise
        """
        self.initialized = False
        return True
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get module status
        
        Returns:
            Dictionary with module status
        """
        return {
            "name": self.name,
            "description": self.description,
            "initialized": self.initialized
        }
    
    def __str__(self) -> str:
        """String representation"""
        return f"{self.name}: {self.description} (Initialized: {self.initialized})" 