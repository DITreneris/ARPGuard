#!/usr/bin/env python3
"""
Module Factory for ARP Guard
Provides factory methods to create appropriate modules based on user settings
"""

import logging
from typing import Optional, Dict, Any, Union

from .detection_module import DetectionModule, DetectionModuleConfig
from .lite_detection_module import LiteDetectionModule
from .remediation_module import RemediationModule

logger = logging.getLogger(__name__)

class ModuleFactory:
    """
    Factory class for creating detection and remediation modules
    """
    
    @staticmethod
    def create_detection_module(
        config: Dict[str, Any],
        remediation: Optional[RemediationModule] = None,
        use_lite_version: bool = False
    ) -> Union[DetectionModule, LiteDetectionModule]:
        """
        Create the appropriate detection module based on configuration
        
        Args:
            config: Configuration dictionary
            remediation: Optional remediation module
            use_lite_version: Whether to use the lite version of the detection module
            
        Returns:
            Detection module instance
        """
        # Create configuration object
        module_config = DetectionModuleConfig(
            detection_interval=config.get("detection_interval", 5),
            enabled_features=config.get("enabled_features", ["basic"]),
            storage_path=config.get("storage_path", None),
            max_packet_cache=config.get("max_packet_cache", 1000),
            auto_protect=config.get("auto_protect", False),
            history_size=config.get("history_size", 10),
            worker_threads=config.get("worker_threads", 2),
            enable_sampling=config.get("enable_sampling", True),
            sampling_rate=config.get("sampling_rate", 0.5),
            batch_size=config.get("batch_size", 50),
            prioritize_packets=config.get("prioritize_packets", True)
        )
        
        # Create lite or full detection module based on setting
        if use_lite_version:
            logger.info("Creating lite detection module")
            return LiteDetectionModule(config=module_config)
        else:
            logger.info("Creating full detection module")
            return DetectionModule(config=module_config, remediation=remediation)
    
    @staticmethod
    def create_remediation_module(config: Dict[str, Any]) -> RemediationModule:
        """
        Create remediation module
        
        Args:
            config: Configuration dictionary
            
        Returns:
            Remediation module instance
        """
        # Create remediation module
        return RemediationModule(
            enabled=config.get("remediation_enabled", False),
            auto_protect=config.get("auto_protect", False),
            protection_methods=config.get("protection_methods", ["notify"])
        ) 