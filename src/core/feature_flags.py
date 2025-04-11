#!/usr/bin/env python3
"""
Feature Flag System

This module manages feature flags and their integration with the license system.
It controls which features are available based on the user's license type.
"""

from enum import Enum, auto
from typing import Dict, Any, Optional, List, Set, Callable
import logging
import json
import os
import functools
from .license_manager import LicenseManager, LicenseType

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ProductTier(Enum):
    """Product tier levels"""
    DEMO = auto()
    LITE = auto()
    PRO = auto()
    ENTERPRISE = auto()

class FeatureFlag:
    """Feature flag definition"""
    
    def __init__(self, 
                 feature_id: str, 
                 name: str, 
                 description: str, 
                 min_tier: ProductTier,
                 default_enabled: bool = True):
        """Initialize feature flag
        
        Args:
            feature_id: Unique identifier for the feature
            name: Human-readable name for the feature
            description: Description of the feature
            min_tier: Minimum product tier required for this feature
            default_enabled: Whether the feature is enabled by default
        """
        self.feature_id = feature_id
        self.name = name
        self.description = description
        self.min_tier = min_tier
        self.default_enabled = default_enabled
        self.enabled = default_enabled
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert feature flag to dictionary"""
        return {
            "feature_id": self.feature_id,
            "name": self.name,
            "description": self.description,
            "min_tier": self.min_tier.name,
            "default_enabled": self.default_enabled,
            "enabled": self.enabled
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FeatureFlag':
        """Create feature flag from dictionary"""
        min_tier = ProductTier[data["min_tier"]]
        flag = cls(
            feature_id=data["feature_id"],
            name=data["name"],
            description=data["description"],
            min_tier=min_tier,
            default_enabled=data["default_enabled"]
        )
        flag.enabled = data.get("enabled", flag.default_enabled)
        return flag


class FeatureFlagManager:
    """Manager for feature flags"""
    
    _instance = None
    
    def __new__(cls):
        """Singleton pattern implementation"""
        if cls._instance is None:
            cls._instance = super(FeatureFlagManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """Initialize feature flag manager"""
        if self._initialized:
            return
            
        self.flags: Dict[str, FeatureFlag] = {}
        self.current_tier = ProductTier.DEMO
        self.override_enabled = False
        self.logger = logging.getLogger(f"{__name__}.manager")
        self._initialized = True
    
    def register_feature(self, feature: FeatureFlag) -> bool:
        """Register a feature flag
        
        Args:
            feature: Feature flag instance
            
        Returns:
            True if registration successful, False otherwise
        """
        if feature.feature_id in self.flags:
            self.logger.warning(f"Feature with ID {feature.feature_id} already registered")
            return False
        
        self.flags[feature.feature_id] = feature
        self.logger.info(f"Feature {feature.name} (ID: {feature.feature_id}) registered")
        
        # Update feature enabled status based on current tier
        self._update_feature_status(feature)
        
        return True
    
    def unregister_feature(self, feature_id: str) -> bool:
        """Unregister a feature flag
        
        Args:
            feature_id: ID of the feature to unregister
            
        Returns:
            True if unregistration successful, False otherwise
        """
        if feature_id not in self.flags:
            self.logger.warning(f"No feature with ID {feature_id} registered")
            return False
        
        feature = self.flags[feature_id]
        del self.flags[feature_id]
        self.logger.info(f"Feature {feature.name} (ID: {feature_id}) unregistered")
        return True
    
    def get_feature(self, feature_id: str) -> Optional[FeatureFlag]:
        """Get a feature flag by ID
        
        Args:
            feature_id: ID of the feature to get
            
        Returns:
            Feature flag instance if found, None otherwise
        """
        return self.flags.get(feature_id)
    
    def is_feature_enabled(self, feature_id: str) -> bool:
        """Check if a feature is enabled
        
        Args:
            feature_id: ID of the feature to check
            
        Returns:
            True if feature is enabled, False otherwise or if feature not found
        """
        feature = self.get_feature(feature_id)
        if not feature:
            self.logger.warning(f"Feature check for unknown ID: {feature_id}")
            return False
        
        return feature.enabled
    
    def set_current_tier(self, tier: ProductTier) -> None:
        """Set the current product tier
        
        Args:
            tier: Product tier to set
        """
        if self.current_tier == tier:
            return
            
        self.current_tier = tier
        self.logger.info(f"Product tier set to {tier.name}")
        
        # Update all features based on new tier
        for feature in self.flags.values():
            self._update_feature_status(feature)
    
    def enable_feature(self, feature_id: str) -> bool:
        """Enable a specific feature
        
        Args:
            feature_id: ID of the feature to enable
            
        Returns:
            True if feature was enabled, False otherwise
        """
        feature = self.get_feature(feature_id)
        if not feature:
            return False
        
        feature.enabled = True
        self.logger.info(f"Feature {feature.name} manually enabled")
        return True
    
    def disable_feature(self, feature_id: str) -> bool:
        """Disable a specific feature
        
        Args:
            feature_id: ID of the feature to disable
            
        Returns:
            True if feature was disabled, False otherwise
        """
        feature = self.get_feature(feature_id)
        if not feature:
            return False
        
        feature.enabled = False
        self.logger.info(f"Feature {feature.name} manually disabled")
        return True
    
    def reset_feature(self, feature_id: str) -> bool:
        """Reset a feature to its tier-based status
        
        Args:
            feature_id: ID of the feature to reset
            
        Returns:
            True if feature was reset, False otherwise
        """
        feature = self.get_feature(feature_id)
        if not feature:
            return False
        
        self._update_feature_status(feature)
        self.logger.info(f"Feature {feature.name} reset to tier-based status")
        return True
    
    def enable_override_mode(self) -> None:
        """Enable override mode (for development/testing)"""
        self.override_enabled = True
        self.logger.warning("Feature flag override mode enabled")
    
    def disable_override_mode(self) -> None:
        """Disable override mode"""
        self.override_enabled = False
        self.logger.info("Feature flag override mode disabled")
    
    def is_override_mode_enabled(self) -> bool:
        """Check if override mode is enabled
        
        Returns:
            True if override mode is enabled, False otherwise
        """
        return self.override_enabled
    
    def save_to_file(self, file_path: str) -> None:
        """Save feature flags to file
        
        Args:
            file_path: Path to save feature flags to
        """
        data = {
            "current_tier": self.current_tier.name,
            "override_enabled": self.override_enabled,
            "features": {fid: f.to_dict() for fid, f in self.flags.items()}
        }
        
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
            
        self.logger.info(f"Feature flags saved to {file_path}")
    
    def load_from_file(self, file_path: str) -> bool:
        """Load feature flags from file
        
        Args:
            file_path: Path to load feature flags from
            
        Returns:
            True if loading was successful, False otherwise
        """
        if not os.path.exists(file_path):
            self.logger.warning(f"Feature flags file {file_path} not found")
            return False
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            self.current_tier = ProductTier[data["current_tier"]]
            self.override_enabled = data.get("override_enabled", False)
            
            # Clear existing flags
            self.flags.clear()
            
            # Load features
            for fid, f_data in data["features"].items():
                feature = FeatureFlag.from_dict(f_data)
                self.flags[feature.feature_id] = feature
                
            self.logger.info(f"Feature flags loaded from {file_path}")
            return True
                
        except Exception as e:
            self.logger.error(f"Failed to load feature flags: {e}")
            return False
    
    def get_all_features(self) -> List[FeatureFlag]:
        """Get all registered features
        
        Returns:
            List of all registered feature flags
        """
        return list(self.flags.values())
    
    def get_tier_features(self, tier: ProductTier) -> List[FeatureFlag]:
        """Get all features available for a specific tier
        
        Args:
            tier: Product tier to get features for
            
        Returns:
            List of feature flags available for the specified tier
        """
        return [f for f in self.flags.values() if f.min_tier.value <= tier.value]
    
    def _update_feature_status(self, feature: FeatureFlag) -> None:
        """Update a feature's enabled status based on current tier
        
        Args:
            feature: Feature to update
        """
        if self.override_enabled:
            # In override mode, don't change feature status
            return
            
        # Enable feature if current tier is at or above feature's minimum tier
        feature.enabled = (self.current_tier.value >= feature.min_tier.value)


# Decorator for feature-gated functions
def feature_required(feature_id: str, graceful_degradation: bool = False):
    """Decorator to gate a function based on a feature flag
    
    Args:
        feature_id: ID of the required feature
        graceful_degradation: If True, function will return None instead of raising
                             exception when feature is disabled
                             
    Returns:
        Decorated function
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            manager = FeatureFlagManager()
            if manager.is_feature_enabled(feature_id):
                return func(*args, **kwargs)
            elif graceful_degradation:
                logger.info(f"Feature {feature_id} disabled, graceful degradation activated")
                return None
            else:
                raise FeatureDisabledException(f"Feature {feature_id} is required but disabled")
        return wrapper
    return decorator


class FeatureDisabledException(Exception):
    """Exception raised when trying to use a disabled feature"""
    pass


# Create standard feature flags
def register_standard_features():
    """Register standard feature flags for the application"""
    manager = FeatureFlagManager()
    
    # Core features (Demo tier)
    manager.register_feature(FeatureFlag(
        feature_id="core.packet_analysis",
        name="Packet Analysis",
        description="Core packet analysis functionality",
        min_tier=ProductTier.DEMO,
        default_enabled=True
    ))
    
    manager.register_feature(FeatureFlag(
        feature_id="core.detection",
        name="ARP Spoofing Detection",
        description="Detection of basic ARP spoofing attacks",
        min_tier=ProductTier.DEMO
    ))
    
    manager.register_feature(FeatureFlag(
        feature_id="core.export",
        name="Export Results",
        description="Export results to JSON/CSV formats",
        min_tier=ProductTier.DEMO
    ))
    
    # Lite tier features
    manager.register_feature(FeatureFlag(
        feature_id="lite.gui",
        name="Basic GUI",
        description="Basic graphical user interface",
        min_tier=ProductTier.LITE
    ))
    
    manager.register_feature(FeatureFlag(
        feature_id="lite.continuous_monitoring",
        name="Continuous Monitoring",
        description="Background continuous monitoring of network",
        min_tier=ProductTier.LITE
    ))
    
    manager.register_feature(FeatureFlag(
        feature_id="lite.alerts",
        name="Basic Alert System",
        description="Local and email alerting capabilities",
        min_tier=ProductTier.LITE
    ))
    
    # Pro tier features
    manager.register_feature(FeatureFlag(
        feature_id="pro.advanced_dashboard",
        name="Advanced Dashboard",
        description="Advanced visualization dashboard with graphs",
        min_tier=ProductTier.PRO
    ))
    
    manager.register_feature(FeatureFlag(
        feature_id="pro.ml_detection",
        name="ML-based Detection",
        description="Machine learning based detection algorithms",
        min_tier=ProductTier.PRO
    ))
    
    manager.register_feature(FeatureFlag(
        feature_id="pro.reporting",
        name="Advanced Reporting",
        description="Detailed reporting and scheduling",
        min_tier=ProductTier.PRO
    ))
    
    # Enterprise tier features
    manager.register_feature(FeatureFlag(
        feature_id="enterprise.centralized_management",
        name="Centralized Management",
        description="Centralized management of multiple agents",
        min_tier=ProductTier.ENTERPRISE
    ))
    
    manager.register_feature(FeatureFlag(
        feature_id="enterprise.siem_integration",
        name="SIEM Integration",
        description="Integration with security information and event management systems",
        min_tier=ProductTier.ENTERPRISE
    ))
    
    manager.register_feature(FeatureFlag(
        feature_id="enterprise.auto_blocking",
        name="Automatic Threat Blocking",
        description="Automatic blocking of detected threats",
        min_tier=ProductTier.ENTERPRISE
    ))

    # Add other standard features...
    manager.register_feature(FeatureFlag(
        feature_id="core.telemetry",
        name="Telemetry",
        description="Usage statistics collection",
        min_tier=ProductTier.DEMO,
        default_enabled=False
    ))

def register_license_based_features(license_manager: LicenseManager):
    """Register feature flags based on the user's license."""
    manager = FeatureFlagManager()
    
    # Register basic monitoring feature
    manager.register_feature(FeatureFlag(
        feature_id="basic_monitoring",
        name="basic_monitoring",
        description="Basic ARP monitoring capabilities",
        min_tier=ProductTier.DEMO,
        default_enabled=True
    ))
    
    # Register network scan feature
    manager.register_feature(FeatureFlag(
        feature_id="network_scan",
        name="network_scan",
        description="Network scanning and device discovery",
        min_tier=ProductTier.DEMO,
        default_enabled=True
    ))
    
    # Register email alerts feature
    manager.register_feature(FeatureFlag(
        feature_id="email_alerts",
        name="email_alerts",
        description="Email notification system for alerts",
        min_tier=ProductTier.LITE,
        default_enabled=False
    ))
    
    # Register custom actions feature
    manager.register_feature(FeatureFlag(
        feature_id="custom_actions",
        name="custom_actions",
        description="Custom alert actions and integrations",
        min_tier=ProductTier.LITE,
        default_enabled=False
    ))
    
    # Register report generation feature
    manager.register_feature(FeatureFlag(
        feature_id="report_generation",
        name="report_generation",
        description="Generate detailed network reports",
        min_tier=ProductTier.LITE,
        default_enabled=False
    ))
    
    # Register advanced detection feature
    manager.register_feature(FeatureFlag(
        feature_id="advanced_detection",
        name="advanced_detection",
        description="Advanced ARP spoofing detection algorithms",
        min_tier=ProductTier.PRO,
        default_enabled=False
    ))
    
    # Register multi-subnet feature
    manager.register_feature(FeatureFlag(
        feature_id="multi_subnet",
        name="multi_subnet",
        description="Monitor multiple subnets simultaneously",
        min_tier=ProductTier.PRO,
        default_enabled=False
    ))
    
    # Register API access feature
    manager.register_feature(FeatureFlag(
        feature_id="api_access",
        name="api_access",
        description="Access to REST API for integration",
        min_tier=ProductTier.PRO,
        default_enabled=False
    ))
    
    # Register enterprise features feature
    manager.register_feature(FeatureFlag(
        feature_id="enterprise_features",
        name="enterprise_features",
        description="Enterprise-grade features and support",
        min_tier=ProductTier.ENTERPRISE,
        default_enabled=False
    ))

    # Update feature status based on license
    for feature in manager.flags.values():
        self._update_feature_status(feature)

def is_feature_enabled(feature_name: str, license_key: Optional[str] = None) -> bool:
    """Check if a feature is enabled for the given license."""
    manager = FeatureFlagManager()
    if feature_name not in manager.flags:
        logger.warning(f"Unknown feature: {feature_name}")
        return False

    feature = manager.flags[feature_name]
    
    # If no license key provided, return default value
    if not license_key:
        return feature.default_enabled

    # Check license validation
    validation = license_manager.validate_license(license_key)
    if not validation["valid"]:
        logger.warning(f"Invalid license for feature {feature_name}")
        return False

    # Check if feature is available for the license type
    license_type = validation["type"]
    if license_type not in feature.tier_requirements:
        logger.info(f"Feature {feature_name} not available for license type {license_type}")
        return False

    return True

def get_available_features(license_key: Optional[str] = None) -> List[str]:
    """Get list of available features for the given license."""
    manager = FeatureFlagManager()
    if not license_key:
        return [f.feature_id for f in manager.get_all_features() if manager.is_feature_enabled(f.feature_id)]
    else:
        # Additional license-specific feature lookup
        license_manager = LicenseManager()
        tier = license_manager.get_license_tier(license_key)
        return [f.feature_id for f in manager.get_tier_features(tier)] 