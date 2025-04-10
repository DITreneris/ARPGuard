import os
import sys
import unittest
import tempfile
import json
from typing import Dict, Any

# Add project root to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.module_interface import Module, ModuleConfig, ModuleRegistry
from src.core.feature_flags import (
    FeatureFlagManager, FeatureFlag, ProductTier, 
    feature_required, FeatureDisabledException
)
from src.core.cli_module import CLIModule, CLICommand
from src.core.detection_module import DetectionModule, DetectionResult

class TestModuleConfig(unittest.TestCase):
    """Test ModuleConfig class"""
    
    def test_init(self):
        """Test initialization"""
        config = ModuleConfig(name="test", value=42)
        self.assertEqual(config.name, "test")
        self.assertEqual(config.value, 42)
    
    def test_to_dict(self):
        """Test to_dict method"""
        config = ModuleConfig(name="test", value=42)
        config_dict = config.to_dict()
        self.assertEqual(config_dict, {"name": "test", "value": 42})
    
    def test_from_dict(self):
        """Test from_dict method"""
        config_dict = {"name": "test", "value": 42}
        config = ModuleConfig.from_dict(config_dict)
        self.assertEqual(config.name, "test")
        self.assertEqual(config.value, 42)
    
    def test_save_load(self):
        """Test save_to_file and load_from_file methods"""
        config = ModuleConfig(name="test", value=42)
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
            # Save config
            config.save_to_file(tmp.name)
            
            # Load config
            loaded_config = ModuleConfig.load_from_file(tmp.name)
            
            # Check loaded config
            self.assertEqual(loaded_config.name, "test")
            self.assertEqual(loaded_config.value, 42)
        
        # Delete temporary file
        if os.path.exists(tmp.name):
            os.unlink(tmp.name)


class TestModule(Module):
    """Test implementation of Module"""
    
    def __init__(self, module_id: str, name: str, config=None):
        """Initialize test module"""
        super().__init__(module_id, name, config)
        self.initialized = False
        self.shutdown_called = False
    
    def initialize(self) -> bool:
        """Initialize the module"""
        self.initialized = True
        return True
    
    def shutdown(self) -> bool:
        """Shutdown the module"""
        self.shutdown_called = True
        return True


class TestModuleRegistry(unittest.TestCase):
    """Test ModuleRegistry class"""
    
    def setUp(self):
        """Set up test case"""
        self.registry = ModuleRegistry()
        
        # Create test modules
        self.module1 = TestModule("test1", "Test Module 1")
        self.module2 = TestModule("test2", "Test Module 2")
        
        # Set up dependencies
        self.module2.add_dependency("test1")
    
    def test_register_module(self):
        """Test register_module method"""
        # Register modules
        self.assertTrue(self.registry.register_module(self.module1))
        self.assertTrue(self.registry.register_module(self.module2))
        
        # Try to register again (should fail)
        self.assertFalse(self.registry.register_module(self.module1))
    
    def test_get_module(self):
        """Test get_module method"""
        # Register module
        self.registry.register_module(self.module1)
        
        # Get module
        module = self.registry.get_module("test1")
        self.assertEqual(module, self.module1)
        
        # Get non-existent module
        module = self.registry.get_module("non_existent")
        self.assertIsNone(module)
    
    def test_unregister_module(self):
        """Test unregister_module method"""
        # Register module
        self.registry.register_module(self.module1)
        
        # Unregister module
        self.assertTrue(self.registry.unregister_module("test1"))
        
        # Try to unregister again (should fail)
        self.assertFalse(self.registry.unregister_module("test1"))
    
    def test_initialize_shutdown(self):
        """Test initialize_all and shutdown_all methods"""
        # Register modules
        self.registry.register_module(self.module1)
        self.registry.register_module(self.module2)
        
        # Initialize all modules
        self.assertTrue(self.registry.initialize_all())
        self.assertTrue(self.module1.initialized)
        self.assertTrue(self.module2.initialized)
        
        # Shutdown all modules
        self.assertTrue(self.registry.shutdown_all())
        self.assertTrue(self.module1.shutdown_called)
        self.assertTrue(self.module2.shutdown_called)


class TestFeatureFlag(unittest.TestCase):
    """Test FeatureFlag class"""
    
    def test_init(self):
        """Test initialization"""
        flag = FeatureFlag(
            feature_id="test.feature",
            name="Test Feature",
            description="Test feature description",
            min_tier=ProductTier.DEMO
        )
        
        self.assertEqual(flag.feature_id, "test.feature")
        self.assertEqual(flag.name, "Test Feature")
        self.assertEqual(flag.description, "Test feature description")
        self.assertEqual(flag.min_tier, ProductTier.DEMO)
        self.assertTrue(flag.default_enabled)
        self.assertTrue(flag.enabled)
    
    def test_to_dict(self):
        """Test to_dict method"""
        flag = FeatureFlag(
            feature_id="test.feature",
            name="Test Feature",
            description="Test feature description",
            min_tier=ProductTier.DEMO,
            default_enabled=False
        )
        
        flag_dict = flag.to_dict()
        self.assertEqual(flag_dict["feature_id"], "test.feature")
        self.assertEqual(flag_dict["name"], "Test Feature")
        self.assertEqual(flag_dict["description"], "Test feature description")
        self.assertEqual(flag_dict["min_tier"], "DEMO")
        self.assertFalse(flag_dict["default_enabled"])
        self.assertFalse(flag_dict["enabled"])
    
    def test_from_dict(self):
        """Test from_dict method"""
        flag_dict = {
            "feature_id": "test.feature",
            "name": "Test Feature",
            "description": "Test feature description",
            "min_tier": "PRO",
            "default_enabled": False
        }
        
        flag = FeatureFlag.from_dict(flag_dict)
        self.assertEqual(flag.feature_id, "test.feature")
        self.assertEqual(flag.name, "Test Feature")
        self.assertEqual(flag.description, "Test feature description")
        self.assertEqual(flag.min_tier, ProductTier.PRO)
        self.assertFalse(flag.default_enabled)
        self.assertFalse(flag.enabled)


class TestFeatureFlagManager(unittest.TestCase):
    """Test FeatureFlagManager class"""
    
    def setUp(self):
        """Set up test case"""
        # Get singleton instance
        self.manager = FeatureFlagManager()
        
        # Clear existing flags
        self.manager.flags = {}
        
        # Reset to DEMO tier
        self.manager.current_tier = ProductTier.DEMO
        self.manager.override_enabled = False
        
        # Create test flags
        self.demo_flag = FeatureFlag(
            feature_id="test.demo",
            name="Demo Feature",
            description="Demo tier feature",
            min_tier=ProductTier.DEMO
        )
        
        self.pro_flag = FeatureFlag(
            feature_id="test.pro",
            name="Pro Feature",
            description="Pro tier feature",
            min_tier=ProductTier.PRO
        )
    
    def test_register_feature(self):
        """Test register_feature method"""
        # Register features
        self.assertTrue(self.manager.register_feature(self.demo_flag))
        self.assertTrue(self.manager.register_feature(self.pro_flag))
        
        # Try to register again (should fail)
        self.assertFalse(self.manager.register_feature(self.demo_flag))
    
    def test_is_feature_enabled(self):
        """Test is_feature_enabled method"""
        # Register features
        self.manager.register_feature(self.demo_flag)
        self.manager.register_feature(self.pro_flag)
        
        # Demo tier enables only demo features
        self.manager.set_current_tier(ProductTier.DEMO)
        self.assertTrue(self.manager.is_feature_enabled("test.demo"))
        self.assertFalse(self.manager.is_feature_enabled("test.pro"))
        
        # Pro tier enables all features
        self.manager.set_current_tier(ProductTier.PRO)
        self.assertTrue(self.manager.is_feature_enabled("test.demo"))
        self.assertTrue(self.manager.is_feature_enabled("test.pro"))
        
        # Non-existent feature
        self.assertFalse(self.manager.is_feature_enabled("non_existent"))
    
    def test_set_current_tier(self):
        """Test set_current_tier method"""
        # Register features
        self.manager.register_feature(self.demo_flag)
        self.manager.register_feature(self.pro_flag)
        
        # Set to DEMO tier
        self.manager.set_current_tier(ProductTier.DEMO)
        self.assertTrue(self.demo_flag.enabled)
        self.assertFalse(self.pro_flag.enabled)
        
        # Set to PRO tier
        self.manager.set_current_tier(ProductTier.PRO)
        self.assertTrue(self.demo_flag.enabled)
        self.assertTrue(self.pro_flag.enabled)
    
    def test_enable_override_mode(self):
        """Test enable_override_mode method"""
        # Register features
        self.manager.register_feature(self.demo_flag)
        self.manager.register_feature(self.pro_flag)
        
        # Set to DEMO tier
        self.manager.set_current_tier(ProductTier.DEMO)
        self.assertTrue(self.demo_flag.enabled)
        self.assertFalse(self.pro_flag.enabled)
        
        # Enable PRO feature manually
        self.manager.enable_feature("test.pro")
        self.assertTrue(self.pro_flag.enabled)
        
        # Change tier (should reset feature status)
        self.manager.set_current_tier(ProductTier.DEMO)
        self.assertFalse(self.pro_flag.enabled)
        
        # Enable override mode
        self.manager.enable_override_mode()
        
        # Enable PRO feature
        self.manager.enable_feature("test.pro")
        self.assertTrue(self.pro_flag.enabled)
        
        # Change tier (should not affect feature status in override mode)
        self.manager.set_current_tier(ProductTier.DEMO)
        self.assertTrue(self.pro_flag.enabled)
    
    def test_feature_required_decorator(self):
        """Test feature_required decorator"""
        # Register features
        self.manager.register_feature(self.demo_flag)
        self.manager.register_feature(self.pro_flag)
        
        # Set to DEMO tier
        self.manager.set_current_tier(ProductTier.DEMO)
        
        # Define test functions
        @feature_required("test.demo")
        def demo_function():
            return "Demo function executed"
        
        @feature_required("test.pro")
        def pro_function():
            return "Pro function executed"
        
        @feature_required("test.pro", graceful_degradation=True)
        def graceful_function():
            return "Graceful function executed"
        
        # Test functions
        self.assertEqual(demo_function(), "Demo function executed")
        
        # Pro function should raise exception
        with self.assertRaises(FeatureDisabledException):
            pro_function()
        
        # Graceful function should return None
        self.assertIsNone(graceful_function())
        
        # Set to PRO tier
        self.manager.set_current_tier(ProductTier.PRO)
        
        # Now all functions should work
        self.assertEqual(demo_function(), "Demo function executed")
        self.assertEqual(pro_function(), "Pro function executed")
        self.assertEqual(graceful_function(), "Graceful function executed")


class TestDetectionModule(unittest.TestCase):
    """Test DetectionModule class"""
    
    def setUp(self):
        """Set up test case"""
        # Reset feature flag manager
        self.manager = FeatureFlagManager()
        self.manager.flags = {}
        self.manager.current_tier = ProductTier.DEMO
        self.manager.override_enabled = False
        
        # Register core detection feature
        self.manager.register_feature(FeatureFlag(
            feature_id="core.detection",
            name="Core Detection",
            description="Core detection feature",
            min_tier=ProductTier.DEMO
        ))
        
        # Register ML detection feature
        self.manager.register_feature(FeatureFlag(
            feature_id="pro.ml_detection",
            name="ML Detection",
            description="ML detection feature",
            min_tier=ProductTier.PRO
        ))
        
        # Create module
        self.module = DetectionModule()
    
    def test_initialization(self):
        """Test initialization"""
        self.assertTrue(self.module.initialize())
        self.assertFalse(self.module.running)
        self.assertEqual(len(self.module.results), 0)
    
    def test_analyze_packet(self):
        """Test analyze_packet method"""
        # Initialize module
        self.module.initialize()
        
        # Create test packet
        packet = {"id": "test_packet", "data": b"test data"}
        
        # Analyze packet (should work in DEMO tier)
        result = self.module.analyze_packet(packet)
        self.assertIsNotNone(result)
        self.assertFalse(result.is_attack)
        
        # ML analysis should gracefully degrade in DEMO tier
        result = self.module.analyze_packet_ml(packet)
        self.assertIsNone(result)
        
        # Set to PRO tier
        self.manager.set_current_tier(ProductTier.PRO)
        
        # Now ML analysis should work
        result = self.module.analyze_packet_ml(packet)
        self.assertIsNotNone(result)
        self.assertFalse(result.is_attack)
        self.assertEqual(result.details["algorithm"], "ml")
    
    def test_detection_result(self):
        """Test DetectionResult class"""
        result = DetectionResult(
            timestamp=1234567890.0,
            is_attack=True,
            confidence=0.95,
            details={"algorithm": "test"}
        )
        
        self.assertEqual(result.timestamp, 1234567890.0)
        self.assertTrue(result.is_attack)
        self.assertEqual(result.confidence, 0.95)
        self.assertEqual(result.details["algorithm"], "test")
        
        # Test to_dict
        result_dict = result.to_dict()
        self.assertEqual(result_dict["timestamp"], 1234567890.0)
        self.assertTrue(result_dict["is_attack"])
        self.assertEqual(result_dict["confidence"], 0.95)
        self.assertEqual(result_dict["details"]["algorithm"], "test")


class TestCLIModule(unittest.TestCase):
    """Test CLIModule class"""
    
    def setUp(self):
        """Set up test case"""
        # Create CLI module
        self.cli = CLIModule()
        
        # Create test command
        self.command = CLICommand(
            name="test",
            description="Test command",
            handler=lambda args: True
        )
    
    def test_initialization(self):
        """Test initialization"""
        self.assertTrue(self.cli.initialize())
    
    def test_register_command(self):
        """Test register_command method"""
        # Register command
        self.assertTrue(self.cli.register_command(self.command))
        
        # Try to register again (should fail)
        self.assertFalse(self.cli.register_command(self.command))
        
        # Unregister command
        self.assertTrue(self.cli.unregister_command("test"))
        
        # Try to unregister again (should fail)
        self.assertFalse(self.cli.unregister_command("test"))


if __name__ == "__main__":
    unittest.main() 