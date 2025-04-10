import unittest
from PyQt5.QtWidgets import QWidget, QLabel
from PyQt5.QtCore import QCoreApplication
from app.ui.lazy_loader import LazyLoader

class TestLazyLoader(unittest.TestCase):
    def setUp(self):
        self.app = QCoreApplication.instance()
        if not self.app:
            self.app = QCoreApplication([])
        self.loader = LazyLoader()
        
    def test_component_registration(self):
        """Test component registration"""
        def create_label():
            return QLabel("Test Label")
            
        self.loader.register_component('test_label', create_label)
        self.assertIn('test_label', self.loader.load_callbacks)
        
    def test_component_loading(self):
        """Test component loading"""
        def create_label():
            return QLabel("Test Label")
            
        self.loader.register_component('test_label', create_label)
        component = self.loader.get_component('test_label')
        
        self.assertIsInstance(component, QLabel)
        self.assertEqual(component.text(), "Test Label")
        
    def test_component_caching(self):
        """Test component caching"""
        load_count = 0
        def create_label():
            nonlocal load_count
            load_count += 1
            return QLabel("Test Label")
            
        self.loader.register_component('test_label', create_label)
        
        # First load
        component1 = self.loader.get_component('test_label')
        self.assertEqual(load_count, 1)
        
        # Second load should use cache
        component2 = self.loader.get_component('test_label')
        self.assertEqual(load_count, 1)
        self.assertEqual(component1, component2)
        
    def test_component_unloading(self):
        """Test component unloading"""
        def create_label():
            return QLabel("Test Label")
            
        self.loader.register_component('test_label', create_label)
        component = self.loader.get_component('test_label')
        
        self.loader.unload_component('test_label')
        self.assertNotIn('test_label', self.loader.loaded_components)
        
    def test_performance_stats(self):
        """Test performance statistics collection"""
        def create_label():
            return QLabel("Test Label")
            
        self.loader.register_component('test_label', create_label)
        self.loader.get_component('test_label')
        
        stats = self.loader.get_performance_stats()
        self.assertIn('response_time_load_component_test_label', stats)
        
    def test_preloading(self):
        """Test component preloading"""
        load_count = 0
        def create_label():
            nonlocal load_count
            load_count += 1
            return QLabel("Test Label")
            
        self.loader.register_component('test_label', create_label)
        self.loader.preload_component('test_label', delay_ms=100)
        
        # Wait for preload
        self.app.processEvents()
        
        # Component should be loaded
        self.assertIn('test_label', self.loader.loaded_components)
        self.assertEqual(load_count, 1)

if __name__ == '__main__':
    unittest.main() 