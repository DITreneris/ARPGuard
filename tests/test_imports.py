import unittest
import sys

# Add the app directory to the Python path
sys.path.append('app')

class TestImports(unittest.TestCase):
    def test_core_imports(self):
        """Test importing core components"""
        try:
            import app
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Failed to import app module: {e}")
            
    def test_components_imports(self):
        """Test importing component modules"""
        try:
            from components import main_window
            from components import network_scanner
            from components import threat_detector
            from components import arp_spoofer
            from components import packet_view
            from components import packet_analyzer
            from components import session_history
            from components import packet_display
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Failed to import component module: {e}")
            
    def test_utils_imports(self):
        """Test importing utility modules"""
        try:
            from utils import config
            from utils import database
            from utils import logger
            from utils import mac_vendor
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Failed to import utility module: {e}")
            
    def test_advanced_components_imports(self):
        """Test importing advanced component modules"""
        try:
            from components import threat_intelligence
            from components import threat_intelligence_view
            from components import attack_recognizer
            from components import attack_view
            from components import defense_mechanism
            from components import defense_view
            from components import network_topology
            from components import vulnerability_scanner
            from components import vulnerability_view
            from components import report_viewer
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Failed to import advanced component module: {e}")

if __name__ == '__main__':
    unittest.main() 