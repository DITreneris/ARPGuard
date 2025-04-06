import unittest
import sys
import time
from unittest.mock import Mock, patch, MagicMock
from PyQt5.QtWidgets import QApplication, QToolTip, QMenu
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt, QPoint, QSize
from PyQt5.QtGui import QFont, QColor

# Add the app directory to the Python path
sys.path.append('app')

from components.main_window import MainWindow
from components.network_scanner import NetworkScanner
from components.threat_detector import ThreatDetector

class TestUIAccessibility(unittest.TestCase):
    """Test accessibility features of the UI"""
    
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv) if not QApplication.instance() else QApplication.instance()
        # Set application-wide font for testing
        cls.original_font = cls.app.font()
        
    @classmethod
    def tearDownClass(cls):
        # Restore original font
        cls.app.setFont(cls.original_font)
        
    def setUp(self):
        """Set up mocks and prepare the main window for testing"""
        # Create mock objects for the main components
        self.mock_scanner = Mock(spec=NetworkScanner)
        self.mock_detector = Mock(spec=ThreatDetector)
        
        # Patch component classes
        self.scanner_patcher = patch('components.main_window.NetworkScanner', 
                                    return_value=self.mock_scanner)
        self.detector_patcher = patch('components.main_window.ThreatDetector', 
                                     return_value=self.mock_detector)
        
        # Start patchers
        self.scanner_patcher.start()
        self.detector_patcher.start()
        
        # Create the main window
        self.window = MainWindow()
        
    def tearDown(self):
        """Clean up after each test"""
        self.window.close()
        self.window.deleteLater()
        
        # Stop patchers
        self.scanner_patcher.stop()
        self.detector_patcher.stop()
        
    def test_tooltip_availability(self):
        """Test that important UI elements have tooltips for accessibility"""
        # Get important UI elements and check for tooltips
        important_elements = []
        
        # Find elements with common names that should have tooltips
        # This is a generic approach - adapt to actual UI element names
        for element_name in ['scan_button', 'stop_button', 'filter_input', 'refresh_button']:
            if hasattr(self.window, element_name):
                element = getattr(self.window, element_name)
                important_elements.append((element_name, element))
        
        # Check toolbar actions if they exist
        if hasattr(self.window, 'toolbar'):
            for action in self.window.toolbar.actions():
                important_elements.append((action.text(), action))
        
        # Check menu actions if they exist
        if hasattr(self.window, 'menuBar'):
            for menu in self.window.menuBar().findChildren(QMenu):
                for action in menu.actions():
                    important_elements.append((action.text(), action))
        
        # Verify tooltips exist and are not empty
        missing_tooltips = []
        for name, element in important_elements:
            if hasattr(element, 'toolTip'):
                tooltip = element.toolTip()
                if not tooltip:
                    missing_tooltips.append(name)
            elif hasattr(element, 'statusTip'):
                statustip = element.statusTip()
                if not statustip:
                    missing_tooltips.append(name)
        
        # Report missing tooltips but don't fail the test if a few are missing
        if missing_tooltips:
            print(f"UI elements missing tooltips: {', '.join(missing_tooltips)}")
        
        # At least 80% of elements should have tooltips
        self.assertLessEqual(
            len(missing_tooltips), 
            len(important_elements) * 0.2,
            f"Too many UI elements ({len(missing_tooltips)}/{len(important_elements)}) missing tooltips"
        )
    
    def test_keyboard_navigation(self):
        """Test that the UI can be navigated using keyboard shortcuts"""
        # Check if there are keyboard shortcuts defined for important actions
        shortcuts_found = 0
        
        # Check menu items for shortcuts
        if hasattr(self.window, 'menuBar'):
            for menu in self.window.menuBar().findChildren(QMenu):
                for action in menu.actions():
                    if not action.shortcut().isEmpty():
                        shortcuts_found += 1
        
        # Check toolbar actions for shortcuts
        if hasattr(self.window, 'toolbar'):
            for action in self.window.toolbar.actions():
                if not action.shortcut().isEmpty():
                    shortcuts_found += 1
        
        # Report shortcut count
        print(f"Found {shortcuts_found} keyboard shortcuts in the UI")
        
        # Should have at least some shortcuts defined
        self.assertGreater(shortcuts_found, 0, "No keyboard shortcuts found in the UI")
        
        # Test tab navigation through the UI
        # Start by setting focus to the first focusable widget
        focusable_widgets = []
        for widget in self.window.findChildren(QWidget):
            if widget.focusPolicy() != Qt.NoFocus:
                focusable_widgets.append(widget)
        
        if focusable_widgets:
            first_widget = focusable_widgets[0]
            first_widget.setFocus()
            
            # Try tabbing through all widgets
            focus_chain_complete = True
            previously_focused = first_widget
            
            for _ in range(len(focusable_widgets)):
                QTest.keyClick(self.window, Qt.Key_Tab)
                QApplication.processEvents()
                
                currently_focused = QApplication.focusWidget()
                if currently_focused is None or currently_focused == previously_focused:
                    focus_chain_complete = False
                    break
                    
                previously_focused = currently_focused
            
            self.assertTrue(focus_chain_complete, "Tab navigation doesn't cycle through all focusable widgets")
    
    def test_font_scaling(self):
        """Test that the UI handles font scaling for accessibility"""
        # Store original sizes of some UI elements
        original_sizes = {}
        
        # Capture sizes of key UI elements
        if hasattr(self.window, 'device_table'):
            original_sizes['device_table'] = self.window.device_table.size()
            
        if hasattr(self.window, 'status_bar'):
            original_sizes['status_bar'] = self.window.status_bar.size()
        
        # Increase the font size by 50%
        larger_font = QFont(self.app.font())
        larger_font.setPointSize(int(larger_font.pointSize() * 1.5))
        self.app.setFont(larger_font)
        
        # Force layout update
        self.window.adjustSize()
        QApplication.processEvents()
        
        # Check if elements have resized to accommodate larger font
        for widget_name, original_size in original_sizes.items():
            widget = getattr(self.window, widget_name)
            new_size = widget.size()
            
            # Either width or height should have increased
            self.assertTrue(
                new_size.width() > original_size.width() or 
                new_size.height() > original_size.height(),
                f"{widget_name} did not resize when font size increased"
            )
    
    def test_color_contrast(self):
        """Test for sufficient color contrast in the UI for readability"""
        # This is a simplified test that checks for extreme contrast issues
        
        # Get background color of the window
        window_bg_color = self.window.palette().color(self.window.backgroundRole())
        
        # Check contrast with text colors
        text_color = self.window.palette().color(self.window.foregroundRole())
        
        # Calculate contrast ratio (simplified formula)
        # In a real test, you would use the WCAG contrast formula
        contrast_issue = False
        
        def luminance(color):
            """Calculate relative luminance of a color"""
            r = color.red() / 255
            g = color.green() / 255
            b = color.blue() / 255
            return 0.2126 * r + 0.7152 * g + 0.0722 * b
        
        def contrast_ratio(color1, color2):
            """Calculate contrast ratio between two colors"""
            l1 = luminance(color1) + 0.05
            l2 = luminance(color2) + 0.05
            return max(l1, l2) / min(l1, l2)
        
        ratio = contrast_ratio(window_bg_color, text_color)
        
        # WCAG AA requires 4.5:1 contrast ratio for normal text
        if ratio < 4.5:
            contrast_issue = True
            print(f"Warning: Contrast ratio between background and text is only {ratio:.2f}:1 (should be at least 4.5:1)")
        
        # This shouldn't fail the test, just warn
        self.assertFalse(contrast_issue, "Color contrast issues detected in the UI")


class TestUIUsability(unittest.TestCase):
    """Test usability aspects of the UI"""
    
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv) if not QApplication.instance() else QApplication.instance()
        
    def setUp(self):
        """Set up mocks and prepare the main window for testing"""
        # Create mock objects for the main components
        self.mock_scanner = Mock(spec=NetworkScanner)
        self.mock_detector = Mock(spec=ThreatDetector)
        
        # Mock device data
        self.mock_devices = []
        for i in range(10):  # Create 10 mock devices
            self.mock_devices.append({
                "ip": f"192.168.1.{i}",
                "mac": f"00:11:22:33:44:{i:02x}",
                "hostname": f"device-{i}",
                "vendor": "Test Vendor"
            })
        
        # Configure scanner mock
        self.mock_scanner.get_devices.return_value = self.mock_devices
        
        # Patch component classes
        self.scanner_patcher = patch('components.main_window.NetworkScanner', 
                                    return_value=self.mock_scanner)
        self.detector_patcher = patch('components.main_window.ThreatDetector', 
                                     return_value=self.mock_detector)
        
        # Start patchers
        self.scanner_patcher.start()
        self.detector_patcher.start()
        
        # Create the main window
        self.window = MainWindow()
        
    def tearDown(self):
        """Clean up after each test"""
        self.window.close()
        self.window.deleteLater()
        
        # Stop patchers
        self.scanner_patcher.stop()
        self.detector_patcher.stop()
        
    def test_ui_element_visibility(self):
        """Test that important UI elements are visible and properly sized"""
        min_btn_size = QSize(20, 20)  # Minimum reasonable button size
        
        # Check important UI elements
        for element_name in ['device_table', 'threat_table', 'status_bar']:
            if hasattr(self.window, element_name):
                element = getattr(self.window, element_name)
                
                # Check visibility
                self.assertTrue(element.isVisible(), f"{element_name} should be visible")
                
                # Check size is reasonable
                size = element.size()
                self.assertGreater(size.width(), 100, f"{element_name} width is too small: {size.width()}")
                self.assertGreater(size.height(), 50, f"{element_name} height is too small: {size.height()}")
        
        # Check buttons and clickable elements if they exist
        for button_name in ['scan_button', 'stop_button', 'refresh_button']:
            if hasattr(self.window, button_name):
                button = getattr(self.window, button_name)
                
                # Buttons should be visible unless disabled
                if button.isEnabled():
                    self.assertTrue(button.isVisible(), f"{button_name} should be visible")
                
                # Check button size is reasonable
                size = button.size()
                self.assertGreaterEqual(size.width(), min_btn_size.width(), 
                                     f"{button_name} width is too small: {size.width()}")
                self.assertGreaterEqual(size.height(), min_btn_size.height(), 
                                     f"{button_name} height is too small: {size.height()}")
    
    def test_user_feedback(self):
        """Test that the UI provides appropriate feedback to user actions"""
        # Load devices in the UI
        self.window.update_device_list()
        
        # Check status bar feedback
        if hasattr(self.window, 'status_bar'):
            # Status bar should have some text by default
            status_text = self.window.status_bar.currentMessage()
            self.assertTrue(status_text, "Status bar should have a default message")
            
            # Test status updates after actions
            if hasattr(self.window, 'action_scan'):
                # Clear status
                self.window.status_bar.clearMessage()
                
                # Trigger scan action
                self.window.action_scan.trigger()
                
                # Should have updated status
                new_status = self.window.status_bar.currentMessage()
                self.assertTrue(new_status, "Status bar should update after scan action")
                self.assertNotEqual(status_text, new_status, "Status should change after scan action")
        
        # Check other feedback mechanisms
        # For example, check if progress indicators work
        if hasattr(self.window, 'progress_bar'):
            # Progress bar should be initially hidden or at 0%
            self.assertTrue(
                not self.window.progress_bar.isVisible() or self.window.progress_bar.value() == 0,
                "Progress bar should be initially hidden or at 0%"
            )
            
            # Set progress to 50%
            self.window.progress_bar.setValue(50)
            
            # Should now be visible and at 50%
            self.assertTrue(self.window.progress_bar.isVisible(), "Progress bar should be visible when in use")
            self.assertEqual(self.window.progress_bar.value(), 50, "Progress bar value should be set correctly")
    
    def test_error_handling(self):
        """Test that the UI handles errors gracefully"""
        # Mock a scan error
        self.mock_scanner.start_scan.side_effect = Exception("Test error")
        
        # Try to start a scan
        if hasattr(self.window, 'action_scan'):
            # Should not crash
            try:
                self.window.action_scan.trigger()
                error_handled = True
            except Exception:
                error_handled = False
                
            self.assertTrue(error_handled, "UI should handle scan errors gracefully")
            
            # Check if error message was displayed (if there's an error label or dialog)
            # This will depend on how your application shows errors
            if hasattr(self.window, 'error_label'):
                self.assertTrue(self.window.error_label.isVisible(), "Error label should be visible after error")
            
            # Status bar should show error message
            if hasattr(self.window, 'status_bar'):
                status_text = self.window.status_bar.currentMessage()
                self.assertTrue("error" in status_text.lower(), "Status bar should indicate an error")
    
    def test_ui_state_consistency(self):
        """Test that UI state remains consistent during operations"""
        # Check initial state
        if hasattr(self.window, 'action_scan') and hasattr(self.window, 'action_stop'):
            # Scan should be enabled, stop disabled initially
            self.assertTrue(self.window.action_scan.isEnabled(), "Scan action should be enabled initially")
            self.assertFalse(self.window.action_stop.isEnabled(), "Stop action should be disabled initially")
            
            # Mock scanner to appear busy
            self.mock_scanner.is_scanning.return_value = True
            
            # Update UI state based on scanner
            if hasattr(self.window, 'update_ui_state'):
                self.window.update_ui_state()
                
                # Now scan should be disabled, stop enabled
                self.assertFalse(self.window.action_scan.isEnabled(), "Scan action should be disabled during scan")
                self.assertTrue(self.window.action_stop.isEnabled(), "Stop action should be enabled during scan")
                
            # Mock scanner to appear idle again
            self.mock_scanner.is_scanning.return_value = False
            
            # Update UI state
            if hasattr(self.window, 'update_ui_state'):
                self.window.update_ui_state()
                
                # Should return to initial state
                self.assertTrue(self.window.action_scan.isEnabled(), "Scan action should be re-enabled after scan")
                self.assertFalse(self.window.action_stop.isEnabled(), "Stop action should be disabled after scan")


if __name__ == '__main__':
    unittest.main() 