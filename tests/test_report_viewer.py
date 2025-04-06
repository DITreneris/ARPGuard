import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import tempfile
from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt

# Add the app directory to the Python path
sys.path.append('app')

from components.report_viewer import ReportViewer

class TestReportViewer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up the QApplication instance once for all tests"""
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        """Create a fresh ReportViewer instance for each test"""
        self.view = ReportViewer()
        
    def tearDown(self):
        """Clean up after each test"""
        self.view.close()
        self.view.deleteLater()
        
    def test_view_initialization(self):
        """Test if report viewer initializes correctly with all UI components"""
        # Check if main components are initialized
        self.assertIsNotNone(self.view)
        self.assertIsNotNone(self.view.report_list)
        self.assertIsNotNone(self.view.report_content)
        self.assertIsNotNone(self.view.export_button)
        
        # Check if the main layout is set
        self.assertIsNotNone(self.view.layout())
        
        # Check if the window title is set correctly
        self.assertEqual(self.view.windowTitle(), "Report Viewer")
        
    def test_report_loading(self):
        """Test loading reports into the viewer"""
        # Mock the load_reports method to simulate loading reports
        self.view.load_reports = Mock()
        self.view.load_reports.return_value = [
            {"name": "Network Scan Report - 2024-03-29", "path": "/reports/network_scan_20240329.html"},
            {"name": "Vulnerability Report - 2024-03-29", "path": "/reports/vulnerability_20240329.html"}
        ]
        
        # Call the method to load reports
        reports = self.view.load_reports()
        
        # Add reports to the list
        for report in reports:
            self.view.add_report_to_list(report["name"], report["path"])
            
        # Verify reports were added to the list
        self.assertEqual(self.view.report_list.count(), 2)
        self.assertEqual(self.view.report_list.item(0).text(), "Network Scan Report - 2024-03-29")
        self.assertEqual(self.view.report_list.item(1).text(), "Vulnerability Report - 2024-03-29")
        
    def test_report_selection(self):
        """Test report selection functionality"""
        # Add test reports to the list
        self.view.add_report_to_list("Test Report 1", "/reports/test1.html")
        self.view.add_report_to_list("Test Report 2", "/reports/test2.html")
        
        # Mock the display_report method
        self.view.display_report = Mock()
        
        # Connect the mocked method to the selection signal
        self.view.report_list.currentItemChanged.connect(
            lambda current, previous: self.view.display_report(current.data(Qt.UserRole))
            if current else None
        )
        
        # Select a report
        self.view.report_list.setCurrentRow(1)
        
        # Verify the display_report method was called with the correct path
        self.view.display_report.assert_called_once_with("/reports/test2.html")
        
    def test_report_export(self):
        """Test report export functionality"""
        # Create a temporary test file to simulate a report
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
            tmp.write(b"<html><body><h1>Test Report</h1></body></html>")
            tmp_path = tmp.name
            
        try:
            # Add the test report to the list
            self.view.add_report_to_list("Test Report", tmp_path)
            
            # Select the report
            self.view.report_list.setCurrentRow(0)
            
            # Mock the export_report method
            self.view.export_report = Mock()
            
            # Mock QFileDialog to avoid opening an actual dialog
            with patch('PyQt5.QtWidgets.QFileDialog.getSaveFileName') as mock_dialog:
                mock_dialog.return_value = ("/export/path/report.pdf", "PDF Files (*.pdf)")
                
                # Trigger the export button click
                self.view.export_button.click()
                
                # Verify the export_report method was called with the correct parameters
                self.view.export_report.assert_called_once_with(tmp_path, "/export/path/report.pdf")
        finally:
            # Clean up the temporary file
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    def test_html_rendering(self):
        """Test HTML content rendering in the viewer"""
        # Create a simple HTML content
        html_content = "<html><body><h1>Test Report</h1><p>This is a test report content.</p></body></html>"
        
        # Mock the load_html_content method
        self.view.load_html_content = Mock()
        
        # Call the method with the test content
        self.view.load_html_content(html_content)
        
        # Verify the method was called with the correct content
        self.view.load_html_content.assert_called_once_with(html_content)

if __name__ == '__main__':
    unittest.main() 