from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
    QComboBox, QGroupBox, QFormLayout, QFileDialog, QMessageBox,
    QListWidget, QListWidgetItem, QSplitter, QTextBrowser,
    QProgressBar, QRadioButton, QButtonGroup
)
from PyQt5.QtCore import Qt, pyqtSignal, QUrl
from PyQt5.QtGui import QDesktopServices

import os
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional

from app.utils.logger import get_logger
from app.utils.database import get_database
from app.utils.reports import get_report_generator

# Module logger
logger = get_logger('components.report_viewer')

class ReportViewer(QWidget):
    """Component for generating and viewing reports."""
    
    # Signals
    status_changed = pyqtSignal(str)  # Emitted when status changes
    
    def __init__(self, parent=None):
        """Initialize the report viewer component."""
        super().__init__(parent)
        
        # Get database and report generator
        self.database = get_database()
        self.report_generator = get_report_generator()
        
        # Setup UI
        self.setup_ui()
        
        # Load sessions
        self.load_sessions()
        
    def setup_ui(self):
        """Set up the user interface."""
        main_layout = QVBoxLayout(self)
        
        # Top section - Session selection and report generation
        top_layout = QHBoxLayout()
        
        # Left side - Session list
        session_group = QGroupBox("Available Sessions")
        session_layout = QVBoxLayout(session_group)
        
        self.session_list = QListWidget()
        self.session_list.setSelectionMode(QListWidget.SingleSelection)
        self.session_list.itemSelectionChanged.connect(self.handle_session_selected)
        
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.load_sessions)
        
        session_layout.addWidget(self.session_list)
        session_layout.addWidget(refresh_button)
        
        # Right side - Report generation options
        options_group = QGroupBox("Report Options")
        options_layout = QFormLayout(options_group)
        
        self.format_group = QButtonGroup(self)
        html_radio = QRadioButton("HTML")
        pdf_radio = QRadioButton("PDF")
        md_radio = QRadioButton("Markdown")
        
        self.format_group.addButton(html_radio, 1)
        self.format_group.addButton(pdf_radio, 2)
        self.format_group.addButton(md_radio, 3)
        html_radio.setChecked(True)  # Default to HTML
        
        format_layout = QHBoxLayout()
        format_layout.addWidget(html_radio)
        format_layout.addWidget(pdf_radio)
        format_layout.addWidget(md_radio)
        format_layout.addStretch()
        
        self.generate_button = QPushButton("Generate Report")
        self.generate_button.clicked.connect(self.generate_report)
        self.generate_button.setEnabled(False)
        
        options_layout.addRow("Format:", format_layout)
        options_layout.addRow(self.generate_button)
        
        # Progress bar for report generation
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.progress_bar.setVisible(False)
        options_layout.addRow(self.progress_bar)
        
        # Add to top layout
        top_layout.addWidget(session_group, 2)
        top_layout.addWidget(options_group, 1)
        
        # Bottom section - Session details and report preview
        self.details_browser = QTextBrowser()
        self.details_browser.setOpenLinks(False)
        self.details_browser.anchorClicked.connect(self.open_report)
        
        # Add to main layout
        main_layout.addLayout(top_layout)
        main_layout.addWidget(self.details_browser, 1)  # Give it stretch
        
        # Status label
        self.status_label = QLabel("Ready")
        main_layout.addWidget(self.status_label)
        
    def load_sessions(self):
        """Load capture sessions from the database."""
        try:
            # Clear list
            self.session_list.clear()
            
            # Get sessions from database
            sessions = self.database.get_capture_sessions(limit=50)
            
            for session in sessions:
                # Only show completed sessions with packets
                if session['end_time'] and session['packet_count'] > 0:
                    item_text = f"{session['start_time'].strftime('%Y-%m-%d %H:%M:%S')} - "
                    if session['description']:
                        item_text += session['description']
                    else:
                        item_text += f"{session['packet_count']} packets"
                    
                    item = QListWidgetItem(item_text)
                    item.setData(Qt.UserRole, session['id'])
                    self.session_list.addItem(item)
            
            # Update status
            self.status_label.setText(f"Loaded {self.session_list.count()} sessions")
            
        except Exception as e:
            logger.error(f"Error loading sessions: {e}")
            self.status_label.setText(f"Error: {e}")
            
    def handle_session_selected(self):
        """Handle selection of a session from the list."""
        selected_items = self.session_list.selectedItems()
        
        if not selected_items:
            self.generate_button.setEnabled(False)
            self.details_browser.setText("")
            return
            
        # Get session ID
        session_id = selected_items[0].data(Qt.UserRole)
        
        # Enable generate button
        self.generate_button.setEnabled(True)
        
        # Show session details
        try:
            session_data = self.database.get_session_summary(session_id)
            
            if not session_data:
                self.details_browser.setText("No data found for the selected session.")
                return
                
            # Format timestamps
            start_time = session_data['start_time'].strftime("%Y-%m-%d %H:%M:%S")
            end_time = "In progress"
            if session_data['end_time']:
                end_time = session_data['end_time'].strftime("%Y-%m-%d %H:%M:%S")
                
            # Format duration
            duration = f"{session_data['duration_seconds']:.1f} seconds"
            
            # Format protocol distribution
            protocol_html = "<ul>"
            for protocol, count in session_data['protocol_distribution'].items():
                percentage = (count / max(1, session_data['packet_count'])) * 100
                protocol_html += f"<li>{protocol}: {count} packets ({percentage:.1f}%)</li>"
            protocol_html += "</ul>"
            
            # Format top talkers
            talkers_html = "<ul>"
            for ip, stats in session_data['top_talkers'].items():
                total = stats['sent_packets'] + stats['recv_packets']
                talkers_html += f"<li>{ip}: {total} packets (Sent: {stats['sent_packets']}, Received: {stats['recv_packets']})</li>"
            talkers_html += "</ul>"
            
            # Check for existing reports
            reports_html = self._get_existing_reports_html(session_id)
            
            # Build HTML
            html = f"""
            <h2>Session Details</h2>
            <p><b>Session ID:</b> {session_id}</p>
            <p><b>Description:</b> {session_data.get('description', 'N/A')}</p>
            <p><b>Start Time:</b> {start_time}</p>
            <p><b>End Time:</b> {end_time}</p>
            <p><b>Duration:</b> {duration}</p>
            <p><b>Interface:</b> {session_data.get('interface', 'Default')}</p>
            <p><b>Filter:</b> {session_data.get('filter', 'None')}</p>
            <p><b>Total Packets:</b> {session_data['packet_count']}</p>
            <p><b>Total Bytes:</b> {session_data['bytes_total']} ({self._format_bytes(session_data['bytes_total'])})</p>
            
            <h3>Protocol Distribution</h3>
            {protocol_html}
            
            <h3>Top Talkers</h3>
            {talkers_html}
            
            {reports_html}
            """
            
            self.details_browser.setHtml(html)
            
        except Exception as e:
            logger.error(f"Error displaying session details: {e}")
            self.details_browser.setText(f"Error displaying session details: {str(e)}")
            
    def generate_report(self):
        """Generate a report for the selected session."""
        selected_items = self.session_list.selectedItems()
        if not selected_items:
            return
            
        # Get session ID
        session_id = selected_items[0].data(Qt.UserRole)
        
        # Get selected format
        format_id = self.format_group.checkedId()
        if format_id == 1:
            output_format = 'html'
        elif format_id == 2:
            output_format = 'pdf'
        elif format_id == 3:
            output_format = 'markdown'
        else:
            output_format = 'html'  # Default
            
        # Ask for output location
        default_ext = '.html' if output_format == 'html' else '.pdf' if output_format == 'pdf' else '.md'
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Report",
            os.path.expanduser(f"~/ARPGuard_Report_{session_id}{default_ext}"),
            f"Report Files (*{default_ext});;All Files (*)"
        )
        
        if not filename:
            return  # User cancelled
            
        # Show progress bar
        self.progress_bar.setVisible(True)
        self.generate_button.setEnabled(False)
        self.status_label.setText(f"Generating {output_format.upper()} report...")
        
        # Generate report in a separate thread
        threading.Thread(
            target=self._generate_report_thread,
            args=(session_id, output_format, filename),
            daemon=True
        ).start()
        
    def _generate_report_thread(self, session_id, output_format, output_path):
        """Background thread for report generation.
        
        Args:
            session_id: ID of the session
            output_format: Format of the report ('html', 'pdf', 'markdown')
            output_path: Path to save the report
        """
        try:
            # Generate the report
            report_path = self.report_generator.generate_session_report(
                session_id,
                output_format,
                output_path
            )
            
            # Update UI in the main thread
            self.update_status(True, f"Report generated successfully: {report_path}", report_path)
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            self.update_status(False, f"Error generating report: {str(e)}")
            
    def update_status(self, success, message, report_path=None):
        """Update the UI after report generation.
        
        Args:
            success: Whether generation was successful
            message: Status message
            report_path: Path to the generated report
        """
        # Use the signal to update UI from the main thread
        from PyQt5.QtCore import QMetaObject, Qt, Q_ARG
        
        QMetaObject.invokeMethod(
            self, 
            "_update_status_ui",
            Qt.QueuedConnection,
            Q_ARG(bool, success),
            Q_ARG(str, message),
            Q_ARG(str, report_path if report_path else "")
        )
        
    def _update_status_ui(self, success, message, report_path):
        """Update UI elements after report generation (called in main thread).
        
        Args:
            success: Whether generation was successful
            message: Status message
            report_path: Path to the generated report
        """
        # Hide progress bar
        self.progress_bar.setVisible(False)
        
        # Update status
        self.status_label.setText(message)
        
        # Re-enable generate button
        self.generate_button.setEnabled(True)
        
        # Show success/error message
        if success:
            # Ask if user wants to open the report
            reply = QMessageBox.question(
                self,
                "Report Generated",
                f"Report generated successfully.\n\nDo you want to open it now?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            
            if reply == QMessageBox.Yes and report_path:
                self.open_file(report_path)
                
            # Refresh session details to show the new report
            self.handle_session_selected()
        else:
            QMessageBox.critical(
                self,
                "Error",
                message,
                QMessageBox.Ok
            )
            
    def open_report(self, url):
        """Open a report when clicked in the details browser.
        
        Args:
            url: URL of the report (local file)
        """
        path = url.toLocalFile()
        if os.path.exists(path):
            self.open_file(path)
            
    def open_file(self, path):
        """Open a file with the default application.
        
        Args:
            path: Path to the file
        """
        try:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))
        except Exception as e:
            logger.error(f"Error opening file: {e}")
            QMessageBox.warning(
                self,
                "Error",
                f"Could not open the file: {str(e)}",
                QMessageBox.Ok
            )
            
    def _get_existing_reports_html(self, session_id):
        """Get HTML for existing reports.
        
        Args:
            session_id: ID of the session
            
        Returns:
            str: HTML with links to existing reports
        """
        # Look for report files in common locations
        home_dir = os.path.expanduser("~")
        docs_dir = os.path.join(home_dir, "Documents")
        locations = [home_dir, docs_dir]
        
        report_files = []
        
        # Search for report files
        for location in locations:
            if not os.path.exists(location):
                continue
                
            for filename in os.listdir(location):
                if f"arpguard_session_{session_id}_" in filename or f"ARPGuard_Report_{session_id}" in filename:
                    file_path = os.path.join(location, filename)
                    report_files.append((filename, file_path))
                    
        if not report_files:
            return ""
            
        # Build HTML
        html = "<h3>Existing Reports</h3><ul>"
        for filename, path in report_files:
            html += f'<li><a href="file:{path}">{filename}</a></li>'
        html += "</ul>"
        
        return html
        
    def _format_bytes(self, num_bytes):
        """Format bytes into human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if num_bytes < 1024.0:
                return f"{num_bytes:.1f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} TB" 