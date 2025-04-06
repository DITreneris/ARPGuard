from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QMessageBox
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QBrush

from datetime import datetime

from app.utils.database import get_database
from app.utils.logger import get_logger

# Module logger
logger = get_logger('components.session_history')

class SessionHistoryView(QWidget):
    """Component for viewing packet capture session history."""
    
    # Signals
    session_selected = pyqtSignal(int)  # Emitted when a session is selected (session_id)
    
    def __init__(self, parent=None):
        """Initialize session history view."""
        super().__init__(parent)
        
        # Database connection
        self.database = get_database()
        
        # Setup UI
        self.setup_ui()
        
        # Load sessions
        self.refresh_sessions()
        
    def setup_ui(self):
        """Set up the user interface."""
        main_layout = QVBoxLayout(self)
        
        # Header with title and controls
        header_layout = QHBoxLayout()
        
        title_label = QLabel("Capture History")
        title_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_sessions)
        
        self.delete_button = QPushButton("Delete")
        self.delete_button.setEnabled(False)
        self.delete_button.clicked.connect(self.delete_selected_session)
        
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(self.refresh_button)
        header_layout.addWidget(self.delete_button)
        
        # Session table
        self.session_table = QTableWidget(0, 5)
        self.session_table.setHorizontalHeaderLabels([
            "Start Time", "Duration", "Packets", "Size", "Description"
        ])
        
        # Connect signals
        self.session_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.session_table.setSelectionMode(QTableWidget.SingleSelection)
        self.session_table.itemSelectionChanged.connect(self.handle_selection_changed)
        self.session_table.itemDoubleClicked.connect(self.handle_session_double_clicked)
        
        # Add to layout
        main_layout.addLayout(header_layout)
        main_layout.addWidget(self.session_table)
        
        # Status label
        self.status_label = QLabel("Ready")
        main_layout.addWidget(self.status_label)
        
    def refresh_sessions(self):
        """Refresh the session list from the database."""
        try:
            # Get sessions from database
            sessions = self.database.get_capture_sessions()
            
            # Update table
            self.session_table.setRowCount(0)
            
            for session in sessions:
                row = self.session_table.rowCount()
                self.session_table.insertRow(row)
                
                # Start time
                start_time = session['start_time'].strftime("%Y-%m-%d %H:%M:%S")
                time_item = QTableWidgetItem(start_time)
                time_item.setData(Qt.UserRole, session['id'])  # Store session ID
                self.session_table.setItem(row, 0, time_item)
                
                # Duration
                if session['end_time'] and session['start_time']:
                    duration = session['end_time'] - session['start_time']
                    duration_text = f"{duration.total_seconds():.1f} sec"
                else:
                    duration_text = "In progress"
                self.session_table.setItem(row, 1, QTableWidgetItem(duration_text))
                
                # Packet count
                packet_count = session['packet_count'] or 0
                self.session_table.setItem(row, 2, QTableWidgetItem(str(packet_count)))
                
                # Size
                bytes_total = session['bytes_total'] or 0
                size_text = self._format_bytes(bytes_total)
                self.session_table.setItem(row, 3, QTableWidgetItem(size_text))
                
                # Description
                description = session['description'] or ""
                self.session_table.setItem(row, 4, QTableWidgetItem(description))
            
            # Update status
            self.status_label.setText(f"Loaded {len(sessions)} sessions")
            
        except Exception as e:
            logger.error(f"Error refreshing sessions: {e}")
            self.status_label.setText(f"Error: {e}")
    
    def handle_selection_changed(self):
        """Handle selection changes in the session table."""
        selected = len(self.session_table.selectedItems()) > 0
        self.delete_button.setEnabled(selected)
        
        if selected:
            # Emit signal with selected session ID
            session_id = self._get_selected_session_id()
            if session_id:
                self.session_selected.emit(session_id)
    
    def handle_session_double_clicked(self, item):
        """Handle double-click on a session."""
        session_id = self._get_selected_session_id()
        if session_id:
            self.session_selected.emit(session_id)
    
    def delete_selected_session(self):
        """Delete the selected capture session."""
        session_id = self._get_selected_session_id()
        if not session_id:
            return
            
        # Confirm deletion
        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            "Are you sure you want to delete this capture session?\nThis action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
            
        try:
            # Delete from database
            success = self.database.delete_session(session_id)
            
            if success:
                # Remove from table
                selected_row = self.session_table.currentRow()
                self.session_table.removeRow(selected_row)
                self.status_label.setText(f"Deleted session {session_id}")
            else:
                self.status_label.setText(f"Failed to delete session {session_id}")
                
        except Exception as e:
            logger.error(f"Error deleting session: {e}")
            self.status_label.setText(f"Error: {e}")
    
    def _get_selected_session_id(self):
        """Get the ID of the selected session."""
        selected_items = self.session_table.selectedItems()
        if not selected_items:
            return None
            
        # Get the first column item (Start Time) which has the session ID
        time_item = self.session_table.item(selected_items[0].row(), 0)
        if time_item:
            return time_item.data(Qt.UserRole)
        
        return None
    
    def _format_bytes(self, num_bytes):
        """Format bytes into human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if num_bytes < 1024.0:
                return f"{num_bytes:.1f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} TB" 