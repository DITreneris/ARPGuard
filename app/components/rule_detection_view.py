"""
Rule-based detection view component for ARPGuard.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QLabel, QPushButton, QHeaderView, QSplitter, QTabWidget, QGroupBox,
    QCheckBox, QComboBox, QFormLayout, QTextEdit, QAction, QMenu
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QIcon

from app.utils.logger import get_logger
from app.utils.config import get_config

# Module logger
logger = get_logger('components.rule_detection_view')

class RuleDetectionView(QWidget):
    """UI component for displaying rule-based detection results."""
    
    rule_toggled = pyqtSignal(str, bool)  # rule_id, enabled
    
    def __init__(self, ml_controller=None, parent=None):
        """Initialize the rule detection view.
        
        Args:
            ml_controller: ML controller instance
            parent: Parent widget
        """
        super().__init__(parent)
        self.ml_controller = ml_controller
        self.config = get_config()
        
        # Cache of rule IDs to row indices
        self.rule_rows = {}
        
        # Set up UI
        self._setup_ui()
        
        # Setup refresh timer for stats
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self._update_stats)
        self.refresh_timer.start(2000)  # Update every 2 seconds
        
    def _setup_ui(self):
        """Set up the UI components."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(5, 5, 5, 5)
        
        # Stats section
        stats_group = QGroupBox("Detection Statistics")
        stats_layout = QHBoxLayout(stats_group)
        
        self.packets_analyzed_label = QLabel("Packets Analyzed: 0")
        self.threats_detected_label = QLabel("Threats Detected: 0")
        self.rules_active_label = QLabel("Active Rules: 0")
        
        stats_layout.addWidget(self.packets_analyzed_label)
        stats_layout.addWidget(self.threats_detected_label)
        stats_layout.addWidget(self.rules_active_label)
        
        main_layout.addWidget(stats_group)
        
        # Create tab widget
        tab_widget = QTabWidget(self)
        
        # Rules tab
        rules_tab = QWidget()
        rules_layout = QVBoxLayout(rules_tab)
        
        # Rules table
        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(5)
        self.rules_table.setHorizontalHeaderLabels([
            "Rule ID", "Description", "Severity", "Hits", "Status"
        ])
        self.rules_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.rules_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.rules_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.rules_table.setSelectionMode(QTableWidget.SingleSelection)
        self.rules_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.rules_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.rules_table.customContextMenuRequested.connect(self._show_rules_context_menu)
        
        rules_layout.addWidget(self.rules_table)
        
        # Detections tab
        detections_tab = QWidget()
        detections_layout = QVBoxLayout(detections_tab)
        
        # Detections table
        self.detections_table = QTableWidget()
        self.detections_table.setColumnCount(5)
        self.detections_table.setHorizontalHeaderLabels([
            "Time", "Rule ID", "Severity", "Confidence", "Description"
        ])
        self.detections_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.detections_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.detections_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.detections_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.detections_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.detections_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.detections_table.setSelectionMode(QTableWidget.SingleSelection)
        self.detections_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.detections_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.detections_table.customContextMenuRequested.connect(self._show_detections_context_menu)
        self.detections_table.doubleClicked.connect(self._show_detection_details)
        
        # Button for clearing detections
        clear_button = QPushButton("Clear Detections")
        clear_button.clicked.connect(self._clear_detections)
        
        detections_layout.addWidget(self.detections_table)
        detections_layout.addWidget(clear_button)
        
        # Add tabs to the tab widget
        tab_widget.addTab(rules_tab, "Rules")
        tab_widget.addTab(detections_tab, "Detections")
        
        main_layout.addWidget(tab_widget)
        
        # Set initial UI state
        self._populate_rules_table()
        self._update_stats()
        
    def _populate_rules_table(self):
        """Populate the rules table with current rule information."""
        if not self.ml_controller:
            return
            
        # Clear existing rows
        self.rules_table.setRowCount(0)
        
        # Get rule information
        rules = self.ml_controller.rule_engine.rules
        rule_hits = self.ml_controller.stats.get("rule_hits", {})
        
        # Add rows for each rule
        self.rules_table.setRowCount(len(rules))
        for i, (rule_id, rule) in enumerate(rules.items()):
            # Rule ID
            self.rules_table.setItem(i, 0, QTableWidgetItem(rule_id))
            
            # Description
            self.rules_table.setItem(i, 1, QTableWidgetItem(rule.description))
            
            # Severity
            severity_item = QTableWidgetItem(rule.severity)
            # Color code by severity
            if rule.severity == "CRITICAL":
                severity_item.setBackground(QColor(255, 0, 0, 50))  # Light red
            elif rule.severity == "HIGH":
                severity_item.setBackground(QColor(255, 165, 0, 50))  # Light orange
            elif rule.severity == "MEDIUM":
                severity_item.setBackground(QColor(255, 255, 0, 50))  # Light yellow
            self.rules_table.setItem(i, 2, severity_item)
            
            # Hits
            hits = rule_hits.get(rule_id, 0)
            self.rules_table.setItem(i, 3, QTableWidgetItem(str(hits)))
            
            # Status
            status_checkbox = QCheckBox()
            status_checkbox.setChecked(True)  # Enabled by default
            status_checkbox.stateChanged.connect(
                lambda state, rule_id=rule_id: self._toggle_rule(rule_id, state == Qt.Checked)
            )
            self.rules_table.setCellWidget(i, 4, status_checkbox)
            
            # Store mapping for quick lookup
            self.rule_rows[rule_id] = i
    
    def _update_stats(self):
        """Update the detection statistics."""
        if not self.ml_controller:
            return
            
        # Get statistics
        stats = self.ml_controller.get_statistics()
        
        # Update labels
        self.packets_analyzed_label.setText(f"Packets Analyzed: {stats['packets_analyzed']}")
        self.threats_detected_label.setText(f"Threats Detected: {stats['threats_detected']}")
        self.rules_active_label.setText(f"Active Rules: {stats['rules_active']}")
        
        # Update hit counts in the rules table
        for rule_id, hits in stats.get("rule_hits", {}).items():
            if rule_id in self.rule_rows:
                row = self.rule_rows[rule_id]
                self.rules_table.item(row, 3).setText(str(hits))
                
        # Update detections table
        self._update_detections()
        
    def _update_detections(self):
        """Update the detections table with recent detections."""
        if not self.ml_controller:
            return
            
        # Get recent detections
        detections = self.ml_controller.get_recent_detections()
        
        # Remember the previous row count
        previous_count = self.detections_table.rowCount()
        
        # Update table if there are new detections
        if len(detections) > previous_count:
            # Set the row count
            self.detections_table.setRowCount(len(detections))
            
            # Add new rows only
            for i in range(previous_count, len(detections)):
                detection = detections[i]
                
                # Skip non-rule-based detections
                if detection.get("type") != "rule_based":
                    continue
                    
                # Timestamp
                time_str = detection["timestamp"].strftime("%H:%M:%S")
                self.detections_table.setItem(i, 0, QTableWidgetItem(time_str))
                
                # Rule ID
                self.detections_table.setItem(i, 1, QTableWidgetItem(detection["rule_id"]))
                
                # Severity
                severity_item = QTableWidgetItem(detection["severity"])
                # Color code by severity
                if detection["severity"] == "CRITICAL":
                    severity_item.setBackground(QColor(255, 0, 0, 50))  # Light red
                elif detection["severity"] == "HIGH":
                    severity_item.setBackground(QColor(255, 165, 0, 50))  # Light orange
                elif detection["severity"] == "MEDIUM":
                    severity_item.setBackground(QColor(255, 255, 0, 50))  # Light yellow
                self.detections_table.setItem(i, 2, severity_item)
                
                # Confidence
                confidence_str = f"{detection['confidence']:.2f}"
                self.detections_table.setItem(i, 3, QTableWidgetItem(confidence_str))
                
                # Description
                self.detections_table.setItem(i, 4, QTableWidgetItem(detection["description"]))
                
            # Scroll to the bottom to show newest detections
            self.detections_table.scrollToBottom()
            
    def _toggle_rule(self, rule_id: str, enabled: bool):
        """Toggle a rule's enabled state.
        
        Args:
            rule_id: ID of the rule
            enabled: Whether the rule is enabled
        """
        logger.info(f"Toggle rule {rule_id}: {'enabled' if enabled else 'disabled'}")
        self.rule_toggled.emit(rule_id, enabled)
        
    def _show_rules_context_menu(self, position):
        """Show context menu for rules table.
        
        Args:
            position: Position where the context menu should appear
        """
        if not self.rules_table.selectedItems():
            return
            
        menu = QMenu()
        
        # Get the selected row
        row = self.rules_table.selectedItems()[0].row()
        rule_id = self.rules_table.item(row, 0).text()
        
        # Actions
        enable_action = QAction("Enable Rule", self)
        enable_action.triggered.connect(lambda: self._toggle_rule(rule_id, True))
        
        disable_action = QAction("Disable Rule", self)
        disable_action.triggered.connect(lambda: self._toggle_rule(rule_id, False))
        
        # Add actions to menu
        menu.addAction(enable_action)
        menu.addAction(disable_action)
        
        # Show the menu
        menu.exec_(self.rules_table.viewport().mapToGlobal(position))
        
    def _show_detections_context_menu(self, position):
        """Show context menu for detections table.
        
        Args:
            position: Position where the context menu should appear
        """
        if not self.detections_table.selectedItems():
            return
            
        menu = QMenu()
        
        # Actions
        details_action = QAction("View Details", self)
        details_action.triggered.connect(self._show_detection_details)
        
        # Add actions to menu
        menu.addAction(details_action)
        
        # Show the menu
        menu.exec_(self.detections_table.viewport().mapToGlobal(position))
        
    def _show_detection_details(self):
        """Show details for the selected detection."""
        if not self.detections_table.selectedItems():
            return
            
        # Get the selected row
        row = self.detections_table.selectedItems()[0].row()
        
        # Get the detection data
        detections = self.ml_controller.get_recent_detections()
        if row < len(detections):
            detection = detections[row]
            
            # Create dialog
            from PyQt5.QtWidgets import QDialog, QVBoxLayout, QDialogButtonBox
            
            dialog = QDialog(self)
            dialog.setWindowTitle("Detection Details")
            dialog.setMinimumSize(600, 400)
            
            layout = QVBoxLayout(dialog)
            
            # Text display
            text_display = QTextEdit()
            text_display.setReadOnly(True)
            
            # Format the detection data
            details = f"<h2>Detection Details</h2>"
            details += f"<p><b>Type:</b> {detection['type']}</p>"
            details += f"<p><b>Rule ID:</b> {detection['rule_id']}</p>"
            details += f"<p><b>Description:</b> {detection['description']}</p>"
            details += f"<p><b>Severity:</b> {detection['severity']}</p>"
            details += f"<p><b>Confidence:</b> {detection['confidence']:.2f}</p>"
            details += f"<p><b>Timestamp:</b> {detection['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}</p>"
            
            # Evidence details
            details += f"<h3>Evidence</h3>"
            details += "<ul>"
            for key, value in detection['evidence'].items():
                details += f"<li><b>{key}:</b> {value}</li>"
            details += "</ul>"
            
            text_display.setHtml(details)
            layout.addWidget(text_display)
            
            # Buttons
            buttons = QDialogButtonBox(QDialogButtonBox.Ok)
            buttons.accepted.connect(dialog.accept)
            layout.addWidget(buttons)
            
            dialog.exec_()
            
    def _clear_detections(self):
        """Clear all detections from the table."""
        self.detections_table.setRowCount(0)
        if self.ml_controller:
            with self.ml_controller.detection_lock:
                self.ml_controller.detection_results = []
                
    def set_ml_controller(self, ml_controller):
        """Set the ML controller for this view.
        
        Args:
            ml_controller: ML controller instance
        """
        self.ml_controller = ml_controller
        self._populate_rules_table()
        self._update_stats() 