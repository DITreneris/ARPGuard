from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QGroupBox, QFormLayout, QTextEdit, QComboBox, QTabWidget,
    QMessageBox, QListWidget, QListWidgetItem, QCheckBox,
    QProgressBar, QLineEdit, QSpinBox
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QColor, QBrush, QFont, QIcon

import threading
from datetime import datetime
from typing import Dict, List, Any, Optional

from app.utils.logger import get_logger
from app.components.threat_intelligence import get_threat_intelligence

# Module logger
logger = get_logger('components.threat_intelligence_view')

class ThreatIntelligenceView(QWidget):
    """UI component for cloud-based threat intelligence integration."""
    
    # Signals
    status_changed = pyqtSignal(str)  # Emitted when status changes
    data_updated = pyqtSignal(dict)   # Emitted when threat data is updated
    
    def __init__(self, parent=None):
        """Initialize the threat intelligence view component."""
        super().__init__(parent)
        
        # Get threat intelligence backend
        self.threat_intel = get_threat_intelligence()
        
        # Setup UI
        self.setup_ui()
        
        # Start automatic updates if backends permits
        self.auto_update = False
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.check_for_updates)
        
        # Check if we should enable auto-updates
        if not self.threat_intel.is_running():
            self.auto_update = True
            self.update_timer.start(5000)  # Check every 5 seconds
    
    def setup_ui(self):
        """Set up the user interface."""
        main_layout = QVBoxLayout(self)
        
        # Header controls
        header_layout = QHBoxLayout()
        
        # Update button
        self.update_button = QPushButton("Update Intelligence Data")
        self.update_button.clicked.connect(self.update_threat_data)
        
        # Status indicators
        self.status_label = QLabel("Status: Not initialized")
        self.last_update_label = QLabel("Last update: Never")
        
        # Add to header layout
        header_layout.addWidget(self.update_button)
        header_layout.addStretch()
        header_layout.addWidget(self.status_label)
        header_layout.addWidget(self.last_update_label)
        
        # Main content - tabs
        self.tabs = QTabWidget()
        
        # Malicious IPs tab
        self.ip_tab = QWidget()
        ip_layout = QVBoxLayout(self.ip_tab)
        
        # IP filtering controls
        ip_filter_layout = QHBoxLayout()
        ip_filter_layout.addWidget(QLabel("Minimum score:"))
        self.ip_score_filter = QSpinBox()
        self.ip_score_filter.setRange(0, 100)
        self.ip_score_filter.setValue(75)  # Default threshold
        self.ip_score_filter.valueChanged.connect(self.filter_malicious_ips)
        ip_filter_layout.addWidget(self.ip_score_filter)
        
        ip_filter_layout.addWidget(QLabel("Category:"))
        self.ip_category_filter = QComboBox()
        self.ip_category_filter.addItem("All categories", "all")
        self.ip_category_filter.currentIndexChanged.connect(self.filter_malicious_ips)
        ip_filter_layout.addWidget(self.ip_category_filter)
        
        ip_filter_layout.addStretch()
        
        # IP search
        ip_filter_layout.addWidget(QLabel("Search IP:"))
        self.ip_search = QLineEdit()
        self.ip_search.setPlaceholderText("IP address...")
        self.ip_search.textChanged.connect(self.filter_malicious_ips)
        ip_filter_layout.addWidget(self.ip_search)
        
        ip_layout.addLayout(ip_filter_layout)
        
        # IP table
        self.ip_table = QTableWidget(0, 4)
        self.ip_table.setHorizontalHeaderLabels(["IP Address", "Score", "Categories", "Source"])
        self.ip_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.ip_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.ip_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.ip_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.ip_table.setAlternatingRowColors(True)
        self.ip_table.setEditTriggers(QTableWidget.NoEditTriggers)
        ip_layout.addWidget(self.ip_table)
        
        # Malicious Domains tab
        self.domains_tab = QWidget()
        domains_layout = QVBoxLayout(self.domains_tab)
        
        # Domain filtering controls
        domain_filter_layout = QHBoxLayout()
        domain_filter_layout.addWidget(QLabel("Minimum score:"))
        self.domain_score_filter = QSpinBox()
        self.domain_score_filter.setRange(0, 100)
        self.domain_score_filter.setValue(75)  # Default threshold
        self.domain_score_filter.valueChanged.connect(self.filter_malicious_domains)
        domain_filter_layout.addWidget(self.domain_score_filter)
        
        domain_filter_layout.addWidget(QLabel("Category:"))
        self.domain_category_filter = QComboBox()
        self.domain_category_filter.addItem("All categories", "all")
        self.domain_category_filter.currentIndexChanged.connect(self.filter_malicious_domains)
        domain_filter_layout.addWidget(self.domain_category_filter)
        
        domain_filter_layout.addStretch()
        
        # Domain search
        domain_filter_layout.addWidget(QLabel("Search domain:"))
        self.domain_search = QLineEdit()
        self.domain_search.setPlaceholderText("Domain name...")
        self.domain_search.textChanged.connect(self.filter_malicious_domains)
        domain_filter_layout.addWidget(self.domain_search)
        
        domains_layout.addLayout(domain_filter_layout)
        
        # Domain table
        self.domain_table = QTableWidget(0, 4)
        self.domain_table.setHorizontalHeaderLabels(["Domain", "Score", "Categories", "Source"])
        self.domain_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.domain_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.domain_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.domain_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.domain_table.setAlternatingRowColors(True)
        self.domain_table.setEditTriggers(QTableWidget.NoEditTriggers)
        domains_layout.addWidget(self.domain_table)
        
        # Attack Signatures tab
        self.signatures_tab = QWidget()
        signatures_layout = QVBoxLayout(self.signatures_tab)
        
        # Signature filtering controls
        sig_filter_layout = QHBoxLayout()
        sig_filter_layout.addWidget(QLabel("Severity:"))
        self.sig_severity_filter = QComboBox()
        self.sig_severity_filter.addItem("All severities", "all")
        self.sig_severity_filter.addItem("Critical", "critical")
        self.sig_severity_filter.addItem("High", "high")
        self.sig_severity_filter.addItem("Medium", "medium")
        self.sig_severity_filter.addItem("Low", "low")
        self.sig_severity_filter.currentIndexChanged.connect(self.filter_attack_signatures)
        sig_filter_layout.addWidget(self.sig_severity_filter)
        
        sig_filter_layout.addWidget(QLabel("Source:"))
        self.sig_source_filter = QComboBox()
        self.sig_source_filter.addItem("All sources", "all")
        self.sig_source_filter.currentIndexChanged.connect(self.filter_attack_signatures)
        sig_filter_layout.addWidget(self.sig_source_filter)
        
        sig_filter_layout.addStretch()
        
        # Signature search
        sig_filter_layout.addWidget(QLabel("Search:"))
        self.sig_search = QLineEdit()
        self.sig_search.setPlaceholderText("Search signatures...")
        self.sig_search.textChanged.connect(self.filter_attack_signatures)
        sig_filter_layout.addWidget(self.sig_search)
        
        signatures_layout.addLayout(sig_filter_layout)
        
        # Signature table
        self.signature_table = QTableWidget(0, 4)
        self.signature_table.setHorizontalHeaderLabels(["ID", "Description", "Severity", "Source"])
        self.signature_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.signature_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.signature_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.signature_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.signature_table.setAlternatingRowColors(True)
        self.signature_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.signature_table.itemSelectionChanged.connect(self.show_signature_details)
        signatures_layout.addWidget(self.signature_table)
        
        # Signature details section
        signature_details_group = QGroupBox("Signature Details")
        signature_details_layout = QVBoxLayout(signature_details_group)
        
        self.signature_details_text = QTextEdit()
        self.signature_details_text.setReadOnly(True)
        signature_details_layout.addWidget(self.signature_details_text)
        
        signatures_layout.addWidget(signature_details_group)
        signatures_layout.setStretch(0, 0)  # Filter layout
        signatures_layout.setStretch(1, 3)  # Table
        signatures_layout.setStretch(2, 1)  # Details
        
        # Add tabs
        self.tabs.addTab(self.ip_tab, "Malicious IPs")
        self.tabs.addTab(self.domains_tab, "Malicious Domains")
        self.tabs.addTab(self.signatures_tab, "Attack Signatures")
        
        # Progress bar for updates
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        
        # Add all components to main layout
        main_layout.addLayout(header_layout)
        main_layout.addWidget(self.tabs)
        main_layout.addWidget(self.progress_bar)
        
        # Initial data load
        self.refresh_display()
    
    def update_threat_data(self):
        """Update threat intelligence data from cloud sources."""
        # Disable update button during update
        self.update_button.setEnabled(False)
        self.status_label.setText("Status: Updating...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(10)
        
        # Run update in a thread to avoid blocking UI
        def update_thread():
            success, message, details = self.threat_intel.update_all()
            
            # Use thread-safe emit to update the UI
            from PyQt5.QtCore import QMetaObject, Qt, Q_ARG
            QMetaObject.invokeMethod(
                self,
                "_update_complete",
                Qt.QueuedConnection,
                Q_ARG(bool, success),
                Q_ARG(str, message),
                Q_ARG(object, details)
            )
        
        threading.Thread(target=update_thread).start()
    
    def _update_complete(self, success, message, details):
        """Handle completion of a threat data update (called in main thread)."""
        # Re-enable update button
        self.update_button.setEnabled(True)
        self.progress_bar.setValue(100)
        
        if success:
            self.status_label.setText(f"Status: {message}")
            self.refresh_display()
            
            # Notify other components
            self.data_updated.emit(details)
            self.status_changed.emit(message)
            
            # Update last update time
            last_update = self.threat_intel.get_last_update_time()
            if last_update:
                self.last_update_label.setText(f"Last update: {last_update.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            self.status_label.setText(f"Status: Update failed - {message}")
            QMessageBox.warning(self, "Update Failed", message)
        
        # Hide progress bar after a short delay
        QTimer.singleShot(1000, lambda: self.progress_bar.setVisible(False))
    
    def check_for_updates(self):
        """Check if updates are now running and update UI accordingly."""
        if self.auto_update and self.threat_intel.is_running():
            # Updates are now running, update UI
            self.auto_update = False
            self.update_timer.stop()
            self.update_button.setEnabled(False)
            self.status_label.setText("Status: Auto-updates enabled")
        
        # Also check for any data updates
        last_update = self.threat_intel.get_last_update_time()
        if last_update:
            self.last_update_label.setText(f"Last update: {last_update.strftime('%Y-%m-%d %H:%M:%S')}")
            # Refresh display if we haven't displayed any data yet
            if self.ip_table.rowCount() == 0 and self.domain_table.rowCount() == 0:
                self.refresh_display()
    
    def refresh_display(self):
        """Refresh the display with current threat intelligence data."""
        # Update IP data
        self.update_ip_table()
        
        # Update Domain data
        self.update_domain_table()
        
        # Update Signature data
        self.update_signature_table()
        
        # Update filter dropdowns with new categories
        self.update_filter_options()
    
    def update_ip_table(self):
        """Update the IP table with current data."""
        # Get filter values
        min_score = self.ip_score_filter.value()
        category = self.ip_category_filter.currentData()
        search_text = self.ip_search.text().strip().lower()
        
        # Get data from backend
        malicious_ips = self.threat_intel.get_all_malicious_ips(min_score)
        
        # Clear existing data
        self.ip_table.setRowCount(0)
        
        # Populate table
        row = 0
        for ip, details in malicious_ips.items():
            # Apply category filter if not "all"
            if category != "all" and category not in details.get('categories', []):
                continue
                
            # Apply search filter
            if search_text and search_text not in ip.lower():
                continue
                
            # Add row
            self.ip_table.insertRow(row)
            
            # IP address
            ip_item = QTableWidgetItem(ip)
            self.ip_table.setItem(row, 0, ip_item)
            
            # Score
            score_item = QTableWidgetItem(str(details.get('score', 0)))
            score_value = details.get('score', 0)
            if score_value >= 90:
                score_item.setBackground(QBrush(QColor(255, 200, 200)))  # Red for high scores
            elif score_value >= 70:
                score_item.setBackground(QBrush(QColor(255, 230, 200)))  # Orange for medium scores
            self.ip_table.setItem(row, 1, score_item)
            
            # Categories
            categories = details.get('categories', [])
            categories_item = QTableWidgetItem(", ".join(categories))
            self.ip_table.setItem(row, 2, categories_item)
            
            # Source
            source_item = QTableWidgetItem(details.get('source', 'unknown'))
            self.ip_table.setItem(row, 3, source_item)
            
            row += 1
            
        # Update row count label
        if row == 0:
            self.ip_table.setRowCount(1)
            no_data_item = QTableWidgetItem("No malicious IPs found matching filters")
            self.ip_table.setItem(0, 0, no_data_item)
            self.ip_table.setSpan(0, 0, 1, 4)
            
    def update_domain_table(self):
        """Update the domain table with current data."""
        # Get filter values
        min_score = self.domain_score_filter.value()
        category = self.domain_category_filter.currentData()
        search_text = self.domain_search.text().strip().lower()
        
        # Get data from backend
        malicious_domains = self.threat_intel.get_all_malicious_domains(min_score)
        
        # Clear existing data
        self.domain_table.setRowCount(0)
        
        # Populate table
        row = 0
        for domain, details in malicious_domains.items():
            # Apply category filter if not "all"
            if category != "all" and category not in details.get('categories', []):
                continue
                
            # Apply search filter
            if search_text and search_text not in domain.lower():
                continue
                
            # Add row
            self.domain_table.insertRow(row)
            
            # Domain
            domain_item = QTableWidgetItem(domain)
            self.domain_table.setItem(row, 0, domain_item)
            
            # Score
            score_item = QTableWidgetItem(str(details.get('score', 0)))
            score_value = details.get('score', 0)
            if score_value >= 90:
                score_item.setBackground(QBrush(QColor(255, 200, 200)))  # Red for high scores
            elif score_value >= 70:
                score_item.setBackground(QBrush(QColor(255, 230, 200)))  # Orange for medium scores
            self.domain_table.setItem(row, 1, score_item)
            
            # Categories
            categories = details.get('categories', [])
            categories_item = QTableWidgetItem(", ".join(categories))
            self.domain_table.setItem(row, 2, categories_item)
            
            # Source
            source_item = QTableWidgetItem(details.get('source', 'unknown'))
            self.domain_table.setItem(row, 3, source_item)
            
            row += 1
            
        # Update row count label
        if row == 0:
            self.domain_table.setRowCount(1)
            no_data_item = QTableWidgetItem("No malicious domains found matching filters")
            self.domain_table.setItem(0, 0, no_data_item)
            self.domain_table.setSpan(0, 0, 1, 4)
    
    def update_signature_table(self):
        """Update the signature table with current data."""
        # Get filter values
        severity = self.sig_severity_filter.currentData()
        source = self.sig_source_filter.currentData()
        search_text = self.sig_search.text().strip().lower()
        
        # Get data from backend
        signatures = self.threat_intel.get_attack_signatures()
        
        # Clear existing data
        self.signature_table.setRowCount(0)
        
        # Populate table
        row = 0
        for sig_id, details in signatures.items():
            # Apply severity filter if not "all"
            if severity != "all" and details.get('severity', '') != severity:
                continue
                
            # Apply source filter if not "all"
            if source != "all" and details.get('source', '') != source:
                continue
                
            # Apply search filter
            description = details.get('description', '').lower()
            if search_text and search_text not in sig_id.lower() and search_text not in description:
                continue
                
            # Add row
            self.signature_table.insertRow(row)
            
            # ID
            id_item = QTableWidgetItem(sig_id)
            self.signature_table.setItem(row, 0, id_item)
            
            # Description
            desc_item = QTableWidgetItem(details.get('description', ''))
            self.signature_table.setItem(row, 1, desc_item)
            
            # Severity
            severity_value = details.get('severity', 'medium')
            severity_item = QTableWidgetItem(severity_value)
            if severity_value == 'critical':
                severity_item.setBackground(QBrush(QColor(255, 150, 150)))  # Bright red
            elif severity_value == 'high':
                severity_item.setBackground(QBrush(QColor(255, 200, 200)))  # Red
            elif severity_value == 'medium':
                severity_item.setBackground(QBrush(QColor(255, 230, 200)))  # Orange
            self.signature_table.setItem(row, 2, severity_item)
            
            # Source
            source_item = QTableWidgetItem(details.get('source', 'unknown'))
            self.signature_table.setItem(row, 3, source_item)
            
            row += 1
            
        # Update row count label
        if row == 0:
            self.signature_table.setRowCount(1)
            no_data_item = QTableWidgetItem("No attack signatures found matching filters")
            self.signature_table.setItem(0, 0, no_data_item)
            self.signature_table.setSpan(0, 0, 1, 4)
    
    def update_filter_options(self):
        """Update filter comboboxes with available options from data."""
        # Get current selections
        current_ip_category = self.ip_category_filter.currentData()
        current_domain_category = self.domain_category_filter.currentData()
        current_sig_source = self.sig_source_filter.currentData()
        
        # Extract unique categories and sources
        ip_categories = set()
        domain_categories = set()
        sig_sources = set()
        
        # Get from IPs
        for details in self.threat_intel.malicious_ips.values():
            for category in details.get('categories', []):
                ip_categories.add(category)
        
        # Get from domains
        for details in self.threat_intel.malicious_domains.values():
            for category in details.get('categories', []):
                domain_categories.add(category)
        
        # Get from signatures
        for details in self.threat_intel.attack_signatures.values():
            source = details.get('source', '')
            if source:
                sig_sources.add(source)
        
        # Update IP category filter
        self.ip_category_filter.clear()
        self.ip_category_filter.addItem("All categories", "all")
        for category in sorted(ip_categories):
            self.ip_category_filter.addItem(category, category)
        
        # Try to restore previous selection
        index = self.ip_category_filter.findData(current_ip_category)
        if index >= 0:
            self.ip_category_filter.setCurrentIndex(index)
        
        # Update domain category filter
        self.domain_category_filter.clear()
        self.domain_category_filter.addItem("All categories", "all")
        for category in sorted(domain_categories):
            self.domain_category_filter.addItem(category, category)
        
        # Try to restore previous selection
        index = self.domain_category_filter.findData(current_domain_category)
        if index >= 0:
            self.domain_category_filter.setCurrentIndex(index)
        
        # Update signature source filter
        self.sig_source_filter.clear()
        self.sig_source_filter.addItem("All sources", "all")
        for source in sorted(sig_sources):
            self.sig_source_filter.addItem(source, source)
        
        # Try to restore previous selection
        index = self.sig_source_filter.findData(current_sig_source)
        if index >= 0:
            self.sig_source_filter.setCurrentIndex(index)
    
    def filter_malicious_ips(self):
        """Apply filters to the malicious IPs table."""
        self.update_ip_table()
    
    def filter_malicious_domains(self):
        """Apply filters to the malicious domains table."""
        self.update_domain_table()
    
    def filter_attack_signatures(self):
        """Apply filters to the attack signatures table."""
        self.update_signature_table()
    
    def show_signature_details(self):
        """Show details for the selected signature."""
        selected_items = self.signature_table.selectedItems()
        if not selected_items:
            self.signature_details_text.clear()
            return
        
        # Get the signature ID from first column
        row = selected_items[0].row()
        sig_id = self.signature_table.item(row, 0).text()
        
        # Look up details
        sig_details = self.threat_intel.attack_signatures.get(sig_id, {})
        if not sig_details:
            self.signature_details_text.setHtml("<p>No details available for this signature.</p>")
            return
        
        # Format the details
        html = f"""
        <h3>Signature: {sig_id}</h3>
        <p><b>Description:</b> {sig_details.get('description', 'N/A')}</p>
        <p><b>Severity:</b> {sig_details.get('severity', 'N/A')}</p>
        <p><b>Source:</b> {sig_details.get('source', 'N/A')}</p>
        """
        
        # Add pattern if available
        pattern = sig_details.get('pattern', '')
        if pattern:
            html += f"<p><b>Pattern:</b></p><pre>{pattern}</pre>"
        
        self.signature_details_text.setHtml(html) 