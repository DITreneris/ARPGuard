from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QGroupBox, QFormLayout, QTextEdit, QCheckBox, QMessageBox,
    QTabWidget, QComboBox
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QBrush, QFont

import threading
from datetime import datetime
from typing import Dict, List, Any

from app.utils.logger import get_logger
from app.components.defense_mechanism import get_defense_mechanism

# Module logger
logger = get_logger('components.defense_view')

class DefenseView(QWidget):
    """User interface component for managing defense mechanisms."""
    
    # Signals
    status_changed = pyqtSignal(str)  # Emitted when status changes
    defense_activated = pyqtSignal(dict)  # Emitted when a defense is activated
    
    def __init__(self, parent=None):
        """Initialize the defense view component."""
        super().__init__(parent)
        
        # Get defense mechanism
        self.defense = get_defense_mechanism()
        
        # State
        self.selected_attack = None
        
        # Setup UI
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the user interface."""
        main_layout = QVBoxLayout(self)
        
        # Top controls - buttons for defense actions
        controls_layout = QHBoxLayout()
        
        self.activate_button = QPushButton("Activate Defense")
        self.activate_button.setEnabled(False)
        self.activate_button.clicked.connect(self.activate_defense)
        
        self.deactivate_button = QPushButton("Deactivate Defense")
        self.deactivate_button.setEnabled(False)
        self.deactivate_button.clicked.connect(self.deactivate_defense)
        
        self.deactivate_all_button = QPushButton("Deactivate All")
        self.deactivate_all_button.clicked.connect(self.deactivate_all_defenses)
        
        # Add to controls layout
        controls_layout.addWidget(self.activate_button)
        controls_layout.addWidget(self.deactivate_button)
        controls_layout.addStretch()
        controls_layout.addWidget(self.deactivate_all_button)
        
        # Main content splitter
        content_splitter = QSplitter(Qt.Vertical)
        
        # Top part - List of active defenses
        defense_list_group = QGroupBox("Active Defenses")
        defense_list_layout = QVBoxLayout(defense_list_group)
        
        self.defense_table = QTableWidget(0, 5)
        self.defense_table.setHorizontalHeaderLabels(["Start Time", "Attack Type", "Defense", "Target", "Status"])
        self.defense_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.defense_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.defense_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.defense_table.setAlternatingRowColors(True)
        self.defense_table.itemSelectionChanged.connect(self.handle_defense_selection)
        
        defense_list_layout.addWidget(self.defense_table)
        
        # Bottom part - Defense details
        defense_details_group = QGroupBox("Defense Details")
        defense_details_layout = QVBoxLayout(defense_details_group)
        
        details_tabs = QTabWidget()
        
        # Overview tab
        overview_tab = QWidget()
        overview_layout = QFormLayout(overview_tab)
        
        self.defense_name_label = QLabel("No defense selected")
        self.defense_name_label.setFont(QFont(self.defense_name_label.font().family(), 12, QFont.Bold))
        
        self.defense_description_label = QLabel("")
        self.defense_description_label.setWordWrap(True)
        
        self.defense_action_label = QLabel("")
        self.defense_target_label = QLabel("")
        self.defense_time_label = QLabel("")
        self.defense_status_label = QLabel("")
        
        overview_layout.addRow(self.defense_name_label)
        overview_layout.addRow(QLabel("<hr>"))
        overview_layout.addRow("Description:", self.defense_description_label)
        overview_layout.addRow("Action:", self.defense_action_label)
        overview_layout.addRow("Target:", self.defense_target_label)
        overview_layout.addRow("Start Time:", self.defense_time_label)
        overview_layout.addRow("Status:", self.defense_status_label)
        
        # Commands tab
        commands_tab = QWidget()
        commands_layout = QVBoxLayout(commands_tab)
        
        self.commands_text = QTextEdit()
        self.commands_text.setReadOnly(True)
        self.commands_text.setLineWrapMode(QTextEdit.NoWrap)
        self.commands_text.setStyleSheet("font-family: monospace;")
        
        commands_layout.addWidget(QLabel("Commands executed for this defense:"))
        commands_layout.addWidget(self.commands_text)
        
        # Add tabs
        details_tabs.addTab(overview_tab, "Overview")
        details_tabs.addTab(commands_tab, "Commands")
        
        defense_details_layout.addWidget(details_tabs)
        
        # Add to splitter
        content_splitter.addWidget(defense_list_group)
        content_splitter.addWidget(defense_details_group)
        content_splitter.setSizes([200, 200])  # Equal initial sizes
        
        # Add to main layout
        main_layout.addLayout(controls_layout)
        main_layout.addWidget(content_splitter, 1)  # Give splitter stretch
        
        # Status label
        self.status_label = QLabel("Ready")
        main_layout.addWidget(self.status_label)
        
        # Initial load
        self.refresh_defense_table()
    
    def refresh_defense_table(self):
        """Refresh the active defenses table."""
        # Clear existing items
        self.defense_table.setRowCount(0)
        
        # Get active defenses
        active_defenses = self.defense.get_active_defenses()
        
        # Update the deactivate all button state
        self.deactivate_all_button.setEnabled(len(active_defenses) > 0)
        
        # Add each defense to the table
        for attack_id, defense_info in active_defenses.items():
            attack_details = defense_info.get('attack_details', {})
            defense_details = defense_info.get('defense_details', {})
            start_time = defense_info.get('start_time', datetime.now())
            
            row = self.defense_table.rowCount()
            self.defense_table.insertRow(row)
            
            # Start Time column
            time_item = QTableWidgetItem(start_time.strftime("%Y-%m-%d %H:%M:%S"))
            self.defense_table.setItem(row, 0, time_item)
            
            # Attack Type column
            attack_type = attack_details.get('type', 'unknown')
            attack_name = attack_details.get('name', attack_type.capitalize())
            type_item = QTableWidgetItem(attack_name)
            self.defense_table.setItem(row, 1, type_item)
            
            # Defense column
            defense_type = defense_details.get('type', 'unknown')
            defense_action = defense_details.get('action', 'unknown')
            defense_item = QTableWidgetItem(defense_action)
            self.defense_table.setItem(row, 2, defense_item)
            
            # Target column
            target = self._get_defense_target(defense_details)
            target_item = QTableWidgetItem(target)
            self.defense_table.setItem(row, 3, target_item)
            
            # Status column
            status_item = QTableWidgetItem("Active")
            status_item.setForeground(QBrush(QColor(0, 128, 0)))  # Green text
            self.defense_table.setItem(row, 4, status_item)
            
            # Store defense info in the first item
            time_item.setData(Qt.UserRole, {
                'attack_id': attack_id,
                'defense_info': defense_info
            })
    
    def _get_defense_target(self, defense_details: Dict) -> str:
        """Extract a human-readable target from defense details.
        
        Args:
            defense_details: Dictionary with defense details
            
        Returns:
            str: Target description
        """
        defense_type = defense_details.get('type', '')
        
        if defense_type == 'arp_defense':
            protected_ips = defense_details.get('protected_ips', [])
            if protected_ips:
                ips = [ip_info.get('ip', '') for ip_info in protected_ips]
                if len(ips) > 1:
                    return f"{len(ips)} IPs"
                else:
                    return ips[0]
            return "Unknown IP"
            
        elif defense_type == 'port_scan_defense':
            blocked_ips = defense_details.get('blocked_ips', [])
            if blocked_ips:
                ips = [ip_info.get('ip', '') for ip_info in blocked_ips]
                if len(ips) > 1:
                    return f"{len(ips)} Blocked IPs"
                else:
                    return ips[0]
            return "Unknown IP"
            
        elif defense_type == 'ddos_defense':
            protected_targets = defense_details.get('protected_targets', [])
            if protected_targets:
                ips = [target.get('ip', '') for target in protected_targets]
                if len(ips) > 1:
                    return f"{len(ips)} Protected IPs"
                else:
                    return ips[0]
            return "Unknown IP"
            
        elif defense_type == 'dns_defense':
            protected_domains = defense_details.get('protected_domains', [])
            if protected_domains:
                domains = [domain.get('domain', '') for domain in protected_domains]
                if len(domains) > 1:
                    return f"{len(domains)} Domains"
                else:
                    return domains[0]
            return "Unknown Domain"
            
        else:
            return "Unknown Target"
    
    def handle_defense_selection(self):
        """Handle selection of a defense from the table."""
        selected_items = self.defense_table.selectedItems()
        
        if not selected_items:
            # Clear details
            self.defense_name_label.setText("No defense selected")
            self.defense_description_label.setText("")
            self.defense_action_label.setText("")
            self.defense_target_label.setText("")
            self.defense_time_label.setText("")
            self.defense_status_label.setText("")
            self.commands_text.setText("")
            
            # Disable buttons
            self.deactivate_button.setEnabled(False)
            self.selected_attack = None
            return
            
        # Get defense info from the first column item
        data = selected_items[0].data(Qt.UserRole)
        
        if not data:
            return
            
        self.selected_attack = data.get('attack_id')
        defense_info = data.get('defense_info', {})
        attack_details = defense_info.get('attack_details', {})
        defense_details = defense_info.get('defense_details', {})
        
        # Enable deactivate button
        self.deactivate_button.setEnabled(True)
        
        # Update defense details
        self._update_defense_details(attack_details, defense_details, defense_info.get('start_time'))
    
    def _update_defense_details(self, attack_details, defense_details, start_time):
        """Update the defense details view.
        
        Args:
            attack_details: Dictionary with attack details
            defense_details: Dictionary with defense details
            start_time: Defense start time
        """
        # Basic details
        attack_name = attack_details.get('name', 'Unknown Attack')
        defense_type = defense_details.get('type', 'unknown')
        
        self.defense_name_label.setText(f"Defense against {attack_name}")
        self.defense_description_label.setText(defense_details.get('description', ''))
        self.defense_action_label.setText(defense_details.get('action', 'Unknown'))
        
        # Target details based on defense type
        target = self._get_detailed_target(defense_details)
        self.defense_target_label.setText(target)
        
        # Time
        if start_time:
            self.defense_time_label.setText(start_time.strftime("%Y-%m-%d %H:%M:%S"))
        else:
            self.defense_time_label.setText("Unknown")
        
        # Status
        self.defense_status_label.setText('<span style="color: green">Active</span>')
        
        # Commands
        commands = defense_details.get('commands_run', [])
        if commands:
            self.commands_text.setPlainText("\n".join(commands))
        else:
            self.commands_text.setPlainText("No commands executed.")
    
    def _get_detailed_target(self, defense_details) -> str:
        """Get detailed target information.
        
        Args:
            defense_details: Dictionary with defense details
            
        Returns:
            str: Detailed target description
        """
        defense_type = defense_details.get('type', '')
        
        if defense_type == 'arp_defense':
            protected_ips = defense_details.get('protected_ips', [])
            if protected_ips:
                if len(protected_ips) == 1:
                    ip_info = protected_ips[0]
                    return f"IP: {ip_info.get('ip', '')}, MAC: {ip_info.get('mac', '')}"
                else:
                    return f"{len(protected_ips)} protected IP addresses"
                    
        elif defense_type == 'port_scan_defense':
            blocked_ips = defense_details.get('blocked_ips', [])
            if blocked_ips:
                if len(blocked_ips) == 1:
                    ip_info = blocked_ips[0]
                    return f"Blocked IP: {ip_info.get('ip', '')}"
                else:
                    return f"{len(blocked_ips)} blocked IP addresses"
                    
        elif defense_type == 'ddos_defense':
            protected_targets = defense_details.get('protected_targets', [])
            if protected_targets:
                if len(protected_targets) == 1:
                    target = protected_targets[0]
                    return f"Protected IP: {target.get('ip', '')}, Rate limited to {target.get('packets_per_second', 0)} packets/sec"
                else:
                    return f"{len(protected_targets)} rate-limited targets"
                    
        elif defense_type == 'dns_defense':
            protected_domains = defense_details.get('protected_domains', [])
            if protected_domains:
                if len(protected_domains) == 1:
                    domain_info = protected_domains[0]
                    return f"Domain: {domain_info.get('domain', '')}, IP: {domain_info.get('ip', '')}"
                else:
                    return f"{len(protected_domains)} protected domains"
        
        return "Unknown target"
    
    def activate_defense(self):
        """Manually activate defense for the selected attack."""
        pass  # Placeholder - will be implemented for manual defense activation
    
    def handle_attack_detected(self, attack_details):
        """Handle a newly detected attack.
        
        Args:
            attack_details: Dictionary with attack details
        """
        # Ask user if they want to activate defense
        attack_name = attack_details.get('name', 'Unknown Attack')
        attack_type = attack_details.get('type', 'unknown')
        
        reply = QMessageBox.question(
            self,
            "Activate Defense?",
            f"A {attack_name} attack has been detected.\n\nDo you want to activate defensive measures?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes
        )
        
        if reply == QMessageBox.Yes:
            # Activate defense
            self._activate_defense_for_attack(attack_details)
    
    def _activate_defense_for_attack(self, attack_details):
        """Activate defense for an attack.
        
        Args:
            attack_details: Dictionary with attack details
        """
        # Show message that defense is being activated
        self.status_label.setText(f"Activating defense against {attack_details.get('name', 'unknown attack')}...")
        
        # Define callback function for defense activation
        def defense_callback(success, message, details):
            # Update UI in the main thread
            if threading.current_thread() != threading.main_thread():
                from PyQt5.QtCore import QMetaObject, Qt, Q_ARG
                QMetaObject.invokeMethod(
                    self,
                    "_update_after_defense_activation",
                    Qt.QueuedConnection,
                    Q_ARG(bool, success),
                    Q_ARG(str, message),
                    Q_ARG(object, details)
                )
            else:
                self._update_after_defense_activation(success, message, details)
        
        # Start defense in a separate thread to avoid blocking UI
        threading.Thread(
            target=self._activate_defense_thread,
            args=(attack_details, defense_callback),
            daemon=True
        ).start()
    
    def _activate_defense_thread(self, attack_details, callback):
        """Thread function for defense activation.
        
        Args:
            attack_details: Dictionary with attack details
            callback: Callback function for status updates
        """
        try:
            # Activate defense
            result = self.defense.start_defense(attack_details, callback)
            
            # Log result
            if result:
                logger.info(f"Defense activated for {attack_details.get('name', 'unknown attack')}")
            else:
                logger.error(f"Failed to activate defense for {attack_details.get('name', 'unknown attack')}")
                
        except Exception as e:
            logger.error(f"Error activating defense: {e}")
            if callback:
                callback(False, f"Error: {e}", None)
    
    def _update_after_defense_activation(self, success, message, details):
        """Update UI after defense activation.
        
        Args:
            success: Whether activation was successful
            message: Status message
            details: Defense details dictionary
        """
        # Update status
        self.status_label.setText(message)
        self.status_changed.emit(message)
        
        if success:
            # Refresh the defense table
            self.refresh_defense_table()
            
            # Emit signal
            if details:
                self.defense_activated.emit(details)
                
        else:
            # Show error message
            QMessageBox.warning(
                self,
                "Defense Activation Failed",
                message,
                QMessageBox.Ok
            )
    
    def deactivate_defense(self):
        """Deactivate the selected defense."""
        if not self.selected_attack:
            return
            
        # Get defense info
        active_defenses = self.defense.get_active_defenses()
        if self.selected_attack not in active_defenses:
            QMessageBox.warning(
                self,
                "Defense Not Found",
                "The selected defense is no longer active.",
                QMessageBox.Ok
            )
            self.refresh_defense_table()
            return
            
        defense_info = active_defenses[self.selected_attack]
        attack_name = defense_info.get('attack_details', {}).get('name', 'unknown attack')
        
        # Confirm with user
        reply = QMessageBox.question(
            self,
            "Deactivate Defense?",
            f"Are you sure you want to deactivate defense against {attack_name}?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Deactivate in a separate thread
            self.status_label.setText(f"Deactivating defense against {attack_name}...")
            
            threading.Thread(
                target=self._deactivate_defense_thread,
                args=(self.selected_attack,),
                daemon=True
            ).start()
    
    def _deactivate_defense_thread(self, attack_id):
        """Thread function for defense deactivation.
        
        Args:
            attack_id: ID of the attack to deactivate defense for
        """
        try:
            # Get defense info for the message
            active_defenses = self.defense.get_active_defenses()
            if attack_id in active_defenses:
                defense_info = active_defenses[attack_id]
                attack_name = defense_info.get('attack_details', {}).get('name', 'unknown attack')
            else:
                attack_name = "unknown attack"
            
            # Deactivate defense
            result = self.defense.stop_defense(attack_id)
            
            # Update UI in the main thread
            from PyQt5.QtCore import QMetaObject, Qt, Q_ARG
            QMetaObject.invokeMethod(
                self,
                "_update_after_defense_deactivation",
                Qt.QueuedConnection,
                Q_ARG(bool, result),
                Q_ARG(str, attack_name)
            )
                
        except Exception as e:
            logger.error(f"Error deactivating defense: {e}")
            # Update UI in the main thread
            from PyQt5.QtCore import QMetaObject, Qt, Q_ARG
            QMetaObject.invokeMethod(
                self,
                "_update_after_defense_deactivation",
                Qt.QueuedConnection,
                Q_ARG(bool, False),
                Q_ARG(str, str(e))
            )
    
    def _update_after_defense_deactivation(self, success, message):
        """Update UI after defense deactivation.
        
        Args:
            success: Whether deactivation was successful
            message: Attack name or error message
        """
        if success:
            # Update status
            status_message = f"Defense against {message} deactivated."
            self.status_label.setText(status_message)
            self.status_changed.emit(status_message)
            
            # Refresh the defense table
            self.refresh_defense_table()
            
            # Clear selection
            self.selected_attack = None
                
        else:
            # Show error message
            QMessageBox.warning(
                self,
                "Defense Deactivation Failed",
                f"Failed to deactivate defense: {message}",
                QMessageBox.Ok
            )
            
        # Refresh the defense table in any case
        self.refresh_defense_table()
    
    def deactivate_all_defenses(self):
        """Deactivate all active defenses."""
        # Get active defenses
        active_defenses = self.defense.get_active_defenses()
        if not active_defenses:
            return
            
        # Confirm with user
        reply = QMessageBox.question(
            self,
            "Deactivate All Defenses?",
            f"Are you sure you want to deactivate all {len(active_defenses)} active defenses?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Deactivate in a separate thread
            self.status_label.setText("Deactivating all defenses...")
            
            threading.Thread(
                target=self._deactivate_all_thread,
                daemon=True
            ).start()
    
    def _deactivate_all_thread(self):
        """Thread function for deactivating all defenses."""
        try:
            # Deactivate all defenses
            result = self.defense.stop_all_defenses()
            
            # Update UI in the main thread
            from PyQt5.QtCore import QMetaObject, Qt, Q_ARG
            QMetaObject.invokeMethod(
                self,
                "_update_after_deactivate_all",
                Qt.QueuedConnection,
                Q_ARG(bool, result)
            )
                
        except Exception as e:
            logger.error(f"Error deactivating all defenses: {e}")
            # Update UI in the main thread
            from PyQt5.QtCore import QMetaObject, Qt, Q_ARG
            QMetaObject.invokeMethod(
                self,
                "_update_after_deactivate_all",
                Qt.QueuedConnection,
                Q_ARG(bool, False)
            )
    
    def _update_after_deactivate_all(self, success):
        """Update UI after deactivating all defenses.
        
        Args:
            success: Whether deactivation was successful
        """
        if success:
            # Update status
            status_message = "All defenses deactivated."
            self.status_label.setText(status_message)
            self.status_changed.emit(status_message)
            
            # Clear selection
            self.selected_attack = None
                
        else:
            # Show error message
            QMessageBox.warning(
                self,
                "Deactivation Failed",
                "Failed to deactivate all defenses. Some defenses may still be active.",
                QMessageBox.Ok
            )
            
        # Refresh the defense table in any case
        self.refresh_defense_table() 