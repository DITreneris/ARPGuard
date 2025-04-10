from typing import Dict, List, Optional, Any
from PyQt5.QtWidgets import (QWizard, QWizardPage, QVBoxLayout, QHBoxLayout,
                           QLabel, QComboBox, QCheckBox, QLineEdit, QSpinBox,
                           QGroupBox, QRadioButton, QButtonGroup)
from PyQt5.QtCore import Qt, pyqtSignal
from app.utils.performance_monitor import measure_performance

class NetworkConfigPage(QWizardPage):
    """Network configuration page"""
    
    def __init__(self, parent: Optional[QWizard] = None):
        super().__init__(parent)
        self.setTitle("Network Configuration")
        self.setSubTitle("Configure network interfaces and monitoring settings")
        
        layout = QVBoxLayout(self)
        
        # Network interface selection
        interface_group = QGroupBox("Network Interface")
        interface_layout = QVBoxLayout(interface_group)
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(["eth0", "eth1", "wlan0"])
        interface_layout.addWidget(self.interface_combo)
        layout.addWidget(interface_group)
        
        # Monitoring mode
        mode_group = QGroupBox("Monitoring Mode")
        mode_layout = QVBoxLayout(mode_group)
        self.mode_group = QButtonGroup()
        self.monitor_radio = QRadioButton("Monitor Only")
        self.protect_radio = QRadioButton("Monitor and Protect")
        self.mode_group.addButton(self.monitor_radio)
        self.mode_group.addButton(self.protect_radio)
        self.protect_radio.setChecked(True)
        mode_layout.addWidget(self.monitor_radio)
        mode_layout.addWidget(self.protect_radio)
        layout.addWidget(mode_group)
        
        # Advanced settings
        advanced_group = QGroupBox("Advanced Settings")
        advanced_layout = QVBoxLayout(advanced_group)
        self.promiscuous_check = QCheckBox("Enable Promiscuous Mode")
        self.promiscuous_check.setChecked(True)
        advanced_layout.addWidget(self.promiscuous_check)
        
        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("Packet Timeout (ms):"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(100, 10000)
        self.timeout_spin.setValue(1000)
        self.timeout_spin.setSingleStep(100)
        timeout_layout.addWidget(self.timeout_spin)
        advanced_layout.addLayout(timeout_layout)
        
        layout.addWidget(advanced_group)
        
    def get_config(self) -> Dict[str, Any]:
        """Get network configuration settings"""
        return {
            'interface': self.interface_combo.currentText(),
            'mode': 'monitor' if self.monitor_radio.isChecked() else 'protect',
            'promiscuous_mode': self.promiscuous_check.isChecked(),
            'packet_timeout': self.timeout_spin.value()
        }

class SecurityConfigPage(QWizardPage):
    """Security configuration page"""
    
    def __init__(self, parent: Optional[QWizard] = None):
        super().__init__(parent)
        self.setTitle("Security Configuration")
        self.setSubTitle("Configure ARP spoofing detection and response settings")
        
        layout = QVBoxLayout(self)
        
        # ARP spoofing thresholds
        threshold_group = QGroupBox("ARP Spoofing Thresholds")
        threshold_layout = QVBoxLayout(threshold_group)
        
        # Rate threshold
        rate_layout = QHBoxLayout()
        rate_layout.addWidget(QLabel("Max ARP Requests per Second:"))
        self.rate_spin = QSpinBox()
        self.rate_spin.setRange(1, 1000)
        self.rate_spin.setValue(100)
        rate_layout.addWidget(self.rate_spin)
        threshold_layout.addLayout(rate_layout)
        
        # MAC changes threshold
        mac_layout = QHBoxLayout()
        mac_layout.addWidget(QLabel("Max MAC Changes per Minute:"))
        self.mac_spin = QSpinBox()
        self.mac_spin.setRange(1, 100)
        self.mac_spin.setValue(10)
        mac_layout.addWidget(self.mac_spin)
        threshold_layout.addLayout(mac_layout)
        
        layout.addWidget(threshold_group)
        
        # Response actions
        action_group = QGroupBox("Response Actions")
        action_layout = QVBoxLayout(action_group)
        self.block_check = QCheckBox("Block Attack Traffic")
        self.alert_check = QCheckBox("Alert Administrator")
        self.log_check = QCheckBox("Log Event")
        self.block_check.setChecked(True)
        self.alert_check.setChecked(True)
        self.log_check.setChecked(True)
        action_layout.addWidget(self.block_check)
        action_layout.addWidget(self.alert_check)
        action_layout.addWidget(self.log_check)
        layout.addWidget(action_group)
        
    def get_config(self) -> Dict[str, Any]:
        """Get security configuration settings"""
        return {
            'arp_rate_threshold': self.rate_spin.value(),
            'mac_changes_threshold': self.mac_spin.value(),
            'block_attacks': self.block_check.isChecked(),
            'alert_admin': self.alert_check.isChecked(),
            'log_events': self.log_check.isChecked()
        }

class NotificationConfigPage(QWizardPage):
    """Notification configuration page"""
    
    def __init__(self, parent: Optional[QWizard] = None):
        super().__init__(parent)
        self.setTitle("Notification Configuration")
        self.setSubTitle("Configure alert notification settings")
        
        layout = QVBoxLayout(self)
        
        # Notification methods
        method_group = QGroupBox("Notification Methods")
        method_layout = QVBoxLayout(method_group)
        self.email_check = QCheckBox("Email")
        self.sms_check = QCheckBox("SMS")
        self.desktop_check = QCheckBox("Desktop")
        method_layout.addWidget(self.email_check)
        method_layout.addWidget(self.sms_check)
        method_layout.addWidget(self.desktop_check)
        layout.addWidget(method_group)
        
        # Email settings
        email_group = QGroupBox("Email Settings")
        email_layout = QVBoxLayout(email_group)
        
        # Email address
        address_layout = QHBoxLayout()
        address_layout.addWidget(QLabel("Email Address:"))
        self.email_address = QLineEdit()
        self.email_address.setPlaceholderText("admin@example.com")
        address_layout.addWidget(self.email_address)
        email_layout.addLayout(address_layout)
        
        # SMTP server
        server_layout = QHBoxLayout()
        server_layout.addWidget(QLabel("SMTP Server:"))
        self.smtp_server = QLineEdit()
        self.smtp_server.setPlaceholderText("smtp.example.com")
        server_layout.addWidget(self.smtp_server)
        email_layout.addLayout(server_layout)
        
        # SMTP port
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("SMTP Port:"))
        self.smtp_port = QSpinBox()
        self.smtp_port.setRange(1, 65535)
        self.smtp_port.setValue(587)
        port_layout.addWidget(self.smtp_port)
        email_layout.addLayout(port_layout)
        
        layout.addWidget(email_group)
        
    def get_config(self) -> Dict[str, Any]:
        """Get notification configuration settings"""
        return {
            'email_enabled': self.email_check.isChecked(),
            'sms_enabled': self.sms_check.isChecked(),
            'desktop_enabled': self.desktop_check.isChecked(),
            'email_settings': {
                'address': self.email_address.text(),
                'smtp_server': self.smtp_server.text(),
                'smtp_port': self.smtp_port.value()
            }
        }

class ConfigurationWizard(QWizard):
    """Main configuration wizard"""
    
    config_complete = pyqtSignal(dict)  # Emits when configuration is complete
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("ARPGuard Configuration Wizard")
        self.setWizardStyle(QWizard.ModernStyle)
        
        # Add pages
        self.network_page = NetworkConfigPage()
        self.security_page = SecurityConfigPage()
        self.notification_page = NotificationConfigPage()
        
        self.addPage(self.network_page)
        self.addPage(self.security_page)
        self.addPage(self.notification_page)
        
        # Connect signals
        self.finished.connect(self._on_finished)
        
    def _on_finished(self) -> None:
        """Handle wizard completion"""
        if self.result() == QWizard.Accepted:
            config = self.get_configuration()
            self.config_complete.emit(config)
            
    @measure_performance('get_configuration')
    def get_configuration(self) -> Dict[str, Any]:
        """Get complete configuration"""
        return {
            'network': self.network_page.get_config(),
            'security': self.security_page.get_config(),
            'notification': self.notification_page.get_config()
        } 