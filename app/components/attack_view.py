from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QGroupBox, QFormLayout, QTextEdit, QComboBox, QCheckBox,
    QTabWidget, QMessageBox, QListWidget, QListWidgetItem
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QBrush, QFont

import threading
from datetime import datetime
from typing import Dict, List, Any, Optional

from app.utils.logger import get_logger
from app.utils.database import get_database
from app.components.attack_recognizer import AttackRecognizer

# Module logger
logger = get_logger('components.attack_view')

class AttackView(QWidget):
    """UI component for attack pattern recognition and management."""
    
    # Signals
    status_changed = pyqtSignal(str)  # Emitted when status changes
    attack_detected = pyqtSignal(dict)  # Emitted when an attack is detected
    
    def __init__(self, parent=None):
        """Initialize the attack view component."""
        super().__init__(parent)
        
        # Get database and create attack recognizer
        self.database = get_database()
        self.recognizer = AttackRecognizer()
        
        # Setup UI
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the user interface."""
        main_layout = QVBoxLayout(self)
        
        # Control panel
        control_panel = QWidget()
        control_layout = QHBoxLayout(control_panel)
        
        # Detection controls
        self.start_button = QPushButton("Start Pattern Detection")
        self.start_button.clicked.connect(self.toggle_detection)
        
        # Pattern configuration
        self.pattern_combo = QComboBox()
        self.pattern_combo.addItem("All Patterns", "all")
        
        # Add each available pattern to combobox
        for pattern in self.recognizer.get_available_patterns():
            self.pattern_combo.addItem(
                f"{pattern['name']} ({pattern['severity'].upper()})", 
                pattern['name']
            )
        
        # Add to control layout
        control_layout.addWidget(QLabel("Detection Patterns:"))
        control_layout.addWidget(self.pattern_combo)
        control_layout.addStretch()
        control_layout.addWidget(self.start_button)
        
        # Main content area with splitter
        content_splitter = QSplitter(Qt.Vertical)
        
        # Top section - Attack list
        attack_list_group = QGroupBox("Detected Attacks")
        attack_list_layout = QVBoxLayout(attack_list_group)
        
        self.attack_table = QTableWidget(0, 5)
        self.attack_table.setHorizontalHeaderLabels(["Detection Time", "Attack Type", "Severity", "Duration", "Details"])
        self.attack_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.attack_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.attack_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.attack_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.attack_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.attack_table.setAlternatingRowColors(True)
        self.attack_table.itemSelectionChanged.connect(self.handle_attack_selection)
        
        attack_list_layout.addWidget(self.attack_table)
        
        # Bottom section - Attack details
        attack_details_group = QGroupBox("Attack Details")
        attack_details_layout = QVBoxLayout(attack_details_group)
        
        self.details_tabs = QTabWidget()
        
        # Overview tab
        overview_tab = QWidget()
        overview_layout = QFormLayout(overview_tab)
        
        self.attack_name_label = QLabel("No attack selected")
        self.attack_name_label.setFont(QFont(self.attack_name_label.font().family(), 12, QFont.Bold))
        
        self.attack_description_label = QLabel("")
        self.attack_description_label.setWordWrap(True)
        
        self.attack_severity_label = QLabel("")
        self.attack_time_label = QLabel("")
        self.attack_stats_label = QLabel("")
        self.attack_stats_label.setWordWrap(True)
        
        overview_layout.addRow(self.attack_name_label)
        overview_layout.addRow(QLabel("<hr>"))
        overview_layout.addRow("Description:", self.attack_description_label)
        overview_layout.addRow("Severity:", self.attack_severity_label)
        overview_layout.addRow("Detection Time:", self.attack_time_label)
        overview_layout.addRow("Statistics:", self.attack_stats_label)
        
        # Evidence tab
        evidence_tab = QWidget()
        evidence_layout = QVBoxLayout(evidence_tab)
        
        self.evidence_list = QListWidget()
        self.evidence_list.itemDoubleClicked.connect(self.view_evidence_packet)
        
        evidence_layout.addWidget(QLabel("Packet evidence of the attack (double-click to view):"))
        evidence_layout.addWidget(self.evidence_list)
        
        # Add tabs
        self.details_tabs.addTab(overview_tab, "Overview")
        self.details_tabs.addTab(evidence_tab, "Evidence")
        
        attack_details_layout.addWidget(self.details_tabs)
        
        # Add to splitter
        content_splitter.addWidget(attack_list_group)
        content_splitter.addWidget(attack_details_group)
        content_splitter.setSizes([200, 200])  # Equal initial sizes
        
        # Add components to main layout
        main_layout.addWidget(control_panel)
        main_layout.addWidget(content_splitter, 1)  # Give the splitter stretch
        
        # Status label
        self.status_label = QLabel("Ready")
        main_layout.addWidget(self.status_label)
        
    def toggle_detection(self):
        """Toggle attack pattern detection on/off."""
        if self.start_button.text() == "Start Pattern Detection":
            # Start detection
            pattern_selection = self.pattern_combo.currentData()
            
            # Get selected patterns (future feature: filter by selected pattern)
            if pattern_selection != "all":
                # Eventually implement filtering by pattern
                pass
                
            success = self.recognizer.start_detection(callback=self.handle_attack_detected)
            
            if success:
                self.start_button.setText("Stop Detection")
                self.pattern_combo.setEnabled(False)
                self.status_label.setText("Attack pattern detection running...")
                self.status_changed.emit("Attack pattern detection started")
                logger.info("Attack pattern detection started")
            else:
                self.status_label.setText("Failed to start attack pattern detection")
                self.status_changed.emit("Failed to start attack pattern detection")
                logger.error("Failed to start attack pattern detection")
        else:
            # Stop detection
            success = self.recognizer.stop_detection()
            
            if success:
                self.start_button.setText("Start Pattern Detection")
                self.pattern_combo.setEnabled(True)
                self.status_label.setText("Attack pattern detection stopped")
                self.status_changed.emit("Attack pattern detection stopped")
                logger.info("Attack pattern detection stopped")
            else:
                self.status_label.setText("Failed to stop attack pattern detection")
                self.status_changed.emit("Failed to stop attack pattern detection")
                logger.error("Failed to stop attack pattern detection")
        
    def handle_attack_detected(self, success, message, details):
        """Handle attack detection events from the recognizer.
        
        Args:
            success: Whether detection was successful
            message: Message about the detection
            details: Dictionary with attack details
        """
        # Use thread-safe emit to update the UI
        if threading.current_thread() != threading.main_thread():
            from PyQt5.QtCore import QMetaObject, Qt, Q_ARG
            QMetaObject.invokeMethod(
                self,
                "_update_ui_with_detection",
                Qt.QueuedConnection,
                Q_ARG(bool, success),
                Q_ARG(str, message),
                Q_ARG(object, details)
            )
        else:
            self._update_ui_with_detection(success, message, details)
        
    def _update_ui_with_detection(self, success, message, details):
        """Update UI with attack detection (called in main thread).
        
        Args:
            success: Whether detection was successful
            message: Message about the detection
            details: Dictionary with attack details
        """
        if success and details:
            # Update status
            self.status_label.setText(message)
            self.status_changed.emit(message)
            
            # Add to attack table
            self.add_attack_to_table(details, message)
            
            # Emit signal for other components to use
            self.attack_detected.emit(details)
        else:
            # Show error message
            self.status_label.setText(f"Detection error: {message}")
            
    def add_attack_to_table(self, attack_details, message):
        """Add an attack to the attack table.
        
        Args:
            attack_details: Dictionary with attack details
            message: Formatted message about the attack
        """
        # Get current time for detection
        detection_time = attack_details.get('detection_time', datetime.now())
        
        # Get attack duration if available
        duration = "N/A"
        if 'first_seen' in attack_details and 'last_seen' in attack_details:
            first_seen = attack_details['first_seen']
            last_seen = attack_details['last_seen']
            duration_sec = (last_seen - first_seen).total_seconds()
            duration = f"{duration_sec:.1f} sec"
        
        # Insert at the top of the table (row 0)
        row = 0
        self.attack_table.insertRow(row)
        
        # Time column
        time_item = QTableWidgetItem(detection_time.strftime("%Y-%m-%d %H:%M:%S"))
        self.attack_table.setItem(row, 0, time_item)
        
        # Attack type column
        attack_name = attack_details.get('name', 'Unknown Attack')
        attack_item = QTableWidgetItem(attack_name)
        self.attack_table.setItem(row, 1, attack_item)
        
        # Severity column
        severity = attack_details.get('severity', 'medium')
        severity_item = QTableWidgetItem(severity.upper())
        
        # Color based on severity
        if severity.lower() == 'critical':
            severity_item.setBackground(QBrush(QColor(255, 200, 200)))  # Light red
        elif severity.lower() == 'high':
            severity_item.setBackground(QBrush(QColor(255, 230, 200)))  # Light orange
        elif severity.lower() == 'medium':
            severity_item.setBackground(QBrush(QColor(255, 255, 200)))  # Light yellow
            
        self.attack_table.setItem(row, 2, severity_item)
        
        # Duration column
        duration_item = QTableWidgetItem(duration)
        self.attack_table.setItem(row, 3, duration_item)
        
        # Details column - truncated message
        details_item = QTableWidgetItem(message)
        self.attack_table.setItem(row, 4, details_item)
        
        # Store the full attack details in the first item's data
        time_item.setData(Qt.UserRole, attack_details)
        
        # Automatically select the new attack
        self.attack_table.selectRow(row)
        
    def handle_attack_selection(self):
        """Handle selection of an attack from the table."""
        selected_items = self.attack_table.selectedItems()
        
        if not selected_items:
            # Clear details
            self.attack_name_label.setText("No attack selected")
            self.attack_description_label.setText("")
            self.attack_severity_label.setText("")
            self.attack_time_label.setText("")
            self.attack_stats_label.setText("")
            self.evidence_list.clear()
            return
            
        # Get attack details from first column's data
        attack_details = selected_items[0].data(Qt.UserRole)
        
        if not attack_details:
            return
            
        # Update details view
        self._update_attack_details(attack_details)
        
    def _update_attack_details(self, attack_details):
        """Update the attack details view.
        
        Args:
            attack_details: Dictionary with attack details
        """
        # Set basic information
        self.attack_name_label.setText(attack_details.get('name', 'Unknown Attack'))
        self.attack_description_label.setText(attack_details.get('description', ''))
        
        # Severity with color
        severity = attack_details.get('severity', 'medium').upper()
        self.attack_severity_label.setText(f"<span style='font-weight:bold;'>{severity}</span>")
        
        # Detection time
        detection_time = attack_details.get('detection_time', datetime.now())
        self.attack_time_label.setText(detection_time.strftime("%Y-%m-%d %H:%M:%S"))
        
        # Statistics based on attack type
        stats_html = self._generate_attack_stats_html(attack_details)
        self.attack_stats_label.setText(stats_html)
        
        # Update evidence list
        self._update_evidence_list(attack_details)
        
    def _generate_attack_stats_html(self, attack_details):
        """Generate HTML for attack statistics based on attack type.
        
        Args:
            attack_details: Dictionary with attack details
            
        Returns:
            HTML string with attack statistics
        """
        attack_type = attack_details.get('type', '')
        html = []
        
        try:
            if attack_type == 'arp_spoofing':
                # ARP spoofing attack
                suspicious_ips = attack_details.get('suspicious_ips', [])
                html.append(f"<p><b>Suspicious IPs:</b> {len(suspicious_ips)}</p>")
                html.append("<ul>")
                for ip_info in suspicious_ips:
                    html.append(f"<li><b>IP:</b> {ip_info['ip']}")
                    html.append("<ul>")
                    for mac in ip_info['macs']:
                        html.append(f"<li><b>MAC:</b> {mac}</li>")
                    html.append("</ul></li>")
                html.append("</ul>")
                
            elif attack_type == 'port_scanning':
                # Port scanning attack
                scanners = attack_details.get('scanners', [])
                most_active = attack_details.get('most_active', {})
                
                if most_active:
                    html.append(f"<p><b>Most active scanner:</b> {most_active['src_ip']}</p>")
                    html.append(f"<p><b>Unique ports scanned:</b> {most_active['unique_port_count']}</p>")
                    html.append(f"<p><b>Scan duration:</b> {most_active['duration_seconds']:.1f} seconds</p>")
                    html.append("<p><b>Targeted IPs:</b></p><ul>")
                    for target in most_active.get('targets', []):
                        html.append(f"<li>{target['ip']} ({target['port_count']} ports)</li>")
                    html.append("</ul>")
                
                if len(scanners) > 1:
                    html.append(f"<p><b>Additional scanners:</b> {len(scanners) - 1}</p>")
                    
            elif attack_type == 'ddos':
                # DDoS attack
                targets = attack_details.get('targets', [])
                highest_rate = attack_details.get('highest_rate', 0)
                distributed = attack_details.get('distributed', False)
                
                html.append(f"<p><b>Attack type:</b> {'Distributed' if distributed else 'Single-source'} DoS</p>")
                html.append(f"<p><b>Highest traffic rate:</b> {highest_rate:.1f} packets/second</p>")
                html.append(f"<p><b>Number of targets:</b> {len(targets)}</p>")
                
                if targets:
                    html.append("<p><b>Target details:</b></p><ul>")
                    for target in targets:
                        html.append(f"<li><b>IP:</b> {target['dst_ip']}")
                        html.append(f"<ul><li><b>Protocol:</b> {target.get('protocol', 'Unknown')}</li>")
                        html.append(f"<li><b>Packet count:</b> {target['packet_count']}</li>")
                        html.append(f"<li><b>Rate:</b> {target['rate']:.1f} packets/second</li></ul></li>")
                    html.append("</ul>")
                    
            elif attack_type == 'dns_poisoning':
                # DNS poisoning attack
                suspicious_responses = attack_details.get('suspicious_responses', [])
                total_altered = attack_details.get('total_altered_responses', 0)
                
                html.append(f"<p><b>Total altered DNS responses:</b> {total_altered}</p>")
                html.append("<p><b>Suspicious DNS mappings:</b></p><ul>")
                
                for resp in suspicious_responses:
                    html.append(f"<li><b>Domain:</b> {resp['domain']}")
                    html.append("<ul>")
                    html.append(f"<li><b>Legitimate IP:</b> {resp.get('legitimate_ip', 'Unknown')}</li>")
                    html.append(f"<li><b>Spoofed IP:</b> {resp['spoofed_ip']}</li>")
                    html.append(f"<li><b>Source:</b> {resp['src_ip']}</li>")
                    html.append("</ul></li>")
                html.append("</ul>")
                
            elif attack_type == 'mitm_attack':
                # Man-in-the-Middle attack
                redirected_flows = attack_details.get('redirected_flows', [])
                ssl_issues = attack_details.get('ssl_issues', 0)
                confidence = attack_details.get('confidence', 'medium')
                
                html.append(f"<p><b>Attack confidence:</b> {confidence.capitalize()}</p>")
                html.append(f"<p><b>SSL/TLS issues:</b> {ssl_issues}</p>")
                html.append(f"<p><b>Redirected flows:</b> {len(redirected_flows)}</p>")
                
                if redirected_flows:
                    html.append("<p><b>Suspicious traffic flows:</b></p><ul>")
                    for flow in redirected_flows:
                        if 'type' in flow and flow['type'] == 'icmp_redirect':
                            html.append(f"<li><b>ICMP Redirects:</b> {flow['count']} from {', '.join(flow['sources'])}</li>")
                        else:
                            html.append(f"<li><b>Flow:</b> {flow.get('src_ip', 'Unknown')} → {flow.get('dst_ip', 'Unknown')}")
                            html.append("<ul>")
                            html.append(f"<li><b>Forward path MACs:</b> {', '.join(flow.get('forward_macs', []))}</li>")
                            html.append(f"<li><b>Reverse path MACs:</b> {', '.join(flow.get('reverse_macs', []))}</li>")
                            html.append(f"<li><b>Packet count:</b> {flow.get('packet_count', 0)}</li>")
                            html.append("</ul></li>")
                    html.append("</ul>")
                
            elif attack_type == 'syn_flood':
                # SYN flood attack
                targets = attack_details.get('targets', [])
                distributed = attack_details.get('distributed', False)
                max_rate = attack_details.get('max_rate', 0)
                
                html.append(f"<p><b>Attack type:</b> {'Distributed' if distributed else 'Single-source'} SYN Flood</p>")
                html.append(f"<p><b>Maximum SYN rate:</b> {max_rate:.1f} packets/second</p>")
                html.append(f"<p><b>Number of targets:</b> {len(targets)}</p>")
                
                if targets:
                    html.append("<p><b>Target details:</b></p><ul>")
                    for target in targets[:5]:  # Show top 5 targets
                        html.append(f"<li><b>IP:Port:</b> {target['dst_ip']}:{target['dst_port']}")
                        html.append("<ul>")
                        html.append(f"<li><b>Service:</b> {target['service']}</li>")
                        html.append(f"<li><b>SYN count:</b> {target['syn_count']}</li>")
                        html.append(f"<li><b>Rate:</b> {target['rate_per_second']:.1f} packets/second</li>")
                        html.append(f"<li><b>Unique sources:</b> {target['source_ip_count']}</li>")
                        html.append(f"<li><b>Duration:</b> {target['duration_seconds']:.1f} seconds</li>")
                        html.append("</ul></li>")
                    html.append("</ul>")
                    if len(targets) > 5:
                        html.append(f"<p><i>...and {len(targets) - 5} more targets</i></p>")
                        
            elif attack_type in ('smb_exploit', 'smb_brute_force', 'smb_suspicious'):
                # SMB-related attacks
                exploit_attempts = attack_details.get('exploit_attempts', [])
                brute_force_sources = attack_details.get('brute_force_sources', [])
                exploitation_risk = attack_details.get('exploitation_risk', 'Medium')
                
                html.append(f"<p><b>Attack subtype:</b> {attack_type.replace('smb_', '').replace('_', ' ').title()}</p>")
                html.append(f"<p><b>Exploitation risk:</b> {exploitation_risk}</p>")
                
                if exploit_attempts:
                    html.append(f"<p><b>Exploit attempts:</b> {len(exploit_attempts)}</p>")
                    html.append("<p><b>Detected signatures:</b></p><ul>")
                    signatures = {}
                    for attempt in exploit_attempts:
                        sig = attempt['signature']
                        if sig not in signatures:
                            signatures[sig] = 0
                        signatures[sig] += 1
                    
                    for sig, count in signatures.items():
                        html.append(f"<li><b>Signature:</b> {sig} ({count} occurrences)</li>")
                    html.append("</ul>")
                
                if brute_force_sources:
                    html.append(f"<p><b>Brute force sources:</b> {len(brute_force_sources)}</p>")
                    html.append("<p><b>Top sources:</b></p><ul>")
                    for source in sorted(brute_force_sources, key=lambda x: x['failed_attempts'], reverse=True)[:5]:
                        html.append(f"<li><b>IP:</b> {source['src_ip']}")
                        html.append(f"<ul><li><b>Failed attempts:</b> {source['failed_attempts']}</li>")
                        html.append(f"<li><b>Total packets:</b> {source['packet_count']}</li></ul></li>")
                    html.append("</ul>")
                    
            elif attack_type == 'ssh_brute_force':
                # SSH brute force attack
                sources = attack_details.get('sources', [])
                max_attempts = attack_details.get('max_attempts', 0)
                
                html.append(f"<p><b>Max connection attempts:</b> {max_attempts}</p>")
                html.append(f"<p><b>Number of source IPs:</b> {len(sources)}</p>")
                
                if sources:
                    html.append("<p><b>Top attackers:</b></p><ul>")
                    for source in sources[:5]:  # Show top 5 sources
                        html.append(f"<li><b>IP:</b> {source['src_ip']}")
                        html.append("<ul>")
                        html.append(f"<li><b>Connection attempts:</b> {source['connection_attempts']}</li>")
                        html.append(f"<li><b>Unique targets:</b> {source['unique_targets']}</li>")
                        html.append(f"<li><b>Rate:</b> {source['rate_per_second']:.1f} attempts/second</li>")
                        html.append(f"<li><b>Duration:</b> {source['duration_seconds']:.1f} seconds</li>")
                        html.append("</ul></li>")
                    html.append("</ul>")
                    if len(sources) > 5:
                        html.append(f"<p><i>...and {len(sources) - 5} more sources</i></p>")
                    
            elif attack_type.startswith('web_'):
                # Web application attacks
                attack_subtype = attack_details.get('most_common_attack', 'unknown')
                sources = attack_details.get('sources', [])
                attack_types_found = attack_details.get('attack_types_found', [])
                
                html.append(f"<p><b>Primary attack type:</b> {attack_subtype.replace('_', ' ').title()}</p>")
                html.append(f"<p><b>Attack sources:</b> {len(sources)}</p>")
                
                if attack_types_found:
                    html.append("<p><b>Attack types detected:</b></p><ul>")
                    for attack_type in attack_types_found:
                        html.append(f"<li>{attack_type.replace('_', ' ').title()}</li>")
                    html.append("</ul>")
                
                if sources:
                    html.append("<p><b>Top attackers:</b></p><ul>")
                    for source in sources[:5]:  # Show top 5 sources
                        html.append(f"<li><b>IP:</b> {source['src_ip']}")
                        html.append("<ul>")
                        html.append(f"<li><b>Total attempts:</b> {source['total_attempts']}</li>")
                        
                        if source.get('attack_types'):
                            html.append("<li><b>Attack techniques:</b><ul>")
                            for attack in source['attack_types']:
                                html.append(f"<li>{attack['type'].replace('_', ' ').title()}: {attack['count']} attempts</li>")
                            html.append("</ul></li>")
                        
                        html.append("</ul></li>")
                    html.append("</ul>")
                    if len(sources) > 5:
                        html.append(f"<p><i>...and {len(sources) - 5} more sources</i></p>")
            else:
                # Generic attack details fallback
                html.append(f"<p><b>Attack type:</b> {attack_type}</p>")
                html.append(f"<p><b>Evidence count:</b> {attack_details.get('evidence_count', 0)}</p>")
                
                # Try to display any available information
                for key, value in attack_details.items():
                    if key not in ['type', 'name', 'description', 'severity', 'first_seen', 'last_seen', 
                                   'evidence_count', 'evidence_ids', 'detection_time']:
                        if isinstance(value, (str, int, float, bool)):
                            html.append(f"<p><b>{key.replace('_', ' ').title()}:</b> {value}</p>")
        except Exception as e:
            logger.error(f"Error generating attack stats HTML: {e}")
            html = [f"<p>Error displaying attack details: {e}</p>"]
            
        return "".join(html)
        
    def _update_evidence_list(self, attack_details):
        """Update the evidence list with packet IDs.
        
        Args:
            attack_details: Dictionary with attack details
        """
        self.evidence_list.clear()
        
        # Get evidence packet IDs based on attack type
        evidence_ids = []
        attack_type = attack_details.get('type', '')
        
        if attack_type == 'arp_spoofing':
            evidence_ids = attack_details.get('evidence_ids', [])
        elif attack_type == 'port_scanning':
            most_active = attack_details.get('most_active', {})
            if most_active:
                evidence_ids = most_active.get('evidence_ids', [])
        elif attack_type == 'ddos':
            targets = attack_details.get('targets', [])
            if targets:
                for target in targets:
                    evidence_ids.extend(target.get('evidence_ids', [])[:5])  # First 5 from each target
        elif attack_type == 'dns_poisoning':
            domains = attack_details.get('suspicious_domains', [])
            if domains:
                for domain in domains:
                    evidence_ids.extend(domain.get('evidence_ids', [])[:5])  # First 5 from each domain
        
        # Add to list widget
        if evidence_ids:
            for packet_id in evidence_ids:
                item = QListWidgetItem(f"Packet #{packet_id}")
                item.setData(Qt.UserRole, packet_id)
                self.evidence_list.addItem(item)
        else:
            self.evidence_list.addItem("No evidence packets available")
            
    def view_evidence_packet(self, item):
        """View details of an evidence packet.
        
        Args:
            item: The selected list item
        """
        packet_id = item.data(Qt.UserRole)
        
        if not packet_id:
            return
            
        try:
            # Get packet details from database
            packet = self.database.get_packet_by_id(packet_id)
            
            if packet:
                # Format packet details
                details = "<br>".join([
                    f"<b>ID:</b> {packet['id']}",
                    f"<b>Timestamp:</b> {packet['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')}",
                    f"<b>Protocol:</b> {packet.get('protocol', 'Unknown')}",
                    f"<b>Source IP:</b> {packet.get('src_ip', 'N/A')}",
                    f"<b>Destination IP:</b> {packet.get('dst_ip', 'N/A')}",
                    f"<b>Source Port:</b> {packet.get('src_port', 'N/A')}",
                    f"<b>Destination Port:</b> {packet.get('dst_port', 'N/A')}",
                    f"<b>Length:</b> {packet.get('length', 0)} bytes",
                    f"<b>Info:</b> {packet.get('info', 'N/A')}"
                ])
                
                # Show packet details dialog
                QMessageBox.information(
                    self,
                    f"Packet #{packet_id} Details",
                    details
                )
            else:
                QMessageBox.warning(
                    self,
                    "Packet Not Found",
                    f"Packet #{packet_id} not found in the database."
                )
                
        except Exception as e:
            logger.error(f"Error viewing packet {packet_id}: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Error viewing packet: {str(e)}"
            )
    
    def get_detected_attacks(self):
        """Get the list of detected attacks.
        
        Returns:
            List of attack details dictionaries
        """
        return self.recognizer.get_attack_history() 