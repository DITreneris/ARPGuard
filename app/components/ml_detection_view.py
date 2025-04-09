"""
GUI component for ML-based detection visualization and management.

This module provides a UI for visualizing ML detection results
and managing the ML detection layer settings.
"""

import os
import time
from datetime import datetime
from typing import Dict, List, Optional, Callable, Any

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                             QLabel, QTabWidget, QTableWidget, QTableWidgetItem,
                             QComboBox, QCheckBox, QHeaderView, QProgressBar,
                             QGroupBox, QFrame, QToolTip, QMessageBox, QSplitter,
                             QScrollArea, QApplication)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer
from PyQt5.QtGui import QColor, QPalette, QBrush, QFont, QIcon

from app.utils.logger import get_logger
from app.utils.config import get_config
from app.ml.controller import MLController

# Module logger
logger = get_logger('components.ml_detection_view')

class MLDetectionView(QWidget):
    """Widget for visualizing and managing ML-based detection."""
    
    def __init__(self, ml_controller: Optional[MLController] = None):
        """Initialize the ML detection view.
        
        Args:
            ml_controller: Optional ML controller instance
        """
        super().__init__()
        self.ml_controller = ml_controller
        self.config = get_config()
        
        # UI setup
        self.init_ui()
        
        # Update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_stats)
        self.update_timer.start(5000)  # Update every 5 seconds
        
        # Load initial data
        self.update_stats()
        
    def init_ui(self):
        """Initialize the user interface."""
        # Main layout
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Title and status
        title_layout = QHBoxLayout()
        
        title_label = QLabel("ML-Based Detection Layer")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        title_layout.addWidget(title_label)
        
        self.status_label = QLabel("Status: Initializing...")
        title_layout.addWidget(self.status_label)
        title_layout.addStretch()
        
        # Control buttons
        self.train_button = QPushButton("Train Models")
        self.train_button.clicked.connect(self.on_train_button_clicked)
        title_layout.addWidget(self.train_button)
        
        main_layout.addLayout(title_layout)
        
        # Tab widget for different views
        self.tab_widget = QTabWidget()
        
        # Overview tab
        overview_tab = QWidget()
        overview_layout = QVBoxLayout(overview_tab)
        
        # Detection stats in overview
        stats_group = QGroupBox("Detection Statistics")
        stats_layout = QVBoxLayout(stats_group)
        
        self.stats_table = QTableWidget(5, 2)
        self.stats_table.setHorizontalHeaderLabels(["Metric", "Value"])
        self.stats_table.verticalHeader().setVisible(False)
        self.stats_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        stats_layout.addWidget(self.stats_table)
        overview_layout.addWidget(stats_group)
        
        # Detection methods status
        methods_group = QGroupBox("Detection Methods")
        methods_layout = QVBoxLayout(methods_group)
        
        # Anomaly detection status
        anomaly_layout = QHBoxLayout()
        anomaly_layout.addWidget(QLabel("Anomaly Detection:"))
        self.anomaly_status = QLabel("Not initialized")
        anomaly_layout.addWidget(self.anomaly_status)
        anomaly_layout.addStretch()
        
        # Classification status
        classification_layout = QHBoxLayout()
        classification_layout.addWidget(QLabel("Classification:"))
        self.classification_status = QLabel("Not initialized")
        classification_layout.addWidget(self.classification_status)
        classification_layout.addStretch()
        
        methods_layout.addLayout(anomaly_layout)
        methods_layout.addLayout(classification_layout)
        overview_layout.addWidget(methods_group)
        
        # Training status
        training_group = QGroupBox("Training Status")
        training_layout = QVBoxLayout(training_group)
        
        # Training progress
        training_status_layout = QHBoxLayout()
        training_status_layout.addWidget(QLabel("Status:"))
        self.training_status_label = QLabel("Not started")
        training_status_layout.addWidget(self.training_status_label)
        training_status_layout.addStretch()
        
        # Sample count
        sample_layout = QHBoxLayout()
        sample_layout.addWidget(QLabel("Collected Samples:"))
        self.sample_count_label = QLabel("0")
        sample_layout.addWidget(self.sample_count_label)
        sample_layout.addStretch()
        
        # Last training
        last_training_layout = QHBoxLayout()
        last_training_layout.addWidget(QLabel("Last Training:"))
        self.last_training_label = QLabel("Never")
        last_training_layout.addWidget(self.last_training_label)
        last_training_layout.addStretch()
        
        training_layout.addLayout(training_status_layout)
        training_layout.addLayout(sample_layout)
        training_layout.addLayout(last_training_layout)
        overview_layout.addWidget(training_group)
        
        # Detections tab
        detections_tab = QWidget()
        detections_layout = QVBoxLayout(detections_tab)
        
        # ML detections table
        self.detections_table = QTableWidget(0, 6)
        self.detections_table.setHorizontalHeaderLabels([
            "Time", "Source IP", "Type", "Confidence", "Severity", "Details"
        ])
        self.detections_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.detections_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.detections_table.setAlternatingRowColors(True)
        
        detections_layout.addWidget(self.detections_table)
        
        # Settings tab
        settings_tab = QWidget()
        settings_layout = QVBoxLayout(settings_tab)
        
        # Detection settings
        detection_settings_group = QGroupBox("Detection Settings")
        detection_settings_layout = QVBoxLayout(detection_settings_group)
        
        # Enable ML detection
        self.enable_ml_checkbox = QCheckBox("Enable ML-based detection")
        self.enable_ml_checkbox.setChecked(self.config.get("ml.detection.enabled", True))
        self.enable_ml_checkbox.stateChanged.connect(self.on_settings_changed)
        detection_settings_layout.addWidget(self.enable_ml_checkbox)
        
        # Enable anomaly detection
        self.enable_anomaly_checkbox = QCheckBox("Enable anomaly detection")
        self.enable_anomaly_checkbox.setChecked(self.config.get("ml.detection.use_anomaly", True))
        self.enable_anomaly_checkbox.stateChanged.connect(self.on_settings_changed)
        detection_settings_layout.addWidget(self.enable_anomaly_checkbox)
        
        # Enable classification
        self.enable_classification_checkbox = QCheckBox("Enable classification")
        self.enable_classification_checkbox.setChecked(self.config.get("ml.detection.use_classification", True))
        self.enable_classification_checkbox.stateChanged.connect(self.on_settings_changed)
        detection_settings_layout.addWidget(self.enable_classification_checkbox)
        
        # Anomaly severity
        severity_layout = QHBoxLayout()
        severity_layout.addWidget(QLabel("Anomaly Severity:"))
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        current_severity = self.config.get("ml.detection.anomaly_severity", "MEDIUM")
        self.severity_combo.setCurrentText(current_severity)
        self.severity_combo.currentTextChanged.connect(self.on_settings_changed)
        severity_layout.addWidget(self.severity_combo)
        severity_layout.addStretch()
        detection_settings_layout.addLayout(severity_layout)
        
        settings_layout.addWidget(detection_settings_group)
        
        # Training settings
        training_settings_group = QGroupBox("Training Settings")
        training_settings_layout = QVBoxLayout(training_settings_group)
        
        # Enable training
        self.enable_training_checkbox = QCheckBox("Enable automatic training")
        self.enable_training_checkbox.setChecked(self.config.get("ml.training.enabled", True))
        self.enable_training_checkbox.stateChanged.connect(self.on_settings_changed)
        training_settings_layout.addWidget(self.enable_training_checkbox)
        
        # Enable sample collection
        self.enable_collection_checkbox = QCheckBox("Enable sample collection")
        self.enable_collection_checkbox.setChecked(self.config.get("ml.training.collect_samples", True))
        self.enable_collection_checkbox.stateChanged.connect(self.on_settings_changed)
        training_settings_layout.addWidget(self.enable_collection_checkbox)
        
        settings_layout.addWidget(training_settings_group)
        settings_layout.addStretch()
        
        # Add tabs
        self.tab_widget.addTab(overview_tab, "Overview")
        self.tab_widget.addTab(detections_tab, "Detections")
        self.tab_widget.addTab(settings_tab, "Settings")
        
        main_layout.addWidget(self.tab_widget)
        
        self.setLayout(main_layout)
        
    def set_ml_controller(self, ml_controller: MLController):
        """Set the ML controller for this view.
        
        Args:
            ml_controller: ML controller instance
        """
        self.ml_controller = ml_controller
        self.update_stats()
        
    def update_stats(self):
        """Update the statistics display."""
        if not self.ml_controller:
            self.status_label.setText("Status: No ML controller available")
            return
            
        try:
            # Get statistics
            stats = self.ml_controller.get_statistics()
            
            # Update overall status
            if stats.get("ml_engine", {}).get("anomaly_stats", {}).get("detector_ready", False) or \
               stats.get("ml_engine", {}).get("classifier_stats", {}).get("classifier_ready", False):
                self.status_label.setText("Status: Ready")
                self.status_label.setStyleSheet("color: green;")
            else:
                self.status_label.setText("Status: Needs Training")
                self.status_label.setStyleSheet("color: orange;")
                
            # Update stats table
            self.stats_table.setItem(0, 0, QTableWidgetItem("Packets Analyzed"))
            self.stats_table.setItem(0, 1, QTableWidgetItem(str(stats["packets_analyzed"])))
            
            self.stats_table.setItem(1, 0, QTableWidgetItem("Total Threats Detected"))
            self.stats_table.setItem(1, 1, QTableWidgetItem(str(stats["threats_detected"])))
            
            self.stats_table.setItem(2, 0, QTableWidgetItem("Rule-Based Detections"))
            rule_hits_sum = sum(stats["rule_hits"].values()) if "rule_hits" in stats else 0
            self.stats_table.setItem(2, 1, QTableWidgetItem(str(rule_hits_sum)))
            
            self.stats_table.setItem(3, 0, QTableWidgetItem("ML-Based Detections"))
            self.stats_table.setItem(3, 1, QTableWidgetItem(str(stats["ml_detections"])))
            
            last_detection = stats.get("last_detection")
            self.stats_table.setItem(4, 0, QTableWidgetItem("Last Detection"))
            self.stats_table.setItem(4, 1, QTableWidgetItem(str(last_detection) if last_detection else "None"))
            
            # Update detection methods status
            ml_engine_stats = stats.get("ml_engine", {})
            
            # Anomaly detection status
            anomaly_stats = ml_engine_stats.get("anomaly_stats", {})
            if anomaly_stats.get("detector_ready", False):
                self.anomaly_status.setText("Ready (Total Detections: {})".format(
                    anomaly_stats.get("total_detections", 0)
                ))
                self.anomaly_status.setStyleSheet("color: green;")
            else:
                self.anomaly_status.setText("Not trained")
                self.anomaly_status.setStyleSheet("color: orange;")
                
            # Classification status
            classifier_stats = ml_engine_stats.get("classifier_stats", {})
            if classifier_stats.get("classifier_ready", False):
                self.classification_status.setText("Ready (Total Detections: {})".format(
                    classifier_stats.get("total_detections", 0)
                ))
                self.classification_status.setStyleSheet("color: green;")
            else:
                self.classification_status.setText("Not trained")
                self.classification_status.setStyleSheet("color: orange;")
                
            # Update training status
            training_status = stats.get("training", {})
            training_in_progress = training_status.get("training_in_progress", False)
            
            if training_in_progress:
                self.training_status_label.setText("In Progress")
                self.training_status_label.setStyleSheet("color: blue;")
                self.train_button.setEnabled(False)
            else:
                self.training_status_label.setText("Idle")
                self.training_status_label.setStyleSheet("color: black;")
                self.train_button.setEnabled(True)
                
            # Update sample count
            collected_samples = training_status.get("collected_samples", 0)
            self.sample_count_label.setText(str(collected_samples))
            
            # Update last training
            last_training = training_status.get("last_training")
            if last_training:
                self.last_training_label.setText(str(last_training))
            else:
                self.last_training_label.setText("Never")
                
            # Update detections table
            self.update_detections_table()
                
        except Exception as e:
            logger.error(f"Error updating ML stats: {e}")
            self.status_label.setText(f"Status: Error updating stats")
            self.status_label.setStyleSheet("color: red;")
            
    def update_detections_table(self):
        """Update the detections table with recent ML detections."""
        if not self.ml_controller:
            return
            
        try:
            # Get recent detections
            detections = self.ml_controller.get_recent_detections(100)
            
            # Filter for ML-based detections only
            ml_detections = [d for d in detections if d.get("type") == "ml_based"]
            
            # Update table
            self.detections_table.setRowCount(len(ml_detections))
            
            for row, detection in enumerate(reversed(ml_detections)):
                # Time
                time_item = QTableWidgetItem(str(detection.get("timestamp")))
                self.detections_table.setItem(row, 0, time_item)
                
                # Source IP
                source_ip = detection.get("evidence", {}).get("source_ip", "Unknown")
                source_item = QTableWidgetItem(source_ip)
                self.detections_table.setItem(row, 1, source_item)
                
                # Type
                if "evidence" in detection and "detection_type" in detection["evidence"]:
                    detection_type = detection["evidence"]["detection_type"]
                else:
                    detection_type = "unknown"
                type_item = QTableWidgetItem(detection_type)
                self.detections_table.setItem(row, 2, type_item)
                
                # Confidence
                confidence = detection.get("confidence", 0.0)
                confidence_item = QTableWidgetItem(f"{confidence:.2f}")
                self.detections_table.setItem(row, 3, confidence_item)
                
                # Severity
                severity = detection.get("severity", "UNKNOWN")
                severity_item = QTableWidgetItem(severity)
                if severity == "CRITICAL":
                    severity_item.setBackground(QBrush(QColor(255, 0, 0, 100)))
                elif severity == "HIGH":
                    severity_item.setBackground(QBrush(QColor(255, 165, 0, 100)))
                elif severity == "MEDIUM":
                    severity_item.setBackground(QBrush(QColor(255, 255, 0, 100)))
                elif severity == "LOW":
                    severity_item.setBackground(QBrush(QColor(0, 255, 0, 100)))
                self.detections_table.setItem(row, 4, severity_item)
                
                # Details
                evidence = detection.get("evidence", {})
                
                # Format details based on detection type
                detail_str = ""
                if "attack_type" in evidence:
                    detail_str += f"Attack: {evidence['attack_type']}\n"
                if "anomaly_score" in evidence:
                    detail_str += f"Anomaly Score: {evidence['anomaly_score']:.2f}\n"
                if "contributing_features" in evidence:
                    top_features = sorted(evidence["contributing_features"].items(), 
                                         key=lambda x: x[1], reverse=True)[:3]
                    detail_str += "Top Features: "
                    for feature, score in top_features:
                        detail_str += f"{feature} ({score:.2f}), "
                    detail_str = detail_str[:-2]  # Remove trailing comma and space
                
                details_item = QTableWidgetItem(detail_str)
                self.detections_table.setItem(row, 5, details_item)
                
        except Exception as e:
            logger.error(f"Error updating ML detections table: {e}")
            
    def on_train_button_clicked(self):
        """Handle the Train button click."""
        if not self.ml_controller:
            QMessageBox.warning(self, "Training Error", "ML controller not available")
            return
            
        reply = QMessageBox.question(
            self, "Train ML Models", 
            "Do you want to train the ML models using sample data?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                # Disable button during training
                self.train_button.setEnabled(False)
                self.train_button.setText("Training...")
                
                # Start training in a separate thread
                QApplication.processEvents()
                
                # Load sample data and train
                result = self.ml_controller.load_sample_data()
                
                if result.get("success", False):
                    QMessageBox.information(self, "Training Complete", "ML models trained successfully")
                else:
                    QMessageBox.warning(self, "Training Error", f"Error training models: {result.get('error', 'Unknown error')}")
                    
            except Exception as e:
                logger.error(f"Error training ML models: {e}")
                QMessageBox.warning(self, "Training Error", f"Error training models: {str(e)}")
            finally:
                # Re-enable button
                self.train_button.setEnabled(True)
                self.train_button.setText("Train Models")
                
                # Update stats
                self.update_stats()
                
    def on_settings_changed(self):
        """Handle settings changes."""
        # Get current settings
        settings = {
            "ml.detection.enabled": self.enable_ml_checkbox.isChecked(),
            "ml.detection.use_anomaly": self.enable_anomaly_checkbox.isChecked(),
            "ml.detection.use_classification": self.enable_classification_checkbox.isChecked(),
            "ml.detection.anomaly_severity": self.severity_combo.currentText(),
            "ml.training.enabled": self.enable_training_checkbox.isChecked(),
            "ml.training.collect_samples": self.enable_collection_checkbox.isChecked()
        }
        
        # Update config (would typically involve saving to a file)
        for key, value in settings.items():
            self.config._data[key] = value
            
        # Apply settings if ML controller is available
        if not self.ml_controller or not hasattr(self.ml_controller, "ml_engine"):
            return
            
        try:
            # Update ML engine configuration
            self.ml_controller.ml_engine.use_anomaly_detection = settings["ml.detection.use_anomaly"]
            self.ml_controller.ml_engine.use_classification = settings["ml.detection.use_classification"]
            self.ml_controller.ml_engine.anomaly_severity = settings["ml.detection.anomaly_severity"]
            
            logger.info("ML detection settings updated")
            
        except Exception as e:
            logger.error(f"Error updating ML settings: {e}")
            QMessageBox.warning(self, "Settings Error", f"Error updating settings: {str(e)}")
            
    def closeEvent(self, event):
        """Handle window close event."""
        # Stop the update timer
        self.update_timer.stop()
        event.accept() 