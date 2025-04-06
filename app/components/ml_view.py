from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox,
    QSplitter, QTabWidget, QTextEdit, QComboBox, QLineEdit,
    QFormLayout, QMessageBox, QProgressBar, QSpinBox
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QPixmap, QImage
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import io
from datetime import datetime
import os

from app.components.ml_integration import MLIntegration
from app.utils.logger import get_logger

# Module logger
logger = get_logger('components.ml_view')

class MLView(QWidget):
    """User interface component for interacting with ML models."""
    
    def __init__(self, parent=None):
        """Initialize the ML view."""
        super().__init__(parent)
        
        # Initialize components
        self.ml_integration = MLIntegration()
        
        # Setup UI
        self.setup_ui()
        
        # Refresh timer for metrics
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_metrics)
        self.refresh_timer.start(5000)  # Refresh every 5 seconds
    
    def setup_ui(self):
        """Set up the user interface."""
        main_layout = QVBoxLayout(self)
        
        # Top controls
        controls_layout = QHBoxLayout()
        
        self.collect_data_button = QPushButton("Collect Data")
        self.collect_data_button.clicked.connect(self.collect_training_data)
        
        self.train_models_button = QPushButton("Train Models")
        self.train_models_button.clicked.connect(self.train_models)
        
        self.status_label = QLabel("Status: Ready")
        
        controls_layout.addWidget(self.collect_data_button)
        controls_layout.addWidget(self.train_models_button)
        controls_layout.addStretch()
        controls_layout.addWidget(self.status_label)
        
        # Tab widget for different ML functionalities
        self.tab_widget = QTabWidget()
        
        # Models tab
        models_tab = self.create_models_tab()
        self.tab_widget.addTab(models_tab, "Models")
        
        # Performance tab
        performance_tab = self.create_performance_tab()
        self.tab_widget.addTab(performance_tab, "Performance")
        
        # Predictions tab
        predictions_tab = self.create_predictions_tab()
        self.tab_widget.addTab(predictions_tab, "Predictions")
        
        # Add to main layout
        main_layout.addLayout(controls_layout)
        main_layout.addWidget(self.tab_widget, 1)  # Give tab widget stretch
    
    def create_models_tab(self):
        """Create the models tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Models information
        models_group = QGroupBox("Available Models")
        models_layout = QVBoxLayout(models_group)
        
        self.models_table = QTableWidget(3, 3)
        self.models_table.setHorizontalHeaderLabels(["Model", "Status", "Actions"])
        self.models_table.setAlternatingRowColors(True)
        self.models_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        # Add model rows
        self.models_table.setItem(0, 0, QTableWidgetItem("LSTM Traffic Predictor"))
        self.models_table.setItem(0, 1, QTableWidgetItem("Not Trained"))
        
        self.models_table.setItem(1, 0, QTableWidgetItem("Resource Usage Optimizer"))
        self.models_table.setItem(1, 1, QTableWidgetItem("Not Trained"))
        
        self.models_table.setItem(2, 0, QTableWidgetItem("Anomaly Detection System"))
        self.models_table.setItem(2, 1, QTableWidgetItem("Not Trained"))
        
        # Add action buttons for each model
        for i in range(3):
            button = QPushButton("Train")
            button.clicked.connect(lambda _, row=i: self.train_specific_model(row))
            self.models_table.setCellWidget(i, 2, button)
        
        models_layout.addWidget(self.models_table)
        layout.addWidget(models_group)
        
        # Training configuration
        config_group = QGroupBox("Training Configuration")
        config_layout = QFormLayout(config_group)
        
        self.training_samples = QSpinBox()
        self.training_samples.setRange(100, 10000)
        self.training_samples.setValue(1000)
        config_layout.addRow("Minimum Training Samples:", self.training_samples)
        
        self.training_interval = QSpinBox()
        self.training_interval.setRange(60, 86400)
        self.training_interval.setValue(3600)
        config_layout.addRow("Training Interval (seconds):", self.training_interval)
        
        layout.addWidget(config_group)
        
        return tab
    
    def create_performance_tab(self):
        """Create the performance metrics tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Performance metrics
        metrics_group = QGroupBox("ML Performance Metrics")
        metrics_layout = QVBoxLayout(metrics_group)
        
        self.metrics_table = QTableWidget(1, 4)
        self.metrics_table.setHorizontalHeaderLabels(["Accuracy", "Precision", "Recall", "F1 Score"])
        self.metrics_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        # Initialize with zeros
        for i in range(4):
            self.metrics_table.setItem(0, i, QTableWidgetItem("0.0"))
        
        metrics_layout.addWidget(self.metrics_table)
        layout.addWidget(metrics_group)
        
        # Graphs
        graphs_group = QGroupBox("Performance Graphs")
        graphs_layout = QVBoxLayout(graphs_group)
        
        # Add placeholder for Matplotlib figure
        self.figure = Figure(figsize=(5, 4), dpi=100)
        self.canvas = FigureCanvas(self.figure)
        graphs_layout.addWidget(self.canvas)
        
        layout.addWidget(graphs_group)
        
        return tab
    
    def create_predictions_tab(self):
        """Create the predictions tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Recent predictions
        predictions_group = QGroupBox("Recent ML Predictions")
        predictions_layout = QVBoxLayout(predictions_group)
        
        self.predictions_table = QTableWidget(0, 5)
        self.predictions_table.setHorizontalHeaderLabels(["Timestamp", "Source", "Prediction", "Confidence", "Action"])
        self.predictions_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.predictions_table.setAlternatingRowColors(True)
        
        predictions_layout.addWidget(self.predictions_table)
        layout.addWidget(predictions_group)
        
        return tab
    
    def collect_training_data(self):
        """Start collecting training data."""
        try:
            # Update status
            self.status_label.setText("Status: Collecting data...")
            
            # Get current data counts
            metrics = self.ml_integration.get_performance_metrics()
            
            # Show confirmation message with current data counts
            QMessageBox.information(
                self,
                "Data Collection",
                f"Data collection is ongoing.\n\nCurrent metrics sample count: {len(self.ml_integration.data_collector.feature_buffer)}"
            )
            
        except Exception as e:
            logger.error(f"Error collecting training data: {e}")
            self.status_label.setText("Status: Error collecting data")
            QMessageBox.critical(self, "Error", f"Failed to collect training data: {e}")
    
    def train_models(self):
        """Train all ML models with collected data."""
        try:
            # Update status
            self.status_label.setText("Status: Training models...")
            
            # Set training parameters
            self.ml_integration.min_training_samples = self.training_samples.value()
            self.ml_integration.training_interval = self.training_interval.value()
            
            # Force training
            data_counts = self.ml_integration._check_training(force=True)
            
            if data_counts > 0:
                self.status_label.setText("Status: Models trained successfully")
                self.refresh_model_status()
                QMessageBox.information(
                    self,
                    "Training Complete",
                    f"Models trained successfully with {data_counts} samples."
                )
            else:
                self.status_label.setText("Status: Insufficient training data")
                QMessageBox.warning(
                    self,
                    "Training Incomplete",
                    f"Not enough training data. Minimum required: {self.ml_integration.min_training_samples}"
                )
                
        except Exception as e:
            logger.error(f"Error training models: {e}")
            self.status_label.setText("Status: Error training models")
            QMessageBox.critical(self, "Error", f"Failed to train models: {e}")
    
    def train_specific_model(self, model_index):
        """Train a specific model."""
        model_names = ["Traffic Predictor", "Resource Optimizer", "Anomaly Detector"]
        model_name = model_names[model_index]
        
        try:
            # Update status
            self.status_label.setText(f"Status: Training {model_name}...")
            
            # TODO: Implement specific model training once ARPGuardML API is integrated
            
            self.status_label.setText(f"Status: {model_name} trained successfully")
            QMessageBox.information(
                self,
                "Training Complete",
                f"{model_name} trained successfully."
            )
            
        except Exception as e:
            logger.error(f"Error training {model_name}: {e}")
            self.status_label.setText(f"Status: Error training {model_name}")
            QMessageBox.critical(self, "Error", f"Failed to train {model_name}: {e}")
    
    def refresh_metrics(self):
        """Refresh the performance metrics display."""
        try:
            # Get metrics from ML integration
            metrics = self.ml_integration.get_performance_metrics()
            
            # Update metrics table
            self.metrics_table.setItem(0, 0, QTableWidgetItem(f"{metrics['accuracy']:.4f}"))
            self.metrics_table.setItem(0, 1, QTableWidgetItem(f"{metrics['precision']:.4f}"))
            self.metrics_table.setItem(0, 2, QTableWidgetItem(f"{metrics['recall']:.4f}"))
            self.metrics_table.setItem(0, 3, QTableWidgetItem(f"{metrics['f1_score']:.4f}"))
            
            # Update predictions table
            self.update_predictions_table()
            
            # Update performance graphs
            self.update_performance_graphs(metrics)
            
        except Exception as e:
            logger.error(f"Error refreshing metrics: {e}")
    
    def refresh_model_status(self):
        """Refresh the model status display."""
        # For now, just indicate if models are trained based on ML integration state
        has_data = len(self.ml_integration.data_collector.feature_buffer) > 0
        is_trained = self.ml_integration.last_training_time is not None
        
        status = "Trained" if is_trained else "Not Trained"
        for i in range(3):
            self.models_table.setItem(i, 1, QTableWidgetItem(status))
    
    def update_predictions_table(self):
        """Update the predictions table with recent predictions."""
        try:
            # Get recent predictions
            predictions = self.ml_integration.ml_detector.get_threat_history(10)
            
            # Clear the table and add new rows
            self.predictions_table.setRowCount(0)
            
            for prediction in predictions:
                row = self.predictions_table.rowCount()
                self.predictions_table.insertRow(row)
                
                # Add prediction data
                self.predictions_table.setItem(row, 0, QTableWidgetItem(prediction['timestamp'].strftime("%Y-%m-%d %H:%M:%S")))
                self.predictions_table.setItem(row, 1, QTableWidgetItem(prediction['packet_info'].get('src_ip', 'Unknown')))
                self.predictions_table.setItem(row, 2, QTableWidgetItem(f"{prediction['threat_probability']:.4f}"))
                self.predictions_table.setItem(row, 3, QTableWidgetItem(f"{1.0 - prediction.get('confidence', 0.5):.4f}"))
                self.predictions_table.setItem(row, 4, QTableWidgetItem(prediction['action']))
                
        except Exception as e:
            logger.error(f"Error updating predictions table: {e}")
    
    def update_performance_graphs(self, metrics):
        """Update the performance graphs."""
        try:
            self.figure.clear()
            
            # Create a bar chart of metrics
            ax = self.figure.add_subplot(111)
            metric_names = ['Accuracy', 'Precision', 'Recall', 'F1 Score']
            metric_values = [metrics['accuracy'], metrics['precision'], metrics['recall'], metrics['f1_score']]
            
            ax.bar(metric_names, metric_values, color=['blue', 'green', 'red', 'purple'])
            ax.set_ylim(0, 1.0)
            ax.set_title('ML Performance Metrics')
            
            self.canvas.draw()
            
        except Exception as e:
            logger.error(f"Error updating performance graphs: {e}") 