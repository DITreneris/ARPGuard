"""
ARPGuard ML API Usage Example

This script demonstrates how to use the ARPGuardML API for:
1. Collecting performance metrics
2. Training and using the LSTM Traffic Predictor
3. Training and using the Resource Usage Optimizer
4. Training and using the Anomaly Detection System
"""

import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timedelta

# Add project root to path to ensure imports work
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
if project_root not in sys.path:
    sys.path.append(project_root)

from app.ml.api import ARPGuardML

def main():
    # Initialize the ARPGuard ML API
    ml_api = ARPGuardML(
        base_dir="models",  # Models will be stored in the models/ directory
        output_dir="output",  # Outputs will be stored in the output/ directory
        metrics_window_size=200  # Store up to 200 metrics samples
    )
    
    print("ARPGuard ML API initialized")
    
    # ----- 1. Collect Metrics -----
    
    # For this example, we'll generate synthetic metrics instead of collecting real ones
    print("\n1. Generating synthetic metrics data...")
    metrics_df = generate_synthetic_metrics(1000)
    print(f"Generated {len(metrics_df)} metrics samples")
    print(metrics_df.head())
    
    # Split data for training and testing
    train_size = int(len(metrics_df) * 0.7)
    train_df = metrics_df.iloc[:train_size]
    test_df = metrics_df.iloc[train_size:]
    
    # ----- 2. Traffic Prediction -----
    
    print("\n2. Traffic Prediction Model")
    
    # Initialize the LSTM Traffic Predictor
    traffic_predictor = ml_api.initialize_traffic_predictor(
        input_dim=5,  # Number of input features
        sequence_length=24,  # 24 time steps (e.g., hours) for prediction
        lstm_units=[64, 32]  # Two LSTM layers with 64 and 32 units
    )
    
    # Train the Traffic Predictor
    print("Training traffic predictor...")
    training_results = ml_api.train_traffic_predictor(
        metrics_df=train_df,
        target_column='network_traffic',
        epochs=10,  # Using a small number of epochs for the example
        batch_size=32
    )
    print(f"Training complete - MAE: {training_results['metrics'].get('mae', 'N/A')}")
    
    # Predict traffic
    print("Predicting traffic...")
    prediction_results = ml_api.predict_traffic(
        metrics_df=test_df,
        target_column='network_traffic'
    )
    print(f"Prediction complete - MAE: {prediction_results['metrics'].get('mae', 'N/A')}")
    print(f"Evaluation report saved to: {prediction_results.get('report_dir', 'N/A')}")
    
    # ----- 3. Resource Optimization -----
    
    print("\n3. Resource Optimization Model")
    
    # Initialize the Resource Usage Optimizer
    resource_optimizer = ml_api.initialize_resource_optimizer(
        mode='ensemble',  # Use both Random Forest and Gradient Boosting
        n_estimators=100,
        multi_output=True  # We'll optimize multiple resources
    )
    
    # Define target columns for optimization
    resource_targets = ['cpu_allocation', 'memory_allocation']
    
    # Train the Resource Optimizer
    print("Training resource optimizer...")
    optimizer_results = ml_api.train_resource_optimizer(
        metrics_df=train_df,
        target_columns=resource_targets
    )
    print(f"Training complete - RMSE: {optimizer_results['metrics'].get('rmse', 'N/A')}")
    
    # Print feature importance
    importance = optimizer_results.get('feature_importance', {})
    if 'rf' in importance:
        print("\nFeature Importance (Random Forest):")
        for feature, value in sorted(importance['rf'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {feature}: {value:.4f}")
    
    # Optimize resources with constraints
    constraints = {
        'cpu_allocation': {'min': 0.2, 'max': 0.8},
        'memory_allocation': {'min': 0.3, 'max': 0.9}
    }
    
    print("\nOptimizing resources with constraints...")
    optimization_results = ml_api.optimize_resources(
        metrics_df=test_df,
        target_columns=resource_targets,
        constraints=constraints
    )
    
    optimized_df = optimization_results['optimized_allocations']
    print("Optimized allocations:")
    print(optimized_df.head())
    
    # ----- 4. Anomaly Detection -----
    
    print("\n4. Anomaly Detection System")
    
    # Initialize the Anomaly Detector
    anomaly_detector = ml_api.initialize_anomaly_detector(
        input_dim=5,  # Number of features
        encoding_dims=[16, 8, 4],  # Three encoding layers
        threshold_multiplier=3.0  # Sensitivity for anomaly threshold
    )
    
    # Generate normal data for training (without the injected anomalies)
    normal_df = generate_synthetic_metrics(500, inject_anomalies=False)
    
    # Train the Anomaly Detector (using only normal data)
    print("Training anomaly detector...")
    detector_results = ml_api.train_anomaly_detector(
        normal_metrics_df=normal_df,
        epochs=10,  # Using a small number of epochs for the example
        batch_size=32
    )
    print("Training complete")
    
    # Generate test data with anomalies
    anomaly_test_df = generate_synthetic_metrics(200, inject_anomalies=True)
    
    # Detect anomalies
    print("Detecting anomalies...")
    anomaly_results = ml_api.detect_anomalies(
        metrics_df=anomaly_test_df,
        plot_results=True,
        save_plot=True
    )
    
    print(f"Detected {anomaly_results['anomaly_count']} anomalies")
    print(f"Anomaly plot saved to: {anomaly_results.get('plot_path', 'N/A')}")
    
    # Print anomaly explanation for the first anomaly
    if anomaly_results['explanation']['anomaly_indices'].size > 0:
        idx = anomaly_results['explanation']['anomaly_indices'][0]
        contributions = anomaly_results['explanation']['feature_contributions'][0]
        feature_names = anomaly_test_df.columns.drop('timestamp').tolist()
        
        print("\nTop contributing features for first anomaly:")
        for i, feature in enumerate(feature_names):
            print(f"  {feature}: {contributions[i]:.2%}")
    
    # ----- 5. Save Models -----
    
    print("\n5. Saving Models")
    save_results = ml_api.save_models()
    
    for model, result in save_results.items():
        print(f"  {model}: {'Success' if result else 'Failed'}")
    
    print("\nExample complete!")

def generate_synthetic_metrics(n_samples, inject_anomalies=False):
    """Generate synthetic metrics data for the example."""
    # Start time for timestamps
    start_time = datetime.now() - timedelta(days=n_samples // 24)
    timestamps = [start_time + timedelta(hours=i) for i in range(n_samples)]
    
    # Generate base patterns
    np.random.seed(42)
    hours = np.array([(t.hour + t.minute/60) for t in timestamps])
    days = np.array([t.weekday() for t in timestamps])
    
    # Daily and weekly patterns
    daily_pattern = np.sin(hours * (2 * np.pi / 24)) * 0.5 + 0.5
    weekly_pattern = 0.2 * np.sin(days * (2 * np.pi / 7))
    
    # Generate metrics with patterns and noise
    cpu_usage = 30 + 30 * daily_pattern + 10 * weekly_pattern + np.random.normal(0, 5, n_samples)
    memory_usage = 40 + 20 * daily_pattern + 5 * weekly_pattern + np.random.normal(0, 3, n_samples)
    network_traffic = 1000 + 800 * daily_pattern + 200 * weekly_pattern + np.random.normal(0, 100, n_samples)
    packet_rate = 500 + 400 * daily_pattern + 100 * weekly_pattern + np.random.normal(0, 50, n_samples)
    response_time = 20 + 10 * (1 - daily_pattern) + 5 * weekly_pattern + np.random.normal(0, 2, n_samples)
    
    # Resource allocation metrics (target for optimization)
    cpu_allocation = 0.2 + 0.4 * (cpu_usage / 100) + 0.2 * (network_traffic / 2000) + np.random.normal(0, 0.05, n_samples)
    memory_allocation = 0.3 + 0.3 * (memory_usage / 100) + 0.1 * (packet_rate / 1000) + np.random.normal(0, 0.05, n_samples)
    
    # Clip values to reasonable ranges
    cpu_usage = np.clip(cpu_usage, 0, 100)
    memory_usage = np.clip(memory_usage, 0, 100)
    network_traffic = np.clip(network_traffic, 0, 3000)
    packet_rate = np.clip(packet_rate, 0, 1500)
    response_time = np.clip(response_time, 0, 100)
    cpu_allocation = np.clip(cpu_allocation, 0, 1)
    memory_allocation = np.clip(memory_allocation, 0, 1)
    
    # Inject anomalies if requested
    if inject_anomalies:
        # Inject 5 anomalies at random positions
        for _ in range(5):
            idx = np.random.randint(0, n_samples)
            # Create an anomaly
            cpu_usage[idx:idx+3] *= 2.0  # CPU spike
            memory_usage[idx:idx+3] *= 1.5  # Memory spike
            network_traffic[idx:idx+3] *= 3.0  # Network traffic spike
            response_time[idx:idx+3] *= 2.5  # Response time spike
    
    # Create DataFrame
    return pd.DataFrame({
        'timestamp': timestamps,
        'cpu_usage': cpu_usage,
        'memory_usage': memory_usage,
        'network_traffic': network_traffic,
        'packet_rate': packet_rate,
        'response_time': response_time,
        'cpu_allocation': cpu_allocation,
        'memory_allocation': memory_allocation
    })

if __name__ == "__main__":
    main() 