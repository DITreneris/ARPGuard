---
version: 10
last_modified: '2025-04-06T07:28:37.726618'
git_history:
- hash: 6a86e9ce0eddba890b90c8b1f9c8d192aaedae82
  author: User
  date: '2025-04-06T07:06:49+03:00'
  message: 'Initial commit: ARPGuard project with ML KPI monitoring system'
- hash: ef3989ccbe50479c66e030aaee698d8d2e12ac0d
  author: User
  date: '2025-04-06T06:36:00+03:00'
  message: Initial commit
- hash: 9084c731e73afe38f3a7b9ad5028d553d3efa4eb
  author: DITreneris
  date: '2025-04-06T06:16:52+03:00'
  message: 'Initial commit: Project setup with ML components'
---

# Machine Learning Integration in ARPGuard

This document explains how ARPGuard's machine learning (ML) components are integrated with the main application.

## Architecture Overview

The ML integration consists of the following components:

1. **ARPGuardML API**: Core ML functionality implemented in `app/ml/api.py`, providing a unified interface for all ML models.
2. **ML Components**: Individual ML models for traffic prediction, resource optimization, and anomaly detection.
3. **ML Integration Layer**: Bridge between ARPGuardML API and the main application, located in `app/components/ml_integration.py`.
4. **ML Controller**: Manages ML operations including data collection, training, and inference, located in `app/components/ml_controller.py`.
5. **ML View**: UI component for visualizing and interacting with ML features, located in `app/components/ml_view.py`.

## Data Flow

1. The application collects network packets and system metrics
2. Data is processed by the ML Integration Layer
3. ML models analyze the data and provide predictions
4. Results are integrated with traditional threat detection mechanisms
5. UI components visualize ML insights and allow user interaction

## Component Interactions

```
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│   MainWindow  │────▶│  MLController │────▶│ MLIntegration │
└───────┬───────┘     └───────┬───────┘     └───────┬───────┘
        │                     │                     │
        │                     │                     │
┌───────▼───────┐     ┌───────▼───────┐     ┌───────▼───────┐
│  ThreatDetector│◀───▶│    MLView    │     │   ARPGuardML  │
└───────────────┘     └───────────────┘     └───────────────┘
```

## Key Integration Points

### 1. MainWindow Initialization

The main application initializes ML components during startup:

```python
# Initialize ML controller
self.ml_controller = MLController()

# Connect ML components
self._connect_ml_components()
```

### 2. ML and Traditional Threat Detection Integration

The traditional threat detector is enhanced with ML capabilities:

```python
# If ML controller is available, enhance detection with ML
if self.ml_controller:
    ml_result = self.ml_controller.process_packet(packet)
    # Combine traditional and ML results
    combined_threat = max(
        result.get('threat_probability', 0), 
        ml_result.get('threat_probability', 0)
    )
```

### 3. ML API Integration

The ARPGuardML API is used through the ML Integration layer:

```python
# Initialize the ML API
self.ml_api = ARPGuardML(
    model_dir=model_dir,
    output_dir=output_dir,
    metrics_window=100
)
```

## Available ML Models

1. **LSTM Traffic Predictor**: Forecasts network traffic patterns using LSTM neural networks.
   - Helps identify abnormal traffic patterns
   - Enables proactive resource allocation

2. **Resource Usage Optimizer**: Optimizes system resource allocation using a combination of Random Forest and Gradient Boosting.
   - Reduces resource waste
   - Improves system performance under load

3. **Anomaly Detection System**: Identifies unusual patterns in system and network behavior using autoencoders.
   - Detects zero-day attacks
   - Identifies subtle system compromises
   - Provides explainable anomaly detection

## Using ML Features

### From the UI

1. Navigate to the "Machine Learning" tab in the main application
2. View current ML metrics and predictions
3. Manually trigger data collection or model training
4. Visualize performance metrics and anomaly detection results

### Programmatically

```python
# Get ML controller instance
ml_controller = app_instance.ml_controller

# Process a packet through ML
result = ml_controller.process_packet(packet_data)

# Predict future traffic
traffic_prediction = ml_controller.predict_traffic(hours_ahead=2)

# Detect anomalies in the system
is_anomaly, scores, explanations = ml_controller.detect_anomalies()

# Optimize resource allocation
optimized_resources = ml_controller.optimize_resources({
    'max_cpu': 0.8,
    'max_memory': 0.7
})
```

## Training Models

Models can be trained in several ways:

1. **Automatic training**: The ML controller can automatically train models when sufficient data is available.
2. **Manual training**: Users can trigger training from the ML View UI.
3. **Command-line training**: Run `python run.py ml --train` to train all models.

## Configuration

ML behavior can be configured in the main application settings:

- `ml.start_on_launch`: Automatically start ML controller on application launch
- `ml.collection_interval`: Interval (in seconds) for collecting metrics
- `ml.automatic_training`: Enable/disable automatic model training
- `ml.training_interval`: Interval (in seconds) between training sessions
- `ml.min_training_samples`: Minimum number of samples required for training 