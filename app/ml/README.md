# ARPGuard Machine Learning Component

This directory contains the machine learning components for the ARPGuard project, focusing on traffic prediction, resource optimization, and anomaly detection.

## Directory Structure

- **models/** - ML model implementations
  - `lstm_traffic_predictor.py` - LSTM model for network traffic prediction
  - `resource_optimizer.py` - Random Forest/Gradient Boosting for resource usage optimization
  - `anomaly_detector.py` - Autoencoder for anomaly detection
  
- **features/** - Feature engineering and data collection
  - `performance_metrics.py` - Collects and manages performance metrics
  - `preprocessor.py` - Handles data preprocessing for ML models
  
- **pipeline/** - Training pipelines and data flow
  - `model_trainer.py` - Standardized model training pipeline
  
- **utils/** - Utility functions and helpers
  - `evaluation.py` - Model evaluation metrics and visualization
  
- **tests/** - Unit and integration tests
  - `test_performance_metrics.py` - Tests for the metrics collector
  - `test_resource_optimizer.py` - Tests for the resource optimizer
  - `test_anomaly_detector.py` - Tests for the anomaly detector
  - `test_integration.py` - Integration tests for the full pipeline

## Getting Started

1. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Collect performance metrics:
   ```python
   from app.ml.features.performance_metrics import PerformanceMetrics
   
   # Initialize collector
   metrics = PerformanceMetrics(window_size=100)
   
   # Collect metrics
   for _ in range(50):
       metrics.collect_metrics()
   
   # Convert to DataFrame
   df = metrics.get_metrics_dataframe()
   ```

3. Preprocess data:
   ```python
   from app.ml.features.preprocessor import PerformancePreprocessor
   
   preprocessor = PerformancePreprocessor()
   X, y = preprocessor.preprocess(df, target_column='network_traffic')
   ```

4. Train a model (e.g., LSTM Traffic Predictor):
   ```python
   from app.ml.models.lstm_traffic_predictor import LSTMTrafficPredictor
   from app.ml.pipeline.model_trainer import ModelTrainer
   
   # Initialize model
   model = LSTMTrafficPredictor(input_dim=X.shape[1])
   
   # Create trainer
   trainer = ModelTrainer(model, output_dir='output')
   
   # Train and evaluate
   history, metrics = trainer.train_and_evaluate(X, y)
   ```

5. Evaluate model:
   ```python
   from app.ml.utils.evaluation import ModelEvaluator
   
   evaluator = ModelEvaluator()
   report_dir = evaluator.generate_evaluation_report(
       model_name="LSTM_Traffic_Predictor",
       metrics=metrics,
       y_true=y_test,
       y_pred=y_pred
   )
   ```

## Running Tests

Run the test suite:
```
pytest app/ml/tests/
```

## Models

### LSTM Traffic Predictor

The LSTM Traffic Predictor uses a stacked LSTM architecture to forecast network traffic patterns. It takes a sequence of performance metrics and predicts future network traffic levels.

Key features:
- Configurable number of LSTM layers and units
- Early stopping and model checkpointing
- Comprehensive evaluation metrics

Example usage:
```python
from app.ml.models.lstm_traffic_predictor import LSTMTrafficPredictor

# Initialize
model = LSTMTrafficPredictor(
    input_dim=5,  # Number of features
    sequence_length=24,  # Number of time steps
    lstm_units=[64, 32]  # Two LSTM layers with 64 and 32 units
)

# Train
model.train(X_train, y_train, X_val, y_val, epochs=50)

# Predict
predictions = model.predict(X_test)

# Evaluate
metrics = model.evaluate(X_test, y_test)
```

### Resource Usage Optimizer

The Resource Usage Optimizer combines Random Forest and Gradient Boosting models to predict and optimize resource allocation based on performance metrics.

Key features:
- Multiple mode options: Random Forest, Gradient Boosting, or Ensemble
- Supports multi-output prediction for multiple resource types
- Resource constraint handling
- Feature importance analysis

Example usage:
```python
from app.ml.models.resource_optimizer import ResourceUsageOptimizer

# Initialize
optimizer = ResourceUsageOptimizer(
    mode='ensemble',  # Use both RF and GB
    n_estimators=100,
    multi_output=True  # For multiple resource metrics
)

# Train
optimizer.train(
    X_train=features,
    y_train=targets,
    feature_names=['cpu_load', 'memory_usage', 'request_rate'],
    target_names=['cpu_allocation', 'memory_allocation']
)

# Predict
predictions = optimizer.predict(new_features)

# Optimize with constraints
constraints = {
    'cpu_allocation': {'min': 0.2, 'max': 0.8},
    'memory_allocation': {'min': 0.3, 'max': 0.9}
}
optimized, details = optimizer.optimize_resources(new_features, constraints)

# Get feature importance
importance = optimizer.get_feature_importance()
```

### Anomaly Detection System

The Anomaly Detection System uses an autoencoder architecture to detect anomalies in system performance metrics.

Key features:
- Customizable encoding architecture
- Automatic threshold determination
- Feature-level anomaly explanation
- Visualization of anomalies
- Integration with labeled anomaly data for supervised evaluation

Example usage:
```python
from app.ml.models.anomaly_detector import AnomalyDetector

# Initialize
detector = AnomalyDetector(
    input_dim=5,  # Number of features
    encoding_dims=[32, 16, 8],  # Three encoding layers
    threshold_multiplier=3.0  # How many standard deviations for threshold
)

# Train (using only normal data)
detector.train(
    X_train=normal_data,
    feature_names=['cpu', 'memory', 'network', 'disk', 'temperature']
)

# Detect anomalies
anomalies, scores = detector.detect_anomalies(test_data)

# Explain which features contributed to anomalies
explanation = detector.explain_anomalies(test_data)

# Visualize anomalies
detector.plot_anomalies(
    X=test_data, 
    timestamps=timestamps,
    save_path="anomaly_plot.png"
)
``` 