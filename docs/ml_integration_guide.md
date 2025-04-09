---
version: 1
last_modified: '2024-04-06T12:00:00.000000'
---

# ML Integration Guide

This guide provides information for developers who want to extend or integrate with ARPGuard's machine learning capabilities.

## Overview

ARPGuard's ML subsystem is designed to be modular, extensible, and accessible through well-defined APIs. This document covers the architecture, API endpoints, integration examples, and extension patterns for working with the ML detection layer.

## Architecture Overview

The ML subsystem consists of the following components:

```
┌────────────────────────────────────────────────────────────────────────────┐
│                             ARPGuard Application                           │
└────────────────┬───────────────────────────────────────────┬───────────────┘
                 │                                           │
    ┌────────────▼───────────┐                 ┌────────────▼───────────┐
    │    Core Application    │                 │    ML Subsystem        │
    │    Components          │◄───Interface────►    Components          │
    └────────────┬───────────┘                 └────────────┬───────────┘
                 │                                          │
        ┌────────▼─────────┐                     ┌──────────▼─────────┐
        │                  │                     │                    │
┌───────▼───────┐  ┌───────▼───────┐    ┌────────▼────────┐  ┌───────▼───────┐
│ Network       │  │ UI            │    │ ML              │  │ ML             │
│ Components    │  │ Components    │    │ Engine          │  │ API            │
└───────┬───────┘  └───────┬───────┘    └────────┬────────┘  └───────┬───────┘
        │                  │                     │                    │
        └──────────────────┴─────────────────────┴────────────────────┘
```

### Key Components

- **ML Engine**: Core machine learning functionality including models, training pipelines, and inference
- **ML API**: Interface for accessing ML functionality programmatically
- **ML Integration**: Bridges the ML subsystem with the core application

## Core Integration Points

ARPGuard offers several ways to integrate with the ML subsystem:

1. **API Integration**: Access ML functionality through the ML API
2. **Event-Based Integration**: Subscribe to ML events and alerts
3. **Model Extension**: Add custom models or feature extractors
4. **Pipeline Integration**: Insert custom processing stages in the ML pipeline

## API Reference

### Python API

The primary interface for ML functionality is the `MLController` class:

```python
from app.ml.controller import MLController

# Initialize the controller
ml_controller = MLController()

# Process a packet
result = ml_controller.process_packet(packet_data)

# Train models
training_results = ml_controller.train_models()

# Get ML status
status = ml_controller.get_status()
```

### REST API Endpoints

ARPGuard also provides REST API endpoints for remote integration:

| Endpoint | Method | Description | Parameters | Returns |
|----------|--------|-------------|------------|---------|
| `/api/ml/status` | GET | Get ML subsystem status | None | JSON status object |
| `/api/ml/analyze` | POST | Analyze packet or traffic | JSON packet data | Analysis results |
| `/api/ml/train` | POST | Trigger model training | Optional training parameters | Training status |
| `/api/ml/models` | GET | List available models | None | Array of model info |
| `/api/ml/models/<id>` | GET | Get specific model info | Model ID | Model details |
| `/api/ml/models/<id>/status` | GET | Get model status | Model ID | Status object |
| `/api/ml/predict` | POST | Make prediction | Feature data | Prediction results |
| `/api/ml/metrics` | GET | Get performance metrics | Time range (optional) | Metrics collection |

### WebSocket Events

ARPGuard emits WebSocket events for real-time integration:

| Event | Description | Payload |
|-------|-------------|---------|
| `ml_detection` | ML detection event | Detection details |
| `ml_training_start` | Training started | Training parameters |
| `ml_training_progress` | Training progress update | Progress percentage and metrics |
| `ml_training_complete` | Training completed | Final metrics and model info |
| `ml_model_loaded` | Model loaded | Model details |
| `ml_error` | Error in ML subsystem | Error details |

## Integration Examples

### Example 1: Processing a Packet

```python
from app.ml.controller import MLController
from app.utils.packet import PacketData

# Initialize controller
ml_controller = MLController()

# Create packet data
packet = PacketData(
    timestamp=1617705600.0,
    src_mac="00:11:22:33:44:55",
    dst_mac="aa:bb:cc:dd:ee:ff",
    src_ip="192.168.1.100",
    dst_ip="192.168.1.1",
    op_code=1,  # ARP request
    hw_type=1,
    proto_type=0x0800,
    hw_len=6,
    proto_len=4
)

# Process the packet
result = ml_controller.process_packet(packet)

if result.is_anomaly:
    print(f"Anomaly detected: {result.anomaly_score}")
    print(f"Attack type: {result.attack_type}")
    print(f"Confidence: {result.confidence}")
```

### Example 2: Custom HTTP Client Integration

```python
import requests
import json

# Base URL for ARPGuard API
API_BASE = "http://localhost:8080/api"

# Authentication (if required)
headers = {
    "Authorization": "Bearer YOUR_API_KEY",
    "Content-Type": "application/json"
}

# Get ML status
response = requests.get(f"{API_BASE}/ml/status", headers=headers)
status = response.json()
print(f"ML Status: {status['state']}")

# Analyze packet
packet_data = {
    "timestamp": 1617705600.0,
    "src_mac": "00:11:22:33:44:55",
    "dst_mac": "aa:bb:cc:dd:ee:ff",
    "src_ip": "192.168.1.100",
    "dst_ip": "192.168.1.1",
    "op_code": 1,
    "hw_type": 1,
    "proto_type": 0x0800,
    "hw_len": 6,
    "proto_len": 4
}

response = requests.post(
    f"{API_BASE}/ml/analyze",
    headers=headers,
    data=json.dumps(packet_data)
)

result = response.json()
print(f"Analysis result: {result}")
```

### Example 3: WebSocket Integration

```javascript
// JavaScript example for WebSocket integration
const socket = new WebSocket('ws://localhost:8080/ws');

socket.onopen = function(e) {
  console.log('WebSocket connection established');
  
  // Subscribe to ML events
  socket.send(JSON.stringify({
    action: 'subscribe',
    channels: ['ml_detection', 'ml_training_complete']
  }));
};

socket.onmessage = function(event) {
  const data = JSON.parse(event.data);
  
  switch(data.event) {
    case 'ml_detection':
      console.log('ML Detection:', data.payload);
      // Update UI or trigger response
      break;
      
    case 'ml_training_complete':
      console.log('ML Training completed:', data.payload);
      // Update model status in UI
      break;
  }
};
```

## Extending ML Functionality

ARPGuard supports several methods for extending the ML functionality:

### 1. Custom Feature Extractors

You can add custom feature extractors to enhance the ML system's ability to detect specific threats:

```python
from app.ml.features.extractor import BaseFeatureExtractor

class CustomFeatureExtractor(BaseFeatureExtractor):
    """Custom feature extractor for specialized detection."""
    
    def __init__(self):
        super().__init__()
        self.name = "custom_extractor"
        
    def extract_features(self, packet):
        """Extract custom features from packet."""
        features = {}
        
        # Add basic feature extraction
        features.update(super().extract_features(packet))
        
        # Add custom features
        features['custom_ratio'] = self._calculate_custom_ratio(packet)
        features['specialized_score'] = self._specialized_analysis(packet)
        
        return features
        
    def _calculate_custom_ratio(self, packet):
        """Calculate a custom ratio for detection."""
        # Custom calculation logic
        return ratio
        
    def _specialized_analysis(self, packet):
        """Perform specialized analysis for this packet."""
        # Specialized analysis logic
        return score
        
# Register the custom extractor
from app.ml.registry import register_feature_extractor
register_feature_extractor("custom", CustomFeatureExtractor)
```

### 2. Custom Models

You can add custom models to the ML system:

```python
from app.ml.models.base import BaseModel
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

class CustomAnomalyDetector(BaseModel):
    """Custom anomaly detection model."""
    
    def __init__(self, config=None):
        super().__init__(config or {})
        self.name = "custom_anomaly_detector"
        self.model = None
        
    def train(self, features, labels=None):
        """Train the anomaly detection model."""
        # Configure model parameters
        n_estimators = self.config.get('n_estimators', 100)
        contamination = self.config.get('contamination', 0.1)
        
        # Initialize and train model
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=42
        )
        
        # For anomaly detection, we don't need labels
        self.model.fit(features)
        
        # Return training metrics
        return {
            'status': 'success',
            'model_type': 'isolation_forest',
            'n_samples': len(features)
        }
        
    def predict(self, features):
        """Predict anomalies."""
        if self.model is None:
            raise RuntimeError("Model not trained or loaded")
            
        # Get raw predictions (-1 for anomalies, 1 for normal)
        raw_predictions = self.model.predict(features)
        
        # Get decision scores
        scores = self.model.decision_function(features)
        
        # Convert to normalized anomaly scores (0-1 where 1 is anomalous)
        anomaly_scores = 1 - (scores + 0.5)  # Normalize from decision_function
        anomaly_scores = np.clip(anomaly_scores, 0, 1)  # Ensure 0-1 range
        
        # Create result dictionary
        results = {
            'is_anomaly': [p == -1 for p in raw_predictions],
            'anomaly_score': anomaly_scores.tolist(),
            'raw_scores': scores.tolist()
        }
        
        return results
        
    def save(self, path):
        """Save model to disk."""
        if self.model is None:
            raise RuntimeError("No model to save")
            
        model_data = {
            'model': self.model,
            'config': self.config,
            'metadata': {
                'name': self.name,
                'version': self.version,
                'created_at': datetime.now().isoformat()
            }
        }
        
        joblib.dump(model_data, path)
        
    def load(self, path):
        """Load model from disk."""
        model_data = joblib.load(path)
        self.model = model_data['model']
        self.config = model_data['config']
        
        return True

# Register the custom model
from app.ml.registry import register_model
register_model("custom_anomaly", CustomAnomalyDetector)
```

### 3. Custom Processing Pipeline

You can create custom processing pipelines:

```python
from app.ml.pipeline.base import BasePipeline
from app.ml.registry import get_feature_extractor, get_model

class CustomPipeline(BasePipeline):
    """Custom processing pipeline for specialized detection."""
    
    def __init__(self, config=None):
        super().__init__(config or {})
        self.name = "custom_pipeline"
        
        # Initialize components
        self.feature_extractor = get_feature_extractor(
            self.config.get('feature_extractor', 'default')
        )
        
        self.anomaly_model = get_model(
            self.config.get('anomaly_model', 'isolation_forest')
        )
        
        self.classification_model = get_model(
            self.config.get('classification_model', 'random_forest')
        )
        
    def process(self, packet):
        """Process a packet through the pipeline."""
        # Extract features
        features = self.feature_extractor.extract_features(packet)
        
        # Preprocess features
        preprocessed = self._preprocess_features(features)
        
        # Run anomaly detection
        anomaly_result = self.anomaly_model.predict([preprocessed])[0]
        
        # If anomalous, run classification
        if anomaly_result['is_anomaly']:
            class_result = self.classification_model.predict([preprocessed])[0]
        else:
            class_result = {'class': 'normal', 'probability': 1.0}
        
        # Combine results
        result = {
            'is_anomaly': anomaly_result['is_anomaly'],
            'anomaly_score': anomaly_result['anomaly_score'],
            'attack_type': class_result['class'],
            'confidence': class_result['probability'],
            'features': features
        }
        
        return result
        
    def _preprocess_features(self, features):
        """Preprocess features for models."""
        # Apply preprocessing steps
        # ... preprocessing code ...
        return preprocessed_features

# Register the custom pipeline
from app.ml.registry import register_pipeline
register_pipeline("custom", CustomPipeline)
```

## Configuration

The ML subsystem can be configured through the `config/ml_config.yml` file:

```yaml
# Main ML configuration
ml:
  enabled: true
  auto_start: true
  default_pipeline: "hybrid"
  
  # Data collection settings
  data_collection:
    enabled: true
    save_packets: true
    max_samples: 10000
    
  # Training settings
  training:
    auto_train: true
    min_samples: 1000
    training_interval: 86400  # 24 hours
    
  # Detection settings
  detection:
    anomaly_threshold: 0.7
    classification_threshold: 0.8
    max_detections: 1000
    
  # Model settings
  models:
    anomaly:
      type: "isolation_forest"
      parameters:
        n_estimators: 100
        contamination: 0.1
    classification:
      type: "random_forest"
      parameters:
        n_estimators: 100
        max_depth: 10
        
  # Pipeline settings
  pipelines:
    hybrid:
      feature_extractor: "arp"
      anomaly_model: "isolation_forest"
      classification_model: "random_forest"
```

## Best Practices

When integrating with or extending ARPGuard's ML capabilities, follow these best practices:

1. **Performance Monitoring**: Always monitor the performance impact of ML components
2. **Model Versioning**: Use proper versioning for models and feature extractors
3. **Error Handling**: Implement robust error handling for ML operations
4. **Testing**: Create thorough tests for custom ML components
5. **Documentation**: Document the purpose and behavior of custom components
6. **Incremental Development**: Make small, incremental changes and verify each step
7. **Feature Isolation**: Keep feature extraction logic separate from models
8. **Configuration**: Make parameters configurable rather than hardcoding

## Troubleshooting

Common issues and solutions when working with the ML subsystem:

### Model Loading Failures

If models fail to load:

1. Check that model files exist in the expected location
2. Ensure model versions are compatible with the current code
3. Verify that all dependencies are available

### Performance Issues

If ML processing is slow:

1. Reduce feature complexity
2. Implement batch processing
3. Adjust sampling rates
4. Consider model quantization or pruning

### Integration Errors

If integration fails:

1. Check API endpoints and authentication
2. Verify data formats match expected schemas
3. Enable debug logging for more detailed information

## Conclusion

ARPGuard's ML subsystem provides powerful capabilities for network threat detection. By following this integration guide, developers can extend and enhance these capabilities or integrate ARPGuard's ML features with other systems. 