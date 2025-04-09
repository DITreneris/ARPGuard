# Machine Learning Based Detection Layer

ARPGuard implements a sophisticated machine learning-based detection layer that complements its rule-based detection capabilities. This hybrid approach provides enhanced detection of sophisticated ARP-based attacks that may evade traditional rule-based systems.

## Overview

The ML detection layer consists of two primary detection mechanisms:

1. **Anomaly Detection**: Identifies packets that deviate from normal network behavior without specific knowledge of attack types.
2. **Attack Classification**: Classifies packets into specific attack categories (spoofing, MITM, DoS, reconnaissance).

These mechanisms work together to provide comprehensive protection against known and zero-day ARP-based threats.

## Architecture

The ML detection system consists of the following components:

### MLController

The central controller that manages the ML detection pipeline:

- Coordinates feature extraction and ML processing
- Tracks detection statistics and history
- Manages model training and storage
- Provides API for integration with the main application

### MLEngine

The core machine learning engine that implements detection algorithms:

- Anomaly detection using Isolation Forest
- Attack classification using Random Forest
- Feature importance tracking
- Model serialization and deserialization

### FeatureExtractor

Extracts numerical features from ARP packets for model input:

- Basic packet features (operation type, hardware/protocol types)
- Temporal features (packet rates, request/reply ratios)
- Relationship features (IP-MAC mappings, new mapping detection)
- Network features (special network detection, subnet analysis)

## Feature Extraction

The ML system extracts over 25 features from each ARP packet, including:

| Feature Category | Examples |
|------------------|----------|
| Basic Packet Features | Operation type, hardware type, protocol type, packet completeness |
| Broadcast Features | Is broadcast, reply to broadcast, gratuitous ARP |
| Temporal Features | Packet rate, request/reply ratio, unique IP/MAC counts |
| Relationship Features | IP-MAC mapping counts, new mapping detection |
| Network Features | Special network detection, subnet matching |

These features capture both individual packet characteristics and contextual information about the network state.

## Detection Methods

### Anomaly Detection

The anomaly detection system:

- Uses Isolation Forest algorithm trained on benign traffic
- Identifies statistical outliers in feature space
- Calculates an anomaly score for each packet
- Flags packets with high anomaly scores
- Performs well against zero-day/unknown attacks

### Attack Classification

The classification system:

- Uses Random Forest classifier
- Trained on labeled datasets of different attack types
- Differentiates between different attack categories
- Provides confidence scores for each prediction
- Assigns appropriate severity levels based on attack type

## Training and Sample Data

The ML models can be trained using:

1. Pre-packaged sample data for common attack types
2. Custom datasets collected in your environment
3. Automated training based on confirmed detections

Sample data is provided for the following categories:
- Benign ARP traffic
- ARP spoofing attacks
- Man-in-the-Middle attacks
- Denial of Service attacks
- Network reconnaissance

## Integration with Rule-Based Detection

The ML detection layer complements rule-based detection by:

- Detecting subtle variations of known attacks
- Identifying anomalous behavior without explicit rules
- Providing confidence scores alongside binary detections
- Adapting to your network's specific traffic patterns

## Usage Examples

### Programmatic Access

```python
from app.ml import MLController

# Initialize controller
ml_controller = MLController()

# Process a packet
packet = {
    "op": 2,  # ARP reply
    "src_mac": "00:11:22:33:44:55",
    "dst_mac": "ff:ff:ff:ff:ff:ff",
    "src_ip": "192.168.1.1",
    "dst_ip": "192.168.1.100",
    "hw_type": 1,
    "proto_type": 0x0800,
    "hw_len": 6,
    "proto_len": 4
}

# Get detection results
result = ml_controller.process_packet(packet)

# Check for detections
if result["detections"]:
    for detection in result["detections"]:
        print(f"Detection: {detection['evidence']['detection_type']}")
        print(f"Confidence: {detection['confidence']}")
        print(f"Severity: {detection['severity']}")
```

### GUI Interface

ARPGuard provides a dedicated UI for the ML detection layer, accessible through the main application interface. This UI allows you to:

- View ML detection statistics
- Train models with customizable parameters
- Analyze detection results and contributing features
- Configure detection sensitivity and thresholds
- Export detection reports and visualizations

## Statistics and Reporting

The ML detection layer maintains comprehensive statistics:

- Total packets analyzed
- Detection counts by method and attack type
- False positive/negative rates (when labeled data is available)
- Model performance metrics
- Feature importance analysis

## Configuration Options

The ML detection layer can be configured through the `config.yml` file:

```yaml
ml:
  detection:
    enabled: true
    use_anomaly: true
    use_classification: true
    anomaly_severity: MEDIUM
    min_confidence: 0.7
  training:
    enabled: true
    collect_samples: true
    min_samples: 1000
    interval: 86400  # 1 day in seconds
    clear_after_training: true
```

## Performance Considerations

The ML detection layer is designed to be computationally efficient:

- Feature extraction is optimized for real-time processing
- Models use efficient algorithms suitable for online detection
- Resource usage scales linearly with traffic volume
- Models can be serialized and loaded efficiently

## Extending the ML Layer

The ML system can be extended in several ways:

- Adding new features to the feature extractor
- Implementing new detection algorithms in the ML engine
- Integrating with external ML frameworks
- Adding custom attack type detection

For details on extending the ML layer, see the [Developer Guide](developer_guide.md).

## Troubleshooting

Common issues:

1. **High false positive rate**: Retrain models with more benign samples from your environment
2. **Missed attacks**: Adjust detection thresholds or add samples of missed attack types
3. **Performance issues**: Disable features or adjust sampling rate for high-volume networks

For additional help, see the [Troubleshooting Guide](troubleshooting.md).

## Future Enhancements

Planned enhancements to the ML detection layer include:

- Deep learning models for sequence analysis
- Automatic feature engineering
- Reinforcement learning for adaptive thresholds
- Federated learning across distributed deployments
- Explainable AI techniques for detection reasoning 