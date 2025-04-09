---
version: 1
last_modified: '2024-04-06T11:45:00.000000'
---

# Feature Engineering for ML-Based Threat Detection

## Overview

Feature engineering is a critical component of ARPGuard's machine learning system. This document details the methodologies used to extract meaningful features from network traffic, analyze feature importance, and preprocess data for optimal model performance.

## Feature Extraction Methodologies

ARPGuard extracts features across multiple dimensions to enable comprehensive threat detection:

### Packet-Level Features

Features extracted from individual packets:

| Feature Group | Examples | Purpose |
|---------------|----------|---------|
| **Header Fields** | Source/destination MAC, source/destination IP, operation type | Identify communication patterns |
| **Timing** | Timestamp, inter-packet intervals | Detect timing-based attacks |
| **Size** | Packet length, payload size | Identify abnormal packet structures |
| **Flags** | TCP flags, ARP flags | Detect protocol manipulation |
| **Content** | Hardware type, protocol type, hardware length, protocol length | Identify protocol violations |

### Aggregated Flow Features

Features aggregated across packet flows (time windows or packet sequences):

| Feature Group | Examples | Purpose |
|---------------|----------|---------|
| **Volume** | Packets per second, bytes per second | Detect flooding attacks |
| **Directionality** | Request/reply ratio, inbound/outbound ratio | Identify unusual communication patterns |
| **Dispersion** | Unique IPs contacted, unique MACs | Detect scanning behavior |
| **Persistence** | Duration of communications, regularity | Identify persistent threats |
| **Entropy** | Shannon entropy of addresses, ports | Detect randomization patterns |

### Network-Level Features

Features capturing network-wide behavior:

| Feature Group | Examples | Purpose |
|---------------|----------|---------|
| **Topology** | Graph centrality, connectivity | Detect unauthorized devices |
| **Stability** | Address changes, route changes | Identify topology manipulation |
| **Density** | Communication density, interaction frequency | Detect abnormal network activity |
| **Gateway Metrics** | Gateway interactions, default route stability | Focus on critical infrastructure |
| **Address Mapping** | MAC-IP binding consistency | Identify spoofing attempts |

### Temporal Features

Features based on time-series analysis:

| Feature Group | Examples | Purpose |
|---------------|----------|---------|
| **Seasonality** | Daily/weekly patterns, business hours | Identify deviations from normal patterns |
| **Trends** | Traffic growth, activity patterns | Detect emerging threats |
| **Spikes** | Sudden changes, bursts | Identify flooding attacks |
| **Periodicity** | Regular intervals, heartbeat patterns | Detect beaconing malware |
| **Sequence** | Event ordering, protocol sequences | Identify protocol manipulation |

## Feature Engineering Process

The feature engineering pipeline consists of several key stages:

```
Raw Packets → Basic Extraction → Aggregation → Enrichment → Transformation → Selection
```

### 1. Basic Extraction

Raw packet fields are extracted directly:

```python
def extract_basic_features(packet):
    """Extract basic features from ARP packet."""
    features = {
        'timestamp': packet.time,
        'op_code': packet.op,
        'src_mac': packet.hwsrc,
        'dst_mac': packet.hwdst,
        'src_ip': packet.psrc,
        'dst_ip': packet.pdst,
        'hw_type': packet.hwtype,
        'proto_type': packet.ptype,
        'hw_len': packet.hwlen,
        'proto_len': packet.plen,
        'packet_len': len(packet),
    }
    return features
```

### 2. Aggregation

Packets are aggregated over time windows or by flow:

```python
def aggregate_features(packets, window_size=30):
    """Aggregate features over time windows."""
    windows = {}
    
    for packet in packets:
        window_id = int(packet['timestamp'] / window_size)
        if window_id not in windows:
            windows[window_id] = []
        windows[window_id].append(packet)
    
    aggregated_features = []
    for window_id, window_packets in windows.items():
        agg = {
            'window_start': window_id * window_size,
            'window_end': (window_id + 1) * window_size,
            'packet_count': len(window_packets),
            'unique_src_ips': len(set(p['src_ip'] for p in window_packets)),
            'unique_dst_ips': len(set(p['dst_ip'] for p in window_packets)),
            'unique_src_macs': len(set(p['src_mac'] for p in window_packets)),
            'unique_dst_macs': len(set(p['dst_mac'] for p in window_packets)),
            'arp_request_count': sum(1 for p in window_packets if p['op_code'] == 1),
            'arp_reply_count': sum(1 for p in window_packets if p['op_code'] == 2),
            'bytes_total': sum(p['packet_len'] for p in window_packets),
        }
        aggregated_features.append(agg)
    
    return aggregated_features
```

### 3. Enrichment

Features are enriched with additional context:

```python
def enrich_features(features, network_context):
    """Enrich features with network context."""
    for feature in features:
        # Add known/unknown device information
        feature['src_is_known'] = feature['src_mac'] in network_context['known_devices']
        feature['dst_is_known'] = feature['dst_mac'] in network_context['known_devices']
        
        # Add gateway information
        feature['src_is_gateway'] = feature['src_mac'] == network_context['gateway_mac']
        feature['dst_is_gateway'] = feature['dst_mac'] == network_context['gateway_mac']
        
        # Add MAC-IP binding information
        feature['ip_mac_mismatch'] = (
            feature['src_mac'] in network_context['mac_ip_bindings'] and
            feature['src_ip'] != network_context['mac_ip_bindings'][feature['src_mac']]
        )
    
    return features
```

### 4. Transformation

Features are transformed for better model performance:

```python
def transform_features(features):
    """Transform features for ML models."""
    transformed = []
    
    for feature in features:
        # Create normalized features
        tf = {
            'request_reply_ratio': safe_div(
                feature['arp_request_count'], 
                feature['arp_reply_count']
            ),
            'packets_per_second': feature['packet_count'] / 
                                  (feature['window_end'] - feature['window_start']),
            'bytes_per_packet': safe_div(
                feature['bytes_total'], 
                feature['packet_count']
            ),
            'src_ip_entropy': calculate_entropy(
                [p['src_ip'] for p in feature['packets']]
            ),
            'dst_ip_entropy': calculate_entropy(
                [p['dst_ip'] for p in feature['packets']]
            ),
            'temporal_dispersion': calculate_dispersion(
                [p['timestamp'] for p in feature['packets']]
            ),
        }
        transformed.append({**feature, **tf})
    
    return transformed
```

### 5. Feature Selection

Final set of features is selected based on importance:

```python
def select_features(features, importance_threshold=0.01):
    """Select features based on importance."""
    # Get feature importance from trained model
    importances = get_feature_importances()
    
    # Select features above threshold
    selected_features = [
        name for name, importance in importances.items() 
        if importance >= importance_threshold
    ]
    
    # Filter feature dictionary
    return [{k: v for k, v in f.items() if k in selected_features} 
            for f in features]
```

## Feature Importance Analysis

ARPGuard conducts feature importance analysis to understand which features contribute most to detection accuracy and to optimize feature selection.

### Top Features for Anomaly Detection

| Feature | Importance Score | Description |
|---------|------------------|-------------|
| arp_request_reply_ratio | 0.184 | Ratio of ARP requests to replies |
| gateway_communication_ratio | 0.153 | Proportion of traffic involving gateway |
| ip_mac_binding_changes | 0.129 | Frequency of IP-MAC binding changes |
| unique_ips_per_mac | 0.112 | Number of unique IPs claimed by a MAC |
| packet_rate_variability | 0.098 | Variance in packet transmission rate |
| broadcast_request_ratio | 0.087 | Ratio of broadcast to unicast requests |
| temporal_entropy | 0.082 | Entropy of packet timing |
| mac_spoofing_score | 0.071 | Likelihood score for MAC spoofing |
| packet_size_deviation | 0.048 | Deviation from normal packet sizes |
| protocol_field_entropy | 0.036 | Entropy of protocol field values |

### Feature Importance Visualization

```
arp_request_reply_ratio         ████████████████▌░░░░░░░░░░  0.184
gateway_communication_ratio     █████████████▋░░░░░░░░░░░░░  0.153
ip_mac_binding_changes          ███████████▋░░░░░░░░░░░░░░░  0.129
unique_ips_per_mac              ██████████░░░░░░░░░░░░░░░░░  0.112
packet_rate_variability         ████████▋░░░░░░░░░░░░░░░░░░  0.098
broadcast_request_ratio         ███████▋░░░░░░░░░░░░░░░░░░░  0.087
temporal_entropy                ███████▎░░░░░░░░░░░░░░░░░░░  0.082
mac_spoofing_score              ██████▎░░░░░░░░░░░░░░░░░░░░  0.071
packet_size_deviation           ████▎░░░░░░░░░░░░░░░░░░░░░░  0.048
protocol_field_entropy          ███▎░░░░░░░░░░░░░░░░░░░░░░░  0.036
```

### Feature Importance by Attack Type

Different features are important for detecting specific attack types:

#### ARP Spoofing

```
ip_mac_binding_changes          ████████████████▊░░░░░░░░░░  0.187
gateway_communication_ratio     █████████████▋░░░░░░░░░░░░░  0.153
arp_request_reply_ratio         ████████████▎░░░░░░░░░░░░░░  0.138
unique_ips_per_mac              ███████████░░░░░░░░░░░░░░░░  0.122
```

#### ARP DoS

```
packet_rate_variability         ██████████████▊░░░░░░░░░░░░  0.168
broadcast_request_ratio         █████████████▋░░░░░░░░░░░░░  0.153
arp_request_reply_ratio         ████████████░░░░░░░░░░░░░░░  0.134
temporal_entropy                ███████████░░░░░░░░░░░░░░░░  0.123
```

#### Reconnaissance

```
unique_ips_per_mac              ███████████████▊░░░░░░░░░░░  0.178
destination_ip_entropy          ██████████████▋░░░░░░░░░░░░  0.163
sequential_scanning_score       █████████████▋░░░░░░░░░░░░░  0.153
unique_dst_ips                  ████████████░░░░░░░░░░░░░░░  0.135
```

## Data Preprocessing Steps

ARPGuard applies several preprocessing steps to prepare raw packet data for ML models:

### 1. Cleaning

```python
def clean_data(raw_features):
    """Clean raw feature data."""
    cleaned = []
    
    for feature in raw_features:
        # Skip malformed packets
        if not all(k in feature for k in REQUIRED_FIELDS):
            continue
            
        # Handle missing values
        for field in OPTIONAL_FIELDS:
            if field not in feature:
                feature[field] = DEFAULT_VALUES[field]
                
        # Fix data types
        feature = {k: TYPE_CONVERTERS.get(k, lambda x: x)(v) 
                  for k, v in feature.items()}
                  
        # Remove outliers (simplified)
        if feature['packet_len'] > MAX_PACKET_SIZE:
            continue
            
        cleaned.append(feature)
    
    return cleaned
```

### 2. Normalization

```python
def normalize_features(features):
    """Normalize numerical features to [0, 1] range."""
    # Calculate min/max for each numerical feature
    stats = {}
    for feature_name in NUMERICAL_FEATURES:
        values = [f[feature_name] for f in features if feature_name in f]
        stats[feature_name] = {
            'min': min(values),
            'max': max(values)
        }
    
    # Apply min-max normalization
    normalized = []
    for feature in features:
        norm_feature = {}
        for k, v in feature.items():
            if k in NUMERICAL_FEATURES:
                min_val = stats[k]['min']
                max_val = stats[k]['max']
                # Avoid division by zero
                if max_val > min_val:
                    norm_feature[k] = (v - min_val) / (max_val - min_val)
                else:
                    norm_feature[k] = 0.0
            else:
                norm_feature[k] = v
        normalized.append(norm_feature)
    
    return normalized
```

### 3. Encoding

```python
def encode_categorical_features(features):
    """Encode categorical features."""
    # One-hot encode operation type
    for feature in features:
        op_code = feature.pop('op_code', None)
        if op_code is not None:
            feature['op_is_request'] = 1 if op_code == 1 else 0
            feature['op_is_reply'] = 1 if op_code == 2 else 0
            feature['op_is_other'] = 1 if op_code not in (1, 2) else 0
    
    # Label encode MAC addresses (simplified)
    mac_encoder = {}
    next_mac_id = 0
    
    for feature in features:
        src_mac = feature.pop('src_mac', None)
        if src_mac:
            if src_mac not in mac_encoder:
                mac_encoder[src_mac] = next_mac_id
                next_mac_id += 1
            feature['src_mac_id'] = mac_encoder[src_mac]
            
        dst_mac = feature.pop('dst_mac', None)
        if dst_mac:
            if dst_mac not in mac_encoder:
                mac_encoder[dst_mac] = next_mac_id
                next_mac_id += 1
            feature['dst_mac_id'] = mac_encoder[dst_mac]
    
    return features
```

### 4. Sequence Processing

For temporal models like LSTM, data is processed into sequences:

```python
def create_sequences(features, sequence_length=10, step=1):
    """Create sequences for temporal models."""
    sequences = []
    labels = []
    
    # Sort by timestamp
    sorted_features = sorted(features, key=lambda x: x['timestamp'])
    
    # Create sequences
    for i in range(0, len(sorted_features) - sequence_length, step):
        sequence = sorted_features[i:i + sequence_length]
        label = sorted_features[i + sequence_length].get('label', 0)
        
        # Extract selected features for sequence
        seq_features = []
        for feature in sequence:
            seq_features.append([feature[k] for k in SEQUENCE_FEATURES])
            
        sequences.append(seq_features)
        labels.append(label)
    
    return np.array(sequences), np.array(labels)
```

### 5. Class Balancing

ARPGuard uses techniques to address class imbalance in training data:

```python
def balance_classes(features, labels):
    """Balance classes in training data."""
    # Get class distribution
    class_counts = Counter(labels)
    
    # If no imbalance, return original data
    if len(set(class_counts.values())) == 1:
        return features, labels
    
    # Find minority and majority classes
    minority_class = min(class_counts.items(), key=lambda x: x[1])[0]
    majority_class = max(class_counts.items(), key=lambda x: x[1])[0]
    
    # Indices by class
    minority_indices = [i for i, label in enumerate(labels) if label == minority_class]
    majority_indices = [i for i, label in enumerate(labels) if label == majority_class]
    
    # Number of samples to generate
    n_samples = class_counts[majority_class] - class_counts[minority_class]
    
    # Generate synthetic samples (using SMOTE-like approach)
    synthetic_features = []
    synthetic_labels = []
    
    for _ in range(n_samples):
        # Pick a random minority sample
        i = random.choice(minority_indices)
        
        # Find k nearest neighbors
        distances = [euclidean_distance(features[i], features[j]) 
                     for j in minority_indices]
        neighbor_indices = sorted(range(len(distances)), key=lambda x: distances[x])[:5]
        
        # Pick a random neighbor
        j = minority_indices[random.choice(neighbor_indices[1:])]  # Exclude self
        
        # Generate synthetic sample
        synthetic = {}
        for k in features[i].keys():
            if k in NUMERICAL_FEATURES:
                diff = features[j][k] - features[i][k]
                synthetic[k] = features[i][k] + random.random() * diff
            else:
                synthetic[k] = features[i][k]
        
        synthetic_features.append(synthetic)
        synthetic_labels.append(minority_class)
    
    # Combine original and synthetic data
    balanced_features = features + synthetic_features
    balanced_labels = list(labels) + synthetic_labels
    
    return balanced_features, balanced_labels
```

## Conclusion

ARPGuard's feature engineering pipeline transforms raw network traffic into a rich set of features optimized for machine learning models. The extensive use of domain knowledge in feature extraction and the systematic approach to feature selection ensure that the ML models have access to the most relevant information for detecting network threats while minimizing computational overhead. 