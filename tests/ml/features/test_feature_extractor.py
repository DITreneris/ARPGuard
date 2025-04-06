import pytest
import pandas as pd
import numpy as np
from datetime import datetime
from app.ml.feature_engineering import FeatureExtractor

@pytest.fixture
def sample_packets():
    """Create sample network packets for testing."""
    return [
        {
            'src_ip': '192.168.1.1',
            'dst_ip': '192.168.1.2',
            'src_port': 5000,
            'dst_port': 80,
            'protocol': 'TCP',
            'length': 1500,
            'timestamp': datetime.now().timestamp()
        },
        {
            'src_ip': '192.168.1.2',
            'dst_ip': '192.168.1.1',
            'src_port': 80,
            'dst_port': 5000,
            'protocol': 'TCP',
            'length': 1000,
            'timestamp': datetime.now().timestamp() + 1
        },
        {
            'src_ip': '192.168.1.3',
            'dst_ip': '192.168.1.4',
            'src_port': 53,
            'dst_port': 53,
            'protocol': 'UDP',
            'length': 500,
            'timestamp': datetime.now().timestamp() + 2
        }
    ]

@pytest.fixture
def feature_extractor():
    """Create a FeatureExtractor instance for testing."""
    return FeatureExtractor()

def test_extract_features_basic(feature_extractor, sample_packets):
    """Test basic feature extraction."""
    features = feature_extractor.extract_features(sample_packets)
    
    # Check if DataFrame is returned
    assert isinstance(features, pd.DataFrame)
    
    # Check basic features
    assert 'packet_length' in features.columns
    assert 'protocol_type' in features.columns
    assert 'src_port' in features.columns
    assert 'dst_port' in features.columns
    assert 'port_difference' in features.columns
    
    # Check values
    assert features['packet_length'].iloc[0] == 1500
    assert features['protocol_type'].iloc[0] == 'TCP'
    assert features['src_port'].iloc[0] == 5000
    assert features['dst_port'].iloc[0] == 80
    assert features['port_difference'].iloc[0] == 4920

def test_extract_features_statistical(feature_extractor, sample_packets):
    """Test statistical feature extraction."""
    features = feature_extractor.extract_features(sample_packets)
    
    # Check statistical features
    assert 'length_mean' in features.columns
    assert 'length_std' in features.columns
    assert 'length_min' in features.columns
    assert 'length_max' in features.columns
    assert 'packet_rate' in features.columns
    
    # Check values
    assert features['length_mean'].iloc[-1] == pytest.approx(1000, rel=1e-3)
    assert features['length_min'].iloc[-1] == 500
    assert features['length_max'].iloc[-1] == 1500

def test_extract_features_time(feature_extractor, sample_packets):
    """Test time-based feature extraction."""
    features = feature_extractor.extract_features(sample_packets)
    
    # Check time features
    assert 'hour' in features.columns
    assert 'day_of_week' in features.columns
    assert 'day_of_month' in features.columns
    assert 'month' in features.columns
    assert 'time_since_last' in features.columns
    
    # Check values - don't compare with current time as it's unreliable in tests
    assert isinstance(features['hour'].iloc[0], (int, np.integer))
    assert 0 <= features['hour'].iloc[0] <= 23
    assert 0 <= features['day_of_week'].iloc[0] <= 6
    assert 1 <= features['day_of_month'].iloc[0] <= 31
    assert 1 <= features['month'].iloc[0] <= 12

def test_extract_features_network(feature_extractor, sample_packets):
    """Test network-specific feature extraction."""
    features = feature_extractor.extract_features(sample_packets)
    
    # Check network features
    assert 'is_outgoing' in features.columns
    assert 'src_port_range' in features.columns
    assert 'dst_port_range' in features.columns
    assert 'is_tcp' in features.columns
    assert 'is_udp' in features.columns
    assert 'is_icmp' in features.columns
    
    # Check values - src_port is 5000 which falls in the 'registered' range (1024-49152)
    assert features['is_outgoing'].iloc[0] == 1
    assert features['src_port_range'].iloc[0] == 'registered'
    assert features['dst_port_range'].iloc[0] == 'well_known'
    assert features['is_tcp'].iloc[0] == 1
    assert features['is_udp'].iloc[0] == 0
    assert features['is_icmp'].iloc[0] == 0

def test_extract_features_interaction(feature_extractor, sample_packets):
    """Test interaction feature extraction."""
    features = feature_extractor.extract_features(sample_packets)
    
    # Check interaction features
    interaction_cols = [col for col in features.columns if 'interaction' in col]
    assert len(interaction_cols) > 0
    
    # Check values
    for col in interaction_cols:
        assert not features[col].isnull().all()

def test_encode_ip(feature_extractor):
    """Test IP address encoding."""
    # Test valid IP
    encoded = feature_extractor._encode_ip('192.168.1.1')
    assert isinstance(encoded, int)
    assert encoded > 0
    
    # Test invalid IP
    encoded = feature_extractor._encode_ip('invalid')
    assert encoded == 0
    
    # Test caching
    encoded1 = feature_extractor._encode_ip('192.168.1.1')
    encoded2 = feature_extractor._encode_ip('192.168.1.1')
    assert encoded1 == encoded2

def test_get_feature_names(feature_extractor, sample_packets):
    """Test getting feature names."""
    # Extract features first
    feature_extractor.extract_features(sample_packets)
    
    # Get feature names
    feature_names = feature_extractor.get_feature_names()
    
    # Check if names are returned
    assert isinstance(feature_names, list)
    assert len(feature_names) > 0
    
    # Check if all names are strings
    assert all(isinstance(name, str) for name in feature_names)

def test_empty_packets(feature_extractor):
    """Test feature extraction with empty packet list."""
    features = feature_extractor.extract_features([])
    assert isinstance(features, pd.DataFrame)
    assert len(features) == 0

def test_missing_fields(feature_extractor):
    """Test feature extraction with packets missing required fields."""
    incomplete_packets = [
        {'src_ip': '192.168.1.1'},  # Missing other fields
        {'dst_ip': '192.168.1.2'}   # Missing other fields
    ]
    
    features = feature_extractor.extract_features(incomplete_packets)
    assert isinstance(features, pd.DataFrame)
    assert len(features) == 2

def test_invalid_data_types(feature_extractor):
    """Test feature extraction with invalid data types."""
    invalid_packets = [
        {
            'src_ip': 123,  # Invalid type
            'dst_ip': '192.168.1.2',
            'src_port': 'invalid',  # Invalid type
            'dst_port': 80,
            'protocol': 'TCP',
            'length': '1500',  # Invalid type
            'timestamp': 'invalid'  # Invalid type
        }
    ]
    
    features = feature_extractor.extract_features(invalid_packets)
    assert isinstance(features, pd.DataFrame)
    assert len(features) == 1 