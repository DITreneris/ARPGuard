import numpy as np
import pandas as pd
from typing import Dict, List, Any, Union
from datetime import datetime

class FeatureExtractor:
    """Extracts features from network packet data."""
    
    def __init__(self):
        """Initialize the feature extractor."""
        self.feature_cache = {}
        self.statistical_features = [
            'mean', 'std', 'min', 'max', 'median', 'skew', 'kurtosis'
        ]

    def extract_features(self, packets: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Extract features from network packets.
        
        Args:
            packets: List of network packets
            
        Returns:
            DataFrame containing extracted features
        """
        # Convert packets to DataFrame
        df = pd.DataFrame(packets)
        
        # Handle empty dataframe
        if df.empty:
            return pd.DataFrame()
        
        # Fill missing values with defaults
        self._fill_missing_values(df)
        
        # Extract basic features
        features = self._extract_basic_features(df)
        
        # Extract statistical features
        features = self._extract_statistical_features(features, df)
        
        # Extract time-based features
        features = self._extract_time_features(features, df)
        
        # Extract network-specific features
        features = self._extract_network_features(features, df)
        
        # Extract interaction features
        features = self._extract_interaction_features(features)
        
        return features
        
    def _fill_missing_values(self, df: pd.DataFrame) -> None:
        """
        Fill missing values in DataFrame with defaults.
        
        Args:
            df: DataFrame to fill
        """
        # Fill default values for missing columns
        default_values = {
            'src_ip': '0.0.0.0',
            'dst_ip': '0.0.0.0',
            'src_port': 0,
            'dst_port': 0,
            'protocol': 'UNKNOWN',
            'length': 0,
            'timestamp': datetime.now().timestamp()
        }
        
        # Add missing columns and fill with defaults
        for col, default in default_values.items():
            if col not in df.columns:
                df[col] = default
        
        # Convert columns to appropriate types
        df['src_port'] = pd.to_numeric(df['src_port'], errors='coerce').fillna(0).astype(int)
        df['dst_port'] = pd.to_numeric(df['dst_port'], errors='coerce').fillna(0).astype(int)
        df['length'] = pd.to_numeric(df['length'], errors='coerce').fillna(0).astype(int)
        
        # Convert timestamp to numeric if it's not
        if 'timestamp' in df.columns:
            if df['timestamp'].dtype == 'object':
                df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce')
                df['timestamp'] = df['timestamp'].fillna(datetime.now().timestamp())

    def _extract_basic_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract basic features from packets.
        
        Args:
            df: DataFrame containing packets
            
        Returns:
            DataFrame with basic features
        """
        features = pd.DataFrame()
        
        # Basic packet features
        features['packet_length'] = df['length']
        features['protocol_type'] = df['protocol']
        
        # Port features
        features['src_port'] = df['src_port']
        features['dst_port'] = df['dst_port']
        features['port_difference'] = abs(df['src_port'] - df['dst_port'])
        
        # IP address features (encoded)
        features['src_ip_encoded'] = df['src_ip'].apply(self._encode_ip)
        features['dst_ip_encoded'] = df['dst_ip'].apply(self._encode_ip)
        
        return features

    def _extract_statistical_features(self, 
                                    features: pd.DataFrame, 
                                    df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract statistical features from packets.
        
        Args:
            features: DataFrame containing existing features
            df: DataFrame containing packets
            
        Returns:
            DataFrame with statistical features
        """
        # Calculate rolling statistics for packet length
        window_size = min(10, len(df))
        if window_size > 1:
            rolling_stats = df['length'].rolling(window=window_size)
            
            for stat in self.statistical_features:
                if hasattr(rolling_stats, stat):
                    features[f'length_{stat}'] = getattr(rolling_stats, stat)()
        
        # Calculate packet rate
        if 'timestamp' in df.columns:
            time_diff = df['timestamp'].diff()
            features['packet_rate'] = 1 / time_diff.replace(0, np.nan)
        
        return features

    def _extract_time_features(self, 
                              features: pd.DataFrame, 
                              df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract time-based features from packets.
        
        Args:
            features: DataFrame containing existing features
            df: DataFrame containing packets
            
        Returns:
            DataFrame with time features
        """
        if 'timestamp' in df.columns:
            try:
                # Convert timestamp to datetime
                df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
                
                # Extract time components
                features['hour'] = df['datetime'].dt.hour
                features['day_of_week'] = df['datetime'].dt.dayofweek
                features['day_of_month'] = df['datetime'].dt.day
                features['month'] = df['datetime'].dt.month
                
                # Calculate time since last packet
                features['time_since_last'] = df['timestamp'].diff()
            except (ValueError, TypeError):
                # If conversion fails, use current time
                current_time = datetime.now()
                features['hour'] = current_time.hour
                features['day_of_week'] = current_time.weekday()
                features['day_of_month'] = current_time.day
                features['month'] = current_time.month
                features['time_since_last'] = 0
        
        return features

    def _extract_network_features(self, 
                                 features: pd.DataFrame, 
                                 df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract network-specific features from packets.
        
        Args:
            features: DataFrame containing existing features
            df: DataFrame containing packets
            
        Returns:
            DataFrame with network features
        """
        # Calculate packet direction
        features['is_outgoing'] = (df['src_port'] > df['dst_port']).astype(int)
        
        # Calculate port ranges
        features['src_port_range'] = pd.cut(
            df['src_port'],
            bins=[0, 1024, 49152, 65535],
            labels=['well_known', 'registered', 'dynamic']
        )
        
        features['dst_port_range'] = pd.cut(
            df['dst_port'],
            bins=[0, 1024, 49152, 65535],
            labels=['well_known', 'registered', 'dynamic']
        )
        
        # Calculate protocol-specific features
        features['is_tcp'] = (df['protocol'] == 'TCP').astype(int)
        features['is_udp'] = (df['protocol'] == 'UDP').astype(int)
        features['is_icmp'] = (df['protocol'] == 'ICMP').astype(int)
        
        return features

    def _extract_interaction_features(self, features: pd.DataFrame) -> pd.DataFrame:
        """
        Extract interaction features between existing features.
        
        Args:
            features: DataFrame containing existing features
            
        Returns:
            DataFrame with interaction features
        """
        # Create a copy to avoid fragmentation warning
        features_copy = features.copy()
        
        # Create interaction features between numerical columns
        numerical_cols = features.select_dtypes(include=['int64', 'float64']).columns
        
        if len(numerical_cols) >= 2:
            # Create a temporary dataframe for interactions
            interactions = {}
            
            for i in range(len(numerical_cols)):
                for j in range(i+1, len(numerical_cols)):
                    col1 = numerical_cols[i]
                    col2 = numerical_cols[j]
                    interaction_name = f'{col1}_{col2}_interaction'
                    
                    # Replace NaN values with 0 for multiplication
                    val1 = features_copy[col1].fillna(0)
                    val2 = features_copy[col2].fillna(0)
                    
                    interactions[interaction_name] = val1 * val2
            
            # Add all interactions at once
            interaction_df = pd.DataFrame(interactions, index=features.index)
            features_copy = pd.concat([features_copy, interaction_df], axis=1)
        
        return features_copy

    def _encode_ip(self, ip: str) -> int:
        """
        Encode IP address to integer.
        
        Args:
            ip: IP address string
            
        Returns:
            Encoded IP address as integer
        """
        if ip not in self.feature_cache:
            try:
                # Handle non-string IP addresses
                if not isinstance(ip, str):
                    self.feature_cache[ip] = 0
                    return 0
                    
                # Split IP into octets
                octets = ip.split('.')
                # Convert to integer
                encoded = sum(int(octet) * (256 ** (3 - i)) for i, octet in enumerate(octets))
                self.feature_cache[ip] = encoded
            except (ValueError, AttributeError):
                self.feature_cache[ip] = 0
        
        return self.feature_cache[ip]

    def get_feature_names(self) -> List[str]:
        """
        Get the names of all extracted features.
        
        Returns:
            List of feature names
        """
        # Return cached feature names
        return list(self.feature_cache.keys()) 