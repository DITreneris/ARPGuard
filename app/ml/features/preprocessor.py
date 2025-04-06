import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.decomposition import PCA
from typing import Tuple, Optional, Dict, List
from datetime import datetime

class PerformancePreprocessor:
    """
    Preprocesses performance data for ML models.
    Handles normalization, feature engineering, and dimensionality reduction.
    """
    def __init__(self, n_components: float = 0.95):
        """
        Initialize the preprocessor.
        
        Args:
            n_components (float): Variance ratio for PCA (default: 0.95)
        """
        self.scaler = StandardScaler()
        self.pca = PCA(n_components=n_components)
        self.feature_names: List[str] = []
        
    def preprocess(self, data: pd.DataFrame, target_column: Optional[str] = None) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """
        Preprocess the input data.
        
        Args:
            data (pd.DataFrame): Input data to preprocess
            target_column (Optional[str]): Name of target column if present
            
        Returns:
            Tuple[np.ndarray, Optional[np.ndarray]]: Preprocessed features and target
        """
        # Handle timestamp column
        if 'timestamp' in data.columns:
            data = self._process_timestamp(data)
            
        # Separate features and target
        if target_column is not None:
            X = data.drop(columns=[target_column])
            y = data[target_column].values
        else:
            X = data
            y = None
            
        # Store feature names
        self.feature_names = X.columns.tolist()
        
        # Convert to numpy array
        X = X.values
        
        # Normalize
        X_scaled = self.scaler.fit_transform(X)
        
        # Reduce dimensionality
        X_reduced = self.pca.fit_transform(X_scaled)
        
        return X_reduced, y
    
    def _process_timestamp(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Process timestamp column into useful features.
        
        Args:
            data (pd.DataFrame): Data containing timestamp column
            
        Returns:
            pd.DataFrame: Data with processed timestamp features
        """
        df = data.copy()
        timestamps = pd.to_datetime(df['timestamp'])
        
        # Extract time-based features
        df['hour'] = timestamps.dt.hour
        df['day_of_week'] = timestamps.dt.dayofweek
        df['is_weekend'] = timestamps.dt.dayofweek >= 5
        
        # Drop original timestamp
        df = df.drop(columns=['timestamp'])
        
        return df
    
    def get_feature_importance(self) -> Dict[str, float]:
        """
        Get feature importance from PCA.
        
        Returns:
            Dict[str, float]: Dictionary of feature names and their importance scores
        """
        if not self.feature_names:
            return {}
            
        # Get absolute loadings for each component
        loadings = np.abs(self.pca.components_)
        
        # Calculate feature importance as sum of absolute loadings
        importance = np.sum(loadings, axis=0)
        
        # Create dictionary of feature importance
        feature_importance = dict(zip(self.feature_names, importance))
        
        return feature_importance
    
    def inverse_transform(self, data: np.ndarray) -> np.ndarray:
        """
        Transform reduced data back to original space.
        
        Args:
            data (np.ndarray): Reduced data to transform back
            
        Returns:
            np.ndarray: Data in original feature space
        """
        # Inverse PCA
        X_scaled = self.pca.inverse_transform(data)
        
        # Inverse scaling
        X = self.scaler.inverse_transform(X_scaled)
        
        return X
    
    def get_explained_variance(self) -> float:
        """
        Get the total explained variance ratio.
        
        Returns:
            float: Total explained variance ratio
        """
        return np.sum(self.pca.explained_variance_ratio_) 