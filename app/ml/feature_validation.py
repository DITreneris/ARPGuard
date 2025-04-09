import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from scipy import stats
from typing import Dict, List, Any, Union

class FeatureValidator:
    """Validates and analyzes features for machine learning models."""
    
    def __init__(self, 
                 missing_threshold: float = 0.1,
                 correlation_threshold: float = 0.9,
                 importance_threshold: float = 0.01):
        """
        Initialize the feature validator.
        
        Args:
            missing_threshold: Maximum allowed proportion of missing values
            correlation_threshold: Threshold for high correlation between features
            importance_threshold: Minimum importance score for feature selection
        """
        self.missing_threshold = missing_threshold
        self.correlation_threshold = correlation_threshold
        self.importance_threshold = importance_threshold

    def validate_data_quality(self, features: pd.DataFrame) -> Dict[str, Any]:
        """
        Validate the quality of the feature data.
        
        Args:
            features: DataFrame containing the features
            
        Returns:
            Dictionary containing validation results
        """
        # Check for missing values
        missing_values = features.isnull().sum().sum()
        missing_proportion = missing_values / (features.shape[0] * features.shape[1])
        
        # Check for outliers using IQR method
        outliers = 0
        for column in features.columns:
            if pd.api.types.is_numeric_dtype(features[column]):
                Q1 = features[column].quantile(0.25)
                Q3 = features[column].quantile(0.75)
                IQR = Q3 - Q1
                outliers += ((features[column] < (Q1 - 1.5 * IQR)) | 
                           (features[column] > (Q3 + 1.5 * IQR))).sum()
        
        # Determine if data is valid
        is_valid = (missing_proportion <= self.missing_threshold and 
                   outliers / (features.shape[0] * features.shape[1]) <= 0.05)
        
        return {
            'is_valid': is_valid,
            'missing_values': int(missing_values),
            'missing_proportion': float(missing_proportion),
            'outliers': int(outliers),
            'outlier_proportion': float(outliers / (features.shape[0] * features.shape[1]))
        }

    def analyze_feature_importance(self, 
                                 features: pd.DataFrame, 
                                 labels: np.ndarray) -> Dict[str, float]:
        """
        Analyze feature importance using Random Forest.
        
        Args:
            features: DataFrame containing the features
            labels: Array of target labels
            
        Returns:
            Dictionary mapping feature names to importance scores
        """
        # Train a Random Forest classifier
        rf = RandomForestClassifier(n_estimators=100, random_state=42)
        rf.fit(features, labels)
        
        # Get feature importances
        importances = rf.feature_importances_
        
        # Normalize importances to sum to 1
        importances = importances / importances.sum()
        
        return dict(zip(features.columns, importances))

    def analyze_feature_correlation(self, features: pd.DataFrame) -> pd.DataFrame:
        """
        Analyze correlation between features.
        
        Args:
            features: DataFrame containing the features
            
        Returns:
            Correlation matrix
        """
        return features.corr()

    def analyze_feature_distributions(self, features: pd.DataFrame) -> Dict[str, Dict[str, float]]:
        """
        Analyze statistical properties of feature distributions.
        
        Args:
            features: DataFrame containing the features
            
        Returns:
            Dictionary containing statistical properties for each feature
        """
        distributions = {}
        
        for column in features.columns:
            if pd.api.types.is_numeric_dtype(features[column]):
                data = features[column].dropna()
                distributions[column] = {
                    'mean': float(data.mean()),
                    'std': float(data.std()),
                    'skew': float(stats.skew(data)),
                    'kurtosis': float(stats.kurtosis(data))
                }
        
        return distributions

    def select_features(self, 
                       features: pd.DataFrame, 
                       validation_report: Dict[str, Any]) -> List[str]:
        """
        Select features based on validation results.
        
        Args:
            features: DataFrame containing the features
            validation_report: Dictionary containing validation results
            
        Returns:
            List of selected feature names
        """
        selected_features = set(features.columns)
        
        # Remove features with high missing values
        quality_report = validation_report['data_quality']
        if not quality_report['is_valid']:
            missing_counts = features.isnull().sum()
            high_missing = missing_counts[missing_counts / len(features) > self.missing_threshold].index
            selected_features -= set(high_missing)
        
        # Remove highly correlated features
        correlation_matrix = validation_report['correlation']
        for i in range(len(correlation_matrix.columns)):
            for j in range(i+1, len(correlation_matrix.columns)):
                if abs(correlation_matrix.iloc[i, j]) > self.correlation_threshold:
                    # Keep the feature with higher importance
                    feature1 = correlation_matrix.columns[i]
                    feature2 = correlation_matrix.columns[j]
                    importance1 = validation_report['importance'].get(feature1, 0)
                    importance2 = validation_report['importance'].get(feature2, 0)
                    if importance1 > importance2:
                        selected_features.discard(feature2)
                    else:
                        selected_features.discard(feature1)
        
        # Remove low importance features
        importance_scores = validation_report['importance']
        low_importance = [feature for feature, score in importance_scores.items() 
                         if score < self.importance_threshold]
        selected_features -= set(low_importance)
        
        return list(selected_features) 