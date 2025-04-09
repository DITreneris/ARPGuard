import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from typing import Dict, List, Any, Union

class DataPreprocessor:
    """Preprocesses network packet data for machine learning."""
    
    def __init__(self):
        """Initialize the data preprocessor."""
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.is_fitted = False

    def preprocess(self, data: Union[pd.DataFrame, List[Dict[str, Any]]]) -> np.ndarray:
        """
        Preprocess the input data.
        
        Args:
            data: Input data to preprocess
            
        Returns:
            Preprocessed data as numpy array
        """
        # Convert list of dictionaries to DataFrame if necessary
        if isinstance(data, list):
            data = pd.DataFrame(data)
        
        # Create a copy to avoid modifying original data
        df = data.copy()
        
        # Encode categorical features
        df = self._encode_categorical_features(df)
        
        # Scale numerical features
        df = self._scale_numerical_features(df)
        
        return df.values

    def _encode_categorical_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Encode categorical features using label encoding.
        
        Args:
            df: DataFrame containing features
            
        Returns:
            DataFrame with encoded categorical features
        """
        # Identify categorical columns
        categorical_cols = df.select_dtypes(include=['object']).columns
        
        # Create or reuse label encoders
        for col in categorical_cols:
            if col not in self.label_encoders:
                self.label_encoders[col] = LabelEncoder()
                self.label_encoders[col].fit(df[col])
            
            # Transform the column
            df[col] = self.label_encoders[col].transform(df[col])
        
        return df

    def _scale_numerical_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Scale numerical features using standardization.
        
        Args:
            df: DataFrame containing features
            
        Returns:
            DataFrame with scaled numerical features
        """
        # Identify numerical columns
        numerical_cols = df.select_dtypes(include=['int64', 'float64']).columns
        
        # Fit scaler if not already fitted
        if not self.is_fitted:
            self.scaler.fit(df[numerical_cols])
            self.is_fitted = True
        
        # Transform numerical columns
        df[numerical_cols] = self.scaler.transform(df[numerical_cols])
        
        return df

    def handle_missing_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Handle missing values in the data.
        
        Args:
            df: DataFrame containing features
            
        Returns:
            DataFrame with handled missing values
        """
        # Create a copy to avoid modifying original data
        df = df.copy()
        
        # Fill missing values in numerical columns with median
        numerical_cols = df.select_dtypes(include=['int64', 'float64']).columns
        for col in numerical_cols:
            df[col] = df[col].fillna(df[col].median())
        
        # Fill missing values in categorical columns with mode
        categorical_cols = df.select_dtypes(include=['object']).columns
        for col in categorical_cols:
            df[col] = df[col].fillna(df[col].mode()[0])
        
        return df

    def remove_outliers(self, df: pd.DataFrame, columns: List[str] = None) -> pd.DataFrame:
        """
        Remove outliers from the data using IQR method.
        
        Args:
            df: DataFrame containing features
            columns: List of columns to process (None for all numerical columns)
            
        Returns:
            DataFrame with outliers removed
        """
        # Create a copy to avoid modifying original data
        df = df.copy()
        
        # Use all numerical columns if none specified
        if columns is None:
            columns = df.select_dtypes(include=['int64', 'float64']).columns
        
        # Remove outliers using IQR method
        for col in columns:
            Q1 = df[col].quantile(0.25)
            Q3 = df[col].quantile(0.75)
            IQR = Q3 - Q1
            lower_bound = Q1 - 1.5 * IQR
            upper_bound = Q3 + 1.5 * IQR
            
            # Replace outliers with bounds
            df[col] = df[col].clip(lower_bound, upper_bound)
        
        return df

    def create_time_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Create time-based features from timestamp.
        
        Args:
            df: DataFrame containing features
            
        Returns:
            DataFrame with additional time features
        """
        # Create a copy to avoid modifying original data
        df = df.copy()
        
        if 'timestamp' in df.columns:
            # Convert timestamp to datetime
            df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
            
            # Extract time features
            df['hour'] = df['datetime'].dt.hour
            df['day_of_week'] = df['datetime'].dt.dayofweek
            df['day_of_month'] = df['datetime'].dt.day
            df['month'] = df['datetime'].dt.month
            
            # Drop original timestamp and datetime columns
            df = df.drop(['timestamp', 'datetime'], axis=1)
        
        return df

    def create_interaction_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Create interaction features between numerical columns.
        
        Args:
            df: DataFrame containing features
            
        Returns:
            DataFrame with additional interaction features
        """
        # Create a copy to avoid modifying original data
        df = df.copy()
        
        # Get numerical columns
        numerical_cols = df.select_dtypes(include=['int64', 'float64']).columns
        
        # Create interaction features
        for i in range(len(numerical_cols)):
            for j in range(i+1, len(numerical_cols)):
                col1 = numerical_cols[i]
                col2 = numerical_cols[j]
                df[f'{col1}_{col2}_interaction'] = df[col1] * df[col2]
        
        return df

    def get_feature_names(self) -> List[str]:
        """
        Get the names of all features after preprocessing.
        
        Returns:
            List of feature names
        """
        # Get all label encoders' classes
        feature_names = []
        
        for col, encoder in self.label_encoders.items():
            feature_names.extend([f'{col}_{cls}' for cls in encoder.classes_])
        
        return feature_names 