import numpy as np
import pandas as pd
from typing import Dict, List, Any, Union, Optional
from app.ml.data_collection import DataCollector
from app.ml.feature_engineering import FeatureExtractor
from app.ml.preprocessing import DataPreprocessor
from app.ml.models.ensemble import EnsembleModel
from app.ml.models.deep_learning import DeepLearningModel
from app.ml.feature_validation import FeatureValidator

class MLPipeline:
    """Complete machine learning pipeline for network traffic analysis."""
    
    def __init__(self):
        """Initialize the ML pipeline components."""
        self.data_collector = DataCollector()
        self.feature_extractor = FeatureExtractor()
        self.preprocessor = DataPreprocessor()
        self.feature_validator = FeatureValidator()
        self.ensemble_model = EnsembleModel()
        self.deep_learning_model = DeepLearningModel()
        self.is_trained = False

    def collect_data(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Collect and validate network packet data.
        
        Args:
            packets: List of network packets
            
        Returns:
            List of validated packets
        """
        return self.data_collector.collect_data(packets)

    def extract_features(self, packets: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Extract features from network packets.
        
        Args:
            packets: List of network packets
            
        Returns:
            DataFrame containing extracted features
        """
        return self.feature_extractor.extract_features(packets)

    def preprocess_features(self, features: pd.DataFrame) -> np.ndarray:
        """
        Preprocess extracted features.
        
        Args:
            features: DataFrame containing features
            
        Returns:
            Array of preprocessed features
        """
        return self.preprocessor.preprocess(features)

    def validate_features(self, features: pd.DataFrame) -> Dict[str, Any]:
        """
        Validate feature quality and importance.
        
        Args:
            features: DataFrame containing features
            
        Returns:
            Dictionary containing validation results
        """
        return self.feature_validator.validate_data_quality(features)

    def train_models(self, 
                    features: np.ndarray, 
                    labels: np.ndarray,
                    validation_split: float = 0.2) -> None:
        """
        Train both ensemble and deep learning models.
        
        Args:
            features: Array of preprocessed features
            labels: Array of target labels
            validation_split: Proportion of data to use for validation
        """
        # Split data into training and validation sets
        split_idx = int(len(features) * (1 - validation_split))
        X_train, X_val = features[:split_idx], features[split_idx:]
        y_train, y_val = labels[:split_idx], labels[split_idx:]
        
        # Train ensemble model
        self.ensemble_model.train(X_train, y_train)
        
        # Train deep learning model
        self.deep_learning_model.train(
            X_train, 
            y_train,
            epochs=10,
            batch_size=32
        )
        
        self.is_trained = True

    def predict(self, features: np.ndarray) -> np.ndarray:
        """
        Make predictions using both models.
        
        Args:
            features: Array of preprocessed features
            
        Returns:
            Array of combined predictions
        """
        if not self.is_trained:
            raise RuntimeError("Models must be trained before making predictions")
        
        # Get predictions from both models
        ensemble_preds = self.ensemble_model.predict(features)
        dl_preds = self.deep_learning_model.predict(features)
        
        # Combine predictions (simple average)
        combined_preds = (ensemble_preds + dl_preds) / 2
        
        return (combined_preds > 0.5).astype(int)

    def predict_proba(self, features: np.ndarray) -> np.ndarray:
        """
        Get probability predictions from both models.
        
        Args:
            features: Array of preprocessed features
            
        Returns:
            Array of combined probability predictions
        """
        if not self.is_trained:
            raise RuntimeError("Models must be trained before making predictions")
        
        # Get probability predictions from both models
        ensemble_probas = self.ensemble_model.predict_proba(features)
        dl_probas = self.deep_learning_model.predict_proba(features)
        
        # Combine probabilities (simple average)
        return (ensemble_probas + dl_probas) / 2

    def evaluate(self, features: np.ndarray, labels: np.ndarray) -> Dict[str, float]:
        """
        Evaluate model performance.
        
        Args:
            features: Array of preprocessed features
            labels: Array of target labels
            
        Returns:
            Dictionary of performance metrics
        """
        if not self.is_trained:
            raise RuntimeError("Models must be trained before evaluation")
        
        # Get predictions
        predictions = self.predict(features)
        
        # Calculate metrics
        metrics = {
            'accuracy': np.mean(predictions == labels),
            'precision': np.sum((predictions == 1) & (labels == 1)) / np.sum(predictions == 1),
            'recall': np.sum((predictions == 1) & (labels == 1)) / np.sum(labels == 1),
            'f1_score': 2 * (precision * recall) / (precision + recall)
        }
        
        return metrics

    def configure(self,
                 ensemble_models: Optional[List[str]] = None,
                 deep_learning_params: Optional[Dict[str, Any]] = None) -> None:
        """
        Configure pipeline components.
        
        Args:
            ensemble_models: List of ensemble model types to use
            deep_learning_params: Dictionary of deep learning parameters
        """
        if ensemble_models:
            self.ensemble_model = EnsembleModel()
            # Configure ensemble models based on types
        
        if deep_learning_params:
            self.deep_learning_model = DeepLearningModel(
                input_size=deep_learning_params.get('input_size', 10),
                hidden_size=deep_learning_params.get('hidden_size', 64)
            )

    def save_models(self, path: str) -> None:
        """
        Save trained models to disk.
        
        Args:
            path: Directory path to save models
        """
        if not self.is_trained:
            raise RuntimeError("Models must be trained before saving")
        
        # Save ensemble model
        self.ensemble_model.save_model(f"{path}/ensemble_model.pkl")
        
        # Save deep learning model
        self.deep_learning_model.save_model(f"{path}/deep_learning_model.pth")

    def load_models(self, path: str) -> None:
        """
        Load trained models from disk.
        
        Args:
            path: Directory path containing saved models
        """
        # Load ensemble model
        self.ensemble_model.load_model(f"{path}/ensemble_model.pkl")
        
        # Load deep learning model
        self.deep_learning_model.load_model(f"{path}/deep_learning_model.pth")
        
        self.is_trained = True

    def run(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Run the complete pipeline on input packets.
        
        Args:
            packets: List of network packets
            
        Returns:
            Dictionary containing predictions and metrics
        """
        # Collect data
        collected_data = self.collect_data(packets)
        
        # Extract features
        features = self.extract_features(collected_data)
        
        # Validate features
        validation_report = self.validate_features(features)
        
        # Preprocess features
        processed_features = self.preprocess_features(features)
        
        # Make predictions
        predictions = self.predict(processed_features)
        probabilities = self.predict_proba(processed_features)
        
        # Calculate metrics
        metrics = self.evaluate(processed_features, np.zeros(len(packets)))  # Dummy labels
        
        return {
            'predictions': predictions,
            'probabilities': probabilities,
            'metrics': metrics,
            'validation_report': validation_report
        } 