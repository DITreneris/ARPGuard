import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import Model, Sequential, load_model
from tensorflow.keras.layers import Input, Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from tensorflow.keras.optimizers import Adam
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Tuple, Optional, Union, Any
import os
import logging
import matplotlib.pyplot as plt
from datetime import datetime

class AnomalyDetector:
    """
    Anomaly Detection System using an autoencoder to detect abnormal
    patterns in system performance metrics.
    """
    
    def __init__(
        self,
        input_dim: int = 5,
        encoding_dims: List[int] = [32, 16, 8],
        activation: str = 'relu',
        dropout_rate: float = 0.2,
        learning_rate: float = 0.001,
        threshold_multiplier: float = 3.0,
        model_path: str = "models/anomaly_detector"
    ):
        """
        Initialize the Anomaly Detection System.
        
        Args:
            input_dim: Number of input features
            encoding_dims: List of dimensions for the encoder layers
            activation: Activation function for hidden layers
            dropout_rate: Dropout rate for regularization
            learning_rate: Learning rate for the Adam optimizer
            threshold_multiplier: Multiplier for the threshold (standard deviations)
            model_path: Path to save/load the model
        """
        self.input_dim = input_dim
        self.encoding_dims = encoding_dims
        self.activation = activation
        self.dropout_rate = dropout_rate
        self.learning_rate = learning_rate
        self.threshold_multiplier = threshold_multiplier
        self.model_path = model_path
        self.model = None
        self.threshold = None
        self.scaler = StandardScaler()
        self.history = None
        self.feature_names = None
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
    def build_model(self) -> Model:
        """
        Build and compile the autoencoder model.
        
        Returns:
            Compiled Keras Model
        """
        # Input layer
        inputs = Input(shape=(self.input_dim,))
        
        # Encoder layers
        x = inputs
        for i, dim in enumerate(self.encoding_dims):
            x = Dense(dim, activation=self.activation)(x)
            if self.dropout_rate > 0:
                x = Dropout(self.dropout_rate)(x)
                
        # Bottleneck layer (latent space)
        latent = x
        
        # Decoder layers (symmetric to encoder)
        for i, dim in enumerate(reversed(self.encoding_dims[:-1])):
            x = Dense(dim, activation=self.activation)(x)
            if self.dropout_rate > 0:
                x = Dropout(self.dropout_rate)(x)
                
        # Output layer
        outputs = Dense(self.input_dim, activation='linear')(x)
        
        # Create model
        model = Model(inputs=inputs, outputs=outputs)
        
        # Compile model
        optimizer = Adam(learning_rate=self.learning_rate)
        model.compile(optimizer=optimizer, loss='mse')
        
        self.model = model
        self.logger.info(f"Autoencoder built with {len(self.encoding_dims)} encoder layers")
        return model
    
    def _set_threshold(self, X: np.ndarray) -> float:
        """
        Calculate the anomaly threshold based on reconstruction errors.
        
        Args:
            X: Input data to calculate reconstruction errors
            
        Returns:
            Anomaly threshold value
        """
        # Get reconstruction errors
        reconstructions = self.model.predict(X)
        errors = np.mean(np.square(X - reconstructions), axis=1)
        
        # Set threshold as mean + n*std of reconstruction errors
        threshold = np.mean(errors) + self.threshold_multiplier * np.std(errors)
        self.threshold = threshold
        self.logger.info(f"Anomaly threshold set to {threshold:.6f}")
        return threshold
    
    def train(
        self,
        X_train: np.ndarray,
        y_train: Optional[np.ndarray] = None,  # Not used, included for API compatibility
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,  # Not used, included for API compatibility
        epochs: int = 50,
        batch_size: int = 32,
        patience: int = 10,
        verbose: int = 1,
        feature_names: Optional[List[str]] = None
    ) -> Dict:
        """
        Train the autoencoder model.
        
        Args:
            X_train: Training features
            y_train: Not used, included for API compatibility
            X_val: Validation features
            y_val: Not used, included for API compatibility
            epochs: Number of training epochs
            batch_size: Batch size
            patience: Patience for early stopping
            verbose: Verbosity level
            feature_names: Names of the feature columns
            
        Returns:
            Training history
        """
        # Save feature names if provided
        self.feature_names = feature_names
        
        # Fit the scaler
        X_train_scaled = self.scaler.fit_transform(X_train)
        
        # Scale validation data if provided
        X_val_scaled = None
        if X_val is not None:
            X_val_scaled = self.scaler.transform(X_val)
            
        # Build model if not already built
        if self.model is None:
            self.build_model()
            
        # Create model directory if it doesn't exist
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        # Callbacks
        callbacks = [
            EarlyStopping(monitor='val_loss' if X_val is not None else 'loss', 
                          patience=patience, restore_best_weights=True),
            ModelCheckpoint(
                filepath=self.model_path,
                monitor='val_loss' if X_val is not None else 'loss',
                save_best_only=True,
                verbose=0
            )
        ]
        
        # Training
        validation_data = (X_val_scaled, X_val_scaled) if X_val_scaled is not None else None
        
        self.history = self.model.fit(
            X_train_scaled, X_train_scaled,  # Autoencoder targets are the inputs
            validation_data=validation_data,
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callbacks,
            verbose=verbose
        )
        
        # Calculate anomaly threshold
        self._set_threshold(X_train_scaled)
        
        self.logger.info(f"Model trained for {len(self.history.history['loss'])} epochs")
        return self.history.history
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomaly scores for input data.
        
        Args:
            X: Input features
            
        Returns:
            Array of anomaly scores
        """
        if self.model is None:
            self.logger.error("Model not trained. Call train() first.")
            raise ValueError("Model not trained. Call train() first.")
            
        # Scale the input data
        X_scaled = self.scaler.transform(X)
        
        # Get reconstructions
        reconstructions = self.model.predict(X_scaled)
        
        # Calculate reconstruction errors (anomaly scores)
        errors = np.mean(np.square(X_scaled - reconstructions), axis=1)
        
        return errors
    
    def detect_anomalies(
        self, 
        X: np.ndarray, 
        threshold: Optional[float] = None
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Detect anomalies in the input data.
        
        Args:
            X: Input features
            threshold: Custom threshold (uses self.threshold if None)
            
        Returns:
            Tuple of (anomaly_flags, anomaly_scores)
        """
        # Get anomaly scores
        anomaly_scores = self.predict(X)
        
        # Use the provided threshold or the calculated one
        threshold = threshold if threshold is not None else self.threshold
        if threshold is None:
            self.logger.warning("No threshold set. Using mean + 3*std of scores.")
            threshold = np.mean(anomaly_scores) + 3 * np.std(anomaly_scores)
            
        # Detect anomalies
        anomalies = anomaly_scores > threshold
        
        return anomalies, anomaly_scores
    
    def evaluate(
        self, 
        X_test: np.ndarray, 
        y_test: Optional[np.ndarray] = None
    ) -> Dict[str, float]:
        """
        Evaluate the anomaly detection model.
        
        Args:
            X_test: Test features
            y_test: True anomaly labels (optional)
            
        Returns:
            Dictionary of evaluation metrics
        """
        if self.model is None:
            self.logger.error("Model not trained. Call train() first.")
            raise ValueError("Model not trained. Call train() first.")
        
        # Scale the test data
        X_test_scaled = self.scaler.transform(X_test)
        
        # Get reconstructions
        reconstructions = self.model.predict(X_test_scaled)
        
        # Calculate reconstruction error (MSE)
        mse = np.mean(np.square(X_test_scaled - reconstructions))
        
        metrics = {
            'reconstruction_mse': mse
        }
        
        # If true anomaly labels are provided, calculate classification metrics
        if y_test is not None:
            from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
            
            # Detect anomalies
            anomalies, scores = self.detect_anomalies(X_test)
            
            # Calculate metrics
            precision = precision_score(y_test, anomalies, zero_division=0)
            recall = recall_score(y_test, anomalies, zero_division=0)
            f1 = f1_score(y_test, anomalies, zero_division=0)
            
            # Add to metrics dictionary
            metrics.update({
                'precision': precision,
                'recall': recall,
                'f1': f1
            })
            
            # Add AUC if there are both positive and negative classes
            if len(np.unique(y_test)) > 1:
                try:
                    auc = roc_auc_score(y_test, scores)
                    metrics['auc'] = auc
                except:
                    self.logger.warning("Could not calculate AUC score.")
                    
            self.logger.info(f"Classification metrics - Precision: {precision:.4f}, Recall: {recall:.4f}, F1: {f1:.4f}")
        
        self.logger.info(f"Reconstruction MSE: {mse:.6f}")
        return metrics
    
    def save(self, path: Optional[str] = None) -> None:
        """
        Save the model to disk.
        
        Args:
            path: Path to save the model, uses self.model_path if None
        """
        if self.model is None:
            self.logger.error("No model to save. Call build_model() or train() first.")
            raise ValueError("No model to save")
            
        save_path = path if path is not None else self.model_path
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        # Save Keras model
        model_path = f"{save_path}_keras"
        self.model.save(model_path)
        
        # Save additional parameters
        import pickle
        params_path = f"{save_path}_params.pkl"
        
        with open(params_path, 'wb') as f:
            pickle.dump({
                'threshold': self.threshold,
                'scaler': self.scaler,
                'input_dim': self.input_dim,
                'encoding_dims': self.encoding_dims,
                'activation': self.activation,
                'dropout_rate': self.dropout_rate,
                'learning_rate': self.learning_rate,
                'threshold_multiplier': self.threshold_multiplier,
                'feature_names': self.feature_names
            }, f)
            
        self.logger.info(f"Model saved to {save_path}")
    
    def load(self, path: Optional[str] = None) -> None:
        """
        Load a trained model from disk.
        
        Args:
            path: Path to load the model from, uses self.model_path if None
        """
        load_path = path if path is not None else self.model_path
        
        # Check for model files
        model_path = f"{load_path}_keras"
        params_path = f"{load_path}_params.pkl"
        
        if not os.path.exists(model_path):
            self.logger.error(f"Model file not found at {model_path}")
            raise FileNotFoundError(f"Model file not found at {model_path}")
            
        if not os.path.exists(params_path):
            self.logger.error(f"Parameters file not found at {params_path}")
            raise FileNotFoundError(f"Parameters file not found at {params_path}")
            
        # Load Keras model
        self.model = load_model(model_path)
        
        # Load additional parameters
        import pickle
        with open(params_path, 'rb') as f:
            params = pickle.load(f)
            
        self.threshold = params['threshold']
        self.scaler = params['scaler']
        self.input_dim = params['input_dim']
        self.encoding_dims = params['encoding_dims']
        self.activation = params['activation']
        self.dropout_rate = params['dropout_rate']
        self.learning_rate = params['learning_rate']
        self.threshold_multiplier = params['threshold_multiplier']
        self.feature_names = params['feature_names']
        
        self.logger.info(f"Model loaded from {load_path}")
        
    def plot_anomalies(
        self,
        X: np.ndarray, 
        timestamps: Optional[np.ndarray] = None,
        title: str = "Anomaly Detection Results",
        save_path: Optional[str] = None
    ) -> plt.Figure:
        """
        Plot anomaly detection results.
        
        Args:
            X: Input features
            timestamps: Timestamps for the data points
            title: Plot title
            save_path: Path to save the plot
            
        Returns:
            Matplotlib figure
        """
        # Detect anomalies
        anomalies, scores = self.detect_anomalies(X)
        
        # Create figure
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10), sharex=True)
        
        # Plot anomaly scores
        x = timestamps if timestamps is not None else np.arange(len(scores))
        ax1.plot(x, scores, label='Anomaly Score')
        ax1.axhline(y=self.threshold, color='r', linestyle='--', label=f'Threshold ({self.threshold:.4f})')
        
        # Highlight anomalies
        if np.any(anomalies):
            ax1.scatter(x[anomalies], scores[anomalies], color='red', label='Anomaly')
            
        ax1.set_ylabel('Anomaly Score')
        ax1.set_title(f'{title} - {sum(anomalies)} Anomalies Detected')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Plot features
        if self.feature_names and len(self.feature_names) <= 5:  # Only plot if we have a reasonable number of features
            X_scaled = self.scaler.transform(X)
            for i, feature in enumerate(self.feature_names):
                ax2.plot(x, X_scaled[:, i], label=feature)
                
            # Highlight anomaly regions
            if np.any(anomalies):
                for i, is_anomaly in enumerate(anomalies):
                    if is_anomaly:
                        ax2.axvline(x=x[i], color='r', alpha=0.2)
                        
            ax2.set_ylabel('Normalized Feature Value')
            ax2.set_xlabel('Time' if timestamps is not None else 'Sample')
            ax2.legend()
            ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        # Save the plot if a path is provided
        if save_path:
            dir_path = os.path.dirname(save_path)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            self.logger.info(f"Plot saved to {save_path}")
            
        return fig
    
    def explain_anomalies(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        """
        Explain which features contributed most to anomalies.
        
        Args:
            X: Input features
            
        Returns:
            Dictionary with anomaly indices and feature contributions
        """
        # Scale the input data
        X_scaled = self.scaler.transform(X)
        
        # Get reconstructions
        reconstructions = self.model.predict(X_scaled)
        
        # Calculate reconstruction errors per feature
        feature_errors = np.square(X_scaled - reconstructions)
        
        # Detect anomalies
        anomalies, _ = self.detect_anomalies(X)
        anomaly_indices = np.where(anomalies)[0]
        
        if len(anomaly_indices) == 0:
            return {'anomaly_indices': np.array([]), 'feature_contributions': np.array([])}
        
        # Extract feature errors for anomalies
        anomaly_feature_errors = feature_errors[anomalies]
        
        # Normalize feature contributions
        feature_contributions = anomaly_feature_errors / np.sum(anomaly_feature_errors, axis=1, keepdims=True)
        
        # Create feature names if not provided
        feature_names = self.feature_names
        if feature_names is None:
            feature_names = [f"feature_{i}" for i in range(self.input_dim)]
        
        # Log the top contributing features for each anomaly
        for i, idx in enumerate(anomaly_indices):
            top_feature_idx = np.argmax(feature_contributions[i])
            self.logger.info(f"Anomaly at index {idx}: Top contributing feature is "
                             f"{feature_names[top_feature_idx]} "
                             f"({feature_contributions[i][top_feature_idx]:.2%})")
        
        return {
            'anomaly_indices': anomaly_indices,
            'feature_contributions': feature_contributions
        } 