import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from tensorflow.keras.optimizers import Adam
from typing import Dict, List, Tuple, Optional, Union
import os
import logging

class LSTMTrafficPredictor:
    """
    LSTM model for predicting network traffic patterns.
    Uses sequential time-series data to forecast future network traffic.
    """
    
    def __init__(
        self,
        input_dim: int = 5,
        sequence_length: int = 24,
        lstm_units: List[int] = [64, 32],
        dropout_rate: float = 0.2,
        learning_rate: float = 0.001,
        model_path: str = "models/lstm_traffic_model"
    ):
        """
        Initialize the LSTM Traffic Predictor model.
        
        Args:
            input_dim: Number of input features
            sequence_length: Length of input sequences (time steps)
            lstm_units: List of units for each LSTM layer
            dropout_rate: Dropout rate for regularization
            learning_rate: Learning rate for the Adam optimizer
            model_path: Path to save/load the model
        """
        self.input_dim = input_dim
        self.sequence_length = sequence_length
        self.lstm_units = lstm_units
        self.dropout_rate = dropout_rate
        self.learning_rate = learning_rate
        self.model_path = model_path
        self.model = None
        self.history = None
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def build_model(self) -> Sequential:
        """
        Build and compile the LSTM model.
        
        Returns:
            Compiled Keras Sequential model
        """
        model = Sequential()
        
        # Add LSTM layers
        for i, units in enumerate(self.lstm_units):
            if i == 0:
                # First layer needs input shape
                model.add(LSTM(
                    units=units,
                    return_sequences=(i < len(self.lstm_units) - 1),
                    input_shape=(self.sequence_length, self.input_dim)
                ))
            else:
                model.add(LSTM(
                    units=units,
                    return_sequences=(i < len(self.lstm_units) - 1)
                ))
                
            # Add dropout after each LSTM layer
            model.add(Dropout(self.dropout_rate))
        
        # Output layer
        model.add(Dense(1))
        
        # Compile model
        optimizer = Adam(learning_rate=self.learning_rate)
        model.compile(optimizer=optimizer, loss='mse', metrics=['mae'])
        
        self.model = model
        self.logger.info(f"LSTM model built with {len(self.lstm_units)} LSTM layers")
        return model
    
    def _prepare_sequences(
        self, 
        data: np.ndarray, 
        target_idx: int = -1
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Prepare sequences for LSTM training.
        
        Args:
            data: Input data array
            target_idx: Index of the target variable in the data
            
        Returns:
            X: Sequence input data
            y: Target values
        """
        X, y = [], []
        
        for i in range(len(data) - self.sequence_length):
            # Extract sequence
            seq = data[i:i+self.sequence_length]
            # Extract target (next value after sequence)
            target = data[i+self.sequence_length, target_idx]
            
            X.append(seq)
            y.append(target)
            
        return np.array(X), np.array(y)
    
    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        epochs: int = 50,
        batch_size: int = 32,
        patience: int = 10,
        verbose: int = 1
    ) -> Dict:
        """
        Train the LSTM model.
        
        Args:
            X_train: Training sequences
            y_train: Training targets
            X_val: Validation sequences
            y_val: Validation targets
            epochs: Number of training epochs
            batch_size: Batch size
            patience: Patience for early stopping
            verbose: Verbosity level
            
        Returns:
            Training history
        """
        if self.model is None:
            self.build_model()
            
        # Create model directory if it doesn't exist
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        # Callbacks
        callbacks = [
            EarlyStopping(monitor='val_loss', patience=patience, restore_best_weights=True),
            ModelCheckpoint(
                filepath=self.model_path,
                monitor='val_loss',
                save_best_only=True,
                verbose=0
            )
        ]
        
        # Training
        validation_data = (X_val, y_val) if X_val is not None and y_val is not None else None
        
        self.history = self.model.fit(
            X_train, y_train,
            validation_data=validation_data,
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callbacks,
            verbose=verbose
        )
        
        self.logger.info(f"Model trained for {len(self.history.history['loss'])} epochs")
        return self.history.history
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Make predictions with the trained model.
        
        Args:
            X: Input sequences
            
        Returns:
            Predicted values
        """
        if self.model is None:
            self.logger.error("Model not trained. Call train() first.")
            raise ValueError("Model not trained. Call train() first.")
            
        return self.model.predict(X)
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, float]:
        """
        Evaluate the model on test data.
        
        Args:
            X_test: Test sequences
            y_test: Test targets
            
        Returns:
            Dictionary of evaluation metrics
        """
        if self.model is None:
            self.logger.error("Model not trained. Call train() first.")
            raise ValueError("Model not trained. Call train() first.")
            
        loss, mae = self.model.evaluate(X_test, y_test, verbose=0)
        
        metrics = {
            'loss': loss,
            'mae': mae
        }
        
        self.logger.info(f"Model evaluation - Loss: {loss:.4f}, MAE: {mae:.4f}")
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
        self.model.save(save_path)
        self.logger.info(f"Model saved to {save_path}")
    
    def load(self, path: Optional[str] = None) -> None:
        """
        Load a trained model from disk.
        
        Args:
            path: Path to load the model from, uses self.model_path if None
        """
        load_path = path if path is not None else self.model_path
        
        if not os.path.exists(load_path):
            self.logger.error(f"Model file not found at {load_path}")
            raise FileNotFoundError(f"Model file not found at {load_path}")
            
        self.model = load_model(load_path)
        self.logger.info(f"Model loaded from {load_path}") 