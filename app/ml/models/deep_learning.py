import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from typing import Dict, List, Any, Union, Tuple

class DeepLearningModel:
    """Deep learning model for network traffic analysis."""
    
    def __init__(self, input_size: int = 10, hidden_size: int = 64):
        """
        Initialize the deep learning model.
        
        Args:
            input_size: Size of input features
            hidden_size: Size of hidden layers
        """
        self.model = self._build_model(input_size, hidden_size)
        self.optimizer = optim.Adam(self.model.parameters())
        self.loss_function = nn.BCELoss()
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.is_trained = False

    def _build_model(self, input_size: int, hidden_size: int) -> nn.Module:
        """
        Build the neural network architecture.
        
        Args:
            input_size: Size of input features
            hidden_size: Size of hidden layers
            
        Returns:
            PyTorch neural network model
        """
        return nn.Sequential(
            nn.Linear(input_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_size, 1),
            nn.Sigmoid()
        )

    def train(self, 
             X: np.ndarray, 
             y: np.ndarray, 
             epochs: int = 10, 
             batch_size: int = 32) -> Dict[str, List[float]]:
        """
        Train the deep learning model.
        
        Args:
            X: Feature matrix
            y: Target labels
            epochs: Number of training epochs
            batch_size: Size of training batches
            
        Returns:
            Dictionary containing training history
        """
        # Convert data to PyTorch tensors
        X_tensor = torch.FloatTensor(X).to(self.device)
        y_tensor = torch.FloatTensor(y).to(self.device)
        
        # Initialize history
        history = {
            'loss': [],
            'accuracy': []
        }
        
        # Training loop
        for epoch in range(epochs):
            # Shuffle data
            indices = torch.randperm(len(X))
            X_shuffled = X_tensor[indices]
            y_shuffled = y_tensor[indices]
            
            epoch_loss = 0
            epoch_accuracy = 0
            
            # Mini-batch training
            for i in range(0, len(X), batch_size):
                batch_X = X_shuffled[i:i+batch_size]
                batch_y = y_shuffled[i:i+batch_size]
                
                # Forward pass
                self.optimizer.zero_grad()
                outputs = self.model(batch_X).squeeze()
                loss = self.loss_function(outputs, batch_y)
                
                # Backward pass
                loss.backward()
                self.optimizer.step()
                
                # Calculate metrics
                predictions = (outputs > 0.5).float()
                accuracy = (predictions == batch_y).float().mean()
                
                epoch_loss += loss.item()
                epoch_accuracy += accuracy.item()
            
            # Average metrics
            epoch_loss /= (len(X) / batch_size)
            epoch_accuracy /= (len(X) / batch_size)
            
            # Store history
            history['loss'].append(epoch_loss)
            history['accuracy'].append(epoch_accuracy)
        
        self.is_trained = True
        return history

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Make predictions using the trained model.
        
        Args:
            X: Feature matrix
            
        Returns:
            Array of predictions
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before making predictions")
        
        # Convert to tensor
        X_tensor = torch.FloatTensor(X).to(self.device)
        
        # Make predictions
        with torch.no_grad():
            outputs = self.model(X_tensor)
            predictions = (outputs > 0.5).float().cpu().numpy()
        
        return predictions

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Get probability predictions from the model.
        
        Args:
            X: Feature matrix
            
        Returns:
            Array of probability predictions
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before making predictions")
        
        # Convert to tensor
        X_tensor = torch.FloatTensor(X).to(self.device)
        
        # Get probabilities
        with torch.no_grad():
            probabilities = self.model(X_tensor).cpu().numpy()
        
        return probabilities

    def evaluate(self, X: np.ndarray, y: np.ndarray) -> Dict[str, float]:
        """
        Evaluate the model's performance.
        
        Args:
            X: Feature matrix
            y: Target labels
            
        Returns:
            Dictionary of performance metrics
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before evaluation")
        
        # Make predictions
        predictions = self.predict(X)
        
        # Calculate metrics
        metrics = {
            'accuracy': accuracy_score(y, predictions),
            'precision': precision_score(y, predictions),
            'recall': recall_score(y, predictions),
            'f1_score': f1_score(y, predictions)
        }
        
        return metrics

    def save_model(self, path: str) -> None:
        """
        Save the trained model to a file.
        
        Args:
            path: Path to save the model
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before saving")
        
        torch.save({
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'input_size': self.model[0].in_features,
            'hidden_size': self.model[0].out_features
        }, path)

    def load_model(self, path: str) -> None:
        """
        Load a trained model from a file.
        
        Args:
            path: Path to load the model from
        """
        checkpoint = torch.load(path)
        self.model = self._build_model(
            checkpoint['input_size'],
            checkpoint['hidden_size']
        )
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        self.model.to(self.device)
        self.is_trained = True 