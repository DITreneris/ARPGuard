import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from typing import Dict, List, Any, Union

class EnsembleModel:
    """Ensemble model combining multiple base models for improved performance."""
    
    def __init__(self):
        """Initialize the ensemble model with base models."""
        self.models = [
            RandomForestClassifier(n_estimators=100, random_state=42),
            GradientBoostingClassifier(n_estimators=100, random_state=42),
            SVC(probability=True, random_state=42)
        ]
        self.weights = None
        self.is_trained = False

    def train(self, X: np.ndarray, y: np.ndarray) -> None:
        """
        Train the ensemble model.
        
        Args:
            X: Feature matrix
            y: Target labels
        """
        # Train each base model
        for model in self.models:
            model.fit(X, y)
        
        # Calculate model weights based on performance
        self._calculate_weights(X, y)
        self.is_trained = True

    def _calculate_weights(self, X: np.ndarray, y: np.ndarray) -> None:
        """
        Calculate weights for each model based on their performance.
        
        Args:
            X: Feature matrix
            y: Target labels
        """
        # Get predictions from each model
        predictions = [model.predict(X) for model in self.models]
        
        # Calculate accuracy for each model
        accuracies = [accuracy_score(y, pred) for pred in predictions]
        
        # Normalize accuracies to get weights
        total_accuracy = sum(accuracies)
        self.weights = [acc / total_accuracy for acc in accuracies]

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Make predictions using the ensemble model.
        
        Args:
            X: Feature matrix
            
        Returns:
            Array of predictions
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before making predictions")
        
        # Get predictions from each model
        predictions = [model.predict(X) for model in self.models]
        
        # Weight the predictions
        weighted_predictions = np.zeros_like(predictions[0], dtype=float)
        for pred, weight in zip(predictions, self.weights):
            weighted_predictions += pred * weight
        
        # Convert to binary predictions
        return (weighted_predictions > 0.5).astype(int)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Get probability predictions from the ensemble model.
        
        Args:
            X: Feature matrix
            
        Returns:
            Array of probability predictions
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before making predictions")
        
        # Get probability predictions from each model
        probas = [model.predict_proba(X)[:, 1] for model in self.models]
        
        # Weight the probabilities
        weighted_probas = np.zeros_like(probas[0], dtype=float)
        for proba, weight in zip(probas, self.weights):
            weighted_probas += proba * weight
        
        return weighted_probas

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

    def get_feature_importance(self) -> Dict[str, float]:
        """
        Get feature importance from the ensemble model.
        
        Returns:
            Dictionary mapping feature names to importance scores
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before getting feature importance")
        
        # Get feature importance from each model
        importances = []
        for model in self.models:
            if hasattr(model, 'feature_importances_'):
                importances.append(model.feature_importances_)
            elif hasattr(model, 'coef_'):
                importances.append(np.abs(model.coef_[0]))
        
        # Weight the importances
        weighted_importances = np.zeros_like(importances[0], dtype=float)
        for imp, weight in zip(importances, self.weights):
            weighted_importances += imp * weight
        
        # Normalize importances
        weighted_importances = weighted_importances / weighted_importances.sum()
        
        return dict(zip(range(len(weighted_importances)), weighted_importances)) 