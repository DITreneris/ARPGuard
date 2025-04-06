import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Union, Any, Callable
from sklearn.model_selection import train_test_split
import logging
import os
import json
from datetime import datetime

class ModelTrainer:
    """
    Standardized training pipeline for machine learning models.
    """
    
    def __init__(
        self,
        model: Any,
        output_dir: str = "output",
        test_size: float = 0.2,
        val_size: float = 0.2,
        random_state: int = 42
    ):
        """
        Initialize the model training pipeline.
        
        Args:
            model: The model object to train (must have train, evaluate, save methods)
            output_dir: Directory to save outputs (models, logs, metrics)
            test_size: Proportion of data to use for testing
            val_size: Proportion of training data to use for validation
            random_state: Random seed for reproducibility
        """
        self.model = model
        self.output_dir = output_dir
        self.test_size = test_size
        self.val_size = val_size
        self.random_state = random_state
        self.train_history = None
        self.eval_metrics = None
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
    def _prepare_data(
        self, 
        X: np.ndarray, 
        y: np.ndarray
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Split data into train, validation, and test sets.
        
        Args:
            X: Features data
            y: Target data
            
        Returns:
            Tuple of (X_train, X_val, X_test, y_train, y_val, y_test)
        """
        # First split: training + validation vs test
        X_train_val, X_test, y_train_val, y_test = train_test_split(
            X, y, test_size=self.test_size, random_state=self.random_state
        )
        
        # Second split: training vs validation
        X_train, X_val, y_train, y_val = train_test_split(
            X_train_val, y_train_val, test_size=self.val_size, random_state=self.random_state
        )
        
        self.logger.info(f"Data prepared: Train: {X_train.shape[0]}, Val: {X_val.shape[0]}, Test: {X_test.shape[0]}")
        return X_train, X_val, X_test, y_train, y_val, y_test
    
    def train_and_evaluate(
        self, 
        X: np.ndarray, 
        y: np.ndarray,
        train_kwargs: Dict = {},
        eval_kwargs: Dict = {}
    ) -> Tuple[Dict, Dict]:
        """
        Train the model and evaluate performance.
        
        Args:
            X: Features data
            y: Target data
            train_kwargs: Additional kwargs to pass to model.train()
            eval_kwargs: Additional kwargs to pass to model.evaluate()
            
        Returns:
            Tuple of (training_history, evaluation_metrics)
        """
        # Prepare data
        X_train, X_val, X_test, y_train, y_val, y_test = self._prepare_data(X, y)
        
        # Train model
        self.logger.info("Starting model training...")
        train_start = datetime.now()
        
        train_kwargs['X_val'] = X_val
        train_kwargs['y_val'] = y_val
        
        self.train_history = self.model.train(
            X_train=X_train,
            y_train=y_train,
            **train_kwargs
        )
        
        train_duration = (datetime.now() - train_start).total_seconds()
        self.logger.info(f"Training completed in {train_duration:.2f} seconds")
        
        # Evaluate model
        self.logger.info("Evaluating model on test data...")
        self.eval_metrics = self.model.evaluate(X_test, y_test, **eval_kwargs)
        
        # Save metrics
        self._save_metrics()
        
        return self.train_history, self.eval_metrics
    
    def _save_metrics(self) -> None:
        """
        Save training history and evaluation metrics to disk.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save training history
        if self.train_history:
            # Convert numpy arrays to lists for JSON serialization
            serializable_history = {}
            for key, value in self.train_history.items():
                if isinstance(value, (np.ndarray, list)):
                    serializable_history[key] = value if isinstance(value, list) else value.tolist()
                else:
                    serializable_history[key] = value
            
            history_path = os.path.join(self.output_dir, f"training_history_{timestamp}.json")
            with open(history_path, 'w') as f:
                json.dump(serializable_history, f, indent=2)
            self.logger.info(f"Training history saved to {history_path}")
            
        # Save evaluation metrics
        if self.eval_metrics:
            # Convert to serializable format
            serializable_metrics = {}
            for key, value in self.eval_metrics.items():
                serializable_metrics[key] = float(value) if isinstance(value, np.number) else value
            
            metrics_path = os.path.join(self.output_dir, f"eval_metrics_{timestamp}.json")
            with open(metrics_path, 'w') as f:
                json.dump(serializable_metrics, f, indent=2)
            self.logger.info(f"Evaluation metrics saved to {metrics_path}")
    
    def cross_validate(
        self,
        X: np.ndarray,
        y: np.ndarray,
        n_splits: int = 5,
        train_kwargs: Dict = {},
        eval_kwargs: Dict = {}
    ) -> Dict[str, List]:
        """
        Perform cross-validation with the model.
        
        Args:
            X: Features data
            y: Target data
            n_splits: Number of cross-validation splits
            train_kwargs: Additional kwargs to pass to model.train()
            eval_kwargs: Additional kwargs to pass to model.evaluate()
            
        Returns:
            Dictionary of evaluation metrics for each fold
        """
        from sklearn.model_selection import KFold
        
        kf = KFold(n_splits=n_splits, shuffle=True, random_state=self.random_state)
        
        results = {
            'fold': [],
            'train_duration': []
        }
        
        for fold, (train_idx, test_idx) in enumerate(kf.split(X)):
            self.logger.info(f"Training fold {fold+1}/{n_splits}")
            
            # Split data
            X_train_val, X_test = X[train_idx], X[test_idx]
            y_train_val, y_test = y[train_idx], y[test_idx]
            
            # Further split train into train/val
            X_train, X_val, y_train, y_val = train_test_split(
                X_train_val, y_train_val, 
                test_size=self.val_size, 
                random_state=self.random_state
            )
            
            # Train model
            train_kwargs['X_val'] = X_val
            train_kwargs['y_val'] = y_val
            
            train_start = datetime.now()
            history = self.model.train(X_train, y_train, **train_kwargs)
            train_duration = (datetime.now() - train_start).total_seconds()
            
            # Evaluate model
            metrics = self.model.evaluate(X_test, y_test, **eval_kwargs)
            
            # Store results
            results['fold'].append(fold+1)
            results['train_duration'].append(train_duration)
            
            for metric_name, metric_value in metrics.items():
                if metric_name not in results:
                    results[metric_name] = []
                results[metric_name].append(metric_value)
        
        # Calculate average metrics
        for metric_name in list(results.keys()):
            if metric_name not in ['fold']:
                results[f'avg_{metric_name}'] = np.mean(results[metric_name])
        
        # Save cross-validation results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        cv_path = os.path.join(self.output_dir, f"cv_results_{timestamp}.json")
        
        # Convert to serializable format
        serializable_results = {}
        for key, value in results.items():
            if isinstance(value, (np.ndarray, list)):
                serializable_results[key] = [float(v) if isinstance(v, np.number) else v for v in value]
            else:
                serializable_results[key] = float(value) if isinstance(value, np.number) else value
        
        with open(cv_path, 'w') as f:
            json.dump(serializable_results, f, indent=2)
        
        self.logger.info(f"Cross-validation results saved to {cv_path}")
        return results 