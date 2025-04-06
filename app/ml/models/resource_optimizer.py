import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Union, Any
from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
from sklearn.base import BaseEstimator
from sklearn.multioutput import MultiOutputRegressor
from joblib import dump, load
import os
import logging

class ResourceUsageOptimizer:
    """
    Resource Usage Optimizer that combines Random Forest and Gradient Boosting 
    to predict and optimize resource allocation based on performance metrics.
    """
    
    def __init__(
        self,
        mode: str = 'ensemble',  # 'rf', 'gb', or 'ensemble'
        n_estimators: int = 100,
        max_depth: Optional[int] = None,
        min_samples_split: int = 2,
        min_samples_leaf: int = 1,
        multi_output: bool = False,
        model_path: str = "models/resource_optimizer"
    ):
        """
        Initialize the Resource Usage Optimizer.
        
        Args:
            mode: Model type ('rf' for Random Forest, 'gb' for Gradient Boosting, 'ensemble' for both)
            n_estimators: Number of trees in the forest
            max_depth: Maximum depth of the trees
            min_samples_split: Minimum samples required to split a node
            min_samples_leaf: Minimum samples required at a leaf node
            multi_output: Whether to support multiple target variables
            model_path: Path to save/load the model
        """
        self.mode = mode
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.min_samples_leaf = min_samples_leaf
        self.multi_output = multi_output
        self.model_path = model_path
        self.rf_model = None
        self.gb_model = None
        self.feature_names = None
        self.target_names = None
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
    def build_models(self) -> Dict[str, BaseEstimator]:
        """
        Build the Random Forest and/or Gradient Boosting models.
        
        Returns:
            Dictionary of initialized models
        """
        models = {}
        
        if self.mode in ['rf', 'ensemble']:
            # Initialize Random Forest model
            rf = RandomForestRegressor(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth,
                min_samples_split=self.min_samples_split,
                min_samples_leaf=self.min_samples_leaf,
                random_state=42
            )
            
            # Wrap with MultiOutputRegressor if needed
            if self.multi_output:
                rf = MultiOutputRegressor(rf)
                
            self.rf_model = rf
            models['rf'] = rf
            self.logger.info("Random Forest model built")
            
        if self.mode in ['gb', 'ensemble']:
            # Initialize Gradient Boosting model
            gb = GradientBoostingRegressor(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth if self.max_depth else 3,
                min_samples_split=self.min_samples_split,
                min_samples_leaf=self.min_samples_leaf,
                random_state=42
            )
            
            # Wrap with MultiOutputRegressor if needed
            if self.multi_output:
                gb = MultiOutputRegressor(gb)
                
            self.gb_model = gb
            models['gb'] = gb
            self.logger.info("Gradient Boosting model built")
            
        return models
    
    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        feature_names: Optional[List[str]] = None,
        target_names: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Train the model(s).
        
        Args:
            X_train: Training features
            y_train: Training targets
            X_val: Validation features (unused, included for API compatibility)
            y_val: Validation targets (unused, included for API compatibility)
            feature_names: Names of the feature columns
            target_names: Names of the target columns
            
        Returns:
            Training results as a dictionary
        """
        # Save feature and target names
        self.feature_names = feature_names
        self.target_names = target_names
        
        # Build models if not already built
        if self.rf_model is None and self.gb_model is None:
            self.build_models()
            
        training_results = {}
        
        # Train Random Forest
        if self.rf_model:
            self.logger.info("Training Random Forest model...")
            self.rf_model.fit(X_train, y_train)
            training_results['rf_training_complete'] = True
            
        # Train Gradient Boosting
        if self.gb_model:
            self.logger.info("Training Gradient Boosting model...")
            self.gb_model.fit(X_train, y_train)
            training_results['gb_training_complete'] = True
            
        self.logger.info("Model training completed")
        return training_results
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Make predictions by combining predictions from RF and GB models.
        
        Args:
            X: Input features
            
        Returns:
            Predicted values
        """
        predictions = []
        
        # Predict with Random Forest
        if self.rf_model:
            rf_pred = self.rf_model.predict(X)
            predictions.append(rf_pred)
            
        # Predict with Gradient Boosting
        if self.gb_model:
            gb_pred = self.gb_model.predict(X)
            predictions.append(gb_pred)
            
        # Combine predictions based on mode
        if self.mode == 'rf':
            final_pred = predictions[0]
        elif self.mode == 'gb':
            final_pred = predictions[0]
        elif self.mode == 'ensemble':
            # Average the predictions from both models
            final_pred = np.mean(predictions, axis=0)
            
        return final_pred
    
    def evaluate(
        self, 
        X_test: np.ndarray, 
        y_test: np.ndarray
    ) -> Dict[str, float]:
        """
        Evaluate the model on test data.
        
        Args:
            X_test: Test features
            y_test: Test targets
            
        Returns:
            Dictionary of evaluation metrics
        """
        from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
        
        # Make predictions
        y_pred = self.predict(X_test)
        
        # Calculate metrics
        mse = mean_squared_error(y_test, y_pred)
        rmse = np.sqrt(mse)
        mae = mean_absolute_error(y_test, y_pred)
        r2 = r2_score(y_test, y_pred)
        
        metrics = {
            'mse': mse,
            'rmse': rmse,
            'mae': mae,
            'r2': r2
        }
        
        self.logger.info(f"Model evaluation - RMSE: {rmse:.4f}, MAE: {mae:.4f}, R²: {r2:.4f}")
        return metrics
    
    def get_feature_importance(self) -> Dict[str, Dict[str, float]]:
        """
        Get feature importance from the models.
        
        Returns:
            Dictionary of feature importances
        """
        importance = {}
        
        # Get feature names (use indices if names not provided)
        feature_names = self.feature_names
        if feature_names is None:
            feature_names = [f"feature_{i}" for i in range(self.rf_model.n_features_in_ if hasattr(self.rf_model, 'n_features_in_') else 0)]
            
        # Get Random Forest feature importance
        if self.rf_model:
            if hasattr(self.rf_model, 'feature_importances_'):
                rf_importance = self.rf_model.feature_importances_
                importance['rf'] = dict(zip(feature_names, rf_importance))
            elif hasattr(self.rf_model, 'estimators_'):
                # For MultiOutputRegressor
                rf_importance = np.mean([estimator.feature_importances_ for estimator in self.rf_model.estimators_], axis=0)
                importance['rf'] = dict(zip(feature_names, rf_importance))
                
        # Get Gradient Boosting feature importance
        if self.gb_model:
            if hasattr(self.gb_model, 'feature_importances_'):
                gb_importance = self.gb_model.feature_importances_
                importance['gb'] = dict(zip(feature_names, gb_importance))
            elif hasattr(self.gb_model, 'estimators_'):
                # For MultiOutputRegressor
                gb_importance = np.mean([estimator.feature_importances_ for estimator in self.gb_model.estimators_], axis=0)
                importance['gb'] = dict(zip(feature_names, gb_importance))
                
        return importance
    
    def save(self, path: Optional[str] = None) -> None:
        """
        Save the model to disk.
        
        Args:
            path: Path to save the model, uses self.model_path if None
        """
        save_path = path if path is not None else self.model_path
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        # Save models and metadata
        model_data = {
            'mode': self.mode,
            'rf_model': self.rf_model,
            'gb_model': self.gb_model,
            'feature_names': self.feature_names,
            'target_names': self.target_names,
            'multi_output': self.multi_output,
            'model_params': {
                'n_estimators': self.n_estimators,
                'max_depth': self.max_depth,
                'min_samples_split': self.min_samples_split,
                'min_samples_leaf': self.min_samples_leaf
            }
        }
        
        dump(model_data, save_path)
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
            
        model_data = load(load_path)
        
        self.mode = model_data['mode']
        self.rf_model = model_data['rf_model']
        self.gb_model = model_data['gb_model']
        self.feature_names = model_data['feature_names']
        self.target_names = model_data['target_names']
        self.multi_output = model_data['multi_output']
        
        # Update parameters
        params = model_data['model_params']
        self.n_estimators = params['n_estimators']
        self.max_depth = params['max_depth']
        self.min_samples_split = params['min_samples_split']
        self.min_samples_leaf = params['min_samples_leaf']
        
        self.logger.info(f"Model loaded from {load_path}")
        
    def optimize_resources(
        self, 
        X: np.ndarray, 
        constraints: Optional[Dict[str, Dict[str, float]]] = None
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Optimize resource allocation based on performance predictions.
        
        Args:
            X: Input features for prediction
            constraints: Dictionary of constraints for each target variable
                e.g. {'cpu_allocation': {'min': 0.1, 'max': 0.9}}
                
        Returns:
            Tuple of (optimized_allocation, optimization_details)
        """
        # Get predictions
        predictions = self.predict(X)
        
        # Initialize optimized allocations with predictions
        optimized = predictions.copy()
        
        # Apply constraints if provided
        if constraints and self.target_names:
            for i, target in enumerate(self.target_names):
                if target in constraints:
                    constraint = constraints[target]
                    
                    # Apply minimum constraint
                    if 'min' in constraint:
                        optimized[:, i] = np.maximum(optimized[:, i], constraint['min'])
                        
                    # Apply maximum constraint
                    if 'max' in constraint:
                        optimized[:, i] = np.minimum(optimized[:, i], constraint['max'])
        
        # Generate optimization details
        details = {
            'original_predictions': predictions,
            'optimized_allocations': optimized,
            'adjustments': optimized - predictions
        }
        
        return optimized, details 