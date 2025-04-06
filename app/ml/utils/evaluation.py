import numpy as np
import pandas as pd
from typing import Dict, List, Union, Optional, Tuple
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    mean_squared_error,
    mean_absolute_error,
    mean_absolute_percentage_error,
    r2_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_curve,
    auc,
    precision_recall_curve,
    average_precision_score
)
import os
import logging
from datetime import datetime

class ModelEvaluator:
    """
    Utility class for evaluating machine learning models with
    various metrics and visualization capabilities.
    """
    
    def __init__(self, output_dir: str = "output/evaluation"):
        """
        Initialize the model evaluator.
        
        Args:
            output_dir: Directory to save evaluation outputs
        """
        self.output_dir = output_dir
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
    
    def evaluate_regression(
        self, 
        y_true: np.ndarray, 
        y_pred: np.ndarray
    ) -> Dict[str, float]:
        """
        Evaluate regression model performance.
        
        Args:
            y_true: Ground truth target values
            y_pred: Predicted values
            
        Returns:
            Dictionary of evaluation metrics
        """
        metrics = {
            'mse': mean_squared_error(y_true, y_pred),
            'rmse': np.sqrt(mean_squared_error(y_true, y_pred)),
            'mae': mean_absolute_error(y_true, y_pred),
            'mape': mean_absolute_percentage_error(y_true, y_pred),
            'r2': r2_score(y_true, y_pred)
        }
        
        self.logger.info(f"Regression metrics - RMSE: {metrics['rmse']:.4f}, MAE: {metrics['mae']:.4f}, R²: {metrics['r2']:.4f}")
        return metrics
    
    def evaluate_classification(
        self, 
        y_true: np.ndarray, 
        y_pred: np.ndarray,
        y_prob: Optional[np.ndarray] = None,
        average: str = 'weighted'
    ) -> Dict[str, float]:
        """
        Evaluate classification model performance.
        
        Args:
            y_true: Ground truth target values
            y_pred: Predicted class labels
            y_prob: Predicted class probabilities (for ROC/AUC)
            average: Method for averaging metrics in multiclass case
            
        Returns:
            Dictionary of evaluation metrics
        """
        metrics = {
            'precision': precision_score(y_true, y_pred, average=average, zero_division=0),
            'recall': recall_score(y_true, y_pred, average=average, zero_division=0),
            'f1': f1_score(y_true, y_pred, average=average, zero_division=0),
        }
        
        # Add AUC if probabilities are provided
        if y_prob is not None:
            # For binary classification
            if y_prob.shape[1] if len(y_prob.shape) > 1 else 1 == 2:
                fpr, tpr, _ = roc_curve(y_true, y_prob[:, 1] if len(y_prob.shape) > 1 else y_prob)
                metrics['auc'] = auc(fpr, tpr)
            
        self.logger.info(f"Classification metrics - Precision: {metrics['precision']:.4f}, Recall: {metrics['recall']:.4f}, F1: {metrics['f1']:.4f}")
        return metrics
    
    def evaluate_timeseries(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        timestamps: Optional[np.ndarray] = None
    ) -> Dict[str, float]:
        """
        Evaluate time series forecasting model performance.
        
        Args:
            y_true: Ground truth target values
            y_pred: Predicted values
            timestamps: Timestamps for the predictions
            
        Returns:
            Dictionary of evaluation metrics
        """
        # Basic regression metrics
        metrics = self.evaluate_regression(y_true, y_pred)
        
        # Add time series specific metrics
        
        # Mean Absolute Scaled Error (MASE) - if we have enough data points
        if len(y_true) > 1:
            # Calculate naive forecast (using previous value)
            naive_forecast = np.roll(y_true, 1)
            naive_forecast[0] = y_true[0]  # Replace first value
            
            # Calculate MAE of naive forecast
            naive_mae = mean_absolute_error(y_true[1:], naive_forecast[1:])
            
            # Calculate MASE
            if naive_mae > 0:
                metrics['mase'] = mean_absolute_error(y_true, y_pred) / naive_mae
            else:
                metrics['mase'] = np.nan
        
        self.logger.info(f"Time series metrics - RMSE: {metrics['rmse']:.4f}, MAE: {metrics['mae']:.4f}, MAPE: {metrics['mape']:.4f}")
        return metrics
    
    def plot_prediction_vs_actual(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        timestamps: Optional[np.ndarray] = None,
        title: str = "Prediction vs Actual",
        ylabel: str = "Value",
        save_path: Optional[str] = None
    ) -> plt.Figure:
        """
        Plot predicted values against actual values.
        
        Args:
            y_true: Ground truth target values
            y_pred: Predicted values
            timestamps: Timestamps for the predictions
            title: Plot title
            ylabel: Y-axis label
            save_path: Path to save the plot
            
        Returns:
            Matplotlib figure object
        """
        plt.figure(figsize=(12, 6))
        
        if timestamps is not None:
            plt.plot(timestamps, y_true, label='Actual', marker='o', linestyle='-', alpha=0.7)
            plt.plot(timestamps, y_pred, label='Predicted', marker='x', linestyle='--', alpha=0.7)
            plt.xlabel('Time')
        else:
            plt.plot(y_true, label='Actual', marker='o', linestyle='-', alpha=0.7)
            plt.plot(y_pred, label='Predicted', marker='x', linestyle='--', alpha=0.7)
            plt.xlabel('Sample')
        
        plt.ylabel(ylabel)
        plt.title(title)
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        # Calculate metrics for annotation
        rmse = np.sqrt(mean_squared_error(y_true, y_pred))
        mae = mean_absolute_error(y_true, y_pred)
        
        # Add metrics as text annotation
        plt.annotate(f'RMSE: {rmse:.4f}\nMAE: {mae:.4f}', 
                     xy=(0.05, 0.95), 
                     xycoords='axes fraction',
                     bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.8))
        
        plt.tight_layout()
        
        # Save the plot if a path is provided
        if save_path:
            dir_path = os.path.dirname(save_path)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            self.logger.info(f"Plot saved to {save_path}")
        
        return plt.gcf()
    
    def plot_residuals(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        title: str = "Residual Plot",
        save_path: Optional[str] = None
    ) -> plt.Figure:
        """
        Plot residuals (prediction errors) for regression model.
        
        Args:
            y_true: Ground truth target values
            y_pred: Predicted values
            title: Plot title
            save_path: Path to save the plot
            
        Returns:
            Matplotlib figure object
        """
        residuals = y_true - y_pred
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Residuals vs Predicted values
        ax1.scatter(y_pred, residuals, alpha=0.6)
        ax1.axhline(y=0, color='r', linestyle='--')
        ax1.set_xlabel('Predicted Values')
        ax1.set_ylabel('Residuals')
        ax1.set_title('Residuals vs Predicted Values')
        ax1.grid(True, alpha=0.3)
        
        # Residual distribution
        sns.histplot(residuals, kde=True, ax=ax2)
        ax2.axvline(x=0, color='r', linestyle='--')
        ax2.set_xlabel('Residual Value')
        ax2.set_ylabel('Frequency')
        ax2.set_title('Residual Distribution')
        
        fig.suptitle(title, fontsize=14)
        plt.tight_layout()
        plt.subplots_adjust(top=0.9)
        
        # Save the plot if a path is provided
        if save_path:
            dir_path = os.path.dirname(save_path)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            self.logger.info(f"Residual plot saved to {save_path}")
        
        return fig
    
    def plot_confusion_matrix(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        labels: Optional[List[str]] = None,
        title: str = "Confusion Matrix",
        save_path: Optional[str] = None
    ) -> plt.Figure:
        """
        Plot confusion matrix for classification model.
        
        Args:
            y_true: Ground truth target values
            y_pred: Predicted class labels
            labels: Class labels
            title: Plot title
            save_path: Path to save the plot
            
        Returns:
            Matplotlib figure object
        """
        cm = confusion_matrix(y_true, y_pred)
        
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                    xticklabels=labels, yticklabels=labels)
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.title(title)
        plt.tight_layout()
        
        # Save the plot if a path is provided
        if save_path:
            dir_path = os.path.dirname(save_path)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            self.logger.info(f"Confusion matrix saved to {save_path}")
        
        return plt.gcf()
    
    def generate_evaluation_report(
        self,
        model_name: str,
        metrics: Dict[str, float],
        y_true: np.ndarray,
        y_pred: np.ndarray,
        timestamps: Optional[np.ndarray] = None,
        is_classification: bool = False,
        y_prob: Optional[np.ndarray] = None,
        class_labels: Optional[List[str]] = None
    ) -> str:
        """
        Generate a comprehensive evaluation report with metrics and plots.
        
        Args:
            model_name: Name of the model
            metrics: Dictionary of evaluation metrics
            y_true: Ground truth target values
            y_pred: Predicted values
            timestamps: Timestamps for the predictions
            is_classification: Whether this is a classification model
            y_prob: Predicted class probabilities (for classification)
            class_labels: Class labels (for classification)
            
        Returns:
            Path to the generated report directory
        """
        # Create a timestamped directory for this evaluation
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = os.path.join(self.output_dir, f"{model_name}_{timestamp}")
        os.makedirs(report_dir, exist_ok=True)
        
        # Save metrics to JSON
        metrics_path = os.path.join(report_dir, "metrics.json")
        pd.Series(metrics).to_json(metrics_path)
        
        # Generate appropriate plots
        if is_classification:
            # Confusion matrix
            cm_path = os.path.join(report_dir, "confusion_matrix.png")
            self.plot_confusion_matrix(
                y_true, y_pred, labels=class_labels,
                title=f"{model_name} - Confusion Matrix",
                save_path=cm_path
            )
            
            # ROC curve for binary classification
            if y_prob is not None and (len(np.unique(y_true)) == 2):
                prob_col = 1 if y_prob.shape[1] > 1 else 0
                fpr, tpr, _ = roc_curve(y_true, y_prob[:, prob_col] if len(y_prob.shape) > 1 else y_prob)
                roc_auc = auc(fpr, tpr)
                
                plt.figure(figsize=(8, 8))
                plt.plot(fpr, tpr, color='darkorange', lw=2, 
                         label=f'ROC curve (area = {roc_auc:.2f})')
                plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
                plt.xlim([0.0, 1.0])
                plt.ylim([0.0, 1.05])
                plt.xlabel('False Positive Rate')
                plt.ylabel('True Positive Rate')
                plt.title(f"{model_name} - ROC Curve")
                plt.legend(loc="lower right")
                
                roc_path = os.path.join(report_dir, "roc_curve.png")
                plt.savefig(roc_path, dpi=300, bbox_inches='tight')
                plt.close()
        else:
            # Prediction vs Actual
            pred_path = os.path.join(report_dir, "prediction_vs_actual.png")
            self.plot_prediction_vs_actual(
                y_true, y_pred, timestamps=timestamps,
                title=f"{model_name} - Prediction vs Actual",
                save_path=pred_path
            )
            
            # Residuals
            resid_path = os.path.join(report_dir, "residuals.png")
            self.plot_residuals(
                y_true, y_pred,
                title=f"{model_name} - Residual Analysis",
                save_path=resid_path
            )
        
        self.logger.info(f"Evaluation report generated in {report_dir}")
        return report_dir 