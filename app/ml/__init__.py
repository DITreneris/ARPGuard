"""
Machine Learning module for ARPGuard.

This module provides rule-based and machine learning based threat detection
capabilities for ARP-based attacks.
"""

import os
import logging
from app.utils.logger import get_logger

# Get module logger
logger = get_logger("ml")

# Create model storage directory if it doesn't exist
def init_ml_directories():
    """Initialize ML directories for model storage and outputs."""
    # Create model storage directory
    model_dir = os.path.join('data', 'ml_models')
    os.makedirs(model_dir, exist_ok=True)
    
    # Create sample data directory
    samples_dir = os.path.join('data', 'ml_samples')
    os.makedirs(samples_dir, exist_ok=True)
    
    # Create specific sample type directories
    for sample_type in ['benign', 'spoofing', 'mitm', 'dos', 'recon', 'collected']:
        type_dir = os.path.join(samples_dir, sample_type)
        os.makedirs(type_dir, exist_ok=True)
    
    # Create output directory
    output_dir = os.path.join('data', 'ml_output')
    os.makedirs(output_dir, exist_ok=True)
    
    # Create stats directory
    stats_dir = os.path.join('data', 'ml_stats')
    os.makedirs(stats_dir, exist_ok=True)
    
    logger.info(f"ML directories initialized")
    return model_dir, output_dir

# Import core modules
from app.ml.engine import MLEngine
from app.ml.feature_extraction import FeatureExtractor
from app.ml.controller import MLController

# Initialize directories when module is imported
model_dir, output_dir = init_ml_directories()

__all__ = ['MLController', 'MLEngine', 'FeatureExtractor'] 