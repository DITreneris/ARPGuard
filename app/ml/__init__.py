"""
ARPGuard ML Module

This module contains machine learning components for network monitoring and security,
including traffic prediction, resource optimization, and anomaly detection.
"""

import os
import logging

# Create model storage directory if it doesn't exist
def init_ml_directories():
    """Initialize ML directories for model storage and outputs."""
    # Get base directory
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    
    # Create model storage directory
    model_dir = os.path.join(base_dir, 'data', 'ml_models')
    os.makedirs(model_dir, exist_ok=True)
    
    # Create output directory
    output_dir = os.path.join(base_dir, 'data', 'ml_output')
    os.makedirs(output_dir, exist_ok=True)
    
    return model_dir, output_dir

# Initialize directories when module is imported
model_dir, output_dir = init_ml_directories() 