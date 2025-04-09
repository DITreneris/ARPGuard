#!/usr/bin/env python3
"""
Test script for the ML-based detection system.

This script loads sample ARP packets, trains ML models,
and tests detection capabilities.
"""

import os
import sys
import json
import time
import random
from datetime import datetime
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from app.ml import MLController
from app.utils.logger import setup_logger

# Set up logging
log_file = os.path.join(project_root, 'logs', 'ml_test.log')
logger = setup_logger('ml_test', log_file)

def load_sample_data(data_dir, sample_type):
    """Load sample data from a file.
    
    Args:
        data_dir: Base directory for sample data
        sample_type: Type of sample to load (benign, spoofing, etc.)
        
    Returns:
        List of sample packets
    """
    samples = []
    
    try:
        # Path to sample data
        sample_dir = os.path.join(data_dir, sample_type)
        
        # Check if directory exists
        if not os.path.exists(sample_dir):
            logger.error(f"Sample directory not found: {sample_dir}")
            return samples
            
        # Find all JSON files
        json_files = [f for f in os.listdir(sample_dir) if f.endswith('.json')]
        
        if not json_files:
            logger.error(f"No JSON files found in {sample_dir}")
            return samples
            
        # Load the first file
        sample_file = os.path.join(sample_dir, json_files[0])
        
        with open(sample_file, 'r') as f:
            data = json.load(f)
            
        if isinstance(data, list):
            samples = data
        else:
            samples = [data]
            
        logger.info(f"Loaded {len(samples)} {sample_type} samples from {sample_file}")
            
    except Exception as e:
        logger.error(f"Error loading sample data: {e}")
        
    return samples

def test_detection():
    """Test the ML-based detection system."""
    try:
        logger.info("Starting ML detection test")
        
        # Initialize ML controller
        ml_controller = MLController()
        
        # Check ML controller state
        stats = ml_controller.get_statistics()
        logger.info(f"Initial stats: {json.dumps(stats, indent=2)}")
        
        # Load sample data
        data_dir = os.path.join(project_root, 'data', 'ml_samples')
        
        # Check if sample data exists
        if not os.path.exists(data_dir):
            logger.error(f"Sample data directory not found: {data_dir}")
            return
            
        # Train ML models
        logger.info("Loading sample data and training models...")
        training_result = ml_controller.load_sample_data()
        
        if training_result.get("success", False):
            logger.info("Training completed successfully")
        else:
            logger.error(f"Training failed: {training_result.get('error', 'Unknown error')}")
            return
            
        # Test detection on different sample types
        sample_types = ['benign', 'spoofing', 'mitm', 'dos', 'recon']
        
        for sample_type in sample_types:
            # Load test samples
            test_samples = load_sample_data(data_dir, sample_type)
            
            if not test_samples:
                logger.warning(f"No test samples available for {sample_type}")
                continue
                
            # Test each sample
            detections = 0
            total_samples = min(10, len(test_samples))  # Test up to 10 samples
            
            logger.info(f"Testing {total_samples} {sample_type} samples")
            
            for i, sample in enumerate(test_samples[:total_samples]):
                # Process the sample
                result = ml_controller.process_packet(sample)
                
                # Check for detections
                if result.get("detections", []):
                    detections += 1
                    detection = result["detections"][0]
                    logger.info(f"Sample {i+1}: Detection! Type: {detection.get('evidence', {}).get('detection_type')}, "
                                f"Confidence: {detection.get('confidence')}, Severity: {detection.get('severity')}")
                else:
                    logger.info(f"Sample {i+1}: No detection")
                    
            # Calculate detection rate
            detection_rate = detections / total_samples if total_samples > 0 else 0
            expected_rate = 0.1 if sample_type == 'benign' else 0.7
            
            logger.info(f"{sample_type} detection rate: {detection_rate:.2f} "
                        f"({detections}/{total_samples})")
            
            # Validate detection rate
            if sample_type == 'benign' and detection_rate > 0.2:
                logger.warning(f"High false positive rate for benign traffic: {detection_rate:.2f}")
            elif sample_type != 'benign' and detection_rate < 0.5:
                logger.warning(f"Low detection rate for {sample_type} traffic: {detection_rate:.2f}")
                
        # Get final stats
        final_stats = ml_controller.get_statistics()
        logger.info(f"Final stats: {json.dumps(final_stats, indent=2)}")
        
        # Get recent detections
        recent_detections = ml_controller.get_recent_detections(10)
        logger.info(f"Recent detections: {json.dumps(recent_detections, indent=2)}")
        
        logger.info("ML detection test completed")
        
    except Exception as e:
        logger.error(f"Error during ML detection test: {e}")

if __name__ == "__main__":
    # Ensure logs directory exists
    os.makedirs(os.path.join(project_root, 'logs'), exist_ok=True)
    
    # Run the test
    test_detection() 