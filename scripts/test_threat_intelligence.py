#!/usr/bin/env python3
"""
Test script for the threat intelligence integration.

This script tests the integration with various threat intelligence
services and their API connections.
"""

import os
import sys
import json
import time
import yaml
from pathlib import Path
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from app.threat_intelligence import ThreatIntelligenceController
from app.utils.logger import setup_logger

# Set up logging
log_file = os.path.join(project_root, 'logs', 'threat_intel_test.log')
logger = setup_logger('threat_intel_test', log_file)

def load_config():
    """Load the configuration file."""
    try:
        config_path = os.path.join(project_root, 'config.yaml')
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return None

def test_api_connection(controller, service_name):
    """Test the API connection for a specific service."""
    try:
        logger.info(f"Testing {service_name} API connection...")
        
        # Check if service is enabled
        if not controller.is_service_enabled(service_name):
            logger.warning(f"{service_name} is not enabled in configuration")
            return False
            
        # Test API connection
        result = controller.test_api_connection(service_name)
        
        if result.get("success", False):
            logger.info(f"{service_name} API connection successful")
            return True
        else:
            logger.error(f"{service_name} API connection failed: {result.get('error', 'Unknown error')}")
            return False
            
    except Exception as e:
        logger.error(f"Error testing {service_name} API connection: {e}")
        return False

def test_threat_lookup(controller, service_name):
    """Test threat lookup for a specific service."""
    try:
        logger.info(f"Testing {service_name} threat lookup...")
        
        # Test IP lookup
        test_ip = "8.8.8.8"  # Google DNS - should be safe
        result = controller.lookup_ip(service_name, test_ip)
        
        if result.get("success", False):
            logger.info(f"{service_name} IP lookup successful")
            return True
        else:
            logger.error(f"{service_name} IP lookup failed: {result.get('error', 'Unknown error')}")
            return False
            
    except Exception as e:
        logger.error(f"Error testing {service_name} threat lookup: {e}")
        return False

def test_threat_intelligence():
    """Test the threat intelligence integration."""
    try:
        logger.info("Starting threat intelligence test")
        
        # Load configuration
        config = load_config()
        if not config:
            logger.error("Failed to load configuration")
            return
            
        # Initialize threat intelligence controller
        controller = ThreatIntelligenceController(config)
        
        # Test each service
        services = ['abuseipdb', 'virustotal', 'otx', 'emerging_threats']
        results = {}
        
        for service in services:
            # Test API connection
            api_result = test_api_connection(controller, service)
            
            if api_result:
                # Test threat lookup
                lookup_result = test_threat_lookup(controller, service)
                results[service] = {
                    "api_connection": api_result,
                    "threat_lookup": lookup_result
                }
            else:
                results[service] = {
                    "api_connection": api_result,
                    "threat_lookup": False
                }
                
        # Print summary
        logger.info("Test results summary:")
        for service, result in results.items():
            logger.info(f"{service}:")
            logger.info(f"  API Connection: {'Success' if result['api_connection'] else 'Failed'}")
            logger.info(f"  Threat Lookup: {'Success' if result['threat_lookup'] else 'Failed'}")
            
        # Check cache
        cache_stats = controller.get_cache_stats()
        logger.info(f"Cache statistics: {json.dumps(cache_stats, indent=2)}")
        
        logger.info("Threat intelligence test completed")
        
    except Exception as e:
        logger.error(f"Error during threat intelligence test: {e}")

if __name__ == "__main__":
    # Ensure logs directory exists
    os.makedirs(os.path.join(project_root, 'logs'), exist_ok=True)
    
    # Run the test
    test_threat_intelligence() 