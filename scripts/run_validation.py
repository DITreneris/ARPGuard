#!/usr/bin/env python3
import os
import sys
import logging
from validate_deployment import DeploymentValidator
from generate_validation_report import ValidationReport

def setup_logging():
    """Set up logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('validation.log')
        ]
    )
    return logging.getLogger(__name__)

def main():
    """Main function to run deployment validation."""
    logger = setup_logging()
    
    try:
        # Initialize validator and report
        validator = DeploymentValidator('config/validation_config.yaml')
        report = ValidationReport()
        
        # Run validation
        results = validator.run_validation()
        
        # Add results to report
        for category, data in results.items():
            report.add_test_result(
                category=category,
                test_id=f"{category}_check",
                test_name=f"{category} Validation",
                status=data['status'],
                details=data['details']
            )
        
        # Update overall status
        report.update_overall_status()
        
        # Generate reports
        report.generate_html_report('validation_report.html')
        report.save_json('validation_report.json')
        report.save_yaml('validation_report.yaml')
        
        # Check for failures
        has_failures = any(check['status'] == 'FAIL' for check in results.values())
        
        if has_failures:
            logger.error("Validation completed with failures. Please check the reports for details.")
            sys.exit(1)
        else:
            logger.info("All validation checks passed successfully.")
            sys.exit(0)
            
    except Exception as e:
        logger.error(f"Error during validation: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 