#!/usr/bin/env python3
"""
ML Component Test Runner

This script runs all tests for the ML components and generates a coverage report.
It provides options to run specific test categories or all tests.

Usage:
    python scripts/run_ml_tests.py [OPTIONS]

Options:
    --all                Run all ML tests
    --feature-extraction Run only feature extraction tests
    --preprocessing      Run only preprocessing tests
    --models            Run only model tests
    --pipeline          Run only pipeline tests
    --performance       Run only performance tests
    --coverage          Generate coverage report
"""

import argparse
import os
import sys
import subprocess
import json
from datetime import datetime


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run ML component tests")
    parser.add_argument("--all", action="store_true", help="Run all ML tests")
    parser.add_argument("--feature-extraction", action="store_true", help="Run feature extraction tests")
    parser.add_argument("--preprocessing", action="store_true", help="Run preprocessing tests")
    parser.add_argument("--models", action="store_true", help="Run model tests")
    parser.add_argument("--pipeline", action="store_true", help="Run pipeline tests")
    parser.add_argument("--performance", action="store_true", help="Run performance tests")
    parser.add_argument("--coverage", action="store_true", help="Generate coverage report")
    
    args = parser.parse_args()
    
    # If no specific test group is selected, run all tests
    if not any([args.all, args.feature_extraction, args.preprocessing, 
                args.models, args.pipeline, args.performance]):
        args.all = True
        
    return args


def run_tests(test_paths, coverage=False):
    """Run the specified tests."""
    print(f"\n{'=' * 80}")
    print(f"Running tests: {', '.join(test_paths)}")
    print(f"{'=' * 80}\n")
    
    if not test_paths:
        print("No tests to run.")
        return True
    
    cmd = ["python", "-m", "pytest"]
    
    if coverage:
        cmd.extend(["--cov=app.ml", "--cov-report=term", "--cov-report=html:coverage_reports/ml_coverage"])
    
    cmd.extend(test_paths)
    
    try:
        result = subprocess.run(cmd, check=True)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"Error running tests: {e}")
        return False


def get_test_paths(args):
    """Get test paths based on command line arguments."""
    test_paths = []
    
    if args.all:
        test_paths.append("tests/ml")
    else:
        if args.feature_extraction:
            test_paths.append("tests/ml/test_feature_extraction.py")
        
        if args.preprocessing:
            test_paths.append("tests/ml/features/test_preprocessor.py")
            test_paths.append("tests/ml/features/test_performance_metrics.py")
        
        if args.models:
            # Add model test paths when they are created
            pass
        
        if args.pipeline:
            # Add pipeline test paths when they are created
            pass
        
        if args.performance:
            # Add performance test paths when they are created
            pass
    
    return test_paths


def generate_test_summary(success):
    """Generate a summary of the test results."""
    results = {
        "timestamp": datetime.now().isoformat(),
        "success": success,
        "tests_run": True,
        "coverage_generated": False
    }
    
    try:
        os.makedirs("reports", exist_ok=True)
        with open("reports/ml_test_results.json", "w") as f:
            json.dump(results, f, indent=2)
    except Exception as e:
        print(f"Error generating test summary: {e}")


def main():
    """Main function."""
    args = parse_args()
    test_paths = get_test_paths(args)
    
    # Create coverage reports directory if needed
    if args.coverage:
        os.makedirs("coverage_reports/ml_coverage", exist_ok=True)
    
    # Run tests
    success = run_tests(test_paths, args.coverage)
    
    # Generate test summary
    generate_test_summary(success)
    
    # Return appropriate exit code
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main()) 