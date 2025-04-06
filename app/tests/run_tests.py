#!/usr/bin/env python3
"""
Test runner for ARPGuard application tests.

This script provides a command-line interface for running the ARPGuard test suite.
It can run all tests or specific test modules and provides detailed output formatting.

Usage:
    python run_tests.py [options] [test_module...]

Options:
    -v, --verbose     Increase verbosity of output
    -q, --quiet       Decrease verbosity of output
    -f, --failfast    Stop on first failure
    -c, --coverage    Run tests with coverage report
    -h, --help        Show help message and exit

Examples:
    python run_tests.py                     # Run all tests
    python run_tests.py -v                  # Run all tests with verbose output
    python run_tests.py test_threat_intelligence  # Run only threat intelligence tests
    python run_tests.py -c                  # Run tests with coverage report
"""

import sys
import os
import unittest
import argparse
import importlib
import time
from datetime import datetime

# Add the parent directory to sys.path to import app modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

def get_test_modules():
    """Get a list of all test modules in the current directory."""
    test_modules = []
    for filename in os.listdir(os.path.dirname(__file__)):
        if filename.startswith('test_') and filename.endswith('.py'):
            module_name = filename[:-3]  # Remove .py extension
            test_modules.append(module_name)
    return test_modules

def run_tests_with_coverage(test_names, verbosity=1, failfast=False):
    """Run tests with coverage report."""
    try:
        import coverage
    except ImportError:
        print("Error: Coverage package is not installed. Install with 'pip install coverage'")
        sys.exit(1)
    
    # Start coverage
    cov = coverage.Coverage(source=['app'], omit=['*/tests/*', '*/venv/*'])
    cov.start()
    
    # Run tests
    result = run_tests(test_names, verbosity, failfast)
    
    # Stop coverage
    cov.stop()
    cov.save()
    
    # Print coverage report
    print("\n=== Coverage Report ===")
    cov.report()
    print("To generate HTML report: coverage html")
    
    return result

def run_tests(test_names, verbosity=1, failfast=False):
    """Run specified tests with given verbosity and failfast options."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # If no specific test modules are specified, run all test modules
    if not test_names:
        test_names = get_test_modules()
    
    # Add each specified test module to the suite
    for test_name in test_names:
        try:
            # First try to import as a module
            try:
                module = importlib.import_module(f"app.tests.{test_name}")
                tests = loader.loadTestsFromModule(module)
                suite.addTests(tests)
                print(f"Added tests from module: {test_name}")
            except (ImportError, ModuleNotFoundError):
                # If that fails, try loading as a test case from the current package
                try:
                    tests = loader.loadTestsFromName(test_name)
                    suite.addTests(tests)
                    print(f"Added tests from: {test_name}")
                except Exception as e:
                    print(f"Error loading tests from {test_name}: {e}")
        except Exception as e:
            print(f"Error loading {test_name}: {e}")
    
    # Create a test runner and run the suite
    runner = unittest.TextTestRunner(verbosity=verbosity, failfast=failfast)
    return runner.run(suite)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run ARPGuard tests")
    parser.add_argument('-v', '--verbose', action='store_true', help='Increase output verbosity')
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
    parser.add_argument('-f', '--failfast', action='store_true', help='Stop on first failure')
    parser.add_argument('-c', '--coverage', action='store_true', help='Run with coverage report')
    parser.add_argument('test_modules', nargs='*', help='Test modules to run (e.g., test_threat_intelligence)')
    
    return parser.parse_args()

def main():
    """Main entry point for the test runner."""
    args = parse_args()
    
    # Set verbosity level
    if args.verbose:
        verbosity = 2
    elif args.quiet:
        verbosity = 0
    else:
        verbosity = 1
    
    # Print test information
    print("=== ARPGuard Test Runner ===")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Python version: {sys.version}")
    
    if not args.test_modules:
        print("Running all tests")
    else:
        print(f"Running tests: {', '.join(args.test_modules)}")
    
    # Measure execution time
    start_time = time.time()
    
    # Run tests with or without coverage
    if args.coverage:
        result = run_tests_with_coverage(args.test_modules, verbosity, args.failfast)
    else:
        result = run_tests(args.test_modules, verbosity, args.failfast)
    
    # Print summary
    execution_time = time.time() - start_time
    print(f"\nTest execution completed in {execution_time:.2f} seconds")
    
    # Return exit code based on test result
    if result.wasSuccessful():
        return 0
    return 1

if __name__ == "__main__":
    sys.exit(main()) 