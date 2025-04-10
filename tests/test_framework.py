#!/usr/bin/env python3
"""
ARP Guard Test Framework
Comprehensive testing framework for ARP Guard components
"""

import os
import sys
import unittest
import argparse
import logging
import json
import time
from typing import Dict, List, Any, Optional
from datetime import datetime
import importlib
import traceback

# Add the parent directory to sys.path to import modules
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

# Try to import coverage for test coverage reporting
try:
    import coverage
    COVERAGE_AVAILABLE = True
except ImportError:
    COVERAGE_AVAILABLE = False
    print("Coverage package not found. Install with: pip install coverage")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("arpguard_test")

class TestResult:
    """Store test execution results."""
    
    def __init__(self):
        self.total = 0
        self.passed = 0
        self.failed = 0
        self.errors = 0
        self.skipped = 0
        self.duration = 0.0
        self.failures = []
        self.start_time = None
        self.end_time = None
        
    def start(self):
        """Mark test start time."""
        self.start_time = time.time()
        
    def stop(self):
        """Mark test end time and calculate duration."""
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time
        
    def add_failure(self, test_name: str, exception: Exception, traceback_str: str):
        """Add a test failure."""
        self.failures.append({
            'test': test_name,
            'exception': str(exception),
            'traceback': traceback_str
        })
        
    def to_dict(self) -> Dict:
        """Convert results to dictionary."""
        return {
            'total': self.total,
            'passed': self.passed,
            'failed': self.failed,
            'errors': self.errors,
            'skipped': self.skipped,
            'duration': self.duration,
            'failures': self.failures,
            'start_time': self.start_time,
            'end_time': self.end_time
        }

class TestRunner:
    """Custom test runner for ARP Guard testing."""
    
    def __init__(self, verbosity: int = 1, include_patterns: List[str] = None, 
                 exclude_patterns: List[str] = None, measure_coverage: bool = False):
        """Initialize test runner.
        
        Args:
            verbosity: Verbosity level (0-2)
            include_patterns: List of patterns to include in test discovery
            exclude_patterns: List of patterns to exclude from test discovery
            measure_coverage: Whether to measure code coverage
        """
        self.verbosity = verbosity
        self.include_patterns = include_patterns or ["test_*.py"]
        self.exclude_patterns = exclude_patterns or []
        self.measure_coverage = measure_coverage and COVERAGE_AVAILABLE
        self.cov = None
        
        if self.measure_coverage:
            self.cov = coverage.Coverage(
                source=["src"],
                omit=["*/__pycache__/*", "*/tests/*", "*/ui/*", "*/dashboard.py"],
                branch=True
            )
    
    def discover_tests(self, start_dir: str) -> unittest.TestSuite:
        """Discover tests in the specified directory.
        
        Args:
            start_dir: Directory to start test discovery
            
        Returns:
            Test suite with discovered tests
        """
        logger.info(f"Discovering tests in {start_dir}")
        loader = unittest.TestLoader()
        
        # Apply include patterns
        suite = unittest.TestSuite()
        for pattern in self.include_patterns:
            if self.verbosity > 0:
                logger.info(f"Including pattern: {pattern}")
            sub_suite = loader.discover(start_dir, pattern=pattern)
            suite.addTest(sub_suite)
            
        # Apply exclude patterns (by filtering the suite)
        if self.exclude_patterns:
            filtered_suite = unittest.TestSuite()
            for test in suite:
                should_exclude = False
                test_name = str(test)
                
                for pattern in self.exclude_patterns:
                    if pattern in test_name:
                        if self.verbosity > 0:
                            logger.info(f"Excluding: {test_name} (matched pattern: {pattern})")
                        should_exclude = True
                        break
                
                if not should_exclude:
                    filtered_suite.addTest(test)
            return filtered_suite
        
        return suite
    
    def run_tests(self, suite: unittest.TestSuite) -> TestResult:
        """Run the test suite.
        
        Args:
            suite: Test suite to run
            
        Returns:
            Test results
        """
        result = TestResult()
        result.start()
        
        # Start coverage measurement if enabled
        if self.measure_coverage:
            self.cov.start()
        
        runner = unittest.TextTestRunner(verbosity=self.verbosity)
        unittest_result = runner.run(suite)
        
        # Stop coverage measurement if enabled
        if self.measure_coverage:
            self.cov.stop()
            self.cov.save()
        
        result.stop()
        
        # Extract result information
        result.total = unittest_result.testsRun
        result.passed = result.total - len(unittest_result.failures) - len(unittest_result.errors) - len(unittest_result.skipped)
        result.failed = len(unittest_result.failures)
        result.errors = len(unittest_result.errors)
        result.skipped = getattr(unittest_result, 'skipped', 0)
        
        # Add failure details
        for test, traceback_str in unittest_result.failures:
            result.add_failure(str(test), Exception("Test failed"), traceback_str)
        
        for test, traceback_str in unittest_result.errors:
            result.add_failure(str(test), Exception("Test error"), traceback_str)
        
        return result
    
    def generate_report(self, result: TestResult, output_file: Optional[str] = None) -> Dict:
        """Generate test report.
        
        Args:
            result: Test results
            output_file: Optional file to write report to
            
        Returns:
            Report as dictionary
        """
        report = {
            'timestamp': datetime.now().isoformat(),
            'results': result.to_dict(),
            'coverage': self._generate_coverage_report() if self.measure_coverage else None
        }
        
        if output_file:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
                
        return report
    
    def _generate_coverage_report(self) -> Dict:
        """Generate coverage report.
        
        Returns:
            Coverage report as dictionary
        """
        if not self.measure_coverage or not self.cov:
            return None
        
        # Generate reports
        self.cov.html_report(directory='coverage_html')
        
        # Get coverage data
        data = self.cov.get_data()
        
        # Extract summary information
        summary = {}
        total_statements = 0
        total_missing = 0
        
        for filename in data.measured_files():
            # Skip files not in src directory
            if 'src' not in filename:
                continue
                
            # Get line coverage
            _, executed_lines, _, missing_lines = self.cov.analysis(filename)
            statements = len(executed_lines) + len(missing_lines)
            missing = len(missing_lines)
            covered = statements - missing
            
            # Calculate coverage percentage
            coverage_pct = 0
            if statements > 0:
                coverage_pct = (covered / statements) * 100
                
            # Build relative path
            rel_path = os.path.relpath(filename, parent_dir)
            
            summary[rel_path] = {
                'statements': statements,
                'missing': missing,
                'covered': covered,
                'coverage': round(coverage_pct, 2)
            }
            
            total_statements += statements
            total_missing += missing
        
        # Calculate total coverage
        total_coverage = 0
        if total_statements > 0:
            total_coverage = ((total_statements - total_missing) / total_statements) * 100
            
        return {
            'total_statements': total_statements,
            'total_missing': total_missing,
            'total_covered': total_statements - total_missing,
            'total_coverage': round(total_coverage, 2),
            'files': summary
        }
    
    def print_report(self, report: Dict):
        """Print test report to console.
        
        Args:
            report: Report dictionary
        """
        results = report['results']
        
        print("\n=== ARP Guard Test Report ===")
        print(f"Time: {report['timestamp']}")
        print(f"Duration: {results['duration']:.2f} seconds")
        print(f"Total Tests: {results['total']}")
        print(f"Passed: {results['passed']}")
        print(f"Failed: {results['failed']}")
        print(f"Errors: {results['errors']}")
        print(f"Skipped: {results['skipped']}")
        
        if results['failures']:
            print("\n=== Failures ===")
            for i, failure in enumerate(results['failures'], 1):
                print(f"\n{i}. {failure['test']}")
                print(f"   {failure['exception']}")
                if self.verbosity > 1:
                    print(f"\n{failure['traceback']}")
        
        if report['coverage']:
            print("\n=== Coverage Report ===")
            print(f"Total Statements: {report['coverage']['total_statements']}")
            print(f"Total Covered: {report['coverage']['total_covered']}")
            print(f"Total Coverage: {report['coverage']['total_coverage']}%")
            
            if self.verbosity > 0:
                print("\nCoverage by File:")
                for filename, data in report['coverage']['files'].items():
                    print(f"{filename}: {data['coverage']}% ({data['covered']}/{data['statements']})")
        
        print("\n=== Test Summary ===")
        if results['failed'] > 0 or results['errors'] > 0:
            print("❌ Some tests failed")
        else:
            print("✅ All tests passed")

def run_single_test(test_path: str, verbosity: int = 1, measure_coverage: bool = False) -> TestResult:
    """Run a single test file.
    
    Args:
        test_path: Path to test file
        verbosity: Verbosity level
        measure_coverage: Whether to measure code coverage
        
    Returns:
        Test results
    """
    if not os.path.exists(test_path):
        logger.error(f"Test file not found: {test_path}")
        return None
    
    test_dir = os.path.dirname(test_path)
    test_file = os.path.basename(test_path)
    
    runner = TestRunner(verbosity=verbosity, include_patterns=[test_file], measure_coverage=measure_coverage)
    suite = runner.discover_tests(test_dir)
    return runner.run_tests(suite)

def run_all_tests(test_dir: str = 'tests', verbosity: int = 1, 
                 include_patterns: List[str] = None, exclude_patterns: List[str] = None,
                 measure_coverage: bool = False, output_file: Optional[str] = None) -> Dict:
    """Run all tests and generate report.
    
    Args:
        test_dir: Directory containing tests
        verbosity: Verbosity level
        include_patterns: List of patterns to include in test discovery
        exclude_patterns: List of patterns to exclude from test discovery
        measure_coverage: Whether to measure code coverage
        output_file: Optional file to write report to
        
    Returns:
        Test report
    """
    runner = TestRunner(verbosity=verbosity, 
                       include_patterns=include_patterns, 
                       exclude_patterns=exclude_patterns,
                       measure_coverage=measure_coverage)
    
    suite = runner.discover_tests(test_dir)
    result = runner.run_tests(suite)
    report = runner.generate_report(result, output_file)
    runner.print_report(report)
    
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='ARP Guard Test Framework')
    parser.add_argument('--test-dir', default='tests', help='Directory containing tests')
    parser.add_argument('--test-file', help='Run a specific test file')
    parser.add_argument('--verbosity', type=int, default=1, help='Verbosity level (0-2)')
    parser.add_argument('--include', action='append', help='Patterns to include (e.g. test_detection_*.py)')
    parser.add_argument('--exclude', action='append', help='Patterns to exclude (e.g. test_ui_*.py)')
    parser.add_argument('--coverage', action='store_true', help='Measure code coverage')
    parser.add_argument('--output', help='Output file for test report (JSON)')
    
    args = parser.parse_args()
    
    if args.test_file:
        run_single_test(args.test_file, verbosity=args.verbosity, measure_coverage=args.coverage)
    else:
        run_all_tests(
            test_dir=args.test_dir,
            verbosity=args.verbosity,
            include_patterns=args.include,
            exclude_patterns=args.exclude,
            measure_coverage=args.coverage,
            output_file=args.output
        ) 