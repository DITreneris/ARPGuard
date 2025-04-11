#!/usr/bin/env python3
"""
ARPGuard - Network Security Tool for ARP Poisoning Detection and Prevention

This script serves as the entry point for the ARPGuard application, providing
various command line options for operation modes including CLI, testing,
and utility operations.
"""

import os
import sys
import argparse
import subprocess
import logging

# Add the project root and src directories to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(project_root, "src")
sys.path.insert(0, project_root)
sys.path.insert(0, src_dir)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from src.core.performance_config import PerformanceConfig
from src.core.feature_flags import FeatureFlagManager
from src.core.cli_module import CLIModule
from src.core.detection_module import DetectionModule
from src.core.telemetry_module import TelemetryModule


def run_cli(perf_args=None, cli_args=None):
    """Run the application in CLI mode.
    
    Args:
        perf_args: Optional list of performance-related arguments to pass to main.py
        cli_args: Optional list of CLI arguments to pass to the CLI module
        
    Returns:
        Exit code from the process
    """
    # Start main.py with performance arguments only
    cmd = [sys.executable, "src/main.py"]
    
    # Ensure we're passing performance args properly
    if perf_args:
        # Filter out any None values or empty strings
        perf_args = [arg for arg in perf_args if arg]
        cmd.extend(perf_args)
    
    # Add CLI arguments if provided - no need to add the "--" separator
    # as main.py doesn't pass "--optimize-perf" to the CLI module
    if cli_args:
        cmd.extend(cli_args)
    
    # Log the full command we're about to run
    logger.info(f"Running command: {' '.join(cmd)}")
    
    # Run the process
    process = subprocess.Popen(cmd)
    return process.wait()


def run_tests(verbose=False, coverage=False):
    """Run the test suite.
    
    Args:
        verbose: If True, show detailed test output
        coverage: If True, generate coverage report
    
    Returns:
        int: Exit code from the test run
    """
    print("Running ARPGuard tests...")
    
    cmd = ["pytest"]
    
    if verbose:
        cmd.append("-v")
    
    if coverage:
        cmd.extend(["--cov=app", "--cov-report=term-missing"])
    
    return subprocess.run(cmd).returncode


def run_update():
    """Update application resources."""
    print("Updating ARPGuard resources...")
    return 0


def run_config():
    """Configure the application."""
    print("Configuring ARPGuard...")
    return 0


def run_ml():
    """Run machine learning operations."""
    print("Running ML operations...")
    return 0


def main():
    """Main entry point for the application."""
    parser = argparse.ArgumentParser(description="ARPGuard - Network Security Tool")
    
    # Add operation mode arguments
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--cli", action="store_true", help="Start in CLI mode")
    mode_group.add_argument("--test", action="store_true", help="Run the test suite")
    mode_group.add_argument("--update", action="store_true", help="Update the application")
    mode_group.add_argument("--config", action="store_true", help="Configure the application")
    mode_group.add_argument("--ml", action="store_true", help="Run machine learning operations")
    
    # Add performance-related arguments
    perf_group = parser.add_argument_group("Performance Options")
    perf_group.add_argument(
        "--optimize-perf",
        action="store_true",
        help="Automatically optimize performance for current environment"
    )
    perf_group.add_argument(
        "--disable-sampling",
        action="store_true",
        help="Disable packet sampling in high traffic scenarios"
    )
    perf_group.add_argument(
        "--sampling-ratio",
        type=float,
        help="Packet sampling ratio (0.1-1.0)"
    )
    perf_group.add_argument(
        "--threads",
        type=int,
        help="Number of worker threads"
    )
    
    # Add test-related arguments
    test_group = parser.add_argument_group("Test Options")
    test_group.add_argument("-v", "--verbose", action="store_true", help="Show detailed test output")
    test_group.add_argument("--coverage", action="store_true", help="Generate coverage report")
    
    # Parse known arguments, keeping the rest for CLI commands
    args, remaining_args = parser.parse_known_args()
    
    # Collect performance-related arguments to pass to main.py
    perf_args = []
    if args.optimize_perf:
        perf_args.append("--optimize-perf")
    if args.disable_sampling:
        perf_args.append("--disable-sampling")
    if args.sampling_ratio is not None:
        perf_args.extend(["--sampling-ratio", str(args.sampling_ratio)])
    if args.threads is not None:
        perf_args.extend(["--threads", str(args.threads)])
    
    # Run in appropriate mode
    if args.test:
        return run_tests(args.verbose, args.coverage)
    elif args.update:
        return run_update()
    elif args.config:
        return run_config()
    elif args.ml:
        return run_ml()
    else:
        # Default to CLI mode, passing any remaining arguments
        return run_cli(perf_args, remaining_args)


if __name__ == "__main__":
    # Check for administrator/root privileges
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("Warning: ARPGuard requires administrator privileges for full functionality.")
                print("Some features may not work properly.")
        except:
            pass
    elif os.name == 'posix':  # Unix/Linux/Mac
        if os.geteuid() != 0:
            print("Warning: ARPGuard requires root privileges for full functionality.")
            print("Some features may not work properly.")
    
    sys.exit(main()) 