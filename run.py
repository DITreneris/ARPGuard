#!/usr/bin/env python3
"""
ARPGuard - Network Security Tool for ARP Poisoning Detection and Prevention

This script serves as the entry point for the ARPGuard application, providing
various command line options for operation modes including GUI, testing,
and utility operations.
"""

import os
import sys
import argparse
import subprocess
import logging
from PyQt5.QtWidgets import QApplication

from app.components.main_window import MainWindow
from app.utils.logger import setup_logger
from app.utils.config import get_config, save_config
from app.ml import init_ml_directories


def run_gui():
    """Start the ARPGuard GUI application."""
    # Initialize ML directories
    init_ml_directories()
    
    # Start the application
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec_()


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
        cmd.extend(["--cov=app", "--cov-report=term"])
        
    # Add tests directory
    cmd.append("tests/")
    
    try:
        result = subprocess.run(cmd, check=False)
        if result.returncode == 0:
            print("All tests passed successfully!")
        else:
            print(f"Tests failed with exit code: {result.returncode}")
        return result.returncode
    except Exception as e:
        print(f"Error running tests: {e}")
        return 1


def update_mac_vendors():
    """Update the MAC vendor database."""
    print("Updating MAC vendor database...")
    try:
        from app.utils.mac_vendor import update_vendor_database
        success = update_vendor_database()
        if success:
            print("MAC vendor database updated successfully!")
            return 0
        else:
            print("Failed to update MAC vendor database.")
            return 1
    except Exception as e:
        print(f"Error updating MAC vendor database: {e}")
        return 1


def show_config():
    """Display the current configuration."""
    config = get_config()
    print("Current ARPGuard Configuration:")
    print("-" * 40)
    for key, value in sorted(config.items()):
        print(f"{key}: {value}")
    print("-" * 40)
    return 0


def set_config(key, value):
    """Set a configuration value.
    
    Args:
        key: The configuration key
        value: The new value
        
    Returns:
        int: Exit code (0 for success)
    """
    try:
        # Convert value to appropriate type
        if value.lower() in ('true', 'yes', '1'):
            value = True
        elif value.lower() in ('false', 'no', '0'):
            value = False
        elif value.isdigit():
            value = int(value)
        elif value.replace('.', '', 1).isdigit() and value.count('.') == 1:
            value = float(value)
            
        # Get current config
        config = get_config()
        
        # Update value
        config[key] = value
        
        # Save config
        save_config(config)
        
        print(f"Configuration updated: {key} = {value}")
        return 0
    except Exception as e:
        print(f"Error setting configuration: {e}")
        return 1


def main():
    """Main entry point for the ARPGuard application."""
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="ARPGuard - Network Security Tool for ARP Poisoning Detection and Prevention"
    )
    
    # Add subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # GUI command (default)
    gui_parser = subparsers.add_parser("gui", help="Start the ARPGuard GUI")
    
    # Test command
    test_parser = subparsers.add_parser("test", help="Run the test suite")
    test_parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed test output")
    test_parser.add_argument("--coverage", action="store_true", help="Generate coverage report")
    
    # Update command
    update_parser = subparsers.add_parser("update", help="Update resources")
    update_parser.add_argument("--mac-vendors", action="store_true", help="Update MAC vendor database")
    
    # Config command
    config_parser = subparsers.add_parser("config", help="Manage configuration")
    config_parser.add_argument("--show", action="store_true", help="Show current configuration")
    config_parser.add_argument("--set", nargs=2, metavar=("KEY", "VALUE"), help="Set configuration value")
    
    # ML command
    ml_parser = subparsers.add_parser("ml", help="Machine Learning operations")
    ml_parser.add_argument("--train", action="store_true", help="Train ML models")
    ml_parser.add_argument("--predict", action="store_true", help="Run ML prediction")
    
    # Debug option
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Setup logger
    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_logger(log_level)
    
    # Process commands
    if args.command == "test":
        return run_tests(args.verbose, args.coverage)
    elif args.command == "update":
        if args.mac_vendors:
            return update_mac_vendors()
        else:
            update_parser.print_help()
            return 1
    elif args.command == "config":
        if args.show:
            return show_config()
        elif args.set:
            return set_config(args.set[0], args.set[1])
        else:
            config_parser.print_help()
            return 1
    elif args.command == "ml":
        if args.train:
            # Initialize ML directories and load modules for training
            from app.components.ml_controller import MLController
            
            print("Training ML models...")
            ml_controller = MLController()
            success = ml_controller.train_models(force=True)
            
            if success:
                print("ML models trained successfully")
                return 0
            else:
                print("Failed to train ML models")
                return 1
        else:
            ml_parser.print_help()
            return 1
    else:
        # Default to GUI mode
        return run_gui()


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