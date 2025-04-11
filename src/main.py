#!/usr/bin/env python3
"""
ARPGuard - Network Security Tool
Main entry point for the application
"""

import sys
import logging
import argparse
import os
from typing import List, Optional, Dict, Any, Tuple

from src.core.cli_module import CLIModule, CLIModuleConfig, create_standard_commands
from src.core.detection_module import DetectionModule, DetectionModuleConfig
from src.core.telemetry_module import TelemetryModule, TelemetryModuleConfig
from src.core.cli_utils import OutputFormat, OutputFormatter, ProgressBar, Spinner
from src.core.performance_config import PerformanceConfig
from src.core.feature_flags import FeatureFlagManager, register_standard_features

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s'
)
logger = logging.getLogger(__name__)


def initialize_modules() -> Dict[str, Any]:
    """
    Initialize all application modules
    
    Returns:
        Dictionary of initialized modules
    """
    # Initialize modules
    modules = {}
    
    # Load or create performance configuration
    perf_config_path = os.path.join("config", "performance.json")
    perf_config = PerformanceConfig(config_file=perf_config_path)
    
    # Optimize performance settings for current environment
    perf_config.optimize_for_environment()
    
    # Save optimized configuration
    perf_config.save_to_file()
    
    logger.info(f"Using performance configuration: {perf_config}")
    
    # Create and initialize CLI module with custom config
    cli_config = CLIModuleConfig(
        program_name="arpguard",
        program_description="ARP Guard - Network Security Tool",
        version="1.0.0",
        default_output_format=OutputFormat.PRETTY,
        enable_interactive_mode=True,
        interactive_prompt="arpguard> "
    )
    cli_module = CLIModule(cli_config)
    
    # Create and initialize Detection module with performance-optimized config
    detection_config = DetectionModuleConfig(
        enabled_features=["core.packet_analysis", "core.export"],
        storage_path="./data",
        max_packet_cache=1000,
        worker_threads=perf_config.max_worker_threads,
        enable_sampling=perf_config.enable_packet_sampling,
        sampling_rate=perf_config.sampling_ratio,
        batch_size=perf_config.batch_size
    )
    detection_module = DetectionModule(detection_config)
    
    # Create and initialize Telemetry module with custom config
    telemetry_config = TelemetryModuleConfig(
        enabled=False,  # Disabled by default (opt-in)
        anonymize_data=True,
        storage_path="./data/telemetry",
        collection_interval=24 * 60 * 60,  # 24 hours in seconds
        storage_retention_days=30
    )
    telemetry_module = TelemetryModule(telemetry_config)
    
    # Initialize modules
    logger.info("Initializing modules...")
    
    # Using a progress bar for initialization feedback
    progress = ProgressBar(total=5)
    progress.start()
    
    # Store performance config in modules
    modules["performance"] = perf_config
    progress.update(1)
    
    # Initialize CLI module
    if cli_module.initialize():
        modules["cli"] = cli_module
        progress.update(2)
        logger.info("CLI module initialized successfully")
    else:
        logger.error("Failed to initialize CLI module")
        progress.stop()
        return {}
    
    # Initialize Detection module
    if detection_module.initialize():
        modules["detection"] = detection_module
        progress.update(3)
        logger.info("Detection module initialized successfully")
    else:
        logger.error("Failed to initialize Detection module")
        progress.stop()
        return {}
    
    # Initialize Telemetry module
    if telemetry_module.initialize():
        modules["telemetry"] = telemetry_module
        progress.update(4)
        logger.info("Telemetry module initialized successfully")
    else:
        logger.error("Failed to initialize Telemetry module")
        progress.stop()
        return {}
    
    # Register standard commands with CLI
    commands = create_standard_commands()
    for name, cmd in commands.items():
        if cli_module.register_command(cmd):
            logger.info(f"Registered command: {name}")
        else:
            logger.warning(f"Failed to register command: {name}")
    progress.update(5)
    
    # Final initialization steps
    progress.complete()
    
    logger.info("All modules initialized successfully")
    return modules


def shutdown_modules(modules: Dict[str, Any]) -> bool:
    """
    Shutdown all modules
    
    Args:
        modules: Dictionary of initialized modules
        
    Returns:
        True if shutdown successful, False otherwise
    """
    logger.info("Shutting down modules...")
    
    # Using a spinner for shutdown feedback
    spinner = Spinner("Shutting down ARPGuard")
    spinner.start()
    
    success = True
    
    # Save performance configuration before shutdown
    if "performance" in modules:
        spinner.update_message("Saving performance configuration...")
        modules["performance"].save_to_file()
    
    # Shutdown Telemetry module
    if "telemetry" in modules:
        spinner.update_message("Shutting down Telemetry module...")
        if not modules["telemetry"].shutdown():
            logger.error("Failed to shutdown Telemetry module")
            success = False
    
    # Shutdown Detection module
    if "detection" in modules:
        spinner.update_message("Shutting down Detection module...")
        if not modules["detection"].shutdown():
            logger.error("Failed to shutdown Detection module")
            success = False
    
    # Shutdown CLI module
    if "cli" in modules:
        spinner.update_message("Shutting down CLI module...")
        if not modules["cli"].shutdown():
            logger.error("Failed to shutdown CLI module")
            success = False
    
    spinner.stop()
    
    if success:
        logger.info("All modules shutdown successfully")
    else:
        logger.warning("Some modules failed to shutdown properly")
    
    return success


def parse_arguments(args: List[str]) -> Tuple[argparse.Namespace, List[str]]:
    """
    Parse command line arguments
    
    Args:
        args: Command line arguments
        
    Returns:
        Tuple of (parsed arguments, remaining CLI arguments)
    """
    parser = argparse.ArgumentParser(description="ARP Guard - Network Security Tool", add_help=True)
    
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
    
    # Split the args into the ones we recognize and the ones we don't
    # First, parse known args only to avoid errors on unknown CLI commands
    parsed_args, remaining_args = parser.parse_known_args(args)
    
    # Return parsed arguments and the remaining CLI command arguments
    return parsed_args, remaining_args


def main(args: Optional[List[str]] = None) -> int:
    """
    Main entry point for the application
    
    Args:
        args: Command line arguments
        
    Returns:
        Exit code
    """
    if args is None:
        args = sys.argv[1:]
    
    # Parse command line arguments first
    parsed_args, cli_args = parse_arguments(args)
    
    # Initialize feature flags first
    feature_manager = FeatureFlagManager()
    register_standard_features()  # Call the standalone function
    
    # Initialize modules
    modules = initialize_modules()
    if not modules:
        logger.error("Failed to initialize modules")
        return 1
    
    # Apply command line performance options if specified
    if "performance" in modules:
        perf_config = modules["performance"]
        
        if parsed_args.optimize_perf:
            perf_config.optimize_for_environment()
            logger.info("Re-optimized performance settings for current environment")
        
        if parsed_args.disable_sampling:
            perf_config.enable_packet_sampling = False
            logger.info("Packet sampling disabled")
        
        if parsed_args.sampling_ratio is not None:
            perf_config.sampling_ratio = max(0.1, min(1.0, parsed_args.sampling_ratio))
            logger.info(f"Packet sampling ratio set to {perf_config.sampling_ratio}")
        
        if parsed_args.threads is not None:
            perf_config.max_worker_threads = max(1, min(parsed_args.threads, os.cpu_count()))
            logger.info(f"Worker threads set to {perf_config.max_worker_threads}")
    
    # Run CLI
    if "cli" in modules:
        # Pass the remaining CLI arguments to the CLI module
        success = modules["cli"].run(cli_args)
    else:
        logger.error("CLI module not available")
        success = False
    
    # Shutdown modules
    shutdown_modules(modules)
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main()) 