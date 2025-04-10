#!/usr/bin/env python3
"""
Command Line Interface for ARP Guard
Main entry point for the CLI application
"""

import os
import sys
import argparse
import logging
from typing import List, Dict, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import core modules
from src.core.detection_module import DetectionModule, DetectionModuleConfig, DetectionResult
from src.core.cli_utils import OutputFormat, OutputFormatter, ProgressBar, CLIModule, TabularData


def create_config(args: Dict[str, Any]) -> DetectionModuleConfig:
    """
    Create detection module configuration from command line arguments
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        DetectionModuleConfig object
    """
    # Get configuration from args or use defaults
    options = args.get("options", {})
    
    # Define default storage path
    default_storage_path = os.path.join(os.path.expanduser("~"), ".arpguard")
    
    # Parse features
    features = []
    if "features" in options:
        features = [f.strip() for f in options["features"].split(",")]
    
    return DetectionModuleConfig(
        detection_interval=int(options.get("interval", 5)),
        enabled_features=features,
        storage_path=options.get("storage", default_storage_path),
        max_packet_cache=int(options.get("max-cache", 1000)),
        auto_protect=options.get("auto-protect", False)
    )


def handle_scan_command(args: Dict[str, Any], output_format: OutputFormat) -> int:
    """
    Handle the 'scan' command
    
    Args:
        args: Parsed command arguments
        output_format: Output format to use
        
    Returns:
        Exit code
    """
    options = args.get("options", {})
    
    # Create configuration
    config = create_config(args)
    
    # Create detection module
    detection = DetectionModule(config)
    
    # Parse count option (number of packets to scan)
    count = int(options.get("count", 100))
    
    # Parse timeout option
    timeout = int(options.get("timeout", 30))
    
    # Print scan information
    formatter = OutputFormatter()
    formatter.print(f"Starting ARP scan (packets: {count}, timeout: {timeout}s)", OutputFormat.TEXT)
    
    # Create progress bar
    progress = ProgressBar(count, "Scanning", "packets processed")
    
    # Start detection
    detection.start_detection()
    
    # Monitor progress
    total_processed = 0
    try:
        # Process packets
        while total_processed < count:
            # Process a batch
            batch_size = min(10, count - total_processed)
            result = detection.analyze_packets(batch_size)
            
            # Update progress
            processed = result.get("processed", 0)
            total_processed += processed
            progress.update(processed)
            
            # Check if timeout is reached
            if result.get("timeout", False):
                formatter.print("Scan timed out", OutputFormat.TEXT)
                break
        
        # Complete progress bar
        progress.finish()
        
        # Get detection results
        detected_hosts = detection.get_detected_hosts()
        
        # Display results based on format
        if output_format == OutputFormat.JSON:
            # Convert to serializable dict
            results_dict = {
                "scan_info": {
                    "packets_processed": total_processed,
                    "detected_hosts": len(detected_hosts)
                },
                "detected_hosts": [result.to_dict() for result in detected_hosts]
            }
            formatter.print(results_dict, OutputFormat.JSON)
        else:
            # Create tabular data
            table = TabularData()
            table.headers = ["MAC Address", "IP Address", "Threat Level", "Details"]
            
            for result in detected_hosts:
                row = [
                    result.mac_address,
                    result.ip_address,
                    result.threat_level,
                    ", ".join(result.details) if result.details else ""
                ]
                table.add_row(row)
            
            # Print table
            formatter.print(table, output_format)
            
            # Print summary
            formatter.print(f"\nScan complete. Processed {total_processed} packets and detected {len(detected_hosts)} potential threats.", 
                           OutputFormat.TEXT)
        
        return 0
        
    except KeyboardInterrupt:
        formatter.print("\nScan interrupted by user", OutputFormat.TEXT)
        return 1
    finally:
        # Stop detection
        detection.stop_detection()


def handle_status_command(args: Dict[str, Any], output_format: OutputFormat) -> int:
    """
    Handle the 'status' command
    
    Args:
        args: Parsed command arguments
        output_format: Output format to use
        
    Returns:
        Exit code
    """
    options = args.get("options", {})
    
    # Create configuration
    config = create_config(args)
    
    # Create detection module
    detection = DetectionModule(config)
    
    # Get status
    status = detection.get_status()
    
    # Display status
    formatter = OutputFormatter()
    
    if output_format == OutputFormat.JSON:
        formatter.print(status, OutputFormat.JSON)
    else:
        if isinstance(status, dict):
            # Create tabular data for key-value pairs
            table = TabularData()
            table.headers = ["Property", "Value"]
            
            for key, value in status.items():
                table.add_row([key, str(value)])
            
            formatter.print(table, output_format)
        else:
            formatter.print(str(status), OutputFormat.TEXT)
    
    return 0


def handle_export_command(args: Dict[str, Any], output_format: OutputFormat) -> int:
    """
    Handle the 'export' command
    
    Args:
        args: Parsed command arguments
        output_format: Output format to use
        
    Returns:
        Exit code
    """
    options = args.get("options", {})
    
    # Create configuration
    config = create_config(args)
    
    # Create detection module
    detection = DetectionModule(config)
    
    # Get file path
    file_path = options.get("file", None)
    
    # Determine format
    export_format = options.get("format", "json").upper()
    
    # Export results
    try:
        result = detection.export_results(file_path, export_format)
        
        # Display result
        formatter = OutputFormatter()
        
        if result.get("success", False):
            formatter.print(f"Successfully exported results to {result.get('file_path')}", OutputFormat.TEXT)
        else:
            formatter.print(f"Export failed: {result.get('error', 'Unknown error')}", OutputFormat.TEXT)
            return 1
        
        return 0
        
    except Exception as e:
        logger.error(f"Export error: {e}")
        formatter = OutputFormatter()
        formatter.print(f"Export failed: {str(e)}", OutputFormat.TEXT)
        return 1


def main() -> int:
    """
    Main entry point for the CLI
    
    Returns:
        Exit code
    """
    # Create CLI module
    cli = CLIModule("arpguard", "ARP Guard - ARP Spoofing Detection Tool")
    
    # Register commands
    cli.register_command("scan", handle_scan_command, "Scan the network for ARP spoofing attacks")
    cli.register_command("status", handle_status_command, "Show detection module status")
    cli.register_command("export", handle_export_command, "Export detection results")
    
    # Parse command line arguments
    args = cli.parse_args(sys.argv[1:])
    
    # Execute command
    return cli.execute_command(args)


if __name__ == "__main__":
    sys.exit(main()) 