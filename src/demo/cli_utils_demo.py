#!/usr/bin/env python3
"""
Demo script for CLI utilities

This script demonstrates the usage of the CLI utilities implemented in src/core/cli_utils.py
"""
import os
import sys
import time
import argparse
import random
from typing import List, Dict, Any

# Add project root to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.core.cli_utils import (
    ProgressBar, ProgressBarStyle, ProgressBarConfig,
    Spinner, TableFormatter, OutputFormatter, OutputFormat,
    InteractiveShell
)

def demo_progress_bar() -> None:
    """Demonstrate various progress bar styles"""
    print("\n=== Progress Bar Demo ===\n")
    
    # Demo different styles
    styles = [
        ProgressBarStyle.ASCII,
        ProgressBarStyle.UNICODE,
        ProgressBarStyle.DOTS,
        ProgressBarStyle.ARROW,
        ProgressBarStyle.MINIMAL
    ]
    
    for style in styles:
        print(f"\nDemonstrating {style.name} style:")
        config = ProgressBarConfig(
            width=40,
            style=style,
            show_percentage=True,
            show_time=True,
            show_value=True
        )
        
        progress = ProgressBar(
            total=100,
            description=f"Progress ({style.name})",
            config=config
        )
        
        progress.start()
        
        # Simulate progress
        for i in range(101):
            progress.update(i)
            time.sleep(0.01)
        
        progress.complete()
    
    print("\nProgress bar with custom configuration:")
    config = ProgressBarConfig(
        width=30,
        style=ProgressBarStyle.UNICODE,
        show_percentage=True,
        show_time=False,
        show_value=False
    )
    
    progress = ProgressBar(
        total=50,
        description="Custom Progress",
        config=config
    )
    
    progress.start()
    
    # Simulate progress with varying speeds
    for i in range(51):
        progress.update(i)
        time.sleep(0.02 + random.random() * 0.04)
    
    progress.complete()

def demo_spinner() -> None:
    """Demonstrate spinner functionality"""
    print("\n=== Spinner Demo ===\n")
    
    # Demo different spinner patterns
    patterns = ["dots", "simple", "arrows", "bounce", "moon"]
    
    for pattern in patterns:
        print(f"\nDemonstrating '{pattern}' spinner pattern:")
        spinner = Spinner(f"Processing with {pattern} spinner", pattern)
        spinner.start()
        
        # Simulate work
        time.sleep(2)
        
        # Update message
        spinner.update_message(f"Still processing with {pattern} spinner")
        time.sleep(1)
        
        spinner.stop()

def demo_table_formatter() -> None:
    """Demonstrate table formatting"""
    print("\n=== Table Formatter Demo ===\n")
    
    # Simple table
    headers = ["ID", "Name", "Role", "Active"]
    data = [
        [1, "Alice Smith", "Developer", "Yes"],
        [2, "Bob Johnson", "Designer", "Yes"],
        [3, "Charlie Brown", "Manager", "No"],
        [4, "Diana Taylor", "DevOps", "Yes"]
    ]
    
    formatter = TableFormatter(headers)
    table_output = formatter.format(data)
    print(table_output)
    
    # Table with aligned columns
    print("\nTable with custom column alignment:")
    formatter = TableFormatter(
        headers=headers,
        alignment=["right", "left", "center", "center"]
    )
    table_output = formatter.format(data)
    print(table_output)

def demo_output_formatter() -> None:
    """Demonstrate output formatting"""
    print("\n=== Output Formatter Demo ===\n")
    
    # Create sample data
    data = [
        {
            "id": 1,
            "hostname": "server1.example.com",
            "ip": "192.168.1.101",
            "mac": "00:1A:2B:3C:4D:5E",
            "status": "online"
        },
        {
            "id": 2,
            "hostname": "server2.example.com",
            "ip": "192.168.1.102",
            "mac": "00:1A:2B:3C:4D:5F",
            "status": "offline"
        },
        {
            "id": 3,
            "hostname": "server3.example.com",
            "ip": "192.168.1.103",
            "mac": "00:1A:2B:3C:4D:60",
            "status": "online"
        }
    ]
    
    # Format as table
    print("Data formatted as TABLE:")
    print(OutputFormatter.format_output(data, OutputFormat.TABLE))
    
    # Format as JSON
    print("\nData formatted as JSON:")
    print(OutputFormatter.format_output(data, OutputFormat.JSON))
    
    # Format as raw
    print("\nData formatted as RAW:")
    print(OutputFormatter.format_output(data, OutputFormat.RAW))
    
    # Format as pretty
    print("\nData formatted as PRETTY:")
    print(OutputFormatter.format_output(data, OutputFormat.PRETTY))

def handle_command(command: str) -> bool:
    """Handle commands for interactive shell demo
    
    Args:
        command: Command string
        
    Returns:
        True if command was handled successfully, False otherwise
    """
    parts = command.split()
    cmd = parts[0].lower() if parts else ""
    args = parts[1:] if len(parts) > 1 else []
    
    if cmd == "echo":
        print(" ".join(args))
        return True
    elif cmd == "list":
        print("Sample list items:")
        for i in range(1, 6):
            print(f"  {i}. Item {i}")
        return True
    elif cmd == "clear":
        os.system('cls' if os.name == 'nt' else 'clear')
        return True
    else:
        print(f"Unknown command: {command}")
        return False

def demo_interactive_shell() -> None:
    """Demonstrate interactive shell"""
    print("\n=== Interactive Shell Demo ===\n")
    print("Starting interactive shell. Type commands and press Enter.")
    print("Available commands: help, echo [text], list, clear, exit/quit")
    
    shell = InteractiveShell(
        prompt="arpguard-demo> ",
        command_handler=handle_command
    )
    
    shell.start()

def main() -> None:
    """Main function"""
    parser = argparse.ArgumentParser(description="CLI Utilities Demo")
    parser.add_argument(
        "--component", "-c",
        choices=["progress", "spinner", "table", "output", "shell", "all"],
        default="all",
        help="Which component to demo"
    )
    
    args = parser.parse_args()
    
    if args.component in ("progress", "all"):
        demo_progress_bar()
    
    if args.component in ("spinner", "all"):
        demo_spinner()
    
    if args.component in ("table", "all"):
        demo_table_formatter()
    
    if args.component in ("output", "all"):
        demo_output_formatter()
    
    if args.component in ("shell", "all"):
        demo_interactive_shell()

if __name__ == "__main__":
    main() 