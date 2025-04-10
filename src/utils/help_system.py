"""
ARP Guard Help System

This module provides comprehensive help functionality for the ARP Guard CLI,
including detailed command descriptions, usage examples, and interactive help features.
"""

import sys
import textwrap
import os
import json
from colorama import Fore, Style, init

# Initialize colorama
init()

# Help content for all commands
HELP_CONTENT = {
    "main": {
        "description": "ARP Guard is a powerful network security tool that monitors and protects against ARP spoofing attacks.",
        "usage": "arp-guard [OPTIONS] COMMAND [ARGS]...",
        "options": {
            "-h, --help": "Show this help message and exit",
            "-v, --version": "Show version information and exit",
            "-c, --config FILE": "Specify configuration file (default: /etc/arp-guard/config.yaml)",
            "-i, --interface INTERFACE": "Specify network interface to monitor",
            "-d, --debug": "Enable debug mode"
        },
        "commands": {
            "start": "Start the ARP Guard service",
            "stop": "Stop the ARP Guard service",
            "status": "Show the current status of ARP Guard",
            "config": "Manage ARP Guard configuration",
            "logs": "View and manage ARP Guard logs"
        },
        "examples": [
            {
                "description": "Start ARP Guard with custom configuration",
                "command": "arp-guard start -c /path/to/config.yaml"
            },
            {
                "description": "Show current status",
                "command": "arp-guard status"
            },
            {
                "description": "View logs",
                "command": "arp-guard logs"
            }
        ]
    },
    "start": {
        "description": "Start the ARP Guard service to begin monitoring network traffic for ARP spoofing attacks.",
        "usage": "arp-guard start [OPTIONS]",
        "options": {
            "-c, --config FILE": "Specify configuration file (default: /etc/arp-guard/config.yaml)",
            "-i, --interface INTERFACE": "Specify network interface to monitor",
            "-d, --debug": "Enable debug mode",
            "-f, --foreground": "Run in foreground instead of as a service",
            "-l, --log-level LEVEL": "Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)"
        },
        "examples": [
            {
                "description": "Start with default configuration",
                "command": "arp-guard start"
            },
            {
                "description": "Start with custom configuration",
                "command": "arp-guard start -c /path/to/config.yaml"
            },
            {
                "description": "Start in debug mode",
                "command": "arp-guard start -d"
            },
            {
                "description": "Start with specific interface",
                "command": "arp-guard start -i eth0"
            }
        ]
    },
    "stop": {
        "description": "Stop the ARP Guard service. This command will gracefully shut down the service, ensuring that all monitoring activities are properly terminated and any pending alerts are processed.",
        "usage": "arp-guard stop [OPTIONS]",
        "options": {
            "-f, --force": "Force stop the service without waiting for graceful shutdown",
            "-t, --timeout SECONDS": "Timeout in seconds for graceful shutdown (default: 30)",
            "-v, --verbose": "Show detailed stop process information"
        },
        "examples": [
            {
                "description": "Stop the service gracefully",
                "command": "arp-guard stop"
            },
            {
                "description": "Force stop the service",
                "command": "arp-guard stop -f"
            },
            {
                "description": "Stop with custom timeout",
                "command": "arp-guard stop -t 60"
            },
            {
                "description": "Stop with verbose output",
                "command": "arp-guard stop -v"
            }
        ]
    },
    "status": {
        "description": "Display the current status of the ARP Guard service, including service state, active monitoring interfaces, detection statistics, alert counts, and resource usage.",
        "usage": "arp-guard status [OPTIONS]",
        "options": {
            "-j, --json": "Output status in JSON format",
            "-v, --verbose": "Show detailed status information",
            "-s, --short": "Show only essential status information",
            "-c, --continuous": "Continuously monitor status with updates",
            "-i, --interval SECONDS": "Update interval for continuous monitoring (default: 5)"
        },
        "examples": [
            {
                "description": "Show basic status",
                "command": "arp-guard status"
            },
            {
                "description": "Show detailed status",
                "command": "arp-guard status -v"
            },
            {
                "description": "Show status in JSON format",
                "command": "arp-guard status -j"
            },
            {
                "description": "Monitor status continuously",
                "command": "arp-guard status -c"
            },
            {
                "description": "Monitor with custom interval",
                "command": "arp-guard status -c -i 10"
            }
        ]
    },
    "config": {
        "description": "Manage ARP Guard configuration settings. This command allows you to view, modify, and reset the configuration options.",
        "usage": "arp-guard config SUBCOMMAND [OPTIONS]",
        "subcommands": {
            "show": "Show current configuration settings",
            "set": "Set a configuration option",
            "reset": "Reset configuration to default values"
        },
        "examples": [
            {
                "description": "Show all configuration settings",
                "command": "arp-guard config show"
            },
            {
                "description": "Show specific configuration section",
                "command": "arp-guard config show network"
            },
            {
                "description": "Set a configuration option",
                "command": "arp-guard config set network.interface eth0"
            },
            {
                "description": "Reset all configuration to defaults",
                "command": "arp-guard config reset"
            }
        ]
    },
    "logs": {
        "description": "View and manage ARP Guard logs. This command allows you to display, filter, and export log entries.",
        "usage": "arp-guard logs [OPTIONS]",
        "options": {
            "-n, --lines NUMBER": "Number of lines to show (default: 50)",
            "-f, --follow": "Follow log output as new entries are added",
            "-l, --level LEVEL": "Filter by log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
            "-o, --output FILE": "Export logs to a file",
            "--since TIME": "Show logs since specified time (e.g., '10m', '2h', '1d')"
        },
        "examples": [
            {
                "description": "Show last 50 log entries",
                "command": "arp-guard logs"
            },
            {
                "description": "Show last 100 log entries",
                "command": "arp-guard logs -n 100"
            },
            {
                "description": "Follow log output",
                "command": "arp-guard logs -f"
            },
            {
                "description": "Show only error logs",
                "command": "arp-guard logs -l ERROR"
            },
            {
                "description": "Export logs to a file",
                "command": "arp-guard logs -o export.log"
            },
            {
                "description": "Show logs from the last hour",
                "command": "arp-guard logs --since 1h"
            }
        ]
    }
}

def print_colored(text, color=Fore.WHITE, bold=False):
    """Print text with specified color and style."""
    if bold:
        print(f"{color}{Style.BRIGHT}{text}{Style.RESET_ALL}")
    else:
        print(f"{color}{text}{Style.RESET_ALL}")

def wrap_text(text, indent=0, width=80):
    """Wrap text with specified indentation and width."""
    wrapped = textwrap.fill(text, width=width-indent)
    indented = '\n'.join(' ' * indent + line for line in wrapped.splitlines())
    return indented

def print_command_help(command, details):
    """Print help for a specific command."""
    print_colored(f"\n{command.upper()}", Fore.CYAN, bold=True)
    print_colored("\nDESCRIPTION:", Fore.YELLOW)
    print(wrap_text(details["description"], indent=2))
    
    print_colored("\nUSAGE:", Fore.YELLOW)
    print(f"  {details['usage']}")
    
    if "options" in details:
        print_colored("\nOPTIONS:", Fore.YELLOW)
        for option, desc in details["options"].items():
            print(f"  {Fore.GREEN}{option}{Style.RESET_ALL}")
            print(wrap_text(desc, indent=6))
    
    if "subcommands" in details:
        print_colored("\nSUBCOMMANDS:", Fore.YELLOW)
        for subcmd, desc in details["subcommands"].items():
            print(f"  {Fore.GREEN}{subcmd}{Style.RESET_ALL}")
            print(wrap_text(desc, indent=6))
    
    if "examples" in details:
        print_colored("\nEXAMPLES:", Fore.YELLOW)
        for example in details["examples"]:
            print(f"  # {example['description']}")
            print(f"  {Fore.GREEN}{example['command']}{Style.RESET_ALL}\n")

def print_main_help():
    """Print the main help message."""
    details = HELP_CONTENT["main"]
    print_colored("ARP GUARD", Fore.CYAN, bold=True)
    print_colored("\nDESCRIPTION:", Fore.YELLOW)
    print(wrap_text(details["description"], indent=2))
    
    print_colored("\nUSAGE:", Fore.YELLOW)
    print(f"  {details['usage']}")
    
    if "options" in details:
        print_colored("\nOPTIONS:", Fore.YELLOW)
        for option, desc in details["options"].items():
            print(f"  {Fore.GREEN}{option}{Style.RESET_ALL}")
            print(wrap_text(desc, indent=6))
    
    if "commands" in details:
        print_colored("\nCOMMANDS:", Fore.YELLOW)
        for cmd, desc in details["commands"].items():
            print(f"  {Fore.GREEN}{cmd}{Style.RESET_ALL}")
            print(wrap_text(desc, indent=6))
    
    if "examples" in details:
        print_colored("\nEXAMPLES:", Fore.YELLOW)
        for example in details["examples"]:
            print(f"  # {example['description']}")
            print(f"  {Fore.GREEN}{example['command']}{Style.RESET_ALL}\n")
    
    print("\nFor more information on a specific command, run:")
    print(f"  {Fore.GREEN}arp-guard COMMAND --help{Style.RESET_ALL}")

def show_help(command=None):
    """Show help for a command or the main help."""
    if command is None or command not in HELP_CONTENT:
        print_main_help()
    else:
        print_command_help(command, HELP_CONTENT[command])

def export_help_as_json(output_file=None):
    """Export help content as JSON."""
    if output_file is None:
        output_file = "help_content.json"
    
    with open(output_file, 'w') as f:
        json.dump(HELP_CONTENT, f, indent=2)
    
    print(f"Help content exported to {output_file}")

def interactive_help():
    """Provide interactive help with command suggestions."""
    print_colored("ARP Guard Interactive Help", Fore.CYAN, bold=True)
    print("Type 'exit' to quit the interactive help.\n")
    
    while True:
        query = input(f"{Fore.GREEN}What do you need help with? {Style.RESET_ALL}").strip().lower()
        
        if query in ['exit', 'quit', 'q']:
            break
        
        if not query:
            continue
        
        # Check for exact command matches
        if query in HELP_CONTENT:
            show_help(query)
            continue
        
        # Check for partial command matches
        matches = []
        for cmd in HELP_CONTENT:
            if query in cmd:
                matches.append(cmd)
        
        # Check for keyword matches in descriptions
        keyword_matches = []
        for cmd, details in HELP_CONTENT.items():
            if query in details["description"].lower():
                keyword_matches.append(cmd)
        
        # Combine unique matches
        all_matches = list(set(matches + keyword_matches))
        
        if all_matches:
            if len(all_matches) == 1:
                show_help(all_matches[0])
            else:
                print_colored("\nMultiple matches found:", Fore.YELLOW)
                for match in all_matches:
                    print(f"  {Fore.GREEN}{match}{Style.RESET_ALL}: {HELP_CONTENT[match]['description'][:50]}...")
                print("\nType the full command name for detailed help.")
        else:
            print_colored("\nNo matches found. Try one of these commands:", Fore.YELLOW)
            for cmd in HELP_CONTENT:
                print(f"  {Fore.GREEN}{cmd}{Style.RESET_ALL}")

def handle_help_request(args):
    """Handle help request based on arguments."""
    if not args or args[0] in ['-h', '--help']:
        show_help()
    elif len(args) >= 1 and args[0] == 'interactive':
        interactive_help()
    elif len(args) >= 1 and args[0] == 'export':
        output_file = args[1] if len(args) > 1 else None
        export_help_as_json(output_file)
    elif args[0] in HELP_CONTENT:
        show_help(args[0])
    else:
        print(f"Unknown command: {args[0]}")
        print("Run 'arp-guard --help' for usage information.")

if __name__ == "__main__":
    args = sys.argv[1:]
    handle_help_request(args) 