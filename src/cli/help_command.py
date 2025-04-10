"""
ARP Guard Help Command

This module implements the help command for the ARP Guard CLI,
integrating the help system, command suggestions, and help search functionality.
"""

import sys
import argparse
from typing import List, Dict, Any, Optional

# Import help system modules (adjust imports as needed for your project structure)
try:
    from utils.help_system import show_help, interactive_help, export_help_as_json
    from utils.command_suggestions import predict_next_input, validate_command_line
    from utils.help_search import process_help_query, search_help
except ImportError:
    # Fallback to direct imports for development/testing
    from src.utils.help_system import show_help, interactive_help, export_help_as_json
    from src.utils.command_suggestions import predict_next_input, validate_command_line
    from src.utils.help_search import process_help_query, search_help

def setup_help_parser(subparsers):
    """Set up the argument parser for the help command."""
    help_parser = subparsers.add_parser(
        'help',
        help='Get detailed help on commands and topics',
        description='Provides detailed help on ARP Guard commands and topics.'
    )
    
    # Command or topic argument (optional)
    help_parser.add_argument(
        'topic',
        nargs='?',
        help='Command or topic to get help on'
    )
    
    # Mode options
    mode_group = help_parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        '-i', '--interactive',
        action='store_true',
        help='Start interactive help mode'
    )
    mode_group.add_argument(
        '-s', '--search',
        metavar='QUERY',
        help='Search help topics and commands'
    )
    
    # Output options
    help_parser.add_argument(
        '-j', '--json',
        action='store_true',
        help='Output help content in JSON format'
    )
    
    # Help completion options
    help_parser.add_argument(
        '--suggest',
        metavar='COMMAND',
        help='Suggest next options for a partial command'
    )
    
    help_parser.add_argument(
        '--validate',
        metavar='COMMAND',
        help='Validate a command line string'
    )
    
    # Set the function to handle the help command
    help_parser.set_defaults(func=handle_help_command)

def handle_help_command(args):
    """Handle the help command based on arguments."""
    # Output help content as JSON
    if args.json:
        if args.topic:
            # Export specific topic/command
            export_help_as_json(f"{args.topic}_help.json")
        else:
            # Export all help content
            export_help_as_json()
        return 0
    
    # Interactive help mode
    if args.interactive:
        interactive_help()
        return 0
    
    # Search help
    if args.search:
        results = process_help_query(args.search)
        print(results)
        return 0
    
    # Command completion suggestions
    if args.suggest:
        suggestions = predict_next_input(args.suggest)
        print("\nSuggestions for completing this command:")
        for suggestion in suggestions:
            print(f"  {suggestion}")
        return 0
    
    # Command validation
    if args.validate:
        valid, message = validate_command_line(args.validate)
        if valid:
            print(f"Command is valid: {args.validate}")
        else:
            print(f"Command has issues: {message}")
        return 0 if valid else 1
    
    # Standard help display
    show_help(args.topic)
    return 0

def print_topic_help(topic: str):
    """Print help for a specific topic that's not a command."""
    topic_lower = topic.lower()
    
    # Import topic content (this would be more extensive in a real implementation)
    from utils.help_search import TOPICS
    
    if topic_lower in TOPICS:
        print(f"\n{topic_lower.upper()} HELP\n")
        print(f"Keywords related to {topic_lower}: {', '.join(TOPICS[topic_lower])}\n")
        
        # Search for commands related to this topic
        results = search_help(topic_lower)
        
        if results["commands"]:
            print("RELATED COMMANDS:")
            for cmd, _ in results["commands"]:
                from utils.help_system import HELP_CONTENT
                desc = HELP_CONTENT[cmd]["description"].split('.')[0]  # First sentence
                print(f"  - {cmd}: {desc}")
        
        # In a real implementation, you would have more detailed topic content
        print("\nFor more information, try one of these commands:")
        print(f"  arp-guard help -s \"{topic_lower}\"")
        print(f"  arp-guard help -i")
    else:
        print(f"No help available for topic '{topic}'. Try 'arp-guard help -s {topic}' to search.")

def register_help_command(cli_module):
    """Register the help command with the CLI module."""
    setup_help_parser(cli_module.subparsers)

if __name__ == "__main__":
    # Stand-alone testing
    parser = argparse.ArgumentParser(description='ARP Guard Help')
    subparsers = parser.add_subparsers(dest='command')
    setup_help_parser(subparsers)
    
    args = parser.parse_args()
    if hasattr(args, 'func'):
        sys.exit(args.func(args))
    else:
        parser.print_help()
        sys.exit(1) 