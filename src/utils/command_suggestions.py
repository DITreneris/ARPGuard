"""
ARP Guard Command Suggestions

This module provides context-aware command suggestions and intelligent
autocompletion for the ARP Guard CLI.
"""

import difflib
import re
import json
import os
from typing import List, Dict, Tuple, Any, Optional

# Common command patterns and their suggestions
COMMON_PATTERNS = {
    r"start|run|begin|launch": "start",
    r"stop|end|halt|kill|quit|exit": "stop",
    r"status|info|state|running|details": "status",
    r"config|configure|settings|setup|options": "config",
    r"logs|log|history|output|messages": "logs",
    r"help|assist|support|guide|docs|manual": "--help",
    r"version|ver|about|release": "--version",
}

# Command contextual hints
COMMAND_CONTEXT = {
    "start": {
        "next_likely": ["--help", "--config", "--interface", "--debug"],
        "requires_root": True,
        "needs_config": True,
        "common_errors": [
            "Permission denied (try running with sudo)",
            "Interface not found",
            "Service already running"
        ]
    },
    "stop": {
        "next_likely": ["--help", "--force", "--timeout"],
        "requires_root": True,
        "needs_config": False,
        "common_errors": [
            "Permission denied (try running with sudo)",
            "Service not running"
        ]
    },
    "status": {
        "next_likely": ["--help", "--json", "--verbose", "--short", "--continuous"],
        "requires_root": False,
        "needs_config": False,
        "common_errors": [
            "Service not running"
        ]
    },
    "config": {
        "next_likely": ["show", "set", "reset", "--help"],
        "subcommands": {
            "show": ["--help", "network", "logging", "detection", "alerts", "all"],
            "set": ["--help", "network.interface", "logging.level", "detection.sensitivity"],
            "reset": ["--help", "--force", "network", "logging", "detection", "alerts", "all"]
        },
        "requires_root": False,
        "needs_config": True,
        "common_errors": [
            "Configuration file not found",
            "Invalid configuration format",
            "Permission denied when writing configuration"
        ]
    },
    "logs": {
        "next_likely": ["--help", "--lines", "--follow", "--level", "--output", "--since"],
        "requires_root": False,
        "needs_config": False,
        "common_errors": [
            "Log file not found",
            "Permission denied when reading logs"
        ]
    }
}

def get_command_from_partial(partial_command: str) -> List[str]:
    """Get command suggestions from a partial command."""
    commands = list(COMMAND_CONTEXT.keys()) + ["--help", "--version"]
    
    # Exact match
    if partial_command in commands:
        return [partial_command]
    
    # Pattern match
    for pattern, command in COMMON_PATTERNS.items():
        if re.match(pattern, partial_command, re.IGNORECASE):
            return [command]
    
    # Fuzzy match
    return difflib.get_close_matches(partial_command, commands, n=3, cutoff=0.5)

def get_subcommand_suggestions(command: str, partial_subcommand: str = "") -> List[str]:
    """Get subcommand suggestions for a given command."""
    if command not in COMMAND_CONTEXT:
        return []
    
    if "subcommands" not in COMMAND_CONTEXT[command]:
        return COMMAND_CONTEXT[command].get("next_likely", [])
    
    subcommands = list(COMMAND_CONTEXT[command]["subcommands"].keys())
    
    # Exact match
    if partial_subcommand in subcommands:
        return COMMAND_CONTEXT[command]["subcommands"][partial_subcommand]
    
    # Fuzzy match for subcommand
    if partial_subcommand:
        matches = difflib.get_close_matches(partial_subcommand, subcommands, n=3, cutoff=0.5)
        if matches:
            return matches
    
    # Return all subcommands if no partial match
    return subcommands

def get_option_suggestions(command: str, subcommand: Optional[str] = None) -> List[str]:
    """Get option suggestions for a command/subcommand."""
    if command not in COMMAND_CONTEXT:
        return []
    
    if subcommand and "subcommands" in COMMAND_CONTEXT[command]:
        if subcommand in COMMAND_CONTEXT[command]["subcommands"]:
            return COMMAND_CONTEXT[command]["subcommands"][subcommand]
    
    return COMMAND_CONTEXT[command].get("next_likely", [])

def get_argument_suggestions(command: str, option: str) -> List[str]:
    """Get argument suggestions for a command option."""
    # Example implementations for common arguments
    if option in ["--interface", "-i"]:
        # In a real implementation, this would detect network interfaces
        return ["eth0", "wlan0", "en0", "en1"]
    elif option in ["--log-level", "-l", "--level"]:
        return ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    elif option in ["--config", "-c"]:
        # In a real implementation, this would scan for config files
        return ["/etc/arp-guard/config.yaml", "./config.yaml"]
    
    return []

def predict_next_input(command_line: str) -> List[str]:
    """Predict the next input based on current command line."""
    parts = command_line.strip().split()
    
    # No command yet, suggest main commands
    if not parts or (len(parts) == 1 and parts[0] == "arp-guard"):
        return list(COMMAND_CONTEXT.keys()) + ["--help", "--version"]
    
    # Have arp-guard command, predict next
    if len(parts) == 1:
        return get_command_from_partial(parts[0])
    
    # Main command is arp-guard, look at next token
    if parts[0] == "arp-guard":
        command = parts[1]
        
        # If only have the main command so far
        if len(parts) == 2:
            return get_command_from_partial(command)
        
        # Have command and more tokens
        if command in COMMAND_CONTEXT:
            # Check if we're dealing with subcommands
            if "subcommands" in COMMAND_CONTEXT[command]:
                if len(parts) == 3:
                    return get_subcommand_suggestions(command, parts[2])
                else:
                    subcommand = parts[2]
                    if subcommand in COMMAND_CONTEXT[command]["subcommands"]:
                        # Get option suggestions for subcommand
                        return COMMAND_CONTEXT[command]["subcommands"][subcommand]
            
            # Main command options
            last_token = parts[-1]
            if last_token.startswith("-"):
                # If the last token is an option, suggest arguments
                return get_argument_suggestions(command, last_token)
            else:
                # Otherwise suggest next options
                return get_option_suggestions(command)
    
    # Default to common options if nothing else matches
    return ["--help", "--version"]

def validate_command_line(command_line: str) -> Tuple[bool, str]:
    """Validate a command line and return status and error message."""
    parts = command_line.strip().split()
    
    if not parts:
        return True, ""
    
    if parts[0] != "arp-guard":
        return False, "Command should start with 'arp-guard'"
    
    if len(parts) == 1:
        return True, ""  # Just 'arp-guard' is valid
    
    command = parts[1]
    if command.startswith("-"):  # It's an option
        if command not in ["--help", "--version"]:
            return False, f"Unknown option: {command}"
        return True, ""
    
    if command not in COMMAND_CONTEXT:
        suggestions = get_command_from_partial(command)
        suggestion_str = ", ".join(suggestions) if suggestions else "Try 'arp-guard --help'"
        return False, f"Unknown command: {command}. Did you mean: {suggestion_str}?"
    
    # Command exists, check for potential issues
    context = COMMAND_CONTEXT[command]
    
    # Check for root requirement (simplified, would be more complex in real implementation)
    if context.get("requires_root") and os.geteuid() != 0:
        return False, f"The '{command}' command requires root privileges. Try using sudo."
    
    # Advanced validation would check options, subcommands, etc.
    
    return True, ""

def get_command_help_preview(command: str) -> str:
    """Get a short preview of help for a command."""
    from help_system import HELP_CONTENT
    
    if command in HELP_CONTENT:
        details = HELP_CONTENT[command]
        return f"{command}: {details['description'][:100]}..." if len(details['description']) > 100 else details['description']
    
    return f"No help available for {command}"

def suggest_related_commands(command: str) -> List[str]:
    """Suggest related commands based on the current one."""
    related = {
        "start": ["status", "stop", "config"],
        "stop": ["start", "status"],
        "status": ["start", "stop", "logs"],
        "config": ["start", "status"],
        "logs": ["status"]
    }
    
    return related.get(command, [])

def explain_common_error(command: str, error_message: str) -> str:
    """Provide helpful explanation for common errors."""
    for cmd, context in COMMAND_CONTEXT.items():
        if command == cmd or command.startswith(f"{cmd} "):
            for error in context.get("common_errors", []):
                if error.lower() in error_message.lower():
                    return f"This is a common error with the '{cmd}' command: {error}"
    
    return "An error occurred. Check the command syntax or try using --help."

if __name__ == "__main__":
    # Example usage
    while True:
        cmd = input("Enter a partial command (or 'exit' to quit): ")
        if cmd.lower() == 'exit':
            break
        
        suggestions = predict_next_input(cmd)
        print(f"Suggestions: {', '.join(suggestions)}")
        
        valid, msg = validate_command_line(cmd)
        if not valid:
            print(f"Validation: {msg}")
        else:
            print("Command looks valid!") 