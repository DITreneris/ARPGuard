#!/usr/bin/env python3
"""
CLI Utilities for ARP Guard
Provides utilities for formatting output in different formats.
"""

import sys
import json
import csv
import enum
import logging
from typing import Dict, Any, List, Optional, Union, TextIO, Tuple
from dataclasses import dataclass, field
from io import StringIO
import io
import os
import textwrap
import difflib

try:
    import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False

logger = logging.getLogger(__name__)


class OutputFormat(enum.Enum):
    """Enum for output formats"""
    JSON = "json"
    CSV = "csv"
    TABLE = "table"
    PRETTY = "pretty"
    TEXT = "text"


@dataclass
class TabularData:
    """Data structure for tabular data"""
    headers: List[str] = field(default_factory=list)
    rows: List[List[str]] = field(default_factory=list)
    
    def add_row(self, row: List[str]) -> None:
        """Add a row to the table"""
        self.rows.append(row)
    
    def get_column_widths(self) -> List[int]:
        """Calculate the maximum width of each column"""
        if not self.headers or not self.rows:
            return []
        
        # Initialize with header widths
        widths = [len(h) for h in self.headers]
        
        # Update with row content widths
        for row in self.rows:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], len(str(cell)))
        
        return widths


class OutputFormatter:
    """Class for formatting output in different formats"""
    
    def __init__(self, output_stream: TextIO = sys.stdout):
        """
        Initialize the formatter
        
        Args:
            output_stream: Stream to write output to
        """
        self.output_stream = output_stream
    
    def format_json(self, data: Any) -> str:
        """
        Format data as JSON
        
        Args:
            data: Data to format
            
        Returns:
            JSON formatted string
        """
        return json.dumps(data, indent=2)
    
    def format_csv(self, headers: List[str], data: List[List[Any]]) -> str:
        """
        Format data as CSV
        
        Args:
            headers: Column headers
            data: Data rows
            
        Returns:
            CSV formatted string
        """
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        writer.writerows(data)
        return output.getvalue()
    
    def format_table(self, data: TabularData, pretty: bool = False) -> str:
        """
        Format data as a table
        
        Args:
            data: Tabular data to format
            pretty: Whether to use pretty formatting with borders
            
        Returns:
            Table formatted string
        """
        if not data.headers or not data.rows:
            return "Empty table"
        
        if TABULATE_AVAILABLE:
            tablefmt = "pretty" if pretty else "simple"
            return tabulate.tabulate(data.rows, headers=data.headers, tablefmt=tablefmt)
        else:
            # Fallback to basic table formatting if tabulate not available
            output = []
            
            # Add header
            header_row = " | ".join(str(h) for h in data.headers)
            output.append(header_row)
            output.append("-" * len(header_row))
            
            # Add rows
            for row in data.rows:
                output.append(" | ".join(str(cell) for cell in row))
                
            return "\n".join(output)
    
    def format_text(self, text: str) -> str:
        """
        Format as plain text
        
        Args:
            text: Text to format
            
        Returns:
            Formatted text
        """
        return text
    
    def print(self, data: Any, format_type: OutputFormat = OutputFormat.TEXT) -> None:
        """
        Print data in specified format
        
        Args:
            data: Data to print
            format_type: Format to use
        """
        if format_type == OutputFormat.JSON:
            if isinstance(data, str):
                print(data, file=self.output_stream)
            else:
                print(self.format_json(data), file=self.output_stream)
        
        elif format_type == OutputFormat.CSV:
            if isinstance(data, str):
                print(data, file=self.output_stream)
            elif isinstance(data, TabularData):
                headers = data.headers
                rows = data.rows
                print(self.format_csv(headers, rows), file=self.output_stream)
            elif isinstance(data, tuple) and len(data) == 2:
                headers, rows = data
                print(self.format_csv(headers, rows), file=self.output_stream)
            else:
                logger.error("Invalid data format for CSV output")
        
        elif format_type == OutputFormat.TABLE or format_type == OutputFormat.PRETTY:
            if isinstance(data, str):
                print(data, file=self.output_stream)
            elif isinstance(data, TabularData):
                print(self.format_table(data, format_type == OutputFormat.PRETTY), 
                      file=self.output_stream)
            else:
                logger.error("Invalid data format for table output")
        
        else:  # TEXT format or fallback
            if isinstance(data, str):
                print(data, file=self.output_stream)
            else:
                print(str(data), file=self.output_stream)

    def format_output(self, data: Any, format_type: OutputFormat = OutputFormat.TEXT, headers: Optional[List[str]] = None) -> str:
        """
        Format data in the specified format
        
        Args:
            data: Data to format (dict, list, str, etc.)
            format_type: Output format
            headers: Optional headers for tabular data
            
        Returns:
            Formatted string
        """
        if format_type == OutputFormat.JSON:
            return self.format_json(data)
            
        elif format_type == OutputFormat.CSV:
            if isinstance(data, list) and isinstance(data[0], list):
                return self.format_csv(headers or [], data)
            elif isinstance(data, dict):
                # Convert dict to tabular data
                rows = [[key, value] for key, value in data.items()]
                return self.format_csv(headers or ["Key", "Value"], rows)
            else:
                return f"Error: Cannot format {type(data)} as CSV"
                
        elif format_type == OutputFormat.TABLE or format_type == OutputFormat.PRETTY:
            if isinstance(data, TabularData):
                return self.format_table(data, format_type == OutputFormat.PRETTY)
            elif isinstance(data, list) and isinstance(data[0], list):
                # Create TabularData from list of lists
                tabular_data = TabularData()
                tabular_data.headers = headers or []
                tabular_data.rows = data
                return self.format_table(tabular_data, format_type == OutputFormat.PRETTY)
            elif isinstance(data, dict):
                # Convert dict to tabular data
                tabular_data = TabularData()
                tabular_data.headers = headers or ["Key", "Value"]
                tabular_data.rows = [[key, value] for key, value in data.items()]
                return self.format_table(tabular_data, format_type == OutputFormat.PRETTY)
            else:
                return f"Error: Cannot format {type(data)} as table"
        
        else:  # TEXT format or fallback
            if isinstance(data, str):
                return data
            elif isinstance(data, dict):
                # Format dict as text
                lines = [f"{key}: {value}" for key, value in data.items()]
                return "\n".join(lines)
            elif isinstance(data, list):
                # Format list as text
                return "\n".join(str(item) for item in data)
            else:
                return str(data)


class ProgressBar:
    """Progress bar for CLI operations"""
    
    def __init__(self, total: int, width: int = 50, fill_char: str = "█", empty_char: str = "░", description: str = ""):
        """Initialize progress bar
        
        Args:
            total: Total number of steps
            width: Width of the progress bar in characters
            fill_char: Character to use for filled portion
            empty_char: Character to use for empty portion
            description: Optional description to display before the progress bar
        """
        self.total = total
        self.width = width
        self.fill_char = fill_char
        self.empty_char = empty_char
        self.description = description
        self.current = 0
        self.started = False
    
    def start(self):
        """Start the progress bar"""
        if not self.started:
            if self.description:
                print(self.description)
            self.started = True
            self.update(0)
    
    def update(self, current: Optional[int] = None) -> str:
        """Update progress
        
        Args:
            current: Current progress (if None, increment by 1)
            
        Returns:
            Progress bar string
        """
        if current is not None:
            self.current = current
        else:
            self.current += 1
            
        progress = self.current / self.total
        filled_width = int(self.width * progress)
        bar = self.fill_char * filled_width + self.empty_char * (self.width - filled_width)
        percent = int(progress * 100)
        
        # Move cursor to start of line and clear it
        sys.stdout.write('\r')
        sys.stdout.write(' ' * (self.width + 10))
        sys.stdout.write('\r')
        
        # Write progress bar
        sys.stdout.write(f"[{bar}] {percent}% ({self.current}/{self.total})")
        sys.stdout.flush()
        
        return f"[{bar}] {percent}% ({self.current}/{self.total})"
    
    def complete(self):
        """Complete the progress bar"""
        self.update(self.total)
        print()  # New line after completion
    
    def stop(self):
        """Stop the progress bar"""
        print()  # New line after stopping


class CLIModule:
    """CLI Module for ARP Guard"""
    
    def __init__(self, program_name: str, description: str):
        """
        Initialize CLI module
        
        Args:
            program_name: Name of the program
            description: Program description
        """
        self.program_name = program_name
        self.description = description
        self.formatter = OutputFormatter()
        self.commands = {}
        self.default_format = OutputFormat.PRETTY
    
    def register_command(self, name: str, handler: callable, help_text: str) -> None:
        """
        Register a command with the CLI
        
        Args:
            name: Command name
            handler: Command handler function
            help_text: Help text for the command
        """
        self.commands[name] = {
            "handler": handler,
            "help": help_text
        }
    
    def parse_args(self, args: List[str]) -> Dict[str, Any]:
        """
        Parse command line arguments
        
        Args:
            args: Command line arguments
            
        Returns:
            Dictionary of parsed arguments
        """
        result = {
            "command": None,
            "options": {},
            "args": []
        }
        
        if not args:
            return result
        
        result["command"] = args[0]
        
        # Process remaining arguments
        i = 1
        while i < len(args):
            arg = args[i]
            
            # Handle options (starting with - or --)
            if arg.startswith("--"):
                option = arg[2:]
                if i + 1 < len(args) and not args[i+1].startswith("-"):
                    result["options"][option] = args[i+1]
                    i += 2
                else:
                    result["options"][option] = True
                    i += 1
            elif arg.startswith("-"):
                option = arg[1:]
                if i + 1 < len(args) and not args[i+1].startswith("-"):
                    result["options"][option] = args[i+1]
                    i += 2
                else:
                    result["options"][option] = True
                    i += 1
            else:
                # Positional argument
                result["args"].append(arg)
                i += 1
        
        return result
    
    def execute_command(self, args: Dict[str, Any]) -> int:
        """
        Execute a command
        
        Args:
            args: Parsed arguments
            
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        command = args.get("command")
        
        if not command:
            self.print_help()
            return 0
        
        if command == "help":
            if args["args"]:
                # Help for specific command
                return self.print_command_help(args["args"][0])
            else:
                # General help
                self.print_help()
                return 0
        
        if command not in self.commands:
            print(f"Error: Unknown command '{command}'")
            self.print_help()
            return 1
        
        try:
            # Get output format from options if specified
            output_format = self.default_format
            if "format" in args["options"]:
                format_str = args["options"]["format"]
                try:
                    output_format = OutputFormat(format_str)
                except ValueError:
                    print(f"Warning: Unknown output format '{format_str}', using {self.default_format.value}")
            
            # Execute the command
            handler = self.commands[command]["handler"]
            return handler(args, output_format)
        except Exception as e:
            logger.error(f"Error executing command '{command}': {e}")
            print(f"Error: {e}")
            return 1
    
    def print_help(self) -> None:
        """Print general help information"""
        print(f"{self.program_name} - {self.description}")
        print("\nUsage:")
        print(f"  {self.program_name} COMMAND [OPTIONS] [ARGS]")
        print("\nCommands:")
        
        # Calculate the maximum command name length for proper alignment
        max_len = max(len(cmd) for cmd in self.commands.keys()) if self.commands else 0
        
        for cmd, details in sorted(self.commands.items()):
            print(f"  {cmd.ljust(max_len + 2)} {details['help']}")
        
        print("\nOptions:")
        print("  --format FORMAT   Output format (text, json, csv, table, pretty)")
        print("\nRun 'help COMMAND' for more information on a command")
    
    def print_command_help(self, command: str) -> int:
        """
        Print help for a specific command
        
        Args:
            command: Command to print help for
            
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        if command not in self.commands:
            print(f"Error: Unknown command '{command}'")
            return 1
        
        print(f"{self.program_name} - {command}")
        print(f"\n{self.commands[command]['help']}")
        print("\nOptions:")
        print("  --format FORMAT   Output format (text, json, csv, table, pretty)")
        
        return 0

# ANSI color codes for colorized output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

    @staticmethod
    def disable() -> None:
        """Disable colors for non-compatible terminals"""
        Colors.HEADER = ''
        Colors.BLUE = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.RED = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''
        Colors.END = ''
    
    @staticmethod
    def is_supported() -> bool:
        """Check if terminal supports colors"""
        # Check if we're on Windows
        if os.name == 'nt':
            return 'ANSICON' in os.environ or 'WT_SESSION' in os.environ
        # Check if we're in a terminal that supports colors
        return sys.stdout.isatty()

# Disable colors if terminal doesn't support them
if not Colors.is_supported():
    Colors.disable()

# Command help examples database
COMMAND_EXAMPLES = {
    'start': [
        'arp-guard start',
        'arp-guard start --interface eth0',
        'arp-guard start --background --sensitivity high',
        'arp-guard start --no-defense',
        'arp-guard start --trusted-hosts /path/to/trusted.txt'
    ],
    'stop': [
        'arp-guard stop',
        'arp-guard stop --force',
        'arp-guard stop --pid 1234',
        'arp-guard stop --keep-defenses'
    ],
    'status': [
        'arp-guard status',
        'arp-guard status --all',
        'arp-guard status --threats',
        'arp-guard status --json',
        'arp-guard status --watch'
    ],
    'threats': [
        'arp-guard threats list',
        'arp-guard threats show 12345',
        'arp-guard threats acknowledge 12345',
        'arp-guard threats export --output threats.json'
    ],
    'export': [
        'arp-guard export --format json --output results.json',
        'arp-guard export --format csv --output results.csv',
        'arp-guard export --last-hours 24 --format json'
    ],
    'config': [
        'arp-guard config show',
        'arp-guard config show detection.sensitivity',
        'arp-guard config set detection.sensitivity high',
        'arp-guard config reset'
    ],
    'service': [
        'arp-guard service install',
        'arp-guard service start',
        'arp-guard service stop',
        'arp-guard service status',
        'arp-guard service uninstall'
    ]
}

# Detailed command descriptions
COMMAND_DESCRIPTIONS = {
    'start': {
        'short': 'Start monitoring for ARP spoofing attacks',
        'long': """
        The start command begins monitoring network traffic for ARP spoofing attacks. It captures
        and analyzes ARP packets to detect potential threats on your network.
        
        When started, ARP Guard will monitor the specified network interface for suspicious ARP
        activity such as MAC address changes, unauthorized gateway announcements, and other 
        indicators of ARP spoofing attacks.
        
        By default, ARP Guard will also activate defense mechanisms to protect against detected
        threats. These defenses include creating static ARP entries for critical devices and
        optionally blocking traffic from suspected attackers.
        """,
        'options': {
            '-i, --interface': 'Specify the network interface to monitor',
            '-b, --background': 'Run in background mode (detached from terminal)',
            '-f, --foreground': 'Run in foreground mode (attached to terminal)',
            '--no-defense': 'Disable automatic defense mechanisms (detection only)',
            '--sensitivity': 'Set detection sensitivity level (low, medium, high)',
            '--alert-mode': 'Set alert notification mode (none, console, system, all)',
            '--trusted-hosts': 'Specify trusted hosts file (no alerts for these hosts)',
            '--gateway-macs': 'Specify gateway MAC addresses file for protection'
        }
    },
    'stop': {
        'short': 'Stop monitoring',
        'long': """
        The stop command terminates the ARP Guard monitoring process. This will stop all packet
        capture, analysis, and protection activities. 
        
        By default, ARP Guard will gracefully deactivate any active defenses to prevent network
        disruption. Use the --force option to stop immediately without graceful deactivation.
        Use --keep-defenses to maintain the protection even after stopping monitoring.
        
        The stop command will work regardless of whether ARP Guard was started in foreground or
        background mode.
        """,
        'options': {
            '-f, --force': 'Force termination even if defenses are active',
            '-g, --graceful': 'Gracefully deactivate defenses before stopping',
            '-t, --timeout': 'Timeout in seconds for graceful shutdown (default: 30)',
            '-p, --pid': 'Stop a specific instance by PID',
            '--keep-logs': 'Preserve log files (don\'t rotate)',
            '--keep-defenses': 'Keep active defenses in place after stopping'
        }
    },
    'status': {
        'short': 'Display current monitoring status',
        'long': """
        The status command displays information about the current state of ARP Guard monitoring,
        including whether it's running, monitoring statistics, detected threats, and active defenses.
        This provides a snapshot of the system's operation and security status.
        
        By default, the status command provides a summary overview. Use the --verbose option for
        more detailed information or specific options to focus on particular aspects such as
        threats or defenses.
        
        The --watch option provides a continuously updating display similar to the 'top' command.
        """,
        'options': {
            '-v, --verbose': 'Show detailed status information',
            '-j, --json': 'Output status in JSON format',
            '-s, --stats': 'Display performance statistics',
            '-t, --threats': 'Show detected threat information',
            '-d, --defenses': 'Show active defenses information',
            '-n, --network': 'Show network interface information',
            '-a, --all': 'Show all available information',
            '-w, --watch': 'Continuously update the status (like top)',
            '-r, --refresh': 'Refresh interval for watch mode (default: 2)'
        }
    },
    'threats': {
        'short': 'Manage detected threats',
        'long': """
        The threats command provides functionality to view, manage, and take action on detected
        ARP spoofing threats. You can list all threats, view details about specific threats,
        acknowledge threats, or export threat data for further analysis.
        
        Threats are assigned severity levels (info, low, medium, high, critical) based on their
        potential impact and confidence of detection. Each threat includes information about the
        source, affected devices, and recommended actions.
        """,
        'options': {
            'list': 'List all detected threats',
            'show <id>': 'Show detailed information about a specific threat',
            'acknowledge <id>': 'Mark a threat as acknowledged',
            'export': 'Export threats to file'
        }
    },
    'export': {
        'short': 'Export detection results to file',
        'long': """
        The export command allows you to save detection results, statistics, and threat
        information to a file for archiving or further analysis. You can export data in
        various formats including JSON, CSV, and XML.
        
        You can filter the exported data by time range, severity, and status. The export
        includes detection events, threat details, and system performance metrics.
        """,
        'options': {
            '--format': 'Output format (json, csv, xml)',
            '--output': 'Output file path',
            '--last-hours': 'Export data from the last N hours',
            '--start-time': 'Export data starting from this time',
            '--end-time': 'Export data ending at this time',
            '--include-acknowledged': 'Include acknowledged threats in export'
        }
    },
    'config': {
        'short': 'Configure ARP Guard settings',
        'long': """
        The config command allows you to view and modify ARP Guard configuration settings.
        You can display the current configuration, set specific values, or reset to defaults.
        
        Configuration settings include detection sensitivity, defense options, notification
        preferences, and performance tuning parameters. Changes take effect immediately for
        most settings, but some may require a restart.
        
        Configuration values are stored in /etc/arpguard/config.yaml by default.
        """,
        'options': {
            'show [key]': 'Show current configuration (optionally for specific key)',
            'set <key> <value>': 'Set a configuration value',
            'reset [key]': 'Reset configuration to defaults (optionally for specific key)'
        }
    },
    'service': {
        'short': 'Manage service/daemon mode operation',
        'long': """
        The service command manages ARP Guard when running as a system service or daemon.
        This allows ARP Guard to start automatically at boot time and run in the background.
        
        You can install, start, stop, and check the status of the service. The installation
        creates appropriate service files based on your operating system (systemd on Linux,
        launchd on macOS, or Windows services).
        
        Running as a service ensures continuous protection without requiring manual intervention.
        """,
        'options': {
            'install': 'Install ARP Guard as a system service',
            'start': 'Start the ARP Guard service',
            'stop': 'Stop the ARP Guard service',
            'status': 'Check status of the ARP Guard service',
            'uninstall': 'Remove the ARP Guard service'
        }
    }
}

class HelpSystem:
    """Enhanced help system for ARP Guard CLI"""
    
    @staticmethod
    def print_general_help() -> None:
        """Print the general help overview"""
        print(f"\n{Colors.BOLD}ARP Guard - ARP Spoofing Detection and Protection Tool{Colors.END}")
        print("\nUsage:")
        print(f"  arp-guard {Colors.BLUE}<command>{Colors.END} [options]")
        
        print("\nAvailable Commands:")
        for cmd, desc in COMMAND_DESCRIPTIONS.items():
            print(f"  {Colors.BLUE}{cmd.ljust(10)}{Colors.END} {desc['short']}")
        
        print("\nOptions:")
        print(f"  {Colors.YELLOW}-h, --help{Colors.END}     Show help for a command")
        print(f"  {Colors.YELLOW}-v, --version{Colors.END}  Show version information")
        
        print("\nRun 'arp-guard help <command>' for more information on a command.")
    
    @staticmethod
    def print_command_help(command: str) -> bool:
        """
        Print detailed help for a specific command
        
        Args:
            command: Command to show help for
            
        Returns:
            bool: True if command was found, False otherwise
        """
        if command not in COMMAND_DESCRIPTIONS:
            print(f"\n{Colors.RED}Error:{Colors.END} Unknown command '{command}'")
            
            # Suggest similar commands
            suggestions = difflib.get_close_matches(command, COMMAND_DESCRIPTIONS.keys())
            if suggestions:
                print(f"\nDid you mean one of these?")
                for suggestion in suggestions:
                    print(f"  {Colors.BLUE}{suggestion}{Colors.END}")
                    
            print("\nRun 'arp-guard help' to see all available commands.")
            return False
        
        # Get command info
        cmd_info = COMMAND_DESCRIPTIONS[command]
        
        # Print command details
        print(f"\n{Colors.BOLD}ARP Guard - {command.capitalize()} Command{Colors.END}")
        print(f"\n{Colors.BOLD}Description:{Colors.END}")
        print(textwrap.dedent(cmd_info['long']).strip())
        
        print(f"\n{Colors.BOLD}Usage:{Colors.END}")
        print(f"  arp-guard {Colors.BLUE}{command}{Colors.END} [options]")
        
        print(f"\n{Colors.BOLD}Options:{Colors.END}")
        for opt, desc in cmd_info['options'].items():
            print(f"  {Colors.YELLOW}{opt.ljust(20)}{Colors.END} {desc}")
        
        print(f"\n{Colors.BOLD}Examples:{Colors.END}")
        for example in COMMAND_EXAMPLES.get(command, []):
            print(f"  {example}")
            
        return True
    
    @staticmethod
    def get_command_suggestions(partial_cmd: str) -> List[str]:
        """
        Get command suggestions based on partial input
        
        Args:
            partial_cmd: Partial command string
            
        Returns:
            List of matching command suggestions
        """
        if not partial_cmd:
            return list(COMMAND_DESCRIPTIONS.keys())
            
        # Get direct matches (commands that start with partial_cmd)
        direct_matches = [cmd for cmd in COMMAND_DESCRIPTIONS.keys() 
                        if cmd.startswith(partial_cmd)]
        
        # If we have direct matches, return those
        if direct_matches:
            return direct_matches
            
        # Otherwise, find fuzzy matches
        return difflib.get_close_matches(partial_cmd, COMMAND_DESCRIPTIONS.keys())
    
    @staticmethod
    def get_option_suggestions(command: str, partial_opt: str) -> List[str]:
        """
        Get option suggestions for a command based on partial input
        
        Args:
            command: The command to get options for
            partial_opt: Partial option string
            
        Returns:
            List of matching option suggestions
        """
        if command not in COMMAND_DESCRIPTIONS:
            return []
            
        # Get all available options for the command
        cmd_options = COMMAND_DESCRIPTIONS[command]['options']
        options = []
        
        # Extract option names (handle both short and long forms)
        for opt_str in cmd_options.keys():
            for opt in opt_str.split(', '):
                opt = opt.strip()
                if opt.startswith('-'):
                    options.append(opt)
        
        # Filter by partial match
        if not partial_opt:
            return options
            
        return [opt for opt in options if opt.startswith(partial_opt)]
    
    @staticmethod
    def search_help(search_term: str) -> List[Dict[str, str]]:
        """
        Search help content for a term
        
        Args:
            search_term: Term to search for
            
        Returns:
            List of matching results with context
        """
        results = []
        
        # Convert search term to lowercase for case-insensitive matching
        search_term = search_term.lower()
        
        # Search in command descriptions
        for cmd, info in COMMAND_DESCRIPTIONS.items():
            # Search in short description
            if search_term in info['short'].lower():
                results.append({
                    'command': cmd,
                    'context': 'short description',
                    'text': info['short']
                })
            
            # Search in long description
            long_desc = textwrap.dedent(info['long']).strip()
            if search_term in long_desc.lower():
                # Find the specific paragraph containing the match
                paragraphs = long_desc.split('\n\n')
                for para in paragraphs:
                    if search_term in para.lower():
                        results.append({
                            'command': cmd,
                            'context': 'description',
                            'text': para.strip()
                        })
            
            # Search in options
            for opt, desc in info['options'].items():
                if search_term in opt.lower() or search_term in desc.lower():
                    results.append({
                        'command': cmd,
                        'context': f'option: {opt}',
                        'text': desc
                    })
        
        # Search in examples
        for cmd, examples in COMMAND_EXAMPLES.items():
            for example in examples:
                if search_term in example.lower():
                    results.append({
                        'command': cmd,
                        'context': 'example',
                        'text': example
                    })
        
        return results
    
    @staticmethod
    def print_search_results(search_term: str, results: List[Dict[str, str]]) -> None:
        """
        Print formatted search results
        
        Args:
            search_term: The search term
            results: List of search results
        """
        if not results:
            print(f"\n{Colors.YELLOW}No results found for '{search_term}'{Colors.END}")
            return
            
        print(f"\n{Colors.BOLD}Search results for '{search_term}':{Colors.END}")
        print(f"Found {len(results)} matches\n")
        
        for i, result in enumerate(results, 1):
            print(f"{i}. {Colors.BLUE}{result['command']}{Colors.END} ({result['context']})")
            
            # Highlight the search term in the text
            highlighted_text = result['text'].replace(
                search_term, 
                f"{Colors.YELLOW}{search_term}{Colors.END}"
            )
            print(f"   {highlighted_text}\n")
    
    @staticmethod
    def get_context_sensitive_help(command: str, subcommand: Optional[str] = None) -> str:
        """
        Get context-sensitive help based on the current command/subcommand
        
        Args:
            command: Current command
            subcommand: Current subcommand (optional)
            
        Returns:
            Context-sensitive help message
        """
        if command not in COMMAND_DESCRIPTIONS:
            return f"Unknown command: {command}. Run 'arp-guard help' for a list of commands."
            
        cmd_info = COMMAND_DESCRIPTIONS[command]
        
        if subcommand and subcommand in cmd_info['options']:
            # Return help for the specific subcommand
            return f"{subcommand}: {cmd_info['options'][subcommand]}"
        
        # Return general command help
        help_text = f"{command}: {cmd_info['short']}\n\n"
        help_text += "Options:\n"
        
        for opt, desc in list(cmd_info['options'].items())[:3]:  # Show first 3 options
            help_text += f"  {opt}: {desc}\n"
            
        if len(cmd_info['options']) > 3:
            help_text += f"  (and {len(cmd_info['options']) - 3} more options)\n"
            
        help_text += f"\nRun 'arp-guard help {command}' for more information."
        return help_text

def format_usage_example(command: str) -> None:
    """
    Print a formatted usage example for a command
    
    Args:
        command: Command to show usage example for
    """
    if command in COMMAND_EXAMPLES and COMMAND_EXAMPLES[command]:
        example = COMMAND_EXAMPLES[command][0]  # Get first example
        print(f"\n{Colors.BOLD}Example:{Colors.END} {example}")

def format_error(message: str) -> str:
    """
    Format an error message with color
    
    Args:
        message: Error message to format
        
    Returns:
        Formatted error message
    """
    return f"{Colors.RED}Error:{Colors.END} {message}"

def suggest_command_correction(wrong_cmd: str) -> Optional[str]:
    """
    Suggest a command correction for a mistyped command
    
    Args:
        wrong_cmd: The command to find corrections for
        
    Returns:
        Suggested correction or None if no good match found
    """
    suggestions = difflib.get_close_matches(wrong_cmd, COMMAND_DESCRIPTIONS.keys(), n=1, cutoff=0.6)
    return suggestions[0] if suggestions else None

# Interactive help session
def start_interactive_help() -> None:
    """Start an interactive help session"""
    print(f"\n{Colors.BOLD}Welcome to ARP Guard Interactive Help{Colors.END}")
    print("Type a command name, search term, or question.")
    print("Type 'exit' or 'quit' to exit.")
    
    while True:
        try:
            query = input(f"\n{Colors.BOLD}Help>{Colors.END} ").strip()
            
            if query.lower() in ('exit', 'quit', 'q'):
                break
                
            if not query:
                continue
                
            # Handle direct command help requests
            if query in COMMAND_DESCRIPTIONS:
                HelpSystem.print_command_help(query)
                continue
                
            # Check if this is a search request
            if query.startswith('search ') or query.startswith('find ') or '?' in query:
                search_term = query.replace('search ', '').replace('find ', '').replace('?', '').strip()
                if search_term:
                    results = HelpSystem.search_help(search_term)
                    HelpSystem.print_search_results(search_term, results)
                continue
                
            # Check for command suggestions
            suggestions = HelpSystem.get_command_suggestions(query)
            if suggestions:
                print(f"\nDid you mean one of these commands?")
                for suggestion in suggestions:
                    print(f"  {Colors.BLUE}{suggestion}{Colors.END} - {COMMAND_DESCRIPTIONS[suggestion]['short']}")
                continue
                
            # General search as fallback
            print(f"\nSearching help for '{query}'...")
            results = HelpSystem.search_help(query)
            HelpSystem.print_search_results(query, results)
                
        except KeyboardInterrupt:
            print("\nExiting interactive help.")
            break
        except Exception as e:
            print(f"\n{Colors.RED}Error in help system:{Colors.END} {str(e)}")

# Main entry point for help system
def show_help(args: List[str]) -> int:
    """
    Main entry point for the help system
    
    Args:
        args: Command line arguments for help
        
    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    if not args or args[0] in ('-h', '--help'):
        # Show general help
        HelpSystem.print_general_help()
        return 0
        
    if args[0] == 'interactive':
        # Start interactive help session
        start_interactive_help()
        return 0
        
    if args[0] == 'search' and len(args) > 1:
        # Search help
        search_term = ' '.join(args[1:])
        results = HelpSystem.search_help(search_term)
        HelpSystem.print_search_results(search_term, results)
        return 0
        
    # Show help for specific command
    command = args[0].lower()
    if HelpSystem.print_command_help(command):
        return 0
    else:
        return 1 
import time
import threading
import sys
import shutil

class Spinner:
    """Spinner animation for command-line interfaces"""
    
    def __init__(self, message: str = "Processing", chars: str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏", delay: float = 0.1):
        """
        Initialize the spinner
        
        Args:
            message: Message to display next to the spinner
            chars: Characters to use for spinner animation
            delay: Delay between spinner updates in seconds
        """
        self.message = message
        self.chars = chars
        self.delay = delay
        self.running = False
        self.thread = None
        self.spinner_idx = 0
        self.terminal_width = shutil.get_terminal_size().columns
        
    def _spin(self):
        """Internal method to update spinner"""
        while self.running:
            # Get current spinner character
            char = self.chars[self.spinner_idx % len(self.chars)]
            
            # Construct and print line with spinner
            line = f"\r{char} {self.message}"
            
            # Truncate if too long for terminal
            if len(line) > self.terminal_width:
                line = line[:self.terminal_width - 3] + "..."
            
            # Clear to end of line
            line = line.ljust(self.terminal_width)
            
            # Print spinner
            sys.stdout.write(line)
            sys.stdout.flush()
            
            # Update spinner index
            self.spinner_idx += 1
            
            # Sleep before next update
            time.sleep(self.delay)
    
    def start(self):
        """Start the spinner animation"""
        if self.running:
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._spin)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self):
        """Stop the spinner animation"""
        self.running = False
        if self.thread:
            self.thread.join()
        
        # Clear spinner line
        sys.stdout.write("\r" + " " * self.terminal_width + "\r")
        sys.stdout.flush()
        
    def update_message(self, message: str):
        """
        Update spinner message
        
        Args:
            message: New message
        """
        self.message = message


class InteractiveShell:
    """Interactive shell for CLI applications"""
    
    def __init__(self, prompt: str = "> ", history_file: str = None):
        """
        Initialize interactive shell
        
        Args:
            prompt: Command prompt string
            history_file: Path to history file (if any)
        """
        self.prompt = prompt
        self.history_file = history_file
        self.running = False
        self.command_handlers = {}
        self.help_messages = {}
        self.aliases = {}
        
        # Register built-in commands
        self.register_command("help", self._help_command, "Show help for commands")
        self.register_command("exit", self._exit_command, "Exit the shell")
        self.register_command("quit", self._exit_command, "Exit the shell")
        
        # Try to import readline for better input handling
        try:
            import readline
            self.readline_available = True
            
            # Set up history file
            if history_file:
                try:
                    readline.read_history_file(history_file)
                except FileNotFoundError:
                    # History file doesn't exist yet
                    pass
        except ImportError:
            self.readline_available = False
    
    def register_command(self, command: str, handler: callable, help_message: str = None):
        """
        Register a command handler
        
        Args:
            command: Command string
            handler: Function to call when command is entered
            help_message: Help message for command
        """
        self.command_handlers[command] = handler
        if help_message:
            self.help_messages[command] = help_message
    
    def register_alias(self, alias: str, command: str):
        """
        Register an alias for a command
        
        Args:
            alias: Alias string
            command: Command to execute
        """
        if command in self.command_handlers:
            self.aliases[alias] = command
        else:
            print(f"Cannot create alias for unknown command: {command}")
    
    def _help_command(self, args: List[str]) -> bool:
        """Handle help command"""
        if args:
            # Help for specific command
            command = args[0]
            if command in self.help_messages:
                print(f"{command}: {self.help_messages[command]}")
            else:
                print(f"No help available for '{command}'")
        else:
            # General help - list all commands
            print("Available commands:")
            for cmd, help_text in sorted(self.help_messages.items()):
                print(f"  {cmd:<15} - {help_text}")
            
            if self.aliases:
                print("\nAliases:")
                for alias, cmd in sorted(self.aliases.items()):
                    print(f"  {alias:<15} -> {cmd}")
        
        return True
    
    def _exit_command(self, args: List[str]) -> bool:
        """Handle exit command"""
        self.running = False
        return True
    
    def _parse_command(self, command_line: str) -> (str, List[str]):
        """
        Parse command line into command and arguments
        
        Args:
            command_line: Command line to parse
            
        Returns:
            Tuple of (command, arguments)
        """
        parts = command_line.strip().split()
        if not parts:
            return "", []
            
        command = parts[0].lower()
        
        # Check if this is an alias
        if command in self.aliases:
            command = self.aliases[command]
            
        args = parts[1:] if len(parts) > 1 else []
        
        return command, args
    
    def run(self) -> int:
        """
        Run the interactive shell loop
        
        Returns:
            Exit code
        """
        self.running = True
        
        print("Type 'help' for a list of commands. Type 'exit' to quit.")
        
        while self.running:
            try:
                # Get input with prompt
                command_line = input(self.prompt)
                
                # Skip empty lines
                if not command_line.strip():
                    continue
                
                # Parse command
                command, args = self._parse_command(command_line)
                
                # Execute command if registered
                if command in self.command_handlers:
                    try:
                        self.command_handlers[command](args)
                    except Exception as e:
                        print(f"Error executing command: {e}")
                else:
                    print(f"Unknown command: {command}")
            
            except KeyboardInterrupt:
                print("\nInterrupted.")
            
            except EOFError:
                # Handle Ctrl+D
                print("\nExiting...")
                self.running = False
        
        # Save history when exiting
        if self.readline_available and self.history_file:
            try:
                import readline
                readline.write_history_file(self.history_file)
            except Exception as e:
                print(f"Error saving command history: {e}")
        
        return 0
