from typing import Dict, Any, List, Optional, Callable, Union, Tuple
import argparse
import sys
import logging
import os
from dataclasses import dataclass, field
import time
import json
import yaml
import threading
from datetime import datetime

from .module_interface import Module, ModuleConfig
from .feature_flags import feature_required, FeatureDisabledException
from .cli_utils import OutputFormatter, OutputFormat, ProgressBar, Spinner, InteractiveShell
from .network_config import NetworkConfigManager, create_default_config
from .version import get_version, get_release_date

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class CLICommandConfig(ModuleConfig):
    """Configuration for CLI commands"""
    name: str
    description: str
    feature_id: Optional[str] = None
    subcommands: Dict[str, 'CLICommandConfig'] = field(default_factory=dict)
    arguments: List[Dict[str, Any]] = field(default_factory=list)


class CLICommand:
    """Command class for CLI interface"""
    
    def __init__(self, 
                 name: str, 
                 description: str, 
                 handler: Callable[[argparse.Namespace], bool],
                 feature_id: Optional[str] = None):
        """Initialize CLI command
        
        Args:
            name: Command name
            description: Command description
            handler: Function to handle command execution
            feature_id: Optional feature ID required for this command
        """
        self.name = name
        self.description = description
        self.handler = handler
        self.feature_id = feature_id
        self.subcommands: Dict[str, CLICommand] = {}
        self.arguments: List[Dict[str, Any]] = []
        self.parser = argparse.ArgumentParser(description=description, add_help=False)
    
    def add_subcommand(self, command: 'CLICommand') -> None:
        """Add a subcommand
        
        Args:
            command: Subcommand to add
        """
        self.subcommands[command.name] = command
    
    def add_argument(self, *args, **kwargs) -> None:
        """Add an argument to the command
        
        Args:
            *args: Positional arguments for argparse.add_argument
            **kwargs: Keyword arguments for argparse.add_argument
        """
        self.arguments.append({"args": args, "kwargs": kwargs})
        self.parser.add_argument(*args, **kwargs)
    
    def add_subparsers(self, dest: str) -> argparse._SubParsersAction:
        """Add subparsers to command parser
        
        Args:
            dest: Destination attribute for subparser
            
        Returns:
            Subparsers action object
        """
        return self.parser.add_subparsers(dest=dest, help=f"{self.name} subcommands")
    
    def setup_parser(self, parser: argparse.ArgumentParser) -> None:
        """Set up command in parser
        
        Args:
            parser: Parser to set up command in
        """
        # Add arguments to parser
        for arg in self.arguments:
            parser.add_argument(*arg["args"], **arg["kwargs"])
        
        # Set up subcommands if any
        if self.subcommands:
            subparsers = parser.add_subparsers(dest=f"{self.name}_command", help=f"{self.name} commands")
            for name, cmd in self.subcommands.items():
                subparser = subparsers.add_parser(name, help=cmd.description, conflict_handler='resolve')
                cmd.setup_parser(subparser)
    
    def execute(self, args: argparse.Namespace) -> bool:
        """Execute the command
        
        Args:
            args: Parsed arguments
            
        Returns:
            True if command executed successfully, False otherwise
        """
        # Check if we need to execute a subcommand
        subcommand_dest = f"{self.name}_command"
        if self.subcommands and hasattr(args, subcommand_dest):
            subcommand_name = getattr(args, subcommand_dest)
            if subcommand_name and subcommand_name in self.subcommands:
                return self.subcommands[subcommand_name].execute(args)
        
        # Execute this command's handler if feature is enabled
        if self.feature_id:
            try:
                # Use the feature_required decorator dynamically
                decorated_handler = feature_required(self.feature_id)(self.handler)
                return decorated_handler(args)
            except FeatureDisabledException as e:
                logger.error(f"Cannot execute command: {e}")
                return False
        else:
            # No feature requirement, execute directly
            return self.handler(args)


class CLIModuleConfig(ModuleConfig):
    """Configuration for CLI module"""
    program_name: str = "arpguard"
    program_description: str = "ARP Guard - Network Security Tool"
    version: str = "1.0.0"
    config_dir: str = os.path.expanduser("~/.arpguard")
    log_file: str = "arpguard.log"
    command_configs: Dict[str, CLICommandConfig] = field(default_factory=dict)
    default_output_format: OutputFormat = OutputFormat.PRETTY
    enable_interactive_mode: bool = True
    interactive_prompt: str = "arpguard> "


class CLIModule(Module):
    """CLI module for ARPGuard"""
    
    def __init__(self, config: Optional[CLIModuleConfig] = None):
        """Initialize CLI module
        
        Args:
            config: CLI module configuration
        """
        super().__init__("cli", "Command Line Interface", config or CLIModuleConfig())
        self.parser = argparse.ArgumentParser(
            prog=self.config.program_name,
            description=f"ARP Guard CLI (Version {get_version()})",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        self.commands: Dict[str, CLICommand] = {}
        self.subparsers = self.parser.add_subparsers(dest="command", help="Available commands")
        self.output_formatter = OutputFormatter()
        self.interactive_shell = None
        
        # Create all command groups
        self._create_remediation_commands()
    
    def initialize(self) -> bool:
        """Initialize the CLI module
        
        Returns:
            True if initialization successful, False otherwise
        """
        try:
            # Create config directory if it doesn't exist
            os.makedirs(self.config.config_dir, exist_ok=True)
            
            # Set up parser
            self.parser.add_argument(
                "--version", 
                action="version", 
                version=f"%(prog)s {self.config.version}"
            )
            
            # Add global output format option
            self.parser.add_argument(
                "--output-format", "-of",
                choices=[format.value for format in OutputFormat],
                help="Output format"
            )
            
            # Add interactive mode option
            if self.config.enable_interactive_mode:
                self.parser.add_argument(
                    "--interactive", "-i",
                    action="store_true",
                    help="Run in interactive mode"
                )
            
            # Add parser for commands - this is the key part
            self.subparsers = self.parser.add_subparsers(
                dest="command",
                help="Commands"
            )
            
            # Set up registered commands
            # Add all commands to the subparsers
            for name, cmd in self.commands.items():
                command_parser = self.subparsers.add_parser(name, help=cmd.description, conflict_handler='resolve')
                cmd.setup_parser(command_parser)
            
            # Initialize interactive shell if enabled
            if self.config.enable_interactive_mode:
                # Create interactive shell with prompt only
                self.interactive_shell = InteractiveShell(
                    prompt=self.config.interactive_prompt,
                    history_file=os.path.join(self.config.config_dir, "history")
                )
                
                # Register command handler
                self.interactive_shell.register_command(
                    "command", 
                    self._handle_interactive_command,
                    "Execute CLI command"
                )
            
            self.logger.info("CLI module initialized")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize CLI module: {e}")
            return False
    
    def shutdown(self) -> bool:
        """Shutdown the CLI module
        
        Returns:
            True if shutdown successful, False otherwise
        """
        try:
            self.logger.info("CLI module shutdown")
            return True
        except Exception as e:
            self.logger.error(f"Failed to shutdown CLI module: {e}")
            return False
    
    def register_command(self, command: CLICommand) -> bool:
        """Register a command with the CLI
        
        Args:
            command: Command to register
            
        Returns:
            True if registration successful, False otherwise
        """
        if command.name in self.commands:
            # Update existing command instead of skipping
            logger.info(f"Updating existing command: {command.name}")
            self.commands[command.name] = command
            return True
        
        self.commands[command.name] = command
        logger.info(f"Registered command: {command.name}")
        return True
    
    def unregister_command(self, command_name: str) -> bool:
        """Unregister a command
        
        Args:
            command_name: Name of command to unregister
            
        Returns:
            True if unregistration successful, False otherwise
        """
        if command_name not in self.commands:
            self.logger.warning(f"Command {command_name} not registered")
            return False
        
        del self.commands[command_name]
        self.logger.info(f"Command {command_name} unregistered")
        return True
    
    def run(self, args: Optional[List[str]] = None) -> bool:
        """Run the CLI
        
        Args:
            args: Optional list of command line arguments (defaults to sys.argv[1:])
            
        Returns:
            True if command execution successful, False otherwise
        """
        if args is None:
            parsed_args = self.parser.parse_args()
        else:
            # Parse the provided arguments
            parsed_args = self.parser.parse_args(args)
        
        # Check for interactive mode
        if self.config.enable_interactive_mode and hasattr(parsed_args, 'interactive') and parsed_args.interactive:
            return self._run_interactive_mode()
        
        # Set output format if specified
        if hasattr(parsed_args, 'output_format') and parsed_args.output_format:
            self.config.default_output_format = OutputFormat(parsed_args.output_format)
        
        # If no command specified, and we have args, show help and return
        if not hasattr(parsed_args, 'command') or not parsed_args.command:
            self.parser.print_help()
            return True
        
        # Execute the command if it exists
        if parsed_args.command in self.commands:
            return self.commands[parsed_args.command].execute(parsed_args)
        
        self.logger.error(f"Unknown command: {parsed_args.command}")
        return False
    
    def _run_interactive_mode(self) -> bool:
        """Run in interactive mode
        
        Returns:
            True if interactive mode ran successfully, False otherwise
        """
        if not self.interactive_shell:
            self.logger.error("Interactive shell not initialized")
            return False
        
        try:
            self.interactive_shell.start()
            return True
        except Exception as e:
            self.logger.error(f"Error in interactive mode: {e}")
            return False
    
    def _handle_interactive_command(self, args: List[str]) -> bool:
        """Handle command in interactive mode
        
        Args:
            args: Command arguments
            
        Returns:
            True if command handled successfully, False otherwise
        """
        try:
            # Create spinner for long-running commands
            spinner = Spinner(f"Executing command: {' '.join(args)}")
            
            if not args:
                return True
                
            # Convert args list to a command string and its arguments
            cmd_name = args[0]
            cmd_args = args[1:] if len(args) > 1 else []
            
            if cmd_name in self.commands:
                # Start spinner for commands that might take time
                if cmd_name in ('start', 'scan', 'export'):
                    spinner.start()
                
                try:
                    # Create a namespace with the command and its arguments
                    namespace = argparse.Namespace()
                    namespace.command = cmd_name
                    
                    # Add any command-specific arguments
                    for i, arg in enumerate(cmd_args):
                        if arg.startswith('--') and i + 1 < len(cmd_args) and not cmd_args[i + 1].startswith('--'):
                            # Handle --key value pairs
                            key = arg[2:]  # Remove -- prefix
                            setattr(namespace, key.replace('-', '_'), cmd_args[i + 1])
                        elif arg.startswith('-') and i + 1 < len(cmd_args) and not cmd_args[i + 1].startswith('-'):
                            # Handle -k value pairs
                            key = arg[1:]  # Remove - prefix
                            setattr(namespace, key.replace('-', '_'), cmd_args[i + 1])
                    
                    # Execute the command
                    result = self.commands[cmd_name].execute(namespace)
                    
                    # Stop spinner
                    if spinner.running:
                        spinner.stop()
                        
                    return result
                except Exception as e:
                    self.logger.error(f"Error executing command: {e}")
                    if spinner.running:
                        spinner.stop()
                    print(f"Error: {e}")
                    return False
            else:
                print(f"Unknown command: {cmd_name}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error handling interactive command: {e}")
            if 'spinner' in locals() and spinner.running:
                spinner.stop()
            return False
    
    def format_output(self, data: Any, format_type: Optional[OutputFormat] = None, headers: Optional[List[str]] = None) -> str:
        """Format data for output
        
        Args:
            data: Data to format
            format_type: Output format (uses default if None)
            headers: Headers for table format
            
        Returns:
            Formatted output string
        """
        format_type = format_type or self.config.default_output_format
        return OutputFormatter.format_output(data, format_type, headers)
    
    def create_progress_bar(self, total: int, description: str = "Progress") -> ProgressBar:
        """Create a progress bar
        
        Args:
            total: Total number of steps
            description: Description of the progress bar
            
        Returns:
            Progress bar instance
        """
        return ProgressBar(total=total, description=description)
    
    def create_spinner(self, description: str = "Processing", pattern: str = "dots") -> Spinner:
        """Create a spinner
        
        Args:
            description: Description of the spinner
            pattern: Spinner pattern to use
            
        Returns:
            Spinner instance
        """
        return Spinner(description=description, pattern=pattern)

    def _create_remediation_commands(self) -> None:
        """Create remediation-related commands."""
        # First, create and add all standard commands
        standard_commands = create_standard_commands()
        for name, cmd in standard_commands.items():
            if name not in self.commands:  # Only register if not already registered
                self.commands[name] = cmd
                self.logger.info(f"Registered standard command: {name}")
            
        # Create a single top-level remediation command
        remediation_cmd = CLICommand(
            name="remediation",
            description="Manage remediation settings",
            handler=self._handle_remediation_main  # A main handler for remediation commands
        )
        
        # Create subcommands of the remediation command
        # Show command
        show_cmd = CLICommand(
            name="show",
            description="Show current remediation settings",
            handler=self._handle_remediation_show
        )
        remediation_cmd.add_subcommand(show_cmd)
        
        # Set command
        set_cmd = CLICommand(
            name="set",
            description="Set remediation settings",
            handler=self._handle_remediation_set
        )
        set_cmd.add_argument("setting", help="Setting to modify")
        set_cmd.add_argument("value", help="New value")
        remediation_cmd.add_subcommand(set_cmd)
        
        # Whitelist command
        whitelist_cmd = CLICommand(
            name="whitelist",
            description="Manage whitelist entries",
            handler=self._handle_remediation_whitelist
        )
        
        # Create subcommands for whitelist
        whitelist_subparsers = whitelist_cmd.add_subparsers(dest="action")
        
        # Add subcommand
        add_parser = whitelist_subparsers.add_parser("add", conflict_handler='resolve')
        add_parser.add_argument("mac", help="MAC address to whitelist")
        add_parser.add_argument("ip", help="IP address to whitelist")
        
        # Remove subcommand
        remove_parser = whitelist_subparsers.add_parser("remove", conflict_handler='resolve')
        remove_parser.add_argument("mac", help="MAC address to remove")
        
        # List subcommand
        whitelist_subparsers.add_parser("list", conflict_handler='resolve')
        
        remediation_cmd.add_subcommand(whitelist_cmd)
        
        # Register the main remediation command with the top-level parser
        if "remediation" not in self.commands:  # Only register if not already registered
            self.commands["remediation"] = remediation_cmd
            self.logger.info("Registered remediation command")
    
    def _handle_remediation_main(self, args: argparse.Namespace) -> bool:
        """Main handler for remediation commands
        
        Args:
            args: Parsed arguments
            
        Returns:
            True if command executed successfully, False otherwise
        """
        if not hasattr(args, 'command') or not args.command:
            # No subcommand specified, show help
            remediation_cmd = self.commands.get("remediation")
            if remediation_cmd:
                remediation_cmd.parser.print_help()
            return True
        return False

    def _handle_remediation_show(self, args: argparse.Namespace) -> bool:
        """Handle remediation show command
        
        Args:
            args: Parsed arguments
            
        Returns:
            True if command executed successfully, False otherwise
        """
        logger.info("Showing remediation settings")
        try:
            from .remediation_module import RemediationModule
            remediation = RemediationModule()
            status = remediation.get_status()
            
            print("Remediation settings:")
            print(f"- Auto-blocking: {'Enabled' if status['auto_block'] else 'Disabled'}")
            print(f"- Block duration: {status['block_duration']} seconds")
            print(f"- Notification: {'Enabled' if status['notify_admin'] else 'Disabled'}")
            print(f"- Whitelist: {len(status.get('whitelist', []))} entries")
            print(f"- Blocked hosts: {status['blocked_hosts_count']}")
            
            # Show blocked hosts if any
            if status['blocked_hosts_count'] > 0:
                print("\nCurrently blocked hosts:")
                blocked_hosts = remediation.get_blocked_hosts()
                for host in blocked_hosts:
                    print(f"- {host['mac_address']} ({host['ip_address']}) - {host['reason']}")
                    
        except Exception as e:
            logger.error(f"Error showing remediation settings: {e}")
            print(f"Error: {e}")
            return False
        return True
    
    def _handle_remediation_set(self, args: argparse.Namespace) -> bool:
        """Handle remediation set command
        
        Args:
            args: Parsed arguments
            
        Returns:
            True if command executed successfully, False otherwise
        """
        logger.info(f"Setting remediation: {args.setting} = {args.value}")
        try:
            from .remediation_module import RemediationModule
            remediation = RemediationModule()
            
            # Map setting names to actual config attributes
            setting_map = {
                'auto_block': bool,
                'block_duration': int,
                'notify_admin': bool,
                'notification_email': str,
                'notification_threshold': int
            }
            
            if args.setting not in setting_map:
                print(f"Error: Invalid setting '{args.setting}'. Valid settings are: {', '.join(setting_map.keys())}")
                return False
                
            # Convert value to appropriate type
            value_type = setting_map[args.setting]
            try:
                if value_type == bool:
                    value = args.value.lower() in ('true', 'yes', '1', 'enabled')
                else:
                    value = value_type(args.value)
            except ValueError:
                print(f"Error: Invalid value for {args.setting}. Expected type: {value_type.__name__}")
                return False
                
            # Update the setting
            setattr(remediation.config, args.setting, value)
            print(f"Successfully set {args.setting} to {value}")
            
        except Exception as e:
            logger.error(f"Error setting remediation setting: {e}")
            print(f"Error: {e}")
            return False
        return True
    
    def _handle_remediation_whitelist(self, args: argparse.Namespace) -> bool:
        """Handle remediation whitelist command
        
        Args:
            args: Parsed arguments
            
        Returns:
            True if command executed successfully, False otherwise
        """
        try:
            from .remediation_module import RemediationModule
            remediation = RemediationModule()
            
            if args.action == "add":
                logger.info(f"Adding to whitelist: {args.mac} - {args.ip}")
                # Validate MAC and IP format
                if not _is_valid_mac(args.mac):
                    print(f"Error: Invalid MAC address format: {args.mac}")
                    return False
                if not _is_valid_ip(args.ip):
                    print(f"Error: Invalid IP address format: {args.ip}")
                    return False
                    
                # Add to whitelist
                entry = f"{args.mac}:{args.ip}"
                if entry not in remediation.config.whitelist:
                    remediation.config.whitelist.append(entry)
                    print(f"Added {args.mac} ({args.ip}) to whitelist")
                else:
                    print(f"Entry {args.mac} ({args.ip}) already in whitelist")
                    
            elif args.action == "remove":
                logger.info(f"Removing from whitelist: {args.mac}")
                # Remove all entries with this MAC
                removed = False
                for entry in remediation.config.whitelist[:]:
                    if entry.startswith(args.mac + ":"):
                        remediation.config.whitelist.remove(entry)
                        removed = True
                if removed:
                    print(f"Removed {args.mac} from whitelist")
                else:
                    print(f"No entries found for MAC {args.mac}")
                    
            elif args.action == "list":
                logger.info("Listing whitelist entries")
                print("Whitelist entries:")
                if not remediation.config.whitelist:
                    print("- No entries")
                else:
                    for entry in remediation.config.whitelist:
                        mac, ip = entry.split(":")
                        print(f"- {mac} ({ip})")
                        
        except Exception as e:
            logger.error(f"Error managing whitelist: {e}")
            print(f"Error: {e}")
            return False
        return True

    def _handle_telemetry(self, args: argparse.Namespace) -> bool:
        """Handle telemetry command
        
        Args:
            args: Parsed arguments
            
        Returns:
            True if command executed successfully, False otherwise
        """
        try:
            from .telemetry_module import TelemetryModule
            telemetry = TelemetryModule()
            
            if args.action == "show":
                logger.info("Showing telemetry status")
                status = telemetry.get_status()
                print("Telemetry status:")
                print(f"- Enabled: {'Yes' if status['enabled'] else 'No'}")
                print(f"- Collection interval: {status['collection_interval']} minutes")
                print(f"- Last collection: {status['last_collection']}")
                print(f"- Data points collected: {status['data_points']}")
                print(f"- Installation ID: {status['installation_id']}")
                
            elif args.action == "enable":
                logger.info("Enabling telemetry")
                result = telemetry.enable()
                if result:
                    print("Telemetry enabled successfully")
                else:
                    print("Failed to enable telemetry")
                    return False
                
            elif args.action == "disable":
                logger.info("Disabling telemetry")
                result = telemetry.disable()
                if result:
                    print("Telemetry disabled successfully")
                else:
                    print("Failed to disable telemetry")
                    return False
                
        except Exception as e:
            logger.error(f"Error managing telemetry: {e}")
            print(f"Error: {e}")
            return False
        return True

    def _handle_version(self, args: argparse.Namespace) -> None:
        """Handle version command."""
        print(f"ARP Guard Version: {get_version()} (Released: {get_release_date()})")
        print("Copyright (c) 2024-2025 ARP Guard Team")
        print("License: MIT")


# Standard commands factory functions

def create_standard_commands() -> Dict[str, CLICommand]:
    """Create standard commands for the CLI
    
    Returns:
        Dictionary of standard commands
    """
    commands = {}
    
    # Start command
    start_cmd = CLICommand(
        name="start",
        description="Start ARP Guard monitoring",
        handler=_handle_start,
        feature_id="core.packet_analysis"
    )
    start_cmd.add_argument(
        "--interface", "-i",
        help="Network interface to monitor"
    )
    start_cmd.add_argument(
        "--duration", "-d",
        type=int,
        help="Duration to monitor in seconds (0 for continuous)"
    )
    start_cmd.add_argument(
        "--filter", "-f",
        help="Packet filter expression"
    )
    commands["start"] = start_cmd
    
    # Stop command
    stop_cmd = CLICommand(
        name="stop",
        description="Stop ARP Guard monitoring",
        handler=_handle_stop
    )
    commands["stop"] = stop_cmd
    
    # Status command
    status_cmd = CLICommand(
        name="status",
        description="Show ARP Guard status",
        handler=_handle_status
    )
    commands["status"] = status_cmd
    
    # Stats command
    stats_cmd = CLICommand(
        name="stats",
        description="Show ARP Guard statistics",
        handler=_handle_statistics
    )
    stats_cmd.add_argument(
        "--detailed", "-d",
        action="store_true",
        help="Show detailed statistics"
    )
    stats_cmd.add_argument(
        "--format", "-f",
        choices=["json", "csv", "table", "pretty", "text"],
        default="text",
        help="Output format"
    )
    commands["stats"] = stats_cmd
    
    # Export command
    export_cmd = CLICommand(
        name="export",
        description="Export detection results",
        handler=_handle_export,
        feature_id="core.export"
    )
    export_cmd.add_argument(
        "--format", "-f",
        choices=["json", "csv"],
        default="json",
        help="Export format"
    )
    export_cmd.add_argument(
        "--output", "-o",
        help="Output file path"
    )
    commands["export"] = export_cmd
    
    # Config command
    config_cmd = CLICommand(
        name="config",
        description="Manage configuration",
        handler=_handle_config
    )
    config_cmd.add_argument(
        "action",
        choices=["show", "set", "reset"],
        help="Configuration action"
    )
    config_cmd.add_argument(
        "--key", "-k",
        help="Configuration key"
    )
    config_cmd.add_argument(
        "--value", "-v",
        help="Configuration value"
    )
    commands["config"] = config_cmd
    
    # Telemetry command
    telemetry_cmd = CLICommand(
        name="telemetry",
        description="Manage telemetry settings",
        handler=_handle_telemetry
    )
    telemetry_cmd.add_argument(
        "action",
        choices=["show", "enable", "disable"],
        help="Telemetry action"
    )
    commands["telemetry"] = telemetry_cmd
    
    return commands


# Command handlers

def _handle_start(args: argparse.Namespace) -> bool:
    """Handle start command
    
    Args:
        args: Parsed arguments
        
    Returns:
        True if command executed successfully, False otherwise
    """
    try:
        # Import detection module and config
        from .detection_module import DetectionModule, DetectionModuleConfig
        import time  # Explicitly import time module
        
        # Initialize progress bar
        progress = ProgressBar(total=5, description="Starting ARP Guard...")
        progress.start()
        
        # Step 1: Initialize detection module
        progress.update(1)
        # Create configuration object
        config = DetectionModuleConfig()
        if args.interface:
            config.network_interface = args.interface
        if args.filter:
            config.packet_filter = args.filter
            
        detection = DetectionModule(config=config)
        detection.initialize()
        
        # Step 2: Start the detection module
        progress.update(2)
        detection.start()
        
        # Step 3: Start analysis
        progress.update(3)
        # The start() method likely handles this already
        time.sleep(0.5)  # Small delay to show progress
        
        # Step 4: Check if remediation is enabled
        progress.update(4)
        # This is handled by the detection module internally
        time.sleep(0.5)  # Small delay to show progress
        
        # Step 5: Complete initialization
        progress.update(5)
        progress.complete()
        print("ARP Guard monitoring started successfully!")
        
        # If duration specified, run for that time
        if args.duration and args.duration > 0:
            print(f"Monitoring for {args.duration} seconds...")
            time.sleep(args.duration)
            detection.stop()
            print("Monitoring completed")
        
        return True
        
    except Exception as e:
        logger.error(f"Error starting ARP Guard: {e}")
        print(f"Error: {e}")
        return False

def _handle_stop(args: argparse.Namespace) -> bool:
    """Handle stop command
    
    Args:
        args: Parsed arguments
        
    Returns:
        True if command executed successfully, False otherwise
    """
    try:
        # Import detection module
        from .detection_module import DetectionModule, DetectionModuleConfig
        
        logger.info("Stopping ARP Guard monitoring...")
        
        # Create spinner for shutdown
        spinner = Spinner("Stopping ARP Guard monitoring")
        spinner.start()
        
        # Get detection module instance
        config = DetectionModuleConfig()
        detection = DetectionModule(config=config)
        
        # Stop monitoring - using the stop method
        spinner.update_message("Stopping detection engine...")
        detection.stop()
        time.sleep(0.5)
        
        spinner.update_message("Saving results...")
        # Assuming there's a method to save results
        if hasattr(detection, 'save_results'):
            detection.save_results()
        time.sleep(0.5)
        
        spinner.stop()
        print("ARP Guard monitoring stopped successfully")
        
        return True
    except Exception as e:
        logger.error(f"Error stopping ARP Guard: {e}")
        print(f"Error: {e}")
        return False

def _handle_status(args: argparse.Namespace) -> bool:
    """Handle status command
    
    Args:
        args: Parsed arguments
        
    Returns:
        True if command executed successfully, False otherwise
    """
    try:
        # Import detection module
        from .detection_module import DetectionModule, DetectionModuleConfig
        
        logger.info("ARP Guard Status:")
        
        # Get detection module instance
        config = DetectionModuleConfig()
        detection = DetectionModule(config=config)
        
        # Get status data
        try:
            status_data = detection.get_status()
        except:
            # Fallback to sample data if detection module not running
            status_data = {
                "status": "not running",
                "uptime": "0s",
                "interface": "not active",
                "packets_processed": 0,
                "attacks_detected": 0,
                "alerts_generated": 0,
                "memory_usage": "0 MB",
                "cpu_usage": "0%"
            }
        
        # Determine output format
        output_format = OutputFormat.PRETTY
        if hasattr(args, 'output_format') and args.output_format:
            output_format = OutputFormat(args.output_format)
        
        # Format and print status data
        formatter = OutputFormatter()
        formatted_output = formatter.format_output(status_data, output_format)
        print(formatted_output)
        
        return True
    except Exception as e:
        logger.error(f"Error getting ARP Guard status: {e}")
        print(f"Error: {e}")
        return False

def _handle_export(args: argparse.Namespace) -> bool:
    """Handle export command
    
    Args:
        args: Parsed arguments
        
    Returns:
        True if command executed successfully, False otherwise
    """
    try:
        # Import detection module
        from .detection_module import DetectionModule, DetectionModuleConfig
        
        format_type = args.format
        output_file = args.output or f"arpguard_export.{format_type}"
        
        logger.info(f"Exporting results to {output_file} in {format_type} format...")
        
        # Create progress bar for export
        progress = ProgressBar(total=100, description="Exporting results")
        progress.start()
        
        # Get detection module instance
        config = DetectionModuleConfig()
        detection = DetectionModule(config=config)
        
        # Export data
        success = detection.export_results(
            output_file=output_file,
            format_type=format_type
        )
        
        # Update progress to 100%
        progress.update(100)
        progress.complete()
        
        if success:
            logger.info(f"Export completed successfully. Results saved to {output_file}")
            print(f"Export completed successfully. Results saved to {output_file}")
        else:
            logger.error(f"Export failed.")
            print(f"Export failed. See logs for details.")
            return False
        
        return True
    except Exception as e:
        logger.error(f"Error exporting results: {e}")
        print(f"Error: {e}")
        return False

def _handle_config(args: argparse.Namespace) -> bool:
    """Handle config command
    
    Args:
        args: Parsed arguments
        
    Returns:
        True if command executed successfully, False otherwise
    """
    logger.info("Configuration management")
    # This should never be called directly as it has subcommands
    return False

def _handle_statistics(args: argparse.Namespace) -> bool:
    """Handle statistics command
    
    Args:
        args: Parsed arguments
        
    Returns:
        True if command executed successfully, False otherwise
    """
    try:
        # Import detection module
        from .detection_module import DetectionModule, DetectionModuleConfig
        
        logger.info("Showing ARP Guard statistics")
        
        # Get detection module instance
        config = DetectionModuleConfig()
        detection = DetectionModule(config=config)
        
        # Get statistics data
        try:
            stats_data = detection.get_statistics(detailed=args.detailed if hasattr(args, 'detailed') else False)
        except:
            # Fallback to sample data if detection module not running
            stats_data = {
                "total_packets": 0,
                "arp_packets": 0,
                "suspicious_arp": 0,
                "alerts_triggered": 0,
                "average_traffic": "0 Mbps",
                "monitoring_time": "0h 0m",
                "top_talkers": []
            }
        
        # Determine output format
        output_format = OutputFormat.PRETTY
        if hasattr(args, 'format') and args.format:
            output_format = OutputFormat(args.format)
        elif hasattr(args, 'output_format') and args.output_format:
            output_format = OutputFormat(args.output_format)
        
        # Format and print statistics data
        formatter = OutputFormatter()
        
        if hasattr(args, 'detailed') and args.detailed:
            # Detailed statistics
            print("=== DETAILED STATISTICS ===")
            formatted_output = formatter.format_output(stats_data, output_format)
            print(formatted_output)
            
            # Print top talkers
            print("\nTop Talkers:")
            talkers_data = stats_data.get("top_talkers", [])
            if talkers_data:
                headers = ["MAC Address", "IP Address", "Packets"]
                table_data = [[t["mac"], t["ip"], t["packets"]] for t in talkers_data]
                formatted_talkers = formatter.format_output(table_data, OutputFormat.TABLE, headers)
                print(formatted_talkers)
            else:
                print("No data available")
        else:
            # Basic statistics
            basic_stats = {k: v for k, v in stats_data.items() if k != "top_talkers"}
            formatted_output = formatter.format_output(basic_stats, output_format)
            print(formatted_output)
        
        return True
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        print(f"Error: {e}")
        return False

def _handle_telemetry(args: argparse.Namespace) -> bool:
    """Handle telemetry command
    
    Args:
        args: Parsed arguments
        
    Returns:
        True if command executed successfully, False otherwise
    """
    try:
        from .telemetry_module import TelemetryModule
        telemetry = TelemetryModule()
        
        if args.action == "show":
            logger.info("Showing telemetry status")
            status = telemetry.get_status()
            print("Telemetry status:")
            print(f"- Enabled: {'Yes' if status['enabled'] else 'No'}")
            print(f"- Collection interval: {status['collection_interval']} minutes")
            print(f"- Last collection: {status['last_collection']}")
            print(f"- Data points collected: {status['data_points']}")
            print(f"- Installation ID: {status['installation_id']}")
            
        elif args.action == "enable":
            logger.info("Enabling telemetry")
            result = telemetry.enable()
            if result:
                print("Telemetry enabled successfully")
            else:
                print("Failed to enable telemetry")
                return False
            
        elif args.action == "disable":
            logger.info("Disabling telemetry")
            result = telemetry.disable()
            if result:
                print("Telemetry disabled successfully")
            else:
                print("Failed to disable telemetry")
                return False
            
    except Exception as e:
        logger.error(f"Error managing telemetry: {e}")
        print(f"Error: {e}")
        return False
    return True 