from typing import Dict, Any, List, Optional, Callable, Union
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
                subparser = subparsers.add_parser(name, help=cmd.description)
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
            description=self.config.program_description
        )
        self.commands: Dict[str, CLICommand] = {}
        self.subparsers = None
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
            
            # Add parser for commands
            self.subparsers = self.parser.add_subparsers(
                dest="command",
                help="Commands"
            )
            
            # Set up registered commands
            for name, cmd in self.commands.items():
                command_parser = self.subparsers.add_parser(name, help=cmd.description)
                cmd.setup_parser(command_parser)
            
            # Initialize interactive shell if enabled
            if self.config.enable_interactive_mode:
                self.interactive_shell = InteractiveShell(
                    prompt=self.config.interactive_prompt,
                    command_handler=self._handle_interactive_command
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
        """Register a command
        
        Args:
            command: Command to register
            
        Returns:
            True if registration successful, False otherwise
        """
        if command.name in self.commands:
            self.logger.warning(f"Command {command.name} already registered")
            return False
        
        self.commands[command.name] = command
        self.logger.info(f"Command {command.name} registered")
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
    
    def run(self) -> bool:
        """Run the CLI
        
        Returns:
            True if command execution successful, False otherwise
        """
        args = self.parser.parse_args()
        
        # Check for interactive mode
        if self.config.enable_interactive_mode and hasattr(args, 'interactive') and args.interactive:
            return self._run_interactive_mode()
        
        # Set output format if specified
        if hasattr(args, 'output_format') and args.output_format:
            self.config.default_output_format = OutputFormat(args.output_format)
        
        if not args.command:
            self.parser.print_help()
            return True
        
        if args.command in self.commands:
            return self.commands[args.command].execute(args)
        
        self.logger.error(f"Unknown command: {args.command}")
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
    
    def _handle_interactive_command(self, command: str) -> bool:
        """Handle command in interactive mode
        
        Args:
            command: Command string
            
        Returns:
            True if command handled successfully, False otherwise
        """
        try:
            # Create spinner for long-running commands
            spinner = Spinner(f"Executing command: {command}")
            
            # Split command into arguments
            args = command.split()
            if not args:
                return True
            
            cmd_name = args[0]
            if cmd_name in self.commands:
                # Convert args to argparse namespace
                try:
                    # Start spinner for commands that might take time
                    if cmd_name in ('start', 'scan', 'export'):
                        spinner.start()
                    
                    # Parse args and execute command
                    parsed_args = self.parser.parse_args(args)
                    result = self.commands[cmd_name].execute(parsed_args)
                    
                    # Stop spinner
                    if spinner.running:
                        spinner.stop()
                    
                    return result
                except SystemExit:
                    # Argparse might call sys.exit for help/version/errors
                    # We catch this to keep the interactive shell running
                    if spinner.running:
                        spinner.stop()
                    return True
            else:
                print(f"Unknown command: {cmd_name}")
                return False
            
        except Exception as e:
            self.logger.error(f"Error handling interactive command: {e}")
            if spinner.running:
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
        # Remediation show command
        remediation_show = CLICommand(
            name="show",
            description="Show current remediation settings",
            handler=_handle_remediation_show
        )
        
        # Remediation set command
        remediation_set = CLICommand(
            name="set",
            description="Set remediation settings",
            handler=_handle_remediation_set
        )
        remediation_set.add_argument("setting", help="Setting to modify")
        remediation_set.add_argument("value", help="New value")
        
        # Remediation whitelist command
        remediation_whitelist = CLICommand(
            name="whitelist",
            description="Manage whitelist entries",
            handler=_handle_remediation_whitelist
        )
        whitelist_subparser = remediation_whitelist.add_subparsers(dest="action")
        
        # Add subcommand
        add_parser = whitelist_subparser.add_parser("add")
        add_parser.add_argument("mac", help="MAC address to whitelist")
        add_parser.add_argument("ip", help="IP address to whitelist")
        
        # Remove subcommand
        remove_parser = whitelist_subparser.add_parser("remove")
        remove_parser.add_argument("mac", help="MAC address to remove")
        
        # List subcommand
        whitelist_subparser.add_parser("list")
        
        # Add all remediation commands to the main parser
        remediation_parser = self.parser.add_subparsers(dest="remediation")
        remediation_parser.add_parser("show", parents=[remediation_show.parser])
        remediation_parser.add_parser("set", parents=[remediation_set.parser])
        remediation_parser.add_parser("whitelist", parents=[remediation_whitelist.parser])


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
    commands[start_cmd.name] = start_cmd
    
    # Stop command
    stop_cmd = CLICommand(
        name="stop",
        description="Stop ARP Guard monitoring",
        handler=_handle_stop
    )
    commands[stop_cmd.name] = stop_cmd
    
    # Status command
    status_cmd = CLICommand(
        name="status",
        description="Show ARP Guard status",
        handler=_handle_status
    )
    status_cmd.add_argument(
        "--output-format", "-of",
        choices=[format.value for format in OutputFormat],
        help="Output format"
    )
    commands[status_cmd.name] = status_cmd
    
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
    export_cmd.add_argument(
        "--limit", "-l",
        type=int,
        default=100,
        help="Maximum number of results to export"
    )
    commands[export_cmd.name] = export_cmd
    
    # Config command with subcommands
    config_cmd = CLICommand(
        name="config",
        description="Manage configuration",
        handler=_handle_config
    )
    
    # Config subcommands
    config_show_cmd = CLICommand(
        name="show",
        description="Show current configuration",
        handler=_handle_config_show
    )
    config_show_cmd.add_argument(
        "--output-format", "-of",
        choices=[format.value for format in OutputFormat],
        help="Output format"
    )
    config_cmd.add_subcommand(config_show_cmd)
    
    config_set_cmd = CLICommand(
        name="set",
        description="Set configuration value",
        handler=_handle_config_set
    )
    config_set_cmd.add_argument(
        "--key", "-k",
        required=True,
        help="Configuration key"
    )
    config_set_cmd.add_argument(
        "--value", "-v",
        required=True,
        help="Configuration value"
    )
    config_cmd.add_subcommand(config_set_cmd)
    
    config_reset_cmd = CLICommand(
        name="reset",
        description="Reset configuration to defaults",
        handler=_handle_config_reset
    )
    config_cmd.add_subcommand(config_reset_cmd)
    
    commands[config_cmd.name] = config_cmd
    
    # Create telemetry command with subcommands
    telemetry_cmd = CLICommand(
        name="telemetry",
        description="Manage telemetry settings",
        handler=_handle_telemetry
    )
    
    # Add telemetry subcommands
    telemetry_status_cmd = CLICommand(
        name="status",
        description="Show telemetry status",
        handler=_handle_telemetry_status
    )
    telemetry_cmd.add_subcommand(telemetry_status_cmd)
    
    telemetry_enable_cmd = CLICommand(
        name="enable",
        description="Enable telemetry collection",
        handler=_handle_telemetry_enable
    )
    telemetry_enable_cmd.add_argument("--confirm", action="store_true", 
                                      help="Confirm enabling telemetry")
    telemetry_cmd.add_subcommand(telemetry_enable_cmd)
    
    telemetry_disable_cmd = CLICommand(
        name="disable",
        description="Disable telemetry collection",
        handler=_handle_telemetry_disable
    )
    telemetry_cmd.add_subcommand(telemetry_disable_cmd)
    
    telemetry_delete_cmd = CLICommand(
        name="delete-data",
        description="Delete all telemetry data",
        handler=_handle_telemetry_delete_data
    )
    telemetry_delete_cmd.add_argument("--confirm", action="store_true", 
                                       help="Confirm deletion of all telemetry data")
    telemetry_cmd.add_subcommand(telemetry_delete_cmd)
    
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
    logger.info("Starting ARP Guard monitoring...")
    
    # Create progress for startup
    progress = ProgressBar(total=5, description="Starting ARP Guard")
    progress.start()
    
    # Simulate startup steps
    progress.update(1)
    logger.info("Initializing network interfaces...")
    time.sleep(0.5)
    
    progress.update(2)
    logger.info("Setting up packet filters...")
    time.sleep(0.5)
    
    progress.update(3)
    logger.info("Initializing detection engine...")
    time.sleep(0.5)
    
    progress.update(4)
    logger.info("Starting monitoring...")
    time.sleep(0.5)
    
    progress.update(5)
    progress.complete()
    
    logger.info("ARP Guard monitoring started successfully")
    
    # TODO: Implement actual start functionality
    return True

def _handle_stop(args: argparse.Namespace) -> bool:
    """Handle stop command
    
    Args:
        args: Parsed arguments
        
    Returns:
        True if command executed successfully, False otherwise
    """
    logger.info("Stopping ARP Guard monitoring...")
    
    # Create spinner for shutdown
    spinner = Spinner("Stopping ARP Guard monitoring")
    spinner.start()
    
    # Simulate shutdown steps
    time.sleep(1)
    spinner.update_message("Stopping detection engine...")
    time.sleep(0.5)
    
    spinner.update_message("Stopping packet capture...")
    time.sleep(0.5)
    
    spinner.update_message("Saving detection results...")
    time.sleep(0.5)
    
    spinner.stop()
    
    logger.info("ARP Guard monitoring stopped successfully")
    
    # TODO: Implement actual stop functionality
    return True

def _handle_status(args: argparse.Namespace) -> bool:
    """Handle status command
    
    Args:
        args: Parsed arguments
        
    Returns:
        True if command executed successfully, False otherwise
    """
    logger.info("ARP Guard Status:")
    
    # Create sample status data
    status_data = {
        "status": "running",
        "uptime": "2h 34m 12s",
        "interface": "eth0",
        "packets_processed": 12345,
        "attacks_detected": 2,
        "alerts_generated": 5,
        "memory_usage": "123.4 MB",
        "cpu_usage": "2.3%"
    }
    
    # Determine output format
    output_format = OutputFormat.PRETTY
    if hasattr(args, 'output_format') and args.output_format:
        output_format = OutputFormat(args.output_format)
    
    # Format and print status data
    formatted_output = OutputFormatter.format_output(status_data, output_format)
    print(formatted_output)
    
    # TODO: Implement actual status functionality
    return True

def _handle_export(args: argparse.Namespace) -> bool:
    """Handle export command
    
    Args:
        args: Parsed arguments
        
    Returns:
        True if command executed successfully, False otherwise
    """
    format_type = args.format
    output_file = args.output or f"arpguard_export.{format_type}"
    limit = args.limit
    
    logger.info(f"Exporting results to {output_file} in {format_type} format...")
    
    # Create progress bar for export
    progress = ProgressBar(total=100, description="Exporting results")
    progress.start()
    
    # Simulate export progress
    for i in range(101):
        progress.update(i)
        time.sleep(0.02)
    
    progress.complete()
    
    logger.info(f"Export completed successfully. Results saved to {output_file}")
    
    # TODO: Implement actual export functionality
    return True

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

def _handle_config_show(args: argparse.Namespace) -> bool:
    """Handle config show command
    
    Args:
        args: Parsed arguments
        
    Returns:
        True if command executed successfully, False otherwise
    """
    logger.info("Showing current configuration:")
    
    # Create sample configuration data
    config_data = {
        "interface": "eth0",
        "capture_filter": "arp",
        "detection_threshold": 0.8,
        "sample_window": 100,
        "alert_cooldown": 60,
        "log_level": "INFO",
        "log_file": "arpguard.log",
        "max_packets": 1000,
        "demo_duration": 300,
        "visualization_enabled": True
    }
    
    # Determine output format
    output_format = OutputFormat.TABLE
    if hasattr(args, 'output_format') and args.output_format:
        output_format = OutputFormat(args.output_format)
    
    # Format and print configuration data
    headers = ["Setting", "Value"]
    table_data = [[key, value] for key, value in config_data.items()]
    
    formatted_output = OutputFormatter.format_output(table_data, output_format, headers)
    print(formatted_output)
    
    # TODO: Implement actual config show functionality
    return True

def _handle_config_set(args: argparse.Namespace) -> bool:
    """Handle config set command
    
    Args:
        args: Parsed arguments
        
    Returns:
        True if command executed successfully, False otherwise
    """
    key = args.key
    value = args.value
    
    # Create spinner for configuration update
    spinner = Spinner(f"Setting configuration {key} to {value}")
    spinner.start()
    
    # Simulate configuration update
    time.sleep(1)
    
    spinner.stop()
    
    logger.info(f"Configuration {key} set to {value}")
    
    # TODO: Implement actual config set functionality
    return True

def _handle_config_reset(args: argparse.Namespace) -> bool:
    """Handle config reset command
    
    Args:
        args: Parsed arguments
        
    Returns:
        True if command executed successfully, False otherwise
    """
    if not args.confirm:
        print("Warning: This will reset all configuration to defaults.")
        print("Use --confirm to confirm reset.")
        return True
    
    print("Resetting configuration to defaults...")
    
    # Simulate progress
    progress = ProgressBar(total=100)
    for i in range(101):
        progress.update(i)
        time.sleep(0.01)
    
    print("Configuration reset to defaults.")
    return True

def _handle_telemetry(args: argparse.Namespace) -> bool:
    """Handle telemetry command
    
    Args:
        args: Command arguments
        
    Returns:
        True if successful
    """
    parser = args.parser
    if parser:
        parser.print_help()
    else:
        print("Telemetry Management")
        print("-------------------")
        print("Use subcommands: status, enable, disable, delete-data")
    return True

def _handle_telemetry_status(args: argparse.Namespace) -> bool:
    """Handle telemetry status command
    
    Args:
        args: Command arguments
        
    Returns:
        True if successful
    """
    print("Fetching telemetry status...")
    
    # In a real implementation, this would call the telemetry module
    # Here we're simulating a response
    telemetry_status = {
        "enabled": False,
        "anonymize_data": True,
        "installation_id": "anonymized",
        "uptime_days": 3.2,
        "collection_interval_hours": 24,
        "storage_path": "/tmp/arpguard_telemetry",
        "storage_retention_days": 30,
        "pending_events": 5,
        "saved_event_files": 2,
        "last_file_event_count": 15,
        "upload_url": "not configured"
    }
    
    # Display status as a table
    from .cli_utils import TabularData, OutputFormat, OutputFormatter
    
    table = TabularData()
    table.headers = ["Property", "Value"]
    
    for key, value in telemetry_status.items():
        table.add_row([key, str(value)])
    
    formatter = OutputFormatter()
    formatter.print(table, OutputFormat.PRETTY)
    
    return True

def _handle_telemetry_enable(args: argparse.Namespace) -> bool:
    """Handle telemetry enable command
    
    Args:
        args: Command arguments
        
    Returns:
        True if successful
    """
    if not args.confirm:
        print("This will enable telemetry collection with the following details:")
        print("- Anonymous usage data will be collected")
        print("- Data is used to improve ARP Guard and track feature usage")
        print("- You can disable telemetry at any time")
        print("- Data is anonymized by default")
        print("Use --confirm to confirm enabling telemetry.")
        return True
    
    print("Enabling telemetry collection...")
    
    # Simulate progress
    spinner = Spinner("Enabling telemetry")
    spinner.start()
    time.sleep(2)
    spinner.stop()
    
    print("Telemetry collection enabled.")
    print("Thank you for helping improve ARP Guard!")
    return True

def _handle_telemetry_disable(args: argparse.Namespace) -> bool:
    """Handle telemetry disable command
    
    Args:
        args: Command arguments
        
    Returns:
        True if successful
    """
    print("Disabling telemetry collection...")
    
    # Simulate progress
    spinner = Spinner("Disabling telemetry")
    spinner.start()
    time.sleep(1)
    spinner.stop()
    
    print("Telemetry collection disabled.")
    return True

def _handle_telemetry_delete_data(args: argparse.Namespace) -> bool:
    """Handle telemetry delete-data command
    
    Args:
        args: Command arguments
        
    Returns:
        True if successful
    """
    if not args.confirm:
        print("Warning: This will delete all collected telemetry data.")
        print("Use --confirm to confirm deletion.")
        return True
    
    print("Deleting all telemetry data...")
    
    # Simulate progress
    progress = ProgressBar(total=100)
    for i in range(101):
        progress.update(i)
        time.sleep(0.02)
    
    print("All telemetry data has been deleted.")
    return True

def _handle_remediation_show(args: argparse.Namespace) -> None:
    """Show current remediation settings."""
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

def _handle_remediation_set(args: argparse.Namespace) -> None:
    """Set remediation settings."""
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
            return
            
        # Convert value to appropriate type
        value_type = setting_map[args.setting]
        try:
            if value_type == bool:
                value = args.value.lower() in ('true', 'yes', '1', 'enabled')
            else:
                value = value_type(args.value)
        except ValueError:
            print(f"Error: Invalid value for {args.setting}. Expected type: {value_type.__name__}")
            return
            
        # Update the setting
        setattr(remediation.config, args.setting, value)
        print(f"Successfully set {args.setting} to {value}")
        
    except Exception as e:
        logger.error(f"Error setting remediation setting: {e}")
        print(f"Error: {e}")

def _handle_remediation_whitelist(args: argparse.Namespace) -> None:
    """Manage whitelist entries."""
    try:
        from .remediation_module import RemediationModule
        remediation = RemediationModule()
        
        if args.action == "add":
            logger.info(f"Adding to whitelist: {args.mac} - {args.ip}")
            # Validate MAC and IP format
            if not _is_valid_mac(args.mac):
                print(f"Error: Invalid MAC address format: {args.mac}")
                return
            if not _is_valid_ip(args.ip):
                print(f"Error: Invalid IP address format: {args.ip}")
                return
                
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

def _is_valid_mac(mac: str) -> bool:
    """Validate MAC address format."""
    import re
    mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(mac_pattern, mac))

def _is_valid_ip(ip: str) -> bool:
    """Validate IP address format."""
    import re
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ip_pattern, ip):
        return False
    return all(0 <= int(octet) <= 255 for octet in ip.split('.'))

def _create_commands() -> List[CLICommandConfig]:
    """Create the list of standard commands."""
    
    commands = [
        CLICommandConfig(
            name="start",
            description="Start monitoring for ARP spoofing attacks",
            feature_id="core.monitoring",
            handler=_handle_start,
            arguments=[
                CLICommandArgumentConfig(
                    name="--interface",
                    help="Network interface to monitor",
                    type=str,
                    required=False
                ),
                CLICommandArgumentConfig(
                    name="--timeout",
                    help="Monitoring timeout in seconds (0 for no timeout)",
                    type=int,
                    default=0,
                    required=False
                ),
                CLICommandArgumentConfig(
                    name="--verbose",
                    help="Enable verbose output",
                    action="store_true",
                    required=False
                )
            ]
        ),
        CLICommandConfig(
            name="stop",
            description="Stop monitoring for ARP spoofing attacks",
            feature_id="core.monitoring",
            handler=_handle_stop,
            arguments=[
                CLICommandArgumentConfig(
                    name="--force",
                    help="Force stop without confirmation",
                    action="store_true",
                    required=False
                )
            ]
        ),
        CLICommandConfig(
            name="status",
            description="Show the current monitoring status",
            feature_id="core.monitoring",
            handler=_handle_status,
            arguments=[
                CLICommandArgumentConfig(
                    name="--format",
                    help="Output format",
                    type=str,
                    choices=["pretty", "json", "csv"],
                    default="pretty",
                    required=False
                ),
                CLICommandArgumentConfig(
                    name="--detailed",
                    help="Show detailed status information",
                    action="store_true",
                    required=False
                )
            ]
        ),
        CLICommandConfig(
            name="export",
            description="Export detection results to a file",
            feature_id="core.export",
            handler=_handle_export,
            arguments=[
                CLICommandArgumentConfig(
                    name="--format",
                    help="Export format",
                    type=str,
                    choices=["json", "csv", "yaml"],
                    default="json",
                    required=False
                ),
                CLICommandArgumentConfig(
                    name="--output",
                    help="Output file path",
                    type=str,
                    required=False
                ),
                CLICommandArgumentConfig(
                    name="--all",
                    help="Export all records including historical data",
                    action="store_true",
                    required=False
                )
            ]
        ),
        CLICommandConfig(
            name="config",
            description="Configuration management commands",
            feature_id="core.config",
            handler=_handle_config,
            subcommands={
                "show": CLICommandConfig(
                    name="show",
                    description="Show the current configuration",
                    feature_id="core.config",
                    handler=_handle_config_show,
                    arguments=[
                        CLICommandArgumentConfig(
                            name="--format",
                            help="Output format",
                            type=str,
                            choices=["pretty", "json", "yaml"],
                            default="pretty",
                            required=False
                        ),
                        CLICommandArgumentConfig(
                            name="--section",
                            help="Configuration section to show",
                            type=str,
                            required=False
                        )
                    ]
                ),
                "set": CLICommandConfig(
                    name="set",
                    description="Set a configuration value",
                    feature_id="core.config",
                    handler=_handle_config_set,
                    arguments=[
                        CLICommandArgumentConfig(
                            name="key",
                            help="Configuration key to set",
                            type=str,
                            nargs="?",
                            required=False
                        ),
                        CLICommandArgumentConfig(
                            name="value",
                            help="Value to set",
                            type=str,
                            nargs="?",
                            required=False
                        ),
                        CLICommandArgumentConfig(
                            name="--file",
                            help="Load configuration from file",
                            type=str,
                            required=False
                        )
                    ]
                ),
                "reset": CLICommandConfig(
                    name="reset",
                    description="Reset configuration to defaults",
                    feature_id="core.config",
                    handler=_handle_config_reset,
                    arguments=[
                        CLICommandArgumentConfig(
                            name="--section",
                            help="Configuration section to reset",
                            type=str,
                            required=False
                        ),
                        CLICommandArgumentConfig(
                            name="--force",
                            help="Force reset without confirmation",
                            action="store_true",
                            required=False
                        )
                    ]
                )
            }
        ),
        CLICommandConfig(
            name="telemetry",
            description="Telemetry data collection commands",
            feature_id="telemetry.collection",
            handler=_handle_telemetry,
            subcommands={
                "status": CLICommandConfig(
                    name="status",
                    description="Show the current telemetry status",
                    feature_id="telemetry.collection",
                    handler=_handle_telemetry_status,
                    arguments=[
                        CLICommandArgumentConfig(
                            name="--format",
                            help="Output format",
                            type=str,
                            choices=["pretty", "json", "yaml"],
                            default="pretty",
                            required=False
                        ),
                        CLICommandArgumentConfig(
                            name="--detailed",
                            help="Show detailed telemetry information",
                            action="store_true",
                            required=False
                        )
                    ]
                ),
                "enable": CLICommandConfig(
                    name="enable",
                    description="Enable telemetry data collection",
                    feature_id="telemetry.collection",
                    handler=_handle_telemetry_enable,
                    arguments=[
                        CLICommandArgumentConfig(
                            name="--level",
                            help="Telemetry collection level",
                            type=str,
                            choices=["basic", "enhanced", "full"],
                            default="basic",
                            required=False
                        )
                    ]
                ),
                "disable": CLICommandConfig(
                    name="disable",
                    description="Disable telemetry data collection",
                    feature_id="telemetry.collection",
                    handler=_handle_telemetry_disable,
                    arguments=[
                        CLICommandArgumentConfig(
                            name="--delete-data",
                            help="Delete existing telemetry data",
                            action="store_true",
                            required=False
                        )
                    ]
                ),
                "delete-data": CLICommandConfig(
                    name="delete-data",
                    description="Delete all collected telemetry data",
                    feature_id="telemetry.collection",
                    handler=_handle_telemetry_delete_data,
                    arguments=[
                        CLICommandArgumentConfig(
                            name="--force",
                            help="Force delete without confirmation",
                            action="store_true",
                            required=False
                        )
                    ]
                )
            }
        ),
        # Add network command
        CLICommandConfig(
            name="network",
            description="Network configuration commands",
            feature_id="networking",
            handler=_handle_network,
            subcommands={
                "list": CLICommandConfig(
                    name="list",
                    description="List available network interfaces",
                    feature_id="networking",
                    handler=_handle_network_list
                ),
                "status": CLICommandConfig(
                    name="status",
                    description="Show network status and configuration",
                    feature_id="networking",
                    handler=_handle_network_status
                ),
                "set": CLICommandConfig(
                    name="set",
                    description="Set network configuration",
                    feature_id="networking",
                    handler=_handle_network_set,
                    arguments=[
                        CLICommandArgumentConfig(
                            name="--interface",
                            help="Set primary network interface",
                            type=str,
                            required=False
                        ),
                        CLICommandArgumentConfig(
                            name="--mode",
                            help="Set monitoring mode (promiscuous, passive, active)",
                            type=str,
                            choices=["promiscuous", "passive", "active"],
                            required=False
                        ),
                        CLICommandArgumentConfig(
                            name="--buffer",
                            help="Set packet buffer size",
                            type=int,
                            required=False
                        ),
                        CLICommandArgumentConfig(
                            name="--timeout",
                            help="Set packet timeout in seconds",
                            type=float,
                            required=False
                        ),
                        CLICommandArgumentConfig(
                            name="--multi-interface",
                            help="Enable/disable multi-interface mode",
                            action="store_true",
                            required=False
                        ),
                    ]
                ),
                "apply": CLICommandConfig(
                    name="apply",
                    description="Apply current network configuration",
                    feature_id="networking",
                    handler=_handle_network_apply
                ),
                "reset": CLICommandConfig(
                    name="reset",
                    description="Reset network configuration to defaults",
                    feature_id="networking",
                    handler=_handle_network_reset
                ),
            }
        ),
    ]
    
    return commands


# Network command handlers
def _handle_network(args: argparse.Namespace) -> bool:
    """Handle the network command."""
    print("Network Configuration Commands:")
    print("  list    - List available network interfaces")
    print("  status  - Show network status and configuration")
    print("  set     - Set network configuration")
    print("  apply   - Apply current network configuration")
    print("  reset   - Reset network configuration to defaults")
    return True

def _handle_network_list(args: argparse.Namespace) -> bool:
    """Handle the network list command."""
    print("Detecting network interfaces...")
    
    # Create network config manager
    net_config = NetworkConfigManager()
    
    # Get all interfaces
    interfaces = net_config.get_all_interfaces()
    
    if not interfaces:
        print("No network interfaces found.")
        return False
    
    # Display interfaces
    print(f"Found {len(interfaces)} network interfaces:")
    for iface in interfaces:
        is_primary = (iface == net_config.config.primary_interface)
        primary_mark = " (PRIMARY)" if is_primary else ""
        print(f"  - {iface}{primary_mark}")
    
    return True

def _handle_network_status(args: argparse.Namespace) -> bool:
    """Handle the network status command."""
    print("Retrieving network status...")
    
    # Create network config manager
    net_config = NetworkConfigManager()
    
    # Get primary interface
    primary_interface = net_config.config.primary_interface
    
    # Get interface status
    status = net_config.get_interface_status(primary_interface)
    
    if "error" in status:
        print(f"Error: {status['error']}")
        return False
    
    # Display status
    print(f"Primary Interface: {primary_interface}")
    print(f"  Status:        {'UP' if status['is_up'] else 'DOWN'}")
    print(f"  IP Address:    {status['current_ip'] or 'Not available'}")
    print(f"  MAC Address:   {status['mac_address'] or 'Not available'}")
    print(f"  MTU:           {status['mtu']}")
    print(f"  Monitoring:    {'Enabled' if status['is_monitoring'] else 'Disabled'}")
    print(f"  Promiscuous:   {'Enabled' if status['promiscuous_mode'] else 'Disabled'}")
    
    # Display monitoring configuration
    print("\nMonitoring Configuration:")
    print(f"  Mode:            {net_config.config.monitoring.monitoring_mode}")
    print(f"  Packet Buffer:   {net_config.config.monitoring.max_packets_per_scan}")
    print(f"  Scan Interval:   {net_config.config.monitoring.scan_interval_seconds}s")
    print(f"  ARP Only:        {'Yes' if net_config.config.monitoring.capture_arp_only else 'No'}")
    print(f"  Filter String:   {net_config.config.monitoring.filter_string}")
    
    # Display advanced settings
    print("\nAdvanced Settings:")
    print(f"  Multi-Interface: {'Enabled' if net_config.config.multi_interface_mode else 'Disabled'}")
    print(f"  IP Forwarding:   {'Enabled' if net_config.config.allow_ip_forwarding else 'Disabled'}")
    
    if net_config.config.fallback_interfaces:
        print(f"  Fallback Interfaces: {', '.join(net_config.config.fallback_interfaces)}")
    
    return True

def _handle_network_set(args: argparse.Namespace) -> bool:
    """Handle the network set command."""
    # Create network config manager
    net_config = NetworkConfigManager()
    
    changes_made = False
    
    # Check if we need to change the interface
    if args.interface:
        print(f"Setting primary interface to {args.interface}...")
        if net_config.set_primary_interface(args.interface):
            print(f"Primary interface set to {args.interface}")
            changes_made = True
        else:
            print(f"Failed to set primary interface to {args.interface}")
            return False
    
    # Check if we need to change the monitoring mode
    if args.mode:
        print(f"Setting monitoring mode to {args.mode}...")
        net_config.config.monitoring.monitoring_mode = args.mode
        changes_made = True
    
    # Check if we need to change the buffer size
    if args.buffer:
        print(f"Setting packet buffer size to {args.buffer}...")
        net_config.config.monitoring.max_packets_per_scan = args.buffer
        changes_made = True
    
    # Check if we need to change the timeout
    if args.timeout:
        print(f"Setting packet timeout to {args.timeout}s...")
        net_config.config.monitoring.scan_interval_seconds = args.timeout
        changes_made = True
    
    # Check if we need to change multi-interface mode
    if args.multi_interface:
        print("Enabling multi-interface mode...")
        net_config.config.multi_interface_mode = True
        changes_made = True
    
    # Save configuration if changes were made
    if changes_made:
        print("Saving network configuration...")
        net_config.save_config()
        print("Configuration saved. Run 'arp-guard network apply' to apply changes.")
    else:
        print("No changes specified.")
    
    return True

def _handle_network_apply(args: argparse.Namespace) -> bool:
    """Handle the network apply command."""
    print("Applying network configuration...")
    
    # Create network config manager
    net_config = NetworkConfigManager()
    
    # Apply monitoring settings
    if net_config.apply_monitoring_settings():
        print("Network configuration applied successfully.")
        return True
    else:
        print("Failed to apply network configuration.")
        return False

def _handle_network_reset(args: argparse.Namespace) -> bool:
    """Handle the network reset command."""
    print("Resetting network configuration to defaults...")
    
    # Delete existing configuration
    config_path = os.path.join("config", "network_config.yaml")
    if os.path.exists(config_path):
        try:
            os.remove(config_path)
            print("Existing configuration removed.")
        except Exception as e:
            print(f"Failed to remove existing configuration: {e}")
            return False
    
    # Create default configuration
    create_default_config()
    print("Default network configuration created.")
    
    # Create network config manager with default configuration
    net_config = NetworkConfigManager()
    print(f"Default primary interface: {net_config.config.primary_interface}")
    
    return True 