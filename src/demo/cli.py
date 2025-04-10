#!/usr/bin/env python3
import argparse
import logging
import sys
from typing import Optional
from config import DemoConfig, get_preset_config
from logger import DemoLogger
from status import StatusReporter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DemoCLI:
    """Command-line interface for ARP Guard demo"""
    
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="ARP Guard Demo Command Line Interface"
        )
        self.setup_parser()
        self.logger = DemoLogger()
        self.status_reporter = StatusReporter()
    
    def setup_parser(self):
        """Setup command line argument parser"""
        subparsers = self.parser.add_subparsers(dest="command", help="Commands")
        
        # Start command
        start_parser = subparsers.add_parser("start", help="Start the demo")
        start_parser.add_argument(
            "--preset", "-p",
            choices=["basic", "advanced", "performance"],
            help="Use a preset configuration"
        )
        start_parser.add_argument(
            "--duration", "-d",
            type=int,
            help="Demo duration in seconds"
        )
        start_parser.add_argument(
            "--interface", "-i",
            help="Network interface to monitor"
        )
        
        # Stop command
        subparsers.add_parser("stop", help="Stop the demo")
        
        # Status command
        subparsers.add_parser("status", help="Show demo status")
        
        # Config command
        config_parser = subparsers.add_parser("config", help="Manage configuration")
        config_parser.add_argument(
            "action",
            choices=["show", "set", "reset"],
            help="Configuration action"
        )
        config_parser.add_argument(
            "--key", "-k",
            help="Configuration key to set"
        )
        config_parser.add_argument(
            "--value", "-v",
            help="Configuration value to set"
        )
        
        # Logs command
        logs_parser = subparsers.add_parser("logs", help="Manage logs")
        logs_parser.add_argument(
            "action",
            choices=["show", "clear", "rotate"],
            help="Log action"
        )
        logs_parser.add_argument(
            "--level", "-l",
            choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            help="Log level to show"
        )
    
    def start_demo(self, args) -> bool:
        """Start the demo with given configuration"""
        try:
            config = None
            if args.preset:
                config = get_preset_config(args.preset)
                if not config:
                    self.logger.error(f"Invalid preset configuration: {args.preset}")
                    return False
            else:
                config = DemoConfig()
            
            if args.duration:
                config.demo_duration = args.duration
            if args.interface:
                config.interface = args.interface
            
            self.logger.info(f"Starting demo with configuration: {config}")
            self.status_reporter.reset_metrics()
            self.logger.log_demo_event("demo_start", {"config": config.__dict__})
            # TODO: Implement actual demo start
            return True
        except Exception as e:
            self.logger.error(f"Failed to start demo: {e}")
            return False
    
    def stop_demo(self) -> bool:
        """Stop the running demo"""
        try:
            self.logger.info("Stopping demo...")
            self.logger.log_demo_event("demo_stop", {})
            self.status_reporter.save_metrics()
            # TODO: Implement actual demo stop
            return True
        except Exception as e:
            self.logger.error(f"Failed to stop demo: {e}")
            return False
    
    def show_status(self) -> bool:
        """Show current demo status"""
        try:
            status = self.status_reporter.format_status()
            self.logger.info(status)
            return True
        except Exception as e:
            self.logger.error(f"Failed to get status: {e}")
            return False
    
    def manage_config(self, args) -> bool:
        """Manage demo configuration"""
        try:
            if args.action == "show":
                config = DemoConfig.from_file("config/demo_config.json")
                self.logger.info("Current configuration:")
                for key, value in config.__dict__.items():
                    self.logger.info(f"{key}: {value}")
            elif args.action == "set":
                if not args.key or not args.value:
                    self.logger.error("Both --key and --value are required for set action")
                    return False
                config = DemoConfig.from_file("config/demo_config.json")
                if hasattr(config, args.key):
                    setattr(config, args.key, args.value)
                    config.to_file("config/demo_config.json")
                    self.logger.info(f"Set {args.key} to {args.value}")
                else:
                    self.logger.error(f"Invalid configuration key: {args.key}")
                    return False
            elif args.action == "reset":
                config = DemoConfig()
                config.to_file("config/demo_config.json")
                self.logger.info("Configuration reset to defaults")
            return True
        except Exception as e:
            self.logger.error(f"Failed to manage configuration: {e}")
            return False
    
    def manage_logs(self, args) -> bool:
        """Manage demo logs"""
        try:
            if args.action == "show":
                log_level = getattr(logging, args.level) if args.level else logging.INFO
                self.logger.logger.setLevel(log_level)
                self.logger.info("Showing logs...")
                # TODO: Implement log display
            elif args.action == "clear":
                self.logger.info("Clearing logs...")
                self.logger.rotate_logs()
            elif args.action == "rotate":
                self.logger.info("Rotating logs...")
                self.logger.rotate_logs()
            return True
        except Exception as e:
            self.logger.error(f"Failed to manage logs: {e}")
            return False
    
    def run(self) -> bool:
        """Run the CLI"""
        args = self.parser.parse_args()
        
        if not args.command:
            self.parser.print_help()
            return False
        
        if args.command == "start":
            return self.start_demo(args)
        elif args.command == "stop":
            return self.stop_demo()
        elif args.command == "status":
            return self.show_status()
        elif args.command == "config":
            return self.manage_config(args)
        elif args.command == "logs":
            return self.manage_logs(args)
        
        return False

if __name__ == "__main__":
    cli = DemoCLI()
    success = cli.run()
    sys.exit(0 if success else 1) 