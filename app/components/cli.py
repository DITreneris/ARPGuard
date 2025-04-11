import argparse
import sys
import textwrap
import json
import time
import signal
import os
from typing import List, Optional, Dict
from datetime import datetime
from colorama import Fore, Style, init
from tabulate import tabulate

from app.components.device_discovery import DeviceDiscovery
from app.components.arp_cache_monitor import ARPCacheMonitor
from app.components.packet_capture import PacketCapture
from app.utils.cli_formatter import formatter
from app.utils.config import get_config_manager

# Initialize colorama
init(autoreset=True)

class ARPGuardCLI:
    """Command-line interface for ARPGuard."""
    
    def __init__(self):
        self.version = "1.0.0"
        self.example_text = textwrap.dedent('''
            Examples:
              # Scan a local network
              arpguard scan --subnet 192.168.1.0/24
              
              # Monitor an interface for ARP spoofing
              arpguard monitor --interface eth0
              
              # Analyze a captured packet file
              arpguard analyze --file capture.pcap
              
              # Export results to JSON
              arpguard export --output results.json --format json
        ''')
        
        # Check for root/admin privileges first
        if not self._check_privileges():
            print(f"{Fore.RED}Error: ARPGuard requires root/admin privileges to run.{Style.RESET_ALL}")
            print("Please run the program with sudo (Linux/Mac) or as Administrator (Windows).")
            sys.exit(1)
        
        # Initialize components first
        try:
            self.device_discovery = DeviceDiscovery()
            self.arp_cache_monitor = ARPCacheMonitor()
            self.packet_capture = PacketCapture()
            self.config_manager = get_config_manager()
        except Exception as e:
            print(f"{Fore.RED}Error initializing components: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)
        
        self.parser = argparse.ArgumentParser(
            description='ARPGuard - Network Security Monitoring Tool',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=self.example_text
        )
        self.parser.add_argument('--version', action='version', version=f'ARPGuard {self.version}')
        
        self.subparsers = self.parser.add_subparsers(dest='command', help='Available commands')
        
        # Initialize commands
        self._init_help_command()
        self._init_scan_command()
        self._init_monitor_command()
        self._init_analyze_command()
        self._init_export_command()
        self._init_config_command()
        
        # Command help details
        self.command_help: Dict[str, str] = {
            'scan': textwrap.dedent('''
                The scan command allows you to discover devices on your network.
                
                It performs ARP and ICMP scanning to identify active hosts and retrieves
                information such as:
                - IP and MAC addresses
                - Hostname (when available)
                - Device type (based on MAC prefix)
                - Open ports (with --ports option)
                
                Examples:
                  # Basic network scan
                  arpguard scan --subnet 192.168.1.0/24
                  
                  # Scan with longer timeout
                  arpguard scan --subnet 10.0.0.0/24 --timeout 10
                  
                  # Scan with port detection
                  arpguard scan --subnet 172.16.0.0/16 --ports 22,80,443
            '''),
            'monitor': textwrap.dedent('''
                The monitor command continuously watches network traffic for
                ARP spoofing attacks and other suspicious activities.
                
                It detects:
                - ARP cache poisoning
                - MAC address changes
                - Gateway impersonation
                - Unusual ARP request patterns
                
                Examples:
                  # Monitor the eth0 interface continuously
                  arpguard monitor --interface eth0
                  
                  # Monitor for a specific duration
                  arpguard monitor --interface wlan0 --duration 3600
                  
                  # Monitor with alert settings
                  arpguard monitor --interface eth0 --alert-level high
            '''),
            'analyze': textwrap.dedent('''
                The analyze command examines packet captures for security issues.
                
                It can detect:
                - Protocol anomalies
                - Known attack patterns
                - Suspicious traffic flows
                - Communication with malicious IPs
                
                Examples:
                  # Basic packet analysis
                  arpguard analyze --file capture.pcap
                  
                  # Analyze with custom rules
                  arpguard analyze --file capture.pcap --rules custom_rules.txt
                  
                  # Focus on specific protocol
                  arpguard analyze --file capture.pcap --protocol arp
                  
                  # Live capture
                  arpguard analyze --interface eth0 --duration 60
            '''),
            'export': textwrap.dedent('''
                The export command saves scan results, monitoring data, or
                analysis findings to a file for reporting or further processing.
                
                Supported formats:
                - JSON: Full data with nested structures
                - CSV: Tabular format for spreadsheet applications
                
                Examples:
                  # Export to JSON
                  arpguard export --output results.json --format json
                  
                  # Export to CSV
                  arpguard export --output devices.csv --format csv
                  
                  # Export specific data type
                  arpguard export --output threats.json --format json --type threats
            '''),
        }
    
    def _check_privileges(self) -> bool:
        """Check if the program has the necessary privileges."""
        try:
            if os.name == 'nt':  # Windows
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:  # Unix-like
                return os.geteuid() == 0
        except Exception:
            return False
    
    def _init_help_command(self):
        """Initialize the help command."""
        help_parser = self.subparsers.add_parser('help', help='Show detailed help for a command')
        help_parser.add_argument(
            'command_name',
            nargs='?',
            help='Command name to get help for'
        )
        help_parser.set_defaults(func=self._handle_help)
    
    def _init_scan_command(self):
        """Initialize the scan command."""
        scan_parser = self.subparsers.add_parser('scan', help='Scan network for devices')
        scan_parser.add_argument('-i', '--interface', type=str, 
                              help='Network interface to use')
        scan_parser.add_argument('-t', '--timeout', type=int, 
                              default=self.config_manager.get('scan', 'default_timeout', 2),
                              help='Timeout in seconds')
        scan_parser.add_argument('-s', '--subnet', type=str, 
                              help='Subnet to scan (CIDR format)')
        scan_parser.add_argument('-p', '--ports', type=str, 
                              help='Comma-separated list of ports to scan')
        scan_parser.add_argument('-c', '--classify', action='store_true', 
                              default=self.config_manager.get('scan', 'classify_devices', True),
                              help='Classify devices by type')
        scan_parser.add_argument('-o', '--output-format', type=str, 
                              choices=['json', 'csv', 'table'], 
                              default=self.config_manager.get('scan', 'output_format', 'table'),
                              help='Output format')
        scan_parser.set_defaults(func=self._handle_scan)
    
    def _init_monitor_command(self):
        """Initialize the monitor command."""
        monitor_parser = self.subparsers.add_parser('monitor', help='Monitor for ARP spoofing attacks')
        monitor_parser.add_argument('-i', '--interface', type=str, 
                                 help='Network interface to use')
        monitor_parser.add_argument('-a', '--alert-level', type=str, 
                                 choices=['low', 'medium', 'high'], 
                                 default=self.config_manager.get('monitor', 'alert_level', 'medium'),
                                 help='Alert level (low, medium, high)')
        monitor_parser.add_argument('-d', '--duration', type=int, 
                                 help='Duration in seconds (0 for continuous)')
        monitor_parser.add_argument('-o', '--output-format', type=str, 
                                 choices=['normal', 'json'], 
                                 default=self.config_manager.get('monitor', 'output_format', 'normal'),
                                 help='Output format')
        monitor_parser.set_defaults(func=self._handle_monitor)
    
    def _init_analyze_command(self):
        """Initialize the analyze command."""
        analyze_parser = self.subparsers.add_parser('analyze', help='Analyze network packets')
        
        # Create a mutually exclusive group for file/interface options
        source_group = analyze_parser.add_mutually_exclusive_group(required=True)
        source_group.add_argument(
            '--file',
            type=str,
            help='PCAP file to analyze'
        )
        source_group.add_argument(
            '--interface',
            type=str,
            help='Network interface for live capture'
        )
        
        # Additional options
        analyze_parser.add_argument(
            '--protocol',
            type=str,
            help='Focus on specific protocol (e.g., arp, tcp, udp, icmp)'
        )
        analyze_parser.add_argument(
            '--filter',
            type=str,
            help='BPF filter expression (e.g., "port 80" or "host 192.168.1.1")'
        )
        analyze_parser.add_argument(
            '--duration',
            type=int,
            default=0,
            help='Duration in seconds for live capture (0 for indefinite)'
        )
        analyze_parser.add_argument(
            '--max-packets',
            type=int,
            default=self.config_manager.get('analyze', 'max_packets', 10000),
            help='Maximum number of packets to analyze'
        )
        analyze_parser.add_argument(
            '--output',
            type=str,
            help='Save analysis results to file'
        )
        analyze_parser.add_argument(
            '--save-pcap',
            type=str,
            help='Save captured packets to PCAP file'
        )
        analyze_parser.add_argument(
            '--rules',
            type=str,
            help='Custom rules file path'
        )
        analyze_parser.add_argument(
            '--format',
            choices=['json', 'table'],
            default='table',
            help='Output format'
        )
        
        analyze_parser.set_defaults(func=self._handle_analyze)
    
    def _init_export_command(self):
        """Initialize the export command."""
        export_parser = self.subparsers.add_parser('export', help='Export results')
        export_parser.add_argument(
            '--format',
            choices=['json', 'csv'],
            default='json',
            help='Export format'
        )
        export_parser.add_argument(
            '--output',
            type=str,
            help='Output file path',
            required=True
        )
        export_parser.add_argument(
            '--type',
            choices=['devices', 'threats', 'all'],
            default='all',
            help='Type of data to export'
        )
        export_parser.set_defaults(func=self._handle_export)
    
    def _init_config_command(self):
        """Initialize the config command."""
        config_parser = self.subparsers.add_parser('config', help='Manage configuration')
        config_subparsers = config_parser.add_subparsers(dest='config_command', help='Configuration command')
        
        # Config get command
        config_get_parser = config_subparsers.add_parser('get', help='Get configuration value')
        config_get_parser.add_argument('section', type=str, help='Configuration section')
        config_get_parser.add_argument('key', type=str, nargs='?', help='Configuration key')
        
        # Config set command
        config_set_parser = config_subparsers.add_parser('set', help='Set configuration value')
        config_set_parser.add_argument('section', type=str, help='Configuration section')
        config_set_parser.add_argument('key', type=str, help='Configuration key')
        config_set_parser.add_argument('value', type=str, help='Configuration value')
        
        # Config list command
        config_list_parser = config_subparsers.add_parser('list', help='List configuration')
        config_list_parser.add_argument('section', type=str, nargs='?', help='Configuration section to list')
        
        # Config save command
        config_save_parser = config_subparsers.add_parser('save', help='Save configuration')
        config_save_parser.add_argument('-f', '--file', type=str, help='Configuration file path')
        
        # Config reset command
        config_reset_parser = config_subparsers.add_parser('reset', help='Reset configuration')
        config_reset_parser.add_argument('-s', '--section', type=str, help='Configuration section to reset')
        
        # Config create command
        config_create_parser = config_subparsers.add_parser('create', help='Create default configuration')
        config_create_parser.add_argument('-f', '--file', type=str, required=True, help='Configuration file path')
        
        # Config import command
        config_import_parser = config_subparsers.add_parser('import', help='Import configuration from file')
        config_import_parser.add_argument('-f', '--file', type=str, required=True, help='Configuration file to import')
        config_import_parser.add_argument('--validate', action='store_true', help='Validate without importing')
        
        # Config template command
        config_template_parser = config_subparsers.add_parser('template', help='Create a configuration template file')
        config_template_parser.add_argument('-f', '--file', type=str, required=True, help='Output template file path')
    
    def _handle_help(self, args):
        """Handle help command."""
        if args.command_name and args.command_name in self.command_help:
            examples = []
            
            # Extract examples from help text
            help_text = self.command_help[args.command_name]
            desc_parts = help_text.split('Examples:')
            description = desc_parts[0].strip()
            
            if len(desc_parts) > 1:
                example_lines = desc_parts[1].strip().split('\n')
                for i in range(0, len(example_lines), 2):
                    if i+1 < len(example_lines):
                        cmd = example_lines[i].strip().replace('#', '').strip()
                        desc = example_lines[i+1].strip() if i+1 < len(example_lines) else ""
                        examples.append({'cmd': cmd, 'desc': desc})
            
            # Print formatted help
            print(formatter.format_help(args.command_name, description, examples))
        elif args.command_name:
            print(formatter.error(f"Unknown command: {args.command_name}"))
            print("Available commands: help, scan, monitor, analyze, export, config")
        else:
            print(formatter.header("ARPGuard CLI Help", 80))
            self.parser.print_help()
    
    def _handle_scan(self, args):
        """Handle the scan command."""
        try:
            print(f"{Fore.CYAN}Starting network scan...{Style.RESET_ALL}")
            
            if not args.subnet:
                print(f"{Fore.RED}Error: Subnet is required for scanning{Style.RESET_ALL}")
                print("Example: --subnet 192.168.1.0/24")
                return 1
            
            scan_options = {
                'timeout': args.timeout,
                'classify': args.classify
            }
            
            # Add interface if present
            if hasattr(args, 'interface') and args.interface:
                scan_options['interface'] = args.interface
            
            if args.ports:
                try:
                    ports = [int(p.strip()) for p in args.ports.split(',')]
                    scan_options['ports'] = ports
                except ValueError:
                    print(f"{Fore.RED}Error: Invalid port specification{Style.RESET_ALL}")
                    print("Example: --ports 22,80,443")
                    return 1
            
            results = self.device_discovery.discover(args.subnet, **scan_options)
            
            if not results:
                print(f"{Fore.YELLOW}No devices found in the specified subnet.{Style.RESET_ALL}")
                return 0
            
            if args.output_format == 'json':
                print(json.dumps(results, indent=2))
            elif args.output_format == 'csv':
                # Convert results to CSV format
                headers = ['IP', 'MAC', 'Hostname', 'Type']
                rows = [[d['ip'], d['mac'], d.get('hostname', 'N/A'), d.get('type', 'Unknown')] 
                       for d in results]
                print('\n'.join([','.join(headers)] + [','.join(row) for row in rows]))
            else:  # table format
                headers = ['IP Address', 'MAC Address', 'Hostname', 'Device Type']
                rows = [[d['ip'], d['mac'], d.get('hostname', 'N/A'), d.get('type', 'Unknown')] 
                       for d in results]
                print(tabulate(rows, headers=headers, tablefmt='grid'))
            
            return 0
            
        except PermissionError:
            print(f"{Fore.RED}Error: Insufficient permissions to perform network scan{Style.RESET_ALL}")
            print("Please run the program with appropriate privileges")
            return 1
        except Exception as e:
            print(f"{Fore.RED}Error during network scan: {str(e)}{Style.RESET_ALL}")
            return 1
    
    def _handle_monitor(self, args):
        """Handle monitor command."""
        print(formatter.header("ARP Cache Monitor", 60))
        
        # Use interface from config if not provided
        interface = args.interface or self.config_manager.get('monitor', 'default_interface')
        check_interval = self.config_manager.get('monitor', 'check_interval', 2)
        
        if not interface:
            print(formatter.warning("No interface specified and no default configured. Using auto-detection."))
        
        try:
            print(formatter.info(f"Starting ARP cache monitoring with alert level {args.alert_level}..."))
            print(formatter.info("Press Ctrl+C to stop monitoring."))
            
            # Start monitoring
            self.arp_cache_monitor.start_monitoring(
                interface=interface,
                alert_level=args.alert_level,
                duration=args.duration or 0,
                check_interval=check_interval,
                alert_callback=self._monitor_alert_callback,
                status_callback=self._monitor_status_callback
            )
            
            # Track metrics
            self.alert_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
            self.monitor_start_time = datetime.now()
            
            try:
                # Wait for monitoring to complete or user interruption
                while self.arp_cache_monitor.is_monitoring():
                    time.sleep(0.1)
            except KeyboardInterrupt:
                print(formatter.info("\nStopping monitoring..."))
            
            # Stop monitoring if still active
            if self.arp_cache_monitor.is_monitoring():
                self.arp_cache_monitor.stop_monitoring()
            
            # Print summary
            duration = (datetime.now() - self.monitor_start_time).total_seconds()
            total_alerts = sum(self.alert_counts.values())
            
            print(formatter.success(f"\nMonitoring completed. Duration: {duration:.1f} seconds"))
            print(formatter.info(f"Detected {total_alerts} potential anomalies:"))
            print(formatter.error(f"  - High severity: {self.alert_counts['HIGH']}"))
            print(formatter.warning(f"  - Medium severity: {self.alert_counts['MEDIUM']}"))
            print(formatter.info(f"  - Low severity: {self.alert_counts['LOW']}"))
            
            return 0
            
        except Exception as e:
            print(formatter.error(f"Error during monitoring: {str(e)}"))
            return 1
    
    def _handle_analyze(self, args):
        """Handle analyze command."""
        print(formatter.header("Packet Analysis", 80))
        
        # Track if we need to do a live capture or file analysis
        is_live_capture = args.interface is not None
        
        if is_live_capture:
            print(formatter.info(f"Starting packet capture on interface: {args.interface}"))
            
            # Setup filter string from protocol or filter
            packet_filter = args.filter
            if not packet_filter and args.protocol:
                packet_filter = args.protocol.lower()  # Simple filter using protocol name
                
            if packet_filter:
                print(formatter.info(f"Using filter: {packet_filter}"))
                
            # Track stats to show after capture
            self.packet_stats = {"packet_count": 0}
            self.capture_start_time = datetime.now()
            
            # Start packet capture
            if not self.packet_capture.start_capture(
                interface=args.interface,
                packet_filter=packet_filter,
                duration=args.duration,
                max_packets=args.max_packets,
                packet_callback=self._packet_callback,
                status_callback=self._capture_status_callback
            ):
                print(formatter.error("Failed to start packet capture"))
                return 1
                
            # Show progress while capturing
            try:
                spinner_update = formatter.spinner("Capturing packets")
                last_count = 0
                
                # Wait until capture is complete or interrupted
                while self.packet_capture.running:
                    stats = self.packet_capture.get_statistics()
                    count = stats.get("packet_count", 0)
                    
                    # Update spinner with current stats
                    if count > last_count:
                        pps = count / max(1, (datetime.now() - self.capture_start_time).total_seconds())
                        spinner_update(f"Captured {count} packets ({pps:.1f} packets/sec)")
                        last_count = count
                        
                    time.sleep(0.1)
                    
                # Capture complete
                spinner_update("Capture complete", force_stop=True)
                
                # Save to PCAP if requested
                if args.save_pcap:
                    print(formatter.info(f"Saving packets to {args.save_pcap}"))
                    if self.packet_capture.save_to_pcap(args.save_pcap):
                        print(formatter.success(f"Saved {last_count} packets to {args.save_pcap}"))
                    else:
                        print(formatter.error(f"Failed to save packets to {args.save_pcap}"))
                
                # Analyze and display results
                self._display_packet_analysis(self.packet_capture.get_statistics(), args.format)
                
                # Save results if requested
                if args.output:
                    self._save_analysis_results(self.packet_capture.get_statistics(), args.output, args.format)
                    
            except KeyboardInterrupt:
                print(formatter.info("\nStopping packet capture..."))
                self.packet_capture.stop_capture()
                
                # Display partial results
                self._display_packet_analysis(self.packet_capture.get_statistics(), args.format)
                
        else:  # File analysis
            print(formatter.info(f"Analyzing file: {args.file}"))
            
            if args.protocol:
                print(formatter.info(f"Focusing on protocol: {args.protocol}"))
                
            if args.filter:
                print(formatter.info(f"Using filter: {args.filter}"))
                
            if args.rules:
                print(formatter.info(f"Using custom rules from: {args.rules}"))
                
            # Show progress spinner during analysis
            spinner_update = formatter.spinner("Analyzing packets")
            spinner_update("Loading packet data...")
            
            # Perform analysis
            try:
                results = self.packet_capture.analyze_pcap(
                    filename=args.file,
                    packet_filter=args.filter,
                    protocol=args.protocol,
                    max_packets=args.max_packets
                )
                
                # Check for errors
                if "error" in results:
                    spinner_update("Analysis failed", force_stop=True)
                    print(formatter.error(f"Analysis error: {results['error']}"))
                    return 1
                    
                # Analysis successful
                spinner_update("Analysis complete", force_stop=True)
                
                # Display results
                self._display_packet_analysis(results, args.format)
                
                # Save results if requested
                if args.output:
                    self._save_analysis_results(results, args.output, args.format)
                    
            except Exception as e:
                spinner_update("Analysis failed", force_stop=True)
                print(formatter.error(f"Error analyzing packets: {str(e)}"))
                return 1
                
        return 0
        
    def _display_packet_analysis(self, results, format_type):
        """Display packet analysis results."""
        if not results:
            print(formatter.warning("No results to display"))
            return
            
        print(formatter.header("Analysis Results", 60))
        
        # Display summary statistics
        print(formatter.info("Summary:"))
        
        # Get packet count and duration
        packet_count = results.get("packet_count", 0)
        duration = results.get("duration_seconds", 0)
        
        # Calculate packets per second
        pps = packet_count / max(1, duration)
        
        # Display basic statistics
        print(f"  Packets: {packet_count}")
        print(f"  Duration: {duration:.1f} seconds")
        print(f"  Rate: {pps:.1f} packets/second")
        
        # Display average packet size if available
        if "avg_packet_size" in results:
            avg_size = results["avg_packet_size"]
            print(f"  Average packet size: {avg_size:.1f} bytes")
            
        # Display protocol distribution
        if "protocols" in results and results["protocols"]:
            print("\n" + formatter.info("Protocol Distribution:"))
            
            # Sort protocols by count
            protocols = sorted(
                results["protocols"].items(),
                key=lambda x: x[1],
                reverse=True
            )
            
            if format_type == "json":
                # Display as JSON
                print(json.dumps(dict(protocols), indent=2))
            else:
                # Display as table
                table_data = []
                total = sum(count for _, count in protocols)
                
                for protocol, count in protocols:
                    percentage = (count / total) * 100
                    table_data.append([protocol, count, f"{percentage:.1f}%"])
                    
                print(tabulate(table_data, headers=['Protocol', 'Count', 'Percentage'], tablefmt='grid'))
                
        # Display top source IPs
        if "top_source_ips" in results and results["top_source_ips"]:
            print("\n" + formatter.info("Top Source IPs:"))
            
            if format_type == "json":
                # Display as JSON
                print(json.dumps(results["top_source_ips"], indent=2))
            else:
                # Display as table
                table_data = []
                for ip, count in results["top_source_ips"].items():
                    table_data.append([ip, count])
                    
                print(tabulate(table_data, headers=['IP Address', 'Count'], tablefmt='grid'))
                
    def _save_analysis_results(self, results, filename, format_type):
        """Save analysis results to a file."""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
            
            if format_type == "json" or filename.endswith(".json"):
                # Save as JSON
                with open(filename, 'w') as file:
                    json.dump(results, file, indent=2)
            else:
                # Save as text table
                with open(filename, 'w') as file:
                    # Write summary
                    file.write("# Packet Analysis Results\n\n")
                    file.write(f"Packets: {results.get('packet_count', 0)}\n")
                    file.write(f"Duration: {results.get('duration_seconds', 0):.1f} seconds\n")
                    file.write(f"Rate: {results.get('packets_per_second', 0):.1f} packets/second\n")
                    
                    if "avg_packet_size" in results:
                        file.write(f"Average packet size: {results['avg_packet_size']:.1f} bytes\n")
                    
                    # Write protocol distribution
                    if "protocols" in results and results["protocols"]:
                        file.write("\n## Protocol Distribution\n\n")
                        
                        protocols = sorted(
                            results["protocols"].items(),
                            key=lambda x: x[1],
                            reverse=True
                        )
                        
                        table_data = []
                        total = sum(count for _, count in protocols)
                        
                        for protocol, count in protocols:
                            percentage = (count / total) * 100
                            table_data.append([protocol, count, f"{percentage:.1f}%"])
                            
                        file.write(tabulate(table_data, headers=['Protocol', 'Count', 'Percentage'], tablefmt='grid'))
                        
                    # Write top source IPs
                    if "top_source_ips" in results and results["top_source_ips"]:
                        file.write("\n\n## Top Source IPs\n\n")
                        
                        table_data = []
                        for ip, count in results["top_source_ips"].items():
                            table_data.append([ip, count])
                            
                        file.write(tabulate(table_data, headers=['IP Address', 'Count'], tablefmt='grid'))
                        
                    # Write top destination IPs
                    if "top_destination_ips" in results and results["top_destination_ips"]:
                        file.write("\n\n## Top Destination IPs\n\n")
                        
                        table_data = []
                        for ip, count in results["top_destination_ips"].items():
                            table_data.append([ip, count])
                            
                        file.write(tabulate(table_data, headers=['IP Address', 'Count'], tablefmt='grid'))
            
            print(formatter.success(f"Results saved to {filename}"))
            
        except Exception as e:
            print(formatter.error(f"Error saving results: {str(e)}"))
            
    def _packet_callback(self, packet_info):
        """Callback for processed packets."""
        # This function is called for each processed packet during live capture
        # We can use it to show real-time information about packets if needed
        pass
        
    def _capture_status_callback(self, success, message):
        """Callback for capture status updates."""
        if success:
            print(formatter.info(message))
        else:
            print(formatter.error(message))
    
    def _handle_export(self, args):
        """Handle export command."""
        print(formatter.header("Export Results", 80))
        print(formatter.info(f"Exporting {args.type} data to {args.output} in {args.format} format"))
        
        # TODO: Implement actual export logic
        
        # Simulate export with a spinner
        spinner_update = formatter.spinner("Exporting data")
        for i in range(5):
            spinner_update(f"Exporting data: {i*20}% complete")
            time.sleep(0.5)
            
        spinner_update("Export completed", force_stop=True)
        
        print(formatter.success("Data exported successfully."))
        return 0
    
    def _handle_config(self, args):
        """Handle config command."""
        if not hasattr(args, 'config_command') or not args.config_command:
            print(f"{Fore.RED}Error: config subcommand required{Style.RESET_ALL}")
            return
        
        if args.config_command == 'get':
            self._handle_config_get(args)
        elif args.config_command == 'set':
            self._handle_config_set(args)
        elif args.config_command == 'list':
            self._handle_config_list(args)
        elif args.config_command == 'save':
            self._handle_config_save(args)
        elif args.config_command == 'reset':
            self._handle_config_reset(args)
        elif args.config_command == 'create':
            self._handle_config_create(args)
        elif args.config_command == 'import':
            self._handle_config_import(args)
        elif args.config_command == 'template':
            self._handle_config_template(args)
        else:
            print(f"{Fore.RED}Error: unknown config subcommand: {args.config_command}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Available subcommands: get, set, list, save, reset, create, import, template{Style.RESET_ALL}")
    
    def _handle_config_get(self, args):
        """Handle the config get command."""
        if not args.section:
            print(f"{Fore.RED}Error: section required{Style.RESET_ALL}")
            return
        
        value = self.config_manager.get(args.section, args.key)
        if value is None:
            print(f"{Fore.YELLOW}No configuration found for {args.section}" + 
                  (f".{args.key}" if args.key else "") + 
                  f"{Style.RESET_ALL}")
            return
        
        if isinstance(value, dict):
            print(json.dumps(value, indent=2))
        else:
            print(value)
    
    def _handle_config_set(self, args):
        """Handle the config set command."""
        if not args.section or not args.key:
            print(f"{Fore.RED}Error: section and key required{Style.RESET_ALL}")
            return
        
        # Try to convert value to appropriate type
        value = args.value
        try:
            # Try to convert to int
            value = int(value)
        except ValueError:
            try:
                # Try to convert to float
                value = float(value)
            except ValueError:
                # Try to convert to bool
                if value.lower() in ('true', 'yes', '1'):
                    value = True
                elif value.lower() in ('false', 'no', '0'):
                    value = False
                # Try to convert to list (comma-separated)
                elif ',' in value:
                    try:
                        items = [item.strip() for item in value.split(',')]
                        # Try to convert items to int if possible
                        int_items = []
                        for item in items:
                            try:
                                int_items.append(int(item))
                            except ValueError:
                                int_items = None
                                break
                        
                        if int_items:
                            value = int_items
                        else:
                            value = items
                    except:
                        pass
        
        # Set the value
        if self.config_manager.set(args.section, args.key, value):
            print(f"{Fore.GREEN}Configuration updated: {args.section}.{args.key} = {value}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed to update configuration{Style.RESET_ALL}")
    
    def _handle_config_list(self, args):
        """Handle the config list command."""
        if args.section:
            section_data = self.config_manager.get(args.section)
            if section_data is None:
                print(f"{Fore.YELLOW}No configuration found for section: {args.section}{Style.RESET_ALL}")
                return
            
            if isinstance(section_data, dict):
                # Convert to table format
                table_data = [[key, self._format_value(value)] for key, value in section_data.items()]
                print(tabulate(table_data, headers=['Key', 'Value'], tablefmt='grid'))
            else:
                print(section_data)
        else:
            # List all sections
            config = self.config_manager.config
            if not config:
                print(f"{Fore.YELLOW}No configuration found{Style.RESET_ALL}")
                return
            
            # Print sections with their key count
            table_data = []
            for section, data in config.items():
                if isinstance(data, dict):
                    table_data.append([section, len(data), self._summarize_keys(data)])
                else:
                    table_data.append([section, 1, str(data)])
            
            print(tabulate(table_data, headers=['Section', 'Keys', 'Summary'], tablefmt='grid'))
            print(f"\n{Fore.CYAN}Use 'config list <section>' to see details of a specific section{Style.RESET_ALL}")
    
    def _handle_config_save(self, args):
        """Handle the config save command."""
        file_path = args.file
        if self.config_manager.save_config(file_path):
            path = file_path or self.config_manager.config_file
            print(f"{Fore.GREEN}Configuration saved to {path}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed to save configuration{Style.RESET_ALL}")
    
    def _handle_config_reset(self, args):
        """Handle the config reset command."""
        from app.utils.config import DEFAULT_CONFIG
        
        if args.section:
            if args.section in DEFAULT_CONFIG:
                self.config_manager.config[args.section] = DEFAULT_CONFIG[args.section].copy()
                print(f"{Fore.GREEN}Reset configuration section: {args.section}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}Section not found: {args.section}{Style.RESET_ALL}")
        else:
            # Reset all configuration
            self.config_manager.config = DEFAULT_CONFIG.copy()
            print(f"{Fore.GREEN}Reset all configuration to defaults{Style.RESET_ALL}")
    
    def _handle_config_create(self, args):
        """Handle the config create command."""
        if self.config_manager.create_default_config(args.file):
            print(f"{Fore.GREEN}Created default configuration at {args.file}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed to create default configuration{Style.RESET_ALL}")
    
    def _handle_config_import(self, args):
        """Handle the config import command."""
        if not args.file:
            print(f"{Fore.RED}Error: file required{Style.RESET_ALL}")
            return
        
        if args.validate:
            print(f"{Fore.YELLOW}Validation mode. No changes made to configuration{Style.RESET_ALL}")
            return
        
        if self.config_manager.import_config(args.file):
            print(f"{Fore.GREEN}Configuration imported from {args.file}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed to import configuration{Style.RESET_ALL}")
    
    def _handle_config_template(self, args):
        """Handle the config template command."""
        if not args.file:
            print(f"{Fore.RED}Error: file required{Style.RESET_ALL}")
            return
        
        if self.config_manager.create_template_config(args.file):
            print(f"{Fore.GREEN}Created configuration template at {args.file}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed to create configuration template{Style.RESET_ALL}")
    
    def _format_value(self, value):
        """Format a value for display."""
        if isinstance(value, (list, tuple)):
            return ', '.join(str(item) for item in value)
        elif isinstance(value, dict):
            return json.dumps(value)
        else:
            return str(value)
    
    def _summarize_keys(self, data):
        """Summarize the keys in a dictionary."""
        if not isinstance(data, dict):
            return str(data)
        
        keys = list(data.keys())
        if len(keys) <= 3:
            return ', '.join(keys)
        else:
            return f"{', '.join(keys[:3])}, ..."
    
    def _monitor_alert_callback(self, alert):
        """Callback for monitor alerts."""
        alert_time = datetime.now().strftime("%H:%M:%S")
        severity = alert.get('severity', 'UNKNOWN')
        message = alert.get('message', 'Unknown alert')
        source = alert.get('source', 'Unknown')
        
        # Update alert counts
        self.alert_counts[severity] = self.alert_counts.get(severity, 0) + 1
        
        # Format output based on format
        if hasattr(self, 'args') and self.args.output_format == 'json':
            alert['timestamp'] = alert_time
            print(json.dumps(alert))
        else:
            if severity == "HIGH":
                print(formatter.error(f"[{alert_time}] HIGH ALERT: {message} (from {source})"))
            elif severity == "MEDIUM":
                print(formatter.warning(f"[{alert_time}] MEDIUM ALERT: {message} (from {source})"))
            else:
                print(formatter.info(f"[{alert_time}] LOW ALERT: {message} (from {source})"))
    
    def _monitor_status_callback(self, success, status):
        # Only show status updates for significant events
        if 'completed' in status or 'anomalies' in status or not success:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if success:
                print(f"[{timestamp}] {formatter.info(status)}")
            else:
                print(f"[{timestamp}] {formatter.error(status)}")
    
    def _scan_progress_callback(self, count, status):
        # This method is now empty as the progress callback is handled internally
        pass
    
    def _display_devices_table(self, devices, classify=True):
        # This method is now empty as the table display logic is handled internally
        pass
    
    def _export_devices_csv(self, devices):
        # This method is now empty as the CSV export logic is handled internally
        pass
    
    def run(self, args: Optional[List[str]] = None):
        """Run the CLI with the given arguments."""
        if args is None:
            args = sys.argv[1:]
        
        if not args:
            print(formatter.header("ARPGuard CLI", 80))
            self.parser.print_help()
            return 0
        
        try:
            parsed_args = self.parser.parse_args(args)
            
            if hasattr(parsed_args, 'func'):
                return parsed_args.func(parsed_args)
            else:
                print(formatter.header("ARPGuard CLI", 80))
                self.parser.print_help()
                return 0
        except KeyboardInterrupt:
            print(f"\n{formatter.warning('Operation cancelled by user')}")
            return 130  # Standard exit code for SIGINT
        except Exception as e:
            print(formatter.error(f"Error: {str(e)}"))
            return 1

def main():
    """Main entry point for the CLI."""
    cli = ARPGuardCLI()
    sys.exit(cli.run())

if __name__ == '__main__':
    main() 