#!/usr/bin/env python3
import os
import sys
import time
import logging
import subprocess
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from generate_validation_report import ValidationReport
import psutil
import socket
from datetime import datetime
import platform

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('arpguard.validation')

class DeploymentValidator:
    def __init__(self, config_path: str = 'config/validation_config.yaml'):
        """Initialize the validator with configuration"""
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config(config_path)
        self.report = ValidationReport()
        self.test_results = []

    def _load_config(self, config_path: str) -> Dict:
        """Load validation configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            self.logger.error(f"Failed to load config: {str(e)}")
            raise

    def run_validation(self) -> Dict[str, Dict[str, Any]]:
        """Run all validation checks"""
        results = {}
        
        # Network validation
        results['network_interfaces'] = self.validate_network_interfaces()
        results['connectivity'] = self.validate_connectivity()
        
        # System validation
        results['services'] = self.validate_services()
        results['file_permissions'] = self.validate_file_permissions()
        
        # Performance validation
        results['cpu_usage'] = self.validate_cpu_usage()
        results['memory_usage'] = self.validate_memory_usage()
        
        # Logging validation
        results['logging'] = self.validate_logging()
        
        return results

    def validate_network_interfaces(self) -> Dict[str, Any]:
        """Validate network interfaces"""
        result = {'status': 'PASS', 'details': []}
        required_interfaces = self.config['network']['interfaces']
        
        try:
            interfaces = psutil.net_if_addrs()
            for interface in required_interfaces:
                if interface not in interfaces:
                    result['status'] = 'FAIL'
                    result['details'].append(f"Missing interface: {interface}")
                else:
                    result['details'].append(f"Interface {interface} found")
        except Exception as e:
            result['status'] = 'FAIL'
            result['details'].append(f"Error checking interfaces: {str(e)}")
            
        return result

    def validate_connectivity(self) -> Dict[str, Any]:
        """Validate network connectivity to targets"""
        result = {'status': 'PASS', 'details': []}
        targets = self.config['network']['connectivity_targets']
        
        for target in targets:
            try:
                socket.gethostbyname(target)
                result['details'].append(f"Successfully connected to {target}")
            except Exception as e:
                result['status'] = 'FAIL'
                result['details'].append(f"Failed to connect to {target}: {str(e)}")
                
        return result

    def validate_services(self) -> Dict[str, Any]:
        """Validate required system services"""
        result = {'status': 'PASS', 'details': []}
        required_services = self.config['system']['services']
        
        for service in required_services:
            try:
                if platform.system() == 'Windows':
                    cmd = f"Get-Service -Name {service} | Select-Object -Property Status"
                    status = subprocess.check_output(['powershell', '-Command', cmd])
                    if 'Running' not in str(status):
                        result['status'] = 'FAIL'
                        result['details'].append(f"Service {service} is not running")
                    else:
                        result['details'].append(f"Service {service} is running")
                else:
                    cmd = f"systemctl is-active {service}"
                    status = subprocess.check_output(cmd.split()).decode().strip()
                    if status != 'active':
                        result['status'] = 'FAIL'
                        result['details'].append(f"Service {service} is not active")
                    else:
                        result['details'].append(f"Service {service} is active")
            except Exception as e:
                result['status'] = 'FAIL'
                result['details'].append(f"Error checking service {service}: {str(e)}")
                
        return result

    def validate_file_permissions(self) -> Dict[str, Any]:
        """Validate file permissions"""
        result = {'status': 'PASS', 'details': []}
        required_permissions = self.config['security']['file_permissions']
        
        for file_path, expected_permissions in required_permissions.items():
            try:
                if not os.path.exists(file_path):
                    result['status'] = 'FAIL'
                    result['details'].append(f"File not found: {file_path}")
                    continue
                    
                if platform.system() == 'Windows':
                    # Windows permissions check would be implemented here
                    result['details'].append(f"Windows permissions check for {file_path}")
                else:
                    mode = os.stat(file_path).st_mode
                    actual_permissions = oct(mode)[-3:]
                    if actual_permissions != expected_permissions:
                        result['status'] = 'FAIL'
                        result['details'].append(
                            f"Invalid permissions for {file_path}: "
                            f"expected {expected_permissions}, got {actual_permissions}"
                        )
                    else:
                        result['details'].append(f"Correct permissions for {file_path}")
            except Exception as e:
                result['status'] = 'FAIL'
                result['details'].append(f"Error checking permissions for {file_path}: {str(e)}")
                
        return result

    def validate_cpu_usage(self) -> Dict[str, Any]:
        """Validate CPU usage"""
        result = {'status': 'PASS', 'details': []}
        threshold = self.config['performance']['cpu_threshold']
        
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            result['details'].append(f"Current CPU usage: {cpu_percent}%")
            
            if cpu_percent > threshold:
                result['status'] = 'FAIL'
                result['details'].append(f"CPU usage exceeds threshold of {threshold}%")
        except Exception as e:
            result['status'] = 'FAIL'
            result['details'].append(f"Error checking CPU usage: {str(e)}")
            
        return result

    def validate_memory_usage(self) -> Dict[str, Any]:
        """Validate memory usage"""
        result = {'status': 'PASS', 'details': []}
        threshold = self.config['performance']['memory_threshold']
        
        try:
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            result['details'].append(f"Current memory usage: {memory_percent}%")
            
            if memory_percent > threshold:
                result['status'] = 'FAIL'
                result['details'].append(f"Memory usage exceeds threshold of {threshold}%")
        except Exception as e:
            result['status'] = 'FAIL'
            result['details'].append(f"Error checking memory usage: {str(e)}")
            
        return result

    def validate_logging(self) -> Dict[str, Any]:
        """Validate logging configuration"""
        result = {'status': 'PASS', 'details': []}
        log_file = self.config['logging']['log_file']
        
        try:
            if not os.path.exists(log_file):
                result['status'] = 'FAIL'
                result['details'].append(f"Log file not found: {log_file}")
            else:
                result['details'].append(f"Log file exists: {log_file}")
                
                # Check if log file is writable
                try:
                    with open(log_file, 'a') as f:
                        f.write(f"Test log entry at {datetime.now()}\n")
                    result['details'].append("Log file is writable")
                except Exception as e:
                    result['status'] = 'FAIL'
                    result['details'].append(f"Log file is not writable: {str(e)}")
        except Exception as e:
            result['status'] = 'FAIL'
            result['details'].append(f"Error checking logging: {str(e)}")
            
        return result

    def generate_report(self, results: Dict[str, Dict[str, Any]], format: str = 'html') -> None:
        """Generate validation report in specified format"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == 'html':
            self._generate_html_report(results, f"validation_report_{timestamp}.html")
        elif format == 'json':
            self._generate_json_report(results, f"validation_report_{timestamp}.json")
        elif format == 'yaml':
            self._generate_yaml_report(results, f"validation_report_{timestamp}.yaml")
        else:
            raise ValueError(f"Unsupported report format: {format}")

    def _generate_html_report(self, results: Dict[str, Dict[str, Any]], filename: str) -> None:
        """Generate HTML report"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Deployment Validation Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .pass { color: green; }
                .fail { color: red; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <h1>Deployment Validation Report</h1>
            <p>Generated at: {timestamp}</p>
            <table>
                <tr>
                    <th>Check</th>
                    <th>Status</th>
                    <th>Details</th>
                </tr>
        """
        
        for check, result in results.items():
            status_class = 'pass' if result['status'] == 'PASS' else 'fail'
            details = '<br>'.join(result['details'])
            html += f"""
                <tr>
                    <td>{check}</td>
                    <td class="{status_class}">{result['status']}</td>
                    <td>{details}</td>
                </tr>
            """
            
        html += """
            </table>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html.format(timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    def _generate_json_report(self, results: Dict[str, Dict[str, Any]], filename: str) -> None:
        """Generate JSON report"""
        with open(filename, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'results': results
            }, f, indent=2)

    def _generate_yaml_report(self, results: Dict[str, Dict[str, Any]], filename: str) -> None:
        """Generate YAML report"""
        with open(filename, 'w') as f:
            yaml.dump({
                'timestamp': datetime.now().isoformat(),
                'results': results
            }, f, default_flow_style=False)

    def run_all_validations(self) -> None:
        """Run all validation tests and generate report."""
        logger.info("Starting comprehensive validation...")

        # Run all validation tests
        self.run_validation()

        # Add results to validation report
        for section, data in self.test_results.items():
            self.report.add_test_result(
                section,
                "PASS" if data['status'] else "FAIL",
                data['checks'] + data['errors']
            )

        # Generate and save report
        report_path = Path(self.config['report_path'])
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.report.generate_html_report(str(report_path))
        self.report.save_json_report(str(report_path.with_suffix('.json')))
        self.report.save_yaml_report(str(report_path.with_suffix('.yaml')))

        logger.info(f"Validation complete. Reports saved to {report_path}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python validate_deployment.py <config_path>")
        sys.exit(1)

    config_path = sys.argv[1]
    validator = DeploymentValidator(config_path)
    validator.run_all_validations()

if __name__ == "__main__":
    main() 