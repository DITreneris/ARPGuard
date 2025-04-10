#!/usr/bin/env python3
"""
ARPGuard Validation Report Generator
This script generates comprehensive validation reports by aggregating results
from all validation tests and providing detailed analysis.
"""

import argparse
import sys
import os
import json
import yaml
import logging
import datetime
from typing import Dict, List, Any
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('validation_report.log')
    ]
)
logger = logging.getLogger('arpguard-validation-report')

class ValidationReport:
    def __init__(self):
        self.report = {
            'metadata': {
                'generated_at': datetime.datetime.now().isoformat(),
                'version': '1.0',
                'system': {
                    'platform': sys.platform,
                    'python_version': sys.version,
                    'hostname': os.uname().nodename if hasattr(os, 'uname') else os.environ.get('COMPUTERNAME', 'unknown')
                }
            },
            'summary': {
                'total_tests': 0,
                'passed_tests': 0,
                'failed_tests': 0,
                'skipped_tests': 0,
                'overall_status': 'PASSED'
            },
            'categories': {},
            'failures': [],
            'warnings': [],
            'recommendations': []
        }

    def add_test_result(self, category: str, test_id: str, test_name: str, 
                       status: str, details: Dict[str, Any]):
        """Add a test result to the report."""
        if category not in self.report['categories']:
            self.report['categories'][category] = {
                'total_tests': 0,
                'passed_tests': 0,
                'failed_tests': 0,
                'skipped_tests': 0,
                'tests': []
            }

        test_result = {
            'id': test_id,
            'name': test_name,
            'status': status,
            'timestamp': datetime.datetime.now().isoformat(),
            'details': details
        }

        self.report['categories'][category]['tests'].append(test_result)
        self.report['categories'][category]['total_tests'] += 1
        
        if status == 'PASSED':
            self.report['categories'][category]['passed_tests'] += 1
        elif status == 'FAILED':
            self.report['categories'][category]['failed_tests'] += 1
            self.report['failures'].append({
                'category': category,
                'test_id': test_id,
                'test_name': test_name,
                'details': details
            })
        else:
            self.report['categories'][category]['skipped_tests'] += 1

        # Update summary
        self.report['summary']['total_tests'] += 1
        if status == 'PASSED':
            self.report['summary']['passed_tests'] += 1
        elif status == 'FAILED':
            self.report['summary']['failed_tests'] += 1
        else:
            self.report['summary']['skipped_tests'] += 1

    def add_warning(self, message: str, context: Dict[str, Any] = None):
        """Add a warning to the report."""
        self.report['warnings'].append({
            'message': message,
            'context': context or {},
            'timestamp': datetime.datetime.now().isoformat()
        })

    def add_recommendation(self, message: str, priority: str = 'medium'):
        """Add a recommendation to the report."""
        self.report['recommendations'].append({
            'message': message,
            'priority': priority,
            'timestamp': datetime.datetime.now().isoformat()
        })

    def update_overall_status(self):
        """Update the overall status based on test results."""
        if self.report['summary']['failed_tests'] > 0:
            self.report['summary']['overall_status'] = 'FAILED'
        elif self.report['summary']['skipped_tests'] > 0:
            self.report['summary']['overall_status'] = 'WARNING'
        else:
            self.report['summary']['overall_status'] = 'PASSED'

    def generate_html_report(self, output_path: str):
        """Generate an HTML version of the report."""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>ARPGuard Validation Report</title>
    <style>
        body {{
            font-family: sans-serif;
            margin: 20px;
        }}
        h1, h2, h3 {{
            color: #333;
        }}
        .header {{
            background-color: #f0f0f0;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .passed {{
            color: green;
        }}
        .failed {{
            color: red;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 20px;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>ARPGuard Validation Report</h1>
        <p>Generated at: {self.report['metadata']['generated_at']}</p>
    </div>
    
    <h2>Summary</h2>
    <table>
        <tr>
            <th>Total Tests</th>
            <th>Passed</th>
            <th>Failed</th>
            <th>Skipped</th>
            <th>Overall Status</th>
        </tr>
        <tr>
            <td>{self.report['summary']['total_tests']}</td>
            <td class="passed">{self.report['summary']['passed_tests']}</td>
            <td class="failed">{self.report['summary']['failed_tests']}</td>
            <td>{self.report['summary']['skipped_tests']}</td>
            <td class="{self.report['summary']['overall_status'].lower()}">{self.report['summary']['overall_status']}</td>
        </tr>
    </table>
    
    <h2>Test Results by Category</h2>
"""

        # Add category results
        for category, data in self.report['categories'].items():
            html_content += f"""
    <h3>{category}</h3>
    <table>
        <tr>
            <th>Test ID</th>
            <th>Name</th>
            <th>Status</th>
            <th>Details</th>
        </tr>
"""
            for test in data['tests']:
                status_class = test['status'].lower()
                details_str = str(test['details']).replace("<", "&lt;").replace(">", "&gt;")
                html_content += f"""
        <tr>
            <td>{test['id']}</td>
            <td>{test['name']}</td>
            <td class="{status_class}">{test['status']}</td>
            <td>{details_str}</td>
        </tr>
"""
            html_content += """
    </table>
"""

        # Add failures if any
        if self.report['failures']:
            html_content += """
    <h2>Failures</h2>
    <table>
        <tr>
            <th>Category</th>
            <th>Test ID</th>
            <th>Test Name</th>
            <th>Details</th>
        </tr>
"""
            for failure in self.report['failures']:
                details_str = str(failure['details']).replace("<", "&lt;").replace(">", "&gt;")
                html_content += f"""
        <tr>
            <td>{failure['category']}</td>
            <td>{failure['test_id']}</td>
            <td>{failure['test_name']}</td>
            <td>{details_str}</td>
        </tr>
"""
            html_content += """
    </table>
"""

        # Add warnings if any
        if self.report['warnings']:
            html_content += """
    <h2>Warnings</h2>
    <table>
        <tr>
            <th>Message</th>
            <th>Context</th>
            <th>Timestamp</th>
        </tr>
"""
            for warning in self.report['warnings']:
                context_str = str(warning['context']).replace("<", "&lt;").replace(">", "&gt;")
                html_content += f"""
        <tr>
            <td>{warning['message']}</td>
            <td>{context_str}</td>
            <td>{warning['timestamp']}</td>
        </tr>
"""
            html_content += """
    </table>
"""

        # Add recommendations if any
        if self.report['recommendations']:
            html_content += """
    <h2>Recommendations</h2>
    <table>
        <tr>
            <th>Priority</th>
            <th>Message</th>
            <th>Timestamp</th>
        </tr>
"""
            for rec in self.report['recommendations']:
                html_content += f"""
        <tr>
            <td>{rec['priority']}</td>
            <td>{rec['message']}</td>
            <td>{rec['timestamp']}</td>
        </tr>
"""
            html_content += """
    </table>
"""

        # Close HTML
        html_content += """
</body>
</html>
"""

        # Write to file
        with open(output_path, 'w') as f:
            f.write(html_content)

    def save_json(self, output_path: str):
        """Save the report as JSON."""
        with open(output_path, 'w') as f:
            json.dump(self.report, f, indent=2)

    def save_yaml(self, output_path: str):
        """Save the report as YAML."""
        with open(output_path, 'w') as f:
            yaml.dump(self.report, f, default_flow_style=False)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Generate ARPGuard Validation Report')
    parser.add_argument('--input', type=str, required=True, help='Input JSON/YAML file with test results')
    parser.add_argument('--output', type=str, required=True, help='Output file path')
    parser.add_argument('--format', choices=['json', 'yaml', 'html'], default='html', help='Output format')
    return parser.parse_args()

def main():
    """Main function."""
    args = parse_args()
    
    # Create report object
    report = ValidationReport()
    
    # Load test results
    try:
        with open(args.input, 'r') as f:
            if args.input.endswith('.json'):
                test_results = json.load(f)
            elif args.input.endswith('.yaml') or args.input.endswith('.yml'):
                test_results = yaml.safe_load(f)
            else:
                logger.error(f"Unsupported input file format: {args.input}")
                sys.exit(1)
    except Exception as e:
        logger.error(f"Error loading test results: {str(e)}")
        sys.exit(1)
    
    # Process test results
    for category, tests in test_results.items():
        for test in tests:
            report.add_test_result(
                category=category,
                test_id=test.get('id', ''),
                test_name=test.get('name', ''),
                status=test.get('status', 'SKIPPED'),
                details=test.get('details', {})
            )
    
    # Update overall status
    report.update_overall_status()
    
    # Generate report in specified format
    if args.format == 'json':
        report.save_json(args.output)
    elif args.format == 'yaml':
        report.save_yaml(args.output)
    else:  # html
        report.generate_html_report(args.output)
    
    logger.info(f"Report generated successfully: {args.output}")

if __name__ == "__main__":
    main() 