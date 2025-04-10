#!/usr/bin/env python3
import os
import sys
import time
import logging
import subprocess
import yaml
from pathlib import Path
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('demo-videos/demo_log.txt'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DemoRunner:
    def __init__(self):
        self.network_config = self.load_network_config()
        self.scenarios = self.load_scenarios()
        self.results = {}
        
    def load_network_config(self):
        """Load network configuration from YAML file."""
        config_path = Path('config/demo_network.yaml')
        if not config_path.exists():
            logger.error(f"Network configuration not found at {config_path}")
            sys.exit(1)
            
        with open(config_path) as f:
            return yaml.safe_load(f)['network_config']
            
    def load_scenarios(self):
        """Load demo scenarios from markdown file."""
        scenarios_path = Path('demo_test_scenarios.md')
        if not scenarios_path.exists():
            logger.error(f"Scenarios file not found at {scenarios_path}")
            sys.exit(1)
            
        # Parse scenarios from markdown
        # This is a simplified version - in production, you'd want a proper markdown parser
        with open(scenarios_path) as f:
            content = f.read()
            
        scenarios = {}
        current_scenario = None
        
        for line in content.split('\n'):
            if line.startswith('## Scenario'):
                current_scenario = line.strip('# ').split(':')[0]
                scenarios[current_scenario] = {'steps': []}
            elif line.strip() and current_scenario:
                scenarios[current_scenario]['steps'].append(line.strip())
                
        return scenarios
        
    def run_scenario(self, scenario_name):
        """Run a specific demo scenario."""
        logger.info(f"Starting scenario: {scenario_name}")
        
        if scenario_name not in self.scenarios:
            logger.error(f"Scenario {scenario_name} not found")
            return False
            
        scenario = self.scenarios[scenario_name]
        success = True
        
        for step in scenario['steps']:
            if step.startswith('```'):
                # This is a command to execute
                command = step.strip('```').strip()
                logger.info(f"Executing: {command}")
                
                try:
                    result = subprocess.run(command, shell=True, check=True)
                    if result.returncode != 0:
                        logger.error(f"Command failed: {command}")
                        success = False
                        break
                except subprocess.CalledProcessError as e:
                    logger.error(f"Error executing command: {e}")
                    success = False
                    break
                    
        self.results[scenario_name] = {
            'success': success,
            'timestamp': datetime.now().isoformat()
        }
        
        return success
        
    def run_all_scenarios(self):
        """Run all demo scenarios in sequence."""
        logger.info("Starting all demo scenarios")
        
        for scenario_name in self.scenarios:
            if not self.run_scenario(scenario_name):
                logger.error(f"Scenario {scenario_name} failed")
                break
                
        self.save_results()
        
    def save_results(self):
        """Save demo results to a file."""
        results_path = Path('demo-videos/demo_results.yaml')
        with open(results_path, 'w') as f:
            yaml.dump(self.results, f)
            
        logger.info(f"Demo results saved to {results_path}")
        
    def generate_report(self):
        """Generate a demo report."""
        report_path = Path('demo-videos/demo_report.html')
        
        with open(report_path, 'w') as f:
            f.write('<!DOCTYPE html>\n<html>\n<head>\n')
            f.write('<title>ARPGuard Demo Report</title>\n')
            f.write('<style>body { font-family: Arial, sans-serif; }</style>\n')
            f.write('</head>\n<body>\n')
            f.write('<h1>ARPGuard Demo Report</h1>\n')
            f.write(f'<p>Generated: {datetime.now().isoformat()}</p>\n')
            
            for scenario, result in self.results.items():
                status = 'Success' if result['success'] else 'Failed'
                color = 'green' if result['success'] else 'red'
                f.write(f'<h2 style="color: {color};">{scenario}: {status}</h2>\n')
                f.write(f'<p>Completed: {result["timestamp"]}</p>\n')
                
            f.write('</body>\n</html>')
            
        logger.info(f"Demo report generated at {report_path}")

if __name__ == "__main__":
    runner = DemoRunner()
    runner.run_all_scenarios()
    runner.generate_report() 