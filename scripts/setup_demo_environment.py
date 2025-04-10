#!/usr/bin/env python3
import os
import sys
import subprocess
import platform
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DemoEnvironmentSetup:
    def __init__(self):
        self.system = platform.system()
        self.requirements = {
            'python': '3.7+',
            'wireshark': '3.0+',
            'iperf3': '3.0+',
            'arpguard': 'latest'
        }
        
    def check_python_version(self):
        """Check if Python version meets requirements."""
        version = sys.version_info
        required = (3, 7)
        if version < required:
            logger.error(f"Python version {version.major}.{version.minor} is below required {required[0]}.{required[1]}")
            return False
        logger.info(f"Python version {version.major}.{version.minor} meets requirements")
        return True

    def check_wireshark(self):
        """Check if Wireshark is installed."""
        try:
            if self.system == 'Windows':
                result = subprocess.run(['wireshark', '--version'], capture_output=True, text=True)
            else:
                result = subprocess.run(['which', 'wireshark'], capture_output=True, text=True)
            if result.returncode == 0:
                logger.info("Wireshark is installed")
                return True
        except FileNotFoundError:
            logger.error("Wireshark is not installed")
            return False

    def check_iperf3(self):
        """Check if iperf3 is installed."""
        try:
            result = subprocess.run(['iperf3', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                logger.info("iperf3 is installed")
                return True
        except FileNotFoundError:
            logger.error("iperf3 is not installed")
            return False

    def check_arpguard(self):
        """Check if ARPGuard is installed and configured."""
        try:
            result = subprocess.run(['arpguard', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                logger.info("ARPGuard is installed")
                return True
        except FileNotFoundError:
            logger.error("ARPGuard is not installed")
            return False

    def create_demo_directory(self):
        """Create directory structure for demo files."""
        demo_dirs = [
            'demo-videos',
            'demo-videos/recordings',
            'demo-videos/backup',
            'demo-videos/screenshots'
        ]
        
        for dir_path in demo_dirs:
            Path(dir_path).mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {dir_path}")

    def setup_network_config(self):
        """Create network configuration file for demo."""
        config = {
            'network': '192.168.88.0/24',
            'demo_laptop': '192.168.88.10',
            'client': '192.168.88.20',
            'target': '192.168.88.30',
            'attacker': '192.168.88.40'
        }
        
        config_path = Path('config/demo_network.yaml')
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_path, 'w') as f:
            f.write('network_config:\n')
            for key, value in config.items():
                f.write(f'  {key}: {value}\n')
        
        logger.info(f"Created network configuration at {config_path}")

    def run(self):
        """Run all setup checks and configurations."""
        logger.info("Starting demo environment setup...")
        
        checks = [
            self.check_python_version(),
            self.check_wireshark(),
            self.check_iperf3(),
            self.check_arpguard()
        ]
        
        if all(checks):
            self.create_demo_directory()
            self.setup_network_config()
            logger.info("Demo environment setup completed successfully")
            return True
        else:
            logger.error("Demo environment setup failed. Please fix the issues above.")
            return False

if __name__ == "__main__":
    setup = DemoEnvironmentSetup()
    setup.run() 