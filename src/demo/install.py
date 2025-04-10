#!/usr/bin/env python3
import os
import sys
import subprocess
import platform
from typing import List, Dict
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DemoInstaller:
    """Handles installation of ARP Guard demo package"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.requirements = {
            "python": {
                "packages": [
                    "scapy>=2.4.5",
                    "psutil>=5.8.0",
                    "pyyaml>=5.4.1",
                    "websockets>=10.0",
                    "fastapi>=0.68.0",
                    "uvicorn>=0.15.0"
                ]
            },
            "system": {
                "linux": ["libpcap-dev", "python3-dev"],
                "darwin": ["libpcap", "python3-dev"],
                "windows": ["npcap"]  # Windows requires Npcap for packet capture
            }
        }
    
    def check_python_version(self) -> bool:
        """Check if Python version meets requirements"""
        required_version = (3, 7)
        current_version = sys.version_info[:2]
        
        if current_version < required_version:
            logger.error(f"Python {required_version[0]}.{required_version[1]} or higher is required")
            return False
        return True
    
    def install_python_packages(self) -> bool:
        """Install required Python packages"""
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "--upgrade", "pip"
            ])
            subprocess.check_call([
                sys.executable, "-m", "pip", "install"
            ] + self.requirements["python"]["packages"])
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install Python packages: {e}")
            return False
    
    def install_system_packages(self) -> bool:
        """Install system-level dependencies"""
        if self.system not in self.requirements["system"]:
            logger.error(f"Unsupported operating system: {self.system}")
            return False
            
        try:
            if self.system == "linux":
                subprocess.check_call(["apt-get", "update"])
                subprocess.check_call([
                    "apt-get", "install", "-y"
                ] + self.requirements["system"]["linux"])
            elif self.system == "darwin":
                subprocess.check_call([
                    "brew", "install"
                ] + self.requirements["system"]["darwin"])
            elif self.system == "windows":
                logger.info("Please install Npcap manually from https://npcap.com/")
                return True
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install system packages: {e}")
            return False
    
    def setup_demo_environment(self) -> bool:
        """Setup demo environment and directories"""
        try:
            # Create necessary directories
            directories = [
                "logs",
                "config",
                "data",
                "visualizations"
            ]
            
            for directory in directories:
                os.makedirs(directory, exist_ok=True)
                
            # Create default configuration
            from config import DemoConfig
            default_config = DemoConfig()
            default_config.to_file("config/demo_config.json")
            
            return True
        except Exception as e:
            logger.error(f"Failed to setup demo environment: {e}")
            return False
    
    def run(self) -> bool:
        """Run the complete installation process"""
        logger.info("Starting ARP Guard demo installation...")
        
        if not self.check_python_version():
            return False
            
        if not self.install_python_packages():
            return False
            
        if not self.install_system_packages():
            return False
            
        if not self.setup_demo_environment():
            return False
            
        logger.info("Installation completed successfully!")
        return True

if __name__ == "__main__":
    installer = DemoInstaller()
    success = installer.run()
    sys.exit(0 if success else 1) 