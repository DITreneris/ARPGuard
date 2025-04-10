#!/usr/bin/env python3
import sys
import time
import logging
import subprocess
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def run_command(command):
    """Run a command and return its output."""
    try:
        result = subprocess.run(command, shell=True, check=True, 
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e.stderr}")
        return None

def demo_monitor_mode():
    """Run the monitor mode demo."""
    logger.info("Starting Monitor Mode Demo")
    logger.info("This will show how ARPGuard detects ARP spoofing attacks")
    
    # Start ARPGuard in monitor mode
    arpguard_cmd = "python scripts/mock_arpguard.py --mode monitor --interface eth0"
    arpguard_process = subprocess.Popen(arpguard_cmd, shell=True)
    
    try:
        # Let it run for 30 seconds
        logger.info("Running for 30 seconds to detect attacks...")
        time.sleep(30)
        
        # Get statistics
        stats_cmd = "python scripts/mock_arpguard.py --interface eth0 --stats"
        stats = run_command(stats_cmd)
        if stats:
            logger.info("\nFinal Statistics:")
            print(stats)
            
    except KeyboardInterrupt:
        logger.info("Demo interrupted by user")
    finally:
        arpguard_process.terminate()
        arpguard_process.wait()

def demo_protect_mode():
    """Run the protection mode demo."""
    logger.info("Starting Protection Mode Demo")
    logger.info("This will show how ARPGuard blocks ARP spoofing attacks")
    
    # Start ARPGuard in protect mode
    arpguard_cmd = "python scripts/mock_arpguard.py --mode protect --interface eth0"
    arpguard_process = subprocess.Popen(arpguard_cmd, shell=True)
    
    try:
        # Let it run for 30 seconds
        logger.info("Running for 30 seconds to demonstrate protection...")
        time.sleep(30)
        
        # Get statistics
        stats_cmd = "python scripts/mock_arpguard.py --interface eth0 --stats"
        stats = run_command(stats_cmd)
        if stats:
            logger.info("\nFinal Statistics:")
            print(stats)
            
    except KeyboardInterrupt:
        logger.info("Demo interrupted by user")
    finally:
        arpguard_process.terminate()
        arpguard_process.wait()

def main():
    """Main demo function."""
    print("\n=== ARPGuard Demo ===")
    print("1. Monitor Mode Demo")
    print("2. Protection Mode Demo")
    print("3. Exit")
    
    while True:
        choice = input("\nSelect demo mode (1-3): ")
        
        if choice == "1":
            demo_monitor_mode()
        elif choice == "2":
            demo_protect_mode()
        elif choice == "3":
            logger.info("Exiting demo...")
            sys.exit(0)
        else:
            logger.warning("Invalid choice. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main() 