#!/usr/bin/env python3
"""
Script to download and update the MAC vendor database.
This script can be run periodically to keep the vendors database up-to-date.
"""

import os
import sys
import logging

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.utils.mac_vendor import update_vendor_database

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('update_mac_vendors')

def main():
    """Update the MAC vendor database."""
    logger.info("Starting MAC vendor database update...")
    success = update_vendor_database()
    
    if success:
        logger.info("MAC vendor database updated successfully.")
        return 0
    else:
        logger.error("Failed to update MAC vendor database.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 