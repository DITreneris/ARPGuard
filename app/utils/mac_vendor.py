import os
import json
import re
import logging
import urllib.request
from typing import Optional

# Default vendors database location
VENDORS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vendors.json')

# URL to download MAC vendors database
VENDORS_URL = "https://macaddress.io/database/macaddress.io-db.json"

class MacVendorDB:
    """MAC address vendor database utility."""
    
    def __init__(self, db_file: str = VENDORS_FILE):
        """Initialize the MAC vendor database.
        
        Args:
            db_file: Path to the vendors database file.
        """
        self.db_file = db_file
        self.vendors = {}
        self.load_database()
    
    def load_database(self) -> bool:
        """Load the MAC vendor database from file.
        
        Returns:
            bool: True if database was loaded successfully, False otherwise.
        """
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    self.vendors = json.load(f)
                return True
            except Exception as e:
                logging.error(f"Failed to load MAC vendor database: {e}")
                return False
        else:
            logging.warning(f"MAC vendor database file not found: {self.db_file}")
            return False
    
    def update_database(self) -> bool:
        """Update the MAC vendor database from the internet.
        
        Returns:
            bool: True if database was updated successfully, False otherwise.
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.db_file), exist_ok=True)
            
            # Download the database
            logging.info(f"Downloading MAC vendor database from {VENDORS_URL}")
            urllib.request.urlretrieve(VENDORS_URL, self.db_file)
            
            # Reload the database
            return self.load_database()
        except Exception as e:
            logging.error(f"Failed to update MAC vendor database: {e}")
            return False
    
    def get_vendor(self, mac_address: str) -> Optional[str]:
        """Get the vendor name for a MAC address.
        
        Args:
            mac_address: The MAC address to look up.
            
        Returns:
            str: The vendor name if found, None otherwise.
        """
        if not self.vendors:
            return None
            
        # Normalize MAC address format
        mac = self.normalize_mac(mac_address)
        if not mac:
            return None
            
        # Check for matches with decreasing prefix length
        for prefix_len in [9, 8, 7, 6]:  # Try OUI prefixes (first 3 bytes)
            prefix = mac[:prefix_len]
            if prefix in self.vendors:
                return self.vendors[prefix]
                
        return None
    
    @staticmethod
    def normalize_mac(mac_address: str) -> Optional[str]:
        """Normalize a MAC address to a standard format.
        
        Args:
            mac_address: The MAC address to normalize.
            
        Returns:
            str: The normalized MAC address, or None if invalid.
        """
        if not mac_address:
            return None
            
        # Remove all non-hexadecimal characters
        mac = re.sub(r'[^0-9a-fA-F]', '', mac_address.upper())
        
        # Check if we have a valid MAC address
        if len(mac) != 12:
            return None
            
        return mac


# Singleton pattern for database access
_vendor_db_instance = None

def get_vendor_db() -> MacVendorDB:
    """Get the singleton MAC vendor database instance.
    
    Returns:
        MacVendorDB: The MAC vendor database instance.
    """
    global _vendor_db_instance
    if _vendor_db_instance is None:
        _vendor_db_instance = MacVendorDB()
    return _vendor_db_instance


def get_vendor_name(mac_address: str) -> str:
    """Get the vendor name for a MAC address.
    
    Args:
        mac_address: The MAC address to look up.
        
    Returns:
        str: The vendor name if found, 'Unknown' otherwise.
    """
    db = get_vendor_db()
    vendor = db.get_vendor(mac_address)
    return vendor if vendor else "Unknown"


def update_vendor_database() -> bool:
    """Update the MAC vendor database from the internet.
    
    Returns:
        bool: True if database was updated successfully, False otherwise.
    """
    db = get_vendor_db()
    return db.update_database()


# Create an empty vendors.json file if it doesn't exist
if not os.path.exists(VENDORS_FILE):
    try:
        os.makedirs(os.path.dirname(VENDORS_FILE), exist_ok=True)
        with open(VENDORS_FILE, 'w') as f:
            json.dump({}, f)
    except Exception as e:
        logging.error(f"Failed to create empty vendors database: {e}") 