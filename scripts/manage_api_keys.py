#!/usr/bin/env python3
"""
Script to manage API keys for threat intelligence services.

This script helps manage API keys securely by:
1. Storing them in environment variables
2. Updating the config file with encrypted values
3. Testing API connections
"""

import os
import sys
import yaml
import json
import base64
from pathlib import Path
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from app.utils.logger import setup_logger

# Set up logging
log_file = os.path.join(project_root, 'logs', 'api_keys.log')
logger = setup_logger('api_keys', log_file)

def generate_key(password: str, salt: bytes = None) -> tuple:
    """Generate a Fernet key from a password."""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key), salt

def encrypt_value(fernet: Fernet, value: str) -> str:
    """Encrypt a value using Fernet."""
    return fernet.encrypt(value.encode()).decode()

def decrypt_value(fernet: Fernet, encrypted_value: str) -> str:
    """Decrypt a value using Fernet."""
    return fernet.decrypt(encrypted_value.encode()).decode()

def load_config():
    """Load the configuration file."""
    try:
        config_path = os.path.join(project_root, 'config.yaml')
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return None

def save_config(config):
    """Save the configuration file."""
    try:
        config_path = os.path.join(project_root, 'config.yaml')
        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        return True
    except Exception as e:
        logger.error(f"Error saving configuration: {e}")
        return False

def get_api_keys():
    """Get API keys from user input."""
    print("\nEnter API keys for threat intelligence services.")
    print("Leave blank to skip a service.\n")
    
    keys = {}
    services = ['abuseipdb', 'virustotal', 'otx', 'emerging_threats']
    
    for service in services:
        key = getpass(f"{service} API key: ")
        if key:
            keys[service] = key
            
    return keys

def update_config_with_keys(config, keys, fernet):
    """Update configuration with encrypted API keys."""
    if 'threat_intelligence' not in config:
        config['threat_intelligence'] = {}
        
    for service, key in keys.items():
        if service not in config['threat_intelligence']:
            config['threat_intelligence'][service] = {}
            
        encrypted_key = encrypt_value(fernet, key)
        config['threat_intelligence'][service]['api_key'] = encrypted_key
        config['threat_intelligence'][service]['enabled'] = True
        
    return config

def main():
    """Main function."""
    try:
        # Load existing configuration
        config = load_config()
        if not config:
            print("Failed to load configuration")
            return
            
        # Get encryption password
        password = getpass("\nEnter encryption password: ")
        confirm = getpass("Confirm encryption password: ")
        
        if password != confirm:
            print("Passwords do not match")
            return
            
        # Generate encryption key
        fernet, salt = generate_key(password)
        
        # Save salt for future use
        salt_file = os.path.join(project_root, '.salt')
        with open(salt_file, 'wb') as f:
            f.write(salt)
            
        # Get API keys
        keys = get_api_keys()
        
        if not keys:
            print("No API keys provided")
            return
            
        # Update configuration
        config = update_config_with_keys(config, keys, fernet)
        
        # Save configuration
        if save_config(config):
            print("\nAPI keys have been encrypted and saved to config.yaml")
            print("The encryption password is required to decrypt the keys")
            print(f"Salt file has been saved to {salt_file}")
        else:
            print("\nFailed to save configuration")
            
    except Exception as e:
        logger.error(f"Error in main: {e}")
        print(f"\nAn error occurred: {e}")

if __name__ == "__main__":
    # Ensure logs directory exists
    os.makedirs(os.path.join(project_root, 'logs'), exist_ok=True)
    
    # Run the script
    main() 