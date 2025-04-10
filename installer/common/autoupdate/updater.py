#!/usr/bin/env python3
"""
Auto-update client for ARP Guard.
This module provides functionality to check for updates, download and install them.
"""

import os
import sys
import json
import hashlib
import platform
import subprocess
import tempfile
import logging
import shutil
import time
import requests
from pathlib import Path
from typing import Dict, Optional, Tuple, Any, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(
            tempfile.gettempdir(), 'arpguard_updater.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('arpguard_updater')

# Update server configuration
UPDATE_SERVER = "https://download.arpguard.com"
MANIFEST_URL = f"{UPDATE_SERVER}/releases/latest/update_manifest.json"

class UpdateError(Exception):
    """Exception raised for errors in the update process."""
    pass

class AutoUpdater:
    """
    Auto-update client for ARP Guard.
    
    This class handles checking for updates, downloading and installing them.
    """
    
    def __init__(self, current_version: str, app_path: str = None, 
                 manifest_url: str = MANIFEST_URL,
                 backup_dir: str = None,
                 temp_dir: str = None):
        """
        Initialize the auto-updater.
        
        Args:
            current_version: Current version of the application
            app_path: Path to the application installation
            manifest_url: URL to the update manifest
            backup_dir: Directory to store backups for rollback
            temp_dir: Temporary directory for downloads
        """
        self.current_version = current_version
        self.app_path = app_path or self._get_default_app_path()
        self.manifest_url = manifest_url
        self.backup_dir = backup_dir or os.path.join(
            os.path.expanduser('~'), '.arpguard', 'backup')
        self.temp_dir = temp_dir or tempfile.gettempdir()
        self.manifest = None
        self.system = self._get_system_info()
        
        # Create backup directory if it doesn't exist
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def _get_default_app_path(self) -> str:
        """Get default application path based on platform."""
        system = platform.system()
        if system == 'Windows':
            return os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'ARP Guard')
        elif system == 'Darwin':  # macOS
            return '/Applications/ARPGuard.app'
        else:  # Linux
            return '/opt/arpguard'
    
    def _get_system_info(self) -> str:
        """Get system info to determine which update to download."""
        system = platform.system()
        if system == 'Windows':
            return 'windows'
        elif system == 'Darwin':  # macOS
            return 'macos'
        elif system == 'Linux':
            # Check for DEB or RPM based system
            if os.path.exists('/etc/debian_version'):
                return 'linux-deb'
            elif os.path.exists('/etc/redhat-release'):
                return 'linux-rpm'
            else:
                return 'linux-deb'  # Default to DEB
        return None
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """
        Compare two version strings.
        
        Returns:
            -1 if version1 < version2
             0 if version1 == version2
             1 if version1 > version2
        """
        v1_parts = [int(x) for x in version1.split('.')]
        v2_parts = [int(x) for x in version2.split('.')]
        
        for i in range(max(len(v1_parts), len(v2_parts))):
            v1 = v1_parts[i] if i < len(v1_parts) else 0
            v2 = v2_parts[i] if i < len(v2_parts) else 0
            
            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
        
        return 0
    
    def check_for_update(self) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Check if an update is available.
        
        Returns:
            Tuple[bool, dict]: (is_update_available, update_info)
        """
        try:
            logger.info(f"Checking for updates at {self.manifest_url}")
            response = requests.get(self.manifest_url, timeout=10)
            response.raise_for_status()
            
            self.manifest = response.json()
            logger.info(f"Manifest retrieved: version {self.manifest.get('version')}")
            
            latest_version = self.manifest.get('version')
            min_version = self.manifest.get('minVersion', '0.0.0')
            
            # Check if current version meets minimum requirement
            if self._compare_versions(self.current_version, min_version) < 0:
                logger.warning(f"Current version {self.current_version} is below minimum required version {min_version}")
                return False, None
            
            # Check if update is available
            is_update = self._compare_versions(self.current_version, latest_version) < 0
            
            if is_update:
                logger.info(f"Update available: {latest_version}")
                return True, self.manifest
            else:
                logger.info(f"No update available. Current version: {self.current_version}, Latest: {latest_version}")
                return False, None
            
        except Exception as e:
            logger.error(f"Error checking for updates: {e}")
            return False, None
    
    def download_update(self) -> Optional[str]:
        """
        Download the update package.
        
        Returns:
            str: Path to downloaded file or None if download failed
        """
        if not self.manifest:
            update_available, manifest = self.check_for_update()
            if not update_available:
                return None
        
        try:
            platform_info = self.manifest.get('platforms', {}).get(self.system)
            if not platform_info:
                logger.error(f"No update available for platform: {self.system}")
                return None
            
            url = platform_info.get('url')
            expected_hash = platform_info.get('sha256')
            filename = platform_info.get('filename')
            
            if not url or not expected_hash or not filename:
                logger.error("Missing information in manifest")
                return None
            
            download_path = os.path.join(self.temp_dir, filename)
            logger.info(f"Downloading update from {url} to {download_path}")
            
            with requests.get(url, stream=True, timeout=60) as response:
                response.raise_for_status()
                with open(download_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
            
            # Verify file hash
            file_hash = self._calculate_file_hash(download_path)
            if file_hash != expected_hash:
                logger.error(f"Hash verification failed. Expected: {expected_hash}, Got: {file_hash}")
                os.remove(download_path)
                return None
            
            logger.info(f"Update downloaded and verified: {download_path}")
            return download_path
            
        except Exception as e:
            logger.error(f"Error downloading update: {e}")
            return None
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def create_backup(self) -> bool:
        """
        Create a backup of the current installation for rollback.
        
        Returns:
            bool: True if backup was successful, False otherwise
        """
        try:
            backup_name = f"arpguard_backup_{self.current_version}_{int(time.time())}"
            backup_path = os.path.join(self.backup_dir, backup_name)
            
            logger.info(f"Creating backup at {backup_path}")
            
            if platform.system() == 'Windows':
                # Create a directory backup
                shutil.copytree(self.app_path, backup_path)
            elif platform.system() == 'Darwin':  # macOS
                # Create a gzipped tar archive
                subprocess.run(
                    ['tar', '-czf', f"{backup_path}.tar.gz", '-C', 
                     os.path.dirname(self.app_path), os.path.basename(self.app_path)],
                    check=True
                )
            else:  # Linux
                # Create a gzipped tar archive
                subprocess.run(
                    ['tar', '-czf', f"{backup_path}.tar.gz", '-C', '/opt', 'arpguard'],
                    check=True
                )
            
            logger.info("Backup created successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error creating backup: {e}")
            return False
    
    def install_update(self, package_path: str) -> bool:
        """
        Install the downloaded update.
        
        Args:
            package_path: Path to the downloaded update package
            
        Returns:
            bool: True if installation was successful, False otherwise
        """
        if not os.path.exists(package_path):
            logger.error(f"Update package not found: {package_path}")
            return False
        
        try:
            # Create backup before installing
            if not self.create_backup():
                logger.warning("Backup failed, continuing with installation")
            
            system = platform.system()
            logger.info(f"Installing update on {system}")
            
            if system == 'Windows':
                # Run installer with silent flag
                result = subprocess.run(
                    [package_path, '/S'],
                    check=True
                )
            elif system == 'Darwin':  # macOS
                # Open DMG and run installer
                mount_dir = tempfile.mkdtemp()
                subprocess.run(['hdiutil', 'attach', package_path, '-mountpoint', mount_dir], check=True)
                pkg_files = [f for f in os.listdir(mount_dir) if f.endswith('.pkg')]
                
                if not pkg_files:
                    logger.error("No .pkg file found in DMG")
                    subprocess.run(['hdiutil', 'detach', mount_dir], check=False)
                    return False
                
                pkg_path = os.path.join(mount_dir, pkg_files[0])
                subprocess.run(['installer', '-pkg', pkg_path, '-target', '/'], check=True)
                subprocess.run(['hdiutil', 'detach', mount_dir], check=True)
                
            else:  # Linux
                if package_path.endswith('.deb'):
                    # Install DEB package
                    subprocess.run(['sudo', 'dpkg', '-i', package_path], check=True)
                elif package_path.endswith('.rpm'):
                    # Install RPM package
                    subprocess.run(['sudo', 'rpm', '-U', package_path], check=True)
                else:
                    logger.error(f"Unsupported package format: {package_path}")
                    return False
            
            logger.info("Update installed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error installing update: {e}")
            return False
    
    def rollback(self) -> bool:
        """
        Rollback to the previous version if update fails.
        
        Returns:
            bool: True if rollback was successful, False otherwise
        """
        try:
            # Find the most recent backup
            backup_files = os.listdir(self.backup_dir)
            backup_files = [f for f in backup_files if f.startswith('arpguard_backup_')]
            
            if not backup_files:
                logger.error("No backup found for rollback")
                return False
            
            # Sort by time (newest first)
            backup_files.sort(reverse=True)
            latest_backup = backup_files[0]
            backup_path = os.path.join(self.backup_dir, latest_backup)
            
            logger.info(f"Rolling back to backup: {backup_path}")
            
            system = platform.system()
            if system == 'Windows':
                if os.path.isdir(backup_path):
                    # Stop the service if running
                    subprocess.run(['sc', 'stop', 'ARPGuard'], check=False)
                    
                    # Remove current installation
                    shutil.rmtree(self.app_path, ignore_errors=True)
                    
                    # Restore from backup
                    shutil.copytree(backup_path, self.app_path)
                    
                    # Start the service
                    subprocess.run(['sc', 'start', 'ARPGuard'], check=False)
                else:
                    logger.error(f"Backup is not a directory: {backup_path}")
                    return False
                
            elif system == 'Darwin':  # macOS
                tar_path = f"{backup_path}.tar.gz"
                if os.path.exists(tar_path):
                    # Stop the service
                    subprocess.run(['launchctl', 'unload', '/Library/LaunchDaemons/com.arpguard.daemon.plist'], check=False)
                    
                    # Remove current installation
                    shutil.rmtree(self.app_path, ignore_errors=True)
                    
                    # Restore from backup
                    subprocess.run(['tar', '-xzf', tar_path, '-C', '/'], check=True)
                    
                    # Start the service
                    subprocess.run(['launchctl', 'load', '/Library/LaunchDaemons/com.arpguard.daemon.plist'], check=False)
                else:
                    logger.error(f"Backup tar file not found: {tar_path}")
                    return False
                
            else:  # Linux
                tar_path = f"{backup_path}.tar.gz"
                if os.path.exists(tar_path):
                    # Stop the service
                    subprocess.run(['systemctl', 'stop', 'arpguard'], check=False)
                    
                    # Remove current installation
                    shutil.rmtree('/opt/arpguard', ignore_errors=True)
                    
                    # Restore from backup
                    subprocess.run(['tar', '-xzf', tar_path, '-C', '/'], check=True)
                    
                    # Start the service
                    subprocess.run(['systemctl', 'start', 'arpguard'], check=False)
                else:
                    logger.error(f"Backup tar file not found: {tar_path}")
                    return False
            
            logger.info("Rollback completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error during rollback: {e}")
            return False
    
    def update(self) -> bool:
        """
        Check for, download and install an update.
        
        Returns:
            bool: True if update process was successful, False otherwise
        """
        try:
            # Check for update
            update_available, _ = self.check_for_update()
            if not update_available:
                logger.info("No update available")
                return True  # Not an error condition
            
            # Download update
            package_path = self.download_update()
            if not package_path:
                logger.error("Failed to download update")
                return False
            
            # Install update
            if not self.install_update(package_path):
                logger.error("Failed to install update, rolling back")
                if not self.rollback():
                    logger.error("Rollback failed")
                return False
            
            logger.info("Update process completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error during update process: {e}")
            try:
                logger.info("Attempting rollback...")
                self.rollback()
            except Exception as rollback_error:
                logger.error(f"Rollback failed: {rollback_error}")
            return False

def main():
    """Main function for running the updater from command line."""
    import argparse
    
    parser = argparse.ArgumentParser(description='ARP Guard Auto Updater')
    parser.add_argument('--version', '-v', required=True, help='Current version of the application')
    parser.add_argument('--app-path', '-p', help='Path to the application installation')
    parser.add_argument('--server', '-s', help='Update server URL')
    parser.add_argument('--check-only', '-c', action='store_true', help='Only check for updates, don\'t download or install')
    
    args = parser.parse_args()
    
    # Create updater instance
    manifest_url = f"{args.server}/releases/latest/update_manifest.json" if args.server else MANIFEST_URL
    updater = AutoUpdater(args.version, args.app_path, manifest_url)
    
    if args.check_only:
        # Just check for updates
        update_available, manifest = updater.check_for_update()
        if update_available:
            print(f"Update available: {manifest.get('version')}")
            return 0
        else:
            print("No updates available")
            return 0
    else:
        # Perform full update
        if updater.update():
            print("Update successful")
            return 0
        else:
            print("Update failed")
            return 1

if __name__ == "__main__":
    sys.exit(main()) 