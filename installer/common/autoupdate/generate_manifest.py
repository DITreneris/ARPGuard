#!/usr/bin/env python3
"""
Generate update manifest for ARP Guard auto-update system.
This script creates a JSON manifest file containing information about the latest version.
"""

import json
import hashlib
import os
import sys
import argparse
import datetime
from typing import Dict, List, Any

def calculate_file_hash(file_path: str) -> str:
    """Calculate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read and update hash in chunks to avoid loading large files into memory
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_file_size(file_path: str) -> int:
    """Get file size in bytes."""
    return os.path.getsize(file_path)

def generate_manifest(
    version: str,
    release_date: str,
    windows_installer: str = None,
    macos_installer: str = None,
    linux_deb: str = None,
    linux_rpm: str = None,
    release_notes: str = None,
    min_version: str = None,
    output_file: str = "update_manifest.json"
) -> None:
    """Generate update manifest JSON file."""
    manifest: Dict[str, Any] = {
        "version": version,
        "releaseDate": release_date,
        "minVersion": min_version or "0.1.0",
        "mandatory": False,
        "platforms": {}
    }
    
    if release_notes:
        with open(release_notes, 'r') as f:
            manifest["releaseNotes"] = f.read()
    
    # Windows installer info
    if windows_installer and os.path.exists(windows_installer):
        manifest["platforms"]["windows"] = {
            "url": f"https://download.arpguard.com/releases/{version}/windows/ARPGuard-Setup-{version}.exe",
            "sha256": calculate_file_hash(windows_installer),
            "size": get_file_size(windows_installer),
            "filename": f"ARPGuard-Setup-{version}.exe"
        }
    
    # macOS installer info
    if macos_installer and os.path.exists(macos_installer):
        manifest["platforms"]["macos"] = {
            "url": f"https://download.arpguard.com/releases/{version}/macos/ARPGuard-{version}.dmg",
            "sha256": calculate_file_hash(macos_installer),
            "size": get_file_size(macos_installer),
            "filename": f"ARPGuard-{version}.dmg"
        }
    
    # Linux DEB installer info
    if linux_deb and os.path.exists(linux_deb):
        manifest["platforms"]["linux-deb"] = {
            "url": f"https://download.arpguard.com/releases/{version}/linux/arpguard_{version}_amd64.deb",
            "sha256": calculate_file_hash(linux_deb),
            "size": get_file_size(linux_deb),
            "filename": f"arpguard_{version}_amd64.deb"
        }
    
    # Linux RPM installer info
    if linux_rpm and os.path.exists(linux_rpm):
        manifest["platforms"]["linux-rpm"] = {
            "url": f"https://download.arpguard.com/releases/{version}/linux/arpguard-{version}.rpm",
            "sha256": calculate_file_hash(linux_rpm),
            "size": get_file_size(linux_rpm),
            "filename": f"arpguard-{version}.rpm"
        }
    
    # Write manifest to file
    with open(output_file, 'w') as f:
        json.dump(manifest, f, indent=2)
    
    print(f"Manifest generated: {output_file}")

def main() -> None:
    """Main function to parse arguments and generate manifest."""
    parser = argparse.ArgumentParser(description="Generate update manifest for ARP Guard")
    parser.add_argument("--version", required=True, help="Version number (e.g., 0.3.0)")
    parser.add_argument("--date", help="Release date (YYYY-MM-DD), defaults to today")
    parser.add_argument("--windows", help="Path to Windows installer")
    parser.add_argument("--macos", help="Path to macOS installer")
    parser.add_argument("--linux-deb", help="Path to Linux DEB package")
    parser.add_argument("--linux-rpm", help="Path to Linux RPM package")
    parser.add_argument("--notes", help="Path to release notes markdown file")
    parser.add_argument("--min-version", help="Minimum version required for update")
    parser.add_argument("--output", default="update_manifest.json", help="Output manifest filename")
    
    args = parser.parse_args()
    
    release_date = args.date or datetime.datetime.now().strftime("%Y-%m-%d")
    
    generate_manifest(
        version=args.version,
        release_date=release_date,
        windows_installer=args.windows,
        macos_installer=args.macos,
        linux_deb=args.linux_deb,
        linux_rpm=args.linux_rpm,
        release_notes=args.notes,
        min_version=args.min_version,
        output_file=args.output
    )

if __name__ == "__main__":
    main() 