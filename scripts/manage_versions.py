#!/usr/bin/env python3
import os
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import subprocess
import re

class VersionManager:
    def __init__(self, docs_dir: str):
        self.docs_dir = Path(docs_dir)
        self.versions_file = self.docs_dir / 'versions.json'
        self.versions: Dict[str, Dict] = {}
        
        if self.versions_file.exists():
            with open(self.versions_file, 'r', encoding='utf-8') as f:
                self.versions = json.load(f)
    
    def _validate_version(self, version: str) -> bool:
        """Validate version string format (semantic versioning)."""
        pattern = r'^\d+\.\d+\.\d+$'
        return bool(re.match(pattern, version))
    
    def _get_git_changes(self) -> List[str]:
        """Get list of changed files from git."""
        try:
            result = subprocess.run(
                ['git', 'diff', '--name-only', 'HEAD'],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip().split('\n')
        except subprocess.CalledProcessError:
            return []
    
    def create_version(self, version: str, description: str) -> None:
        """Create a new documentation version."""
        if not self._validate_version(version):
            print(f"Invalid version format: {version}")
            print("Version must follow semantic versioning (e.g., 1.0.0)")
            sys.exit(1)
        
        if version in self.versions:
            print(f"Version {version} already exists")
            sys.exit(1)
        
        # Get changed files
        changed_files = self._get_git_changes()
        
        # Create version entry
        self.versions[version] = {
            'date': datetime.now().isoformat(),
            'description': description,
            'changes': changed_files
        }
        
        # Save versions
        with open(self.versions_file, 'w', encoding='utf-8') as f:
            json.dump(self.versions, f, indent=2)
        
        print(f"Created version {version}")
    
    def list_versions(self) -> None:
        """List all documentation versions."""
        if not self.versions:
            print("No versions found")
            return
        
        print("Documentation Versions:")
        for version, info in sorted(self.versions.items(), reverse=True):
            print(f"\nVersion: {version}")
            print(f"Date: {info['date']}")
            print(f"Description: {info['description']}")
            print("Changes:")
            for change in info['changes']:
                print(f"  - {change}")
    
    def get_version(self, version: str) -> Optional[Dict]:
        """Get information about a specific version."""
        return self.versions.get(version)
    
    def delete_version(self, version: str) -> None:
        """Delete a documentation version."""
        if version not in self.versions:
            print(f"Version {version} not found")
            sys.exit(1)
        
        del self.versions[version]
        
        with open(self.versions_file, 'w', encoding='utf-8') as f:
            json.dump(self.versions, f, indent=2)
        
        print(f"Deleted version {version}")
    
    def update_version(self, version: str, description: Optional[str] = None) -> None:
        """Update a documentation version."""
        if version not in self.versions:
            print(f"Version {version} not found")
            sys.exit(1)
        
        if description:
            self.versions[version]['description'] = description
        
        # Update changes
        self.versions[version]['changes'] = self._get_git_changes()
        
        with open(self.versions_file, 'w', encoding='utf-8') as f:
            json.dump(self.versions, f, indent=2)
        
        print(f"Updated version {version}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python manage_versions.py <command> [options]")
        print("\nCommands:")
        print("  create <version> <description>  Create a new version")
        print("  list                           List all versions")
        print("  get <version>                  Get version information")
        print("  delete <version>               Delete a version")
        print("  update <version> [description] Update a version")
        sys.exit(1)
    
    command = sys.argv[1]
    manager = VersionManager('docs')
    
    if command == 'create':
        if len(sys.argv) != 4:
            print("Usage: python manage_versions.py create <version> <description>")
            sys.exit(1)
        manager.create_version(sys.argv[2], sys.argv[3])
    
    elif command == 'list':
        manager.list_versions()
    
    elif command == 'get':
        if len(sys.argv) != 3:
            print("Usage: python manage_versions.py get <version>")
            sys.exit(1)
        version_info = manager.get_version(sys.argv[2])
        if version_info:
            print(f"Version: {sys.argv[2]}")
            print(f"Date: {version_info['date']}")
            print(f"Description: {version_info['description']}")
            print("Changes:")
            for change in version_info['changes']:
                print(f"  - {change}")
        else:
            print(f"Version {sys.argv[2]} not found")
    
    elif command == 'delete':
        if len(sys.argv) != 3:
            print("Usage: python manage_versions.py delete <version>")
            sys.exit(1)
        manager.delete_version(sys.argv[2])
    
    elif command == 'update':
        if len(sys.argv) < 3:
            print("Usage: python manage_versions.py update <version> [description]")
            sys.exit(1)
        description = sys.argv[3] if len(sys.argv) > 3 else None
        manager.update_version(sys.argv[2], description)
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main() 