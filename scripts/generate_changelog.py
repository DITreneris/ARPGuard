#!/usr/bin/env python3
import os
import sys
import json
from pathlib import Path
from typing import Dict, List
import re
from datetime import datetime
import subprocess
from collections import defaultdict

class ChangelogGenerator:
    def __init__(self, docs_dir: str, git_dir: str):
        self.docs_dir = Path(docs_dir)
        self.git_dir = Path(git_dir)
        self.changelog = {
            'version': '1.0',
            'encoding': 'UTF-8',
            'changes': [],
            'metadata': {
                'total_changes': 0,
                'generated_at': datetime.now().isoformat()
            }
        }
    
    def _get_git_log(self) -> List[Dict]:
        """Get git log for documentation changes."""
        try:
            # Change to git directory
            os.chdir(self.git_dir)
            
            # Get git log for docs directory
            cmd = [
                'git', 'log',
                '--pretty=format:%H|%an|%ad|%s',
                '--date=iso',
                '--', str(self.docs_dir)
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Error getting git log: {result.stderr}")
                return []
            
            # Parse git log
            changes = []
            for line in result.stdout.split('\n'):
                if not line:
                    continue
                
                commit_hash, author, date, message = line.split('|', 3)
                changes.append({
                    'commit': commit_hash,
                    'author': author,
                    'date': date,
                    'message': message
                })
            
            return changes
        
        except Exception as e:
            print(f"Error getting git log: {e}")
            return []
    
    def _get_file_changes(self, commit: str) -> Dict[str, str]:
        """Get file changes for a commit."""
        try:
            cmd = [
                'git', 'show',
                '--name-status',
                '--pretty=format:',
                commit,
                '--', str(self.docs_dir)
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Error getting file changes: {result.stderr}")
                return {}
            
            # Parse file changes
            changes = {}
            for line in result.stdout.split('\n'):
                if not line:
                    continue
                
                status, path = line.split('\t', 1)
                changes[path] = status
            
            return changes
        
        except Exception as e:
            print(f"Error getting file changes: {e}")
            return {}
    
    def _categorize_change(self, message: str) -> str:
        """Categorize change based on commit message."""
        message = message.lower()
        
        if any(word in message for word in ['add', 'create', 'new']):
            return 'added'
        elif any(word in message for word in ['update', 'modify', 'change']):
            return 'changed'
        elif any(word in message for word in ['remove', 'delete', 'drop']):
            return 'removed'
        elif any(word in message for word in ['fix', 'bug', 'error']):
            return 'fixed'
        else:
            return 'other'
    
    def generate(self) -> None:
        """Generate changelog for documentation."""
        changes = self._get_git_log()
        
        for change in changes:
            file_changes = self._get_file_changes(change['commit'])
            
            if not file_changes:
                continue
            
            # Add change to changelog
            self.changelog['changes'].append({
                'commit': change['commit'],
                'author': change['author'],
                'date': change['date'],
                'message': change['message'],
                'type': self._categorize_change(change['message']),
                'files': file_changes
            })
        
        # Sort changes by date
        self.changelog['changes'].sort(key=lambda x: x['date'], reverse=True)
        
        # Update metadata
        self.changelog['metadata']['total_changes'] = len(self.changelog['changes'])
        
        # Group changes by type
        changes_by_type = defaultdict(list)
        for change in self.changelog['changes']:
            changes_by_type[change['type']].append(change)
        
        # Save changelog
        changelog_file = self.docs_dir / 'changelog.json'
        with open(changelog_file, 'w', encoding='utf-8') as f:
            json.dump(self.changelog, f, indent=2)
        
        # Print summary
        print(f"Changelog generated: {changelog_file}")
        print(f"Total changes: {self.changelog['metadata']['total_changes']}")
        print("\nChanges by type:")
        for change_type, changes in changes_by_type.items():
            print(f"  {change_type}: {len(changes)}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python generate_changelog.py <docs_directory> <git_directory>")
        sys.exit(1)
    
    docs_dir = sys.argv[1]
    git_dir = sys.argv[2]
    
    generator = ChangelogGenerator(docs_dir, git_dir)
    generator.generate()

if __name__ == '__main__':
    main() 