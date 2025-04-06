#!/usr/bin/env python3
import os
import sys
import json
from pathlib import Path
from typing import Dict, List, Optional
import re
from datetime import datetime
import yaml
import hashlib
from collections import defaultdict
import git

class DocumentVersioner:
    def __init__(self, docs_dir: str):
        self.docs_dir = Path(docs_dir)
        self.version_file = self.docs_dir / 'docs_versions.json'
        self.versions_data = self._load_versions_data()
        self.repo = git.Repo(self.docs_dir.parent)
        
    def _load_versions_data(self) -> Dict:
        """Load version tracking data from JSON file."""
        if self.version_file.exists():
            with open(self.version_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            'version': '1.0',
            'documents': {},
            'last_updated': datetime.now().isoformat(),
            'metadata': {
                'total_versions': 0,
                'total_documents': 0
            }
        }
    
    def _save_versions_data(self) -> None:
        """Save version tracking data to JSON file."""
        self.versions_data['last_updated'] = datetime.now().isoformat()
        with open(self.version_file, 'w', encoding='utf-8') as f:
            json.dump(self.versions_data, f, indent=2)
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file content."""
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    
    def _extract_frontmatter(self, content: str) -> Dict:
        """Extract frontmatter from markdown file."""
        frontmatter = {}
        frontmatter_match = re.search(r'^---\n([\s\S]*?)\n---', content)
        
        if frontmatter_match:
            try:
                frontmatter = yaml.safe_load(frontmatter_match.group(1))
            except Exception as e:
                print(f"Error parsing frontmatter: {e}")
        
        return frontmatter
    
    def _get_git_history(self, file_path: Path) -> List[Dict]:
        """Get git commit history for a file."""
        try:
            commits = list(self.repo.iter_commits(paths=str(file_path)))
            history = []
            for commit in commits:
                history.append({
                    'hash': commit.hexsha,
                    'author': commit.author.name,
                    'date': commit.committed_datetime.isoformat(),
                    'message': commit.message.strip()
                })
            return history
        except Exception as e:
            print(f"Error getting git history for {file_path}: {e}")
            return []
    
    def _update_document_version(self, file_path: Path) -> None:
        """Update version information for a document."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            file_hash = self._calculate_file_hash(file_path)
            relative_path = str(file_path.relative_to(self.docs_dir))
            
            # Get document metadata
            frontmatter = self._extract_frontmatter(content)
            git_history = self._get_git_history(file_path)
            
            # Update version data
            doc_id = str(file_path)
            if doc_id not in self.versions_data['documents']:
                self.versions_data['documents'][doc_id] = {
                    'path': relative_path,
                    'versions': [],
                    'current_version': 1,
                    'last_modified': datetime.now().isoformat(),
                    'git_history': git_history
                }
                self.versions_data['metadata']['total_documents'] += 1
            
            current_doc = self.versions_data['documents'][doc_id]
            if not current_doc['versions'] or current_doc['versions'][-1]['hash'] != file_hash:
                # New version detected
                version_number = current_doc['current_version'] + 1
                current_doc['versions'].append({
                    'version': version_number,
                    'hash': file_hash,
                    'timestamp': datetime.now().isoformat(),
                    'frontmatter': frontmatter
                })
                current_doc['current_version'] = version_number
                current_doc['last_modified'] = datetime.now().isoformat()
                current_doc['git_history'] = git_history
                self.versions_data['metadata']['total_versions'] += 1
            
        except Exception as e:
            print(f"Error updating version for {file_path}: {e}")
    
    def _update_frontmatter(self, file_path: Path) -> None:
        """Update document frontmatter with version information."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            doc_id = str(file_path)
            if doc_id not in self.versions_data['documents']:
                return
            
            doc_info = self.versions_data['documents'][doc_id]
            frontmatter = self._extract_frontmatter(content)
            
            # Update frontmatter with version info
            frontmatter['version'] = doc_info['current_version']
            frontmatter['last_modified'] = doc_info['last_modified']
            frontmatter['git_history'] = doc_info['git_history']
            
            # Convert frontmatter to YAML
            frontmatter_yaml = yaml.dump(frontmatter, default_flow_style=False, sort_keys=False)
            
            # Replace existing frontmatter or add new one
            if re.search(r'^---\n[\s\S]*?\n---', content):
                new_content = re.sub(
                    r'^---\n[\s\S]*?\n---',
                    f'---\n{frontmatter_yaml}---',
                    content
                )
            else:
                new_content = f'---\n{frontmatter_yaml}---\n\n{content}'
            
            # Write updated content back to file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
        except Exception as e:
            print(f"Error updating frontmatter for {file_path}: {e}")
    
    def scan_documents(self) -> None:
        """Scan all documents and update version information."""
        markdown_files = list(self.docs_dir.rglob('*.md'))
        
        for file_path in markdown_files:
            # Skip files in specific directories
            if any(d in str(file_path) for d in ['search', 'translations']):
                continue
            
            self._update_document_version(file_path)
            self._update_frontmatter(file_path)
        
        self._save_versions_data()
        print(f"Documentation versions updated: {self.version_file}")
        print(f"Total documents tracked: {self.versions_data['metadata']['total_documents']}")
        print(f"Total versions: {self.versions_data['metadata']['total_versions']}")
    
    def get_version_history(self, file_path: str) -> None:
        """Get version history for a document."""
        doc_path = self.docs_dir / file_path
        if not doc_path.exists():
            print(f"Document not found: {file_path}")
            return
        
        doc_id = str(doc_path)
        if doc_id in self.versions_data['documents']:
            doc = self.versions_data['documents'][doc_id]
            print(f"\nVersion History for: {doc['path']}")
            print(f"Current Version: {doc['current_version']}")
            print(f"Last Modified: {doc['last_modified']}")
            print("\nVersions:")
            for version in doc['versions']:
                print(f"\nVersion {version['version']}:")
                print(f"  Timestamp: {version['timestamp']}")
                print(f"  Hash: {version['hash']}")
                if 'frontmatter' in version:
                    print("  Frontmatter:")
                    for key, value in version['frontmatter'].items():
                        print(f"    {key}: {value}")
            
            print("\nGit History:")
            for commit in doc['git_history']:
                print(f"\n  Commit: {commit['hash']}")
                print(f"  Author: {commit['author']}")
                print(f"  Date: {commit['date']}")
                print(f"  Message: {commit['message']}")
        else:
            print(f"No version history found for: {file_path}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python version_docs.py <command> [args]")
        print("\nCommands:")
        print("  scan                 Scan all documents and update versions")
        print("  history <file>       Get version history for a document")
        sys.exit(1)
    
    command = sys.argv[1]
    docs_dir = os.getenv('DOCS_DIR', 'docs')
    
    versioner = DocumentVersioner(docs_dir)
    
    if command == 'scan':
        versioner.scan_documents()
    elif command == 'history':
        if len(sys.argv) < 3:
            print("Error: File path required")
            sys.exit(1)
        versioner.get_version_history(sys.argv[2])
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main() 