#!/usr/bin/env python3
import os
import sys
import json
from pathlib import Path
from typing import Dict, Optional
import re
from datetime import datetime
import yaml

class FrontmatterUpdater:
    def __init__(self, docs_dir: str):
        self.docs_dir = Path(docs_dir)
        self.tracking_file = self.docs_dir / 'docs_tracking.json'
        self.tracking_data = self._load_tracking_data()
    
    def _load_tracking_data(self) -> Dict:
        """Load tracking data from JSON file."""
        if self.tracking_file.exists():
            with open(self.tracking_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {'documents': {}}
    
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
    
    def _update_frontmatter(self, file_path: Path) -> None:
        """Update frontmatter with tracking information."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            doc_id = str(file_path)
            if doc_id not in self.tracking_data['documents']:
                print(f"No tracking data found for: {file_path}")
                return
            
            tracking_info = self.tracking_data['documents'][doc_id]
            frontmatter = self._extract_frontmatter(content)
            
            # Update frontmatter with tracking information
            frontmatter['status'] = tracking_info['status']
            frontmatter['created_at'] = tracking_info['created_at']
            frontmatter['last_modified'] = tracking_info['last_modified']
            
            if 'completed_at' in tracking_info:
                frontmatter['completed_at'] = tracking_info['completed_at']
            if 'reviewed_at' in tracking_info:
                frontmatter['reviewed_at'] = tracking_info['reviewed_at']
            
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
            
            print(f"Updated frontmatter for: {file_path}")
            
        except Exception as e:
            print(f"Error updating frontmatter for {file_path}: {e}")
    
    def update_all(self) -> None:
        """Update frontmatter for all documents."""
        markdown_files = list(self.docs_dir.rglob('*.md'))
        
        for file_path in markdown_files:
            # Skip files in specific directories
            if any(d in str(file_path) for d in ['search', 'translations']):
                continue
            
            self._update_frontmatter(file_path)
        
        print("Frontmatter update completed")
    
    def update_single(self, file_path: str) -> None:
        """Update frontmatter for a single document."""
        doc_path = self.docs_dir / file_path
        if not doc_path.exists():
            print(f"Document not found: {file_path}")
            return
        
        self._update_frontmatter(doc_path)

def main():
    if len(sys.argv) < 2:
        print("Usage: python update_frontmatter.py <command> [file]")
        print("\nCommands:")
        print("  all                  Update frontmatter for all documents")
        print("  single <file>        Update frontmatter for a single document")
        sys.exit(1)
    
    command = sys.argv[1]
    docs_dir = os.getenv('DOCS_DIR', 'docs')
    
    updater = FrontmatterUpdater(docs_dir)
    
    if command == 'all':
        updater.update_all()
    elif command == 'single':
        if len(sys.argv) < 3:
            print("Error: File path required")
            sys.exit(1)
        updater.update_single(sys.argv[2])
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main() 