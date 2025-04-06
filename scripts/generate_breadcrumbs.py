#!/usr/bin/env python3
import os
import sys
import json
from pathlib import Path
from typing import Dict, List
import re
from datetime import datetime

class BreadcrumbGenerator:
    def __init__(self, docs_dir: str, base_url: str):
        self.docs_dir = Path(docs_dir)
        self.base_url = base_url.rstrip('/')
        self.breadcrumbs = {}
    
    def _get_title(self, file_path: Path) -> str:
        """Get title from markdown file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                first_line = f.readline().strip()
                if first_line.startswith('# '):
                    return first_line[2:].strip()
        except Exception as e:
            print(f"Error reading title from {file_path}: {e}")
        
        # Fallback to filename
        return file_path.stem.replace('_', ' ').title()
    
    def _get_parent_path(self, file_path: Path) -> Path:
        """Get parent directory path."""
        return file_path.parent
    
    def _get_breadcrumb_path(self, file_path: Path) -> List[Dict[str, str]]:
        """Generate breadcrumb path for a file."""
        path = []
        current = file_path
        
        while current != self.docs_dir:
            if current.is_file():
                title = self._get_title(current)
                url = str(current.relative_to(self.docs_dir)).replace('\\', '/').replace('.md', '')
            else:
                title = current.name.replace('_', ' ').title()
                url = str(current.relative_to(self.docs_dir)).replace('\\', '/')
            
            path.insert(0, {
                'title': title,
                'url': f"{self.base_url}/{url}"
            })
            
            current = current.parent
        
        # Add root
        path.insert(0, {
            'title': 'Home',
            'url': self.base_url
        })
        
        return path
    
    def generate(self) -> None:
        """Generate breadcrumbs for documentation."""
        markdown_files = list(self.docs_dir.rglob('*.md'))
        
        for file_path in markdown_files:
            # Skip files in specific directories
            if any(d in str(file_path) for d in ['search', 'translations']):
                continue
            
            # Generate breadcrumb path
            relative_path = str(file_path.relative_to(self.docs_dir)).replace('\\', '/')
            self.breadcrumbs[relative_path] = self._get_breadcrumb_path(file_path)
        
        # Save breadcrumbs
        breadcrumbs_file = self.docs_dir / 'breadcrumbs.json'
        with open(breadcrumbs_file, 'w', encoding='utf-8') as f:
            json.dump(self.breadcrumbs, f, indent=2)
        
        print(f"Breadcrumbs generated: {breadcrumbs_file}")
        print(f"Total files with breadcrumbs: {len(self.breadcrumbs)}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python generate_breadcrumbs.py <docs_directory> <base_url>")
        sys.exit(1)
    
    docs_dir = sys.argv[1]
    base_url = sys.argv[2]
    
    generator = BreadcrumbGenerator(docs_dir, base_url)
    generator.generate()

if __name__ == '__main__':
    main() 