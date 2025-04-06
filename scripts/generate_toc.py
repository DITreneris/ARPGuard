#!/usr/bin/env python3
import os
import sys
import json
from pathlib import Path
from typing import Dict, List
import re
from datetime import datetime

class TOCGenerator:
    def __init__(self, docs_dir: str, base_url: str):
        self.docs_dir = Path(docs_dir)
        self.base_url = base_url.rstrip('/')
        self.toc = {
            'version': '1.0',
            'encoding': 'UTF-8',
            'toc': []
        }
    
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
    
    def _get_headers(self, file_path: Path) -> List[Dict[str, str]]:
        """Get headers from markdown file."""
        headers = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                # Find all headers
                header_pattern = r'^(#{1,6})\s+(.+)$'
                for match in re.finditer(header_pattern, content, re.MULTILINE):
                    level = len(match.group(1))
                    title = match.group(2).strip()
                    # Generate anchor
                    anchor = re.sub(r'[^\w\s-]', '', title.lower())
                    anchor = re.sub(r'[-\s]+', '-', anchor).strip('-')
                    headers.append({
                        'level': level,
                        'title': title,
                        'anchor': anchor
                    })
        except Exception as e:
            print(f"Error reading headers from {file_path}: {e}")
        
        return headers
    
    def _build_toc_entry(self, file_path: Path, relative_path: str) -> Dict:
        """Build TOC entry for a file."""
        title = self._get_title(file_path)
        url = f"{self.base_url}/{relative_path.replace('.md', '')}"
        headers = self._get_headers(file_path)
        
        return {
            'title': title,
            'url': url,
            'headers': headers
        }
    
    def _build_directory_toc(self, directory: Path) -> List[Dict]:
        """Build TOC for a directory."""
        entries = []
        
        # Get all markdown files and directories
        items = list(directory.iterdir())
        items.sort(key=lambda x: (not x.is_file(), x.name))
        
        for item in items:
            if item.is_file() and item.suffix == '.md':
                relative_path = str(item.relative_to(self.docs_dir)).replace('\\', '/')
                entries.append(self._build_toc_entry(item, relative_path))
            elif item.is_dir() and not any(d in str(item) for d in ['search', 'translations']):
                dir_entries = self._build_directory_toc(item)
                if dir_entries:
                    entries.append({
                        'title': item.name.replace('_', ' ').title(),
                        'children': dir_entries
                    })
        
        return entries
    
    def generate(self) -> None:
        """Generate table of contents for documentation."""
        self.toc['toc'] = self._build_directory_toc(self.docs_dir)
        
        # Save TOC
        toc_file = self.docs_dir / 'toc.json'
        with open(toc_file, 'w', encoding='utf-8') as f:
            json.dump(self.toc, f, indent=2)
        
        print(f"Table of contents generated: {toc_file}")
        print(f"Total entries: {len(self.toc['toc'])}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python generate_toc.py <docs_directory> <base_url>")
        sys.exit(1)
    
    docs_dir = sys.argv[1]
    base_url = sys.argv[2]
    
    generator = TOCGenerator(docs_dir, base_url)
    generator.generate()

if __name__ == '__main__':
    main() 