#!/usr/bin/env python3
import os
import sys
import re
from pathlib import Path
from typing import List, Dict, Set
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import time

class LinkValidator:
    def __init__(self, docs_dir: str):
        self.docs_dir = Path(docs_dir)
        self.broken_links: List[Dict[str, str]] = []
        self.checked_urls: Set[str] = set()
        self.rate_limit = 1  # seconds between requests
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if a URL is valid."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _check_url(self, url: str, source_file: str) -> bool:
        """Check if a URL is accessible."""
        if url in self.checked_urls:
            return True
        
        try:
            response = requests.head(url, allow_redirects=True, timeout=5)
            self.checked_urls.add(url)
            
            if response.status_code >= 400:
                self.broken_links.append({
                    'url': url,
                    'file': source_file,
                    'status': response.status_code
                })
                return False
            
            return True
        except requests.RequestException as e:
            self.broken_links.append({
                'url': url,
                'file': source_file,
                'error': str(e)
            })
            return False
        finally:
            time.sleep(self.rate_limit)
    
    def _check_local_link(self, link: str, source_file: str) -> bool:
        """Check if a local link is valid."""
        source_path = Path(source_file)
        
        # Handle anchor links
        if link.startswith('#'):
            return True
        
        # Handle relative paths
        if link.startswith('./'):
            link = link[2:]
        elif link.startswith('../'):
            # Count number of parent directories
            parent_count = len(re.findall(r'\.\./', link))
            link = link[parent_count * 3:]
            
            # Get parent directory
            parent_dir = source_path.parent
            for _ in range(parent_count):
                parent_dir = parent_dir.parent
            
            target_path = parent_dir / link
        else:
            target_path = source_path.parent / link
        
        # Check if file exists
        if not target_path.exists():
            self.broken_links.append({
                'url': link,
                'file': source_file,
                'error': 'File not found'
            })
            return False
        
        return True
    
    def _check_file(self, file_path: Path) -> None:
        """Check all links in a file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find all links
        link_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
        links = re.finditer(link_pattern, content)
        
        for match in links:
            link_text, link_url = match.groups()
            
            # Skip empty links
            if not link_url.strip():
                self.broken_links.append({
                    'url': link_url,
                    'file': str(file_path),
                    'error': 'Empty link'
                })
                continue
            
            # Check URL or local link
            if self._is_valid_url(link_url):
                self._check_url(link_url, str(file_path))
            else:
                self._check_local_link(link_url, str(file_path))
    
    def validate(self) -> bool:
        """Validate all links in documentation."""
        markdown_files = list(self.docs_dir.rglob('*.md'))
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(self._check_file, markdown_files)
        
        # Print results
        if self.broken_links:
            print("\nBroken links found:")
            for link in self.broken_links:
                print(f"\nFile: {link['file']}")
                print(f"Link: {link['url']}")
                if 'status' in link:
                    print(f"Status: {link['status']}")
                if 'error' in link:
                    print(f"Error: {link['error']}")
            return False
        else:
            print("No broken links found!")
            return True

def main():
    if len(sys.argv) != 2:
        print("Usage: python validate_links.py <docs_directory>")
        sys.exit(1)
    
    docs_dir = sys.argv[1]
    validator = LinkValidator(docs_dir)
    
    if not validator.validate():
        sys.exit(1)

if __name__ == '__main__':
    main() 