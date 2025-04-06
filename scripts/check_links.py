#!/usr/bin/env python3
import os
import re
import sys
from pathlib import Path
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

def check_link(link, source_file):
    """Check if a link is valid."""
    if link.startswith('http'):
        try:
            response = requests.head(link, allow_redirects=True, timeout=5)
            if response.status_code >= 400:
                print(f"Broken link in {source_file}: {link} (Status: {response.status_code})")
                return False
        except requests.RequestException as e:
            print(f"Error checking link in {source_file}: {link} ({str(e)})")
            return False
    else:
        # Local link
        target_path = (Path(source_file).parent / link).resolve()
        if not target_path.exists():
            print(f"Broken local link in {source_file}: {link}")
            return False
    return True

def check_file(file_path):
    """Check all links in a file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find all links
    link_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
    links = re.finditer(link_pattern, content)
    
    results = []
    for match in links:
        link_text, link_url = match.groups()
        if not check_link(link_url, file_path):
            results.append((link_url, file_path))
    
    return results

def main():
    if len(sys.argv) != 2:
        print("Usage: python check_links.py <docs_directory>")
        sys.exit(1)
    
    docs_dir = Path(sys.argv[1])
    if not docs_dir.exists():
        print(f"Directory not found: {docs_dir}")
        sys.exit(1)
    
    # Find all markdown files
    markdown_files = list(docs_dir.rglob('*.md'))
    
    # Check links in parallel
    broken_links = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(check_file, markdown_files)
        for result in results:
            broken_links.extend(result)
    
    if broken_links:
        print("\nBroken links found:")
        for link, file in broken_links:
            print(f"- {link} in {file}")
        sys.exit(1)
    else:
        print("All links are valid!")
        sys.exit(0)

if __name__ == '__main__':
    main() 