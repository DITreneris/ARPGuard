#!/usr/bin/env python3
import os
import sys
import json
from pathlib import Path
from typing import Dict, List
import re
from datetime import datetime
import xml.etree.ElementTree as ET

class SitemapGenerator:
    def __init__(self, docs_dir: str, base_url: str):
        self.docs_dir = Path(docs_dir)
        self.base_url = base_url.rstrip('/')
        self.sitemap = {
            'version': '1.0',
            'encoding': 'UTF-8',
            'urlset': {
                'xmlns': 'http://www.sitemaps.org/schemas/sitemap/0.9',
                'urls': []
            }
        }
    
    def _get_last_modified(self, file_path: Path) -> str:
        """Get last modified date of a file."""
        return datetime.fromtimestamp(file_path.stat().st_mtime).strftime('%Y-%m-%d')
    
    def _get_priority(self, file_path: Path) -> float:
        """Get priority for a file based on its depth."""
        depth = len(str(file_path.relative_to(self.docs_dir)).split('/'))
        
        if depth == 1:
            return 1.0
        elif depth == 2:
            return 0.8
        elif depth == 3:
            return 0.6
        else:
            return 0.4
    
    def _get_change_freq(self, file_path: Path) -> str:
        """Get change frequency for a file."""
        # Check if file is in specific directories
        if 'api' in str(file_path):
            return 'weekly'
        elif 'guides' in str(file_path):
            return 'monthly'
        else:
            return 'yearly'
    
    def generate(self) -> None:
        """Generate sitemap for documentation."""
        markdown_files = list(self.docs_dir.rglob('*.md'))
        
        for file_path in markdown_files:
            # Skip files in specific directories
            if any(d in str(file_path) for d in ['search', 'translations']):
                continue
            
            # Convert file path to URL
            relative_path = str(file_path.relative_to(self.docs_dir))
            url_path = relative_path.replace('\\', '/').replace('.md', '')
            url = f"{self.base_url}/{url_path}"
            
            # Add URL to sitemap
            self.sitemap['urlset']['urls'].append({
                'loc': url,
                'lastmod': self._get_last_modified(file_path),
                'changefreq': self._get_change_freq(file_path),
                'priority': self._get_priority(file_path)
            })
        
        # Create XML sitemap
        root = ET.Element('urlset')
        root.set('xmlns', self.sitemap['urlset']['xmlns'])
        
        for url in self.sitemap['urlset']['urls']:
            url_elem = ET.SubElement(root, 'url')
            
            loc = ET.SubElement(url_elem, 'loc')
            loc.text = url['loc']
            
            lastmod = ET.SubElement(url_elem, 'lastmod')
            lastmod.text = url['lastmod']
            
            changefreq = ET.SubElement(url_elem, 'changefreq')
            changefreq.text = url['changefreq']
            
            priority = ET.SubElement(url_elem, 'priority')
            priority.text = str(url['priority'])
        
        # Save sitemap
        sitemap_file = self.docs_dir / 'sitemap.xml'
        tree = ET.ElementTree(root)
        tree.write(sitemap_file, encoding='utf-8', xml_declaration=True)
        
        print(f"Sitemap generated: {sitemap_file}")
        print(f"Total URLs: {len(self.sitemap['urlset']['urls'])}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python generate_sitemap.py <docs_directory> <base_url>")
        sys.exit(1)
    
    docs_dir = sys.argv[1]
    base_url = sys.argv[2]
    
    generator = SitemapGenerator(docs_dir, base_url)
    generator.generate()

if __name__ == '__main__':
    main() 