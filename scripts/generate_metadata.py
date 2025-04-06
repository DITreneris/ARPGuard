#!/usr/bin/env python3
import os
import sys
import json
from pathlib import Path
from typing import Dict, List
import re
from datetime import datetime
import yaml

class MetadataGenerator:
    def __init__(self, docs_dir: str, base_url: str):
        self.docs_dir = Path(docs_dir)
        self.base_url = base_url.rstrip('/')
        self.metadata = {
            'version': '1.0',
            'encoding': 'UTF-8',
            'documents': {},
            'categories': {},
            'tags': {},
            'authors': {},
            'metadata': {
                'total_documents': 0,
                'total_categories': 0,
                'total_tags': 0,
                'total_authors': 0,
                'generated_at': datetime.now().isoformat()
            }
        }
    
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
    
    def _get_title(self, content: str, file_path: Path) -> str:
        """Get title from markdown file."""
        title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
        return title_match.group(1) if title_match else file_path.stem.replace('_', ' ').title()
    
    def _get_description(self, content: str) -> str:
        """Get description from markdown file."""
        # Remove frontmatter and first header
        content = re.sub(r'^---\n[\s\S]*?\n---', '', content)
        content = re.sub(r'^#\s+.+$', '', content, flags=re.MULTILINE)
        
        # Get first paragraph
        paragraph_match = re.search(r'^\s*([^\n]+)', content, re.MULTILINE)
        return paragraph_match.group(1).strip() if paragraph_match else ''
    
    def _get_last_modified(self, file_path: Path) -> str:
        """Get last modified date of a file."""
        return datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
    
    def _process_document(self, file_path: Path) -> None:
        """Process a document and extract metadata."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Get basic information
                relative_path = str(file_path.relative_to(self.docs_dir)).replace('\\', '/')
                url = f"{self.base_url}/{relative_path.replace('.md', '')}"
                title = self._get_title(content, file_path)
                description = self._get_description(content)
                last_modified = self._get_last_modified(file_path)
                
                # Extract frontmatter
                frontmatter = self._extract_frontmatter(content)
                
                # Get categories and tags
                categories = frontmatter.get('categories', [])
                tags = frontmatter.get('tags', [])
                author = frontmatter.get('author', 'Unknown')
                
                # Add to documents
                doc_id = str(file_path)
                self.metadata['documents'][doc_id] = {
                    'title': title,
                    'description': description,
                    'url': url,
                    'path': relative_path,
                    'last_modified': last_modified,
                    'categories': categories,
                    'tags': tags,
                    'author': author
                }
                
                # Add to categories
                for category in categories:
                    if category not in self.metadata['categories']:
                        self.metadata['categories'][category] = []
                    self.metadata['categories'][category].append(doc_id)
                
                # Add to tags
                for tag in tags:
                    if tag not in self.metadata['tags']:
                        self.metadata['tags'][tag] = []
                    self.metadata['tags'][tag].append(doc_id)
                
                # Add to authors
                if author not in self.metadata['authors']:
                    self.metadata['authors'][author] = []
                self.metadata['authors'][author].append(doc_id)
                
                self.metadata['metadata']['total_documents'] += 1
                self.metadata['metadata']['total_categories'] = len(self.metadata['categories'])
                self.metadata['metadata']['total_tags'] = len(self.metadata['tags'])
                self.metadata['metadata']['total_authors'] = len(self.metadata['authors'])
                
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
    
    def generate(self) -> None:
        """Generate metadata for documentation."""
        markdown_files = list(self.docs_dir.rglob('*.md'))
        
        for file_path in markdown_files:
            # Skip files in specific directories
            if any(d in str(file_path) for d in ['search', 'translations']):
                continue
            
            self._process_document(file_path)
        
        # Save metadata
        metadata_file = self.docs_dir / 'metadata.json'
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(self.metadata, f, indent=2)
        
        print(f"Metadata generated: {metadata_file}")
        print(f"Total documents: {self.metadata['metadata']['total_documents']}")
        print(f"Total categories: {self.metadata['metadata']['total_categories']}")
        print(f"Total tags: {self.metadata['metadata']['total_tags']}")
        print(f"Total authors: {self.metadata['metadata']['total_authors']}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python generate_metadata.py <docs_directory> <base_url>")
        sys.exit(1)
    
    docs_dir = sys.argv[1]
    base_url = sys.argv[2]
    
    generator = MetadataGenerator(docs_dir, base_url)
    generator.generate()

if __name__ == '__main__':
    main() 