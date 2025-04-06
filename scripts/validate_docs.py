#!/usr/bin/env python3
import os
import sys
import json
from pathlib import Path
from typing import Dict, List
import re
from datetime import datetime
import yaml
from collections import defaultdict

class DocumentationValidator:
    def __init__(self, docs_dir: str):
        self.docs_dir = Path(docs_dir)
        self.tracking_file = self.docs_dir / 'docs_tracking.json'
        self.tracking_data = self._load_tracking_data()
        self.validation_results = {
            'version': '1.0',
            'timestamp': datetime.now().isoformat(),
            'errors': [],
            'warnings': [],
            'stats': {
                'total_files': 0,
                'valid_files': 0,
                'files_with_errors': 0,
                'files_with_warnings': 0
            }
        }
    
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
                self.validation_results['errors'].append({
                    'file': 'unknown',
                    'line': 1,
                    'message': f'Invalid frontmatter: {str(e)}'
                })
        
        return frontmatter
    
    def _validate_frontmatter(self, file_path: Path, frontmatter: Dict) -> None:
        """Validate document frontmatter."""
        required_fields = ['title', 'description', 'author']
        for field in required_fields:
            if field not in frontmatter:
                self.validation_results['errors'].append({
                    'file': str(file_path),
                    'line': 1,
                    'message': f'Missing required frontmatter field: {field}'
                })
    
    def _validate_headers(self, file_path: Path, content: str) -> None:
        """Validate markdown headers."""
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if line.startswith('#'):
                # Check header level
                level = len(line.split()[0])
                if level > 6:
                    self.validation_results['warnings'].append({
                        'file': str(file_path),
                        'line': i,
                        'message': f'Header level {level} exceeds maximum recommended level of 6'
                    })
                
                # Check header format
                if not re.match(r'^#+\s+.+$', line):
                    self.validation_results['errors'].append({
                        'file': str(file_path),
                        'line': i,
                        'message': 'Invalid header format'
                    })
    
    def _validate_links(self, file_path: Path, content: str) -> None:
        """Validate markdown links."""
        # Check for broken links
        link_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
        for match in re.finditer(link_pattern, content):
            link_text, link_url = match.groups()
            
            # Check for empty links
            if not link_text.strip():
                self.validation_results['errors'].append({
                    'file': str(file_path),
                    'line': content[:match.start()].count('\n') + 1,
                    'message': 'Empty link text'
                })
            
            # Check for empty URLs
            if not link_url.strip():
                self.validation_results['errors'].append({
                    'file': str(file_path),
                    'line': content[:match.start()].count('\n') + 1,
                    'message': 'Empty link URL'
                })
    
    def _validate_code_blocks(self, file_path: Path, content: str) -> None:
        """Validate code blocks."""
        code_block_pattern = r'```[\s\S]*?```'
        for match in re.finditer(code_block_pattern, content):
            code_block = match.group()
            
            # Check for language specification
            if not re.match(r'^```\w+', code_block):
                self.validation_results['warnings'].append({
                    'file': str(file_path),
                    'line': content[:match.start()].count('\n') + 1,
                    'message': 'Code block missing language specification'
                })
    
    def _validate_images(self, file_path: Path, content: str) -> None:
        """Validate markdown images."""
        image_pattern = r'!\[([^\]]*)\]\(([^)]+)\)'
        for match in re.finditer(image_pattern, content):
            alt_text, image_path = match.groups()
            
            # Check for empty alt text
            if not alt_text.strip():
                self.validation_results['warnings'].append({
                    'file': str(file_path),
                    'line': content[:match.start()].count('\n') + 1,
                    'message': 'Image missing alt text'
                })
            
            # Check if image exists
            image_full_path = self.docs_dir / image_path
            if not image_full_path.exists():
                self.validation_results['errors'].append({
                    'file': str(file_path),
                    'line': content[:match.start()].count('\n') + 1,
                    'message': f'Image not found: {image_path}'
                })
    
    def _validate_document(self, file_path: Path) -> None:
        """Validate a single document."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Update stats
            self.validation_results['stats']['total_files'] += 1
            
            # Extract and validate frontmatter
            frontmatter = self._extract_frontmatter(content)
            self._validate_frontmatter(file_path, frontmatter)
            
            # Validate document content
            self._validate_headers(file_path, content)
            self._validate_links(file_path, content)
            self._validate_code_blocks(file_path, content)
            self._validate_images(file_path, content)
            
            # Update validation stats
            if not any(e['file'] == str(file_path) for e in self.validation_results['errors']):
                self.validation_results['stats']['valid_files'] += 1
            else:
                self.validation_results['stats']['files_with_errors'] += 1
            
            if any(w['file'] == str(file_path) for w in self.validation_results['warnings']):
                self.validation_results['stats']['files_with_warnings'] += 1
            
        except Exception as e:
            self.validation_results['errors'].append({
                'file': str(file_path),
                'line': 1,
                'message': f'Error reading file: {str(e)}'
            })
    
    def validate(self) -> None:
        """Validate all documentation files."""
        markdown_files = list(self.docs_dir.rglob('*.md'))
        
        for file_path in markdown_files:
            # Skip files in specific directories
            if any(d in str(file_path) for d in ['search', 'translations']):
                continue
            
            self._validate_document(file_path)
        
        # Save validation results
        results_file = self.docs_dir / 'validation_results.json'
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(self.validation_results, f, indent=2)
        
        # Print summary
        print("\nDocumentation Validation Summary:")
        print(f"Total Files: {self.validation_results['stats']['total_files']}")
        print(f"Valid Files: {self.validation_results['stats']['valid_files']}")
        print(f"Files with Errors: {self.validation_results['stats']['files_with_errors']}")
        print(f"Files with Warnings: {self.validation_results['stats']['files_with_warnings']}")
        
        if self.validation_results['errors']:
            print("\nErrors:")
            for error in self.validation_results['errors']:
                print(f"{error['file']}:{error['line']} - {error['message']}")
        
        if self.validation_results['warnings']:
            print("\nWarnings:")
            for warning in self.validation_results['warnings']:
                print(f"{warning['file']}:{warning['line']} - {warning['message']}")
        
        # Exit with error code if there are validation errors
        if self.validation_results['errors']:
            sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print("Usage: python validate_docs.py <docs_directory>")
        sys.exit(1)
    
    docs_dir = sys.argv[1]
    
    validator = DocumentationValidator(docs_dir)
    validator.validate()

if __name__ == '__main__':
    main() 