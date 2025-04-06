#!/usr/bin/env python3
import os
import sys
import json
from pathlib import Path
from typing import Dict, List
from datetime import datetime
import shutil
import subprocess
from collections import defaultdict

class DocumentationBuilder:
    def __init__(self, docs_dir: str, output_dir: str):
        self.docs_dir = Path(docs_dir)
        self.output_dir = Path(output_dir)
        self.tracking_file = self.docs_dir / 'docs_tracking.json'
        self.tracking_data = self._load_tracking_data()
        self.build_data = {
            'version': '1.0',
            'timestamp': datetime.now().isoformat(),
            'files': [],
            'stats': {
                'total_files': 0,
                'built_files': 0,
                'skipped_files': 0,
                'error_files': 0
            }
        }
    
    def _load_tracking_data(self) -> Dict:
        """Load tracking data from JSON file."""
        if self.tracking_file.exists():
            with open(self.tracking_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {'documents': {}}
    
    def _create_output_dirs(self) -> None:
        """Create output directories."""
        # Create main output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        subdirs = ['html', 'pdf', 'epub', 'search', 'images']
        for subdir in subdirs:
            (self.output_dir / subdir).mkdir(parents=True, exist_ok=True)
    
    def _copy_static_files(self) -> None:
        """Copy static files to output directory."""
        static_dirs = ['images', 'css', 'js']
        for static_dir in static_dirs:
            src_dir = self.docs_dir / static_dir
            if src_dir.exists():
                dst_dir = self.output_dir / static_dir
                shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)
    
    def _build_html(self) -> None:
        """Build HTML documentation."""
        try:
            # Run mkdocs build
            subprocess.run(
                ['mkdocs', 'build', '--site-dir', str(self.output_dir / 'html')],
                check=True
            )
            
            # Update build data
            self.build_data['stats']['built_files'] += 1
            
        except subprocess.CalledProcessError as e:
            print(f"Error building HTML: {e}")
            self.build_data['stats']['error_files'] += 1
    
    def _build_pdf(self) -> None:
        """Build PDF documentation."""
        try:
            # Run pandoc to convert markdown to PDF
            for file_path in self.docs_dir.rglob('*.md'):
                if any(d in str(file_path) for d in ['search', 'translations']):
                    continue
                
                output_file = self.output_dir / 'pdf' / f"{file_path.stem}.pdf"
                subprocess.run(
                    [
                        'pandoc',
                        str(file_path),
                        '-o', str(output_file),
                        '--pdf-engine=xelatex',
                        '-V', 'geometry:margin=1in',
                        '-V', 'mainfont:DejaVu Sans',
                        '-V', 'monofont:DejaVu Sans Mono'
                    ],
                    check=True
                )
                
                # Update build data
                self.build_data['stats']['built_files'] += 1
                self.build_data['files'].append({
                    'path': str(file_path),
                    'type': 'pdf',
                    'output': str(output_file),
                    'status': 'success'
                })
            
        except subprocess.CalledProcessError as e:
            print(f"Error building PDF: {e}")
            self.build_data['stats']['error_files'] += 1
    
    def _build_epub(self) -> None:
        """Build EPUB documentation."""
        try:
            # Run pandoc to convert markdown to EPUB
            for file_path in self.docs_dir.rglob('*.md'):
                if any(d in str(file_path) for d in ['search', 'translations']):
                    continue
                
                output_file = self.output_dir / 'epub' / f"{file_path.stem}.epub"
                subprocess.run(
                    [
                        'pandoc',
                        str(file_path),
                        '-o', str(output_file),
                        '--epub-cover-image=cover.jpg',
                        '--toc'
                    ],
                    check=True
                )
                
                # Update build data
                self.build_data['stats']['built_files'] += 1
                self.build_data['files'].append({
                    'path': str(file_path),
                    'type': 'epub',
                    'output': str(output_file),
                    'status': 'success'
                })
            
        except subprocess.CalledProcessError as e:
            print(f"Error building EPUB: {e}")
            self.build_data['stats']['error_files'] += 1
    
    def _build_search_index(self) -> None:
        """Build search index."""
        try:
            # Run search index generator
            subprocess.run(
                ['python', 'scripts/generate_search.py', str(self.docs_dir)],
                check=True
            )
            
            # Copy search index to output directory
            search_index = self.docs_dir / 'search' / 'index.json'
            if search_index.exists():
                shutil.copy2(
                    search_index,
                    self.output_dir / 'search' / 'index.json'
                )
            
            # Update build data
            self.build_data['stats']['built_files'] += 1
            
        except subprocess.CalledProcessError as e:
            print(f"Error building search index: {e}")
            self.build_data['stats']['error_files'] += 1
    
    def build(self) -> None:
        """Build documentation."""
        # Create output directories
        self._create_output_dirs()
        
        # Copy static files
        self._copy_static_files()
        
        # Build documentation formats
        self._build_html()
        self._build_pdf()
        self._build_epub()
        
        # Build search index
        self._build_search_index()
        
        # Save build data
        build_data_file = self.output_dir / 'build_data.json'
        with open(build_data_file, 'w', encoding='utf-8') as f:
            json.dump(self.build_data, f, indent=2)
        
        # Print summary
        print("\nDocumentation Build Summary:")
        print(f"Total Files: {self.build_data['stats']['total_files']}")
        print(f"Built Files: {self.build_data['stats']['built_files']}")
        print(f"Skipped Files: {self.build_data['stats']['skipped_files']}")
        print(f"Error Files: {self.build_data['stats']['error_files']}")
        
        if self.build_data['stats']['error_files'] > 0:
            sys.exit(1)

def main():
    if len(sys.argv) < 3:
        print("Usage: python build_docs.py <docs_directory> <output_directory>")
        sys.exit(1)
    
    docs_dir = sys.argv[1]
    output_dir = sys.argv[2]
    
    builder = DocumentationBuilder(docs_dir, output_dir)
    builder.build()

if __name__ == '__main__':
    main() 