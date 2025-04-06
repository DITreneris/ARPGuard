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

class DocumentationManager:
    def __init__(self, docs_dir: str):
        self.docs_dir = Path(docs_dir)
        self.tracking_file = self.docs_dir / 'docs_tracking.json'
        self.tracking_data = self._load_tracking_data()
        
    def _load_tracking_data(self) -> Dict:
        """Load tracking data from JSON file."""
        if self.tracking_file.exists():
            with open(self.tracking_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            'version': '1.0',
            'documents': {},
            'categories': defaultdict(list),
            'last_updated': datetime.now().isoformat(),
            'metadata': {
                'total_documents': 0,
                'total_categories': 0,
                'last_sync': None
            }
        }
    
    def _save_tracking_data(self) -> None:
        """Save tracking data to JSON file."""
        self.tracking_data['last_updated'] = datetime.now().isoformat()
        with open(self.tracking_file, 'w', encoding='utf-8') as f:
            json.dump(self.tracking_data, f, indent=2)
    
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
    
    def _get_title(self, content: str, file_path: Path) -> str:
        """Get title from markdown file."""
        title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
        return title_match.group(1) if title_match else file_path.stem.replace('_', ' ').title()
    
    def _get_category(self, file_path: Path) -> str:
        """Get category from file path."""
        relative_path = str(file_path.relative_to(self.docs_dir))
        parts = relative_path.split(os.sep)
        return parts[0] if len(parts) > 1 else 'uncategorized'
    
    def _update_document_tracking(self, file_path: Path) -> None:
        """Update tracking information for a document."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            file_hash = self._calculate_file_hash(file_path)
            relative_path = str(file_path.relative_to(self.docs_dir))
            category = self._get_category(file_path)
            
            # Get document metadata
            frontmatter = self._extract_frontmatter(content)
            title = self._get_title(content, file_path)
            
            # Update tracking data
            doc_id = str(file_path)
            if doc_id not in self.tracking_data['documents']:
                self.tracking_data['documents'][doc_id] = {
                    'path': relative_path,
                    'title': title,
                    'category': category,
                    'created_at': datetime.now().isoformat(),
                    'last_modified': datetime.now().isoformat(),
                    'hash': file_hash,
                    'status': 'active',
                    'updates': []
                }
                self.tracking_data['metadata']['total_documents'] += 1
            else:
                if self.tracking_data['documents'][doc_id]['hash'] != file_hash:
                    self.tracking_data['documents'][doc_id]['last_modified'] = datetime.now().isoformat()
                    self.tracking_data['documents'][doc_id]['hash'] = file_hash
                    self.tracking_data['documents'][doc_id]['updates'].append({
                        'timestamp': datetime.now().isoformat(),
                        'changes': 'Content updated'
                    })
            
            # Update category tracking
            if category not in self.tracking_data['categories']:
                self.tracking_data['categories'][category] = []
                self.tracking_data['metadata']['total_categories'] += 1
            
            if doc_id not in self.tracking_data['categories'][category]:
                self.tracking_data['categories'][category].append(doc_id)
            
        except Exception as e:
            print(f"Error updating tracking for {file_path}: {e}")
    
    def _mark_document_completed(self, file_path: Path) -> None:
        """Mark a document as completed."""
        doc_id = str(file_path)
        if doc_id in self.tracking_data['documents']:
            self.tracking_data['documents'][doc_id]['status'] = 'completed'
            self.tracking_data['documents'][doc_id]['completed_at'] = datetime.now().isoformat()
    
    def _mark_document_reviewed(self, file_path: Path) -> None:
        """Mark a document as reviewed."""
        doc_id = str(file_path)
        if doc_id in self.tracking_data['documents']:
            self.tracking_data['documents'][doc_id]['status'] = 'reviewed'
            self.tracking_data['documents'][doc_id]['reviewed_at'] = datetime.now().isoformat()
    
    def scan_documents(self) -> None:
        """Scan all documents and update tracking information."""
        markdown_files = list(self.docs_dir.rglob('*.md'))
        
        for file_path in markdown_files:
            # Skip files in specific directories
            if any(d in str(file_path) for d in ['search', 'translations']):
                continue
            
            self._update_document_tracking(file_path)
        
        self._save_tracking_data()
        print(f"Documentation tracking updated: {self.tracking_file}")
        print(f"Total documents tracked: {self.tracking_data['metadata']['total_documents']}")
        print(f"Total categories: {self.tracking_data['metadata']['total_categories']}")
    
    def mark_completed(self, file_path: str) -> None:
        """Mark a document as completed."""
        doc_path = self.docs_dir / file_path
        if not doc_path.exists():
            print(f"Document not found: {file_path}")
            return
        
        self._mark_document_completed(doc_path)
        self._save_tracking_data()
        print(f"Document marked as completed: {file_path}")
    
    def mark_reviewed(self, file_path: str) -> None:
        """Mark a document as reviewed."""
        doc_path = self.docs_dir / file_path
        if not doc_path.exists():
            print(f"Document not found: {file_path}")
            return
        
        self._mark_document_reviewed(doc_path)
        self._save_tracking_data()
        print(f"Document marked as reviewed: {file_path}")
    
    def get_status(self, file_path: Optional[str] = None) -> None:
        """Get status of documents."""
        if file_path:
            doc_path = self.docs_dir / file_path
            if not doc_path.exists():
                print(f"Document not found: {file_path}")
                return
            
            doc_id = str(doc_path)
            if doc_id in self.tracking_data['documents']:
                doc = self.tracking_data['documents'][doc_id]
                print(f"\nDocument: {doc['path']}")
                print(f"Title: {doc['title']}")
                print(f"Category: {doc['category']}")
                print(f"Status: {doc['status']}")
                print(f"Created: {doc['created_at']}")
                print(f"Last Modified: {doc['last_modified']}")
                if 'completed_at' in doc:
                    print(f"Completed: {doc['completed_at']}")
                if 'reviewed_at' in doc:
                    print(f"Reviewed: {doc['reviewed_at']}")
                print(f"Updates: {len(doc['updates'])}")
            else:
                print(f"No tracking data found for: {file_path}")
        else:
            # Print summary
            print("\nDocumentation Status Summary:")
            print(f"Total Documents: {self.tracking_data['metadata']['total_documents']}")
            print(f"Total Categories: {self.tracking_data['metadata']['total_categories']}")
            print(f"Last Updated: {self.tracking_data['last_updated']}")
            
            # Print status counts
            status_counts = defaultdict(int)
            for doc in self.tracking_data['documents'].values():
                status_counts[doc['status']] += 1
            
            print("\nStatus Counts:")
            for status, count in status_counts.items():
                print(f"{status}: {count}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python manage_docs.py <command> [args]")
        print("\nCommands:")
        print("  scan                 Scan all documents and update tracking")
        print("  complete <file>      Mark a document as completed")
        print("  review <file>        Mark a document as reviewed")
        print("  status [file]        Get status of documents")
        sys.exit(1)
    
    command = sys.argv[1]
    docs_dir = os.getenv('DOCS_DIR', 'docs')
    
    manager = DocumentationManager(docs_dir)
    
    if command == 'scan':
        manager.scan_documents()
    elif command == 'complete':
        if len(sys.argv) < 3:
            print("Error: File path required")
            sys.exit(1)
        manager.mark_completed(sys.argv[2])
    elif command == 'review':
        if len(sys.argv) < 3:
            print("Error: File path required")
            sys.exit(1)
        manager.mark_reviewed(sys.argv[2])
    elif command == 'status':
        manager.get_status(sys.argv[2] if len(sys.argv) > 2 else None)
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main() 