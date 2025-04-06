#!/usr/bin/env python3
import os
import sys
import json
from pathlib import Path
from typing import Dict, List, Set
import re
from datetime import datetime
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import PorterStemmer

class SearchIndexGenerator:
    def __init__(self, docs_dir: str, base_url: str):
        self.docs_dir = Path(docs_dir)
        self.base_url = base_url.rstrip('/')
        self.index = {
            'version': '1.0',
            'encoding': 'UTF-8',
            'documents': {},
            'terms': {},
            'metadata': {
                'total_documents': 0,
                'total_terms': 0,
                'generated_at': datetime.now().isoformat()
            }
        }
        
        # Download NLTK data if not already downloaded
        try:
            nltk.data.find('tokenizers/punkt')
        except LookupError:
            nltk.download('punkt')
        try:
            nltk.data.find('corpora/stopwords')
        except LookupError:
            nltk.download('stopwords')
        
        self.stop_words = set(stopwords.words('english'))
        self.stemmer = PorterStemmer()
    
    def _clean_text(self, text: str) -> str:
        """Clean text for indexing."""
        # Remove markdown formatting
        text = re.sub(r'#+\s+', '', text)  # Headers
        text = re.sub(r'`[^`]+`', '', text)  # Inline code
        text = re.sub(r'```[\s\S]*?```', '', text)  # Code blocks
        text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', text)  # Links
        text = re.sub(r'[*_~`]', '', text)  # Formatting
        text = re.sub(r'<[^>]+>', '', text)  # HTML tags
        
        # Remove special characters and convert to lowercase
        text = re.sub(r'[^\w\s]', ' ', text.lower())
        
        return text
    
    def _extract_terms(self, text: str) -> Set[str]:
        """Extract terms from text."""
        # Tokenize and clean
        tokens = word_tokenize(text)
        tokens = [token for token in tokens if token not in self.stop_words]
        tokens = [self.stemmer.stem(token) for token in tokens]
        
        return set(tokens)
    
    def _index_document(self, file_path: Path) -> None:
        """Index a document."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Get title
                title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
                title = title_match.group(1) if title_match else file_path.stem.replace('_', ' ').title()
                
                # Clean and extract terms
                cleaned_text = self._clean_text(content)
                terms = self._extract_terms(cleaned_text)
                
                # Get URL
                relative_path = str(file_path.relative_to(self.docs_dir)).replace('\\', '/')
                url = f"{self.base_url}/{relative_path.replace('.md', '')}"
                
                # Add to documents
                doc_id = str(file_path)
                self.index['documents'][doc_id] = {
                    'title': title,
                    'url': url,
                    'terms': list(terms),
                    'path': relative_path
                }
                
                # Add to terms
                for term in terms:
                    if term not in self.index['terms']:
                        self.index['terms'][term] = []
                    self.index['terms'][term].append(doc_id)
                
                self.index['metadata']['total_documents'] += 1
                self.index['metadata']['total_terms'] += len(terms)
                
        except Exception as e:
            print(f"Error indexing {file_path}: {e}")
    
    def generate(self) -> None:
        """Generate search index for documentation."""
        markdown_files = list(self.docs_dir.rglob('*.md'))
        
        for file_path in markdown_files:
            # Skip files in specific directories
            if any(d in str(file_path) for d in ['search', 'translations']):
                continue
            
            self._index_document(file_path)
        
        # Save index
        index_file = self.docs_dir / 'search' / 'index.json'
        index_file.parent.mkdir(exist_ok=True)
        
        with open(index_file, 'w', encoding='utf-8') as f:
            json.dump(self.index, f, indent=2)
        
        print(f"Search index generated: {index_file}")
        print(f"Total documents indexed: {self.index['metadata']['total_documents']}")
        print(f"Total terms indexed: {self.index['metadata']['total_terms']}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python generate_search_index.py <docs_directory> <base_url>")
        sys.exit(1)
    
    docs_dir = sys.argv[1]
    base_url = sys.argv[2]
    
    generator = SearchIndexGenerator(docs_dir, base_url)
    generator.generate()

if __name__ == '__main__':
    main() 