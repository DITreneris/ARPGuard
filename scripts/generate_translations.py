#!/usr/bin/env python3
import os
import sys
import json
from pathlib import Path
from typing import Dict, List
import re
from datetime import datetime
import yaml
from deep_translator import GoogleTranslator

class TranslationGenerator:
    def __init__(self, docs_dir: str, base_url: str):
        self.docs_dir = Path(docs_dir)
        self.base_url = base_url.rstrip('/')
        self.translations = {
            'version': '1.0',
            'encoding': 'UTF-8',
            'languages': {},
            'documents': {},
            'metadata': {
                'total_documents': 0,
                'total_languages': 0,
                'generated_at': datetime.now().isoformat()
            }
        }
        
        # Initialize translator
        self.translator = GoogleTranslator(source='auto', target='en')
    
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
    
    def _translate_text(self, text: str, target_lang: str) -> str:
        """Translate text to target language."""
        try:
            self.translator.target = target_lang
            return self.translator.translate(text)
        except Exception as e:
            print(f"Error translating text: {e}")
            return text
    
    def _translate_document(self, file_path: Path, target_lang: str) -> None:
        """Translate a document to target language."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Get basic information
                relative_path = str(file_path.relative_to(self.docs_dir)).replace('\\', '/')
                url = f"{self.base_url}/{relative_path.replace('.md', '')}"
                title = self._get_title(content, file_path)
                description = self._get_description(content)
                
                # Extract frontmatter
                frontmatter = self._extract_frontmatter(content)
                
                # Translate title and description
                translated_title = self._translate_text(title, target_lang)
                translated_description = self._translate_text(description, target_lang)
                
                # Add to translations
                doc_id = str(file_path)
                if doc_id not in self.translations['documents']:
                    self.translations['documents'][doc_id] = {}
                
                self.translations['documents'][doc_id][target_lang] = {
                    'title': translated_title,
                    'description': translated_description,
                    'url': url,
                    'path': relative_path
                }
                
                # Add to languages
                if target_lang not in self.translations['languages']:
                    self.translations['languages'][target_lang] = []
                self.translations['languages'][target_lang].append(doc_id)
                
                self.translations['metadata']['total_documents'] += 1
                self.translations['metadata']['total_languages'] = len(self.translations['languages'])
                
        except Exception as e:
            print(f"Error translating {file_path}: {e}")
    
    def generate(self, target_languages: List[str]) -> None:
        """Generate translations for documentation."""
        markdown_files = list(self.docs_dir.rglob('*.md'))
        
        for file_path in markdown_files:
            # Skip files in specific directories
            if any(d in str(file_path) for d in ['search', 'translations']):
                continue
            
            for target_lang in target_languages:
                self._translate_document(file_path, target_lang)
        
        # Save translations
        translations_file = self.docs_dir / 'translations.json'
        with open(translations_file, 'w', encoding='utf-8') as f:
            json.dump(self.translations, f, indent=2)
        
        print(f"Translations generated: {translations_file}")
        print(f"Total documents translated: {self.translations['metadata']['total_documents']}")
        print(f"Total languages: {self.translations['metadata']['total_languages']}")

def main():
    if len(sys.argv) < 4:
        print("Usage: python generate_translations.py <docs_directory> <base_url> <target_language1> [target_language2 ...]")
        sys.exit(1)
    
    docs_dir = sys.argv[1]
    base_url = sys.argv[2]
    target_languages = sys.argv[3:]
    
    generator = TranslationGenerator(docs_dir, base_url)
    generator.generate(target_languages)

if __name__ == '__main__':
    main() 