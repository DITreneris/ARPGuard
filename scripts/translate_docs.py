#!/usr/bin/env python3
import os
import sys
import json
from pathlib import Path
from typing import Dict, List, Optional
import re
from deep_translator import GoogleTranslator

class DocumentationTranslator:
    def __init__(self, docs_dir: str):
        self.docs_dir = Path(docs_dir)
        self.translations_dir = self.docs_dir / 'translations'
        self.translations_dir.mkdir(parents=True, exist_ok=True)
        self.translator = GoogleTranslator(source='auto', target='en')
    
    def _load_translation_config(self) -> Dict:
        """Load translation configuration."""
        config_file = self.docs_dir / 'translation_config.json'
        if config_file.exists():
            with open(config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            'languages': ['es', 'fr', 'de', 'it', 'pt'],
            'exclude_patterns': [
                r'```.*?```',
                r'`[^`]+`',
                r'\[([^\]]+)\]\([^)]+\)',
                r'#+.*'
            ]
        }
    
    def _save_translation_config(self, config: Dict) -> None:
        """Save translation configuration."""
        config_file = self.docs_dir / 'translation_config.json'
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
    
    def _extract_text(self, content: str, exclude_patterns: List[str]) -> List[str]:
        """Extract text to translate from markdown content."""
        # Remove excluded patterns
        for pattern in exclude_patterns:
            content = re.sub(pattern, '', content, flags=re.DOTALL)
        
        # Split into paragraphs
        paragraphs = [p.strip() for p in content.split('\n\n') if p.strip()]
        
        return paragraphs
    
    def _translate_text(self, text: str, target_lang: str) -> str:
        """Translate text to target language."""
        try:
            self.translator.target = target_lang
            return self.translator.translate(text)
        except Exception as e:
            print(f"Error translating text: {str(e)}")
            return text
    
    def _translate_file(self, file_path: Path, target_lang: str) -> None:
        """Translate a documentation file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        config = self._load_translation_config()
        paragraphs = self._extract_text(content, config['exclude_patterns'])
        
        translated_paragraphs = []
        for paragraph in paragraphs:
            translated = self._translate_text(paragraph, target_lang)
            translated_paragraphs.append(translated)
        
        # Create translated content
        translated_content = content
        for original, translated in zip(paragraphs, translated_paragraphs):
            translated_content = translated_content.replace(original, translated)
        
        # Save translated file
        lang_dir = self.translations_dir / target_lang
        lang_dir.mkdir(parents=True, exist_ok=True)
        
        output_path = lang_dir / file_path.name
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(translated_content)
        
        print(f"Translated {file_path} to {target_lang}")
    
    def translate(self, target_lang: Optional[str] = None) -> None:
        """Translate documentation files."""
        config = self._load_translation_config()
        
        if target_lang:
            if target_lang not in config['languages']:
                print(f"Language {target_lang} not in configuration")
                print(f"Available languages: {', '.join(config['languages'])}")
                sys.exit(1)
            target_languages = [target_lang]
        else:
            target_languages = config['languages']
        
        markdown_files = list(self.docs_dir.rglob('*.md'))
        
        for file_path in markdown_files:
            # Skip files in translations directory
            if 'translations' in str(file_path):
                continue
            
            for lang in target_languages:
                self._translate_file(file_path, lang)
    
    def add_language(self, language: str) -> None:
        """Add a new language to the translation configuration."""
        config = self._load_translation_config()
        
        if language in config['languages']:
            print(f"Language {language} already in configuration")
            return
        
        config['languages'].append(language)
        self._save_translation_config(config)
        print(f"Added language {language}")
    
    def remove_language(self, language: str) -> None:
        """Remove a language from the translation configuration."""
        config = self._load_translation_config()
        
        if language not in config['languages']:
            print(f"Language {language} not in configuration")
            return
        
        config['languages'].remove(language)
        self._save_translation_config(config)
        
        # Remove translated files for the language
        lang_dir = self.translations_dir / language
        if lang_dir.exists():
            for file_path in lang_dir.rglob('*.md'):
                file_path.unlink()
            lang_dir.rmdir()
        
        print(f"Removed language {language}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python translate_docs.py <command> [options]")
        print("\nCommands:")
        print("  translate [language]  Translate documentation")
        print("  add <language>       Add a new language")
        print("  remove <language>    Remove a language")
        sys.exit(1)
    
    command = sys.argv[1]
    translator = DocumentationTranslator('docs')
    
    if command == 'translate':
        target_lang = sys.argv[2] if len(sys.argv) > 2 else None
        translator.translate(target_lang)
    
    elif command == 'add':
        if len(sys.argv) != 3:
            print("Usage: python translate_docs.py add <language>")
            sys.exit(1)
        translator.add_language(sys.argv[2])
    
    elif command == 'remove':
        if len(sys.argv) != 3:
            print("Usage: python translate_docs.py remove <language>")
            sys.exit(1)
        translator.remove_language(sys.argv[2])
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main() 