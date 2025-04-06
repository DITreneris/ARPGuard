#!/usr/bin/env python3
import os
import sys
import re
from pathlib import Path
from typing import List, Dict, Set
import enchant
from concurrent.futures import ThreadPoolExecutor

class SpellChecker:
    def __init__(self, docs_dir: str, language: str = 'en_US'):
        self.docs_dir = Path(docs_dir)
        self.dictionary = enchant.Dict(language)
        self.ignored_words: Set[str] = set()
        self.load_ignored_words()
    
    def load_ignored_words(self) -> None:
        """Load ignored words from .spelling file."""
        spelling_file = self.docs_dir / '.spelling'
        if spelling_file.exists():
            with open(spelling_file, 'r', encoding='utf-8') as f:
                self.ignored_words = set(line.strip() for line in f if line.strip())
    
    def _is_ignored(self, word: str) -> bool:
        """Check if a word should be ignored."""
        # Ignore words with special characters
        if not word.isalnum():
            return True
        
        # Ignore words in the ignored words list
        if word.lower() in self.ignored_words:
            return True
        
        # Ignore words that are all uppercase (likely acronyms)
        if word.isupper():
            return True
        
        # Ignore words that contain numbers
        if any(c.isdigit() for c in word):
            return True
        
        return False
    
    def _check_file(self, file_path: Path) -> List[Dict[str, str]]:
        """Check spelling in a single file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Remove code blocks
        content = re.sub(r'```[\w]*\n.*?```', '', content, flags=re.DOTALL)
        
        # Remove inline code
        content = re.sub(r'`[^`]+`', '', content)
        
        # Find all words
        words = re.findall(r'\b\w+\b', content)
        
        errors = []
        for word in words:
            if not self._is_ignored(word) and not self.dictionary.check(word):
                errors.append({
                    'word': word,
                    'file': str(file_path.relative_to(self.docs_dir)),
                    'suggestions': self.dictionary.suggest(word)
                })
        
        return errors
    
    def check(self) -> List[Dict[str, str]]:
        """Check spelling in all documentation files."""
        markdown_files = list(self.docs_dir.rglob('*.md'))
        all_errors = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(self._check_file, markdown_files)
            for errors in results:
                all_errors.extend(errors)
        
        return all_errors
    
    def save_ignored_words(self) -> None:
        """Save ignored words to .spelling file."""
        spelling_file = self.docs_dir / '.spelling'
        with open(spelling_file, 'w', encoding='utf-8') as f:
            for word in sorted(self.ignored_words):
                f.write(f"{word}\n")
    
    def add_ignored_word(self, word: str) -> None:
        """Add a word to the ignored words list."""
        self.ignored_words.add(word.lower())
        self.save_ignored_words()

def main():
    if len(sys.argv) < 2:
        print("Usage: python check_spelling.py <docs_directory> [--add-word <word>]")
        sys.exit(1)
    
    docs_dir = sys.argv[1]
    checker = SpellChecker(docs_dir)
    
    if len(sys.argv) > 2 and sys.argv[2] == '--add-word':
        if len(sys.argv) != 4:
            print("Usage: python check_spelling.py <docs_directory> --add-word <word>")
            sys.exit(1)
        checker.add_ignored_word(sys.argv[3])
        print(f"Added '{sys.argv[3]}' to ignored words")
        return
    
    errors = checker.check()
    
    if errors:
        print("\nSpelling errors found:")
        for error in errors:
            print(f"\nFile: {error['file']}")
            print(f"Word: {error['word']}")
            print("Suggestions:")
            for suggestion in error['suggestions'][:5]:
                print(f"  - {suggestion}")
        print("\nTo ignore a word, run:")
        print(f"python check_spelling.py {docs_dir} --add-word <word>")
        sys.exit(1)
    else:
        print("No spelling errors found!")
        sys.exit(0)

if __name__ == '__main__':
    main() 