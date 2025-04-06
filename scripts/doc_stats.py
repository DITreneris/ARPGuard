#!/usr/bin/env python3
import os
import re
from pathlib import Path
from collections import defaultdict
import json
from datetime import datetime

def count_words(text):
    """Count words in text."""
    return len(re.findall(r'\w+', text))

def analyze_file(file_path):
    """Analyze a documentation file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Count sections
    sections = len(re.findall(r'^#+\s+', content, re.MULTILINE))
    
    # Count code blocks
    code_blocks = len(re.findall(r'```[\w]*\n.*?```', content, re.DOTALL))
    
    # Count links
    links = len(re.findall(r'\[([^\]]+)\]\(([^)]+)\)', content))
    
    # Count images
    images = len(re.findall(r'!\[([^\]]*)\]\(([^)]+)\)', content))
    
    # Count words
    words = count_words(content)
    
    return {
        'sections': sections,
        'code_blocks': code_blocks,
        'links': links,
        'images': images,
        'words': words
    }

def main():
    docs_dir = Path('docs')
    if not docs_dir.exists():
        print(f"Directory not found: {docs_dir}")
        return
    
    # Find all markdown files
    markdown_files = list(docs_dir.rglob('*.md'))
    
    # Analyze files
    stats = defaultdict(lambda: defaultdict(int))
    total_stats = defaultdict(int)
    
    for file_path in markdown_files:
        file_stats = analyze_file(file_path)
        relative_path = str(file_path.relative_to(docs_dir))
        
        # Update category stats
        category = relative_path.split('/')[0]
        for key, value in file_stats.items():
            stats[category][key] += value
            total_stats[key] += value
    
    # Generate report
    report = {
        'timestamp': datetime.now().isoformat(),
        'total_files': len(markdown_files),
        'categories': {
            category: dict(category_stats)
            for category, category_stats in stats.items()
        },
        'total': dict(total_stats)
    }
    
    # Save report
    output_file = 'docs/stats.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    print(f"Documentation statistics saved to {output_file}")
    
    # Print summary
    print("\nDocumentation Statistics Summary:")
    print(f"Total files: {len(markdown_files)}")
    print(f"Total words: {total_stats['words']}")
    print(f"Total sections: {total_stats['sections']}")
    print(f"Total code blocks: {total_stats['code_blocks']}")
    print(f"Total links: {total_stats['links']}")
    print(f"Total images: {total_stats['images']}")
    
    print("\nBy category:")
    for category, category_stats in stats.items():
        print(f"\n{category}:")
        for key, value in category_stats.items():
            print(f"  {key}: {value}")

if __name__ == '__main__':
    main() 