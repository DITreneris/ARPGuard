#!/usr/bin/env python3
"""
Fix document dates in the documentation files.
This script updates all date references from 2025 to 2024.
"""

import json
import os
import re
from pathlib import Path

def fix_doc_dates():
    """Fix all dates in documentation files from 2025 to 2024."""
    docs_dir = Path(__file__).parent.parent / "docs"
    versions_file = docs_dir / "docs_versions.json"
    
    print("Fixing documentation dates...")
    
    # Fix the versions.json file
    if versions_file.exists():
        try:
            # Load the versions file
            with open(versions_file, 'r', encoding='utf-8') as f:
                versions_data = json.load(f)
            
            # Make a backup of the original file
            with open(str(versions_file) + '.bak', 'w', encoding='utf-8') as f:
                json.dump(versions_data, f, indent=2)
            
            # Replace all 2025 date references with 2024
            versions_str = json.dumps(versions_data)
            versions_str = versions_str.replace("2025-04-06", "2024-04-06")
            
            # Load back to ensure valid JSON
            versions_data = json.loads(versions_str)
            
            # Save the updated file
            with open(versions_file, 'w', encoding='utf-8') as f:
                json.dump(versions_data, f, indent=2)
            
            print(f"Updated dates in {versions_file}")
        except Exception as e:
            print(f"Error processing {versions_file}: {e}")
    
    # Scan all markdown files in the docs directory
    for md_file in docs_dir.glob("**/*.md"):
        try:
            # Try different encodings
            encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']
            content = None
            
            for encoding in encodings:
                try:
                    with open(md_file, 'r', encoding=encoding) as f:
                        content = f.read()
                    break  # If we get here, we found the right encoding
                except UnicodeDecodeError:
                    continue
            
            if content is None:
                print(f"Error: Could not determine encoding for {md_file}")
                continue
            
            # Simple replacement for 2025-04-06
            if "2025-04-06" in content:
                content = content.replace("2025-04-06", "2024-04-06")
                updated = True
            else:
                updated = False
                
            # Also handle written dates like "April 6, 2025"
            if "April 6, 2025" in content:
                content = content.replace("April 6, 2025", "April 6, 2024")
                updated = True
                
            # Also handle written dates like "April 6 2025"
            if "April 6 2025" in content:
                content = content.replace("April 6 2025", "April 6 2024")
                updated = True
                
            if updated:
                with open(md_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"Updated dates in {md_file}")
        except Exception as e:
            print(f"Error processing {md_file}: {e}")
    
    print("Date fixing complete!")

if __name__ == "__main__":
    fix_doc_dates() 