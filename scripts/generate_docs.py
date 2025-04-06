#!/usr/bin/env python3
import os
import sys
import ast
import inspect
from pathlib import Path
from typing import List, Dict, Any
import re

class DocumentationGenerator:
    def __init__(self, source_dir: str, output_dir: str):
        self.source_dir = Path(source_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def _parse_python_file(self, file_path: Path) -> Dict[str, Any]:
        """Parse a Python file and extract documentation."""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        tree = ast.parse(content)
        documentation = {
            'module': {
                'name': file_path.stem,
                'docstring': ast.get_docstring(tree),
                'classes': [],
                'functions': []
            }
        }
        
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                class_doc = {
                    'name': node.name,
                    'docstring': ast.get_docstring(node),
                    'methods': [],
                    'bases': [base.id for base in node.bases if isinstance(base, ast.Name)]
                }
                
                for item in node.body:
                    if isinstance(item, ast.FunctionDef):
                        method_doc = {
                            'name': item.name,
                            'docstring': ast.get_docstring(item),
                            'args': [],
                            'returns': None
                        }
                        
                        # Parse arguments
                        for arg in item.args.args:
                            method_doc['args'].append({
                                'name': arg.arg,
                                'annotation': ast.unparse(arg.annotation) if arg.annotation else None
                            })
                        
                        # Parse return annotation
                        if item.returns:
                            method_doc['returns'] = ast.unparse(item.returns)
                        
                        class_doc['methods'].append(method_doc)
                
                documentation['module']['classes'].append(class_doc)
            
            elif isinstance(node, ast.FunctionDef) and not isinstance(node.parent, ast.ClassDef):
                function_doc = {
                    'name': node.name,
                    'docstring': ast.get_docstring(node),
                    'args': [],
                    'returns': None
                }
                
                # Parse arguments
                for arg in node.args.args:
                    function_doc['args'].append({
                        'name': arg.arg,
                        'annotation': ast.unparse(arg.annotation) if arg.annotation else None
                    })
                
                # Parse return annotation
                if node.returns:
                    function_doc['returns'] = ast.unparse(node.returns)
                
                documentation['module']['functions'].append(function_doc)
        
        return documentation
    
    def _generate_markdown(self, documentation: Dict[str, Any]) -> str:
        """Generate markdown documentation from parsed Python code."""
        content = []
        
        # Module documentation
        content.append(f"# {documentation['module']['name']}\n")
        if documentation['module']['docstring']:
            content.append(documentation['module']['docstring'] + "\n")
        
        # Classes
        if documentation['module']['classes']:
            content.append("## Classes\n")
            for class_doc in documentation['module']['classes']:
                content.append(f"### {class_doc['name']}\n")
                if class_doc['bases']:
                    content.append(f"*Inherits from: {', '.join(class_doc['bases'])}*\n")
                if class_doc['docstring']:
                    content.append(class_doc['docstring'] + "\n")
                
                # Methods
                if class_doc['methods']:
                    content.append("#### Methods\n")
                    for method in class_doc['methods']:
                        content.append(f"##### {method['name']}\n")
                        if method['docstring']:
                            content.append(method['docstring'] + "\n")
                        
                        # Arguments
                        if method['args']:
                            content.append("###### Arguments\n")
                            content.append("| Name | Type | Description |")
                            content.append("|------|------|-------------|")
                            for arg in method['args']:
                                content.append(f"| {arg['name']} | {arg['annotation'] or 'Any'} | |")
                        
                        # Return value
                        if method['returns']:
                            content.append(f"\n###### Returns\n")
                            content.append(f"Type: `{method['returns']}`\n")
        
        # Functions
        if documentation['module']['functions']:
            content.append("## Functions\n")
            for function in documentation['module']['functions']:
                content.append(f"### {function['name']}\n")
                if function['docstring']:
                    content.append(function['docstring'] + "\n")
                
                # Arguments
                if function['args']:
                    content.append("#### Arguments\n")
                    content.append("| Name | Type | Description |")
                    content.append("|------|------|-------------|")
                    for arg in function['args']:
                        content.append(f"| {arg['name']} | {arg['annotation'] or 'Any'} | |")
                
                # Return value
                if function['returns']:
                    content.append(f"\n#### Returns\n")
                    content.append(f"Type: `{function['returns']}`\n")
        
        return "\n".join(content)
    
    def generate(self) -> None:
        """Generate documentation for all Python files in the source directory."""
        python_files = list(self.source_dir.rglob('*.py'))
        
        for file_path in python_files:
            # Skip __init__.py and test files
            if file_path.name == '__init__.py' or 'test' in file_path.name.lower():
                continue
            
            # Parse the file
            documentation = self._parse_python_file(file_path)
            
            # Generate markdown
            markdown = self._generate_markdown(documentation)
            
            # Write to output file
            output_path = self.output_dir / f"{file_path.stem}.md"
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(markdown)
            
            print(f"Generated documentation for {file_path}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python generate_docs.py <source_directory> <output_directory>")
        sys.exit(1)
    
    source_dir = sys.argv[1]
    output_dir = sys.argv[2]
    
    generator = DocumentationGenerator(source_dir, output_dir)
    generator.generate()

if __name__ == '__main__':
    main() 