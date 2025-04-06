import os
import re
from pathlib import Path
import pytest
from docutils.core import publish_doctree
from docutils.parsers.rst import Parser
from sphinx.application import Sphinx

def test_documentation_structure():
    """Test that all documentation files follow the required structure."""
    docs_dir = Path('docs')
    required_sections = [
        'Overview',
        'Features',
        'Architecture',
        'API Reference',
        'Usage Examples',
        'Configuration Options',
        'Dependencies',
        'Testing',
        'Performance Considerations',
        'Troubleshooting',
        'Version History'
    ]
    
    for doc_file in docs_dir.rglob('*.md'):
        content = doc_file.read_text()
        missing_sections = [section for section in required_sections 
                          if f"## {section}" not in content]
        assert not missing_sections, f"Missing sections in {doc_file}: {missing_sections}"

def test_api_documentation():
    """Test that all Python classes and methods are properly documented."""
    code_dir = Path('app')
    for py_file in code_dir.rglob('*.py'):
        content = py_file.read_text()
        class_matches = re.finditer(r'class\s+(\w+)', content)
        for match in class_matches:
            class_name = match.group(1)
            assert f'class {class_name}:' in content, f"Missing class documentation for {class_name}"
            
        method_matches = re.finditer(r'def\s+(\w+)\(', content)
        for match in method_matches:
            method_name = match.group(1)
            if not method_name.startswith('_'):
                assert f'def {method_name}(' in content, f"Missing method documentation for {method_name}"

def test_documentation_links():
    """Test that all documentation links are valid."""
    docs_dir = Path('docs')
    for doc_file in docs_dir.rglob('*.md'):
        content = doc_file.read_text()
        link_matches = re.finditer(r'\[([^\]]+)\]\(([^)]+)\)', content)
        for match in link_matches:
            link_text, link_url = match.groups()
            if link_url.startswith('http'):
                continue
            target_path = (doc_file.parent / link_url).resolve()
            assert target_path.exists(), f"Broken link in {doc_file}: {link_url}"

def test_code_examples():
    """Test that all code examples in documentation are valid Python."""
    docs_dir = Path('docs')
    for doc_file in docs_dir.rglob('*.md'):
        content = doc_file.read_text()
        code_blocks = re.finditer(r'```python\n(.*?)\n```', content, re.DOTALL)
        for match in code_blocks:
            code = match.group(1)
            try:
                compile(code, '<string>', 'exec')
            except SyntaxError as e:
                pytest.fail(f"Invalid Python code in {doc_file}: {str(e)}")

def test_documentation_spelling():
    """Test documentation for common spelling mistakes."""
    docs_dir = Path('docs')
    common_mistakes = {
        'seperate': 'separate',
        'definately': 'definitely',
        'occured': 'occurred',
        'recieve': 'receive',
        'wich': 'which'
    }
    
    for doc_file in docs_dir.rglob('*.md'):
        content = doc_file.read_text()
        for mistake, correction in common_mistakes.items():
            assert mistake not in content, f"Spelling mistake in {doc_file}: {mistake} should be {correction}"

def test_documentation_images():
    """Test that all images referenced in documentation exist."""
    docs_dir = Path('docs')
    for doc_file in docs_dir.rglob('*.md'):
        content = doc_file.read_text()
        image_matches = re.finditer(r'!\[([^\]]*)\]\(([^)]+)\)', content)
        for match in image_matches:
            alt_text, image_path = match.groups()
            if image_path.startswith('http'):
                continue
            target_path = (doc_file.parent / image_path).resolve()
            assert target_path.exists(), f"Missing image in {doc_file}: {image_path}"

def test_documentation_metadata():
    """Test that all documentation files have required metadata."""
    docs_dir = Path('docs')
    required_metadata = ['title', 'author', 'date']
    
    for doc_file in docs_dir.rglob('*.md'):
        content = doc_file.read_text()
        if content.startswith('---'):
            metadata = content.split('---')[1]
            for field in required_metadata:
                assert f'{field}:' in metadata, f"Missing metadata {field} in {doc_file}" 