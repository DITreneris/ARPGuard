#!/usr/bin/env python3
import os
import sys
import re
from pathlib import Path
from typing import List, Dict, Optional
import subprocess
import tempfile
import shutil

class DiagramGenerator:
    def __init__(self, docs_dir: str):
        self.docs_dir = Path(docs_dir)
        self.diagrams_dir = self.docs_dir / 'diagrams'
        self.diagrams_dir.mkdir(parents=True, exist_ok=True)
        
        # Check if PlantUML is installed
        try:
            subprocess.run(['plantuml', '-version'], capture_output=True, check=True)
            self.plantuml_available = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.plantuml_available = False
            print("Warning: PlantUML not found. Some diagrams may not be generated.")
    
    def _generate_plantuml(self, content: str, output_path: Path) -> bool:
        """Generate a diagram using PlantUML."""
        if not self.plantuml_available:
            return False
        
        with tempfile.NamedTemporaryFile(suffix='.puml', mode='w', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            subprocess.run(['plantuml', temp_path], check=True)
            diagram_path = Path(temp_path).with_suffix('.png')
            if diagram_path.exists():
                shutil.move(diagram_path, output_path)
                return True
        except subprocess.CalledProcessError:
            pass
        finally:
            os.unlink(temp_path)
        
        return False
    
    def _generate_mermaid(self, content: str, output_path: Path) -> bool:
        """Generate a diagram using Mermaid."""
        # Mermaid diagrams are rendered by the markdown viewer
        # We just need to ensure the content is properly formatted
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    
    def _generate_class_diagram(self, file_path: Path) -> Optional[Path]:
        """Generate a class diagram from a Python file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extract class definitions
        class_pattern = r'class\s+(\w+)(?:\(([^)]+)\))?:'
        classes = re.finditer(class_pattern, content)
        
        plantuml_content = ['@startuml']
        
        for match in classes:
            class_name = match.group(1)
            bases = match.group(2)
            
            plantuml_content.append(f'class {class_name} {{')
            
            # Extract methods
            method_pattern = rf'def\s+(\w+)\s*\([^)]*\):'
            methods = re.finditer(method_pattern, content)
            
            for method in methods:
                plantuml_content.append(f'  +{method.group(1)}()')
            
            plantuml_content.append('}')
            
            # Add inheritance relationships
            if bases:
                for base in bases.split(','):
                    base = base.strip()
                    if base != 'object':
                        plantuml_content.append(f'{base} <|-- {class_name}')
        
        plantuml_content.append('@enduml')
        
        output_path = self.diagrams_dir / f"{file_path.stem}_class.png"
        if self._generate_plantuml('\n'.join(plantuml_content), output_path):
            return output_path
        
        return None
    
    def _generate_sequence_diagram(self, file_path: Path) -> Optional[Path]:
        """Generate a sequence diagram from a Python file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extract function calls
        call_pattern = r'(\w+)\.(\w+)\s*\('
        calls = re.finditer(call_pattern, content)
        
        mermaid_content = ['sequenceDiagram']
        participants = set()
        
        for match in calls:
            caller = match.group(1)
            callee = match.group(1)
            method = match.group(2)
            
            participants.add(caller)
            participants.add(callee)
            
            mermaid_content.append(f'    {caller}->>{callee}: {method}()')
        
        # Add participants
        for participant in sorted(participants):
            mermaid_content.insert(1, f'    participant {participant}')
        
        output_path = self.diagrams_dir / f"{file_path.stem}_sequence.md"
        if self._generate_mermaid('\n'.join(mermaid_content), output_path):
            return output_path
        
        return None
    
    def _generate_flow_diagram(self, file_path: Path) -> Optional[Path]:
        """Generate a flow diagram from a Python file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extract function definitions
        function_pattern = r'def\s+(\w+)\s*\([^)]*\):'
        functions = re.finditer(function_pattern, content)
        
        mermaid_content = ['graph TD']
        
        for match in functions:
            function_name = match.group(1)
            mermaid_content.append(f'    {function_name}[{function_name}]')
            
            # Extract function calls
            call_pattern = rf'{function_name}.*?(\w+)\s*\('
            calls = re.finditer(call_pattern, content)
            
            for call in calls:
                called_function = call.group(1)
                mermaid_content.append(f'    {function_name} --> {called_function}')
        
        output_path = self.diagrams_dir / f"{file_path.stem}_flow.md"
        if self._generate_mermaid('\n'.join(mermaid_content), output_path):
            return output_path
        
        return None
    
    def generate(self) -> None:
        """Generate diagrams for all Python files."""
        python_files = list(self.docs_dir.rglob('*.py'))
        
        for file_path in python_files:
            # Skip __init__.py and test files
            if file_path.name == '__init__.py' or 'test' in file_path.name.lower():
                continue
            
            print(f"\nGenerating diagrams for {file_path}")
            
            # Generate class diagram
            class_diagram = self._generate_class_diagram(file_path)
            if class_diagram:
                print(f"  - Class diagram: {class_diagram}")
            
            # Generate sequence diagram
            sequence_diagram = self._generate_sequence_diagram(file_path)
            if sequence_diagram:
                print(f"  - Sequence diagram: {sequence_diagram}")
            
            # Generate flow diagram
            flow_diagram = self._generate_flow_diagram(file_path)
            if flow_diagram:
                print(f"  - Flow diagram: {flow_diagram}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python generate_diagrams.py <docs_directory>")
        sys.exit(1)
    
    docs_dir = sys.argv[1]
    generator = DiagramGenerator(docs_dir)
    generator.generate()

if __name__ == '__main__':
    main() 