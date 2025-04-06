#!/usr/bin/env python3
import os
import sys
import json
from pathlib import Path
from typing import Dict, List
from datetime import datetime
import yaml
import subprocess
from collections import defaultdict

class WorkflowUpdater:
    def __init__(self, docs_dir: str):
        self.docs_dir = Path(docs_dir)
        self.tracking_file = self.docs_dir / 'docs_tracking.json'
        self.tracking_data = self._load_tracking_data()
        self.workflow_file = self.docs_dir / '.github/workflows/docs.yml'
    
    def _load_tracking_data(self) -> Dict:
        """Load tracking data from JSON file."""
        if self.tracking_file.exists():
            with open(self.tracking_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {'documents': {}}
    
    def _get_git_changes(self) -> List[str]:
        """Get list of changed files from git."""
        try:
            result = subprocess.run(
                ['git', 'diff', '--name-only', 'HEAD'],
                capture_output=True,
                text=True
            )
            return result.stdout.strip().split('\n')
        except Exception as e:
            print(f"Error getting git changes: {e}")
            return []
    
    def _update_workflow(self) -> None:
        """Update GitHub Actions workflow file."""
        workflow = {
            'name': 'Documentation Workflow',
            'on': {
                'push': {
                    'paths': ['docs/**']
                },
                'pull_request': {
                    'paths': ['docs/**']
                }
            },
            'jobs': {
                'validate': {
                    'runs-on': 'ubuntu-latest',
                    'steps': [
                        {
                            'uses': 'actions/checkout@v2'
                        },
                        {
                            'name': 'Set up Python',
                            'uses': 'actions/setup-python@v2',
                            'with': {
                                'python-version': '3.9'
                            }
                        },
                        {
                            'name': 'Install dependencies',
                            'run': 'pip install -r requirements.txt'
                        },
                        {
                            'name': 'Validate documentation',
                            'run': 'python scripts/validate_docs.py'
                        }
                    ]
                },
                'build': {
                    'needs': 'validate',
                    'runs-on': 'ubuntu-latest',
                    'steps': [
                        {
                            'uses': 'actions/checkout@v2'
                        },
                        {
                            'name': 'Set up Python',
                            'uses': 'actions/setup-python@v2',
                            'with': {
                                'python-version': '3.9'
                            }
                        },
                        {
                            'name': 'Install dependencies',
                            'run': 'pip install -r requirements.txt'
                        },
                        {
                            'name': 'Build documentation',
                            'run': 'python scripts/build_docs.py'
                        }
                    ]
                },
                'deploy': {
                    'needs': 'build',
                    'runs-on': 'ubuntu-latest',
                    'if': "github.ref == 'refs/heads/main'",
                    'steps': [
                        {
                            'uses': 'actions/checkout@v2'
                        },
                        {
                            'name': 'Deploy to GitHub Pages',
                            'uses': 'peaceiris/actions-gh-pages@v3',
                            'with': {
                                'github_token': '${{ secrets.GITHUB_TOKEN }}',
                                'publish_dir': './docs/_build/html'
                            }
                        }
                    ]
                }
            }
        }
        
        # Create workflow directory if it doesn't exist
        self.workflow_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Write workflow file
        with open(self.workflow_file, 'w', encoding='utf-8') as f:
            yaml.dump(workflow, f, default_flow_style=False, sort_keys=False)
        
        print(f"Workflow file updated: {self.workflow_file}")
    
    def _update_documentation(self) -> None:
        """Update documentation based on changes."""
        changed_files = self._get_git_changes()
        docs_changes = [f for f in changed_files if f.startswith('docs/')]
        
        if not docs_changes:
            print("No documentation changes detected")
            return
        
        print("Updating documentation for changed files:")
        for file_path in docs_changes:
            print(f"- {file_path}")
            
            # Update tracking data
            doc_path = Path(file_path)
            if doc_path.suffix == '.md':
                self._update_document_tracking(doc_path)
        
        self._save_tracking_data()
    
    def _update_document_tracking(self, file_path: Path) -> None:
        """Update tracking information for a document."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            doc_id = str(file_path)
            if doc_id not in self.tracking_data['documents']:
                self.tracking_data['documents'][doc_id] = {
                    'path': str(file_path),
                    'status': 'active',
                    'created_at': datetime.now().isoformat(),
                    'last_modified': datetime.now().isoformat(),
                    'updates': []
                }
            else:
                self.tracking_data['documents'][doc_id]['last_modified'] = datetime.now().isoformat()
                self.tracking_data['documents'][doc_id]['updates'].append({
                    'timestamp': datetime.now().isoformat(),
                    'changes': 'Content updated'
                })
        
        except Exception as e:
            print(f"Error updating tracking for {file_path}: {e}")
    
    def _save_tracking_data(self) -> None:
        """Save tracking data to JSON file."""
        self.tracking_data['last_updated'] = datetime.now().isoformat()
        with open(self.tracking_file, 'w', encoding='utf-8') as f:
            json.dump(self.tracking_data, f, indent=2)
    
    def update(self) -> None:
        """Update documentation workflow and tracking."""
        self._update_workflow()
        self._update_documentation()
        print("Documentation workflow and tracking updated")

def main():
    if len(sys.argv) < 2:
        print("Usage: python update_workflow.py <docs_directory>")
        sys.exit(1)
    
    docs_dir = sys.argv[1]
    
    updater = WorkflowUpdater(docs_dir)
    updater.update()

if __name__ == '__main__':
    main() 