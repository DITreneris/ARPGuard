#!/usr/bin/env python3
import os
import sys
import json
from pathlib import Path
from typing import Dict, List
from datetime import datetime
from collections import defaultdict
import markdown
from jinja2 import Environment, FileSystemLoader

class StatusReportGenerator:
    def __init__(self, docs_dir: str, output_dir: str):
        self.docs_dir = Path(docs_dir)
        self.output_dir = Path(output_dir)
        self.tracking_file = self.docs_dir / 'docs_tracking.json'
        self.tracking_data = self._load_tracking_data()
        
        # Setup Jinja2 environment
        self.env = Environment(
            loader=FileSystemLoader('templates'),
            autoescape=True
        )
    
    def _load_tracking_data(self) -> Dict:
        """Load tracking data from JSON file."""
        if self.tracking_file.exists():
            with open(self.tracking_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {'documents': {}}
    
    def _get_category_stats(self) -> Dict:
        """Get statistics by category."""
        category_stats = defaultdict(lambda: {
            'total': 0,
            'completed': 0,
            'reviewed': 0,
            'active': 0,
            'last_updated': None
        })
        
        for doc in self.tracking_data['documents'].values():
            category = doc['category']
            category_stats[category]['total'] += 1
            category_stats[category][doc['status']] += 1
            
            if (category_stats[category]['last_updated'] is None or 
                doc['last_modified'] > category_stats[category]['last_updated']):
                category_stats[category]['last_updated'] = doc['last_modified']
        
        return dict(category_stats)
    
    def _get_overall_stats(self) -> Dict:
        """Get overall documentation statistics."""
        stats = {
            'total_documents': 0,
            'completed': 0,
            'reviewed': 0,
            'active': 0,
            'categories': len(self.tracking_data.get('categories', {})),
            'last_updated': self.tracking_data.get('last_updated'),
            'completion_percentage': 0
        }
        
        for doc in self.tracking_data['documents'].values():
            stats['total_documents'] += 1
            stats[doc['status']] += 1
        
        if stats['total_documents'] > 0:
            stats['completion_percentage'] = round(
                (stats['completed'] / stats['total_documents']) * 100,
                2
            )
        
        return stats
    
    def _get_recent_updates(self, limit: int = 10) -> List[Dict]:
        """Get recent document updates."""
        updates = []
        for doc in self.tracking_data['documents'].values():
            if 'updates' in doc:
                for update in doc['updates']:
                    updates.append({
                        'path': doc['path'],
                        'title': doc['title'],
                        'timestamp': update['timestamp'],
                        'changes': update['changes']
                    })
        
        updates.sort(key=lambda x: x['timestamp'], reverse=True)
        return updates[:limit]
    
    def _get_oldest_active(self, limit: int = 10) -> List[Dict]:
        """Get oldest active documents."""
        active_docs = [
            doc for doc in self.tracking_data['documents'].values()
            if doc['status'] == 'active'
        ]
        active_docs.sort(key=lambda x: x['created_at'])
        return active_docs[:limit]
    
    def generate_report(self) -> None:
        """Generate documentation status report."""
        # Create output directory if it doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Prepare report data
        report_data = {
            'overall_stats': self._get_overall_stats(),
            'category_stats': self._get_category_stats(),
            'recent_updates': self._get_recent_updates(),
            'oldest_active': self._get_oldest_active(),
            'generated_at': datetime.now().isoformat()
        }
        
        # Generate HTML report
        template = self.env.get_template('status_report.html')
        html_content = template.render(**report_data)
        
        # Save HTML report
        report_file = self.output_dir / 'status_report.html'
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # Save JSON data
        data_file = self.output_dir / 'status_data.json'
        with open(data_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"Status report generated: {report_file}")
        print(f"Status data saved: {data_file}")

def main():
    if len(sys.argv) < 3:
        print("Usage: python generate_status_report.py <docs_directory> <output_directory>")
        sys.exit(1)
    
    docs_dir = sys.argv[1]
    output_dir = sys.argv[2]
    
    generator = StatusReportGenerator(docs_dir, output_dir)
    generator.generate_report()

if __name__ == '__main__':
    main() 