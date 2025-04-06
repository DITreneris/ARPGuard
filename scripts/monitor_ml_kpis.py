#!/usr/bin/env python3
import os
import sys
import json
import yaml
import datetime
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, List, Optional, Tuple
import argparse
from collections import defaultdict

class MLKPIMonitor:
    def __init__(self, data_dir: str, output_dir: str):
        self.data_dir = Path(data_dir)
        self.output_dir = Path(output_dir)
        self.kpi_file = self.data_dir / "ml_kpis.json"
        self.kpis = self._load_kpis()
        
        # Fix date to use 2024 instead of system date which may be incorrect
        # This ensures consistency with project_health.md date
        self.current_date = "2024-04-06"
        
        # Ensure directories exist
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)
        
    def _load_kpis(self) -> Dict:
        """Load KPI data from JSON file or initialize if not exists."""
        if self.kpi_file.exists():
            with open(self.kpi_file, 'r') as f:
                return json.load(f)
        else:
            return {
                "version": "1.0",
                "last_updated": "2024-04-06T00:00:00",
                "development_kpis": {
                    "ml_environment": [],
                    "implementation_progress": [],
                    "test_coverage": [],
                    "documentation": [],
                    "code_quality": []
                },
                "technical_kpis": {
                    "model_accuracy": [],
                    "false_positive_rate": [],
                    "inference_latency": [],
                    "memory_footprint": [],
                    "cpu_utilization": [],
                    "training_time": []
                },
                "operational_kpis": {
                    "model_drift": [],
                    "integration_status": [],
                    "resource_utilization": [],
                    "user_feedback": [],
                    "incident_response": []
                },
                "business_kpis": {
                    "feature_completion": [],
                    "quality_issues": [],
                    "adoption_rate": [],
                    "detection_improvement": [],
                    "cost_efficiency": []
                }
            }
    
    def _save_kpis(self) -> None:
        """Save KPI data to JSON file."""
        self.kpis["last_updated"] = "2024-04-06T00:00:00"
        with open(self.kpi_file, 'w') as f:
            json.dump(self.kpis, f, indent=2)
    
    def update_development_kpi(self, kpi_name: str, value: float, details: Optional[Dict] = None) -> None:
        """Update a development KPI with current value."""
        if kpi_name not in self.kpis["development_kpis"]:
            print(f"Unknown development KPI: {kpi_name}")
            return
        
        entry = {
            "date": self.current_date,
            "value": value,
            "details": details or {}
        }
        self.kpis["development_kpis"][kpi_name].append(entry)
        self._save_kpis()
        print(f"Updated development KPI: {kpi_name} = {value}")
    
    def update_technical_kpi(self, kpi_name: str, value: float, details: Optional[Dict] = None) -> None:
        """Update a technical KPI with current value."""
        if kpi_name not in self.kpis["technical_kpis"]:
            print(f"Unknown technical KPI: {kpi_name}")
            return
        
        entry = {
            "date": self.current_date,
            "value": value,
            "details": details or {}
        }
        self.kpis["technical_kpis"][kpi_name].append(entry)
        self._save_kpis()
        print(f"Updated technical KPI: {kpi_name} = {value}")
    
    def update_operational_kpi(self, kpi_name: str, value: float, details: Optional[Dict] = None) -> None:
        """Update an operational KPI with current value."""
        if kpi_name not in self.kpis["operational_kpis"]:
            print(f"Unknown operational KPI: {kpi_name}")
            return
        
        entry = {
            "date": self.current_date,
            "value": value,
            "details": details or {}
        }
        self.kpis["operational_kpis"][kpi_name].append(entry)
        self._save_kpis()
        print(f"Updated operational KPI: {kpi_name} = {value}")
    
    def update_business_kpi(self, kpi_name: str, value: float, details: Optional[Dict] = None) -> None:
        """Update a business KPI with current value."""
        if kpi_name not in self.kpis["business_kpis"]:
            print(f"Unknown business KPI: {kpi_name}")
            return
        
        entry = {
            "date": self.current_date,
            "value": value,
            "details": details or {}
        }
        self.kpis["business_kpis"][kpi_name].append(entry)
        self._save_kpis()
        print(f"Updated business KPI: {kpi_name} = {value}")
    
    def get_kpi_trend(self, category: str, kpi_name: str) -> List[Tuple[str, float]]:
        """Get trend data for a specific KPI."""
        if category not in self.kpis or kpi_name not in self.kpis[category]:
            return []
        
        return [(entry["date"], entry["value"]) for entry in self.kpis[category][kpi_name]]
    
    def generate_kpi_trend_chart(self, category: str, kpi_name: str) -> str:
        """Generate a trend chart for a specific KPI."""
        trend_data = self.get_kpi_trend(category, kpi_name)
        if not trend_data:
            return None
        
        dates, values = zip(*trend_data)
        
        plt.figure(figsize=(10, 6))
        plt.plot(dates, values, marker='o', linestyle='-', linewidth=2)
        plt.title(f"{kpi_name.replace('_', ' ').title()} Trend")
        plt.xlabel("Date")
        plt.ylabel("Value")
        plt.grid(True)
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        chart_path = self.output_dir / f"{category}_{kpi_name}_trend.png"
        plt.savefig(chart_path)
        plt.close()
        
        return str(chart_path)
    
    def generate_category_dashboard(self, category: str) -> str:
        """Generate a dashboard for a category of KPIs."""
        if category not in self.kpis:
            return None
        
        kpi_names = list(self.kpis[category].keys())
        if not kpi_names:
            return None
        
        fig, axes = plt.subplots(len(kpi_names), 1, figsize=(12, 4 * len(kpi_names)))
        
        for i, kpi_name in enumerate(kpi_names):
            trend_data = self.get_kpi_trend(category, kpi_name)
            if not trend_data:
                continue
            
            dates, values = zip(*trend_data)
            
            if len(kpi_names) == 1:
                ax = axes
            else:
                ax = axes[i]
            
            ax.plot(dates, values, marker='o', linestyle='-', linewidth=2)
            ax.set_title(f"{kpi_name.replace('_', ' ').title()}")
            ax.set_xlabel("Date")
            ax.set_ylabel("Value")
            ax.grid(True)
            ax.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        
        dashboard_path = self.output_dir / f"{category}_dashboard.png"
        plt.savefig(dashboard_path)
        plt.close()
        
        return str(dashboard_path)
    
    def generate_summary_report(self) -> str:
        """Generate a summary report of all KPIs."""
        report = {
            "generated_at": datetime.datetime.now().isoformat(),
            "kpi_summary": {},
            "charts": {}
        }
        
        for category in ["development_kpis", "technical_kpis", "operational_kpis", "business_kpis"]:
            report["kpi_summary"][category] = {}
            report["charts"][category] = {}
            
            for kpi_name in self.kpis[category]:
                trend_data = self.get_kpi_trend(category, kpi_name)
                if not trend_data:
                    report["kpi_summary"][category][kpi_name] = {
                        "current": None,
                        "previous": None,
                        "change": None
                    }
                    continue
                
                current = trend_data[-1][1] if trend_data else None
                previous = trend_data[-2][1] if len(trend_data) > 1 else None
                change = ((current - previous) / previous * 100) if current is not None and previous is not None and previous != 0 else None
                
                report["kpi_summary"][category][kpi_name] = {
                    "current": current,
                    "previous": previous,
                    "change": change
                }
                
                chart_path = self.generate_kpi_trend_chart(category, kpi_name)
                if chart_path:
                    report["charts"][category][kpi_name] = chart_path
            
            dashboard_path = self.generate_category_dashboard(category)
            if dashboard_path:
                report["charts"][category]["dashboard"] = dashboard_path
        
        # Save summary report
        report_path = self.output_dir / f"ml_kpi_summary_{self.current_date}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        return str(report_path)
    
    def generate_html_report(self) -> str:
        """Generate an HTML report of KPI dashboards."""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>ML KPI Dashboard - {self.current_date}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                h2 {{ color: #555; margin-top: 30px; }}
                .dashboard {{ margin-top: 20px; }}
                .kpi-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin-top: 20px; }}
                .kpi-card {{ border: 1px solid #ddd; border-radius: 5px; padding: 15px; }}
                .kpi-title {{ font-weight: bold; margin-bottom: 10px; }}
                .kpi-value {{ font-size: 24px; margin-bottom: 5px; }}
                .kpi-change {{ font-size: 14px; }}
                .positive {{ color: green; }}
                .negative {{ color: red; }}
                .neutral {{ color: #888; }}
                img {{ max-width: 100%; border: 1px solid #eee; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>ML KPI Dashboard</h1>
            <p>Generated on {self.current_date}</p>
        """
        
        for category_title, category in [
            ("Development KPIs", "development_kpis"),
            ("Technical Performance KPIs", "technical_kpis"),
            ("Operational KPIs", "operational_kpis"),
            ("Business KPIs", "business_kpis")
        ]:
            html_content += f"""
            <h2>{category_title}</h2>
            <div class="dashboard">
                <img src="{category}_dashboard.png" alt="{category} Dashboard">
            </div>
            <div class="kpi-grid">
            """
            
            for kpi_name in self.kpis[category]:
                trend_data = self.get_kpi_trend(category, kpi_name)
                current = trend_data[-1][1] if trend_data else "N/A"
                previous = trend_data[-2][1] if len(trend_data) > 1 else None
                
                if previous is not None and current != "N/A":
                    change = ((current - previous) / previous * 100) if previous != 0 else 0
                    change_class = "positive" if change >= 0 else "negative"
                    change_html = f'<div class="kpi-change {change_class}">{change:.1f}% from previous</div>'
                else:
                    change_html = '<div class="kpi-change neutral">No previous data</div>'
                
                html_content += f"""
                <div class="kpi-card">
                    <div class="kpi-title">{kpi_name.replace('_', ' ').title()}</div>
                    <div class="kpi-value">{current}</div>
                    {change_html}
                    <div class="kpi-chart">
                        <img src="{category}_{kpi_name}_trend.png" alt="{kpi_name} Trend">
                    </div>
                </div>
                """
            
            html_content += """
            </div>
            """
        
        html_content += """
        </body>
        </html>
        """
        
        html_path = self.output_dir / f"ml_kpi_dashboard_{self.current_date}.html"
        with open(html_path, 'w') as f:
            f.write(html_content)
        
        return str(html_path)

    def import_kpis_from_yaml(self, yaml_file: str) -> None:
        """Import KPI values from a YAML file."""
        try:
            with open(yaml_file, 'r') as f:
                data = yaml.safe_load(f)
            
            if 'date' in data:
                self.current_date = data['date']
            
            for category, kpis in data.items():
                if category in ['development_kpis', 'technical_kpis', 'operational_kpis', 'business_kpis']:
                    for kpi_name, kpi_data in kpis.items():
                        value = kpi_data.get('value')
                        details = kpi_data.get('details', {})
                        
                        if value is not None:
                            if category == 'development_kpis':
                                self.update_development_kpi(kpi_name, value, details)
                            elif category == 'technical_kpis':
                                self.update_technical_kpi(kpi_name, value, details)
                            elif category == 'operational_kpis':
                                self.update_operational_kpi(kpi_name, value, details)
                            elif category == 'business_kpis':
                                self.update_business_kpi(kpi_name, value, details)
            
            print(f"Successfully imported KPIs from {yaml_file}")
        except Exception as e:
            print(f"Error importing KPIs from {yaml_file}: {e}")


def main():
    parser = argparse.ArgumentParser(description='ML KPI Monitoring Tool')
    parser.add_argument('--data-dir', default='data/ml_kpis', help='Directory for KPI data storage')
    parser.add_argument('--output-dir', default='reports/ml_kpis', help='Directory for output reports')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Update KPI command
    update_parser = subparsers.add_parser('update', help='Update a KPI value')
    update_parser.add_argument('--category', required=True, choices=['development_kpis', 'technical_kpis', 'operational_kpis', 'business_kpis'], help='KPI category')
    update_parser.add_argument('--name', required=True, help='KPI name')
    update_parser.add_argument('--value', required=True, type=float, help='KPI value')
    update_parser.add_argument('--details', help='Additional details in JSON format')
    
    # Import KPIs command
    import_parser = subparsers.add_parser('import', help='Import KPIs from YAML file')
    import_parser.add_argument('--file', required=True, help='YAML file with KPI values')
    
    # Generate reports command
    report_parser = subparsers.add_parser('report', help='Generate KPI reports')
    report_parser.add_argument('--format', choices=['json', 'html', 'all'], default='all', help='Report format')
    
    # Chart generation command
    chart_parser = subparsers.add_parser('chart', help='Generate KPI charts')
    chart_parser.add_argument('--category', required=True, choices=['development_kpis', 'technical_kpis', 'operational_kpis', 'business_kpis'], help='KPI category')
    chart_parser.add_argument('--name', help='KPI name (optional, generates all if not specified)')
    
    args = parser.parse_args()
    
    monitor = MLKPIMonitor(args.data_dir, args.output_dir)
    
    if args.command == 'update':
        details = {}
        if args.details:
            try:
                details = json.loads(args.details)
            except json.JSONDecodeError:
                print(f"Error: Could not parse details as JSON: {args.details}")
                return
        
        if args.category == 'development_kpis':
            monitor.update_development_kpi(args.name, args.value, details)
        elif args.category == 'technical_kpis':
            monitor.update_technical_kpi(args.name, args.value, details)
        elif args.category == 'operational_kpis':
            monitor.update_operational_kpi(args.name, args.value, details)
        elif args.category == 'business_kpis':
            monitor.update_business_kpi(args.name, args.value, details)
    
    elif args.command == 'import':
        monitor.import_kpis_from_yaml(args.file)
    
    elif args.command == 'report':
        if args.format in ['json', 'all']:
            report_path = monitor.generate_summary_report()
            print(f"Generated JSON report: {report_path}")
        
        if args.format in ['html', 'all']:
            html_path = monitor.generate_html_report()
            print(f"Generated HTML report: {html_path}")
    
    elif args.command == 'chart':
        if args.name:
            chart_path = monitor.generate_kpi_trend_chart(args.category, args.name)
            if chart_path:
                print(f"Generated chart: {chart_path}")
            else:
                print(f"Error: Could not generate chart for {args.category}.{args.name}")
        else:
            dashboard_path = monitor.generate_category_dashboard(args.category)
            if dashboard_path:
                print(f"Generated dashboard: {dashboard_path}")
            else:
                print(f"Error: Could not generate dashboard for {args.category}")
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main() 