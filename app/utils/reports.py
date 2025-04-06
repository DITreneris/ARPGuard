import os
import csv
import json
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
import numpy as np
import io

from app.utils.logger import get_logger
from app.utils.database import get_database

# Module logger
logger = get_logger('utils.reports')

class ReportGenerator:
    """Generates comprehensive reports with visualizations from captured data."""
    
    def __init__(self):
        """Initialize the report generator."""
        self.database = get_database()
        
    def generate_session_report(self, session_id: int, output_format: str = 'html', 
                               output_path: Optional[str] = None) -> str:
        """Generate a comprehensive report for a capture session.
        
        Args:
            session_id: ID of the capture session
            output_format: 'html', 'pdf', or 'markdown'
            output_path: Path to save the report (None for default location)
            
        Returns:
            str: Path to the generated report file
        """
        # Get session data
        session_summary = self.database.get_session_summary(session_id)
        
        if not session_summary:
            logger.error(f"No data found for session {session_id}")
            return ""
            
        # Create report content based on format
        if output_format == 'html':
            report_content = self._generate_html_report(session_summary)
            ext = '.html'
        elif output_format == 'pdf':
            # For PDF we'll generate HTML first then convert
            report_content = self._generate_html_report(session_summary)
            ext = '.pdf'
        elif output_format == 'markdown':
            report_content = self._generate_markdown_report(session_summary)
            ext = '.md'
        else:
            logger.error(f"Unsupported output format: {output_format}")
            return ""
            
        # Determine output path if not provided
        if not output_path:
            # Use default location in user documents
            home_dir = os.path.expanduser("~")
            docs_dir = os.path.join(home_dir, "Documents")
            
            if not os.path.exists(docs_dir):
                docs_dir = home_dir
                
            # Create output filename based on session details
            timestamp = session_summary['start_time'].strftime("%Y%m%d_%H%M%S")
            filename = f"arpguard_session_{session_id}_{timestamp}{ext}"
            output_path = os.path.join(docs_dir, filename)
            
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        # Write report to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
            
        logger.info(f"Generated {output_format} report for session {session_id} at {output_path}")
        
        # For PDF, convert HTML to PDF
        if output_format == 'pdf':
            html_path = output_path
            output_path = html_path.replace('.pdf', '.pdf')
            
            try:
                # Try to use weasyprint for PDF generation if available
                from weasyprint import HTML
                HTML(html_path).write_pdf(output_path)
                os.remove(html_path)  # Remove the intermediate HTML file
                logger.info(f"Converted HTML to PDF: {output_path}")
            except ImportError:
                logger.warning("WeasyPrint not available, PDF conversion skipped")
                output_path = html_path  # Fall back to HTML
                
        return output_path
        
    def _generate_html_report(self, session_data: Dict[str, Any]) -> str:
        """Generate an HTML report for the session.
        
        Args:
            session_data: Dictionary with session data
            
        Returns:
            str: HTML report content
        """
        # Generate charts and encode as base64 for embedding
        traffic_chart = self._generate_traffic_chart(session_data['id'])
        protocol_chart = self._generate_protocol_chart(session_data)
        
        # Format timestamps
        start_time = session_data['start_time'].strftime("%Y-%m-%d %H:%M:%S")
        end_time = "N/A"
        if session_data['end_time']:
            end_time = session_data['end_time'].strftime("%Y-%m-%d %H:%M:%S")
            
        # Format duration
        duration = f"{session_data['duration_seconds']:.1f}"
        
        # Format interface and filter
        interface = session_data.get('interface', 'Default')
        capture_filter = session_data.get('filter', 'None')
        
        # Create protocol distribution table
        protocol_rows = ""
        for protocol, count in session_data['protocol_distribution'].items():
            percentage = (count / max(1, session_data['packet_count'])) * 100
            protocol_rows += f"""
            <tr>
                <td>{protocol}</td>
                <td>{count}</td>
                <td>{percentage:.1f}%</td>
            </tr>
            """
            
        # Create top talkers table
        talker_rows = ""
        for ip, stats in session_data['top_talkers'].items():
            talker_rows += f"""
            <tr>
                <td>{ip}</td>
                <td>{stats['sent_packets']}</td>
                <td>{stats['recv_packets']}</td>
                <td>{stats['sent_packets'] + stats['recv_packets']}</td>
            </tr>
            """
            
        # Build the HTML report
        html = f"""<!DOCTYPE html>
        <html>
        <head>
            <title>ARPGuard Network Capture Report - Session {session_data['id']}</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                h1, h2, h3 {{
                    color: #2c3e50;
                }}
                table {{
                    border-collapse: collapse;
                    width: 100%;
                    margin-bottom: 20px;
                }}
                th, td {{
                    border: 1px solid #ddd;
                    padding: 8px;
                    text-align: left;
                }}
                th {{
                    background-color: #f2f2f2;
                }}
                tr:nth-child(even) {{
                    background-color: #f9f9f9;
                }}
                .chart-container {{
                    width: 100%;
                    max-width: 800px;
                    margin: 20px auto;
                }}
                .summary-grid {{
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 20px;
                }}
                .metadata {{
                    background-color: #f8f9fa;
                    padding: 15px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }}
                .footer {{
                    margin-top: 30px;
                    font-size: 0.8em;
                    color: #777;
                    text-align: center;
                }}
            </style>
        </head>
        <body>
            <h1>ARPGuard Network Capture Report</h1>
            
            <div class="metadata">
                <h2>Session Information</h2>
                <table>
                    <tr><th>Session ID</th><td>{session_data['id']}</td></tr>
                    <tr><th>Description</th><td>{session_data.get('description', 'N/A')}</td></tr>
                    <tr><th>Start Time</th><td>{start_time}</td></tr>
                    <tr><th>End Time</th><td>{end_time}</td></tr>
                    <tr><th>Duration</th><td>{duration} seconds</td></tr>
                    <tr><th>Interface</th><td>{interface}</td></tr>
                    <tr><th>Filter</th><td>{capture_filter}</td></tr>
                    <tr><th>Total Packets</th><td>{session_data['packet_count']}</td></tr>
                    <tr><th>Total Bytes</th><td>{session_data['bytes_total']} ({self._format_bytes(session_data['bytes_total'])})</td></tr>
                </table>
            </div>
            
            <div class="summary-grid">
                <div>
                    <h2>Traffic Over Time</h2>
                    <div class="chart-container">
                        <img src="data:image/png;base64,{traffic_chart}" alt="Traffic Over Time" width="100%">
                    </div>
                </div>
                
                <div>
                    <h2>Protocol Distribution</h2>
                    <div class="chart-container">
                        <img src="data:image/png;base64,{protocol_chart}" alt="Protocol Distribution" width="100%">
                    </div>
                </div>
            </div>
            
            <h2>Protocol Details</h2>
            <table>
                <tr>
                    <th>Protocol</th>
                    <th>Packet Count</th>
                    <th>Percentage</th>
                </tr>
                {protocol_rows}
            </table>
            
            <h2>Top Talkers</h2>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Packets Sent</th>
                    <th>Packets Received</th>
                    <th>Total Packets</th>
                </tr>
                {talker_rows}
            </table>
            
            <div class="footer">
                <p>Generated by ARPGuard on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            </div>
        </body>
        </html>
        """
        
        return html
        
    def _generate_markdown_report(self, session_data: Dict[str, Any]) -> str:
        """Generate a Markdown report for the session.
        
        Args:
            session_data: Dictionary with session data
            
        Returns:
            str: Markdown report content
        """
        # Format timestamps
        start_time = session_data['start_time'].strftime("%Y-%m-%d %H:%M:%S")
        end_time = "N/A"
        if session_data['end_time']:
            end_time = session_data['end_time'].strftime("%Y-%m-%d %H:%M:%S")
            
        # Format duration
        duration = f"{session_data['duration_seconds']:.1f}"
        
        # Format interface and filter
        interface = session_data.get('interface', 'Default')
        capture_filter = session_data.get('filter', 'None')
        
        # Generate protocol distribution table
        protocol_table = "| Protocol | Packet Count | Percentage |\n"
        protocol_table += "|----------|--------------|------------|\n"
        
        for protocol, count in session_data['protocol_distribution'].items():
            percentage = (count / max(1, session_data['packet_count'])) * 100
            protocol_table += f"| {protocol} | {count} | {percentage:.1f}% |\n"
            
        # Generate top talkers table
        talkers_table = "| IP Address | Packets Sent | Packets Received | Total Packets |\n"
        talkers_table += "|------------|--------------|------------------|---------------|\n"
        
        for ip, stats in session_data['top_talkers'].items():
            total = stats['sent_packets'] + stats['recv_packets']
            talkers_table += f"| {ip} | {stats['sent_packets']} | {stats['recv_packets']} | {total} |\n"
            
        # Build the Markdown report
        markdown = f"""# ARPGuard Network Capture Report

## Session Information

- **Session ID:** {session_data['id']}
- **Description:** {session_data.get('description', 'N/A')}
- **Start Time:** {start_time}
- **End Time:** {end_time}
- **Duration:** {duration} seconds
- **Interface:** {interface}
- **Filter:** {capture_filter}
- **Total Packets:** {session_data['packet_count']}
- **Total Bytes:** {session_data['bytes_total']} ({self._format_bytes(session_data['bytes_total'])})

## Protocol Distribution

{protocol_table}

## Top Talkers

{talkers_table}

*Note: Charts and graphs are only available in HTML and PDF reports.*

---

Generated by ARPGuard on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
        
        return markdown
        
    def _generate_traffic_chart(self, session_id: int) -> str:
        """Generate a chart of traffic over time.
        
        Args:
            session_id: ID of the capture session
            
        Returns:
            str: Base64-encoded PNG image
        """
        # Get traffic data
        traffic_data = self.database.get_traffic_over_time(session_id)
        
        if not traffic_data:
            # Return placeholder image
            return self._generate_placeholder_chart("No traffic data available")
            
        # Extract data for plotting
        timestamps = [data['timestamp'] for data in traffic_data]
        packet_rates = [data['packets_per_second'] for data in traffic_data]
        byte_rates = [data['bytes_per_second'] / 1024 for data in traffic_data]  # KB/s
        
        # Create figure
        fig, ax1 = plt.subplots(figsize=(10, 5))
        
        # Plot packet rate
        color = 'tab:blue'
        ax1.set_xlabel('Time')
        ax1.set_ylabel('Packets/second', color=color)
        ax1.plot(timestamps, packet_rates, color=color, marker='o', linestyle='-', markersize=3)
        ax1.tick_params(axis='y', labelcolor=color)
        
        # Create second y-axis
        ax2 = ax1.twinx()
        color = 'tab:red'
        ax2.set_ylabel('KB/second', color=color)
        ax2.plot(timestamps, byte_rates, color=color, marker='s', linestyle='-', markersize=3)
        ax2.tick_params(axis='y', labelcolor=color)
        
        # Set title and grid
        plt.title('Traffic Rate Over Time')
        ax1.grid(True, alpha=0.3)
        
        # Rotate date labels
        plt.gcf().autofmt_xdate()
        
        # Tight layout
        fig.tight_layout()
        
        # Convert to base64
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=100)
        buffer.seek(0)
        import base64
        image_png = buffer.getvalue()
        buffer.close()
        plt.close(fig)
        
        # Return base64 encoded string
        return base64.b64encode(image_png).decode('utf-8')
        
    def _generate_protocol_chart(self, session_data: Dict[str, Any]) -> str:
        """Generate a pie chart of protocol distribution.
        
        Args:
            session_data: Session data with protocol distribution
            
        Returns:
            str: Base64-encoded PNG image
        """
        protocol_dist = session_data.get('protocol_distribution', {})
        
        if not protocol_dist:
            # Return placeholder image
            return self._generate_placeholder_chart("No protocol data available")
            
        # Get the top 5 protocols, group the rest as 'Other'
        top_protocols = sorted(protocol_dist.items(), key=lambda x: x[1], reverse=True)
        
        if len(top_protocols) > 5:
            top_5 = top_protocols[:5]
            others_count = sum(count for _, count in top_protocols[5:])
            if others_count > 0:
                top_5.append(('Other', others_count))
            protocols = [p[0] for p in top_5]
            counts = [p[1] for p in top_5]
        else:
            protocols = [p[0] for p in top_protocols]
            counts = [p[1] for p in top_protocols]
            
        # Create pie chart
        fig, ax = plt.subplots(figsize=(8, 6))
        
        # Define a color map for common protocols
        color_map = {
            'TCP': '#3498db',
            'UDP': '#2ecc71',
            'ICMP': '#e74c3c',
            'ARP': '#f39c12',
            'HTTP': '#9b59b6',
            'DNS': '#1abc9c',
            'Other': '#95a5a6'
        }
        
        colors = [color_map.get(protocol, '#34495e') for protocol in protocols]
        
        # Plot pie chart
        wedges, texts, autotexts = ax.pie(
            counts, 
            labels=protocols, 
            autopct='%1.1f%%',
            startangle=90,
            colors=colors
        )
        
        # Equal aspect ratio ensures that pie is drawn as a circle
        ax.axis('equal')
        plt.title('Protocol Distribution')
        
        # Make texts more readable
        for text in texts:
            text.set_fontsize(9)
        for autotext in autotexts:
            autotext.set_fontsize(9)
            autotext.set_color('white')
            
        # Tight layout
        fig.tight_layout()
        
        # Convert to base64
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=100)
        buffer.seek(0)
        import base64
        image_png = buffer.getvalue()
        buffer.close()
        plt.close(fig)
        
        # Return base64 encoded string
        return base64.b64encode(image_png).decode('utf-8')
        
    def _generate_placeholder_chart(self, message: str) -> str:
        """Generate a placeholder chart with a message.
        
        Args:
            message: Message to display
            
        Returns:
            str: Base64-encoded PNG image
        """
        fig, ax = plt.subplots(figsize=(8, 5))
        
        # Create a gray rectangle
        ax.add_patch(plt.Rectangle((0, 0), 1, 1, fill=True, color='#f2f2f2', transform=ax.transAxes))
        
        # Add text
        ax.text(0.5, 0.5, message, ha='center', va='center', transform=ax.transAxes, fontsize=14)
        
        # Remove axes
        ax.axis('off')
        
        # Convert to base64
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=100)
        buffer.seek(0)
        import base64
        image_png = buffer.getvalue()
        buffer.close()
        plt.close(fig)
        
        # Return base64 encoded string
        return base64.b64encode(image_png).decode('utf-8')
        
    def _format_bytes(self, num_bytes):
        """Format bytes into human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if num_bytes < 1024.0:
                return f"{num_bytes:.1f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} TB"


# Create a singleton instance
_report_generator = None

def get_report_generator() -> ReportGenerator:
    """Get the report generator singleton instance.
    
    Returns:
        ReportGenerator: The report generator instance
    """
    global _report_generator
    if _report_generator is None:
        _report_generator = ReportGenerator()
    return _report_generator 