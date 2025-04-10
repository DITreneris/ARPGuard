# ARP Guard Demo Dashboard

A real-time dashboard for monitoring and visualizing ARP Guard's network protection capabilities.

## Features

- Real-time network monitoring and visualization
- ARP packet capture and analysis
- Network topology mapping
- Threat detection and alerting
- System performance metrics
- Interactive dashboard with responsive design

## Prerequisites

- Python 3.8+
- FastAPI
- Scapy (for packet capture)
- Chart.js (included via CDN)
- Bootstrap 5 (included via CDN)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/your-username/arp-guard.git
   cd arp-guard
   ```

2. Install required packages:
   ```
   pip install fastapi uvicorn scapy jinja2
   ```

3. Additional requirements for packet capture:
   - Windows: Install [Npcap](https://npcap.com/#download) or [WinPcap](https://www.winpcap.org/install/)
   - Linux: May require root privileges to capture packets

## Running the Dashboard

1. Navigate to the dashboard directory:
   ```
   cd src/demo/dashboard
   ```

2. Start the FastAPI server:
   ```
   python server.py
   ```
   
   Alternatively, you can use Uvicorn directly:
   ```
   uvicorn server:app --host 0.0.0.0 --port 8000 --reload
   ```

3. Open your browser and navigate to:
   ```
   http://localhost:8000
   ```

## Using the Dashboard

1. **Overview**: Shows system status, network activity, and threat level metrics
2. **Network View**: Displays the network topology as discovered by ARP Guard
3. **Alerts**: Lists security alerts with details and acknowledgment options
4. **Metrics**: Visualizes packet rates and threat levels over time

## Demo Mode

1. Click the "Start Demo" button to begin packet capture and analysis
2. Monitor real-time updates across all dashboard sections
3. Click "Stop Demo" to end the capture session

## Important Notes

- **Administrator/Root Privileges**: Packet capture requires elevated privileges
- **Security**: This is a demo application and should not be used in production without security hardening
- **Simulation**: When no packets are detected, the dashboard will simulate activity for demonstration purposes

## Troubleshooting

- **No Packets Captured**: Ensure you have sufficient privileges and correct network adapter permissions
- **WebSocket Connection Issues**: Check for firewall settings blocking WebSocket connections
- **Visualization Problems**: Make sure JavaScript is enabled in your browser

## License

[Include your license information here] 