# Linux Installation Guide

## Prerequisites

Before installing ARP Guard, ensure your system meets these requirements:

- Linux kernel 4.4 or later
- Python 3.8 or later
- Root or sudo privileges
- Network interface with ARP support
- 100 MB free disk space
- 512 MB RAM minimum
- systemd (for service management)

## Installation Methods

### Method 1: Using Package Manager (Recommended)

#### Debian/Ubuntu
```bash
# Add repository and install
curl -s https://arp-guard.github.io/install.sh | sudo bash
sudo apt update
sudo apt install arp-guard
```

#### RHEL/CentOS
```bash
# Add repository and install
curl -s https://arp-guard.github.io/install.sh | sudo bash
sudo yum install arp-guard
```

### Method 2: Manual Installation

1. Download the latest release:
```bash
wget https://github.com/arp-guard/arp-guard/releases/latest/download/arp-guard.tar.gz
```

2. Extract and install:
```bash
# Create installation directory
sudo mkdir -p /opt/arp-guard

# Extract files
sudo tar -xzf arp-guard.tar.gz -C /opt/arp-guard

# Create virtual environment
cd /opt/arp-guard
sudo python3 -m venv venv
source venv/bin/activate

# Install dependencies
sudo pip install -r requirements.txt
```

## Configuration

1. Create configuration file:
```bash
sudo mkdir -p /etc/arp-guard
sudo nano /etc/arp-guard/config.yaml
```

2. Add configuration:
```yaml
network:
  interface: "eth0"      # Your network interface name
  scan_interval: 60      # Seconds between scans
  alert_threshold: 3     # Number of changes before alert

logging:
  level: "INFO"
  file: "/var/log/arp-guard/arp_guard.log"
```

3. Set up systemd service:
```bash
sudo nano /etc/systemd/system/arp-guard.service
```

4. Add service configuration:
```ini
[Unit]
Description=ARP Guard Network Security
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/arp-guard
Environment="PATH=/opt/arp-guard/venv/bin"
ExecStart=/opt/arp-guard/venv/bin/python main.py
Restart=always

[Install]
WantedBy=multi-user.target
```

5. Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable arp-guard
sudo systemctl start arp-guard
```

## Verification

To verify the installation:

1. Check service status:
```bash
sudo systemctl status arp-guard
```

2. View logs:
```bash
sudo journalctl -u arp-guard -f
```

3. Test the CLI:
```bash
arp-guard status
```

## Common Issues

### Issue 1: Python Not Found
**Solution:**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
```

### Issue 2: Permission Errors
**Solution:**
- Ensure proper permissions:
```bash
sudo chown -R root:root /opt/arp-guard
sudo chmod -R 755 /opt/arp-guard
```

### Issue 3: Network Interface Not Found
**Solution:**
- List available interfaces:
```bash
ip link show
```
- Update config.yaml with correct interface name

### Issue 4: Service Won't Start
**Solution:**
- Check systemd logs:
```bash
sudo journalctl -u arp-guard
```
- Verify Python path and permissions
- Check configuration file syntax

## Uninstallation

### Package Manager Installation
```bash
# Debian/Ubuntu
sudo apt remove arp-guard
sudo apt autoremove

# RHEL/CentOS
sudo yum remove arp-guard
```

### Manual Installation
```bash
# Stop and disable service
sudo systemctl stop arp-guard
sudo systemctl disable arp-guard

# Remove files
sudo rm -rf /opt/arp-guard
sudo rm -rf /etc/arp-guard
sudo rm /etc/systemd/system/arp-guard.service

# Reload systemd
sudo systemctl daemon-reload
```

## Support

For additional support:
- Visit our GitHub repository
- Check the troubleshooting guide
- Open an issue with detailed error information 