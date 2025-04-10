# Linux Installation Guide for ARP Guard

## System Requirements

- Linux distribution (Ubuntu 20.04+, Debian 11+, Fedora 34+, or equivalent)
- Python 3.8 or higher
- Root privileges (for packet capture)
- Network interface with promiscuous mode support
- At least 100MB free disk space

## Installation Methods

### Option 1: Using the Installation Script (Recommended)

1. **Download the installation script**
   ```bash
   curl -o install_linux.sh https://raw.githubusercontent.com/yourorg/arp-guard/main/scripts/install_linux.sh
   ```

2. **Make the script executable**
   ```bash
   chmod +x install_linux.sh
   ```

3. **Run the installation script**
   ```bash
   sudo ./install_linux.sh
   ```
   
4. **Verify installation**
   ```bash
   arp-guard --version
   ```

### Option 2: Package Manager Installation

#### For Debian/Ubuntu:

1. **Install prerequisites**
   ```bash
   sudo apt update
   sudo apt install -y python3 python3-pip python3-venv libpcap-dev tcpdump
   ```

2. **Install ARP Guard**
   ```bash
   sudo pip3 install arp-guard
   ```

#### For Fedora/RHEL/CentOS:

1. **Install prerequisites**
   ```bash
   sudo dnf install -y python3 python3-pip python3-devel libpcap-devel tcpdump
   ```

2. **Install ARP Guard**
   ```bash
   sudo pip3 install arp-guard
   ```

#### For Arch Linux:

1. **Install prerequisites**
   ```bash
   sudo pacman -Sy python python-pip libpcap tcpdump
   ```

2. **Install ARP Guard**
   ```bash
   sudo pip install arp-guard
   ```

### Option 3: Manual Installation

1. **Install system dependencies**
   
   For Debian/Ubuntu:
   ```bash
   sudo apt update
   sudo apt install -y python3 python3-pip python3-venv libpcap-dev git tcpdump
   ```

2. **Clone the repository**
   ```bash
   git clone https://github.com/yourorg/arp-guard.git
   cd arp-guard
   ```

3. **Create and activate a virtual environment (recommended)**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

4. **Install the package**
   ```bash
   pip install -e .
   ```

## Running ARP Guard

### As a Command-Line Tool

```bash
# Start ARP Guard monitoring
sudo arp-guard start

# Check status
arp-guard status

# Stop monitoring
sudo arp-guard stop
```

### As a Systemd Service

1. **Install the service**
   ```bash
   sudo arp-guard service install
   ```

2. **Enable and start the service**
   ```bash
   sudo systemctl enable arpguard
   sudo systemctl start arpguard
   ```

3. **Check service status**
   ```bash
   sudo systemctl status arpguard
   ```

### Service Management

```bash
# Stop the service
sudo systemctl stop arpguard

# Restart the service
sudo systemctl restart arpguard

# View logs
sudo journalctl -u arpguard
```

## Configuration

The default configuration file is located at `/etc/arpguard/config.yaml`. You can modify this file to customize ARP Guard's behavior:

```bash
# Edit configuration
sudo nano /etc/arpguard/config.yaml
```

After changing the configuration, restart the service:
```bash
sudo systemctl restart arpguard
```

## Common Issues and Solutions

### Error: "Couldn't create socket. Operation not permitted"
- Make sure to run with sudo privileges
- Check if the current user is in the correct group: `sudo usermod -a -G pcap $USER`

### Error: "ImportError: No module named scapy"
- Install Scapy manually: `pip install scapy`
- Check if Python dependencies installed correctly

### ARP Guard not detecting network traffic
- Make sure promiscuous mode is enabled on your interface
- Check if your distribution has any additional firewall rules blocking packet capture
- Verify tcpdump works: `sudo tcpdump -i eth0 arp`

## Uninstallation

```bash
# Remove the systemd service first (if installed)
sudo arp-guard service uninstall

# Uninstall the package
sudo pip3 uninstall arp-guard

# Remove configuration files
sudo rm -rf /etc/arpguard
```

For further assistance, please check our [troubleshooting guide](../troubleshooting.md) or open an issue on GitHub. 