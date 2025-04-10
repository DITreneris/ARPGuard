# macOS Installation Guide for ARP Guard

## System Requirements

- macOS 11 Big Sur or newer
- Python 3.8 or higher
- Administrator privileges
- Network interface with promiscuous mode support
- At least 100MB free disk space
- [Homebrew](https://brew.sh/) (recommended)
- XCode Command Line Tools

## Installation Methods

### Option 1: Using the Installation Script (Recommended)

1. **Download the installation script**
   ```bash
   curl -o install_macos.sh https://raw.githubusercontent.com/yourorg/arp-guard/main/scripts/install_macos.sh
   ```

2. **Make the script executable**
   ```bash
   chmod +x install_macos.sh
   ```

3. **Run the installation script**
   ```bash
   sudo ./install_macos.sh
   ```
   
4. **Verify installation**
   ```bash
   arp-guard --version
   ```

### Option 2: Using Homebrew

1. **Install Homebrew** (if not already installed)
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

2. **Install ARP Guard**
   ```bash
   brew install python libpcap
   pip3 install arp-guard
   ```

### Option 3: Manual Installation

1. **Install XCode Command Line Tools**
   ```bash
   xcode-select --install
   ```

2. **Install Python (if not already installed)**
   ```bash
   brew install python
   ```

3. **Install LibPCAP**
   ```bash
   brew install libpcap
   ```

4. **Clone the repository**
   ```bash
   git clone https://github.com/yourorg/arp-guard.git
   cd arp-guard
   ```

5. **Create and activate a virtual environment** (recommended)
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

6. **Install the package**
   ```bash
   pip install -e .
   ```

## Permission Requirements

ARP Guard requires special permissions to capture network traffic:

1. **Enable Full Disk Access**
   - Go to System Preferences > Security & Privacy > Privacy
   - Select "Full Disk Access" from the left sidebar
   - Click the lock icon to make changes (you'll need to enter your password)
   - Add Terminal or the application you're using to run ARP Guard

2. **Enable Network Filter Extension** (macOS Catalina or newer)
   - An approval dialogue may appear when running ARP Guard for the first time
   - Approve the extension in System Preferences > Security & Privacy > General

3. **Enable Network Monitoring Extensions** (If prompted)
   - Go to System Preferences > Security & Privacy > Privacy
   - Select "Network" from the left sidebar
   - Ensure Terminal or the ARP Guard application is enabled

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

### As a LaunchDaemon Service

1. **Install the service**
   ```bash
   sudo arp-guard service install
   ```

2. **Start the service**
   ```bash
   sudo launchctl load /Library/LaunchDaemons/com.arpguard.daemon.plist
   ```

3. **Check service status**
   ```bash
   sudo arp-guard service status
   ```

### Service Management

```bash
# Stop the service
sudo launchctl unload /Library/LaunchDaemons/com.arpguard.daemon.plist

# Restart the service
sudo launchctl unload /Library/LaunchDaemons/com.arpguard.daemon.plist
sudo launchctl load /Library/LaunchDaemons/com.arpguard.daemon.plist

# View logs
log show --predicate 'subsystem contains "com.arpguard"' --last 1h
```

## Configuration

The default configuration file is located at `/etc/arpguard/config.yaml`. You can modify this file to customize ARP Guard's behavior:

```bash
# Edit configuration
sudo nano /etc/arpguard/config.yaml
```

After changing the configuration, restart the service:
```bash
sudo launchctl unload /Library/LaunchDaemons/com.arpguard.daemon.plist
sudo launchctl load /Library/LaunchDaemons/com.arpguard.daemon.plist
```

## Common Issues and Solutions

### Error: "Scapy: Permission denied"
- Make sure to run with sudo privileges
- Check if the Terminal app has Full Disk Access permission

### Error: "No module named 'scapy'"
- Install Scapy manually: `pip3 install scapy`
- Check if Python dependencies installed correctly

### ARP Guard not detecting network traffic
- Make sure promiscuous mode is enabled on your interface
- Check if your macOS firewall is blocking packet capture
- Verify tcpdump works: `sudo tcpdump -i en0 arp`

### Installation fails with "Operation not permitted"
- Check if System Integrity Protection (SIP) is preventing installation
- Make sure you're using sudo for commands that require elevated privileges

## Uninstallation

```bash
# Remove the LaunchDaemon service first (if installed)
sudo launchctl unload /Library/LaunchDaemons/com.arpguard.daemon.plist
sudo rm /Library/LaunchDaemons/com.arpguard.daemon.plist

# Uninstall the package
sudo pip3 uninstall arp-guard

# Remove configuration files
sudo rm -rf /etc/arpguard
```

For further assistance, please check our [troubleshooting guide](../troubleshooting.md) or open an issue on GitHub. 