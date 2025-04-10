# macOS Installation Guide

## Prerequisites

Before installing ARP Guard, ensure your system meets these requirements:

- macOS 10.15 (Catalina) or later
- Python 3.8 or later
- Administrator privileges
- Network interface with ARP support
- 100 MB free disk space
- 512 MB RAM minimum
- Homebrew (recommended)

## Installation Methods

### Method 1: Using Homebrew (Recommended)

1. Install Homebrew if not already installed:
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

2. Install ARP Guard:
```bash
brew tap arp-guard/arp-guard
brew install arp-guard
```

### Method 2: Manual Installation

1. Download the latest release:
```bash
curl -LO https://github.com/arp-guard/arp-guard/releases/latest/download/arp-guard.tar.gz
```

2. Extract and install:
```bash
# Create installation directory
sudo mkdir -p /usr/local/arp-guard

# Extract files
sudo tar -xzf arp-guard.tar.gz -C /usr/local/arp-guard

# Create virtual environment
cd /usr/local/arp-guard
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Configuration

1. Create configuration file:
```bash
sudo mkdir -p /usr/local/etc/arp-guard
sudo nano /usr/local/etc/arp-guard/config.yaml
```

2. Add configuration:
```yaml
network:
  interface: "en0"       # Your network interface name
  scan_interval: 60      # Seconds between scans
  alert_threshold: 3     # Number of changes before alert

logging:
  level: "INFO"
  file: "/usr/local/var/log/arp-guard/arp_guard.log"
```

3. Set up launchd service:
```bash
sudo nano /Library/LaunchDaemons/com.arpguard.plist
```

4. Add service configuration:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.arpguard</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/arp-guard/venv/bin/python</string>
        <string>/usr/local/arp-guard/main.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/usr/local/var/log/arp-guard/error.log</string>
    <key>StandardOutPath</key>
    <string>/usr/local/var/log/arp-guard/output.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/arp-guard/venv/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
```

5. Load and start the service:
```bash
sudo launchctl load /Library/LaunchDaemons/com.arpguard.plist
sudo launchctl start com.arpguard
```

## Verification

To verify the installation:

1. Check service status:
```bash
sudo launchctl list | grep arpguard
```

2. View logs:
```bash
tail -f /usr/local/var/log/arp-guard/arp_guard.log
```

3. Test the CLI:
```bash
arp-guard status
```

## Common Issues

### Issue 1: Python Not Found
**Solution:**
```bash
brew install python
```

### Issue 2: Permission Errors
**Solution:**
- Ensure proper permissions:
```bash
sudo chown -R root:wheel /usr/local/arp-guard
sudo chmod -R 755 /usr/local/arp-guard
```

### Issue 3: Network Interface Not Found
**Solution:**
- List available interfaces:
```bash
networksetup -listallhardwareports
```
- Update config.yaml with correct interface name

### Issue 4: Service Won't Start
**Solution:**
- Check launchd logs:
```bash
sudo launchctl debug com.arpguard
```
- Verify Python path and permissions
- Check configuration file syntax

## Uninstallation

### Homebrew Installation
```bash
brew uninstall arp-guard
brew untap arp-guard/arp-guard
```

### Manual Installation
```bash
# Stop service
sudo launchctl unload /Library/LaunchDaemons/com.arpguard.plist

# Remove files
sudo rm -rf /usr/local/arp-guard
sudo rm -rf /usr/local/etc/arp-guard
sudo rm /Library/LaunchDaemons/com.arpguard.plist
```

## Support

For additional support:
- Visit our GitHub repository
- Check the troubleshooting guide
- Open an issue with detailed error information 