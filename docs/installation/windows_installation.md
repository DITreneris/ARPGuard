# Windows Installation Guide for ARP Guard

## Prerequisites

- Windows 10 or Windows 11 (64-bit recommended)
- Python 3.8 or higher installed
- Administrator privileges
- PowerShell 5.1 or higher
- Git (optional, for development version)
- Network adapter with promiscuous mode support

## Installation Options

### Option 1: Automated Installation (Recommended)

1. **Download the PowerShell installation script**
   - Download `install_windows.ps1` from the project repository

2. **Run PowerShell as Administrator**
   - Right-click on PowerShell in the Start menu
   - Select "Run as administrator"

3. **Allow script execution**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
   ```

4. **Run the installation script**
   ```powershell
   .\install_windows.ps1
   ```

5. **Verify installation**
   ```powershell
   arp-guard --version
   ```

### Option 2: Manual Installation

1. **Install Python dependencies**
   ```powershell
   pip install scapy colorama pywin32 click python-dotenv
   ```

2. **Clone or download the repository**
   ```powershell
   git clone https://github.com/yourorg/arp-guard.git
   cd arp-guard
   ```

3. **Install the package**
   ```powershell
   pip install -e .
   ```

4. **Configure Windows Firewall**
   - Allow ARP Guard through Windows Firewall
   - Open Windows Defender Firewall
   - Click "Allow an app or feature through Windows Defender Firewall"
   - Click "Change settings" and then "Allow another app"
   - Browse to the Python executable running ARP Guard
   - Select both Private and Public networks

5. **Install WinPcap/Npcap**
   - Download and install [Npcap](https://nmap.org/npcap/) or [WinPcap](https://www.winpcap.org/)
   - Make sure to select the option "Install Npcap in WinPcap API-compatible Mode"

## Running ARP Guard

### As a Command-Line Tool

```powershell
# Start ARP Guard monitoring
arp-guard start

# Check status
arp-guard status

# Stop monitoring
arp-guard stop
```

### As a Windows Service

1. **Install as a service**
   ```powershell
   arp-guard service install
   ```

2. **Start the service**
   ```powershell
   arp-guard service start
   # Or use Windows Services console
   ```

3. **Check service status**
   ```powershell
   arp-guard service status
   ```

## Common Issues and Solutions

### Error: "Scapy requires administrative privileges"
- Make sure to run PowerShell or Command Prompt as Administrator
- Check your user account has sufficient privileges

### Error: "No module named 'scapy'"
- Verify Python is in your PATH
- Reinstall the scapy package: `pip install scapy`

### ARP Guard not detecting network traffic
- Verify Npcap/WinPcap is installed correctly
- Check if your network adapter supports promiscuous mode
- Ensure Windows Firewall is not blocking the application

### Path issues after installation
- Log out and log back in to refresh environment variables
- Manually add the installation path to your PATH environment variable

## Uninstallation

```powershell
# Remove as a service first (if installed as service)
arp-guard service uninstall

# Uninstall package
pip uninstall arp-guard
```

For further assistance, please check our [troubleshooting guide](../troubleshooting.md) or open an issue on GitHub. 