# Windows Installation Guide

## Prerequisites

Before installing ARP Guard, ensure your system meets these requirements:

- Windows 10 or later
- Python 3.8 or later
- Administrator privileges
- Network interface with ARP support
- 100 MB free disk space
- 512 MB RAM minimum

## Installation Methods

### Method 1: Using PowerShell (Recommended)

1. Open PowerShell as Administrator
2. Run the following commands:

```powershell
# Create installation directory
New-Item -ItemType Directory -Path "C:\Program Files\ARP Guard" -Force

# Download and install Python if not present
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    winget install Python.Python.3.11
}

# Create virtual environment
python -m venv "C:\Program Files\ARP Guard\venv"

# Activate virtual environment
& "C:\Program Files\ARP Guard\venv\Scripts\Activate.ps1"

# Install ARP Guard
pip install arp-guard

# Add to PATH
$env:Path += ";C:\Program Files\ARP Guard\venv\Scripts"
[Environment]::SetEnvironmentVariable("Path", $env:Path, [EnvironmentVariableTarget]::Machine)
```

### Method 2: Manual Installation

1. Download the latest release from GitHub
2. Extract the files to `C:\Program Files\ARP Guard`
3. Open Command Prompt as Administrator
4. Navigate to the installation directory
5. Run the following commands:

```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Configuration

1. Create a configuration file at `C:\Program Files\ARP Guard\config.yaml`:

```yaml
network:
  interface: "Ethernet"  # Your network interface name
  scan_interval: 60      # Seconds between scans
  alert_threshold: 3     # Number of changes before alert

logging:
  level: "INFO"
  file: "C:\Program Files\ARP Guard\logs\arp_guard.log"
```

2. Set up the service:

```powershell
# Create service
New-Service -Name "ARP Guard" -BinaryPathName "C:\Program Files\ARP Guard\venv\Scripts\python.exe C:\Program Files\ARP Guard\main.py" -DisplayName "ARP Guard" -StartupType Automatic

# Start service
Start-Service "ARP Guard"
```

## Verification

To verify the installation:

1. Check service status:
```powershell
Get-Service "ARP Guard"
```

2. View logs:
```powershell
Get-Content "C:\Program Files\ARP Guard\logs\arp_guard.log"
```

3. Test the CLI:
```powershell
arp-guard status
```

## Common Issues

### Issue 1: Python Not Found
**Solution:**
- Ensure Python is installed and in PATH
- Run `python --version` to verify installation
- Reinstall Python if necessary

### Issue 2: Permission Errors
**Solution:**
- Run PowerShell/Command Prompt as Administrator
- Check file permissions on installation directory
- Ensure service has proper permissions

### Issue 3: Network Interface Not Found
**Solution:**
- Verify interface name in config.yaml
- Run `Get-NetAdapter` to list available interfaces
- Update config.yaml with correct interface name

### Issue 4: Service Won't Start
**Solution:**
- Check event logs for errors
- Verify Python path in service configuration
- Ensure all dependencies are installed

## Uninstallation

1. Stop the service:
```powershell
Stop-Service "ARP Guard"
Remove-Service "ARP Guard"
```

2. Remove installation directory:
```powershell
Remove-Item -Path "C:\Program Files\ARP Guard" -Recurse -Force
```

3. Remove from PATH:
```powershell
$oldPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
$newPath = ($oldPath.Split(';') | Where-Object { $_ -ne "C:\Program Files\ARP Guard\venv\Scripts" }) -join ';'
[Environment]::SetEnvironmentVariable("Path", $newPath, [EnvironmentVariableTarget]::Machine)
```

## Support

For additional support:
- Visit our GitHub repository
- Check the troubleshooting guide
- Open an issue with detailed error information 