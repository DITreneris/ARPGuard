# ARP Guard Windows Installation Script
# This script installs ARP Guard on Windows systems

#Requires -RunAsAdministrator

# Configuration
$INSTALL_DIR = "$env:ProgramFiles\ARP Guard"
$PYTHON_MIN_VERSION = "3.8.0"
$REQUIRED_PACKAGES = @("scapy", "colorama", "pywin32", "click", "pyyaml", "python-dotenv")
$GITHUB_REPO = "https://github.com/yourorg/arp-guard/archive/refs/heads/main.zip"
$DOWNLOAD_ZIP = "$env:TEMP\arp-guard.zip"
$EXTRACTED_DIR = "$env:TEMP\arp-guard-main"

# Text formatting
function Write-Title {
    param([string]$Text)
    Write-Host "`n==== $Text ====" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Text)
    Write-Host "► $Text" -ForegroundColor Green
}

function Write-Success {
    param([string]$Text)
    Write-Host "✓ $Text" -ForegroundColor Green
}

function Write-Error {
    param([string]$Text)
    Write-Host "✗ $Text" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Text)
    Write-Host "! $Text" -ForegroundColor Yellow
}

# Display header
Write-Host "`n"
Write-Host "ARP Guard - Windows Installation Script" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host "This script will install ARP Guard on your Windows system.`n"

# Check if running as administrator
Write-Step "Checking administrator privileges..."
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    Write-Host "Please right-click on PowerShell and select 'Run as Administrator'."
    exit 1
}
Write-Success "Running with administrator privileges."

# Check Python installation
Write-Title "Checking Python Installation"
try {
    $pythonVersion = python --version 2>&1
    if ($pythonVersion -match "Python (\d+\.\d+\.\d+)") {
        $version = $matches[1]
        Write-Success "Python $version found."
        
        # Check version
        $minVersion = [version]$PYTHON_MIN_VERSION
        $currentVersion = [version]$version
        
        if ($currentVersion -lt $minVersion) {
            Write-Warning "Python version $version is older than required version $PYTHON_MIN_VERSION."
            $installPython = Read-Host "Would you like to install Python $PYTHON_MIN_VERSION? (Y/N)"
            if ($installPython -eq "Y" -or $installPython -eq "y") {
                Write-Step "Opening Python download page..."
                Start-Process "https://www.python.org/downloads/"
                Write-Host "Please install Python and then run this script again."
                exit 0
            } else {
                Write-Warning "Continuing with older Python version. This may cause issues."
            }
        }
    } else {
        throw "Python not found"
    }
} catch {
    Write-Error "Python is not installed or not in PATH."
    $installPython = Read-Host "Would you like to install Python? (Y/N)"
    if ($installPython -eq "Y" -or $installPython -eq "y") {
        Write-Step "Opening Python download page..."
        Start-Process "https://www.python.org/downloads/"
        Write-Host "Please install Python and then run this script again."
        exit 0
    } else {
        Write-Error "Python is required for ARP Guard. Installation aborted."
        exit 1
    }
}

# Check for pip
Write-Step "Checking pip installation..."
try {
    $pipVersion = pip --version 2>&1
    Write-Success "pip found: $pipVersion"
} catch {
    Write-Error "pip not found. Attempting to install..."
    try {
        python -m ensurepip --upgrade
        Write-Success "pip installed successfully."
    } catch {
        Write-Error "Failed to install pip. Installation aborted."
        exit 1
    }
}

# Check/Install Npcap
Write-Title "Checking Npcap Installation"
Write-Step "Checking for Npcap/WinPcap..."

$npcapPresent = $false
# Try to load wpcap.dll which should be present if Npcap or WinPcap is installed
if (Test-Path "$env:SystemRoot\System32\wpcap.dll" -or 
    Test-Path "$env:windir\System32\Npcap\wpcap.dll" -or
    Test-Path "C:\Windows\System32\wpcap.dll") {
    $npcapPresent = $true
    Write-Success "Npcap/WinPcap found."
} else {
    Write-Warning "Npcap/WinPcap not found."
    $installNpcap = Read-Host "Would you like to install Npcap? (Y/N)"
    if ($installNpcap -eq "Y" -or $installNpcap -eq "y") {
        Write-Step "Downloading Npcap installer..."
        $npcapUrl = "https://nmap.org/npcap/dist/npcap-1.50.exe"
        $npcapInstaller = "$env:TEMP\npcap-installer.exe"
        
        try {
            Invoke-WebRequest -Uri $npcapUrl -OutFile $npcapInstaller
            Write-Success "Downloaded Npcap installer."
            
            Write-Step "Installing Npcap..."
            Start-Process -FilePath $npcapInstaller -ArgumentList "/S" -Wait
            
            Write-Success "Npcap installed successfully."
            $npcapPresent = $true
        } catch {
            Write-Error "Failed to download or install Npcap: $_"
            Write-Host "Please download and install Npcap manually from: https://nmap.org/npcap/"
        }
    } else {
        Write-Warning "Skipping Npcap installation. ARP Guard requires Npcap or WinPcap to function properly."
    }
}

# Install Python packages
Write-Title "Installing Python Dependencies"
foreach ($package in $REQUIRED_PACKAGES) {
    Write-Step "Checking package: $package"
    try {
        $pythonCommand = "import $package; print('Package found:', $package.__version__)"
        $output = python -c $pythonCommand 2>&1
        
        if ($output -match "Package found") {
            Write-Success "Package $package is already installed: $output"
        } else {
            throw "Package not found"
        }
    } catch {
        Write-Step "Installing package: $package"
        try {
            pip install $package
            Write-Success "Package $package installed successfully."
        } catch {
            Write-Error "Failed to install package $package: $_"
            exit 1
        }
    }
}

# Download and extract ARP Guard
Write-Title "Downloading ARP Guard"
Write-Step "Downloading from GitHub repository..."

try {
    # Create installation directory if it doesn't exist
    if (-not (Test-Path $INSTALL_DIR)) {
        New-Item -Path $INSTALL_DIR -ItemType Directory -Force | Out-Null
        Write-Success "Created installation directory: $INSTALL_DIR"
    }
    
    # Download the ZIP file
    Invoke-WebRequest -Uri $GITHUB_REPO -OutFile $DOWNLOAD_ZIP
    Write-Success "Downloaded ARP Guard source code."
    
    # Extract the ZIP file
    Write-Step "Extracting files..."
    Expand-Archive -Path $DOWNLOAD_ZIP -DestinationPath $env:TEMP -Force
    
    # Copy files to installation directory
    Write-Step "Copying files to installation directory..."
    Copy-Item -Path "$EXTRACTED_DIR\*" -Destination $INSTALL_DIR -Recurse -Force
    
    Write-Success "ARP Guard extracted to $INSTALL_DIR"
} catch {
    Write-Error "Error downloading or extracting ARP Guard: $_"
    exit 1
}

# Install ARP Guard
Write-Title "Installing ARP Guard"
Write-Step "Installing package..."

try {
    # Navigate to installation directory
    Push-Location $INSTALL_DIR
    
    # Install the package in development mode
    python -m pip install -e .
    
    # Return to original directory
    Pop-Location
    
    Write-Success "ARP Guard installed successfully."
} catch {
    Write-Error "Error installing ARP Guard: $_"
    exit 1
}

# Add to PATH if not already present
Write-Title "Configuring PATH"
Write-Step "Checking if ARP Guard is in PATH..."

$scriptsPath = "$env:ProgramFiles\ARP Guard\scripts"
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")

if ($envPath -notlike "*$scriptsPath*") {
    Write-Step "Adding ARP Guard to PATH..."
    try {
        [Environment]::SetEnvironmentVariable("PATH", "$envPath;$scriptsPath", "Machine")
        Write-Success "Added ARP Guard to PATH."
    } catch {
        Write-Error "Failed to add ARP Guard to PATH: $_"
        Write-Warning "You may need to manually add $scriptsPath to your PATH."
    }
} else {
    Write-Success "ARP Guard is already in PATH."
}

# Create batch file for easy execution
Write-Step "Creating arp-guard.bat file..."
$batchContent = @"
@echo off
python "$INSTALL_DIR\src\main.py" %*
"@

$batchFile = "$INSTALL_DIR\scripts\arp-guard.bat"
Set-Content -Path $batchFile -Value $batchContent

# Install Windows Service (optional)
Write-Title "Windows Service Setup"
$installService = Read-Host "Would you like to install ARP Guard as a Windows service? (Y/N)"

if ($installService -eq "Y" -or $installService -eq "y") {
    Write-Step "Installing ARP Guard service..."
    try {
        # Create the service using sc command
        Start-Process -FilePath "sc.exe" -ArgumentList "create", "ARPGuard", 
            "binPath=`"$INSTALL_DIR\scripts\arp-guard-service.bat`"", 
            "DisplayName=`"ARP Guard`"", 
            "start=auto", 
            "description=`"ARP Guard Protection Service`"" -Wait -NoNewWindow
        
        # Create service batch file
        $serviceContent = @"
@echo off
python "$INSTALL_DIR\src\service.py"
"@
        $serviceBatchFile = "$INSTALL_DIR\scripts\arp-guard-service.bat"
        Set-Content -Path $serviceBatchFile -Value $serviceContent
        
        Write-Success "ARP Guard service installed successfully."
        Write-Host "You can start the service with: sc start ARPGuard"
    } catch {
        Write-Error "Failed to install ARP Guard service: $_"
        Write-Host "You can still use ARP Guard as a regular application."
    }
} else {
    Write-Host "Skipping service installation."
}

# Cleanup
Write-Title "Cleaning Up"
Write-Step "Removing temporary files..."
try {
    Remove-Item $DOWNLOAD_ZIP -Force -ErrorAction SilentlyContinue
    Remove-Item $EXTRACTED_DIR -Recurse -Force -ErrorAction SilentlyContinue
    Write-Success "Temporary files removed."
} catch {
    Write-Warning "Could not remove all temporary files: $_"
}

# Installation complete
Write-Title "Installation Complete"
Write-Success "ARP Guard has been successfully installed on your system!"
Write-Host "`nTo get started, run:"
Write-Host "  arp-guard --help" -ForegroundColor Cyan
Write-Host "`nFor documentation, visit:"
Write-Host "  https://github.com/yourorg/arp-guard/blob/main/README.md" -ForegroundColor Cyan

exit 0 