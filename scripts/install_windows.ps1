# ARPGuard Installation Script for Windows
#requires -RunAsAdministrator

# Define variables
$INSTALL_DIR = "$env:ProgramFiles\ARP Guard"
$GITHUB_REPO = "https://github.com/DITreneris/ARPGuard/archive/refs/heads/master.zip"
$DOWNLOAD_ZIP = "$env:TEMP\arp-guard.zip"
$EXTRACTED_DIR = "$env:TEMP\ARPGuard-master"
$REQUIRED_PACKAGES = @(
    "scapy",
    "netifaces",
    "psutil",
    "colorama",
    "PyYAML",
    "tabulate"
)

# Helper Functions
function Write-Title {
    param([string]$Message)
    
    Write-Host "`n================================================" -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Message)
    
    Write-Host "-> $Message" -ForegroundColor Yellow
}

function Write-Success {
    param([string]$Message)
    
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Display banner
Write-Host @"
 _____  _____ ______     _____                     _ 
|  __ \|  __ \| ___ \   |  __ \                   | |
| |  \/| |  \/| |_/ /   | |  \/ _   _  __ _ _ _ __| |
| | __ | | __ |  __/    | | __ | | | |/ _' | '__| |
| |_\ \| |_\ \| |       | |_\ \| |_| | (_| | |  | |
 \____/ \____/\_|        \____/ \__,_|\__,_|_|  |_|
                                                   
"@ -ForegroundColor Cyan

Write-Host "ARPGuard Installation for Windows" -ForegroundColor Cyan
Write-Host "--------------------------------" -ForegroundColor Cyan

# Check for Npcap/WinPcap
Write-Title "Checking Dependencies"
Write-Step "Checking for Npcap/WinPcap..."

if ((Test-Path "$env:windir\System32\wpcap.dll") -or
    (Test-Path "$env:windir\System32\Npcap\wpcap.dll") -or
    (Test-Path "C:\Windows\System32\wpcap.dll")) {
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
            Write-Error "Failed to download or install Npcap: $($_.Exception.Message)"
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
            $result = python -m pip install $package
            if ($LASTEXITCODE -ne 0) {
                throw "Pip command failed with exit code: $LASTEXITCODE"
            }
            Write-Success "Package $package installed successfully."
        } catch {
            Write-Error "Failed to install package $package`: $($_.Exception.Message)"
            Write-Host "The installation will continue, but some features may not work correctly."
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
    
    # Check if the extracted directory exists
    if (-not (Test-Path $EXTRACTED_DIR)) {
        Write-Warning "Expected directory $EXTRACTED_DIR not found."
        # List directories in temp to find the actual extracted folder
        $extractedFolders = Get-ChildItem -Path $env:TEMP -Directory -Filter "ARP*" | Select-Object -ExpandProperty FullName
        if ($extractedFolders.Count -gt 0) {
            $EXTRACTED_DIR = $extractedFolders[0]
            Write-Step "Using found directory: $EXTRACTED_DIR"
        } else {
            throw "Could not find extracted ARP Guard directory."
        }
    }
    
    # Copy files to installation directory
    Write-Step "Copying files to installation directory..."
    Copy-Item -Path "$EXTRACTED_DIR\*" -Destination $INSTALL_DIR -Recurse -Force
    
    Write-Success "ARP Guard extracted to $INSTALL_DIR"
} catch {
    Write-Error "Error downloading or extracting ARP Guard: $($_.Exception.Message)"
    exit 1
}

# Install ARP Guard
Write-Title "Installing ARP Guard"
Write-Step "Setting up runtime environment..."

try {
    # Create scripts directory if it doesn't exist
    $scriptsDir = "$INSTALL_DIR\scripts"
    if (-not (Test-Path $scriptsDir)) {
        New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
        Write-Success "Created scripts directory: $scriptsDir"
    }
    
    # Get Python version
    $pythonVersion = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
    Write-Step "Detected Python version: $pythonVersion"
    
    # Check if requirements.txt exists and modify it for compatibility
    $requirementsPath = "$INSTALL_DIR\requirements.txt"
    if (Test-Path $requirementsPath) {
        Write-Step "Checking requirements.txt for compatibility..."
        $requirementsContent = Get-Content $requirementsPath
        $newRequirementsContent = @()
        
        foreach ($line in $requirementsContent) {
            # Adjust package versions based on Python version
            if ($line -match "pyqtgraph>=0.13.3" -and [version]$pythonVersion -lt [version]"3.8") {
                $newRequirementsContent += "pyqtgraph==0.12.4"
                Write-Warning "Downgraded pyqtgraph to version 0.12.4 for Python $pythonVersion compatibility"
            } elseif ($line -match "PyQt5>=5.15.9" -and [version]$pythonVersion -lt [version]"3.8") {
                $newRequirementsContent += "PyQt5==5.15.7"
                Write-Warning "Adjusted PyQt5 version for Python $pythonVersion compatibility"
            } elseif ($line -match "pyfiglet>=1.0.0" -and [version]$pythonVersion -lt [version]"3.8") {
                $newRequirementsContent += "pyfiglet==0.8.post1"
                Write-Warning "Downgraded pyfiglet to version 0.8.post1 for Python $pythonVersion compatibility"
            } elseif ($line -match "pandas>=2.[0-9].[0-9]" -and [version]$pythonVersion -lt [version]"3.8") {
                $newRequirementsContent += "pandas==1.3.5"
                Write-Warning "Downgraded pandas to version 1.3.5 for Python $pythonVersion compatibility"
            } elseif ($line -match "matplotlib>=3.7.0" -and [version]$pythonVersion -lt [version]"3.8") {
                $newRequirementsContent += "matplotlib==3.5.3"
                Write-Warning "Downgraded matplotlib to version 3.5.3 for Python $pythonVersion compatibility"
            } elseif ($line -match "markdown>=3.5.0" -and [version]$pythonVersion -lt [version]"3.8") {
                $newRequirementsContent += "markdown==3.4.4"
                Write-Warning "Downgraded markdown to version 3.4.4 for Python $pythonVersion compatibility"
            } elseif ($line -match "bcrypt>=4.0.0" -and [version]$pythonVersion -lt [version]"3.8") {
                $newRequirementsContent += "bcrypt==3.2.2"
                Write-Warning "Downgraded bcrypt to version 3.2.2 for Python $pythonVersion compatibility"
            } elseif ($line -match "scipy>=1.[0-9].[0-9]" -and [version]$pythonVersion -lt [version]"3.8") {
                $newRequirementsContent += "scipy==1.7.3"
                Write-Warning "Downgraded scipy to version 1.7.3 for Python $pythonVersion compatibility"
            } else {
                $newRequirementsContent += $line
            }
        }
        
        # Write the modified requirements back to the file
        Set-Content -Path $requirementsPath -Value $newRequirementsContent
        Write-Success "Updated requirements.txt for Python $pythonVersion compatibility"
    } else {
        # Create a new requirements.txt file with compatible versions
        Write-Step "Creating compatible requirements.txt..."
        $requirementsContent = @(
            "# ARP Guard requirements",
            "# Auto-generated for Python $pythonVersion",
            "scapy>=2.4.5",
            "netifaces>=0.11.0",
            "psutil>=5.8.0",
            "colorama>=0.4.4",
            "PyYAML>=5.4.1",
            "tabulate>=0.8.9"
        )
        
        # Add PyQt and other packages with version-specific compatibility
        if ([version]$pythonVersion -lt [version]"3.8") {
            $requirementsContent += "PyQt5==5.15.7"
            $requirementsContent += "pyqtgraph==0.12.4"
            $requirementsContent += "pyfiglet==0.8.post1"
            $requirementsContent += "pandas==1.3.5"
            $requirementsContent += "matplotlib==3.5.3"
            $requirementsContent += "markdown==3.4.4"
            $requirementsContent += "bcrypt==3.2.2"
            $requirementsContent += "scipy==1.7.3"
        } else {
            $requirementsContent += "PyQt5>=5.15.9"
            $requirementsContent += "pyqtgraph>=0.13.3"
            $requirementsContent += "pyfiglet>=1.0.0"
            $requirementsContent += "pandas>=2.1.0"
            $requirementsContent += "matplotlib>=3.7.0"
            $requirementsContent += "markdown>=3.5.0"
            $requirementsContent += "bcrypt>=4.0.0"
            $requirementsContent += "scipy>=1.11.0"
        }
        
        Set-Content -Path $requirementsPath -Value $requirementsContent
        Write-Success "Created compatible requirements.txt for Python $pythonVersion"
    }
    
    # Install required packages
    Write-Step "Installing dependencies from requirements.txt..."
    try {
        python -m pip install -r $requirementsPath
    } catch {
        Write-Warning "Some packages could not be installed. Trying individual installations..."
        $requirementsContent = Get-Content $requirementsPath
        $installedPackages = @()
        
        # First pass - install packages that are likely to succeed
        foreach ($line in $requirementsContent) {
            if ($line -match "^#" -or $line.Trim() -eq "") {
                continue
            }
            
            # Skip packages known to cause compatibility issues, we'll handle them later
            if ($line -match "scipy|pandas|pyqtgraph|matplotlib") {
                continue
            }
            
            try {
                $packageSpec = $line.Trim()
                Write-Step "Installing $packageSpec..."
                $output = python -m pip install "$packageSpec" 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "Installed $packageSpec"
                    $installedPackages += $packageSpec -replace '>=.*|==.*', ''
                } else {
                    Write-Warning "Failed to install $packageSpec. Will try a compatible version."
                }
            } catch {
                Write-Warning "Failed to install package $packageSpec`: $($_.Exception.Message)"
            }
        }
        
        # Second pass - try to install problematic packages with fallbacks
        $problematicPackages = @(
            @{Name="scipy"; Fallbacks=@("scipy==1.7.3", "scipy==1.6.3", "scipy==1.5.4")}
            @{Name="pandas"; Fallbacks=@("pandas==1.3.5", "pandas==1.2.5", "pandas==1.1.5")}
            @{Name="matplotlib"; Fallbacks=@("matplotlib==3.5.3", "matplotlib==3.4.3", "matplotlib==3.3.4")}
            @{Name="pyqtgraph"; Fallbacks=@("pyqtgraph==0.12.4", "pyqtgraph==0.12.3", "pyqtgraph==0.11.0")}
        )
        
        foreach ($package in $problematicPackages) {
            if ($installedPackages -contains $package.Name) {
                continue
            }
            
            $installed = $false
            foreach ($version in $package.Fallbacks) {
                try {
                    Write-Step "Trying to install $version..."
                    $output = python -m pip install $version 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-Success "Installed $version"
                        $installed = $true
                        break
                    }
                } catch {
                    # Continue to next version
                }
            }
            
            if (-not $installed) {
                Write-Warning "Could not install $($package.Name) with any compatible version."
            }
        }
    }
    
    Write-Success "ARP Guard environment setup completed."
} catch {
    Write-Error "Error setting up ARP Guard environment: $($_.Exception.Message)"
    Write-Host "You can still use ARP Guard, but some features may not work correctly."
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
        Write-Error "Failed to add ARP Guard to PATH: $($_.Exception.Message)"
        Write-Warning "You may need to manually add $scriptsPath to your PATH."
    }
} else {
    Write-Success "ARP Guard is already in PATH."
}

# Create batch file for easy execution
Write-Step "Creating arp-guard.bat file..."
# Ensure scripts directory exists
if (-not (Test-Path "$INSTALL_DIR\scripts")) {
    New-Item -Path "$INSTALL_DIR\scripts" -ItemType Directory -Force | Out-Null
}

$mainPyPath = ""
# Find main.py in the src directory
if (Test-Path "$INSTALL_DIR\src\main.py") {
    $mainPyPath = "$INSTALL_DIR\src\main.py"
} elseif (Test-Path "$INSTALL_DIR\run.py") {
    $mainPyPath = "$INSTALL_DIR\run.py"
} else {
    # Find any .py file that might be the main entry point
    $pyFiles = Get-ChildItem -Path $INSTALL_DIR -Filter "*.py" -Recurse | Where-Object { $_.Name -match "main|run|app" } | Select-Object -First 1
    if ($pyFiles) {
        $mainPyPath = $pyFiles.FullName
    } else {
        $mainPyPath = "$INSTALL_DIR\run.py"  # Default fallback
    }
}

$batchContent = @"
@echo off
python "$mainPyPath" %*
"@

$batchFile = "$INSTALL_DIR\scripts\arp-guard.bat"
Set-Content -Path $batchFile -Value $batchContent -Force
Write-Success "Created arp-guard.bat launcher."

# Install Windows Service (optional)
Write-Title "Windows Service Setup"
$installService = Read-Host "Would you like to install ARP Guard as a Windows service? (Y/N)"

if ($installService -eq "Y" -or $installService -eq "y") {
    Write-Step "Installing ARP Guard service..."
    try {
        # Create the service using sc command
        Start-Process -FilePath "sc.exe" -ArgumentList "create", "ARPGuard", "binPath=`"$INSTALL_DIR\scripts\arp-guard-service.bat`"", "DisplayName=`"ARP Guard`"", "start=auto", "description=`"ARP Guard Protection Service`"" -Wait -NoNewWindow
        
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
        Write-Error "Failed to install ARP Guard service: $($_.Exception.Message)"
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
    Write-Warning "Could not remove all temporary files: $($_.Exception.Message)"
}

# Installation complete
Write-Title "Installation Complete"
Write-Success "ARP Guard has been successfully installed on your system!"
Write-Host "`nTo get started, run:"
Write-Host "  arp-guard --help" -ForegroundColor Cyan
Write-Host "`nFor documentation, visit:"
Write-Host "  https://github.com/DITreneris/ARPGuard" -ForegroundColor Cyan

exit 0 