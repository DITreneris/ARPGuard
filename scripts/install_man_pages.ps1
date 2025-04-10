# ARP Guard Man Pages Installer for Windows
# This script installs man pages for ARP Guard on Windows

# Requires administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires administrator privileges. Please run as administrator."
    exit 1
}

# Default installation paths
$ManDir = "C:\Program Files\ARP Guard\man"
$Man1Dir = Join-Path $ManDir "man1"

# Function to create directory if it doesn't exist
function Create-Directory {
    param (
        [string]$Path
    )
    if (-not (Test-Path $Path)) {
        Write-Host "Creating directory: $Path"
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

# Function to install man page
function Install-ManPage {
    param (
        [string]$Source,
        [string]$Destination
    )
    Write-Host "Installing man page: $Source -> $Destination"
    Copy-Item -Path $Source -Destination $Destination -Force
}

# Main installation
Write-Host "Installing ARP Guard man pages..."

# Create directories
Create-Directory -Path $ManDir
Create-Directory -Path $Man1Dir

# Install man pages
$ManPages = @(
    "arp-guard",
    "arp-guard-start",
    "arp-guard-stop",
    "arp-guard-status"
)

foreach ($page in $ManPages) {
    $source = Join-Path "man" "$page.1"
    $dest = Join-Path $Man1Dir "$page.1"
    if (Test-Path $source) {
        Install-ManPage -Source $source -Destination $dest
    } else {
        Write-Warning "Man page $page.1 not found"
    }
}

# Add man directory to PATH if not already present
$CurrentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if (-not $CurrentPath.Contains($ManDir)) {
    Write-Host "Adding man directory to PATH"
    [Environment]::SetEnvironmentVariable("Path", "$CurrentPath;$ManDir", "Machine")
}

# Create man.exe if not present
$ManExePath = Join-Path $ManDir "man.exe"
if (-not (Test-Path $ManExePath)) {
    Write-Host "Creating man.exe wrapper"
    @"
@echo off
setlocal
set MANPATH=%~dp0
python -c "import sys; from man import main; main()" %*
"@ | Out-File -FilePath $ManExePath -Encoding ASCII
}

Write-Host "Man pages installation complete!"
Write-Host "You can now view the man pages using: man arp-guard" 