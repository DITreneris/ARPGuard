[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [ValidateSet("list", "update", "rollback", "history", "validate")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$Version,
    
    [Parameter(Mandatory=$false)]
    [string]$Component,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# Define paths
$VERSION_CONFIG_PATH = Join-Path (Split-Path $PSScriptRoot -Parent) "k8s\production\version-control.yaml"
$DEPLOYMENT_PATH = Join-Path (Split-Path $PSScriptRoot -Parent) "k8s\production"
$BACKUP_DIR = Join-Path (Split-Path $PSScriptRoot -Parent) "backups\version-control"

# Import required modules
$modulePath = Join-Path $PSScriptRoot "modules\ARPGuardVerification.psm1"
if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
} else {
    Write-Host "Warning: Verification module not found at $modulePath" -ForegroundColor Yellow
}

# Output functions
function Write-Success {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "ERROR: $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "WARNING: $Message" -ForegroundColor Yellow
}

function Write-Info {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Cyan
}

# Function to parse YAML content
function Get-VersionControlData {
    param([string]$YamlPath)
    
    if (-not (Test-Path $YamlPath)) {
        Write-Error "Version control configuration not found at $YamlPath"
        return $null
    }
    
    try {
        $yamlContent = Get-Content $YamlPath -Raw
        
        # Extract current_version
        $currentVersionMatch = [regex]::Match($yamlContent, 'current_version:\s*"([^"]+)"')
        if ($currentVersionMatch.Success) {
            $currentVersion = $currentVersionMatch.Groups[1].Value
        } else {
            $currentVersion = "Unknown"
        }
        
        # Extract release_channel
        $channelMatch = [regex]::Match($yamlContent, 'release_channel:\s*"([^"]+)"')
        if ($channelMatch.Success) {
            $channel = $channelMatch.Groups[1].Value
        } else {
            $channel = "Unknown"
        }
        
        # Extract rollback_version
        $rollbackMatch = [regex]::Match($yamlContent, 'rollback_version:\s*"([^"]+)"')
        if ($rollbackMatch.Success) {
            $rollbackVersion = $rollbackMatch.Groups[1].Value
        } else {
            $rollbackVersion = "None"
        }
        
        # Extract component versions using regex
        $componentVersionsMatch = [regex]::Match($yamlContent, 'component_versions:\s*\|\s*\{([^}]+)\}', [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if ($componentVersionsMatch.Success) {
            $componentVersionsText = "{" + $componentVersionsMatch.Groups[1].Value + "}"
            # Convert to proper JSON format
            $componentVersionsText = $componentVersionsText -replace '(?m)^\s*"([^"]+)":\s*"([^"]+)"', '"$1": "$2"'
            try {
                $componentVersions = ConvertFrom-Json $componentVersionsText
            } catch {
                Write-Warning "Failed to parse component versions: $_"
                $componentVersions = @{}
            }
        } else {
            $componentVersions = @{}
        }
        
        # Create return object
        $versionData = [PSCustomObject]@{
            CurrentVersion = $currentVersion
            Channel = $channel
            RollbackVersion = $rollbackVersion
            ComponentVersions = $componentVersions
            YamlContent = $yamlContent
        }
        
        return $versionData
    } catch {
        Write-Error "Failed to parse version control file: $_"
        return $null
    }
}

# Function to update version control data
function Update-VersionControlData {
    param(
        [string]$YamlPath,
        [string]$Version,
        [string]$Component,
        [string]$NewVersion
    )
    
    if (-not (Test-Path $YamlPath)) {
        Write-Error "Version control configuration not found at $YamlPath"
        return $false
    }
    
    # Create backup
    $backupDir = $BACKUP_DIR
    if (-not (Test-Path $backupDir)) {
        New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
    }
    
    $backupFile = Join-Path $backupDir "version-control_$(Get-Date -Format 'yyyyMMdd_HHmmss').yaml"
    try {
        Copy-Item $YamlPath $backupFile -Force
        Write-Info "Created backup at $backupFile"
    } catch {
        Write-Warning "Failed to create backup: $_"
    }
    
    try {
        $yamlContent = Get-Content $YamlPath -Raw
        
        if ($Component) {
            # Update component version
            $pattern = "(?m)([\s]+""$Component"":\s*"")[^""]+(""\s*)"
            if ($yamlContent -match $pattern) {
                $yamlContent = $yamlContent -replace $pattern, "`$1$NewVersion`$2"
                Write-Success "Updated component $Component to version $NewVersion"
            } else {
                Write-Error "Component $Component not found in version control file"
                return $false
            }
        } else {
            # Update main version
            $yamlContent = $yamlContent -replace 'current_version:\s*"[^"]+"', "current_version: `"$NewVersion`""
            Write-Success "Updated main version to $NewVersion"
            
            # Update rollback version
            $currentVersionMatch = [regex]::Match($yamlContent, 'current_version:\s*"([^"]+)"')
            if ($currentVersionMatch.Success) {
                $oldVersion = $currentVersionMatch.Groups[1].Value
                $yamlContent = $yamlContent -replace 'rollback_version:\s*"[^"]+"', "rollback_version: `"$oldVersion`""
            }
            
            # Update all component versions to match
            $pattern = '(?m)([\s]+""[^""]+"":\s*"")[^""]+("")'
            $yamlContent = $yamlContent -replace $pattern, "`$1$NewVersion`$2"
        }
        
        # Write back to file
        Set-Content -Path $YamlPath -Value $yamlContent
        Write-Success "Version control file updated successfully"
        return $true
    } catch {
        Write-Error "Failed to update version control file: $_"
        return $false
    }
}

# Function to show version info
function Show-VersionInfo {
    param($VersionData)
    
    if (-not $VersionData) {
        return
    }
    
    Write-Host "`nARPGuard Version Information" -ForegroundColor White
    Write-Host "==============================" -ForegroundColor White
    Write-Host "Current Version  : $($VersionData.CurrentVersion)" -ForegroundColor Cyan
    Write-Host "Release Channel  : $($VersionData.Channel)" -ForegroundColor Cyan
    Write-Host "Rollback Version : $($VersionData.RollbackVersion)" -ForegroundColor Cyan
    
    Write-Host "`nComponent Versions:" -ForegroundColor White
    $VersionData.ComponentVersions.PSObject.Properties | ForEach-Object {
        Write-Host "  $($_.Name): " -NoNewline
        Write-Host "$($_.Value)" -ForegroundColor Green
    }
    Write-Host ""
}

# Function to show version history
function Show-VersionHistory {
    param([string]$YamlPath)
    
    if (-not (Test-Path $YamlPath)) {
        Write-Error "Version control configuration not found at $YamlPath"
        return
    }
    
    try {
        $yamlContent = Get-Content $YamlPath -Raw
        
        # Extract version history section
        $historyMatch = [regex]::Match($yamlContent, 'version_history:\s*\|\s*(\[\s*\{.+?\}\s*\])', [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if ($historyMatch.Success) {
            $historyJson = $historyMatch.Groups[1].Value
            
            # Clean up the JSON to make it parseable
            $historyJson = $historyJson -replace '(?m)^\s*', ''
            $historyJson = $historyJson -replace ',\s*$', ''
            
            try {
                $versionHistory = ConvertFrom-Json $historyJson
                
                Write-Host "`nARPGuard Version History" -ForegroundColor White
                Write-Host "=========================" -ForegroundColor White
                
                foreach ($entry in $versionHistory) {
                    Write-Host "Version: " -NoNewline
                    Write-Host "$($entry.version)" -ForegroundColor Green
                    Write-Host "  Released: $($entry.release_date)"
                    Write-Host "  Changes : $($entry.release_notes)"
                    Write-Host "  Commit  : $($entry.commit_hash)"
                    Write-Host ""
                }
            } catch {
                Write-Error "Failed to parse version history: $_"
            }
        } else {
            Write-Warning "No version history found in configuration file"
        }
    } catch {
        Write-Error "Failed to read version history: $_"
    }
}

# Function to rollback version
function Invoke-VersionRollback {
    param(
        [string]$YamlPath,
        [switch]$Force
    )
    
    $versionData = Get-VersionControlData -YamlPath $YamlPath
    if (-not $versionData) {
        return $false
    }
    
    $currentVersion = $versionData.CurrentVersion
    $rollbackVersion = $versionData.RollbackVersion
    
    if ([string]::IsNullOrEmpty($rollbackVersion) -or $rollbackVersion -eq "None") {
        Write-Error "No rollback version available"
        return $false
    }
    
    if (-not $Force) {
        $confirmation = Read-Host "Are you sure you want to rollback from $currentVersion to $rollbackVersion? (y/n)"
        if ($confirmation -ne "y") {
            Write-Info "Rollback cancelled"
            return $false
        }
    }
    
    # Perform rollback
    return (Update-VersionControlData -YamlPath $YamlPath -Version "main" -NewVersion $rollbackVersion)
}

# Function to validate version control data
function Test-VersionData {
    param([string]$YamlPath)
    
    if (-not (Test-Path $YamlPath)) {
        Write-Error "Version control configuration not found at $YamlPath"
        return $false
    }
    
    $valid = $true
    $versionData = Get-VersionControlData -YamlPath $YamlPath
    
    if (-not $versionData) {
        return $false
    }
    
    # Check if current version is set
    if ([string]::IsNullOrEmpty($versionData.CurrentVersion) -or $versionData.CurrentVersion -eq "Unknown") {
        Write-Error "Current version is not set"
        $valid = $false
    }
    
    # Check if channel is set
    if ([string]::IsNullOrEmpty($versionData.Channel) -or $versionData.Channel -eq "Unknown") {
        Write-Error "Release channel is not set"
        $valid = $false
    }
    
    # Check component versions
    if ($versionData.ComponentVersions.PSObject.Properties.Count -eq 0) {
        Write-Warning "No component versions found"
        $valid = $false
    }
    
    # Check YAML validity
    try {
        $yamlContent = Get-Content $YamlPath -Raw
        # Basic check for YAML validity (indentation, structure)
        if (-not ($yamlContent -match 'apiVersion:' -and $yamlContent -match 'kind:' -and $yamlContent -match 'metadata:')) {
            Write-Error "YAML file does not appear to be a valid Kubernetes resource"
            $valid = $false
        }
    } catch {
        Write-Error "Failed to read YAML file: $_"
        $valid = $false
    }
    
    if ($valid) {
        Write-Success "Version control configuration is valid"
    } else {
        Write-Warning "Version control configuration has issues that need to be addressed"
    }
    
    return $valid
}

# Main execution logic
try {
    # Ensure config path exists
    if (-not (Test-Path $VERSION_CONFIG_PATH)) {
        Write-Error "Version control configuration not found at $VERSION_CONFIG_PATH"
        exit 1
    }
    
    # Process based on action
    switch ($Action) {
        "list" {
            $versionData = Get-VersionControlData -YamlPath $VERSION_CONFIG_PATH
            Show-VersionInfo -VersionData $versionData
        }
        "history" {
            Show-VersionHistory -YamlPath $VERSION_CONFIG_PATH
        }
        "update" {
            if (-not $Version) {
                Write-Error "Version parameter is required for update action"
                exit 1
            }
            
            if ($Component) {
                # Update specific component
                $result = Update-VersionControlData -YamlPath $VERSION_CONFIG_PATH -Component $Component -NewVersion $Version
            } else {
                # Update main version
                $result = Update-VersionControlData -YamlPath $VERSION_CONFIG_PATH -Version "main" -NewVersion $Version
            }
            
            if ($result) {
                $versionData = Get-VersionControlData -YamlPath $VERSION_CONFIG_PATH
                Show-VersionInfo -VersionData $versionData
            }
        }
        "rollback" {
            $result = Invoke-VersionRollback -YamlPath $VERSION_CONFIG_PATH -Force:$Force
            if ($result) {
                $versionData = Get-VersionControlData -YamlPath $VERSION_CONFIG_PATH
                Show-VersionInfo -VersionData $versionData
            }
        }
        "validate" {
            Test-VersionData -YamlPath $VERSION_CONFIG_PATH
        }
    }
} catch {
    Write-Error "An error occurred: $_"
    exit 1
} 