param (
    [Parameter(Mandatory=$false)]
    [ValidateSet("list", "update", "rollback", "history", "validate")]
    [string]$Action = "list",
    
    [Parameter(Mandatory=$false)]
    [string]$Version,
    
    [Parameter(Mandatory=$false)]
    [string]$Component,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force = $false
)

# Import the ARPGuardVerification module if available
$modulePath = Join-Path $PSScriptRoot "ARPGuardVerification.psm1"
if (Test-Path $modulePath) {
    Import-Module $modulePath -Force -ErrorAction SilentlyContinue
}

# Colors for output
$GREEN = [ConsoleColor]::Green
$RED = [ConsoleColor]::Red
$YELLOW = [ConsoleColor]::Yellow
$CYAN = [ConsoleColor]::Cyan
$MAGENTA = [ConsoleColor]::Magenta

# Output functions
function Write-Success($Message) { Write-Host $Message -ForegroundColor $GREEN }
function Write-Error($Message) { Write-Host "ERROR: $Message" -ForegroundColor $RED }
function Write-Warning($Message) { Write-Host "WARNING: $Message" -ForegroundColor $YELLOW }
function Write-Info($Message) { Write-Host $Message -ForegroundColor $CYAN }
function Write-Title($Message) { 
    Write-Host "`n$Message" -ForegroundColor $MAGENTA
    Write-Host ("-" * $Message.Length) -ForegroundColor $MAGENTA
}

# Constants
$VERSION_CONFIG_PATH = Join-Path $PSScriptRoot "..\k8s\production\version-control.yaml"
$DEPLOYMENT_PATH = Join-Path $PSScriptRoot "..\k8s\production\deployment.yaml"
$BACKUP_DIR = Join-Path $PSScriptRoot "..\backups\version-control"

# Create backup directory if it doesn't exist
if (-not (Test-Path $BACKUP_DIR)) {
    New-Item -ItemType Directory -Path $BACKUP_DIR -Force | Out-Null
}

# Load version control data
function Get-VersionControlData {
    if (-not (Test-Path $VERSION_CONFIG_PATH)) {
        Write-Error "Version control configuration not found at: $VERSION_CONFIG_PATH"
        exit 1
    }
    
    $content = Get-Content -Path $VERSION_CONFIG_PATH -Raw
    
    # Parse current version
    if ($content -match 'current_version:\s*"([^"]+)"') {
        $currentVersion = $matches[1]
    } else {
        $currentVersion = "Unknown"
    }
    
    # Parse release channel
    if ($content -match 'release_channel:\s*"([^"]+)"') {
        $releaseChannel = $matches[1]
    } else {
        $releaseChannel = "Unknown"
    }
    
    # Parse rollback version
    if ($content -match 'rollback_version:\s*"([^"]+)"') {
        $rollbackVersion = $matches[1]
    } else {
        $rollbackVersion = "Unknown"
    }
    
    # Parse component versions
    if ($content -match 'component_versions:\s*\|\s*\{([^}]+)\}') {
        $componentVersionsStr = "{" + $matches[1] + "}"
        $componentVersions = ConvertFrom-Json $componentVersionsStr -ErrorAction SilentlyContinue
        if (-not $componentVersions) {
            $componentVersions = @{}
        }
    } else {
        $componentVersions = @{}
    }
    
    # Parse version history
    if ($content -match 'version_history:\s*\|\s*\[([^]]+)\]') {
        $versionHistoryStr = "[" + $matches[1] + "]"
        $versionHistory = ConvertFrom-Json $versionHistoryStr -ErrorAction SilentlyContinue
        if (-not $versionHistory) {
            $versionHistory = @()
        }
    } else {
        $versionHistory = @()
    }
    
    return @{
        CurrentVersion = $currentVersion
        ReleaseChannel = $releaseChannel
        RollbackVersion = $rollbackVersion
        ComponentVersions = $componentVersions
        VersionHistory = $versionHistory
    }
}

# Update version control data
function Update-VersionControlData {
    param (
        [Parameter(Mandatory=$true)]
        [string]$NewVersion,
        
        [Parameter(Mandatory=$false)]
        [string]$Component,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$VersionData
    )
    
    if (-not $VersionData) {
        $VersionData = Get-VersionControlData
    }
    
    # Create backup
    $backupFile = Join-Path $BACKUP_DIR "version-control_$(Get-Date -Format 'yyyyMMdd_HHmmss').yaml"
    Copy-Item -Path $VERSION_CONFIG_PATH -Destination $backupFile -Force
    Write-Info "Backup created at: $backupFile"
    
    $content = Get-Content -Path $VERSION_CONFIG_PATH -Raw
    
    if ($Component) {
        # Update component version
        $componentJson = ConvertTo-Json $VersionData.ComponentVersions -Compress
        $componentJson = $componentJson -replace "`"$Component`":\s*`"[^`"]*`"", "`"$Component`": `"$NewVersion`""
        $componentJson = $componentJson.Trim('{}')
        $componentBlock = @"
  component_versions: |
    {
$componentJson
    }
"@
        $content = $content -replace "component_versions:\s*\|\s*\{[^}]+\}", $componentBlock
        Write-Success "Updated $Component version to $NewVersion"
    } else {
        # Update main version
        $content = $content -replace 'current_version:\s*"[^"]+"', "current_version: `"$NewVersion`""
        
        # Update rollback version (old current becomes rollback)
        $content = $content -replace 'rollback_version:\s*"[^"]+"', "rollback_version: `"$($VersionData.CurrentVersion)`""
        
        # Add to version history
        $newHistoryEntry = @{
            version = $NewVersion
            release_date = (Get-Date -Format "yyyy-MM-dd")
            release_notes = "Update to version $NewVersion"
            commit_hash = "auto-generated"
        }
        
        $updatedHistory = @($newHistoryEntry) + $VersionData.VersionHistory | Select-Object -First 5
        $historyJson = ConvertTo-Json $updatedHistory -Depth 10
        $historyJson = $historyJson.Substring(1, $historyJson.Length - 2).Trim()
        
        $historyBlock = @"
  version_history: |
    [
$historyJson
    ]
"@
        $content = $content -replace "version_history:\s*\|\s*\[[^]]+\]", $historyBlock
        
        # Update component versions to match main version if not specified
        $componentVersions = $VersionData.ComponentVersions
        foreach ($key in $componentVersions.PSObject.Properties.Name) {
            $componentVersions.$key = $NewVersion
        }
        
        $componentJson = ConvertTo-Json $componentVersions -Compress
        $componentJson = $componentJson.Trim('{}')
        $componentBlock = @"
  component_versions: |
    {
$componentJson
    }
"@
        $content = $content -replace "component_versions:\s*\|\s*\{[^}]+\}", $componentBlock
        
        Write-Success "Updated main version to $NewVersion (previous version $($VersionData.CurrentVersion) saved as rollback)"
    }
    
    # Save updated content
    Set-Content -Path $VERSION_CONFIG_PATH -Value $content
    Write-Success "Version control configuration updated successfully"
}

# Display version information
function Show-VersionInfo {
    param (
        [Parameter(Mandatory=$false)]
        [hashtable]$VersionData
    )
    
    if (-not $VersionData) {
        $VersionData = Get-VersionControlData
    }
    
    Write-Title "ARPGuard Version Information"
    Write-Info "Current Version: $($VersionData.CurrentVersion)"
    Write-Info "Release Channel: $($VersionData.ReleaseChannel)"
    Write-Info "Rollback Version: $($VersionData.RollbackVersion)"
    
    Write-Title "Component Versions"
    foreach ($prop in $VersionData.ComponentVersions.PSObject.Properties) {
        Write-Info "$($prop.Name): $($prop.Value)"
    }
    
    Write-Title "Version History"
    foreach ($version in $VersionData.VersionHistory) {
        Write-Info "$($version.version) ($($version.release_date))"
        Write-Host "  $($version.release_notes)"
        Write-Host "  Commit: $($version.commit_hash)"
    }
}

# Show history
function Show-VersionHistory {
    param (
        [Parameter(Mandatory=$false)]
        [hashtable]$VersionData
    )
    
    if (-not $VersionData) {
        $VersionData = Get-VersionControlData
    }
    
    Write-Title "ARPGuard Version History"
    
    $i = 0
    foreach ($version in $VersionData.VersionHistory) {
        $i++
        if ($version.version -eq $VersionData.CurrentVersion) {
            Write-Success "$i. $($version.version) ($($version.release_date)) - CURRENT"
        } elseif ($version.version -eq $VersionData.RollbackVersion) {
            Write-Info "$i. $($version.version) ($($version.release_date)) - ROLLBACK TARGET"
        } else {
            Write-Host "$i. $($version.version) ($($version.release_date))"
        }
        Write-Host "   Notes: $($version.release_notes)"
        Write-Host "   Commit: $($version.commit_hash)"
    }
}

# Perform rollback
function Invoke-Rollback {
    param (
        [Parameter(Mandatory=$false)]
        [hashtable]$VersionData,
        
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )
    
    if (-not $VersionData) {
        $VersionData = Get-VersionControlData
    }
    
    Write-Title "ARPGuard Version Rollback"
    Write-Warning "Preparing to roll back from version $($VersionData.CurrentVersion) to $($VersionData.RollbackVersion)"
    
    if (-not $Force) {
        $confirmation = Read-Host "Are you sure you want to proceed? (y/N)"
        if ($confirmation -ne "y") {
            Write-Info "Rollback cancelled by user."
            return
        }
    }
    
    # Store current as temp
    $tempVersion = $VersionData.CurrentVersion
    
    # Update to rollback version
    Update-VersionControlData -NewVersion $VersionData.RollbackVersion -VersionData $VersionData
    
    # Update rollback version to be the temp
    $updatedData = Get-VersionControlData
    
    $content = Get-Content -Path $VERSION_CONFIG_PATH -Raw
    $content = $content -replace 'rollback_version:\s*"[^"]+"', "rollback_version: `"$tempVersion`""
    Set-Content -Path $VERSION_CONFIG_PATH -Value $content
    
    Write-Success "Rollback completed successfully"
    Write-Info "Current Version: $($VersionData.RollbackVersion)"
    Write-Info "Rollback Version: $tempVersion"
}

# Validate version data
function Test-VersionData {
    param (
        [Parameter(Mandatory=$false)]
        [hashtable]$VersionData
    )
    
    if (-not $VersionData) {
        $VersionData = Get-VersionControlData
    }
    
    Write-Title "Validating ARPGuard Version Configuration"
    
    $isValid = $true
    
    # Check version format
    if ($VersionData.CurrentVersion -notmatch '^\d+\.\d+\.\d+$') {
        Write-Error "Current version does not follow semantic versioning format (x.y.z)"
        $isValid = $false
    } else {
        Write-Success "Current version format is valid"
    }
    
    # Check rollback version format
    if ($VersionData.RollbackVersion -notmatch '^\d+\.\d+\.\d+$') {
        Write-Error "Rollback version does not follow semantic versioning format (x.y.z)"
        $isValid = $false
    } else {
        Write-Success "Rollback version format is valid"
    }
    
    # Check release channel
    if ($VersionData.ReleaseChannel -notin @('stable', 'beta', 'edge')) {
        Write-Error "Release channel should be one of: stable, beta, edge"
        $isValid = $false
    } else {
        Write-Success "Release channel is valid"
    }
    
    # Check component versions
    $componentMismatch = $false
    foreach ($prop in $VersionData.ComponentVersions.PSObject.Properties) {
        if ($prop.Value -notmatch '^\d+\.\d+\.\d+$') {
            Write-Error "Component $($prop.Name) version does not follow semantic versioning format (x.y.z)"
            $isValid = $false
        }
        
        if ($VersionData.ReleaseChannel -eq 'stable' -and $prop.Value -ne $VersionData.CurrentVersion) {
            Write-Warning "Component $($prop.Name) version ($($prop.Value)) does not match current version ($($VersionData.CurrentVersion))"
            $componentMismatch = $true
        }
    }
    
    if (-not $componentMismatch) {
        Write-Success "All component versions are consistent"
    }
    
    # Check version history
    if ($VersionData.VersionHistory.Count -eq 0) {
        Write-Error "Version history is empty"
        $isValid = $false
    } else {
        Write-Success "Version history contains $($VersionData.VersionHistory.Count) entries"
    }
    
    # Check if current version is in history
    $currentInHistory = $false
    foreach ($version in $VersionData.VersionHistory) {
        if ($version.version -eq $VersionData.CurrentVersion) {
            $currentInHistory = $true
            break
        }
    }
    
    if (-not $currentInHistory) {
        Write-Error "Current version not found in version history"
        $isValid = $false
    } else {
        Write-Success "Current version found in version history"
    }
    
    if ($isValid) {
        Write-Success "Version configuration validation passed"
    } else {
        Write-Error "Version configuration validation failed"
    }
    
    return $isValid
}

# Main execution
try {
    $versionData = Get-VersionControlData
    
    switch ($Action) {
        "list" {
            Show-VersionInfo -VersionData $versionData
        }
        "update" {
            if (-not $Version) {
                Write-Error "Version parameter is required for update action"
                exit 1
            }
            Update-VersionControlData -NewVersion $Version -Component $Component -VersionData $versionData
            Write-Info "Version updated successfully"
        }
        "rollback" {
            Invoke-Rollback -VersionData $versionData -Force:$Force
        }
        "history" {
            Show-VersionHistory -VersionData $versionData
        }
        "validate" {
            Test-VersionData -VersionData $versionData
        }
    }
} catch {
    Write-Error "An error occurred: $_"
    exit 1
} 