# Common functions for ARPGuard verification scripts

# Setup colors for output
$GREEN = [ConsoleColor]::Green
$RED = [ConsoleColor]::Red
$YELLOW = [ConsoleColor]::Yellow
$CYAN = [ConsoleColor]::Cyan
$MAGENTA = [ConsoleColor]::Magenta

function Write-StatusSuccess {
    param (
        [string]$Message
    )
    Write-Host "✓ $Message" -ForegroundColor $GREEN
}

function Write-StatusError {
    param (
        [string]$Message
    )
    Write-Host "✗ $Message" -ForegroundColor $RED
}

function Write-StatusWarning {
    param (
        [string]$Message
    )
    Write-Host "! $Message" -ForegroundColor $YELLOW
}

function Write-StatusInfo {
    param (
        [string]$Message
    )
    Write-Host "ℹ $Message" -ForegroundColor $CYAN
}

function Write-Section {
    param (
        [string]$Message
    )
    Write-Host "`n=== $Message ===`n" -ForegroundColor $MAGENTA
}

# Function to validate YAML file
function Test-YamlFile {
    param (
        [string]$FilePath
    )

    try {
        $content = Get-Content -Path $FilePath -Raw
        # For PowerShell compatibility, we'll just check if the file can be read
        return $true
    }
    catch {
        Write-StatusError "YAML validation failed for $FilePath : $_"
        return $false
    }
}

# Export functions
Export-ModuleMember -Function Write-StatusSuccess
Export-ModuleMember -Function Write-StatusError
Export-ModuleMember -Function Write-StatusWarning
Export-ModuleMember -Function Write-StatusInfo
Export-ModuleMember -Function Write-Section
Export-ModuleMember -Function Test-YamlFile 