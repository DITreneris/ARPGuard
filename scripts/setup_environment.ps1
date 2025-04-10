Write-Host "Setting up ARPGuard verification environment..."

# Create modules directory if it doesn't exist
$modulesDir = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\ARPGuardVerification"
if (-not (Test-Path $modulesDir)) {
    Write-Host "Creating modules directory: $modulesDir"
    New-Item -ItemType Directory -Path $modulesDir -Force | Out-Null
}

# Copy module file to modules directory
$moduleSource = Join-Path $PSScriptRoot "ARPGuardVerification.psm1"
$moduleDest = Join-Path $modulesDir "ARPGuardVerification.psm1"
Write-Host "Copying module file to: $moduleDest"
Copy-Item -Path $moduleSource -Destination $moduleDest -Force

# Create module manifest
$manifestPath = Join-Path $modulesDir "ARPGuardVerification.psd1"
Write-Host "Creating module manifest: $manifestPath"
New-ModuleManifest -Path $manifestPath `
    -RootModule "ARPGuardVerification.psm1" `
    -ModuleVersion "1.0.0" `
    -Author "ARPGuard Team" `
    -Description "Common functions for ARPGuard verification scripts" `
    -PowerShellVersion "5.1" `
    -FunctionsToExport @(
        "Write-StatusSuccess",
        "Write-StatusError",
        "Write-StatusWarning", 
        "Write-StatusInfo",
        "Write-Section",
        "Test-YamlFile"
    )

Write-Host "Environment setup complete. You can now run verification scripts."
Write-Host "Run 'Import-Module ARPGuardVerification' to use the module functions directly." 