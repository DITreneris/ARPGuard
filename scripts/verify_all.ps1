param (
    [switch]$Simulate = $false
)

# Import the ARPGuardVerification module
$modulePath = Join-Path $PSScriptRoot "ARPGuardVerification.psm1"
Import-Module $modulePath -Force

Write-Host "ARPGuard TRL 8 Production Environment Verification" -ForegroundColor Magenta
Write-Host "------------------------------------------------" -ForegroundColor Magenta

Write-Section "Verifying Kubernetes Deployment Configuration"
& "$PSScriptRoot\verify_deployment.ps1" -ValidateOnly

Write-Section "Verifying Backup Configuration"
& "$PSScriptRoot\verify_backup.ps1" -Simulate:$Simulate

Write-Section "Verifying Monitoring Configuration"
& "$PSScriptRoot\verify_monitoring.ps1" -Simulate:$Simulate

Write-Section "Summary"
Write-Host "Production environment verification completed." -ForegroundColor Green
Write-Host "You can now proceed with deployment using the verified configurations." -ForegroundColor Cyan

Write-Host "`nTo simulate the deployment, run:" -ForegroundColor Yellow
Write-Host ".\scripts\verify_deployment.ps1" -ForegroundColor Yellow

Write-Host "`nTo simulate the backup, run:" -ForegroundColor Yellow
Write-Host ".\scripts\verify_backup.ps1 -Simulate" -ForegroundColor Yellow

Write-Host "`nTo simulate the monitoring, run:" -ForegroundColor Yellow
Write-Host ".\scripts\verify_monitoring.ps1 -Simulate" -ForegroundColor Yellow

Write-Host "`nTo run all simulations, run:" -ForegroundColor Yellow
Write-Host ".\scripts\verify_all.ps1 -Simulate" -ForegroundColor Yellow 