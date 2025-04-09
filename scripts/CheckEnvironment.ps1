# ARPGuard Final System Check - Simplified Version
Write-Host "Running ARPGuard Final System Check" -ForegroundColor Cyan
Write-Host "This script will verify that essential components are available" -ForegroundColor Yellow
Write-Host "--------------------------------------------------------------"

# Files to check
$requiredFiles = @(
    "../demo_script.md",
    "../demo_test_scenarios.md",
    "../requirements.txt",
    "../backup_demo_environment.md",
    "../investor_presentation.md",
    "../market_analysis.md",
    "../competitive_analysis.md",
    "../implementation_roadmap.md",
    "check_backup_environment.py",
    "configure_network.sh",
    "test_connectivity.sh",
    "check_vms.sh"
)

# Commands to check
$requiredCommands = @(
    "python",
    "pip",
    "git",
    "wireshark"
)

# Check files
Write-Host "`nCHECKING FILES" -ForegroundColor Cyan
$missingFiles = @()
foreach ($file in $requiredFiles) {
    Write-Host "Checking $file" -NoNewline
    if (Test-Path $file) {
        Write-Host " - OK" -ForegroundColor Green
    } else {
        Write-Host " - MISSING" -ForegroundColor Red
        $missingFiles += $file
    }
}

# Check commands
Write-Host "`nCHECKING COMMANDS" -ForegroundColor Cyan
$missingCommands = @()
foreach ($command in $requiredCommands) {
    Write-Host "Checking $command" -NoNewline
    if (Get-Command $command -ErrorAction SilentlyContinue) {
        Write-Host " - OK" -ForegroundColor Green
    } else {
        Write-Host " - MISSING" -ForegroundColor Red
        $missingCommands += $command
    }
}

# Check network configuration
Write-Host "`nCHECKING NETWORK" -ForegroundColor Cyan
Write-Host "Current network configuration:"
ipconfig | Select-String "IPv4"

# Check system resources
Write-Host "`nCHECKING SYSTEM RESOURCES" -ForegroundColor Cyan
# Disk space
Get-PSDrive -PSProvider FileSystem | Format-Table Name, Used, Free

# Memory
$computerSystem = Get-CimInstance CIM_ComputerSystem
$totalMemory = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
Write-Host "Total Physical Memory: $totalMemory GB"

# CPU
$processor = Get-CimInstance CIM_Processor
Write-Host "CPU: $($processor.Name)"
Write-Host "Cores: $($processor.NumberOfCores)"

# Generate summary
Write-Host "`nSUMMARY" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------------"
if ($missingFiles.Count -eq 0 -and $missingCommands.Count -eq 0) {
    Write-Host "All required files and commands found!" -ForegroundColor Green
    Write-Host "The system appears ready for the investor demo." -ForegroundColor Green
} else {
    if ($missingFiles.Count -gt 0) {
        Write-Host "Missing files ($($missingFiles.Count)):" -ForegroundColor Red
        foreach ($file in $missingFiles) {
            Write-Host "  - $file" -ForegroundColor Red
        }
    }
    
    if ($missingCommands.Count -gt 0) {
        Write-Host "Missing commands ($($missingCommands.Count)):" -ForegroundColor Red
        foreach ($command in $missingCommands) {
            Write-Host "  - $command" -ForegroundColor Red
        }
    }
    
    Write-Host "Please address these issues before proceeding with the demo." -ForegroundColor Yellow
}

# Check for demo_videos directory
if (Test-Path "../demo-videos") {
    $videoCount = (Get-ChildItem "../demo-videos" -File).Count
    Write-Host "Found demo videos directory with $videoCount files" -ForegroundColor Green
} else {
    Write-Host "Warning: Demo videos directory not found" -ForegroundColor Yellow
    Write-Host "This is not critical but recommended for backup during presentations" -ForegroundColor Yellow
}

Write-Host "`nCheck completed at $(Get-Date)" -ForegroundColor Cyan 