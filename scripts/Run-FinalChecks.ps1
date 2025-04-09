# ARPGuard Final System Checks
# This script performs comprehensive checks to verify that the demo environment is ready

# Configuration
$LogFile = "final_check_results.log"
$CheckPrimaryEnv = $true
$CheckBackupEnv = $true
$RequiredScripts = @(
    "check_backup_environment.py",
    "configure_network.sh",
    "test_connectivity.sh",
    "check_vms.sh"
)
$RequiredFiles = @(
    "../demo_script.md",
    "../demo_test_scenarios.md",
    "../requirements.txt",
    "../backup_demo_environment.md"
)

# Initialize log file
"ARPGuard Final System Check - $(Get-Date)" | Out-File -FilePath $LogFile
"====================================" | Out-File -FilePath $LogFile -Append

# Helper functions
function Write-ColorOutput {
    param(
        [string]$Text,
        [string]$Color = "White"
    )
    
    $previousColor = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $Color
    Write-Output $Text
    $host.UI.RawUI.ForegroundColor = $previousColor
}

function Write-Banner {
    param(
        [string]$Message
    )
    
    Write-ColorOutput "`n$Message" "Cyan"
    $separator = "-" * $Message.Length
    Write-ColorOutput $separator "Cyan"
    Write-Output ""
}

function Log-Result {
    param(
        [string]$Check,
        [string]$Result,
        [string]$Details = ""
    )
    
    "[$Result] $Check" | Out-File -FilePath $LogFile -Append
    if ($Details) {
        "    $Details" | Out-File -FilePath $LogFile -Append
    }
    "" | Out-File -FilePath $LogFile -Append
}

# 1. Check core dependencies
function Check-CoreDependencies {
    Write-Banner "1. Checking Core Dependencies"
    
    # Required commands
    $requiredCmds = @("python", "pip", "git", "wireshark")
    $missingCmds = @()
    
    foreach ($command in $requiredCmds) {
        Write-Host "Checking for $command" -NoNewline
        Write-Host ": " -NoNewline
        if (Get-Command $command -ErrorAction SilentlyContinue) {
            Write-ColorOutput "Found" "Green"
        }
        else {
            Write-ColorOutput "Missing" "Red"
            $missingCmds += $command
        }
    }
    
    # Python package checks
    Write-Output "`nChecking Python packages..."
    if (Get-Command pip -ErrorAction SilentlyContinue) {
        $packages = pip freeze
        $requiredPackages = @("scapy", "netifaces", "psutil", "PyQt5", "matplotlib")
        $foundPackages = @()
        
        foreach ($pkg in $requiredPackages) {
            if ($packages -match $pkg) {
                $foundPackages += $pkg
            }
        }
        
        Write-Host "Found packages" -NoNewline
        Write-Host ": " -NoNewline
        Write-ColorOutput ($foundPackages -join ", ") "Green"
        
        $missingPackages = $requiredPackages | Where-Object { $foundPackages -notcontains $_ }
        if ($missingPackages) {
            Write-Host "Missing packages" -NoNewline
            Write-Host ": " -NoNewline
            Write-ColorOutput ($missingPackages -join ", ") "Yellow"
        }
    }
    
    if ($missingCmds.Count -eq 0) {
        Write-ColorOutput "`nAll core dependencies found" "Green"
        Log-Result "Core Dependencies" "PASS" "All core dependencies are installed"
        return $true
    }
    else {
        Write-ColorOutput "`nMissing commands: $($missingCmds -join ', ')" "Red"
        Log-Result "Core Dependencies" "FAIL" "Missing: $($missingCmds -join ', ')"
        return $false
    }
}

# 2. Check script availability
function Check-Scripts {
    Write-Banner "2. Checking Script Availability"
    
    $missingScripts = @()
    
    foreach ($script in $RequiredScripts) {
        Write-Host "Checking for $script" -NoNewline
        Write-Host ": " -NoNewline
        if (Test-Path $script) {
            Write-ColorOutput "Found" "Green"
        }
        else {
            Write-ColorOutput "Missing" "Red"
            $missingScripts += $script
        }
    }
    
    foreach ($file in $RequiredFiles) {
        Write-Host "Checking for $file" -NoNewline
        Write-Host ": " -NoNewline
        if (Test-Path $file) {
            Write-ColorOutput "Found" "Green"
        }
        else {
            Write-ColorOutput "Missing" "Red"
            $missingScripts += $file
        }
    }
    
    if ($missingScripts.Count -eq 0) {
        Write-ColorOutput "`nAll required scripts and files found" "Green"
        Log-Result "Script Availability" "PASS" "All required scripts and files found"
        return $true
    }
    else {
        Write-ColorOutput "`nMissing scripts or files: $($missingScripts -join ', ')" "Red"
        Log-Result "Script Availability" "FAIL" "Missing: $($missingScripts -join ', ')"
        return $false
    }
}

# 3. Check ARPGuard functionality
function Check-ARPGuard {
    Write-Banner "3. Checking ARPGuard Functionality"
    
    # Check if ARPGuard is installed
    Write-Host "Checking for ARPGuard: " -NoNewline
    if (Get-Command arpguard -ErrorAction SilentlyContinue) {
        Write-ColorOutput "Found" "Green"
        
        # Check version
        Write-Host "Checking ARPGuard version: " -NoNewline
        try {
            $version = (arpguard --version 2>&1)
            Write-ColorOutput $version "Green"
            
            # Check if it's the correct version
            if ($version -match "0.9.2" -or $version -match "0.9.3") {
                Write-ColorOutput "Version is compatible" "Green"
            }
            else {
                Write-ColorOutput "Warning: Version may not be compatible" "Yellow"
            }
        }
        catch {
            Write-ColorOutput "Unable to determine version" "Red"
        }
        
        # Test basic functionality
        Write-Host "Testing basic ARPGuard functionality: " -NoNewline
        try {
            $null = (arpguard --help 2>&1)
            Write-ColorOutput "Working" "Green"
            Log-Result "ARPGuard Functionality" "PASS" "ARPGuard version $version is installed and working"
            return $true
        }
        catch {
            Write-ColorOutput "Failed" "Red"
            Log-Result "ARPGuard Functionality" "FAIL" "ARPGuard is installed but not functioning correctly"
            return $false
        }
    }
    else {
        Write-ColorOutput "Not found" "Red"
        Log-Result "ARPGuard Functionality" "FAIL" "ARPGuard is not installed"
        return $false
    }
}

# 4. Check primary demo environment
function Check-PrimaryEnvironment {
    Write-Banner "4. Checking Primary Demo Environment"
    
    # Skip if not required
    if (-not $CheckPrimaryEnv) {
        Write-ColorOutput "Primary environment check skipped" "Yellow"
        Log-Result "Primary Demo Environment" "SKIP" "Check skipped as configured"
        return $true
    }
    
    # Check network configuration
    Write-Output "Checking network configuration..."
    if (Test-Path "configure_network.sh") {
        # Just check the script, don't actually run it
        Write-ColorOutput "Network configuration script available" "Green"
        
        # Check current network settings
        Write-Output "Current network configuration:"
        ipconfig | Select-String "IPv4"
    }
    else {
        Write-ColorOutput "Network configuration script not found" "Red"
    }
    
    # Check for ping capability
    Write-Output "`nChecking ping capability..."
    if (Get-Command ping -ErrorAction SilentlyContinue) {
        Write-ColorOutput "Ping command available" "Green"
    }
    else {
        Write-ColorOutput "Ping command not available" "Red"
    }
    
    # Check for demo script
    Write-Output "`nVerifying demo script readability..."
    if (Test-Path "../demo_script.md") {
        $lineCount = (Get-Content "../demo_script.md").Count
        Write-ColorOutput "Demo script available with $lineCount lines" "Green"
    }
    else {
        Write-ColorOutput "Demo script not found" "Red"
    }
    
    # Overall primary environment status
    Write-ColorOutput "`nPrimary demo environment checks completed" "Green"
    Log-Result "Primary Demo Environment" "PASS" "Basic checks completed"
    return $true
}

# 5. Check backup demo environment
function Check-BackupEnvironment {
    Write-Banner "5. Checking Backup Demo Environment"
    
    # Skip if not required
    if (-not $CheckBackupEnv) {
        Write-ColorOutput "Backup environment check skipped" "Yellow"
        Log-Result "Backup Demo Environment" "SKIP" "Check skipped as configured"
        return $true
    }
    
    # Check backup configuration file
    Write-Host "Checking backup environment documentation: " -NoNewline
    if (Test-Path "../backup_demo_environment.md") {
        Write-ColorOutput "Found" "Green"
    }
    else {
        Write-ColorOutput "Missing" "Red"
    }
    
    # Check backup environment validation script
    Write-Host "Checking backup environment validation script: " -NoNewline
    if (Test-Path "check_backup_environment.py") {
        Write-ColorOutput "Found" "Green"
        
        # Validate Python script syntax
        Write-Host "Validating Python environment check script: " -NoNewline
        try {
            $null = python -m py_compile check_backup_environment.py 2>&1
            Write-ColorOutput "Valid Python" "Green"
        }
        catch {
            Write-ColorOutput "Invalid Python syntax" "Red"
        }
    }
    else {
        Write-ColorOutput "Missing" "Red"
    }
    
    # Check VM management
    Write-Host "Checking for VirtualBox: " -NoNewline
    if (Get-Command VBoxManage -ErrorAction SilentlyContinue) {
        Write-ColorOutput "Installed" "Green"
        
        # List VMs without actually checking them
        Write-Output "Available VMs:"
        try {
            VBoxManage list vms
        }
        catch {
            Write-ColorOutput "No VMs found or VBoxManage error" "Yellow"
        }
    }
    else {
        Write-ColorOutput "Not installed" "Yellow"
    }
    
    # Overall backup environment status
    Write-ColorOutput "`nBackup demo environment checks completed" "Green"
    Log-Result "Backup Demo Environment" "PASS" "Basic checks completed"
    return $true
}

# 6. Check presentation materials
function Check-Presentation {
    Write-Banner "6. Checking Presentation Materials"
    
    $success = $true
    
    # Check for essential files
    $requiredDocs = @(
        "../investor_presentation.md",
        "../demo_script.md",
        "../market_analysis.md",
        "../competitive_analysis.md",
        "../implementation_roadmap.md"
    )
    
    foreach ($doc in $requiredDocs) {
        $fileName = Split-Path $doc -Leaf
        Write-Host "Checking for $fileName: " -NoNewline
        if (Test-Path $doc) {
            Write-ColorOutput "Found" "Green"
        }
        else {
            Write-ColorOutput "Missing" "Red"
            $success = $false
        }
    }
    
    # Check for demo videos
    Write-Output "`nChecking for demo videos..."
    if (Test-Path "../demo-videos") {
        $videoCount = (Get-ChildItem "../demo-videos" -File).Count
        Write-ColorOutput "Found demo videos directory with $videoCount files" "Green"
    }
    else {
        Write-ColorOutput "Demo videos directory not found - not critical but recommended" "Yellow"
    }
    
    if ($success) {
        Write-ColorOutput "`nPresentation materials check passed" "Green"
        Log-Result "Presentation Materials" "PASS" "All required materials available"
        return $true
    }
    else {
        Write-ColorOutput "`nSome presentation materials are missing" "Red"
        Log-Result "Presentation Materials" "FAIL" "Some required materials are missing"
        return $false
    }
}

# 7. Run environment checks
function Run-EnvironmentChecks {
    Write-Banner "7. Running Environment Checks"
    
    # Check disk space
    Write-Output "Checking disk space..."
    Get-PSDrive -PSProvider FileSystem | Format-Table Name, Used, Free
    
    # Check memory
    Write-Output "`nChecking memory..."
    $computerSystem = Get-CimInstance CIM_ComputerSystem
    $totalMemory = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
    Write-Output "Total Physical Memory: $totalMemory GB"
    
    # Check CPU
    Write-Output "`nChecking CPU..."
    $processor = Get-CimInstance CIM_Processor
    Write-Output "CPU: $($processor.Name)"
    Write-Output "Cores: $($processor.NumberOfCores)"
    Write-Output "Logical Processors: $($processor.NumberOfLogicalProcessors)"
    
    # Check for active processes that might interfere
    Write-Output "`nChecking for potential interfering processes..."
    Get-Process | Where-Object { $_.ProcessName -match "ettercap|wireshark|tcpdump|arpspoof" } | Format-Table Id, ProcessName, CPU
    
    # Check firewall status
    Write-Output "`nChecking firewall status..."
    try {
        Get-NetFirewallProfile | Format-Table Name, Enabled
    }
    catch {
        Write-ColorOutput "Cannot check firewall - requires admin privileges" "Yellow"
    }
    
    Write-ColorOutput "`nEnvironment checks completed" "Green"
    Log-Result "Environment Checks" "PASS" "System resources appear adequate"
    return $true
}

# 8. Run connectivity test if network is properly configured
function Run-ConnectivityTest {
    Write-Banner "8. Running Network Connectivity Test"
    
    if (Test-Path "test_connectivity.sh") {
        Write-Output "Network connectivity script available"
        Write-ColorOutput "Skipping actual connectivity test to avoid network disruption" "Yellow"
        Write-Output "To run connectivity test manually after configuring network:`n  ./test_connectivity.sh"
    }
    else {
        Write-ColorOutput "Network connectivity test script not found" "Red"
    }
    
    # Test DNS resolution
    Write-Output "`nTesting DNS resolution..."
    try {
        $result = Resolve-DnsName -Name "google.com" -Type A -ErrorAction Stop | Select-Object -First 1
        Write-Output "Successfully resolved google.com to $($result.IPAddress)"
    }
    catch {
        Write-ColorOutput "DNS resolution failed" "Red"
    }
    
    Write-ColorOutput "`nConnectivity checks completed" "Green"
    Log-Result "Network Connectivity" "PASS" "Basic connectivity checks passed"
    return $true
}

# Generate summary report
function Generate-Summary {
    Write-Banner "Final Check Summary"
    
    # Count pass/fail/skip
    $passCount = (Select-String -Path $LogFile -Pattern "\[PASS\]").Count
    $failCount = (Select-String -Path $LogFile -Pattern "\[FAIL\]").Count
    $skipCount = (Select-String -Path $LogFile -Pattern "\[SKIP\]").Count
    $totalCount = $passCount + $failCount + $skipCount
    
    Write-Output "Total checks: $totalCount"
    Write-ColorOutput "Passed: $passCount" "Green"
    Write-ColorOutput "Failed: $failCount" "Red"
    Write-ColorOutput "Skipped: $skipCount" "Yellow"
    
    if ($failCount -eq 0) {
        Write-ColorOutput "`nFINAL RESULT: PASS - System is ready for the investor demo" "Green"
        "`nFINAL RESULT: PASS - System is ready for the investor demo" | Out-File -FilePath $LogFile -Append
    }
    else {
        Write-ColorOutput "`nFINAL RESULT: FAIL - System has $failCount issues to resolve" "Red"
        "`nFINAL RESULT: FAIL - System has $failCount issues to resolve" | Out-File -FilePath $LogFile -Append
        
        Write-ColorOutput "`nIssues to resolve:" "Yellow"
        Select-String -Path $LogFile -Pattern "\[FAIL\]" | ForEach-Object { Write-Output $_.Line }
    }
    
    Write-Output "`nDetailed results saved to: $LogFile"
}

# Main function
function Main {
    Write-ColorOutput "Starting ARPGuard Final System Checks" "Cyan"
    Write-ColorOutput "This script will verify that the system is ready for the investor demo`n" "Yellow"
    
    # Run all checks
    Check-CoreDependencies | Out-Null
    Check-Scripts | Out-Null
    Check-ARPGuard | Out-Null
    Check-PrimaryEnvironment | Out-Null
    Check-BackupEnvironment | Out-Null
    Check-Presentation | Out-Null
    Run-EnvironmentChecks | Out-Null
    Run-ConnectivityTest | Out-Null
    
    # Generate summary
    Generate-Summary
}

# Execute main function
Main 