param (
    [string]$PrometheusConfig = "$PSScriptRoot\..\monitoring\prometheus-config.yaml",
    [string]$AlertConfig = "$PSScriptRoot\..\monitoring\arpguard-alerts.yml",
    [switch]$Simulate = $false
)

# Import the ARPGuardVerification module
$modulePath = Join-Path $PSScriptRoot "ARPGuardVerification.psm1"
Import-Module $modulePath -Force

# Function to verify Prometheus configuration
function Test-PrometheusConfig {
    param (
        [string]$ConfigPath
    )

    Write-StatusInfo "Verifying Prometheus configuration: $ConfigPath"
    
    # Check if the file exists
    if (-not (Test-Path $ConfigPath)) {
        Write-StatusError "Prometheus configuration file not found: $ConfigPath"
        return $false
    }
    
    # Validate YAML syntax
    if (-not (Test-YamlFile -FilePath $ConfigPath)) {
        return $false
    }
    
    Write-StatusSuccess "Prometheus configuration file is valid"
    
    # Parse and validate configuration content
    $config = Get-Content -Path $ConfigPath -Raw
    
    # Check for required sections
    if ($config -notmatch "global:") {
        Write-StatusError "Prometheus configuration is missing required section: global"
        return $false
    }
    
    if ($config -notmatch "scrape_configs:") {
        Write-StatusError "Prometheus configuration is missing required section: scrape_configs"
        return $false
    }
    
    Write-StatusSuccess "Prometheus configuration contains all required sections"
    
    # Check for ARPGuard job
    if ($config -notmatch "job_name:\s*'arpguard'") {
        Write-StatusWarning "Prometheus configuration does not contain an ARPGuard job"
    } else {
        Write-StatusSuccess "ARPGuard job found in Prometheus configuration"
    }
    
    # Check if metrics path is defined
    if ($config -match "metrics_path:\s*'([^']+)'") {
        $metricsPath = $matches[1]
        Write-StatusInfo "Metrics path: $metricsPath"
    } else {
        Write-StatusWarning "Metrics path not explicitly defined in Prometheus configuration"
    }
    
    # Check alert rules
    if ($config -match "rule_files:") {
        Write-StatusSuccess "Rule files section found in Prometheus configuration"
    } else {
        Write-StatusWarning "No rule files section found in Prometheus configuration"
    }
    
    Write-StatusSuccess "Prometheus configuration verification completed"
    return $true
}

# Function to verify Alert configuration
function Test-AlertConfig {
    param (
        [string]$ConfigPath
    )

    Write-StatusInfo "Verifying Alert configuration: $ConfigPath"
    
    # Check if the file exists
    if (-not (Test-Path $ConfigPath)) {
        Write-StatusError "Alert configuration file not found: $ConfigPath"
        return $false
    }
    
    # Validate YAML syntax
    if (-not (Test-YamlFile -FilePath $ConfigPath)) {
        return $false
    }
    
    Write-StatusSuccess "Alert configuration file is valid"
    
    # Parse and validate configuration content
    $config = Get-Content -Path $ConfigPath -Raw
    
    # Check for required sections
    if ($config -notmatch "groups:") {
        Write-StatusError "Alert configuration is missing required section: groups"
        return $false
    }
    
    Write-StatusSuccess "Alert configuration contains all required sections"
    
    # Count alert rules
    $ruleMatches = [regex]::Matches($config, '- alert:')
    $ruleCount = $ruleMatches.Count
    
    Write-StatusInfo "Found $ruleCount alert rules"
    
    if ($ruleCount -eq 0) {
        Write-StatusError "No alert rules defined"
        return $false
    }
    
    # Check for severity labels
    $severityMatches = [regex]::Matches($config, 'severity:\s*(\w+)')
    $severityCount = $severityMatches.Count
    
    Write-StatusInfo "Found $severityCount severity labels"
    
    if ($severityCount -eq 0) {
        Write-StatusWarning "No severity labels found in alert rules"
    } else {
        Write-StatusSuccess "Severity labels found in alert rules"
    }
    
    Write-StatusSuccess "Alert configuration verification completed"
    return $true
}

# Function to simulate monitoring operation
function Simulate-Monitoring {
    param (
        [string]$PrometheusConfig,
        [string]$AlertConfig
    )

    Write-StatusInfo "Simulating monitoring operation..."
    
    # Check configurations first
    $prometheusValid = Test-PrometheusConfig -ConfigPath $PrometheusConfig
    $alertsValid = Test-AlertConfig -ConfigPath $AlertConfig
    
    if (-not ($prometheusValid -and $alertsValid)) {
        Write-StatusError "Cannot simulate monitoring with invalid configurations"
        return $false
    }
    
    # Parse configurations
    $prometheusContent = Get-Content -Path $PrometheusConfig -Raw
    $alertContent = Get-Content -Path $AlertConfig -Raw
    
    # Extract targets from Prometheus configuration
    $targetMatches = [regex]::Matches($prometheusContent, "targets:\s*\[([^\]]+)\]")
    $targets = @()
    
    foreach ($match in $targetMatches) {
        $targetString = $match.Groups[1].Value
        $targetString -split "," | ForEach-Object {
            if ($_ -match "'([^']+)'") {
                $targets += $matches[1]
            }
        }
    }
    
    Write-StatusInfo "Found $($targets.Count) monitoring targets"
    
    # Extract alert rules from Alert configuration
    $ruleMatches = [regex]::Matches($alertContent, '- alert:\s*(\w+)')
    $rules = $ruleMatches | ForEach-Object { $_.Groups[1].Value }
    
    Write-StatusInfo "Found $($rules.Count) alert rules"
    
    # Simulate monitoring steps
    Write-StatusInfo "Starting monitoring simulation..."
    
    # Check targets
    Write-StatusInfo "Checking targets..."
    foreach ($target in $targets) {
        Write-StatusInfo "Checking target: $target"
        Start-Sleep -Milliseconds 500 # Simulate actual work
        Write-StatusSuccess "Target $target is up and running"
    }
    
    # Test alert rules
    Write-StatusInfo "Testing alert rules..."
    foreach ($rule in $rules) {
        Write-StatusInfo "Testing alert rule: $rule"
        Start-Sleep -Milliseconds 500 # Simulate actual work
        
        # Randomly determine if alert is triggered (for simulation)
        $triggered = (Get-Random -Minimum 0 -Maximum 10) -gt 7
        
        if ($triggered) {
            Write-StatusWarning "Alert rule $rule triggered!"
        } else {
            Write-StatusSuccess "Alert rule $rule not triggered"
        }
    }
    
    Write-StatusSuccess "Monitoring simulation completed successfully"
    return $true
}

# Main script execution
$prometheusValid = Test-PrometheusConfig -ConfigPath $PrometheusConfig
$alertsValid = Test-AlertConfig -ConfigPath $AlertConfig

if ($prometheusValid -and $alertsValid -and $Simulate) {
    Simulate-Monitoring -PrometheusConfig $PrometheusConfig -AlertConfig $AlertConfig
} 