# ARPGuard Validation Rollback Procedures

This document outlines the procedures for rolling back changes when validation tests fail during enterprise deployment.

## Overview

ARPGuard's validation framework includes automated checks to ensure that deployments meet all system requirements and enterprise feature expectations. When these validations fail, a systematic rollback procedure should be followed to restore the system to a known good state.

## General Rollback Principles

1. **Snapshot Before Validation**: Always create a snapshot or backup of the system state before running validations
2. **Incremental Validation**: Validate changes incrementally rather than all at once
3. **Transaction Log**: Maintain a log of all changes made during the deployment
4. **Testing in Isolation**: Test rollback procedures in a non-production environment before deployment

## Rollback Procedures by Category

### Network Configuration Failures

#### Failed Network Interface Validation
1. Stop the ARPGuard service: `systemctl stop arpguard` or `Stop-Service ARPGuard`
2. Restore the network configuration from backup:
   - Linux: `cp /etc/network/interfaces.bak /etc/network/interfaces`
   - Windows: Use Network Adapter rollback or System Restore
3. Restart networking services:
   - Linux: `systemctl restart networking`
   - Windows: `Restart-Service -Name "Network Adapter"`
4. Verify connectivity with `ping` to gateway
5. Log the rollback in the deployment log

#### Failed Connectivity Validation
1. Check if firewall rules have been changed during deployment
2. Restore previous firewall configuration:
   - Linux: `iptables-restore < /etc/iptables.backup`
   - Windows: `netsh advfirewall reset` or restore from export
3. If DNS settings were changed, restore previous DNS configuration
4. Verify connectivity to target endpoints
5. Document failed connectivity targets and potential network issues

### System Service Failures

#### Failed Services Validation
1. Stop any new services installed during deployment:
   - Linux: `systemctl stop arpguard*`
   - Windows: `Stop-Service ARPGuard*`
2. Restore previous service configurations:
   - Linux: `cp /etc/systemd/system/arpguard.service.bak /etc/systemd/system/arpguard.service`
   - Windows: Use SC command or service MMC
3. If service dependencies were modified, restore them from backup
4. Restart dependent services
5. Verify service status and dependencies

### Enterprise Feature Failures

#### Failed RBAC Validation
1. Restore previous RBAC configuration:
   ```bash
   cp config/rbac.yaml.bak config/rbac.yaml
   ```
2. Recreate any authentication tokens or update existing ones
3. Verify user access with test accounts for each role
4. Document any permissions that were causing validation failures

#### Failed High Availability Validation
1. Stop all ARPGuard services on primary and backup nodes
2. Restore HA configuration from backup:
   ```bash
   cp config/ha_config.yaml.bak config/ha_config.yaml
   ```
3. Reset cluster state:
   ```bash
   ./scripts/reset_cluster_state.sh
   ```
4. Restart services on primary node first, then on backup nodes
5. Verify cluster status and node communication

#### Failed API Security Validation
1. Restore previous API configuration:
   ```bash
   cp config/api_config.yaml.bak config/api_config.yaml
   ```
2. Restart API services
3. Test API endpoints with previous credentials
4. Update any client configurations to use previous API settings

#### Failed VLAN Support Validation
1. Restore network interface configurations:
   - Linux: `cp /etc/network/interfaces.bak /etc/network/interfaces`
   - Windows: Restore network adapter settings
2. Restore VLAN configuration:
   ```bash
   cp config/vlan_config.yaml.bak config/vlan_config.yaml
   ```
3. Restart networking and ARPGuard services
4. Verify VLAN tagging and connectivity

## Automated Rollback

ARPGuard includes an automated rollback script that can be executed when validations fail:

```bash
./scripts/rollback.sh --validation-log validation_report.yaml --timestamp 20250409-1527
```

The automated rollback script:
1. Reads the validation report to identify failed components
2. Locates the appropriate backups based on timestamp
3. Executes component-specific rollback procedures
4. Verifies the rollback was successful
5. Generates a rollback report

## Windows-Specific Rollback Procedures

For Windows systems, the following PowerShell script can be used:

```powershell
.\scripts\Rollback-ARPGuard.ps1 -ValidationReport validation_report.json -Timestamp "20250409-1527"
```

The script performs similar functions to the Linux variant but using Windows-specific commands and services.

## Verifying Rollback Success

After performing rollback procedures:

1. Run the ARPGuard status check:
   ```bash
   ./scripts/check_status.sh --basic
   ```

2. Verify core functionality without enterprise features:
   ```bash
   ./scripts/verify_core.sh
   ```

3. Document the rollback in the deployment log with:
   - Timestamp of rollback
   - Validation failures that triggered rollback
   - Components affected
   - Verification status

## Next Steps After Rollback

1. Analyze validation failures from the logs
2. Address root causes in a development or staging environment
3. Create a new deployment plan with incremental validation
4. Test the fixed deployment in a non-production environment
5. Schedule a new deployment window with updated procedures 