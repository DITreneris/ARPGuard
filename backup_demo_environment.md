# ARPGuard Backup Demo Environment Setup

This document outlines the process for setting up a backup demo environment for the ARPGuard investor presentation. This backup environment ensures the demo can proceed even if there are issues with the primary demo setup.

## Backup Environment Components

### 1. Hardware Setup
- **Backup Laptop**: Minimum 8-core CPU, 16GB RAM, SSD storage
- **Portable Network Switch**: Unmanaged switch with at least 5 ports
- **Backup Devices**:
  - 1× Raspberry Pi 4 (4GB) for client simulation
  - 1× Virtual machine on laptop for target system
  - 1× Secondary laptop for attack system
- **Network Cables**: 5× Cat6 Ethernet cables (min 2m length)
- **Power Supply**: Power strip with at least 5 outlets
- **Portable Monitor**: 15" USB-C powered portable display

### 2. Software Preparation

#### On Backup Laptop:
- ARPGuard latest stable build (v0.9.2)
- ARPGuard development build (v0.9.3-dev) as fallback
- Wireshark pre-installed and configured
- VirtualBox with pre-configured VMs:
  - Ubuntu 22.04 LTS VM (target system backup)
  - Kali Linux VM (attacker system backup)
- Backup of all demo configurations in `~/arpguard-backup`
- Pre-recorded demo videos in `~/demo-videos`
- All investor presentation materials downloaded locally

#### On Raspberry Pi:
- Raspbian OS with networking tools installed
- ARPGuard client agent pre-installed
- Network testing tools (iperf3, mtr, etc.)
- Static IP configuration script

#### On Secondary Laptop:
- Attack tools pre-installed (Ettercap, Arpspoof, custom scripts)
- Network configuration scripts
- Backup of attack demonstration scripts

## Network Configuration

### Primary Configuration
```
Network: 192.168.88.0/24
Backup Laptop: 192.168.88.10
Raspberry Pi: 192.168.88.20
VM Target: 192.168.88.30
Secondary Laptop: 192.168.88.40
```

### Fallback Configuration
```
Network: 10.10.10.0/24
Backup Laptop: 10.10.10.10
Raspberry Pi: 10.10.10.20
VM Target: 10.10.10.30
Secondary Laptop: 10.10.10.40
```

## Setup Procedure

### 1. Hardware Assembly (15 minutes)
1. Set up the backup laptop and connect power
2. Connect the portable monitor via USB-C
3. Power up the network switch
4. Connect all devices to the network switch
5. Power up all devices

### 2. Network Configuration (10 minutes)
1. On backup laptop, run the network configuration script:
   ```
   cd ~/arpguard-backup/scripts
   ./configure_network.sh primary
   ```
2. Verify connectivity between all devices:
   ```
   ./test_connectivity.sh
   ```
3. If any connectivity issues, run the fallback configuration:
   ```
   ./configure_network.sh fallback
   ```

### 3. Software Preparation (15 minutes)
1. On backup laptop, run the environment validation script:
   ```
   cd ~/arpguard-backup
   ./validate_environment.sh
   ```
2. Start necessary services and background processes:
   ```
   ./start_services.sh
   ```
3. Ensure all VMs are ready but not running
4. Initialize the demo dashboard:
   ```
   ./init_dashboard.sh
   ```

### 4. Demo Verification (10 minutes)
1. Run through each demo scenario to verify it works:
   ```
   cd ~/arpguard-backup/demos
   ./validate_scenarios.sh --quick
   ```
2. Check that all fallback options are working:
   ```
   ./test_fallbacks.sh
   ```
3. Verify pre-recorded demo videos play correctly

## Environment Check Script

Create a new environment check script specific to the backup environment:

```python
#!/usr/bin/env python3
import sys
import platform
import psutil
import netifaces
import subprocess
import os
from typing import Dict, List, Tuple

def check_backup_hardware():
    """Check if the backup hardware meets requirements."""
    cpu_count = psutil.cpu_count()
    memory = psutil.virtual_memory()
    memory_gb = memory.total / (1024**3)
    
    cpu_ok = cpu_count >= 4
    memory_ok = memory_gb >= 8
    
    message = f"CPU: {cpu_count} cores ({'OK' if cpu_ok else 'Below minimum'})\n"
    message += f"Memory: {memory_gb:.1f}GB ({'OK' if memory_ok else 'Below minimum'})"
    
    return cpu_ok and memory_ok, message

def check_backup_network():
    """Check if the backup network is properly configured."""
    try:
        # Check if the network interface has the correct IP
        interfaces = netifaces.interfaces()
        correct_ip = False
        network_interface = None
        
        for iface in interfaces:
            if iface.startswith(('eth', 'en', 'wl')):
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        if addr['addr'] == '192.168.88.10' or addr['addr'] == '10.10.10.10':
                            correct_ip = True
                            network_interface = iface
                            break
        
        if not correct_ip:
            return False, "Backup laptop does not have the correct IP address"
        
        # Ping test devices
        test_ips = ['192.168.88.20', '192.168.88.30', '192.168.88.40']
        fallback_ips = ['10.10.10.20', '10.10.10.30', '10.10.10.40']
        
        # Use the first set of IPs that responds
        working_ips = None
        for ip_set in [test_ips, fallback_ips]:
            if all(ping_host(ip) for ip in ip_set):
                working_ips = ip_set
                break
        
        if not working_ips:
            return False, "Cannot ping test devices on either network"
        
        message = f"Network properly configured on {network_interface}\n"
        message += f"All devices reachable on network {working_ips[0][:working_ips[0].rindex('.')]}.0/24"
        return True, message
    
    except Exception as e:
        return False, f"Error checking network: {str(e)}"

def ping_host(ip):
    """Ping a host to check connectivity."""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]
    return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def check_backup_software():
    """Check if all required software is installed."""
    required_software = [
        "arpguard",
        "wireshark",
        "virtualbox",
        "python3"
    ]
    
    missing = []
    for software in required_software:
        if not check_installed(software):
            missing.append(software)
    
    if missing:
        return False, f"Missing software: {', '.join(missing)}"
    
    # Check ARPGuard version
    try:
        arpguard_version = subprocess.check_output(["arpguard", "--version"], 
                                                 stderr=subprocess.STDOUT).decode().strip()
        if "0.9.2" not in arpguard_version and "0.9.3" not in arpguard_version:
            return False, f"ARPGuard version mismatch: {arpguard_version}"
    except:
        return False, "Cannot determine ARPGuard version"
    
    return True, "All required software is installed and properly versioned"

def check_installed(software):
    """Check if software is installed."""
    try:
        subprocess.check_call(["which", software], 
                             stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def check_demo_files():
    """Check if all demo files are available."""
    required_paths = [
        "~/arpguard-backup",
        "~/arpguard-backup/scripts",
        "~/arpguard-backup/demos",
        "~/demo-videos",
        "~/arpguard-backup/scripts/configure_network.sh",
        "~/arpguard-backup/scripts/test_connectivity.sh",
        "~/arpguard-backup/demos/validate_scenarios.sh"
    ]
    
    missing = []
    for path in required_paths:
        expanded_path = os.path.expanduser(path)
        if not os.path.exists(expanded_path):
            missing.append(path)
    
    if missing:
        return False, f"Missing files or directories: {', '.join(missing)}"
    
    return True, "All required demo files are available"

def main():
    """Run all backup environment checks and report results."""
    checks = [
        ("Backup Hardware", check_backup_hardware()),
        ("Backup Network", check_backup_network()),
        ("Backup Software", check_backup_software()),
        ("Backup Demo Files", check_demo_files())
    ]
    
    all_passed = True
    print("ARPGuard Backup Environment Check\n")
    print("=" * 50)
    
    for name, (passed, message) in checks:
        status = "PASSED" if passed else "FAILED"
        print(f"\n{name} - {status}")
        print("-" * 50)
        print(message)
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 50)
    print(f"\nOverall Status: {'PASSED' if all_passed else 'FAILED'}")
    
    if not all_passed:
        print("\nRecommendations:")
        print("- Run the recovery script: ~/arpguard-backup/recover_environment.sh")
        print("- Verify network connectivity manually")
        print("- Check that all devices are powered on and connected")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

## Fallback Demo Procedures

### Scenario 1: Hardware Failure
If the backup laptop fails:
1. Use the secondary laptop as the demo machine
2. Run the emergency setup script:
   ```
   cd ~/arpguard-emergency
   ./setup_emergency.sh
   ```
3. Use pre-recorded videos for complex demonstrations

### Scenario 2: Network Failure
If the backup network fails:
1. Switch to local-only demonstration:
   ```
   cd ~/arpguard-backup
   ./switch_to_local_only.sh
   ```
2. Run the simulation mode:
   ```
   arpguard --simulation=enterprise-network
   ```

### Scenario 3: Software Failure
If ARPGuard fails to start:
1. Use the alternative build:
   ```
   cd ~/arpguard-backup/alternative
   ./arpguard-alt
   ```
2. If both builds fail, use the web-based demo:
   ```
   cd ~/arpguard-backup/web-demo
   ./start_web_demo.sh
   ```

## Pre-Presentation Checklist

On the day of the presentation, run through this checklist:

- [ ] Backup laptop fully charged and power adapter available
- [ ] All devices fully charged
- [ ] Network switch tested
- [ ] All network cables tested
- [ ] Environment check script passes all tests
- [ ] Demo scenarios verified within the last hour
- [ ] All presentation materials accessible offline
- [ ] Backup USB drive with all software and configurations
- [ ] Contact information for technical support available
- [ ] Room layout verified for backup demo setup 