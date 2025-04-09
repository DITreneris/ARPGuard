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

def check_vm_status():
    """Check if the required VMs are available and functioning."""
    try:
        # Check VirtualBox VMs
        vms = subprocess.check_output(["VBoxManage", "list", "vms"], 
                                     stderr=subprocess.DEVNULL).decode()
        
        required_vms = ["Ubuntu_Target", "Kali_Attacker"]
        missing_vms = []
        
        for vm in required_vms:
            if vm not in vms:
                missing_vms.append(vm)
        
        if missing_vms:
            return False, f"Missing VMs: {', '.join(missing_vms)}"
        
        # Check if VMs can start (without actually starting them)
        for vm in required_vms:
            vm_info = subprocess.check_output(["VBoxManage", "showvminfo", vm], 
                                            stderr=subprocess.DEVNULL).decode()
            if "running" in vm_info.lower():
                continue
            
            # Check if VM is accessible
            if "inaccessible" in vm_info.lower():
                return False, f"VM {vm} is inaccessible"
        
        return True, "All required VMs are available"
    
    except Exception as e:
        return False, f"Error checking VMs: {str(e)}"

def check_backup_dependencies():
    """Check if all Python dependencies for the backup demo are installed."""
    required_packages = {
        'scapy': None,
        'netifaces': None,
        'psutil': None,
        'netaddr': None,
        'PyQt5': None,
        'matplotlib': None
    }
    
    import pkg_resources
    installed_packages = {pkg.key: pkg.version for pkg in pkg_resources.working_set}
    missing = []
    
    for package in required_packages:
        if package.lower() not in [p.lower() for p in installed_packages]:
            missing.append(package)
    
    if missing:
        return False, f"Missing Python packages: {', '.join(missing)}"
    
    return True, "All required Python packages are installed"

def main():
    """Run all backup environment checks and report results."""
    checks = [
        ("Backup Hardware", check_backup_hardware()),
        ("Backup Network", check_backup_network()),
        ("Backup Software", check_backup_software()),
        ("Backup VM Status", check_vm_status()),
        ("Backup Dependencies", check_backup_dependencies()),
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
        print("- Ensure VirtualBox is running and VMs are available")
        sys.exit(1)
    else:
        print("\nBackup demo environment is ready to use.")

if __name__ == "__main__":
    main() 