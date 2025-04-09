#!/usr/bin/env python3
import sys
import platform
import psutil
import netifaces
import pkg_resources
import subprocess
from typing import Dict, List, Tuple

def check_python_version() -> Tuple[bool, str]:
    """Check if Python version meets requirements."""
    required_version = (3, 8)
    current_version = sys.version_info[:2]
    is_compatible = current_version >= required_version
    message = f"Python {current_version[0]}.{current_version[1]} {'meets' if is_compatible else 'does not meet'} minimum requirement of {required_version[0]}.{required_version[1]}"
    return is_compatible, message

def check_system_requirements() -> Tuple[bool, str]:
    """Check system requirements (CPU, RAM)."""
    cpu_count = psutil.cpu_count()
    memory = psutil.virtual_memory()
    memory_gb = memory.total / (1024**3)
    
    cpu_ok = cpu_count >= 2
    memory_ok = memory_gb >= 4
    
    message = f"CPU: {cpu_count} cores ({'OK' if cpu_ok else 'Below minimum'})\n"
    message += f"Memory: {memory_gb:.1f}GB ({'OK' if memory_ok else 'Below minimum'})"
    
    return cpu_ok and memory_ok, message

def check_network_interfaces() -> Tuple[bool, str]:
    """Check available network interfaces."""
    try:
        interfaces = netifaces.interfaces()
        if not interfaces:
            return False, "No network interfaces found"
        
        message = "Available network interfaces:\n"
        for iface in interfaces:
            message += f"- {iface}\n"
        return True, message
    except Exception as e:
        return False, f"Error checking network interfaces: {str(e)}"

def check_dependencies() -> Tuple[bool, str]:
    """Check required Python packages."""
    required_packages = {
        'scapy': None,
        'netifaces': None,
        'psutil': None,
        'netaddr': None,
        'PyQt5': '5.15.2',
        'pyqtwebengine': None,
        'matplotlib': None,
        'pyqtgraph': None
    }
    
    installed_packages = {pkg.key: pkg.version for pkg in pkg_resources.working_set}
    missing = []
    outdated = []
    
    for package, required_version in required_packages.items():
        if package not in installed_packages:
            missing.append(package)
        elif required_version and installed_packages[package] != required_version:
            outdated.append(f"{package} (installed: {installed_packages[package]}, required: {required_version})")
    
    message = ""
    if missing:
        message += f"Missing packages: {', '.join(missing)}\n"
    if outdated:
        message += f"Outdated packages: {', '.join(outdated)}\n"
    if not message:
        message = "All required packages are installed and up to date"
    
    return not (missing or outdated), message

def check_windows_specific() -> Tuple[bool, str]:
    """Check Windows-specific requirements (Npcap)."""
    if platform.system() != 'Windows':
        return True, "Not running on Windows, skipping Npcap check"
    
    try:
        # Check if Npcap is installed by looking for its DLL
        import ctypes
        npcap_path = r"C:\Windows\System32\Npcap\NPFInstall.exe"
        if not ctypes.windll.kernel32.GetFileAttributesW(npcap_path):
            return False, "Npcap is not installed or not in the expected location"
        return True, "Npcap is installed"
    except Exception as e:
        return False, f"Error checking Npcap installation: {str(e)}"

def main():
    """Run all environment checks and report results."""
    checks = [
        ("Python Version", check_python_version()),
        ("System Requirements", check_system_requirements()),
        ("Network Interfaces", check_network_interfaces()),
        ("Dependencies", check_dependencies()),
        ("Windows Specific", check_windows_specific())
    ]
    
    all_passed = True
    print("ARPGuard Environment Check\n")
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
        if platform.system() == 'Windows':
            print("- Install Npcap from https://npcap.com/#download")
        print("- Install missing packages using: pip install -r requirements.txt")
        print("- Ensure you have at least 4GB of RAM and a dual-core processor")
        sys.exit(1)

if __name__ == "__main__":
    main() 