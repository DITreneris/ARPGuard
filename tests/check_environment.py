#!/usr/bin/env python
"""
ARPGuard Test Environment Check
This script verifies that all required dependencies for testing are installed
and properly configured.
"""

import sys
import os
import importlib
import subprocess
import platform
from importlib.util import find_spec

def print_header(title):
    """Print a formatted header"""
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)

def check_python_version():
    """Check Python version"""
    print_header("Python Environment")
    print(f"Python Version: {platform.python_version()}")
    print(f"Python Implementation: {platform.python_implementation()}")
    print(f"Platform: {platform.system()} {platform.release()}")
    
    min_version = (3, 7, 0)
    current_version = sys.version_info[:3]
    
    if current_version >= min_version:
        print(f"✅ Python version >= {'.'.join(map(str, min_version))}")
    else:
        print(f"❌ Python version < {'.'.join(map(str, min_version))}")
        print(f"   Current: {'.'.join(map(str, current_version))}")
        print(f"   Required: {'.'.join(map(str, min_version))}")

def check_module(module_name, min_version=None):
    """Check if a module is installed and meets minimum version requirements"""
    try:
        spec = find_spec(module_name)
        if spec is None:
            print(f"❌ {module_name}: Not found")
            return False
        
        module = importlib.import_module(module_name)
        
        try:
            version = getattr(module, '__version__', 'Unknown')
        except AttributeError:
            version = 'Unknown'
        
        if min_version and version != 'Unknown':
            # Compare versions if both are available
            if version >= min_version:
                print(f"✅ {module_name}: {version} (Required: {min_version})")
                return True
            else:
                print(f"❌ {module_name}: {version} (Required: {min_version})")
                return False
        else:
            print(f"✅ {module_name}: {version}")
            return True
    except ImportError as e:
        print(f"❌ {module_name}: Import error - {str(e)}")
        return False
    except Exception as e:
        print(f"❌ {module_name}: Error - {str(e)}")
        return False

def check_dependencies():
    """Check all required dependencies"""
    print_header("Package Dependencies")
    
    # Required packages with minimum versions
    packages = [
        ("PyQt5", "5.15.4"),
        ("pytest", "7.0.0"),
        ("pytest-qt", "4.1.0"),
        ("pytest-cov", "3.0.0"),
        ("coverage", "6.3.2"),
        ("mock", "4.0.3"),
        ("scapy", "2.4.5"),
        ("netifaces", "0.11.0"),
        ("requests", "2.26.0"),
        ("matplotlib", "3.5.1"),
        ("pyqtgraph", "0.12.4"),
        ("sqlalchemy", "1.4.31"),
        ("cryptography", "36.0.1")
    ]
    
    success_count = 0
    
    for package, min_version in packages:
        if check_module(package, min_version):
            success_count += 1
    
    print(f"\nDependency Check: {success_count}/{len(packages)} packages installed correctly")

def check_system_dependencies():
    """Check system-level dependencies"""
    print_header("System Dependencies")
    
    # Check for WinPcap/Npcap on Windows
    if platform.system() == "Windows":
        print("Checking for WinPcap/Npcap:")
        
        # Check if pcap DLLs exist
        pcap_paths = [
            "C:\\Windows\\System32\\Npcap\\wpcap.dll",
            "C:\\Windows\\System32\\wpcap.dll",
            "C:\\Windows\\System32\\Packet.dll"
        ]
        
        found_pcap = False
        for path in pcap_paths:
            if os.path.exists(path):
                print(f"✅ Found: {path}")
                found_pcap = True
        
        if not found_pcap:
            print("❌ WinPcap/Npcap not found in standard locations")
            print("   Please install Npcap from https://npcap.com/#download")
    
    # Check for libpcap on Linux/macOS
    elif platform.system() in ["Linux", "Darwin"]:
        print("Checking for libpcap:")
        
        try:
            result = subprocess.run(["whereis", "libpcap"], capture_output=True, text=True)
            if "libpcap:" in result.stdout and len(result.stdout.strip().split()) > 1:
                print(f"✅ libpcap found: {result.stdout.strip()}")
            else:
                print("❌ libpcap not found")
                if platform.system() == "Linux":
                    print("   Install with: sudo apt-get install libpcap-dev")
                else:
                    print("   Install with: brew install libpcap")
        except Exception as e:
            print(f"❌ Error checking for libpcap: {str(e)}")

def check_test_environment():
    """Check if the test environment is correctly set up"""
    print_header("Test Environment")
    
    # Check if app directory exists
    app_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app")
    if os.path.isdir(app_dir):
        print(f"✅ App directory found: {app_dir}")
    else:
        print(f"❌ App directory not found: {app_dir}")
    
    # Check if tests can access the app directory
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        import app
        print("✅ Can import app module")
    except ImportError as e:
        print(f"❌ Cannot import app module: {str(e)}")
    
    # Check if test files exist
    test_files = ["test_network_scanner.py", "test_arp_spoofer.py", "test_threat_detector.py"]
    test_dir = os.path.dirname(os.path.abspath(__file__))
    
    test_files_found = 0
    for test_file in test_files:
        test_path = os.path.join(test_dir, test_file)
        if os.path.isfile(test_path):
            test_files_found += 1
            print(f"✅ Test file found: {test_file}")
        else:
            print(f"❌ Test file not found: {test_file}")
    
    print(f"\nTest Files: {test_files_found}/{len(test_files)} required test files found")

def main():
    """Main function"""
    print("\nARPGuard Test Environment Check")
    print("--------------------------------")
    
    check_python_version()
    check_dependencies()
    check_system_dependencies()
    check_test_environment()
    
    print("\nCheck completed. Please address any issues marked with ❌")

if __name__ == "__main__":
    main() 