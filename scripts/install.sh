#!/bin/bash
# ARP Guard Unified Installation Script
# Detects OS and calls the appropriate platform-specific installer

set -e

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

# Print header
echo -e "${BOLD}ARP Guard - Unified Installation Script${RESET}"
echo "This script will detect your operating system and install ARP Guard."
echo

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "cygwin"* || "$OSTYPE" == "win32" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

OS=$(detect_os)
echo -e "Detected OS: ${BOLD}$OS${RESET}"

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Check if running as root/admin
check_admin_privileges() {
    if [[ "$OS" == "windows" ]]; then
        # Check if running as administrator on Windows
        if ! net session &>/dev/null; then
            echo -e "${RED}Error: This script must be run with administrative privileges.${RESET}"
            echo "Please run this script from an administrator PowerShell or Command Prompt."
            exit 1
        fi
    else
        # Check if running as root on Linux/macOS
        if [[ $EUID -ne 0 ]]; then
            echo -e "${RED}Error: This script must be run as root.${RESET}"
            echo "Please run this script with sudo:"
            echo "sudo $0"
            exit 1
        fi
    fi
}

# Download platform-specific installer if not available
download_installer() {
    local platform=$1
    local installer_file=""
    local installer_url=""
    
    case $platform in
        "linux")
            installer_file="$SCRIPT_DIR/install_linux.sh"
            installer_url="https://raw.githubusercontent.com/yourorg/arp-guard/main/scripts/install_linux.sh"
            ;;
        "macos")
            installer_file="$SCRIPT_DIR/install_macos.sh"
            installer_url="https://raw.githubusercontent.com/yourorg/arp-guard/main/scripts/install_macos.sh"
            ;;
        "windows")
            installer_file="$SCRIPT_DIR/install_windows.ps1"
            installer_url="https://raw.githubusercontent.com/yourorg/arp-guard/main/scripts/install_windows.ps1"
            ;;
        *)
            echo -e "${RED}Error: Unsupported platform: $platform${RESET}"
            exit 1
            ;;
    esac
    
    # Check if installer exists
    if [[ ! -f $installer_file ]]; then
        echo "Platform-specific installer not found. Downloading..."
        
        # Check if curl or wget is available
        if command -v curl &>/dev/null; then
            curl -s -o "$installer_file" "$installer_url"
        elif command -v wget &>/dev/null; then
            wget -q -O "$installer_file" "$installer_url"
        else
            echo -e "${RED}Error: Neither curl nor wget is available to download the installer.${RESET}"
            exit 1
        fi
        
        # Make the installer executable
        chmod +x "$installer_file"
    fi
    
    echo "Using installer: $installer_file"
    return 0
}

# Run the appropriate installer
run_installer() {
    case $OS in
        "linux")
            download_installer "linux"
            bash "$SCRIPT_DIR/install_linux.sh"
            ;;
        "macos")
            download_installer "macos"
            bash "$SCRIPT_DIR/install_macos.sh"
            ;;
        "windows")
            download_installer "windows"
            if command -v powershell &>/dev/null; then
                powershell -ExecutionPolicy Bypass -File "$SCRIPT_DIR/install_windows.ps1"
            else
                echo -e "${RED}Error: PowerShell is required for Windows installation but was not found.${RESET}"
                exit 1
            fi
            ;;
        *)
            echo -e "${RED}Error: Unsupported operating system: $OS${RESET}"
            echo "ARP Guard supports Linux, macOS, and Windows."
            exit 1
            ;;
    esac
}

# Main function
main() {
    # Check for admin privileges
    check_admin_privileges
    
    # Run the appropriate installer
    run_installer
}

# Execute main function
main 