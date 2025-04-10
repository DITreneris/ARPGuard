#!/bin/bash

# ARP Guard Installation Script for Linux
# This script automates the installation process of ARP Guard on Linux systems

set -e

# Configuration
INSTALL_DIR="/opt/arpguard"
CONFIG_DIR="/etc/arpguard"
SYSTEMD_DIR="/etc/systemd/system"
GITHUB_REPO="https://github.com/yourorg/arp-guard"
GITHUB_BRANCH="main"
PYTHON_MIN_VERSION="3.8.0"
REQUIRED_PACKAGES="scapy colorama pyyaml click python-dotenv"

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

# Print header
echo -e "${BOLD}ARP Guard - Linux Installation Script${RESET}"
echo "This script will install ARP Guard on your Linux system."
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root.${RESET}"
   echo "Please run this script with sudo:"
   echo "sudo $0"
   exit 1
fi

# Detect Linux distribution
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_VERSION=$VERSION_ID
        echo -e "Detected distribution: ${BOLD}$PRETTY_NAME${RESET}"
    elif [[ -f /etc/lsb-release ]]; then
        . /etc/lsb-release
        DISTRO=$DISTRIB_ID
        DISTRO_VERSION=$DISTRIB_VERSION
        echo -e "Detected distribution: ${BOLD}$DISTRIB_ID $DISTRIB_VERSION${RESET}"
    else
        DISTRO="unknown"
        echo -e "${YELLOW}Warning: Could not detect Linux distribution.${RESET}"
        echo "Installation may not complete correctly."
    fi
}

# Install system dependencies based on distribution
install_dependencies() {
    echo -e "\n${BOLD}Installing system dependencies...${RESET}"
    
    case $DISTRO in
        "ubuntu"|"debian"|"linuxmint"|"pop")
            echo "Using apt package manager..."
            apt update
            apt install -y python3 python3-pip python3-venv libpcap-dev git tcpdump
            ;;
        "fedora"|"rhel"|"centos"|"rocky"|"alma")
            echo "Using dnf/yum package manager..."
            if command -v dnf &>/dev/null; then
                dnf install -y python3 python3-pip python3-devel libpcap-devel git tcpdump
            else
                yum install -y python3 python3-pip python3-devel libpcap-devel git tcpdump
            fi
            ;;
        "arch"|"manjaro")
            echo "Using pacman package manager..."
            pacman -Sy --noconfirm python python-pip libpcap tcpdump git
            ;;
        "opensuse"|"suse")
            echo "Using zypper package manager..."
            zypper install -y python3 python3-pip python3-devel libpcap-devel git tcpdump
            ;;
        *)
            echo -e "${YELLOW}Warning: Unsupported distribution. Installing minimal dependencies.${RESET}"
            # Try to install Python and pip as a minimum
            if command -v apt &>/dev/null; then
                apt update
                apt install -y python3 python3-pip git
            elif command -v dnf &>/dev/null; then
                dnf install -y python3 python3-pip git
            elif command -v yum &>/dev/null; then
                yum install -y python3 python3-pip git
            elif command -v pacman &>/dev/null; then
                pacman -Sy --noconfirm python python-pip git
            else
                echo -e "${RED}Error: No supported package manager found.${RESET}"
                echo "Please install Python 3.8+, pip, and git manually."
                exit 1
            fi
            ;;
    esac
    
    echo -e "${GREEN}System dependencies installed successfully.${RESET}"
}

# Check Python version
check_python() {
    echo -e "\n${BOLD}Checking Python installation...${RESET}"
    
    if command -v python3 &>/dev/null; then
        PYTHON_CMD="python3"
    else
        PYTHON_CMD="python"
    fi
    
    if ! command -v $PYTHON_CMD &>/dev/null; then
        echo -e "${RED}Error: Python not found. Installation failed.${RESET}"
        exit 1
    fi
    
    # Get Python version
    PYTHON_VERSION=$($PYTHON_CMD --version | sed 's/Python //g')
    echo "Python version: $PYTHON_VERSION"
    
    # Compare versions
    compare_versions() {
        python3 -c "
from packaging import version
import sys
sys.exit(0 if version.parse('$1') >= version.parse('$2') else 1)
"
    }
    
    if ! compare_versions $PYTHON_VERSION $PYTHON_MIN_VERSION; then
        echo -e "${RED}Error: Python version $PYTHON_VERSION is below minimum required version $PYTHON_MIN_VERSION.${RESET}"
        echo "Please upgrade Python and try again."
        exit 1
    fi
    
    # Check pip installation
    if ! command -v pip3 &>/dev/null && ! command -v pip &>/dev/null; then
        echo -e "${YELLOW}pip not found. Installing pip...${RESET}"
        $PYTHON_CMD -m ensurepip --upgrade || {
            echo -e "${RED}Error: Failed to install pip. Installation aborted.${RESET}"
            exit 1
        }
    fi
    
    # Determine pip command
    if command -v pip3 &>/dev/null; then
        PIP_CMD="pip3"
    else
        PIP_CMD="pip"
    fi
    
    echo -e "${GREEN}Python $PYTHON_VERSION and pip are properly installed.${RESET}"
}

# Create virtual environment (optional)
setup_virtualenv() {
    echo -e "\n${BOLD}Setting up virtual environment...${RESET}"
    
    # Create venv directory
    mkdir -p $INSTALL_DIR
    $PYTHON_CMD -m venv $INSTALL_DIR/venv
    
    # Activate virtual environment
    source $INSTALL_DIR/venv/bin/activate
    
    # Upgrade pip in virtual environment
    $PIP_CMD install --upgrade pip
    
    echo -e "${GREEN}Virtual environment created at $INSTALL_DIR/venv${RESET}"
}

# Install Python packages
install_python_packages() {
    echo -e "\n${BOLD}Installing Python packages...${RESET}"
    
    # Install required packages
    for package in $REQUIRED_PACKAGES; do
        echo "Installing $package..."
        $PIP_CMD install $package
    done
    
    echo -e "${GREEN}Python packages installed successfully.${RESET}"
}

# Clone the repository
clone_repository() {
    echo -e "\n${BOLD}Downloading ARP Guard...${RESET}"
    
    # Create temp directory
    TEMP_DIR=$(mktemp -d)
    
    # Clone the repository
    echo "Cloning from $GITHUB_REPO..."
    git clone --depth 1 --branch $GITHUB_BRANCH $GITHUB_REPO $TEMP_DIR
    
    # Create installation directories
    mkdir -p $INSTALL_DIR
    mkdir -p $CONFIG_DIR
    
    # Copy files
    cp -r $TEMP_DIR/* $INSTALL_DIR/
    
    # Cleanup
    rm -rf $TEMP_DIR
    
    echo -e "${GREEN}ARP Guard downloaded to $INSTALL_DIR${RESET}"
}

# Install the package
install_package() {
    echo -e "\n${BOLD}Installing ARP Guard package...${RESET}"
    
    # Navigate to installation directory
    cd $INSTALL_DIR
    
    # Install the package
    $PIP_CMD install -e .
    
    # Create symlink to executable
    ln -sf $INSTALL_DIR/venv/bin/arp-guard /usr/local/bin/arp-guard
    
    echo -e "${GREEN}ARP Guard package installed successfully.${RESET}"
}

# Create systemd service
create_systemd_service() {
    echo -e "\n${BOLD}Creating systemd service...${RESET}"
    
    # Create service file
    cat > $SYSTEMD_DIR/arpguard.service << EOF
[Unit]
Description=ARP Guard Protection Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/src/main.py service run
Restart=on-failure
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=arpguard

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    systemctl daemon-reload
    
    echo -e "${GREEN}Systemd service created.${RESET}"
    echo "To enable and start the service:"
    echo "  sudo systemctl enable arpguard"
    echo "  sudo systemctl start arpguard"
}

# Create configuration directory and files
create_config() {
    echo -e "\n${BOLD}Creating configuration...${RESET}"
    
    # Create config directory if it doesn't exist
    mkdir -p $CONFIG_DIR
    
    # Copy default configuration files
    if [[ -d $INSTALL_DIR/config ]]; then
        cp -r $INSTALL_DIR/config/* $CONFIG_DIR/
    fi
    
    # Set appropriate permissions
    chmod 755 $CONFIG_DIR
    chmod 644 $CONFIG_DIR/*
    
    echo -e "${GREEN}Configuration files created in $CONFIG_DIR${RESET}"
}

# Create log directory
create_log_dir() {
    echo -e "\n${BOLD}Setting up logging...${RESET}"
    
    # Create log directory
    mkdir -p /var/log/arpguard
    
    # Set permissions
    chmod 755 /var/log/arpguard
    
    echo -e "${GREEN}Log directory created at /var/log/arpguard${RESET}"
}

# Final setup steps
finalize_installation() {
    echo -e "\n${BOLD}Finalizing installation...${RESET}"
    
    # Create a group for non-root users to access the service
    if ! getent group arpguard > /dev/null; then
        groupadd arpguard
    fi
    
    # Set file permissions
    chown -R root:root $INSTALL_DIR
    chmod -R 755 $INSTALL_DIR
    
    # Create uninstall script
    cat > $INSTALL_DIR/uninstall.sh << EOF
#!/bin/bash
# ARP Guard uninstallation script

echo "Uninstalling ARP Guard..."

# Stop and disable service
systemctl stop arpguard 2>/dev/null || true
systemctl disable arpguard 2>/dev/null || true
rm -f $SYSTEMD_DIR/arpguard.service

# Remove symlink
rm -f /usr/local/bin/arp-guard

# Remove directories
rm -rf $INSTALL_DIR
rm -rf $CONFIG_DIR
rm -rf /var/log/arpguard

echo "ARP Guard has been uninstalled."
EOF
    
    chmod +x $INSTALL_DIR/uninstall.sh
    
    echo -e "${GREEN}Installation finalized.${RESET}"
}

# Display completion message
show_completion() {
    echo -e "\n${BOLD}${GREEN}ARP Guard has been successfully installed!${RESET}"
    echo 
    echo "Installation directory: $INSTALL_DIR"
    echo "Configuration directory: $CONFIG_DIR"
    echo "Log directory: /var/log/arpguard"
    echo 
    echo "To start using ARP Guard:"
    echo "  arp-guard --help"
    echo 
    echo "To run as a service:"
    echo "  sudo systemctl enable arpguard"
    echo "  sudo systemctl start arpguard"
    echo 
    echo "To uninstall:"
    echo "  sudo $INSTALL_DIR/uninstall.sh"
}

# Main installation flow
main() {
    detect_distro
    install_dependencies
    check_python
    setup_virtualenv
    install_python_packages
    clone_repository
    install_package
    create_config
    create_log_dir
    create_systemd_service
    finalize_installation
    show_completion
}

# Run main function
main 