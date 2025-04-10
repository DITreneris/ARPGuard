#!/bin/bash

# ARP Guard macOS Installation Script
# This script installs ARP Guard on macOS systems

set -e

# Configuration
INSTALL_DIR="/opt/arpguard"
CONFIG_DIR="/etc/arpguard"
LAUNCH_DAEMON_DIR="/Library/LaunchDaemons"
LAUNCH_DAEMON_FILE="com.arpguard.daemon.plist"
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
echo -e "${BOLD}ARP Guard - macOS Installation Script${RESET}"
echo "This script will install ARP Guard on your macOS system."
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root.${RESET}"
   echo "Please run this script with sudo:"
   echo "sudo $0"
   exit 1
fi

# Check macOS version
check_macos_version() {
    echo -e "\n${BOLD}Checking macOS version...${RESET}"
    
    # Get macOS version
    MACOS_VERSION=$(sw_vers -productVersion)
    MACOS_MAJOR=$(echo $MACOS_VERSION | cut -d. -f1)
    MACOS_MINOR=$(echo $MACOS_VERSION | cut -d. -f2)
    
    echo "macOS version: $MACOS_VERSION"
    
    # Check if macOS version is at least 10.14 (Mojave)
    if [[ $MACOS_MAJOR -lt 10 || ($MACOS_MAJOR -eq 10 && $MACOS_MINOR -lt 14) ]]; then
        echo -e "${YELLOW}Warning: ARP Guard is designed for macOS 10.14+ (Mojave or newer).${RESET}"
        echo "You may experience issues on older versions."
        read -p "Continue anyway? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Installation aborted."
            exit 1
        fi
    else
        echo -e "${GREEN}macOS version is compatible.${RESET}"
    fi
}

# Check and install Homebrew if needed
check_homebrew() {
    echo -e "\n${BOLD}Checking Homebrew installation...${RESET}"
    
    if ! command -v brew &>/dev/null; then
        echo "Homebrew not found. Would you like to install it?"
        read -p "Install Homebrew? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            if [[ $? -ne 0 ]]; then
                echo -e "${RED}Error: Failed to install Homebrew.${RESET}"
                echo "Please install Homebrew manually from https://brew.sh/"
                echo "Then run this script again."
                exit 1
            fi
            echo -e "${GREEN}Homebrew installed successfully.${RESET}"
        else
            echo "Continuing without Homebrew..."
        fi
    else
        echo -e "${GREEN}Homebrew is already installed.${RESET}"
    fi
}

# Install system dependencies with Homebrew
install_dependencies() {
    echo -e "\n${BOLD}Installing system dependencies...${RESET}"
    
    if command -v brew &>/dev/null; then
        echo "Using Homebrew to install dependencies..."
        brew update
        brew install python libpcap tcpdump git
    else
        echo -e "${YELLOW}Warning: Homebrew not available. Checking for system dependencies...${RESET}"
        
        # Check for Python
        if ! command -v python3 &>/dev/null; then
            echo -e "${RED}Error: Python 3 not found.${RESET}"
            echo "Please install Python 3.8 or newer from https://www.python.org/downloads/macos/"
            exit 1
        fi
        
        # Check for libpcap
        if ! pkgutil --pkg-info=com.apple.pkg.LibpcapDevelopmentHeaders &>/dev/null; then
            echo -e "${YELLOW}Warning: libpcap development headers may not be installed.${RESET}"
            echo "Scapy may not work correctly without libpcap."
            echo "Consider installing XCode Command Line Tools with:"
            echo "  xcode-select --install"
        fi
        
        # Check for git
        if ! command -v git &>/dev/null; then
            echo -e "${RED}Error: git not found.${RESET}"
            echo "Please install git or XCode Command Line Tools."
            exit 1
        fi
    fi
    
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

# Create virtual environment
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

# Create LaunchDaemon service
create_launch_daemon() {
    echo -e "\n${BOLD}Creating LaunchDaemon service...${RESET}"
    
    # Create LaunchDaemon plist file
    cat > $LAUNCH_DAEMON_DIR/$LAUNCH_DAEMON_FILE << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.arpguard.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/venv/bin/python</string>
        <string>$INSTALL_DIR/src/main.py</string>
        <string>service</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/arpguard/error.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/arpguard/output.log</string>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
</dict>
</plist>
EOF
    
    # Set correct permissions
    chmod 644 $LAUNCH_DAEMON_DIR/$LAUNCH_DAEMON_FILE
    
    echo -e "${GREEN}LaunchDaemon service created.${RESET}"
    echo "To load the service:"
    echo "  sudo launchctl load $LAUNCH_DAEMON_DIR/$LAUNCH_DAEMON_FILE"
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

# Set up network permissions
setup_network_permissions() {
    echo -e "\n${BOLD}Setting up network permissions...${RESET}"
    
    echo "ARP Guard requires special permissions to capture network traffic."
    echo "After installation, you may need to manually grant permissions in System Preferences:"
    echo "  1. Go to System Preferences > Security & Privacy > Privacy"
    echo "  2. Select 'Full Disk Access' and add Terminal or the app you're using to run ARP Guard"
    echo "  3. Select 'Network' and ensure Terminal or your app is enabled"
    
    # Check if running in Terminal
    if [[ "$TERM_PROGRAM" == "Apple_Terminal" ]]; then
        echo -e "\n${YELLOW}Note: You are currently using Terminal.${RESET}"
        echo "Would you like to add Terminal to Full Disk Access now?"
        read -p "Open System Preferences? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            # Open System Preferences to the right pane
            open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
        fi
    fi
}

# Final setup steps
finalize_installation() {
    echo -e "\n${BOLD}Finalizing installation...${RESET}"
    
    # Set file permissions
    chown -R root:wheel $INSTALL_DIR
    chmod -R 755 $INSTALL_DIR
    
    # Create uninstall script
    cat > $INSTALL_DIR/uninstall.sh << EOF
#!/bin/bash
# ARP Guard uninstallation script

echo "Uninstalling ARP Guard..."

# Unload LaunchDaemon
launchctl unload $LAUNCH_DAEMON_DIR/$LAUNCH_DAEMON_FILE 2>/dev/null || true
rm -f $LAUNCH_DAEMON_DIR/$LAUNCH_DAEMON_FILE

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
    echo "  sudo launchctl load $LAUNCH_DAEMON_DIR/$LAUNCH_DAEMON_FILE"
    echo 
    echo "To uninstall:"
    echo "  sudo $INSTALL_DIR/uninstall.sh"
    echo
    echo -e "${YELLOW}Important:${RESET} Remember to grant Terminal the required permissions in"
    echo "System Preferences > Security & Privacy > Privacy > Full Disk Access and Network."
}

# Main installation flow
main() {
    check_macos_version
    check_homebrew
    install_dependencies
    check_python
    setup_virtualenv
    install_python_packages
    clone_repository
    install_package
    create_config
    create_log_dir
    create_launch_daemon
    setup_network_permissions
    finalize_installation
    show_completion
}

# Run main function
main 