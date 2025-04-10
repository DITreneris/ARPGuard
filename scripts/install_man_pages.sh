#!/bin/bash
# ARP Guard - Man Page Installation Script
# This script installs ARP Guard man pages on Linux, macOS, and Windows systems

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MAN_SOURCE_DIR="$PROJECT_ROOT/man"
LICENSE_FILE="$PROJECT_ROOT/LICENSE"

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

# Print header
echo -e "${BOLD}ARP Guard - Man Page Installation${RESET}"
echo "This script will install ARP Guard man pages on your system."
echo

# Check OS
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

# Install man pages on Linux
install_linux_man_pages() {
    echo -e "\n${BOLD}Installing man pages on Linux...${RESET}"
    
    # Determine man directory
    MAN_DIR="/usr/local/share/man/man1"
    if [[ ! -d "$MAN_DIR" ]]; then
        mkdir -p "$MAN_DIR"
    fi
    
    # Copy man pages
    echo "Copying man pages to $MAN_DIR..."
    cp "$MAN_SOURCE_DIR"/*.1 "$MAN_DIR/"
    
    # Set permissions
    chmod 644 "$MAN_DIR"/arp-guard*.1
    
    # Update man database
    echo "Updating man database..."
    if command -v mandb &>/dev/null; then
        mandb -q
    elif command -v makewhatis &>/dev/null; then
        makewhatis
    fi
    
    echo -e "${GREEN}Man pages installed successfully.${RESET}"
    echo "You can now view the man pages with:"
    echo "  man arp-guard"
}

# Install man pages on macOS
install_macos_man_pages() {
    echo -e "\n${BOLD}Installing man pages on macOS...${RESET}"
    
    # Determine man directory
    MAN_DIR="/usr/local/share/man/man1"
    if [[ ! -d "$MAN_DIR" ]]; then
        mkdir -p "$MAN_DIR"
    fi
    
    # Copy man pages
    echo "Copying man pages to $MAN_DIR..."
    cp "$MAN_SOURCE_DIR"/*.1 "$MAN_DIR/"
    
    # Set permissions
    chmod 644 "$MAN_DIR"/arp-guard*.1
    
    echo -e "${GREEN}Man pages installed successfully.${RESET}"
    echo "You can now view the man pages with:"
    echo "  man arp-guard"
}

# Install man pages on Windows
install_windows_man_pages() {
    echo -e "\n${BOLD}Installing man pages on Windows...${RESET}"
    
    # Check if Git Bash/MinGW is available
    if command -v git &>/dev/null; then
        GIT_DIR=$(dirname "$(command -v git)" | sed 's/\/cmd//')
        MAN_DIR="$GIT_DIR/usr/share/man/man1"
        
        if [[ -d "$GIT_DIR" ]]; then
            echo "Git Bash detected, installing man pages to $MAN_DIR..."
            
            if [[ ! -d "$MAN_DIR" ]]; then
                mkdir -p "$MAN_DIR"
            fi
            
            cp "$MAN_SOURCE_DIR"/*.1 "$MAN_DIR/"
            echo -e "${GREEN}Man pages installed for Git Bash.${RESET}"
            echo "You can view the man pages in Git Bash with:"
            echo "  man arp-guard"
        fi
    fi
    
    # Create PDF versions for Windows users
    echo "Creating PDF versions of man pages..."
    PDF_DIR="$PROJECT_ROOT/man/pdf"
    
    if [[ ! -d "$PDF_DIR" ]]; then
        mkdir -p "$PDF_DIR"
    fi
    
    if command -v groff &>/dev/null && command -v ps2pdf &>/dev/null; then
        for manpage in "$MAN_SOURCE_DIR"/*.1; do
            base_name=$(basename "$manpage")
            pdf_name="${base_name%.*}.pdf"
            echo "  Converting $base_name to PDF..."
            groff -mandoc -Tps "$manpage" | ps2pdf - "$PDF_DIR/$pdf_name"
        done
        echo -e "${GREEN}PDF man pages created in $PDF_DIR${RESET}"
    else
        echo -e "${YELLOW}Warning: groff or ps2pdf not found. Cannot create PDF versions.${RESET}"
        echo "Install Groff and Ghostscript to create PDF man pages."
    fi
    
    # Create HTML versions as well
    echo "Creating HTML versions of man pages..."
    HTML_DIR="$PROJECT_ROOT/man/html"
    
    if [[ ! -d "$HTML_DIR" ]]; then
        mkdir -p "$HTML_DIR"
    fi
    
    if command -v groff &>/dev/null; then
        for manpage in "$MAN_SOURCE_DIR"/*.1; do
            base_name=$(basename "$manpage")
            html_name="${base_name%.*}.html"
            echo "  Converting $base_name to HTML..."
            groff -mandoc -Thtml "$manpage" > "$HTML_DIR/$html_name"
        done
        echo -e "${GREEN}HTML man pages created in $HTML_DIR${RESET}"
    else
        echo -e "${YELLOW}Warning: groff not found. Cannot create HTML versions.${RESET}"
    fi
    
    echo -e "\n${YELLOW}Note:${RESET} Windows doesn't have a built-in man page system."
    echo "The man pages have been converted to PDF and HTML formats for Windows users."
    echo "You can find them in:"
    echo "  PDF: $PDF_DIR"
    echo "  HTML: $HTML_DIR"
}

# Main installation function
install_man_pages() {
    echo -e "\n${BOLD}Checking for man pages...${RESET}"
    
    # Check if man directory exists
    if [[ ! -d "$MAN_SOURCE_DIR" ]]; then
        echo -e "${RED}Error: Man page directory not found: $MAN_SOURCE_DIR${RESET}"
        exit 1
    fi
    
    # Check if man pages exist
    if ! ls "$MAN_SOURCE_DIR"/*.1 &>/dev/null; then
        echo -e "${RED}Error: No man pages found in $MAN_SOURCE_DIR${RESET}"
        exit 1
    fi
    
    # Install based on OS
    case "$OS" in
        linux)
            install_linux_man_pages
            ;;
        macos)
            install_macos_man_pages
            ;;
        windows)
            install_windows_man_pages
            ;;
        *)
            echo -e "${RED}Error: Unsupported operating system: $OS${RESET}"
            exit 1
            ;;
    esac
}

# Run installation with admin check
check_admin_privileges
install_man_pages

echo -e "\n${BOLD}${GREEN}ARP Guard man page installation complete!${RESET}"
exit 0 