#!/bin/bash
# Script to create a DMG file for ARP Guard macOS application

set -e

# Configuration
VERSION="0.3.0"
PACKAGE_NAME="ARPGuard"
APP_NAME="ARPGuard.app"
DMG_NAME="${PACKAGE_NAME}-${VERSION}"
BUILD_DIR="./build"
DMG_SIZE="500m"
VOLUME_NAME="ARP Guard ${VERSION}"
BACKGROUND_FILE="background.png"
DMG_FINAL="${DMG_NAME}.dmg"

# Check if create-dmg is installed
if ! command -v create-dmg &> /dev/null; then
    echo "Error: create-dmg is not installed."
    echo "Please install it using: 'brew install create-dmg'"
    exit 1
fi

# Ensure the pkg file exists
PKG_FILE="${BUILD_DIR}/${PACKAGE_NAME}-${VERSION}.pkg"
if [ ! -f "${PKG_FILE}" ]; then
    echo "Error: Package file ${PKG_FILE} not found."
    echo "Please run build_pkg.sh first to create the package."
    exit 1
fi

# Create staging directory
echo "Creating staging directory..."
STAGING_DIR="${BUILD_DIR}/staging"
mkdir -p "${STAGING_DIR}"

# Copy files to staging directory
echo "Copying files to staging directory..."
cp "${PKG_FILE}" "${STAGING_DIR}/"

# Create the README file
echo "Creating README file..."
cat > "${STAGING_DIR}/README.txt" << EOF
ARP Guard ${VERSION}
==================

Thank you for downloading ARP Guard, a comprehensive network security tool.

Installation Instructions:
1. Double-click the installer package (${PACKAGE_NAME}-${VERSION}.pkg)
2. Follow the on-screen prompts to complete the installation
3. The application will be installed in your Applications folder
4. A service will be started automatically to provide continuous protection

System Requirements:
- macOS 10.15 or later
- Python 3.8 or later
- 100 MB of disk space
- Administrative privileges for installation

For more information, visit: https://arpguard.com
EOF

# Create DMG
echo "Creating DMG file..."
create-dmg \
    --volname "${VOLUME_NAME}" \
    --volicon "app_icon.icns" \
    --background "${BACKGROUND_FILE}" \
    --window-pos 200 120 \
    --window-size 800 400 \
    --icon-size 100 \
    --icon "${PACKAGE_NAME}-${VERSION}.pkg" 200 190 \
    --icon "README.txt" 600 190 \
    --hide-extension "${PACKAGE_NAME}-${VERSION}.pkg" \
    --app-drop-link 400 190 \
    --no-internet-enable \
    "${DMG_FINAL}" \
    "${STAGING_DIR}"

echo "DMG created: ${DMG_FINAL}"

# Clean up
echo "Cleaning up..."
rm -rf "${STAGING_DIR}"

echo "DMG creation complete!" 