#!/bin/bash
# Build script for ARP Guard macOS package

set -e

# Configuration
VERSION="0.3.0"
PACKAGE_NAME="ARPGuard"
IDENTIFIER="com.arpguard.security"
BUILD_DIR="./build"
PACKAGE_ROOT="${BUILD_DIR}/root"
SCRIPTS_DIR="${BUILD_DIR}/scripts"
RESOURCES_DIR="${BUILD_DIR}/resources"
SRC_DIR="../../"

# Create build directories
echo "Creating build directories..."
mkdir -p ${PACKAGE_ROOT}/Applications/ARPGuard.app/Contents/MacOS
mkdir -p ${PACKAGE_ROOT}/Applications/ARPGuard.app/Contents/Resources
mkdir -p ${PACKAGE_ROOT}/Applications/ARPGuard.app/Contents/Frameworks
mkdir -p ${PACKAGE_ROOT}/Library/LaunchDaemons
mkdir -p ${PACKAGE_ROOT}/Library/LaunchAgents
mkdir -p ${PACKAGE_ROOT}/etc/arpguard
mkdir -p ${PACKAGE_ROOT}/var/log/arpguard
mkdir -p ${PACKAGE_ROOT}/var/lib/arpguard
mkdir -p ${SCRIPTS_DIR}
mkdir -p ${RESOURCES_DIR}

# Copy application files
echo "Copying application files..."
cp -r ${SRC_DIR}/src ${PACKAGE_ROOT}/Applications/ARPGuard.app/Contents/Resources/
cp -r ${SRC_DIR}/app ${PACKAGE_ROOT}/Applications/ARPGuard.app/Contents/Resources/
cp -r ${SRC_DIR}/scripts ${PACKAGE_ROOT}/Applications/ARPGuard.app/Contents/Resources/
cp -r ${SRC_DIR}/config ${PACKAGE_ROOT}/Applications/ARPGuard.app/Contents/Resources/
cp ${SRC_DIR}/requirements.txt ${PACKAGE_ROOT}/Applications/ARPGuard.app/Contents/Resources/

# Create Info.plist
echo "Creating Info.plist..."
cat > ${PACKAGE_ROOT}/Applications/ARPGuard.app/Contents/Info.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>${IDENTIFIER}</string>
    <key>CFBundleName</key>
    <string>ARPGuard</string>
    <key>CFBundleDisplayName</key>
    <string>ARP Guard</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon.icns</string>
    <key>CFBundleExecutable</key>
    <string>arpguard</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>NSHumanReadableCopyright</key>
    <string>© 2025 ARPGuard Security. All rights reserved.</string>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.utilities</string>
</dict>
</plist>
EOF

# Create main executable script
echo "Creating executable..."
cat > ${PACKAGE_ROOT}/Applications/ARPGuard.app/Contents/MacOS/arpguard << 'EOF'
#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
RESOURCES_DIR="$(dirname "$SCRIPT_DIR")/Resources"
export PYTHONPATH=$RESOURCES_DIR:$PYTHONPATH
exec python3 $RESOURCES_DIR/src/main.py "$@"
EOF
chmod 755 ${PACKAGE_ROOT}/Applications/ARPGuard.app/Contents/MacOS/arpguard

# Create launchd service file
echo "Creating launchd service..."
cat > ${PACKAGE_ROOT}/Library/LaunchDaemons/com.arpguard.daemon.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.arpguard.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/ARPGuard.app/Contents/MacOS/arpguard</string>
        <string>--service</string>
        <string>--config</string>
        <string>/etc/arpguard/config.yaml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/arpguard/daemon.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/arpguard/daemon_error.log</string>
    <key>WorkingDirectory</key>
    <string>/Applications/ARPGuard.app/Contents/Resources</string>
</dict>
</plist>
EOF

# Create default configuration file
echo "Creating default configuration..."
cat > ${PACKAGE_ROOT}/etc/arpguard/config.yaml << 'EOF'
# ARP Guard default configuration
application:
  name: ARP Guard
  version: 0.3.0
  mode: lite

network:
  interface: auto
  scan_interval: 60
  monitoring: true

security:
  threat_detection: true
  alerts_enabled: true
  log_level: info

api:
  enabled: true
  host: localhost
  port: 8080
  websocket_port: 8081

notifications:
  email: false
  desktop: true
  console: true

logging:
  path: /var/log/arpguard
  rotation: daily
  retention: 30
EOF

# Create preflight script
echo "Creating installation scripts..."
cat > ${SCRIPTS_DIR}/preinstall << 'EOF'
#!/bin/bash
set -e

# Check for Python
if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: Python 3 is required but not installed."
    echo "Please install Python 3 from https://www.python.org/downloads/mac-osx/"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print("%s.%s" % (sys.version_info.major, sys.version_info.minor))')
if [[ $(echo "$PYTHON_VERSION < 3.8" | bc) -eq 1 ]]; then
    echo "Error: Python 3.8 or higher is required. Found $PYTHON_VERSION"
    echo "Please upgrade Python from https://www.python.org/downloads/mac-osx/"
    exit 1
fi

# Stop existing services
if [ -f "/Library/LaunchDaemons/com.arpguard.daemon.plist" ]; then
    launchctl unload /Library/LaunchDaemons/com.arpguard.daemon.plist || true
fi

exit 0
EOF
chmod 755 ${SCRIPTS_DIR}/preinstall

# Create postflight script
cat > ${SCRIPTS_DIR}/postinstall << 'EOF'
#!/bin/bash
set -e

# Create log and lib directories if they don't exist
mkdir -p /var/log/arpguard
mkdir -p /var/lib/arpguard
chmod -R 755 /var/log/arpguard
chmod -R 755 /var/lib/arpguard

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r /Applications/ARPGuard.app/Contents/Resources/requirements.txt || true

# Load the service
echo "Starting ARP Guard service..."
launchctl load /Library/LaunchDaemons/com.arpguard.daemon.plist || true

# Create symlink for command-line access
ln -sf /Applications/ARPGuard.app/Contents/MacOS/arpguard /usr/local/bin/arpguard

echo "ARP Guard installation complete!"
exit 0
EOF
chmod 755 ${SCRIPTS_DIR}/postinstall

# Set permissions
echo "Setting permissions..."
find ${PACKAGE_ROOT} -type d -exec chmod 755 {} \;
find ${PACKAGE_ROOT} -type f -exec chmod 644 {} \;
chmod 755 ${PACKAGE_ROOT}/Applications/ARPGuard.app/Contents/MacOS/arpguard
chmod 644 ${PACKAGE_ROOT}/Library/LaunchDaemons/com.arpguard.daemon.plist

# Build the package
echo "Building macOS package..."
pkgbuild --root ${PACKAGE_ROOT} \
         --identifier ${IDENTIFIER} \
         --version ${VERSION} \
         --scripts ${SCRIPTS_DIR} \
         --install-location / \
         ${BUILD_DIR}/${PACKAGE_NAME}-${VERSION}.pkg

# Clean up
echo "Cleaning up..."
# rm -rf ${PACKAGE_ROOT} ${SCRIPTS_DIR}
echo "Package built: ${BUILD_DIR}/${PACKAGE_NAME}-${VERSION}.pkg"

echo "Build complete!" 