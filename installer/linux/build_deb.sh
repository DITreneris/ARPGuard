#!/bin/bash
# Build script for ARP Guard Debian package

set -e

# Configuration
VERSION="0.3.0"
PACKAGE_NAME="arpguard"
ARCHITECTURE="amd64"
MAINTAINER="ARPGuard Security <support@arpguard.com>"
DESCRIPTION="ARP Guard Network Security Tool"
BUILD_DIR="./build"
PACKAGE_DIR="${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}"
SRC_DIR="../../"

# Create build directories
echo "Creating build directories..."
mkdir -p ${PACKAGE_DIR}/DEBIAN
mkdir -p ${PACKAGE_DIR}/opt/arpguard/bin
mkdir -p ${PACKAGE_DIR}/opt/arpguard/config
mkdir -p ${PACKAGE_DIR}/opt/arpguard/systemd
mkdir -p ${PACKAGE_DIR}/etc/arpguard
mkdir -p ${PACKAGE_DIR}/var/log/arpguard
mkdir -p ${PACKAGE_DIR}/var/lib/arpguard

# Copy files
echo "Copying files..."
cp deb/control ${PACKAGE_DIR}/DEBIAN/
cp deb/postinst ${PACKAGE_DIR}/DEBIAN/
cp deb/prerm ${PACKAGE_DIR}/DEBIAN/
chmod 755 ${PACKAGE_DIR}/DEBIAN/postinst
chmod 755 ${PACKAGE_DIR}/DEBIAN/prerm

# Copy application files
echo "Copying application files..."
cp -r ${SRC_DIR}/src ${PACKAGE_DIR}/opt/arpguard/
cp -r ${SRC_DIR}/app ${PACKAGE_DIR}/opt/arpguard/
cp -r ${SRC_DIR}/scripts ${PACKAGE_DIR}/opt/arpguard/
cp -r ${SRC_DIR}/config ${PACKAGE_DIR}/opt/arpguard/
cp ${SRC_DIR}/requirements.txt ${PACKAGE_DIR}/opt/arpguard/
cp deb/arpguard.service ${PACKAGE_DIR}/opt/arpguard/systemd/

# Create main executable script
echo "Creating executable..."
cat > ${PACKAGE_DIR}/opt/arpguard/bin/arpguard << 'EOF'
#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
INSTALL_DIR="$(dirname "$SCRIPT_DIR")"
python3 $INSTALL_DIR/src/main.py "$@"
EOF
chmod 755 ${PACKAGE_DIR}/opt/arpguard/bin/arpguard

# Create a default configuration file
echo "Creating default configuration..."
cat > ${PACKAGE_DIR}/opt/arpguard/config/config.yaml << 'EOF'
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

# Set permissions
echo "Setting permissions..."
find ${PACKAGE_DIR} -type d -exec chmod 755 {} \;
find ${PACKAGE_DIR} -type f -exec chmod 644 {} \;
chmod 755 ${PACKAGE_DIR}/opt/arpguard/bin/arpguard
chmod 755 ${PACKAGE_DIR}/DEBIAN/postinst
chmod 755 ${PACKAGE_DIR}/DEBIAN/prerm

# Build the package
echo "Building Debian package..."
dpkg-deb --build ${PACKAGE_DIR}

# Clean up
echo "Cleaning up..."
# mv ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}.deb ./
echo "Package built: ${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}.deb"

echo "Build complete!" 