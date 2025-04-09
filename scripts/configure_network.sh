#!/bin/bash

# ARPGuard Backup Demo Environment - Network Configuration Script
# This script configures the network interfaces for the backup demo environment

set -e  # Exit on error

# Configuration variables
PRIMARY_NETWORK="192.168.88.0/24"
PRIMARY_IP="192.168.88.10"
PRIMARY_GATEWAY="192.168.88.1"

FALLBACK_NETWORK="10.10.10.0/24"
FALLBACK_IP="10.10.10.10"
FALLBACK_GATEWAY="10.10.10.1"

# Determine the active network interface
get_active_interface() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        ip route | grep default | awk '{print $5}'
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        route -n get default | grep interface | awk '{print $2}'
    elif [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "win32" ]]; then
        # Windows with Git Bash
        netsh interface show interface | grep Connected | head -n 1 | awk '{print $4}'
    else
        echo "Unknown operating system"
        exit 1
    fi
}

# Configure the network for Linux
configure_linux_network() {
    local interface=$1
    local ip=$2
    local network=${3%/*}  # Remove CIDR notation
    local netmask
    
    # Convert CIDR to netmask
    if [[ ${3#*/} == "24" ]]; then
        netmask="255.255.255.0"
    else
        netmask="255.255.255.0"  # Default to /24
    fi
    
    echo "Configuring $interface with IP $ip, netmask $netmask"
    sudo ip addr flush dev "$interface"
    sudo ip addr add "$ip/24" dev "$interface"
    sudo ip link set dev "$interface" up
    
    echo "Network configuration complete"
}

# Configure the network for macOS
configure_macos_network() {
    local interface=$1
    local ip=$2
    local network=${3%/*}  # Remove CIDR notation
    local netmask
    
    # Convert CIDR to netmask
    if [[ ${3#*/} == "24" ]]; then
        netmask="255.255.255.0"
    else
        netmask="255.255.255.0"  # Default to /24
    fi
    
    echo "Configuring $interface with IP $ip, netmask $netmask"
    sudo ifconfig "$interface" "$ip" netmask "$netmask"
    
    echo "Network configuration complete"
}

# Configure the network for Windows
configure_windows_network() {
    local interface=$1
    local ip=$2
    local network=${3%/*}  # Remove CIDR notation
    local netmask
    
    # Convert CIDR to netmask
    if [[ ${3#*/} == "24" ]]; then
        netmask="255.255.255.0"
    else
        netmask="255.255.255.0"  # Default to /24
    fi
    
    echo "Configuring $interface with IP $ip, netmask $netmask"
    
    # For Windows, use netsh
    local interface_name=$(netsh interface show interface name="$interface" | grep "$interface")
    if [[ -z "$interface_name" ]]; then
        echo "Interface $interface not found"
        # List available interfaces
        netsh interface show interface
        exit 1
    fi
    
    netsh interface ip set address name="$interface" static "$ip" "$netmask" none
    
    echo "Network configuration complete"
}

# Main function to configure the network
configure_network() {
    local config=$1
    local interface=$(get_active_interface)
    
    if [[ -z "$interface" ]]; then
        echo "Could not determine active network interface"
        exit 1
    fi
    
    echo "Active interface: $interface"
    
    if [[ "$config" == "primary" ]]; then
        echo "Configuring primary network: $PRIMARY_NETWORK"
        
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            configure_linux_network "$interface" "$PRIMARY_IP" "$PRIMARY_NETWORK"
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            configure_macos_network "$interface" "$PRIMARY_IP" "$PRIMARY_NETWORK"
        elif [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "win32" ]]; then
            configure_windows_network "$interface" "$PRIMARY_IP" "$PRIMARY_NETWORK"
        else
            echo "Unsupported operating system"
            exit 1
        fi
        
        echo "Primary network configuration complete"
        
    elif [[ "$config" == "fallback" ]]; then
        echo "Configuring fallback network: $FALLBACK_NETWORK"
        
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            configure_linux_network "$interface" "$FALLBACK_IP" "$FALLBACK_NETWORK"
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            configure_macos_network "$interface" "$FALLBACK_IP" "$FALLBACK_NETWORK"
        elif [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "win32" ]]; then
            configure_windows_network "$interface" "$FALLBACK_IP" "$FALLBACK_NETWORK"
        else
            echo "Unsupported operating system"
            exit 1
        fi
        
        echo "Fallback network configuration complete"
        
    else
        echo "Invalid configuration: $config"
        echo "Usage: $0 [primary|fallback]"
        exit 1
    fi
}

# Script entry point
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 [primary|fallback]"
    exit 1
fi

# Call the main function
configure_network "$1"

# Wait for the network to stabilize
echo "Waiting for network to stabilize..."
sleep 5

# Test connectivity
echo "Testing connectivity..."
if [[ "$1" == "primary" ]]; then
    ping -c 3 192.168.88.1 || echo "Warning: Cannot ping gateway"
    echo "Network configuration successful. Testing connectivity to devices next."
    
    # Try to ping the other devices
    echo "Pinging client device (192.168.88.20)..."
    ping -c 1 192.168.88.20 > /dev/null 2>&1 && echo "Success" || echo "Failed"
    
    echo "Pinging target device (192.168.88.30)..."
    ping -c 1 192.168.88.30 > /dev/null 2>&1 && echo "Success" || echo "Failed"
    
    echo "Pinging attacker device (192.168.88.40)..."
    ping -c 1 192.168.88.40 > /dev/null 2>&1 && echo "Success" || echo "Failed"
    
else
    ping -c 3 10.10.10.1 || echo "Warning: Cannot ping gateway"
    echo "Network configuration successful. Testing connectivity to devices next."
    
    # Try to ping the other devices
    echo "Pinging client device (10.10.10.20)..."
    ping -c 1 10.10.10.20 > /dev/null 2>&1 && echo "Success" || echo "Failed"
    
    echo "Pinging target device (10.10.10.30)..."
    ping -c 1 10.10.10.30 > /dev/null 2>&1 && echo "Success" || echo "Failed"
    
    echo "Pinging attacker device (10.10.10.40)..."
    ping -c 1 10.10.10.40 > /dev/null 2>&1 && echo "Success" || echo "Failed"
fi

echo "Configuration complete" 