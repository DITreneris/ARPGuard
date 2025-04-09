#!/bin/bash

# ARPGuard Backup Demo Environment - Connectivity Test Script
# This script tests connectivity between all devices in the backup demo environment

# Set up color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration variables
PRIMARY_NETWORK_IPS=(
    "192.168.88.1"  # Gateway
    "192.168.88.10" # Demo Laptop
    "192.168.88.20" # Raspberry Pi (Client)
    "192.168.88.30" # VM Target
    "192.168.88.40" # Secondary Laptop (Attacker)
)

FALLBACK_NETWORK_IPS=(
    "10.10.10.1"  # Gateway
    "10.10.10.10" # Demo Laptop
    "10.10.10.20" # Raspberry Pi (Client)
    "10.10.10.30" # VM Target
    "10.10.10.40" # Secondary Laptop (Attacker)
)

PRIMARY_DEVICE_NAMES=(
    "Gateway"
    "Demo Laptop"
    "Client Device"
    "Target Device"
    "Attacker Device"
)

# Function to get current network configuration
get_current_network() {
    # Get IP address of the main interface
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        INTERFACE=$(ip route | grep default | awk '{print $5}')
        IP=$(ip addr show $INTERFACE | grep "inet " | awk '{print $2}' | cut -d/ -f1)
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        INTERFACE=$(route -n get default | grep interface | awk '{print $2}')
        IP=$(ifconfig $INTERFACE | grep "inet " | awk '{print $2}')
    elif [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "win32" ]]; then
        # Windows with Git Bash
        IP=$(ipconfig | grep -A 5 "Ethernet adapter" | grep "IPv4 Address" | head -n 1 | awk '{print $NF}')
    else
        echo -e "${RED}Unknown operating system${NC}"
        exit 1
    fi

    # Determine which network we're on
    if [[ $IP == 192.168.88.* ]]; then
        echo "primary"
    elif [[ $IP == 10.10.10.* ]]; then
        echo "fallback"
    else
        echo "unknown"
    fi
}

# Function to ping a host and return result
ping_host() {
    local ip=$1
    local ping_count=3
    local timeout=1
    
    if [[ "$OSTYPE" == "linux-gnu"* || "$OSTYPE" == "darwin"* ]]; then
        ping -c $ping_count -W $timeout $ip > /dev/null 2>&1
        return $?
    elif [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "win32" ]]; then
        ping -n $ping_count -w $(($timeout * 1000)) $ip > /dev/null 2>&1
        return $?
    else
        echo -e "${RED}Unknown operating system${NC}"
        return 1
    fi
}

# Function to test connectivity to all devices
test_connectivity() {
    local network=$1
    local ips
    local device_names=("${PRIMARY_DEVICE_NAMES[@]}")
    
    if [[ "$network" == "primary" ]]; then
        ips=("${PRIMARY_NETWORK_IPS[@]}")
        echo -e "${YELLOW}Testing connectivity on primary network (192.168.88.0/24)${NC}"
    elif [[ "$network" == "fallback" ]]; then
        ips=("${FALLBACK_NETWORK_IPS[@]}")
        echo -e "${YELLOW}Testing connectivity on fallback network (10.10.10.0/24)${NC}"
    else
        echo -e "${RED}Unknown network: $network${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}Device Connectivity Test:${NC}"
    echo "----------------------------------------"
    
    # Test connectivity to all devices
    local all_success=true
    for i in "${!ips[@]}"; do
        ip=${ips[$i]}
        name=${device_names[$i]}
        
        echo -n "Testing connection to $name ($ip): "
        if ping_host "$ip"; then
            echo -e "${GREEN}Success${NC}"
        else
            echo -e "${RED}Failed${NC}"
            all_success=false
        fi
    done
    
    echo "----------------------------------------"
    if $all_success; then
        echo -e "${GREEN}All devices are reachable!${NC}"
        return 0
    else
        echo -e "${RED}Some devices are not reachable.${NC}"
        return 1
    fi
}

# Function to measure network latency
measure_latency() {
    local network=$1
    local ips
    local device_names=("${PRIMARY_DEVICE_NAMES[@]}")
    
    if [[ "$network" == "primary" ]]; then
        ips=("${PRIMARY_NETWORK_IPS[@]}")
        echo -e "${YELLOW}Measuring latency on primary network (192.168.88.0/24)${NC}"
    elif [[ "$network" == "fallback" ]]; then
        ips=("${FALLBACK_NETWORK_IPS[@]}")
        echo -e "${YELLOW}Measuring latency on fallback network (10.10.10.0/24)${NC}"
    else
        echo -e "${RED}Unknown network: $network${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}Network Latency Test:${NC}"
    echo "----------------------------------------"
    
    # Skip the first IP (gateway) if it's not reachable
    start_idx=0
    if ! ping_host "${ips[0]}"; then
        start_idx=1
    fi
    
    # Measure latency to all devices
    for i in $(seq $start_idx $((${#ips[@]} - 1))); do
        ip=${ips[$i]}
        name=${device_names[$i]}
        
        echo -n "Measuring latency to $name ($ip): "
        if [[ "$OSTYPE" == "linux-gnu"* || "$OSTYPE" == "darwin"* ]]; then
            latency=$(ping -c 5 -q $ip 2>/dev/null | grep -oP 'avg.*? \K[0-9\.]+' || echo "N/A")
        elif [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "win32" ]]; then
            latency=$(ping -n 5 $ip | grep Average | awk '{print $13}' | tr -d 'ms' || echo "N/A")
        else
            latency="N/A"
        fi
        
        if [[ "$latency" != "N/A" ]]; then
            echo -e "${GREEN}$latency ms${NC}"
        else
            echo -e "${RED}Failed${NC}"
        fi
    done
    
    echo "----------------------------------------"
}

# Function to test network throughput
test_throughput() {
    local network=$1
    local ips
    local device_names=("${PRIMARY_DEVICE_NAMES[@]}")
    
    if [[ "$network" == "primary" ]]; then
        ips=("${PRIMARY_NETWORK_IPS[@]}")
        echo -e "${YELLOW}Testing throughput on primary network (192.168.88.0/24)${NC}"
    elif [[ "$network" == "fallback" ]]; then
        ips=("${FALLBACK_NETWORK_IPS[@]}")
        echo -e "${YELLOW}Testing throughput on fallback network (10.10.10.0/24)${NC}"
    else
        echo -e "${RED}Unknown network: $network${NC}"
        return 1
    fi
    
    # Check if iperf3 is installed
    if ! command -v iperf3 &> /dev/null; then
        echo -e "${RED}iperf3 is not installed. Skipping throughput test.${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}Network Throughput Test:${NC}"
    echo "----------------------------------------"
    echo -e "${YELLOW}Note: This test requires iperf3 server running on target devices${NC}"
    echo "----------------------------------------"
    
    # Skip the first IP (gateway) and demo laptop
    for i in $(seq 2 $((${#ips[@]} - 1))); do
        ip=${ips[$i]}
        name=${device_names[$i]}
        
        echo -n "Testing throughput to $name ($ip): "
        iperf3 -c $ip -t 2 -J 2>/dev/null | grep -o '"bits_per_second":[0-9.]*' | head -n 1 | awk -F: '{printf "%.2f Mbps\n", $2/1000000}' || echo -e "${RED}Failed${NC}"
    done
    
    echo "----------------------------------------"
}

# Main function
main() {
    # Determine which network we're on
    current_network=$(get_current_network)
    
    if [[ "$current_network" == "unknown" ]]; then
        echo -e "${RED}Not on a known demo network.${NC}"
        echo -e "${YELLOW}Please run ./configure_network.sh first.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Current network: $current_network${NC}"
    
    # Test connectivity
    test_connectivity "$current_network"
    connectivity_result=$?
    
    # Measure latency if connectivity test passed
    if [[ $connectivity_result -eq 0 ]]; then
        measure_latency "$current_network"
        
        # Test throughput if requested
        if [[ "$1" == "--throughput" ]]; then
            test_throughput "$current_network"
        fi
    fi
    
    # Overall result
    if [[ $connectivity_result -eq 0 ]]; then
        echo -e "${GREEN}Connectivity test passed! The demo environment is ready.${NC}"
        exit 0
    else
        echo -e "${RED}Connectivity test failed. Please check the network configuration.${NC}"
        echo -e "${YELLOW}Suggestions:${NC}"
        echo "1. Ensure all devices are powered on and connected"
        echo "2. Check IP addresses on all devices"
        echo "3. Try the fallback network configuration"
        echo "   ./configure_network.sh fallback"
        exit 1
    fi
}

# Parse command line arguments
if [[ $# -gt 1 ]]; then
    echo "Usage: $0 [--throughput]"
    exit 1
fi

# Call the main function
main "$1" 