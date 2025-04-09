#!/bin/bash

# ARPGuard Backup Demo Environment - VM Status Check Script
# This script checks the status of VirtualBox VMs used in the backup demo environment

# Set up color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REQUIRED_VMS=("Ubuntu_Target" "Kali_Attacker")
VM_DESCRIPTIONS=(
    "Ubuntu 22.04 LTS VM (target system)"
    "Kali Linux VM (attacker system)"
)

# Check if VirtualBox is installed
check_virtualbox() {
    if ! command -v VBoxManage &> /dev/null; then
        echo -e "${RED}Error: VirtualBox is not installed or not in PATH${NC}"
        echo "Please install VirtualBox and ensure VBoxManage is available in your PATH"
        return 1
    fi
    
    echo -e "${GREEN}VirtualBox is installed${NC}"
    VBoxManage --version
    return 0
}

# List all available VMs
list_all_vms() {
    echo -e "${BLUE}Available Virtual Machines:${NC}"
    echo "----------------------------------------"
    
    # Get a list of all VMs
    vms=$(VBoxManage list vms)
    
    if [[ -z "$vms" ]]; then
        echo -e "${YELLOW}No VMs found${NC}"
        return 1
    fi
    
    echo "$vms"
    echo "----------------------------------------"
    return 0
}

# Check if required VMs exist
check_required_vms() {
    echo -e "${BLUE}Checking Required VMs:${NC}"
    echo "----------------------------------------"
    
    all_exist=true
    for i in "${!REQUIRED_VMS[@]}"; do
        vm="${REQUIRED_VMS[$i]}"
        description="${VM_DESCRIPTIONS[$i]}"
        
        echo -n "Checking for $vm ($description): "
        if VBoxManage showvminfo "$vm" &> /dev/null; then
            echo -e "${GREEN}Found${NC}"
        else
            echo -e "${RED}Not found${NC}"
            all_exist=false
        fi
    done
    
    echo "----------------------------------------"
    
    if $all_exist; then
        echo -e "${GREEN}All required VMs exist${NC}"
        return 0
    else
        echo -e "${RED}Some required VMs are missing${NC}"
        return 1
    fi
}

# Check VM statuses
check_vm_statuses() {
    echo -e "${BLUE}VM Status Check:${NC}"
    echo "----------------------------------------"
    
    for i in "${!REQUIRED_VMS[@]}"; do
        vm="${REQUIRED_VMS[$i]}"
        description="${VM_DESCRIPTIONS[$i]}"
        
        # Skip if VM doesn't exist
        if ! VBoxManage showvminfo "$vm" &> /dev/null; then
            echo -e "$vm: ${RED}Not found${NC}"
            continue
        fi
        
        # Check if VM is running
        status=$(VBoxManage showvminfo "$vm" --machinereadable | grep "VMState=" | cut -d '"' -f 2)
        
        echo -n "$vm: "
        case "$status" in
            running)
                echo -e "${GREEN}Running${NC}"
                ;;
            poweroff|aborted|saved)
                echo -e "${YELLOW}Stopped ($status)${NC}"
                ;;
            *)
                echo -e "${RED}Unknown state: $status${NC}"
                ;;
        esac
    done
    
    echo "----------------------------------------"
}

# Check VM network configurations
check_vm_network() {
    echo -e "${BLUE}VM Network Configuration:${NC}"
    echo "----------------------------------------"
    
    for i in "${!REQUIRED_VMS[@]}"; do
        vm="${REQUIRED_VMS[$i]}"
        
        # Skip if VM doesn't exist
        if ! VBoxManage showvminfo "$vm" &> /dev/null; then
            echo -e "$vm: ${RED}Not found${NC}"
            continue
        fi
        
        echo -e "${YELLOW}$vm Network Configuration:${NC}"
        
        # Extract network adapter information
        adapter_info=$(VBoxManage showvminfo "$vm" | grep -A 10 "NIC 1:")
        
        # Check if adapter is in bridge mode
        if echo "$adapter_info" | grep -q "Bridged"; then
            echo -e "Network Mode: ${GREEN}Bridged${NC}"
            bridge_adapter=$(echo "$adapter_info" | grep "bridged interface" | cut -d "'" -f 2)
            echo "Bridged to: $bridge_adapter"
        elif echo "$adapter_info" | grep -q "NAT"; then
            echo -e "Network Mode: ${YELLOW}NAT${NC} (Should be Bridged for demo)"
        elif echo "$adapter_info" | grep -q "Host-only"; then
            echo -e "Network Mode: ${YELLOW}Host-only${NC} (Should be Bridged for demo)"
        else
            echo -e "Network Mode: ${RED}Unknown${NC}"
        fi
        
        # Check if adapter is enabled
        if echo "$adapter_info" | grep -q "disabled"; then
            echo -e "Adapter Status: ${RED}Disabled${NC}"
        else
            echo -e "Adapter Status: ${GREEN}Enabled${NC}"
        fi
        
        echo "----------------------------------------"
    done
}

# Start a VM
start_vm() {
    local vm=$1
    
    # Check if VM exists
    if ! VBoxManage showvminfo "$vm" &> /dev/null; then
        echo -e "${RED}VM '$vm' does not exist${NC}"
        return 1
    fi
    
    # Check if VM is already running
    status=$(VBoxManage showvminfo "$vm" --machinereadable | grep "VMState=" | cut -d '"' -f 2)
    if [[ "$status" == "running" ]]; then
        echo -e "${YELLOW}VM '$vm' is already running${NC}"
        return 0
    fi
    
    # Start the VM
    echo -e "${YELLOW}Starting VM '$vm'...${NC}"
    VBoxManage startvm "$vm" --type headless
    
    # Check if VM started successfully
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}VM '$vm' started successfully${NC}"
        return 0
    else
        echo -e "${RED}Failed to start VM '$vm'${NC}"
        return 1
    fi
}

# Stop a VM
stop_vm() {
    local vm=$1
    
    # Check if VM exists
    if ! VBoxManage showvminfo "$vm" &> /dev/null; then
        echo -e "${RED}VM '$vm' does not exist${NC}"
        return 1
    fi
    
    # Check if VM is running
    status=$(VBoxManage showvminfo "$vm" --machinereadable | grep "VMState=" | cut -d '"' -f 2)
    if [[ "$status" != "running" ]]; then
        echo -e "${YELLOW}VM '$vm' is not running${NC}"
        return 0
    fi
    
    # Stop the VM
    echo -e "${YELLOW}Stopping VM '$vm'...${NC}"
    VBoxManage controlvm "$vm" acpipowerbutton
    
    # Wait for VM to stop
    echo -e "${YELLOW}Waiting for VM to shut down...${NC}"
    for i in {1..30}; do
        sleep 1
        status=$(VBoxManage showvminfo "$vm" --machinereadable | grep "VMState=" | cut -d '"' -f 2)
        if [[ "$status" != "running" ]]; then
            echo -e "${GREEN}VM '$vm' stopped successfully${NC}"
            return 0
        fi
    done
    
    echo -e "${RED}VM '$vm' did not shut down gracefully, forcing power off${NC}"
    VBoxManage controlvm "$vm" poweroff
    return 1
}

# Modify VM network settings
configure_vm_network() {
    local vm=$1
    local mode=$2
    local interface=$3
    
    # Check if VM exists
    if ! VBoxManage showvminfo "$vm" &> /dev/null; then
        echo -e "${RED}VM '$vm' does not exist${NC}"
        return 1
    fi
    
    # Check if VM is running
    status=$(VBoxManage showvminfo "$vm" --machinereadable | grep "VMState=" | cut -d '"' -f 2)
    if [[ "$status" == "running" ]]; then
        echo -e "${RED}VM '$vm' is running. Please stop it first${NC}"
        return 1
    fi
    
    # Configure network
    if [[ "$mode" == "bridged" ]]; then
        echo -e "${YELLOW}Setting '$vm' to bridged mode on interface '$interface'...${NC}"
        VBoxManage modifyvm "$vm" --nic1 bridged --bridgeadapter1 "$interface"
    elif [[ "$mode" == "nat" ]]; then
        echo -e "${YELLOW}Setting '$vm' to NAT mode...${NC}"
        VBoxManage modifyvm "$vm" --nic1 nat
    elif [[ "$mode" == "hostonly" ]]; then
        echo -e "${YELLOW}Setting '$vm' to host-only mode...${NC}"
        VBoxManage modifyvm "$vm" --nic1 hostonly --hostonlyadapter1 "VirtualBox Host-Only Ethernet Adapter"
    else
        echo -e "${RED}Unknown network mode: $mode${NC}"
        return 1
    fi
    
    # Check if command was successful
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}Network settings updated for VM '$vm'${NC}"
        return 0
    else
        echo -e "${RED}Failed to update network settings for VM '$vm'${NC}"
        return 1
    fi
}

# Show usage information
show_usage() {
    echo "Usage: $0 [OPTION]"
    echo "Check and manage the status of VirtualBox VMs for the ARPGuard demo environment"
    echo ""
    echo "Options:"
    echo "  --status           Show status of all required VMs"
    echo "  --network          Check network configuration of all VMs"
    echo "  --start VM_NAME    Start a specific VM"
    echo "  --stop VM_NAME     Stop a specific VM"
    echo "  --configure-net VM_NAME MODE [INTERFACE]   Configure VM network"
    echo "                     MODE can be: bridged, nat, hostonly"
    echo "                     INTERFACE is required for bridged mode"
    echo "  --start-all        Start all required VMs"
    echo "  --stop-all         Stop all required VMs"
    echo "  --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --status"
    echo "  $0 --start Ubuntu_Target"
    echo "  $0 --configure-net Kali_Attacker bridged eth0"
    echo "  $0 --start-all"
}

# Main function
main() {
    if [[ $# -eq 0 ]]; then
        # No arguments, show full status
        check_virtualbox || exit 1
        list_all_vms
        check_required_vms
        check_vm_statuses
        check_vm_network
        exit 0
    fi
    
    # Parse arguments
    case "$1" in
        --status)
            check_virtualbox || exit 1
            check_vm_statuses
            ;;
        --network)
            check_virtualbox || exit 1
            check_vm_network
            ;;
        --start)
            if [[ -z "$2" ]]; then
                echo -e "${RED}Error: VM name required${NC}"
                show_usage
                exit 1
            fi
            check_virtualbox || exit 1
            start_vm "$2"
            ;;
        --stop)
            if [[ -z "$2" ]]; then
                echo -e "${RED}Error: VM name required${NC}"
                show_usage
                exit 1
            fi
            check_virtualbox || exit 1
            stop_vm "$2"
            ;;
        --configure-net)
            if [[ -z "$2" || -z "$3" ]]; then
                echo -e "${RED}Error: VM name and mode required${NC}"
                show_usage
                exit 1
            fi
            
            if [[ "$3" == "bridged" && -z "$4" ]]; then
                echo -e "${RED}Error: Interface name required for bridged mode${NC}"
                show_usage
                exit 1
            fi
            
            check_virtualbox || exit 1
            configure_vm_network "$2" "$3" "$4"
            ;;
        --start-all)
            check_virtualbox || exit 1
            echo -e "${YELLOW}Starting all required VMs...${NC}"
            for vm in "${REQUIRED_VMS[@]}"; do
                start_vm "$vm"
            done
            ;;
        --stop-all)
            check_virtualbox || exit 1
            echo -e "${YELLOW}Stopping all required VMs...${NC}"
            for vm in "${REQUIRED_VMS[@]}"; do
                stop_vm "$vm"
            done
            ;;
        --help)
            show_usage
            ;;
        *)
            echo -e "${RED}Error: Unknown option '$1'${NC}"
            show_usage
            exit 1
            ;;
    esac
}

# Call the main function with all arguments
main "$@" 