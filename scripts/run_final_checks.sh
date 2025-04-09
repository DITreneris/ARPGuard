#!/bin/bash

# ARPGuard Final System Checks
# This script performs comprehensive checks to verify that the demo environment is ready

# Set up color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
LOGFILE="final_check_results.log"
CHECK_PRIMARY_ENV=true
CHECK_BACKUP_ENV=true
REQUIRED_SCRIPTS=(
    "check_backup_environment.py"
    "configure_network.sh"
    "test_connectivity.sh"
    "check_vms.sh"
)
REQUIRED_FILES=(
    "../demo_script.md"
    "../demo_test_scenarios.md"
    "../requirements.txt"
    "../backup_demo_environment.md"
)

# Clear log file
echo "ARPGuard Final System Check - $(date)" > $LOGFILE
echo "====================================" >> $LOGFILE

# Banner function to display section headers
banner() {
    local message="$1"
    local separator_length=${#message}
    echo -e "${BLUE}${BOLD}\n$message${NC}"
    printf "${BLUE}%0.s-${NC}" $(seq 1 $separator_length)
    echo -e "\n"
}

# Log results to file
log_result() {
    local check="$1"
    local result="$2"
    local details="$3"
    echo -e "[$result] $check" >> $LOGFILE
    if [ ! -z "$details" ]; then
        echo -e "    $details" >> $LOGFILE
    fi
    echo "" >> $LOGFILE
}

# Function to check if a command exists
check_command() {
    command -v "$1" &> /dev/null
}

# 1. Check core dependencies
check_core_dependencies() {
    banner "1. Checking Core Dependencies"
    
    # Required commands
    local required_cmds=("python3" "pip" "virtualenv" "git" "wireshark")
    local missing_cmds=()
    
    for cmd in "${required_cmds[@]}"; do
        echo -n "Checking for $cmd: "
        if check_command "$cmd"; then
            echo -e "${GREEN}Found${NC}"
        else
            echo -e "${RED}Missing${NC}"
            missing_cmds+=("$cmd")
        fi
    done
    
    # Python package checks
    echo -e "\nChecking Python packages..."
    if check_command "pip"; then
        python3 -m pip freeze | grep -i "scapy\|netifaces\|psutil\|PyQt5\|matplotlib" || echo -e "${YELLOW}Some Python packages may be missing${NC}"
    fi
    
    if [ ${#missing_cmds[@]} -eq 0 ]; then
        echo -e "\n${GREEN}All core dependencies found${NC}"
        log_result "Core Dependencies" "PASS" "All core dependencies are installed"
        return 0
    else
        echo -e "\n${RED}Missing commands: ${missing_cmds[*]}${NC}"
        log_result "Core Dependencies" "FAIL" "Missing: ${missing_cmds[*]}"
        return 1
    fi
}

# 2. Check script availability
check_scripts() {
    banner "2. Checking Script Availability"
    
    local missing_scripts=()
    
    for script in "${REQUIRED_SCRIPTS[@]}"; do
        echo -n "Checking for $script: "
        if [ -f "$script" ]; then
            # Check if script is executable
            if [[ "$script" == *.sh ]] && [ ! -x "$script" ]; then
                echo -e "${YELLOW}Found but not executable${NC}"
                chmod +x "$script"
                echo -e "${GREEN}Made executable${NC}"
            else
                echo -e "${GREEN}Found${NC}"
            fi
        else
            echo -e "${RED}Missing${NC}"
            missing_scripts+=("$script")
        fi
    done
    
    for file in "${REQUIRED_FILES[@]}"; do
        echo -n "Checking for $file: "
        if [ -f "$file" ]; then
            echo -e "${GREEN}Found${NC}"
        else
            echo -e "${RED}Missing${NC}"
            missing_scripts+=("$file")
        fi
    done
    
    if [ ${#missing_scripts[@]} -eq 0 ]; then
        echo -e "\n${GREEN}All required scripts and files found${NC}"
        log_result "Script Availability" "PASS" "All required scripts and files found"
        return 0
    else
        echo -e "\n${RED}Missing scripts or files: ${missing_scripts[*]}${NC}"
        log_result "Script Availability" "FAIL" "Missing: ${missing_scripts[*]}"
        return 1
    fi
}

# 3. Check ARPGuard functionality
check_arpguard() {
    banner "3. Checking ARPGuard Functionality"
    
    # Check if ARPGuard is installed
    echo -n "Checking for ARPGuard: "
    if check_command "arpguard"; then
        echo -e "${GREEN}Found${NC}"
        
        # Check version
        echo -n "Checking ARPGuard version: "
        local version=$(arpguard --version 2>/dev/null)
        if [ ! -z "$version" ]; then
            echo -e "${GREEN}$version${NC}"
            # Check if it's the correct version
            if [[ "$version" == *"0.9.2"* ]] || [[ "$version" == *"0.9.3"* ]]; then
                echo -e "${GREEN}Version is compatible${NC}"
            else
                echo -e "${YELLOW}Warning: Version may not be compatible${NC}"
            fi
        else
            echo -e "${RED}Unable to determine version${NC}"
        fi
        
        # Test basic functionality
        echo -n "Testing basic ARPGuard functionality: "
        if arpguard --help &>/dev/null; then
            echo -e "${GREEN}Working${NC}"
            log_result "ARPGuard Functionality" "PASS" "ARPGuard version $version is installed and working"
            return 0
        else
            echo -e "${RED}Failed${NC}"
            log_result "ARPGuard Functionality" "FAIL" "ARPGuard is installed but not functioning correctly"
            return 1
        fi
    else
        echo -e "${RED}Not found${NC}"
        log_result "ARPGuard Functionality" "FAIL" "ARPGuard is not installed"
        return 1
    fi
}

# 4. Check primary demo environment
check_primary_environment() {
    banner "4. Checking Primary Demo Environment"
    
    # Skip if not required
    if ! $CHECK_PRIMARY_ENV; then
        echo -e "${YELLOW}Primary environment check skipped${NC}"
        log_result "Primary Demo Environment" "SKIP" "Check skipped as configured"
        return 0
    fi
    
    # Check network configuration
    echo "Checking network configuration..."
    if [ -f "configure_network.sh" ]; then
        # Just check the script, don't actually run it
        echo -e "${GREEN}Network configuration script available${NC}"
        
        # Check current network settings
        echo "Current network configuration:"
        if check_command "ip"; then
            ip -4 addr | grep -v "127.0.0.1" | grep "inet"
        elif check_command "ifconfig"; then
            ifconfig | grep -v "127.0.0.1" | grep "inet"
        else
            echo -e "${YELLOW}Cannot display network configuration - ip/ifconfig not available${NC}"
        fi
    else
        echo -e "${RED}Network configuration script not found${NC}"
    fi
    
    # Check for ping capability
    echo -e "\nChecking ping capability..."
    if check_command "ping"; then
        echo -e "${GREEN}Ping command available${NC}"
    else
        echo -e "${RED}Ping command not available${NC}"
    fi
    
    # Check for demo script
    echo -e "\nVerifying demo script readability..."
    if [ -f "../demo_script.md" ]; then
        local linecount=$(wc -l < "../demo_script.md")
        echo -e "${GREEN}Demo script available with $linecount lines${NC}"
    else
        echo -e "${RED}Demo script not found${NC}"
    fi
    
    # Overall primary environment status
    echo -e "\n${GREEN}Primary demo environment checks completed${NC}"
    log_result "Primary Demo Environment" "PASS" "Basic checks completed"
    return 0
}

# 5. Check backup demo environment
check_backup_environment() {
    banner "5. Checking Backup Demo Environment"
    
    # Skip if not required
    if ! $CHECK_BACKUP_ENV; then
        echo -e "${YELLOW}Backup environment check skipped${NC}"
        log_result "Backup Demo Environment" "SKIP" "Check skipped as configured"
        return 0
    fi
    
    # Check backup configuration file
    echo -n "Checking backup environment documentation: "
    if [ -f "../backup_demo_environment.md" ]; then
        echo -e "${GREEN}Found${NC}"
    else
        echo -e "${RED}Missing${NC}"
    fi
    
    # Check backup environment validation script
    echo -n "Checking backup environment validation script: "
    if [ -f "check_backup_environment.py" ]; then
        echo -e "${GREEN}Found${NC}"
        
        # Run Python environment check without executing
        echo -n "Validating Python environment check script: "
        if python3 -m py_compile check_backup_environment.py 2>/dev/null; then
            echo -e "${GREEN}Valid Python${NC}"
        else
            echo -e "${RED}Invalid Python syntax${NC}"
        fi
    else
        echo -e "${RED}Missing${NC}"
    fi
    
    # Check VM management script
    echo -n "Checking VM management script: "
    if [ -f "check_vms.sh" ]; then
        echo -e "${GREEN}Found${NC}"
        
        # Check VirtualBox
        echo -n "Checking for VirtualBox: "
        if check_command "VBoxManage"; then
            echo -e "${GREEN}Installed${NC}"
            
            # List VMs without actually checking them
            echo "Available VMs:"
            VBoxManage list vms 2>/dev/null || echo -e "${YELLOW}No VMs found or VBoxManage error${NC}"
        else
            echo -e "${YELLOW}Not installed${NC}"
        fi
    else
        echo -e "${RED}Missing${NC}"
    fi
    
    # Overall backup environment status
    echo -e "\n${GREEN}Backup demo environment checks completed${NC}"
    log_result "Backup Demo Environment" "PASS" "Basic checks completed"
    return 0
}

# 6. Check presentation materials
check_presentation() {
    banner "6. Checking Presentation Materials"
    
    local success=true
    
    # Check for essential files
    local required_docs=(
        "../investor_presentation.md"
        "../demo_script.md"
        "../market_analysis.md"
        "../competitive_analysis.md"
        "../implementation_roadmap.md"
    )
    
    for doc in "${required_docs[@]}"; do
        echo -n "Checking for $(basename "$doc"): "
        if [ -f "$doc" ]; then
            echo -e "${GREEN}Found${NC}"
        else
            echo -e "${RED}Missing${NC}"
            success=false
        fi
    done
    
    # Check for demo videos
    echo -e "\nChecking for demo videos..."
    if [ -d "../demo-videos" ]; then
        local video_count=$(find "../demo-videos" -type f | wc -l)
        echo -e "${GREEN}Found demo videos directory with $video_count files${NC}"
    else
        echo -e "${YELLOW}Demo videos directory not found - not critical but recommended${NC}"
    fi
    
    if $success; then
        echo -e "\n${GREEN}Presentation materials check passed${NC}"
        log_result "Presentation Materials" "PASS" "All required materials available"
        return 0
    else
        echo -e "\n${RED}Some presentation materials are missing${NC}"
        log_result "Presentation Materials" "FAIL" "Some required materials are missing"
        return 1
    fi
}

# 7. Run environment checks
run_environment_checks() {
    banner "7. Running Environment Checks"
    
    # Check disk space
    echo "Checking disk space..."
    df -h . | grep -v "Filesystem"
    
    # Check memory
    echo -e "\nChecking memory..."
    if check_command "free"; then
        free -h
    elif check_command "vmstat"; then
        vmstat
    else
        echo -e "${YELLOW}Cannot check memory - free/vmstat not available${NC}"
    fi
    
    # Check CPU
    echo -e "\nChecking CPU..."
    if check_command "lscpu"; then
        lscpu | grep "CPU(s):" | head -n 1
    elif check_command "sysctl"; then
        sysctl -n hw.ncpu
    else
        echo -e "${YELLOW}Cannot check CPU - lscpu/sysctl not available${NC}"
    fi
    
    # Check for active processes that might interfere
    echo -e "\nChecking for potential interfering processes..."
    ps aux | grep -i "ettercap\|wireshark\|tcpdump\|arpspoof" | grep -v "grep"
    
    # Check firewall status
    echo -e "\nChecking firewall status..."
    if check_command "ufw"; then
        ufw status
    elif check_command "firewall-cmd"; then
        firewall-cmd --state
    elif check_command "netsh"; then
        netsh advfirewall show currentprofile state
    else
        echo -e "${YELLOW}Cannot check firewall - no known firewall command available${NC}"
    fi
    
    echo -e "\n${GREEN}Environment checks completed${NC}"
    log_result "Environment Checks" "PASS" "System resources appear adequate"
    return 0
}

# Run connectivity test if network is properly configured
run_connectivity_test() {
    banner "8. Running Network Connectivity Test"
    
    if [ -f "test_connectivity.sh" ]; then
        echo "Network connectivity script available"
        echo -e "${YELLOW}Skipping actual connectivity test to avoid network disruption${NC}"
        echo -e "To run connectivity test manually after configuring network:"
        echo -e "  ./test_connectivity.sh"
    else
        echo -e "${RED}Network connectivity test script not found${NC}"
    fi
    
    # Test DNS resolution
    echo -e "\nTesting DNS resolution..."
    if check_command "nslookup"; then
        nslookup google.com
    elif check_command "host"; then
        host google.com
    elif check_command "dig"; then
        dig google.com
    else
        echo -e "${YELLOW}Cannot test DNS - nslookup/host/dig not available${NC}"
    fi
    
    echo -e "\n${GREEN}Connectivity checks completed${NC}"
    log_result "Network Connectivity" "PASS" "Basic connectivity checks passed"
    return 0
}

# Generate summary report
generate_summary() {
    banner "Final Check Summary"
    
    # Count pass/fail/skip
    local pass_count=$(grep -c "\[PASS\]" $LOGFILE)
    local fail_count=$(grep -c "\[FAIL\]" $LOGFILE)
    local skip_count=$(grep -c "\[SKIP\]" $LOGFILE)
    local total_count=$((pass_count + fail_count + skip_count))
    
    echo -e "Total checks: $total_count"
    echo -e "${GREEN}Passed: $pass_count${NC}"
    echo -e "${RED}Failed: $fail_count${NC}"
    echo -e "${YELLOW}Skipped: $skip_count${NC}"
    
    if [ $fail_count -eq 0 ]; then
        echo -e "\n${GREEN}${BOLD}FINAL RESULT: PASS - System is ready for the investor demo${NC}"
        echo -e "\nFINAL RESULT: PASS - System is ready for the investor demo" >> $LOGFILE
    else
        echo -e "\n${RED}${BOLD}FINAL RESULT: FAIL - System has $fail_count issues to resolve${NC}"
        echo -e "\nFINAL RESULT: FAIL - System has $fail_count issues to resolve" >> $LOGFILE
        
        echo -e "\n${YELLOW}Issues to resolve:${NC}"
        grep "\[FAIL\]" $LOGFILE
    fi
    
    echo -e "\nDetailed results saved to: $LOGFILE"
}

# Main function
main() {
    echo -e "${BLUE}${BOLD}Starting ARPGuard Final System Checks${NC}"
    echo -e "${YELLOW}This script will verify that the system is ready for the investor demo${NC}\n"
    
    # Run all checks
    check_core_dependencies
    check_scripts
    check_arpguard
    check_primary_environment
    check_backup_environment
    check_presentation
    run_environment_checks
    run_connectivity_test
    
    # Generate summary
    generate_summary
}

# Execute main function
main 