# ARPGuard Test Environment Setup

This document outlines the procedures for setting up a test environment for validating ARPGuard's enterprise features before production deployment.

## Overview

A proper test environment is essential for validating ARPGuard's enterprise features and ensuring a smooth production deployment. This document provides step-by-step instructions for creating a test environment that closely mirrors the production environment while remaining isolated for safe testing.

## Hardware Requirements

| Component | Specifications | Purpose |
|-----------|---------------|---------|
| Test Server | 8+ cores, 16GB+ RAM, 256GB+ SSD | Primary ARPGuard installation |
| Secondary Server | 4+ cores, 8GB+ RAM, 128GB+ SSD | High availability testing |
| Network Switch | Managed, VLAN capable | Network infrastructure |
| Test Clients | 2-3 devices/VMs | Generating network traffic |
| Attacker System | 4+ cores, 8GB+ RAM | Simulating network attacks |

## Network Setup

### Network Topology

```
┌───────────────┐     ┌───────────────┐
│ Test Server   │     │ Secondary     │
│ (ARPGuard     │     │ Server        │
│  Primary)     │     │ (ARPGuard HA) │
└───────┬───────┘     └───────┬───────┘
        │                     │
        │                     │
┌───────┴─────────────────────┴───────┐
│           Managed Switch            │
│             (VLANs 10,20)           │
└───────┬─────────────┬───────┬───────┘
        │             │       │
┌───────┴──────┐ ┌────┴────┐  │
│ Test Client 1 │ │ Client 2│  │
│ (VLAN 10)     │ │(VLAN 20)│  │
└──────────────┘ └─────────┘  │
                              │
                       ┌──────┴──────┐
                       │ Attacker    │
                       │ System      │
                       └─────────────┘
```

### VLAN Configuration

1. Configure the managed switch with:
   - VLAN 10: Regular clients
   - VLAN 20: Management
   - VLAN 30: Storage (optional)

2. Set up port assignments:
   - Server ports: Trunk configuration (all VLANs)
   - Client ports: Access ports (specific VLAN)
   - Attacker port: Configure based on test scenario

## Software Installation

### Test Server Setup

1. Install operating system:
   ```bash
   # For Linux
   # Boot from installation media and follow prompts
   # Recommended: Ubuntu Server 22.04 LTS or RHEL 8
   
   # Post-installation update
   sudo apt update && sudo apt upgrade -y  # Ubuntu
   # or
   sudo dnf update -y  # RHEL/CentOS
   ```

2. Install dependencies:
   ```bash
   # Ubuntu
   sudo apt install -y build-essential python3-dev python3-pip \
     libpcap-dev net-tools tcpdump wireshark tshark \
     postgresql postgresql-contrib nginx supervisor

   # RHEL/CentOS
   sudo dnf install -y gcc gcc-c++ python3-devel python3-pip \
     libpcap-devel net-tools tcpdump wireshark tshark \
     postgresql postgresql-server postgresql-contrib nginx supervisor
   ```

3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Install ARPGuard in development mode:
   ```bash
   git clone https://github.com/arpguard/arpguard.git
   cd arpguard
   pip install -e .
   ```

### Secondary Server Setup (HA Configuration)

Follow the same steps as the test server, then configure as a backup node:

1. Install ARPGuard with high availability options:
   ```bash
   pip install -e ".[ha]"
   ```

2. Update the HA configuration:
   ```bash
   # Edit the HA configuration file
   cp config/ha_config.example.yaml config/ha_config.yaml
   vim config/ha_config.yaml
   ```

### Attacker System Setup

1. Install Kali Linux or ParrotOS with security tools:
   ```bash
   # Install common attack tools
   sudo apt update && sudo apt install -y \
     ettercap-graphical arpspoof dsniff \
     wireshark net-tools nmap python3-scapy
   ```

2. Install attack scripts:
   ```bash
   git clone https://github.com/test/arp-attack-tools.git
   cd arp-attack-tools
   pip install -r requirements.txt
   ```

## Configuration

### ARPGuard Configuration

1. Create base configuration:
   ```bash
   cp config.example.yaml config.yaml
   ```

2. Configure monitoring interfaces:
   ```yaml
   # Edit config.yaml
   network:
     monitor_interface: eth0  # Change to match your interface
     backup_interface: eth1   # Change to match your interface
     promiscuous_mode: true
   ```

3. Configure RBAC:
   ```yaml
   # Add to config.yaml
   rbac:
     enabled: true
     roles:
       - name: admin
         permissions: [...]
       # Additional roles
   ```

4. Configure VLAN support:
   ```yaml
   # Add to config.yaml
   vlan:
     enabled: true
     vlan_ids:
       - 10
       - 20
   ```

### Database Setup

1. Initialize the database:
   ```bash
   # PostgreSQL setup
   sudo -u postgres createuser -P arpguard
   sudo -u postgres createdb -O arpguard arpguard_db
   
   # Run database migrations
   cd arpguard
   python scripts/init_db.py
   ```

## Test Data Generation

### Network Traffic Generation

1. Install traffic generation tools:
   ```bash
   pip install traffic-generator
   ```

2. Generate background traffic:
   ```bash
   # Start traffic generator
   python scripts/generate_traffic.py --intensity medium
   ```

### Attack Simulation

1. Basic ARP spoofing:
   ```bash
   # On attacker system
   sudo arpspoof -i eth0 -t [target_ip] [gateway_ip]
   ```

2. Advanced ARP poisoning:
   ```bash
   # On attacker system, run custom script
   sudo python scripts/stealth_arp_poison.py --interface eth0 --target [target_ip]
   ```

## Monitoring Setup

### System Monitoring

1. Install monitoring tools:
   ```bash
   # Install Prometheus and Grafana
   sudo apt install -y prometheus grafana
   ```

2. Configure ARPGuard metrics:
   ```yaml
   # Add to config.yaml
   monitoring:
     prometheus_enabled: true
     prometheus_port: 9090
   ```

### Log Collection

1. Set up centralized logging:
   ```bash
   # Install ELK stack or use built-in logging
   sudo apt install -y elasticsearch logstash kibana
   ```

2. Configure log forwarding:
   ```yaml
   # Add to config.yaml
   logging:
     remote_syslog: true
     syslog_server: 192.168.20.10
   ```

## Testing Procedures

### Functional Testing

1. Basic operation:
   ```bash
   # Start ARPGuard in monitoring mode
   python -m arpguard --monitor
   ```

2. Detection testing:
   ```bash
   # Run attack from attacker system
   # Verify alerts and detection in ARPGuard
   ```

3. Prevention testing:
   ```bash
   # Start ARPGuard in protection mode
   python -m arpguard --protect
   
   # Run attack from attacker system
   # Verify attack is blocked
   ```

### Performance Testing

1. Run benchmark tests:
   ```bash
   # Run performance benchmark
   python scripts/benchmark.py --duration 600
   ```

2. Monitor system resources:
   ```bash
   # On server
   htop
   iotop
   ```

### HA Testing

1. Test failover:
   ```bash
   # Stop primary
   sudo systemctl stop arpguard
   
   # Verify backup takes over
   ssh backup_server "systemctl status arpguard"
   ```

2. Test synchronization:
   ```bash
   # Make configuration change on primary
   # Verify change propagates to backup
   ```

## Reporting

### Test Reports

Generate comprehensive test reports:
```bash
# Run full test suite with reporting
python scripts/run_tests.py --report
```

### Compliance Documentation

Generate compliance documentation for validation:
```bash
# Generate documentation
python scripts/generate_compliance_docs.py
```

## Cleanup Procedures

After testing is complete:

1. Stop all services:
   ```bash
   sudo systemctl stop arpguard elasticsearch logstash kibana prometheus grafana
   ```

2. Clean up test data:
   ```bash
   # Clear database
   sudo -u postgres dropdb arpguard_db
   
   # Clear logs
   sudo rm -rf /var/log/arpguard/*
   ```

3. Reset network configurations:
   ```bash
   # Reset switch VLANs if needed
   ```

## Troubleshooting

### Common Issues

1. Packet capture not working:
   ```bash
   # Check permissions
   sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
   ```

2. Database connection issues:
   ```bash
   # Check PostgreSQL status
   sudo systemctl status postgresql
   ```

3. Network interface issues:
   ```bash
   # Verify interface status
   ip a
   sudo tcpdump -i eth0
   ```

## Security Considerations

1. Isolate test environment from production
2. Use unique credentials for test environment
3. Reset all configurations after testing
4. Monitor for unauthorized access during testing
5. Use dedicated VLANs for test traffic

## Next Steps

After successful validation in the test environment:

1. Document test results
2. Update deployment plan based on findings
3. Schedule production deployment
4. Prepare rollback procedures (see rollback_procedures.md)
5. Conduct final review of all documentation 