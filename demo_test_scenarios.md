# ARPGuard Demo Test Scenarios

This document outlines the specific test scenarios to be used during the investor demonstration. These scenarios are designed to showcase ARPGuard's capabilities, performance, and advantages in a controlled but realistic environment.

## Basic Network Configuration

- **Network:** 192.168.88.0/24
- **Demo Laptop:** 192.168.88.10
- **Device A (Client):** 192.168.88.20
- **Device B (Target):** 192.168.88.30
- **Device C (Attacker):** 192.168.88.40
- **Network Switch:** Unmanaged with port mirroring disabled

## Scenario 1: Basic ARP Spoofing Detection

**Purpose:** Demonstrate ARPGuard's core detection capabilities.

**Setup:**
1. All devices connected to the network
2. ARPGuard running in monitor mode: `arpguard --mode=monitor --interface=eth0 --detect-only`
3. Wireshark running and filtering for ARP: `wireshark -i eth0 -f "arp" &`

**Attack Procedure:**
1. From Device C (Attacker), run basic ARP poisoning attack:
   ```
   sudo ettercap -T -q -M arp:remote /192.168.88.10/ /192.168.88.30/
   ```

**Expected Results:**
- ARPGuard detects the attack within 1 second
- Alert appears in the dashboard
- Wireshark shows the malicious ARP packets
- Alert contains correct source of attack (Device C's MAC address)

**Talking Points:**
- Speed of detection
- Accuracy of identification
- Detailed information provided in the alert

## Scenario 2: Attack Prevention

**Purpose:** Demonstrate ARPGuard's ability to protect against ARP spoofing.

**Setup:**
1. Run continuous ping from demo laptop to Device B:
   ```
   ping -t 192.168.88.30
   ```
2. Launch ARPGuard in protection mode:
   ```
   arpguard --mode=protect --interface=eth0
   ```
3. Open secondary terminal to show ARP table:
   ```
   watch -n 1 arp -a
   ```

**Attack Procedure:**
1. From Device C (Attacker), run sustained ARP poisoning attack:
   ```
   sudo ettercap -T -q -M arp:remote /192.168.88.10/ /192.168.88.30/
   ```

**Expected Results:**
- Ping continues without interruption
- ARPGuard detects and blocks the attack
- ARP table remains correct despite attack attempts
- Protection logs show ARPGuard sending corrective packets

**Talking Points:**
- Zero downtime protection
- Automatic remediation
- Low-latency response
- Protection without network reconfiguration

## Scenario 3: Performance Under Load

**Purpose:** Demonstrate ARPGuard's efficiency and minimal resource utilization.

**Setup:**
1. Launch ARPGuard with performance monitoring:
   ```
   arpguard --mode=protect --interface=eth0 --perf-monitor
   ```
2. Open system monitoring tool:
   ```
   htop
   ```

**Test Procedure:**
1. Run network stress tool from Device A:
   ```
   # On Device A
   sudo iperf3 -c 192.168.88.10 -t 60 -P 8
   ```
2. Simultaneously launch attack from Device C:
   ```
   # On Device C
   sudo python3 ~/attack_tools/flood_arp.py --count=10000 --target=192.168.88.30
   ```

**Expected Results:**
- ARPGuard maintains high packet processing rate (>70,000 packets/sec)
- CPU utilization stays below 30% per core
- Memory usage remains stable around 40-50MB
- All attacks successfully detected and mitigated

**Talking Points:**
- Resource efficiency compared to competitors
- Ability to handle high-volume attacks
- No degradation in protection during stress
- Designed for performance at scale

## Scenario 4: Advanced Attack Detection

**Purpose:** Demonstrate ARPGuard's machine learning capabilities for detecting sophisticated attacks.

**Setup:**
1. Launch ARPGuard with ML detection enabled:
   ```
   arpguard --mode=protect --ml-detection=on --interface=eth0
   ```

**Attack Procedure:**
1. From Device C, run sophisticated stealth attack:
   ```
   # On Device C
   sudo python3 ~/attack_tools/stealth_arp.py --target=192.168.88.30 --interval=random --mac-shift
   ```

**Expected Results:**
- ARPGuard detects the stealth attack that uses timing variations and subtle MAC manipulations
- ML detection identifies the pattern despite randomization
- Alert shows confidence score and attack classification
- Attack is successfully mitigated

**Talking Points:**
- Advanced ML detection capabilities
- Ability to detect sophisticated attacks
- Self-learning capabilities
- Behavioral analysis vs. signature detection

## Scenario 5: Integration Capabilities

**Purpose:** Showcase ARPGuard's ability to integrate with existing security infrastructure.

**Setup:**
1. Configure mock SIEM integration:
   ```
   arpguard --config=demo-siem.conf --mode=protect --interface=eth0
   ```
2. Open second terminal window showing SIEM feed:
   ```
   tail -f /var/log/arpguard/siem-forward.log
   ```

**Test Procedure:**
1. Run multiple different attack types from Device C:
   ```
   # On Device C - Run script that executes multiple attack types
   sudo python3 ~/attack_tools/attack_suite.py --target=192.168.88.30
   ```

**Expected Results:**
- ARPGuard detects all attacks
- SIEM integration shows properly formatted alerts being forwarded
- REST API endpoints receive and respond to queries
- Compliance reporting module generates appropriate documentation

**Talking Points:**
- Enterprise integration capabilities
- Standardized formats for SIEM integration
- API-first design philosophy
- Compliance automation features

## Fallback Scenarios

### Scenario 1 Fallback
If Ettercap fails to run or isn't effective:
1. Navigate to: `~/attack_tools/`
2. Run alternative attack tool:
   ```
   sudo python3 arp_spoof.py -t 192.168.88.30 -g 192.168.88.1
   ```

### Scenario 2 Fallback
If protection mode experiences issues:
1. Restart ARPGuard with fallback configuration:
   ```
   arpguard --config=fallback.conf --mode=protect
   ```
2. Use alternative ping test:
   ```
   mtr -c 100 192.168.88.30
   ```

### Scenario 3 Fallback
If performance metrics aren't impressive in live demo:
1. Switch to pre-recorded benchmark results:
   ```
   arpguard-view --benchmark=benchmark-results.json
   ```

### Scenario 4 Fallback
If ML detection faces issues:
1. Use simpler but still effective detection demonstration:
   ```
   arpguard --config=ml-demo.conf --replay=ml-attack-capture.pcap
   ```

### Scenario 5 Fallback
If integration demo fails:
1. Show screenshots of successful integration
2. Navigate to:
   ```
   xdg-open ~/demos/screenshots/siem-integration.png
   ```

## Pre-Demo Testing Procedure

Run the following script to validate all scenarios before the actual demo:
```
cd ~/demos
./validate_scenarios.sh
```

This will generate a report at `~/demos/validation_report.html` that confirms all scenarios are working as expected.

## Data Collection

During the demo, the following data will be automatically collected:
- Performance metrics
- Detection logs
- System resource utilization
- Network traffic statistics

This data can be exported post-demo for inclusion in follow-up materials:
```
arpguard-export --format=pdf --output=~/investor-demo-results.pdf
``` 