# ARPGuard Investor Demo Script

## Overview

This document outlines the step-by-step process for demonstrating ARPGuard's capabilities to potential investors. The demonstration is designed to highlight ARPGuard's key features, performance advantages, and unique selling points in a live setting.

**Demo Duration:** 15-20 minutes  
**Preparation Time:** 30 minutes  
**Required Setup:** Dual-screen laptop, isolated network environment with 3+ devices

## Demo Environment Setup

### Hardware Requirements:
- Demo laptop (8-core, 16GB RAM minimum)
- Secondary display/projector
- Network switch (unmanaged)
- 3 test devices:
  - Device A: Normal client
  - Device B: Target system
  - Device C: Attack system

### Software Requirements:
- ARPGuard v0.9.2 installed on demo laptop
- Wireshark for packet visualization
- Attack tools on Device C (Ettercap or similar)
- Standard network applications on all devices

### Network Configuration:
- Isolated network (192.168.88.0/24)
- Demo laptop: 192.168.88.10
- Device A: 192.168.88.20
- Device B: 192.168.88.30
- Device C: 192.168.88.40

## Pre-Demo Checklist

- [ ] All devices powered on and connected to network
- [ ] All IP addresses configured correctly
- [ ] ARPGuard installed and ready to run
- [ ] Test pings successful between all devices
- [ ] Attack tools configured but not running
- [ ] Presentation materials loaded and ready
- [ ] Projector/secondary display connected and working
- [ ] Demo laptop in "Do Not Disturb" mode
- [ ] Backup demo environment ready if needed
- [ ] Test run completed successfully

## Demo Script

### Introduction (2 minutes)

1. Start with ARPGuard dashboard closed
2. Open terminal and run:
   ```
   arpguard --version
   ```
3. Provide brief overview of demo goals:
   - "Today I'll demonstrate how ARPGuard detects and prevents ARP-based attacks"
   - "We'll see both the attack mechanics and ARPGuard's response"
   - "We'll also examine performance metrics that differentiate our solution"

### Phase 1: Understanding the Threat (3 minutes)

1. Show network topology on diagram
2. Demonstrate normal network operation
   ```
   ping 192.168.88.30   # Ping Device B from demo laptop
   ```
3. Open Wireshark and filter for ARP traffic
   ```
   wireshark -i eth0 -f "arp" &
   ```
4. Explain ARP protocol basics and point out normal traffic
5. Instruct assistant to initiate basic ARP poisoning attack from Device C
   ```
   # On Device C
   sudo ettercap -T -q -M arp:remote /192.168.88.10/ /192.168.88.30/
   ```
6. Show Wireshark capturing the attack traffic
7. Demonstrate impact - traffic being redirected, potential data interception

### Phase 2: ARPGuard Detection (5 minutes)

1. Close any previous ARPGuard instances
2. Launch ARPGuard in monitoring mode
   ```
   arpguard --mode=monitor --interface=eth0 --detect-only
   ```
3. Point out key UI elements:
   - Network map visualization
   - Live traffic monitoring
   - Alert panel
   - Performance indicators

4. Instruct assistant to restart the attack from Device C
   ```
   # On Device C
   sudo ettercap -T -q -M arp:remote /192.168.88.10/ /192.168.88.30/
   ```

5. Narrate what's happening as ARPGuard detects the attack:
   - "Within milliseconds, ARPGuard has detected the attack"
   - "Notice the alert showing the conflicting MAC addresses"
   - "The threat is automatically classified as 'Critical'"
   - "All details including timestamps and packet information are logged"

6. Demonstrate filtering and searching the alerts
7. Show detailed information for the detected attack

### Phase 3: ARPGuard Protection (4 minutes)

1. Stop monitoring mode and launch in protection mode
   ```
   arpguard --mode=protect --interface=eth0
   ```
2. Instruct assistant to launch the attack again from Device C
3. Observe and explain ARPGuard's response:
   - "ARPGuard immediately detects the attack"
   - "It automatically sends corrective ARP packets"
   - "The legitimate network traffic is protected"
   - "Notice the attack mitigation confirmation in the logs"

4. Demonstrate continuing connectivity between devices despite attack
   ```
   ping 192.168.88.30   # Ping Device B from demo laptop
   ```
5. Show the network map highlighting the protected connections

### Phase 4: Performance Demonstration (3 minutes)

1. Launch ARPGuard with performance monitoring enabled
   ```
   arpguard --mode=protect --interface=eth0 --perf-monitor
   ```
2. Show real-time performance metrics:
   - Packet processing rate
   - Detection latency
   - Memory usage
   - CPU utilization

3. Navigate to historical performance view
4. Highlight key benchmarks:
   - "ARPGuard processes over 70,000 packets per second"
   - "Detection latency averages under 0.5 milliseconds"
   - "Memory footprint stays under 50MB even under heavy load"
   - "CPU utilization remains below 20% per core"

5. Pull up comparison chart showing ARPGuard vs. competitors
6. Emphasize the 60% lower network overhead compared to alternatives

### Phase 5: Extended Features (3 minutes)

1. Quickly demonstrate additional capabilities:
   - Configuration flexibility
     ```
     arpguard --config=demo-custom.conf
     ```
   - Compliance reporting
     ```
     arpguard --generate-report=compliance
     ```
   - Integration capabilities
     ```
     arpguard --siem-forward=demo-siem.conf
     ```

2. Show machine learning-based detection
   - Switch to advanced detection mode
     ```
     arpguard --mode=protect --ml-detection=on
     ```
   - Demonstrate detection of more sophisticated attack
     ```
     # On Device C
     sudo python3 stealth_arp.py --target 192.168.88.30
     ```
   - "Our ML engine detects even sophisticated attacks that traditional systems miss"

### Conclusion (2 minutes)

1. Stop all attacks and ARPGuard instances
2. Summarize key advantages demonstrated:
   - "We've seen ARPGuard's superior detection capabilities"
   - "Protection that maintains network functionality"
   - "Performance that outpaces competitors"
   - "Flexible deployment options for any environment"
   - "Compliance-ready security that integrates with existing infrastructure"

3. Show roadmap slide for where the product is headed
4. Open for questions

## Fallback Scenarios

### If the live attack doesn't work:
- Switch to pre-recorded video of attack scenario
- Navigate to: `~/demos/recorded/attack-demo.mp4`

### If ARPGuard crashes during demo:
- Close the application
- Run diagnostic recovery:
  ```
  arpguard-recover --last-session
  ```
- Restart with safe configuration:
  ```
  arpguard --safe-mode
  ```

### If network connectivity fails:
- Switch to local simulation mode:
  ```
  arpguard --simulation=enterprise-network
  ```

## Post-Demo Actions

1. Stop all attack processes
2. Reset all network configurations
3. Save and export any logs generated during demo
4. Power down test devices
5. Return network to normal operating state 