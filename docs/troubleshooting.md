# ARP Guard Troubleshooting Guide

This guide provides solutions for common issues you might encounter while using ARP Guard.

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Startup Problems](#startup-problems)
3. [Detection Issues](#detection-issues)
4. [Remediation Issues](#remediation-issues)
5. [Dashboard Issues](#dashboard-issues)
6. [Performance Problems](#performance-problems)
7. [Common Error Messages](#common-error-messages)
8. [Advanced Troubleshooting](#advanced-troubleshooting)

## Installation Issues

### Missing Dependencies

**Symptoms:**
- Installation fails with error about missing libraries
- Python import errors when starting ARP Guard

**Solutions:**

For Linux:
```bash
# Install required libraries
sudo apt-get update
sudo apt-get install -y python3-pip python3-dev libpcap-dev

# Ensure Python packages are installed
pip install -r requirements.txt
```

For Windows:
```powershell
# Ensure Npcap is installed
# Download from https://npcap.com/#download

# Install Python packages
pip install -r requirements.txt
```

### Permission Issues

**Symptoms:**
- Permission denied errors during installation
- Unable to create config directories

**Solutions:**

For Linux:
```bash
# Run installation with sudo
sudo python setup.py install

# Check directory permissions
sudo chown -R $(whoami) ~/.config/arp_guard/
```

For Windows:
- Run Command Prompt or PowerShell as Administrator
- Check that your user has write access to `%APPDATA%`

## Startup Problems

### ARP Guard Won't Start

**Symptoms:**
- Error message when running `arp_guard start`
- Service starts but immediately stops

**Solutions:**

1. **Check permissions:**
   ```bash
   # Run with elevated privileges
   sudo arp_guard start
   ```

2. **Check for port conflicts:**
   ```bash
   # Check if another process is using the same port
   sudo netstat -tulpn | grep 5000  # For dashboard port
   ```

3. **Check configuration files:**
   ```bash
   # Verify configuration file is valid
   arp_guard config show
   
   # Reset configuration if corrupted
   arp_guard config reset
   ```

4. **Check log files for specific errors:**
   ```bash
   # View the last 50 lines of the log
   tail -n 50 /var/log/arp_guard.log  # Linux
   ```
   On Windows, check the log file in `%APPDATA%\ARP Guard\logs\`

### Service Starts but Immediately Stops

**Symptoms:**
- ARP Guard appears to start but isn't running when you check status
- Logs show service termination

**Solutions:**

1. **Run in verbose mode to see errors:**
   ```bash
   arp_guard start --verbose
   ```

2. **Check for conflicting services:**
   - Other packet capture applications might be interfering
   - Antivirus software might be blocking network monitoring

3. **Try running in diagnostic mode:**
   ```bash
   arp_guard --diagnostic start
   ```

## Detection Issues

### No Packets Being Detected

**Symptoms:**
- Status shows zero packets processed
- No detections reported

**Solutions:**

1. **Verify the network interface:**
   ```bash
   # List available interfaces
   arp_guard list-interfaces
   
   # Specify interface explicitly
   arp_guard start --interface eth0
   ```

2. **Check packet capture permissions:**
   - Ensure you're running with administrative privileges
   - Verify libpcap/Npcap is correctly installed

3. **Test with other packet capture tools:**
   ```bash
   # Test if tcpdump/Wireshark can capture packets
   sudo tcpdump -i eth0 arp  # Linux
   ```

### False Positives

**Symptoms:**
- Legitimate devices being detected as threats
- Too many alerts for non-malicious activity

**Solutions:**

1. **Add trusted devices to whitelist:**
   ```bash
   arp_guard remediation whitelist add 00:11:22:33:44:55 192.168.1.100
   ```

2. **Adjust detection sensitivity:**
   ```bash
   arp_guard config set detection.sensitivity 3  # Lower value (1-10)
   ```

3. **Update MAC vendor database:**
   ```bash
   arp_guard update mac-vendors
   ```

## Remediation Issues

### Blocking Not Working

**Symptoms:**
- Hosts are detected but not blocked
- Malicious traffic continues after detection

**Solutions:**

1. **Verify auto-blocking is enabled:**
   ```bash
   arp_guard remediation show
   arp_guard remediation set auto_block true
   ```

2. **Check firewall status:**
   - Linux: Ensure iptables is running:
     ```bash
     sudo iptables -L
     ```
   - Windows: Ensure Windows Firewall is enabled:
     ```powershell
     Get-NetFirewallProfile
     ```

3. **Test manual blocking:**
   ```bash
   # Manually block an IP for testing
   arp_guard block 192.168.1.200
   ```

### Cannot Unblock Hosts

**Symptoms:**
- Unblock commands fail
- Hosts remain blocked after duration expires

**Solutions:**

1. **Check permissions:**
   - Ensure you're running with administrative privileges

2. **Try manual unblocking:**
   ```bash
   arp_guard unblock 00:11:22:33:44:55 --force
   ```

3. **Reset remediation cache:**
   ```bash
   arp_guard remediation reset-cache
   ```

### Notification Issues

**Symptoms:**
- Not receiving email notifications
- Notification errors in logs

**Solutions:**

1. **Verify email settings:**
   ```bash
   arp_guard remediation show
   arp_guard remediation set notification_email admin@example.com
   ```

2. **Check SMTP configuration:**
   - Ensure SMTP server details are correct in config
   - Test with a manual notification:
     ```bash
     arp_guard test-notification
     ```

3. **Check for firewall blocking SMTP:**
   - Ensure outbound connections to port 25/587/465 are allowed

## Dashboard Issues

### Dashboard Won't Start

**Symptoms:**
- Error when running `arp_guard dashboard`
- Unable to connect to dashboard URL

**Solutions:**

1. **Check port availability:**
   ```bash
   # Check if port 5000 is already in use
   netstat -tuln | grep 5000
   
   # Start dashboard on different port
   arp_guard dashboard --port 5001
   ```

2. **Verify Flask installation:**
   ```bash
   pip install flask flask-socketio
   ```

3. **Check for firewall blocking:**
   - Ensure local firewall allows connections to dashboard port

### Dashboard Shows No Data

**Symptoms:**
- Dashboard loads but doesn't display statistics
- Charts remain empty

**Solutions:**

1. **Verify detection module is running:**
   ```bash
   arp_guard status
   ```

2. **Check WebSocket connectivity:**
   - Browser console might show WebSocket connection errors
   - Try different browser or disable security extensions

3. **Restart both services:**
   ```bash
   arp_guard stop
   arp_guard start
   arp_guard dashboard
   ```

## Performance Problems

### High CPU Usage

**Symptoms:**
- System becomes slow when ARP Guard is running
- CPU usage consistently high

**Solutions:**

1. **Adjust packet processing settings:**
   ```bash
   # Reduce sampling rate
   arp_guard config set detection.packet_sampling_rate 2
   
   # Increase processing interval
   arp_guard config set detection.check_interval 10
   ```

2. **Limit number of packets analyzed:**
   ```bash
   arp_guard config set detection.max_packets_per_interval 1000
   ```

3. **Disable parallel processing if on limited hardware:**
   ```bash
   arp_guard config set detection.use_parallel_processing false
   ```

### Memory Leaks

**Symptoms:**
- Memory usage grows over time
- System becomes unstable after long runtime

**Solutions:**

1. **Enable memory profiling:**
   ```bash
   arp_guard start --profile-memory
   ```

2. **Set memory limits:**
   ```bash
   arp_guard config set system.memory_limit 512
   ```

3. **Schedule periodic restarts:**
   Add to crontab (Linux) or Task Scheduler (Windows)

## Common Error Messages

### "Unable to initialize packet capture"

**Possible causes:**
- Missing libpcap/Npcap
- Insufficient permissions
- Invalid interface name

**Solutions:**
- Reinstall packet capture libraries
- Run with administrative privileges
- Verify interface name with `arp_guard list-interfaces`

### "Failed to create firewall rule"

**Possible causes:**
- Insufficient permissions
- Firewall service not running
- Invalid IP/MAC format

**Solutions:**
- Run with administrative privileges
- Start firewall service:
  ```bash
  sudo systemctl start firewalld  # Linux
  ```
  ```powershell
  Start-Service -Name "MpsSvc"  # Windows
  ```
- Check format of MAC/IP addresses

### "Configuration file corrupted"

**Possible causes:**
- Manual edits with invalid syntax
- Disk errors
- Incomplete writes

**Solutions:**
- Reset configuration:
  ```bash
  arp_guard config reset
  ```
- Restore from backup if available
- Check disk for errors

## Advanced Troubleshooting

### Generating Diagnostic Reports

For comprehensive troubleshooting, generate a diagnostic report:

```bash
arp_guard diagnose --full --output diagnostic_report.json
```

This will:
- Test all subsystems
- Verify dependencies
- Check network interfaces
- Test firewall integration
- Generate performance metrics
- Output system information

### Debug Mode

For detailed debugging information:

```bash
# Linux
DEBUG=1 arp_guard start

# Windows
set DEBUG=1 && arp_guard start
```

### Packet Capture Debugging

Test raw packet capture to verify it's working:

```bash
# Run in packet dump mode
arp_guard capture --count 10 --output packets.pcap

# View the captured packets
# Linux
tcpdump -r packets.pcap

# Windows (requires Wireshark)
"C:\Program Files\Wireshark\tshark.exe" -r packets.pcap
```

### Log Analysis

For log file analysis:

```bash
# Extract errors only
grep "ERROR" /var/log/arp_guard.log

# Show timeline of detection events
arp_guard log-analyze --type detection
```

### Getting Help

If you're unable to resolve an issue using this guide:

1. Check the online documentation at https://arp-guard.example.com/docs
2. Join our community forum at https://community.arp-guard.example.com
3. Submit a GitHub issue with your diagnostic report
4. Contact support at support@arp-guard.example.com

Remember to include:
- Your diagnostic report
- ARP Guard version (`arp_guard --version`)
- OS and hardware details
- Exact error messages
- Steps to reproduce the issue 