# ARPGuard Packet Capture Interface

## Overview

The ARPGuard Packet Capture Interface provides comprehensive functionality for capturing, analyzing, and examining network packets. This component enables both real-time monitoring and offline analysis of packet captures, making it a powerful tool for network security assessment.

## Features

- **Live Packet Capture**: Capture packets in real-time from any network interface
- **PCAP File Analysis**: Analyze existing packet capture files
- **Protocol Detection**: Automatically identify common protocols (ARP, TCP, UDP, ICMP, HTTP, HTTPS, DNS, DHCP)
- **Packet Filtering**: Apply BPF filters to focus on specific traffic
- **Traffic Pattern Analysis**: Generate statistics on packet flow and protocol distribution
- **Packet Inspection**: Examine packet contents in both hex and structured formats
- **Export Capabilities**: Save results as JSON or formatted reports

## CLI Usage

### Live Packet Capture

Capture packets from a network interface:

```
arpguard analyze --interface eth0 --duration 60
```

This command will capture packets from the eth0 interface for 60 seconds and display a summary of the captured traffic.

Additional options:
- `--filter "port 80"` - Apply a BPF filter to capture specific traffic
- `--protocol tcp` - Focus on a specific protocol
- `--max-packets 1000` - Limit the number of packets captured
- `--save-pcap capture.pcap` - Save the captured packets to a PCAP file
- `--output results.json` - Save analysis results to a file
- `--format json` - Display results in JSON format

### PCAP File Analysis

Analyze an existing packet capture file:

```
arpguard analyze --file capture.pcap
```

This command will analyze the PCAP file and display statistics about the contained packets.

Additional options:
- `--protocol arp` - Focus analysis on a specific protocol
- `--filter "host 192.168.1.1"` - Apply a filter to the analysis
- `--max-packets 5000` - Limit analysis to the first N packets
- `--output report.txt` - Save analysis results to a file

## Architecture

The Packet Capture Interface consists of the following components:

```
┌───────────────────┐     ┌────────────────────┐     ┌───────────────────┐
│ Command Line      │     │ Packet Capture     │     │ Packet Analysis   │
│ Interface         │────>│ Controller         │────>│ Engine            │
└───────────────────┘     └────────────────────┘     └───────────────────┘
                                │                            │
                                ▼                            ▼
                          ┌────────────────┐         ┌──────────────────┐
                          │ Live Capture   │         │ Packet Storage   │
                          │ (Scapy)        │         │ & Statistics     │
                          └────────────────┘         └──────────────────┘
```

## Implementation Details

### Packet Capture Module

The core functionality is implemented in the `PacketCapture` class, which provides methods for:

- Starting and stopping packet capture
- Filtering packets based on protocol or BPF expressions
- Extracting packet information
- Generating traffic statistics
- Saving packets to PCAP files

### Protocol Support

The system can identify and analyze the following protocols:

| Protocol | Description                           | Common Ports           |
|----------|---------------------------------------|------------------------|
| ARP      | Address Resolution Protocol           | N/A (Layer 2)          |
| TCP      | Transmission Control Protocol         | Various                |
| UDP      | User Datagram Protocol                | Various                |
| ICMP     | Internet Control Message Protocol     | N/A                    |
| HTTP     | Hypertext Transfer Protocol           | 80                     |
| HTTPS    | HTTP Secure                           | 443                    |
| DNS      | Domain Name System                    | 53                     |
| DHCP     | Dynamic Host Configuration Protocol   | 67, 68                 |
| SSH      | Secure Shell                          | 22                     |

### Dependencies

The packet capture functionality depends on the following libraries:

- **Scapy**: Used for packet capture, inspection, and PCAP file operations
- **PyShark** (optional): For more advanced packet dissection

## Example Analysis Output

```
========================== Packet Analysis ==========================

Summary:
  Packets: 1482
  Duration: 30.5 seconds
  Rate: 48.6 packets/second
  Average packet size: 342.8 bytes

Protocol Distribution:
┌──────────────┬───────┬────────────┐
│ Protocol     │ Count │ Percentage │
├──────────────┼───────┼────────────┤
│ TCP/443      │ 723   │ 48.8%      │
│ TCP/80       │ 312   │ 21.1%      │
│ UDP/53       │ 187   │ 12.6%      │
│ ARP          │ 94    │ 6.3%       │
│ ICMP         │ 45    │ 3.0%       │
│ TCP          │ 121   │ 8.2%       │
└──────────────┴───────┴────────────┘

Top Source IPs:
┌────────────────┬───────┐
│ IP Address     │ Count │
├────────────────┼───────┤
│ 192.168.1.5    │ 458   │
│ 192.168.1.1    │ 312   │
│ 8.8.8.8        │ 187   │
└────────────────┴───────┘
```

## Future Enhancements

- Deep packet inspection for application-layer protocols
- Integration with threat intelligence feeds for malicious traffic detection
- Custom visualization for traffic patterns
- Advanced anomaly detection using machine learning
- Support for encrypted traffic analysis

## Related Documentation

- [Network Scanning Guide](network_scanning.md)
- [ARP Spoofing Detection](arp_spoof_detection.md)
- [Protocol Analysis](protocol_analysis.md) 