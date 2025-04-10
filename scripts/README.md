# ARPGuard Demo Scripts

This directory contains scripts for demonstrating ARPGuard's functionality in a controlled environment.

## Prerequisites

- Python 3.7 or higher
- Required Python packages (install using `pip install -r requirements.txt`):
  - logging
  - subprocess
  - datetime
  - time

## Available Scripts

1. `mock_arpguard.py`: Simulates ARPGuard's core functionality
   - Monitor mode: Detects ARP spoofing attacks
   - Protect mode: Blocks ARP spoofing attacks
   - Statistics: Shows attack detection and blocking statistics

2. `run_demo.py`: Interactive demo script
   - Provides a menu-driven interface
   - Runs monitor and protect mode demos
   - Displays real-time statistics

## Running the Demo

1. Start the demo:
   ```bash
   python scripts/run_demo.py
   ```

2. Choose a demo mode:
   - Option 1: Monitor Mode Demo
     - Shows how ARPGuard detects ARP spoofing attacks
     - Runs for 30 seconds
     - Displays detection statistics
   
   - Option 2: Protection Mode Demo
     - Shows how ARPGuard blocks ARP spoofing attacks
     - Runs for 30 seconds
     - Displays protection statistics

3. View the results:
   - The demo will show real-time logs of detected attacks
   - Statistics are displayed at the end of each demo
   - You can interrupt the demo at any time using Ctrl+C

## Demo Features

- **Monitor Mode**:
  - Detects ARP spoofing attacks
  - Logs attack details
  - Provides attack statistics

- **Protection Mode**:
  - Blocks ARP spoofing attacks
  - Maintains correct ARP table
  - Provides protection statistics

## Notes

- The demo runs in a simulated environment
- All attacks are simulated for demonstration purposes
- Statistics are generated based on simulated data
- The demo can be interrupted at any time using Ctrl+C

## Troubleshooting

If you encounter any issues:

1. Check Python version:
   ```bash
   python --version
   ```

2. Verify required packages:
   ```bash
   pip list
   ```

3. Check script permissions:
   ```bash
   chmod +x scripts/*.py
   ```

4. Run with verbose logging:
   ```bash
   python scripts/run_demo.py --verbose
   ``` 