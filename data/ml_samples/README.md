# ML Sample Data

This directory contains sample packet data for training the ML detection models.

## Directory Structure

- `benign/`: Contains benign ARP traffic samples
- `spoofing/`: Contains ARP spoofing attack samples
- `mitm/`: Contains Man-in-the-Middle attack samples
- `dos/`: Contains Denial-of-Service attack samples
- `recon/`: Contains reconnaissance attack samples

## File Format

Each sample file is in JSON format and contains a list of packet dictionaries.
Each packet dictionary has the following structure:

```json
{
  "timestamp": "2024-04-06T12:34:56.789Z",
  "type": "arp",
  "op": 1,  # 1=request, 2=reply
  "src_mac": "00:11:22:33:44:55",
  "dst_mac": "ff:ff:ff:ff:ff:ff",
  "src_ip": "192.168.1.100",
  "dst_ip": "192.168.1.1",
  "hw_type": 1,
  "proto_type": 2048,
  "hw_len": 6,
  "proto_len": 4
}
```

## Usage

To train the ML models using these samples:

```python
from app.ml.controller import MLController

# Initialize the controller
controller = MLController()

# Load and train with sample data
controller.load_sample_data()
```

## Adding New Samples

You can add new sample data by saving packet dictionaries in JSON format
in the appropriate category directory. 