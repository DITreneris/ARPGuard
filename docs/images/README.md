# Documentation Images

This directory contains all images used in the ARP Guard documentation.

## Required Images

The following images are referenced in the documentation and need to be created:

### User Documentation Images

1. **gateway_detection.png** - Screenshot of the Network Status panel showing detected gateway information
2. **manual_gateway_config.png** - Screenshot of the Gateway Configuration settings panel
3. **network_scan_results.png** - Screenshot of network scan results with gateway highlighted
4. **troubleshooting_gateway.png** - Screenshot of the gateway troubleshooting tool
5. **vpn_configuration.png** - Screenshot of VPN interface monitoring settings

### Developer Documentation Images

1. **gateway_module_architecture.png** - Diagram showing the gateway detection module architecture
2. **detection_flow.png** - Flowchart of the detection process with gateway checks highlighted
3. **packet_priority.png** - Diagram showing packet priority classification

## Image Guidelines

When creating documentation images:

1. Use 1920x1080 resolution when taking screenshots
2. Crop images to focus on relevant UI elements
3. Highlight important fields with red rectangles
4. Blur out sensitive information (IPs, MACs, etc.)
5. Use dark theme for developer documentation
6. Use light theme for user documentation
7. Save as PNG with reasonable compression

## Naming Convention

Use lowercase with underscores for image filenames:

- `feature_name.png` - Basic feature screenshot
- `feature_name_detail.png` - Detailed view of a feature
- `feature_name_configuration.png` - Configuration screen for a feature

## Directory Structure

```
images/
├── dev/             # Developer documentation images
├── user/            # User documentation images
├── diagrams/        # Architecture and flow diagrams
└── troubleshooting/ # Images for troubleshooting guides
```

The directories will be automatically created when adding the first image to each category. 