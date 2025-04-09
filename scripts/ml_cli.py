#!/usr/bin/env python3
"""
Command-line tool for interacting with ARPGuard's ML detection layer.

This tool provides command-line access to ML-based detection features,
including packet analysis, model training, and statistics.
"""

import os
import sys
import json
import argparse
import time
from pathlib import Path
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from app.ml import MLController
from app.ml.feature_extraction import FeatureExtractor
from app.utils.logger import setup_logger

# Set up logging
log_file = os.path.join(project_root, 'logs', 'ml_cli.log')
logger = setup_logger('ml_cli', log_file)

def train_models(args):
    """Train ML models."""
    ml_controller = MLController()
    
    print("Training ML models with sample data...")
    result = ml_controller.load_sample_data()
    
    if result.get("success", False):
        print("Training completed successfully!")
        
        # Show classifier accuracy if available
        if "classifier" in result and "accuracy" in result["classifier"]:
            accuracy = result["classifier"]["accuracy"]
            print(f"Classifier accuracy: {accuracy:.2f}")
            
        # Show classes if available
        if "classifier" in result and "classes" in result["classifier"]:
            classes = result["classifier"]["classes"]
            print(f"Trained classes: {', '.join(classes)}")
    else:
        print(f"Training failed: {result.get('error', 'Unknown error')}")
        
def analyze_packet(args):
    """Analyze a single packet from a JSON file."""
    if not args.file:
        print("Error: Packet file is required (-f/--file)")
        return
        
    try:
        # Load packet from file
        with open(args.file, 'r') as f:
            data = json.load(f)
            
        # Initialize controllers
        ml_controller = MLController()
        feature_extractor = FeatureExtractor()
        
        # Ensure models are loaded
        if not ml_controller.stats["ml_engine"]["anomaly_stats"]["detector_ready"] and \
           not ml_controller.stats["ml_engine"]["classifier_stats"]["classifier_ready"]:
            print("Warning: No ML models loaded. Run training first with 'ml_cli.py train'")
            if args.force:
                print("Continuing anyway due to --force flag...")
            else:
                print("Use --force to analyze without trained models")
                return
                
        # If data is a list, use the first packet or iterate
        if isinstance(data, list):
            if args.all:
                packets = data
                print(f"Analyzing {len(packets)} packets...")
            else:
                packets = [data[0]]
                print("Analyzing first packet in the file...")
        else:
            packets = [data]
            print("Analyzing packet...")
            
        # Process each packet
        detections_count = 0
        for i, packet in enumerate(packets):
            # Extract features
            features = feature_extractor.extract_features(packet)
            
            # Pretty print basic packet info
            print(f"\nPacket {i+1}:")
            print(f"  Operation: {'Reply' if packet.get('op') == 2 else 'Request' if packet.get('op') == 1 else 'Unknown'}")
            print(f"  Source MAC: {packet.get('src_mac', 'Unknown')}")
            print(f"  Source IP: {packet.get('src_ip', 'Unknown')}")
            print(f"  Destination MAC: {packet.get('dst_mac', 'Unknown')}")
            print(f"  Destination IP: {packet.get('dst_ip', 'Unknown')}")
            
            # Show extracted features if requested
            if args.features:
                print("\nExtracted Features:")
                for feature, value in sorted(features.items()):
                    print(f"  {feature}: {value}")
                    
            # Process with ML
            result = ml_controller.process_packet(packet)
            
            # Show results
            if result.get("detections", []):
                detections_count += len(result["detections"])
                print("\nDetections:")
                for detection in result["detections"]:
                    detection_type = detection.get("evidence", {}).get("detection_type", "unknown")
                    print(f"  Type: {detection_type}")
                    print(f"  Confidence: {detection.get('confidence'):.2f}")
                    print(f"  Severity: {detection.get('severity')}")
                    
                    # Show contributing features
                    contributing = detection.get("evidence", {}).get("contributing_features", {})
                    if contributing and args.features:
                        print("  Contributing Features:")
                        for feature, importance in contributing.items():
                            print(f"    {feature}: {importance:.4f}")
                            
                    # Show attack type for classification
                    if detection_type == "classification":
                        attack_type = detection.get("evidence", {}).get("attack_type", "unknown")
                        print(f"  Attack Type: {attack_type}")
                        
                    # Show anomaly score for anomaly detection
                    if detection_type == "anomaly":
                        anomaly_score = detection.get("evidence", {}).get("anomaly_score", 0)
                        print(f"  Anomaly Score: {anomaly_score:.4f}")
            else:
                print("\nNo detections.")
                
        if len(packets) > 1:
            print(f"\nAnalysis complete. {detections_count} detections in {len(packets)} packets.")
            
    except Exception as e:
        print(f"Error analyzing packet: {e}")
        
def show_stats(args):
    """Show ML engine statistics."""
    ml_controller = MLController()
    stats = ml_controller.get_statistics()
    
    print("ML Engine Statistics:")
    print(f"Packets Analyzed: {stats['packets_analyzed']}")
    print(f"Threats Detected: {stats['threats_detected']}")
    print(f"ML Detections: {stats['ml_detections']}")
    
    # Show ML engine stats
    print("\nModel Status:")
    anomaly_ready = stats["ml_engine"]["anomaly_stats"]["detector_ready"]
    classifier_ready = stats["ml_engine"]["classifier_stats"]["classifier_ready"]
    
    print(f"Anomaly Detection: {'Ready' if anomaly_ready else 'Not Trained'}")
    if anomaly_ready:
        print(f"  Total Anomaly Detections: {stats['ml_engine']['anomaly_stats']['total_detections']}")
        
    print(f"Classification: {'Ready' if classifier_ready else 'Not Trained'}")
    if classifier_ready:
        print(f"  Total Classification Detections: {stats['ml_engine']['classifier_stats']['total_detections']}")
        
    # Training stats
    print("\nTraining Status:")
    print(f"Training in Progress: {stats['training']['training_in_progress']}")
    print(f"Collected Samples: {stats['training']['collected_samples']}")
    
    if stats['training']['last_training']:
        print(f"Last Training: {stats['training']['last_training']}")
    else:
        print("Last Training: Never")
        
    # Recent detections
    if args.detections:
        detections = ml_controller.get_recent_detections(limit=args.detections)
        if detections:
            print(f"\nRecent Detections ({len(detections)}):")
            for i, detection in enumerate(detections):
                print(f"Detection {i+1}:")
                print(f"  Time: {detection.get('timestamp')}")
                print(f"  Type: {detection.get('evidence', {}).get('detection_type', 'unknown')}")
                print(f"  Confidence: {detection.get('confidence'):.2f}")
                print(f"  Severity: {detection.get('severity')}")
                print(f"  Source IP: {detection.get('evidence', {}).get('source_ip', 'Unknown')}")
                
                # Extra details for verbose mode
                if args.verbose:
                    print("  Evidence:")
                    evidence = detection.get("evidence", {})
                    for k, v in evidence.items():
                        if k != "contributing_features":  # Skip features for readability
                            print(f"    {k}: {v}")
        else:
            print("\nNo recent detections.")
            
def reset_stats(args):
    """Reset ML statistics."""
    ml_controller = MLController()
    
    print("Resetting ML statistics...")
    ml_controller.clear_statistics()
    print("Statistics reset complete.")
    
def capture_packets(args):
    """Capture and analyze packets in real-time."""
    try:
        # Check if Scapy is available
        from scapy.all import sniff, ARP
    except ImportError:
        print("Error: Scapy is required for packet capture.")
        print("Install it with: pip install scapy")
        return
        
    from app.ml import MLController
    
    ml_controller = MLController()
    feature_extractor = FeatureExtractor()
    
    # Check if models are loaded
    if not ml_controller.stats["ml_engine"]["anomaly_stats"]["detector_ready"] and \
       not ml_controller.stats["ml_engine"]["classifier_stats"]["classifier_ready"]:
        print("Warning: No ML models loaded. Run training first with 'ml_cli.py train'")
        if args.force:
            print("Continuing anyway due to --force flag...")
        else:
            print("Use --force to analyze without trained models")
            return
            
    count = args.count if args.count else None
    
    print(f"Capturing{''+str(count) if count else ''} ARP packets for ML analysis...")
    print("Press Ctrl+C to stop capturing.")
    
    def process_packet(packet):
        """Process an ARP packet from Scapy."""
        if ARP in packet:
            arp = packet[ARP]
            
            # Convert to dictionary format
            packet_dict = {
                "op": int(arp.op),
                "src_mac": arp.hwsrc,
                "dst_mac": arp.hwdst,
                "src_ip": arp.psrc,
                "dst_ip": arp.pdst,
                "hw_type": int(arp.hwtype),
                "proto_type": int(arp.ptype),
                "hw_len": int(arp.hwlen),
                "proto_len": int(arp.plen),
                "timestamp": datetime.now().isoformat()
            }
            
            # Process with ML
            result = ml_controller.process_packet(packet_dict)
            
            # Print basic info
            print(f"\nARP {'Reply' if arp.op == 2 else 'Request'}: {arp.psrc} ({arp.hwsrc}) -> {arp.pdst} ({arp.hwdst})")
            
            # Show detections
            if result.get("detections", []):
                for detection in result["detections"]:
                    detection_type = detection.get("evidence", {}).get("detection_type", "unknown")
                    confidence = detection.get("confidence", 0)
                    severity = detection.get("severity", "UNKNOWN")
                    
                    # Color coding based on severity
                    color_code = {
                        "LOW": "\033[92m",      # Green
                        "MEDIUM": "\033[93m",   # Yellow
                        "HIGH": "\033[91m",     # Red
                        "CRITICAL": "\033[1;91m" # Bold Red
                    }.get(severity, "\033[0m")
                    
                    reset_color = "\033[0m"
                    
                    # Print detection with color
                    print(f"{color_code}DETECTION: {detection_type.upper()} - {severity} (Confidence: {confidence:.2f}){reset_color}")
                    
                    # Additional info for classification
                    if detection_type == "classification":
                        attack_type = detection.get("evidence", {}).get("attack_type", "unknown")
                        print(f"  Attack Type: {attack_type}")
                        
    try:
        # Start capture
        sniff(filter="arp", prn=process_packet, count=count, store=0)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except Exception as e:
        print(f"\nError during capture: {e}")
        
    # Print final stats
    stats = ml_controller.get_statistics()
    print(f"\nCapture complete. Analyzed {stats['packets_analyzed']} packets, detected {stats['threats_detected']} threats.")
    
def save_state(args):
    """Save ML state to disk."""
    ml_controller = MLController()
    
    print("Saving ML state...")
    ml_controller.save_state()
    print("ML state saved successfully.")
    
def load_state(args):
    """Load ML state from disk."""
    ml_controller = MLController()
    
    print("Loading ML state...")
    ml_controller.load_state()
    print("ML state loaded successfully.")
    
    # Show brief status
    stats = ml_controller.get_statistics()
    anomaly_ready = stats["ml_engine"]["anomaly_stats"]["detector_ready"]
    classifier_ready = stats["ml_engine"]["classifier_stats"]["classifier_ready"]
    
    print("\nModel Status:")
    print(f"Anomaly Detection: {'Ready' if anomaly_ready else 'Not Trained'}")
    print(f"Classification: {'Ready' if classifier_ready else 'Not Trained'}")

def main():
    """Main entry point for the CLI tool."""
    parser = argparse.ArgumentParser(description="ARPGuard ML Detection CLI")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Train command
    train_parser = subparsers.add_parser("train", help="Train ML models with sample data")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze packet from file")
    analyze_parser.add_argument("-f", "--file", help="JSON file containing packet data")
    analyze_parser.add_argument("--features", action="store_true", help="Show extracted features")
    analyze_parser.add_argument("--all", action="store_true", help="Process all packets in file (if list)")
    analyze_parser.add_argument("--force", action="store_true", help="Force analysis even if models not trained")
    
    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Show ML engine statistics")
    stats_parser.add_argument("-d", "--detections", type=int, default=5, help="Number of recent detections to show")
    stats_parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed information")
    
    # Reset command
    reset_parser = subparsers.add_parser("reset", help="Reset ML statistics")
    
    # Capture command
    capture_parser = subparsers.add_parser("capture", help="Capture and analyze packets in real-time")
    capture_parser.add_argument("-c", "--count", type=int, help="Number of packets to capture")
    capture_parser.add_argument("--force", action="store_true", help="Force capture even if models not trained")
    
    # Save state command
    save_parser = subparsers.add_parser("save", help="Save ML state to disk")
    
    # Load state command
    load_parser = subparsers.add_parser("load", help="Load ML state from disk")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Ensure logs directory exists
    os.makedirs(os.path.join(project_root, 'logs'), exist_ok=True)
    
    # Execute command
    if args.command == "train":
        train_models(args)
    elif args.command == "analyze":
        analyze_packet(args)
    elif args.command == "stats":
        show_stats(args)
    elif args.command == "reset":
        reset_stats(args)
    elif args.command == "capture":
        capture_packets(args)
    elif args.command == "save":
        save_state(args)
    elif args.command == "load":
        load_state(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 