#!/usr/bin/env python3

import sys
import logging
import time
from datetime import datetime
import json
import socket
import random
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TestEventGenerator:
    """Generates test events for SIEM integration testing."""
    
    def __init__(self):
        self.event_types = [
            'arp_spoofing',
            'mac_spoofing',
            'gateway_impersonation',
            'arp_flood',
            'suspicious_arp'
        ]
        self.severities = ['low', 'medium', 'high', 'critical']
    
    def generate_event(self) -> Dict[str, Any]:
        """Generate a single test event."""
        return {
            'timestamp': datetime.now().isoformat(),
            'event_type': random.choice(self.event_types),
            'severity': random.choice(self.severities),
            'source_ip': f'192.168.1.{random.randint(1, 254)}',
            'source_mac': ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)]),
            'target_ip': f'192.168.1.{random.randint(1, 254)}',
            'target_mac': ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)]),
            'confidence': random.uniform(0.5, 1.0),
            'description': f'Test {random.choice(self.event_types)} event'
        }
    
    def generate_events(self, count: int = 100) -> List[Dict[str, Any]]:
        """Generate multiple test events."""
        return [self.generate_event() for _ in range(count)]

class SIEMIntegration:
    """Handles SIEM integration testing."""
    
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.syslog_socket = None
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load SIEM configuration."""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            sys.exit(1)
    
    def connect(self) -> bool:
        """Establish connection to SIEM."""
        try:
            self.syslog_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.syslog_socket.connect(
                (self.config['siem_host'], self.config['siem_port'])
            )
            return True
        except Exception as e:
            logger.error(f"Failed to connect to SIEM: {e}")
            return False
    
    def forward_event(self, event: Dict[str, Any]) -> bool:
        """Forward a single event to SIEM."""
        try:
            message = json.dumps(event)
            self.syslog_socket.send(message.encode())
            return True
        except Exception as e:
            logger.error(f"Failed to forward event: {e}")
            return False
    
    def forward_events(self, events: List[Dict[str, Any]]) -> List[bool]:
        """Forward multiple events to SIEM."""
        results = []
        for event in events:
            result = self.forward_event(event)
            results.append(result)
            time.sleep(0.1)  # Prevent overwhelming the SIEM
        return results
    
    def close(self):
        """Close SIEM connection."""
        if self.syslog_socket:
            self.syslog_socket.close()

def test_siem_integration():
    """Test SIEM integration functionality."""
    logger.info("Starting SIEM integration test")
    
    # Initialize components
    siem = SIEMIntegration(config_path='config/siem_config.yaml')
    generator = TestEventGenerator()
    
    # Connect to SIEM
    if not siem.connect():
        logger.error("Failed to connect to SIEM")
        return False
    
    try:
        # Generate and forward test events
        events = generator.generate_events(count=100)
        results = siem.forward_events(events)
        
        # Verify results
        success_rate = sum(results) / len(results)
        if success_rate >= 0.95:
            logger.info(f"SIEM integration test passed with {success_rate:.2%} success rate")
            return True
        else:
            logger.error(f"SIEM integration test failed with {success_rate:.2%} success rate")
            return False
    
    finally:
        siem.close()

if __name__ == "__main__":
    success = test_siem_integration()
    sys.exit(0 if success else 1) 