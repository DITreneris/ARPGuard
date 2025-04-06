import socket
import threading
import json
import time
from typing import Dict, Any, Optional, Callable
from datetime import datetime

from PyQt5.QtCore import QObject, pyqtSignal
from app.utils.logger import get_logger
from app.components.network_scanner import NetworkScanner
from app.components.threat_detector import ThreatDetector
from app.components.arp_spoofer import ARPSpoofer

# Module logger
logger = get_logger('components.site_client')

class SiteClient(QObject):
    """Implements client functionality for sites to connect to the controller."""
    
    # Signals for UI updates
    connected = pyqtSignal()
    disconnected = pyqtSignal()
    command_received = pyqtSignal(str, dict)  # command, data
    scan_completed = pyqtSignal(list)  # devices
    threat_detected = pyqtSignal(dict)  # threat_data
    
    def __init__(self, site_id: str, host: str = 'localhost', port: int = 5000):
        """Initialize the site client.
        
        Args:
            site_id: Unique identifier for this site
            host: Controller host address
            port: Controller port
        """
        super().__init__()
        
        self.site_id = site_id
        self.host = host
        self.port = port
        self.running = False
        self.client_socket = None
        self.client_thread = None
        
        # Initialize components
        self.scanner = NetworkScanner()
        self.detector = ThreatDetector()
        self.spoofer = ARPSpoofer()
        
        # Connect component signals
        self.scanner.scan_completed.connect(self._handle_scan_completed)
        self.detector.threat_detected.connect(self._handle_threat_detected)
        
        # Initialize client socket
        self._init_client()
    
    def _init_client(self):
        """Initialize the client socket."""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            logger.info(f"Site client initialized for {self.site_id}")
        except Exception as e:
            logger.error(f"Failed to initialize site client: {e}")
            raise
    
    def connect(self):
        """Connect to the controller."""
        if self.running:
            logger.warning("Site client already running")
            return
        
        try:
            self.client_socket.connect((self.host, self.port))
            
            # Send handshake
            handshake = {
                'site_id': self.site_id,
                'capabilities': {
                    'network_scanning': True,
                    'threat_detection': True,
                    'arp_spoofing': True
                }
            }
            self.client_socket.send(json.dumps(handshake).encode())
            
            self.running = True
            self.client_thread = threading.Thread(target=self._client_loop)
            self.client_thread.daemon = True
            self.client_thread.start()
            
            logger.info(f"Site {self.site_id} connected to controller")
            self.connected.emit()
            
        except Exception as e:
            logger.error(f"Failed to connect to controller: {e}")
            self.disconnected.emit()
    
    def disconnect(self):
        """Disconnect from the controller."""
        if not self.running:
            return
        
        self.running = False
        if self.client_socket:
            self.client_socket.close()
        if self.client_thread:
            self.client_thread.join(timeout=5)
        
        logger.info(f"Site {self.site_id} disconnected from controller")
        self.disconnected.emit()
    
    def _client_loop(self):
        """Main client loop to handle messages from controller."""
        while self.running:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    break
                
                message = json.loads(data.decode())
                self._handle_message(message)
            
            except Exception as e:
                if self.running:  # Only log if we're not shutting down
                    logger.error(f"Error receiving message: {e}")
                    break
        
        # If we get here, we've lost connection
        if self.running:
            self.disconnect()
    
    def _handle_message(self, message: dict):
        """Handle a message from the controller.
        
        Args:
            message: Message data
        """
        message_type = message.get('type')
        
        if message_type == 'command':
            command = message.get('command')
            data = message.get('data', {})
            self.command_received.emit(command, data)
            
            # Handle specific commands
            if command == 'scan_network':
                self._handle_scan_command(data)
            elif command == 'start_detection':
                self._handle_start_detection_command(data)
            elif command == 'stop_detection':
                self._handle_stop_detection_command(data)
            elif command == 'start_spoofing':
                self._handle_start_spoofing_command(data)
            elif command == 'stop_spoofing':
                self._handle_stop_spoofing_command(data)
    
    def _handle_scan_command(self, data: dict):
        """Handle network scan command.
        
        Args:
            data: Command data with scan parameters
        """
        try:
            target = data.get('target', '')
            timeout = data.get('timeout', 3)
            
            self.scanner.scan_network(target=target, timeout=timeout)
            self.send_status('scanning')
            
        except Exception as e:
            logger.error(f"Error handling scan command: {e}")
            self.send_alert('error', f"Scan failed: {str(e)}")
    
    def _handle_start_detection_command(self, data: dict):
        """Handle start detection command.
        
        Args:
            data: Command data with detection parameters
        """
        try:
            self.detector.start_detection()
            self.send_status('detecting')
            
        except Exception as e:
            logger.error(f"Error starting detection: {e}")
            self.send_alert('error', f"Failed to start detection: {str(e)}")
    
    def _handle_stop_detection_command(self, data: dict):
        """Handle stop detection command.
        
        Args:
            data: Command data
        """
        try:
            self.detector.stop_detection()
            self.send_status('idle')
            
        except Exception as e:
            logger.error(f"Error stopping detection: {e}")
            self.send_alert('error', f"Failed to stop detection: {str(e)}")
    
    def _handle_start_spoofing_command(self, data: dict):
        """Handle start ARP spoofing command.
        
        Args:
            data: Command data with spoofing parameters
        """
        try:
            target_ip = data.get('target_ip')
            gateway_ip = data.get('gateway_ip')
            
            if not target_ip or not gateway_ip:
                raise ValueError("Missing target_ip or gateway_ip")
            
            self.spoofer.start_spoofing(target_ip, gateway_ip)
            self.send_status('spoofing')
            
        except Exception as e:
            logger.error(f"Error starting ARP spoofing: {e}")
            self.send_alert('error', f"Failed to start ARP spoofing: {str(e)}")
    
    def _handle_stop_spoofing_command(self, data: dict):
        """Handle stop ARP spoofing command.
        
        Args:
            data: Command data
        """
        try:
            self.spoofer.stop_spoofing()
            self.send_status('idle')
            
        except Exception as e:
            logger.error(f"Error stopping ARP spoofing: {e}")
            self.send_alert('error', f"Failed to stop ARP spoofing: {str(e)}")
    
    def _handle_scan_completed(self, devices: list):
        """Handle scan completion.
        
        Args:
            devices: List of discovered devices
        """
        self.scan_completed.emit(devices)
        self.send_status('idle')
        
        # Send scan results to controller
        self.send_alert('scan_complete', 'Network scan completed', {
            'devices': devices
        })
    
    def _handle_threat_detected(self, threat_data: dict):
        """Handle threat detection.
        
        Args:
            threat_data: Threat information
        """
        self.threat_detected.emit(threat_data)
        
        # Send threat alert to controller
        self.send_alert('threat', 'Threat detected', threat_data)
    
    def send_status(self, status: str):
        """Send status update to controller.
        
        Args:
            status: Current status
        """
        if not self.running:
            return
        
        try:
            message = {
                'type': 'status',
                'status': status
            }
            self.client_socket.send(json.dumps(message).encode())
        except Exception as e:
            logger.error(f"Failed to send status: {e}")
    
    def send_alert(self, alert_type: str, message: str, data: dict = None):
        """Send alert to controller.
        
        Args:
            alert_type: Type of alert
            message: Alert message
            data: Optional additional data
        """
        if not self.running:
            return
        
        try:
            message = {
                'type': 'alert',
                'data': {
                    'type': alert_type,
                    'message': message,
                    **(data or {})
                }
            }
            self.client_socket.send(json.dumps(message).encode())
        except Exception as e:
            logger.error(f"Failed to send alert: {e}") 