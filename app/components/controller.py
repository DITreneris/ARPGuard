import socket
import threading
import json
import time
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime

from PyQt5.QtCore import QObject, pyqtSignal
from app.utils.logger import get_logger
from app.components.rbac import RBAC, Permission
from app.components.audit_logger import AuditLogger, AuditEventType

# Module logger
logger = get_logger('components.controller')

class Controller(QObject):
    """Implements central management for single-site deployments."""
    
    # Signals for UI updates
    site_connected = pyqtSignal(str)  # site_id
    site_disconnected = pyqtSignal(str)  # site_id
    site_status_changed = pyqtSignal(str, str)  # site_id, status
    alert_received = pyqtSignal(dict)  # alert_data
    
    def __init__(self, host: str = '0.0.0.0', port: int = 5000):
        """Initialize the controller.
        
        Args:
            host: Host address to bind to
            port: Port to listen on
        """
        super().__init__()
        
        self.host = host
        self.port = port
        self.running = False
        self.server_socket = None
        self.server_thread = None
        
        # Store connected sites
        self.connected_sites = {}  # type: Dict[str, Dict[str, Any]]
        
        # Initialize RBAC and audit logging
        self.rbac = RBAC()
        self.audit_logger = AuditLogger()
        
        # Initialize server socket
        self._init_server()
    
    def _init_server(self):
        """Initialize the server socket."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            logger.info(f"Controller server initialized on {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Failed to initialize controller server: {e}")
            raise
    
    def start(self):
        """Start the controller server."""
        if self.running:
            logger.warning("Controller server already running")
            return
        
        self.running = True
        self.server_thread = threading.Thread(target=self._server_loop)
        self.server_thread.daemon = True
        self.server_thread.start()
        logger.info("Controller server started")
    
    def stop(self):
        """Stop the controller server."""
        if not self.running:
            return
        
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        if self.server_thread:
            self.server_thread.join(timeout=5)
        logger.info("Controller server stopped")
    
    def _server_loop(self):
        """Main server loop to accept and handle connections."""
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                logger.info(f"New connection from {address}")
                
                # Start a new thread to handle the client
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                if self.running:  # Only log if we're not shutting down
                    logger.error(f"Error accepting connection: {e}")
    
    def _handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle a client connection.
        
        Args:
            client_socket: Client socket
            address: Client address tuple (host, port)
        """
        site_id = None
        try:
            # Receive initial handshake
            data = client_socket.recv(4096)
            if not data:
                return
            
            handshake = json.loads(data.decode())
            site_id = handshake.get('site_id')
            
            if not site_id:
                logger.error(f"Invalid handshake from {address}: missing site_id")
                return
            
            # Store site connection
            self.connected_sites[site_id] = {
                'socket': client_socket,
                'address': address,
                'last_seen': datetime.now(),
                'status': 'connected',
                'capabilities': handshake.get('capabilities', {})
            }
            
            # Notify UI
            self.site_connected.emit(site_id)
            
            # Log connection
            self.audit_logger.log_event(
                AuditEventType.SITE_CONNECTED,
                'system',
                {'address': address},
                site_id
            )
            
            # Handle messages from site
            while self.running:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                message = json.loads(data.decode())
                self._handle_message(site_id, message)
                
                # Update last seen
                self.connected_sites[site_id]['last_seen'] = datetime.now()
        
        except Exception as e:
            logger.error(f"Error handling client {address}: {e}")
        
        finally:
            if site_id and site_id in self.connected_sites:
                del self.connected_sites[site_id]
                self.site_disconnected.emit(site_id)
                
                # Log disconnection
                self.audit_logger.log_event(
                    AuditEventType.SITE_DISCONNECTED,
                    'system',
                    {'address': address},
                    site_id
                )
            client_socket.close()
    
    def _handle_message(self, site_id: str, message: dict):
        """Handle a message from a site.
        
        Args:
            site_id: ID of the sending site
            message: Message data
        """
        message_type = message.get('type')
        
        if message_type == 'status':
            status = message.get('status')
            if status:
                self.connected_sites[site_id]['status'] = status
                self.site_status_changed.emit(site_id, status)
                
                # Log status change
                self.audit_logger.log_event(
                    AuditEventType.SITE_STATUS_CHANGED,
                    'system',
                    {'status': status},
                    site_id
                )
        
        elif message_type == 'alert':
            alert_data = message.get('data', {})
            alert_data['site_id'] = site_id
            self.alert_received.emit(alert_data)
            
            # Log alert
            self.audit_logger.log_event(
                AuditEventType.ALERT_GENERATED,
                'system',
                alert_data,
                site_id
            )
    
    def send_command(self, username: str, site_id: str, command: str, data: dict = None) -> bool:
        """Send a command to a site.
        
        Args:
            username: Username of the user sending the command
            site_id: ID of the target site
            command: Command to send
            data: Optional command data
            
        Returns:
            bool: True if command was sent successfully
        """
        if site_id not in self.connected_sites:
            logger.error(f"Site {site_id} not connected")
            return False
        
        # Check permissions
        if not self.rbac.has_permission(username, Permission.COMMAND_EXECUTED, site_id):
            logger.error(f"User {username} does not have permission to execute commands on site {site_id}")
            return False
        
        try:
            message = {
                'type': 'command',
                'command': command,
                'data': data or {}
            }
            
            client_socket = self.connected_sites[site_id]['socket']
            client_socket.send(json.dumps(message).encode())
            
            # Log command execution
            self.audit_logger.log_event(
                AuditEventType.COMMAND_EXECUTED,
                username,
                {'command': command, 'data': data},
                site_id
            )
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to send command to site {site_id}: {e}")
            return False
    
    def get_connected_sites(self) -> List[Dict[str, Any]]:
        """Get information about all connected sites.
        
        Returns:
            List[Dict[str, Any]]: List of site information
        """
        sites = []
        for site_id, site_data in self.connected_sites.items():
            sites.append({
                'site_id': site_id,
                'address': site_data['address'],
                'last_seen': site_data['last_seen'],
                'status': site_data['status'],
                'capabilities': site_data['capabilities']
            })
        return sites 