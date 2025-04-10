import json
import logging
import queue
import threading
import time
from typing import Dict, Any, List, Optional, Callable

from .alert import Alert, AlertType, AlertPriority, AlertStatus

class UINotifier:
    """Manages notifications to user interfaces."""
    
    def __init__(self):
        """Initialize the UI notifier."""
        self.logger = logging.getLogger('ui_notifier')
        self.notification_queue = queue.Queue()
        self.connected_clients = {}
        self.client_counter = 0
        self.stop_event = threading.Event()
        self.notification_thread = None
        
    def start(self):
        """Start the notification thread."""
        if self.notification_thread and self.notification_thread.is_alive():
            self.logger.warning("Notification thread is already running")
            return
            
        self.stop_event.clear()
        self.notification_thread = threading.Thread(target=self._notification_loop)
        self.notification_thread.daemon = True
        self.notification_thread.start()
        self.logger.info("Started UI notification thread")
        
    def stop(self):
        """Stop the notification thread."""
        if self.notification_thread and self.notification_thread.is_alive():
            self.stop_event.set()
            self.notification_thread.join(timeout=10)
            self.logger.info("Stopped UI notification thread")
            
    def _notification_loop(self):
        """Process notifications from the queue and send to clients."""
        while not self.stop_event.is_set():
            try:
                # Get notification from queue, wait up to 1 second
                try:
                    notification = self.notification_queue.get(timeout=1)
                    self._broadcast_notification(notification)
                    self.notification_queue.task_done()
                except queue.Empty:
                    # No notifications in queue, continue loop
                    continue
                    
            except Exception as e:
                self.logger.error(f"Error in notification loop: {e}")
                
    def _broadcast_notification(self, notification: Dict[str, Any]):
        """Send notification to all connected clients."""
        disconnected_clients = []
        
        for client_id, client in self.connected_clients.items():
            try:
                client['callback'](notification)
            except Exception as e:
                self.logger.error(f"Error sending notification to client {client_id}: {e}")
                disconnected_clients.append(client_id)
                
        # Remove disconnected clients
        for client_id in disconnected_clients:
            self.disconnect_client(client_id)
            
    def connect_client(self, callback: Callable[[Dict[str, Any]], None], 
                     client_name: str = None) -> str:
        """
        Connect a new client to receive notifications.
        
        Args:
            callback: Function to call with notification data
            client_name: Optional name for the client
            
        Returns:
            Client ID
        """
        self.client_counter += 1
        client_id = f"client_{self.client_counter}"
        
        self.connected_clients[client_id] = {
            'name': client_name or client_id,
            'callback': callback,
            'connected_at': time.time()
        }
        
        self.logger.info(f"Client connected: {client_id} ({client_name or 'unnamed'})")
        return client_id
        
    def disconnect_client(self, client_id: str) -> bool:
        """
        Disconnect a client.
        
        Args:
            client_id: ID of client to disconnect
            
        Returns:
            True if client was disconnected, False otherwise
        """
        if client_id in self.connected_clients:
            client = self.connected_clients.pop(client_id)
            self.logger.info(f"Client disconnected: {client_id} ({client['name']})")
            return True
        return False
        
    def notify(self, alert: Alert) -> None:
        """
        Queue notification for an alert.
        
        Args:
            alert: Alert to notify about
        """
        notification = self._format_notification(alert)
        self.notification_queue.put(notification)
        
    def _format_notification(self, alert: Alert) -> Dict[str, Any]:
        """
        Format alert data for notification.
        
        Args:
            alert: Alert to format
            
        Returns:
            Formatted notification data
        """
        return {
            'type': 'alert',
            'alert_id': alert.id,
            'alert_type': alert.type.value,
            'priority': alert.priority.name,
            'message': alert.message,
            'source': alert.source,
            'timestamp': alert.timestamp,
            'status': alert.status.name,
            'details': alert.details
        }
        
    def get_client_list(self) -> List[Dict[str, Any]]:
        """
        Get list of connected clients.
        
        Returns:
            List of client information
        """
        clients = []
        for client_id, client in self.connected_clients.items():
            clients.append({
                'id': client_id,
                'name': client['name'],
                'connected_at': client['connected_at'],
                'uptime': time.time() - client['connected_at']
            })
        return clients


class WebUIConnector:
    """Connects to web user interfaces for alerts."""
    
    def __init__(self, ui_notifier: UINotifier, websocket_server=None):
        """
        Initialize Web UI connector.
        
        Args:
            ui_notifier: UI notifier instance
            websocket_server: Optional WebSocket server instance
        """
        self.ui_notifier = ui_notifier
        self.websocket_server = websocket_server
        self.logger = logging.getLogger('web_ui_connector')
        self.client_id = None
        
    def connect(self):
        """Connect to the UI notifier."""
        if not self.client_id:
            self.client_id = self.ui_notifier.connect_client(
                self._send_to_websocket, 
                "web_ui"
            )
            self.logger.info("Connected to UI notifier")
        
    def disconnect(self):
        """Disconnect from the UI notifier."""
        if self.client_id:
            self.ui_notifier.disconnect_client(self.client_id)
            self.client_id = None
            self.logger.info("Disconnected from UI notifier")
            
    def _send_to_websocket(self, notification: Dict[str, Any]):
        """
        Send notification to WebSocket clients.
        
        Args:
            notification: Notification data
        """
        if self.websocket_server:
            try:
                message = json.dumps(notification)
                self.websocket_server.broadcast(message)
            except Exception as e:
                self.logger.error(f"Error sending to WebSocket: {e}")
        else:
            self.logger.warning("WebSocket server not configured")
            
    def set_websocket_server(self, websocket_server):
        """
        Set WebSocket server.
        
        Args:
            websocket_server: WebSocket server instance
        """
        self.websocket_server = websocket_server
        self.logger.info("WebSocket server configured")


class DesktopNotifier:
    """Sends desktop notifications for alerts."""
    
    def __init__(self, ui_notifier: UINotifier):
        """
        Initialize desktop notifier.
        
        Args:
            ui_notifier: UI notifier instance
        """
        self.ui_notifier = ui_notifier
        self.logger = logging.getLogger('desktop_notifier')
        self.client_id = None
        
        # Try to import desktop notification libraries
        self.notifier_available = False
        try:
            # Try to import platform-specific modules
            import platform
            self.platform = platform.system()
            
            if self.platform == "Windows":
                from win10toast import ToastNotifier
                self.toaster = ToastNotifier()
                self.notifier_available = True
                
            elif self.platform == "Darwin":  # macOS
                import pync
                self.notifier_available = True
                
            elif self.platform == "Linux":
                import notify2
                notify2.init("ARP Guard")
                self.notifier_available = True
                
            self.logger.info(f"Desktop notifications enabled for {self.platform}")
            
        except ImportError as e:
            self.logger.warning(f"Desktop notification libraries not available: {e}")
            self.logger.info("Desktop notifications disabled")
            
    def connect(self):
        """Connect to the UI notifier."""
        if not self.client_id and self.notifier_available:
            self.client_id = self.ui_notifier.connect_client(
                self._send_desktop_notification, 
                "desktop_notifier"
            )
            self.logger.info("Connected to UI notifier")
        
    def disconnect(self):
        """Disconnect from the UI notifier."""
        if self.client_id:
            self.ui_notifier.disconnect_client(self.client_id)
            self.client_id = None
            self.logger.info("Disconnected from UI notifier")
            
    def _send_desktop_notification(self, notification: Dict[str, Any]):
        """
        Send desktop notification.
        
        Args:
            notification: Notification data
        """
        if not self.notifier_available:
            return
            
        # Only show notifications for high and critical alerts
        priority = notification.get('priority', '')
        if priority not in ['HIGH', 'CRITICAL']:
            return
            
        title = f"ARP Guard: {notification.get('alert_type', '').replace('_', ' ')} - {priority}"
        message = notification.get('message', '')
        
        try:
            if self.platform == "Windows":
                self.toaster.show_toast(
                    title,
                    message,
                    duration=5,
                    threaded=True
                )
                
            elif self.platform == "Darwin":  # macOS
                import pync
                pync.notify(
                    message,
                    title=title,
                    sound=True
                )
                
            elif self.platform == "Linux":
                import notify2
                n = notify2.Notification(title, message)
                if priority == "CRITICAL":
                    n.set_urgency(notify2.URGENCY_CRITICAL)
                n.show()
                
            self.logger.info(f"Sent desktop notification: {title}")
            
        except Exception as e:
            self.logger.error(f"Error sending desktop notification: {e}")


class MobileNotifier:
    """Sends mobile notifications for alerts."""
    
    def __init__(self, ui_notifier: UINotifier, fcm_key: str = None):
        """
        Initialize mobile notifier.
        
        Args:
            ui_notifier: UI notifier instance
            fcm_key: Firebase Cloud Messaging API key
        """
        self.ui_notifier = ui_notifier
        self.fcm_key = fcm_key
        self.logger = logging.getLogger('mobile_notifier')
        self.client_id = None
        self.registered_devices = {}
        
        # Check if Firebase library is available
        self.fcm_available = False
        try:
            import firebase_admin
            from firebase_admin import messaging
            self.firebase_admin = firebase_admin
            self.messaging = messaging
            
            if fcm_key:
                # Initialize Firebase if we have a key
                self.initialize_firebase(fcm_key)
            
        except ImportError as e:
            self.logger.warning(f"Firebase libraries not available: {e}")
            self.logger.info("Mobile notifications disabled")
            
    def initialize_firebase(self, fcm_key: str):
        """
        Initialize Firebase with the provided key.
        
        Args:
            fcm_key: Firebase Cloud Messaging API key
        """
        try:
            import firebase_admin
            from firebase_admin import credentials
            
            cred = credentials.Certificate(fcm_key)
            firebase_admin.initialize_app(cred)
            
            self.fcm_key = fcm_key
            self.fcm_available = True
            self.logger.info("Firebase initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing Firebase: {e}")
            
    def connect(self):
        """Connect to the UI notifier."""
        if not self.client_id and self.fcm_available:
            self.client_id = self.ui_notifier.connect_client(
                self._send_mobile_notification, 
                "mobile_notifier"
            )
            self.logger.info("Connected to UI notifier")
        
    def disconnect(self):
        """Disconnect from the UI notifier."""
        if self.client_id:
            self.ui_notifier.disconnect_client(self.client_id)
            self.client_id = None
            self.logger.info("Disconnected from UI notifier")
            
    def register_device(self, device_token: str, device_name: str = None):
        """
        Register a mobile device to receive notifications.
        
        Args:
            device_token: Firebase device token
            device_name: Optional name for the device
        """
        self.registered_devices[device_token] = {
            'name': device_name or f"device_{len(self.registered_devices) + 1}",
            'registered_at': time.time()
        }
        self.logger.info(f"Registered device: {device_name or device_token[:10]}...")
            
    def _send_mobile_notification(self, notification: Dict[str, Any]):
        """
        Send mobile notification to all registered devices.
        
        Args:
            notification: Notification data
        """
        if not self.fcm_available or not self.registered_devices:
            return
            
        # Only show notifications for high and critical alerts
        priority = notification.get('priority', '')
        if priority not in ['HIGH', 'CRITICAL']:
            return
            
        title = f"ARP Guard: {notification.get('alert_type', '').replace('_', ' ')} - {priority}"
        message = notification.get('message', '')
        
        try:
            for device_token in self.registered_devices:
                message_obj = self.messaging.Message(
                    notification=self.messaging.Notification(
                        title=title,
                        body=message
                    ),
                    data={
                        'alert_id': notification.get('alert_id', ''),
                        'alert_type': notification.get('alert_type', ''),
                        'priority': priority,
                        'source': notification.get('source', '')
                    },
                    token=device_token
                )
                
                response = self.messaging.send(message_obj)
                self.logger.info(f"Sent mobile notification: {response}")
                
        except Exception as e:
            self.logger.error(f"Error sending mobile notification: {e}")
            
    def get_registered_devices(self) -> List[Dict[str, Any]]:
        """
        Get list of registered devices.
        
        Returns:
            List of device information
        """
        devices = []
        for token, device in self.registered_devices.items():
            # Truncate token for security
            truncated_token = f"{token[:10]}...{token[-5:]}" if len(token) > 15 else token
            devices.append({
                'token': truncated_token,
                'name': device['name'],
                'registered_at': device['registered_at']
            })
        return devices 