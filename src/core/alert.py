from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import List, Dict, Any, Optional, Callable
import json
import logging
import uuid
import time
import threading

logger = logging.getLogger(__name__)

class AlertPriority(Enum):
    """Priority levels for alerts."""
    CRITICAL = auto()  # Critical alerts that require immediate attention
    HIGH = auto()      # High priority alerts that should be addressed soon
    MEDIUM = auto()    # Medium priority alerts
    LOW = auto()        # Low priority alerts
    INFO = auto()       # Informational alerts

class AlertType(Enum):
    """Types of alerts that can be generated."""
    SYSTEM = auto()         # System-related alerts
    RATE_ANOMALY = auto()   # Rate-based anomaly alerts
    PATTERN_MATCH = auto()  # Pattern matching alerts
    ARP_SPOOFING = auto()   # ARP spoofing alerts
    GATEWAY_CHANGE = auto() # Gateway MAC/IP change alerts
    NETWORK_SCAN = auto()   # Network scanning alerts
    CUSTOM = auto()         # Custom alert types

class AlertStatus(Enum):
    """Status of an alert."""
    NEW = auto()          # Newly created alert
    ACKNOWLEDGED = auto() # Alert has been acknowledged
    RESOLVED = auto()     # Alert has been resolved
    IGNORED = auto()      # Alert has been ignored
    CLOSED = auto()        # Alert has been closed

@dataclass
class Alert:
    """Represents an alert in the system."""
    id: str
    type: AlertType
    priority: AlertPriority
    message: str
    timestamp: float
    source: str
    details: Dict[str, Any] = field(default_factory=dict)
    status: AlertStatus = AlertStatus.NEW
    acknowledged_at: Optional[float] = None
    resolved_at: Optional[float] = None
    acknowledgement_message: Optional[str] = None
    resolution_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            "id": self.id,
            "type": self.type.value,
            "priority": self.priority.name,
            "message": self.message,
            "timestamp": self.timestamp,
            "source": self.source,
            "details": self.details,
            "status": self.status.name,
            "acknowledged_at": self.acknowledged_at,
            "resolved_at": self.resolved_at,
            "acknowledgement_message": self.acknowledgement_message,
            "resolution_message": self.resolution_message
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Alert':
        """Create alert from dictionary."""
        return cls(
            id=data["id"],
            type=AlertType(data["type"]),
            priority=AlertPriority(data["priority"]),
            message=data["message"],
            timestamp=data["timestamp"],
            source=data["source"],
            details=data["details"],
            status=AlertStatus(data["status"]),
            acknowledged_at=data["acknowledged_at"],
            resolved_at=data["resolved_at"],
            acknowledgement_message=data["acknowledgement_message"],
            resolution_message=data["resolution_message"]
        )

class AlertChannel:
    """Base class for alert notification channels."""
    
    def __init__(self, name: str, config: Dict[str, Any] = None):
        """
        Initialize alert channel.
        
        Args:
            name: Channel name
            config: Channel configuration
        """
        self.name = name
        self.config = config or {}
        self.enabled = True
    
    def send(self, alert: Alert) -> bool:
        """
        Send alert via this channel.
        
        Args:
            alert: Alert to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.enabled:
            return False
            
        try:
            success = self._send_alert(alert)
            if success:
                logger.info(f"Alert {alert.id} sent via {self.name} channel.")
            else:
                logger.warning(f"Failed to send alert {alert.id} via {self.name} channel.")
            return success
        except Exception as e:
            logger.error(f"Error sending alert {alert.id} via {self.name} channel: {e}")
            return False
    
    def _send_alert(self, alert: Alert) -> bool:
        """
        Implement this method in subclasses to send alert.
        
        Args:
            alert: Alert to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        raise NotImplementedError("Subclasses must implement this method")
    
    def enable(self) -> None:
        """Enable this channel."""
        self.enabled = True
    
    def disable(self) -> None:
        """Disable this channel."""
        self.enabled = False

class AlertManager:
    """
    Manages alerts and notifications across multiple channels.
    
    This class is responsible for:
    - Creating and storing alerts
    - Routing alerts to notification channels
    - Managing alert lifecycle (acknowledge, resolve, etc.)
    - Storing alert history
    """
    
    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialize alert manager.
        
        Args:
            storage_path: Path to store alerts. If None, alerts will only be kept in memory.
        """
        self.storage_path = storage_path
        self.channels: List[AlertChannel] = []
        self.alerts: Dict[str, Alert] = {}  # id -> Alert
        self.alert_filters: List[Callable[[Alert], bool]] = []
        self.max_alerts = 1000  # Maximum number of alerts to keep in memory
        
        # Callbacks
        self.on_alert_created: Optional[Callable[[Alert], None]] = None
        self.on_alert_updated: Optional[Callable[[Alert], None]] = None
        
        # Thread safety
        self.lock = threading.Lock()
    
    def add_channel(self, channel: AlertChannel) -> None:
        """
        Add a notification channel.
        
        Args:
            channel: Channel to add
        """
        with self.lock:
            self.channels.append(channel)
        logger.info(f"Added {channel.name} notification channel.")
    
    def remove_channel(self, channel_name: str) -> bool:
        """
        Remove a notification channel by name.
        
        Args:
            channel_name: Name of channel to remove
            
        Returns:
            True if channel was removed, False if not found
        """
        with self.lock:
            for i, channel in enumerate(self.channels):
                if channel.name == channel_name:
                    del self.channels[i]
                    logger.info(f"Removed {channel_name} notification channel.")
                    return True
                    
        logger.warning(f"Channel {channel_name} not found, cannot remove.")
        return False
    
    def add_filter(self, filter_func: Callable[[Alert], bool]) -> None:
        """
        Add a filter function to determine if an alert should be sent.
        
        Args:
            filter_func: Function that takes an Alert and returns True if 
                        the alert should be sent, False otherwise
        """
        with self.lock:
            self.alert_filters.append(filter_func)
    
    def create_alert(
        self, 
        alert_type: AlertType, 
        priority: AlertPriority, 
        message: str, 
        source: str = "system", 
        details: Dict[str, Any] = None
    ) -> Alert:
        """
        Create a new alert and send notifications.
        
        Args:
            alert_type: Type of alert
            priority: Alert priority
            message: Alert message
            source: Source of the alert
            details: Additional details
            
        Returns:
            The created alert
        """
        # Create alert
        alert_id = str(uuid.uuid4())
        alert = Alert(
            id=alert_id,
            type=alert_type,
            priority=priority,
            message=message,
            timestamp=time.time(),
            source=source,
            details=details or {},
            status=AlertStatus.NEW
        )
        
        # Apply filters
        if not all(filter_func(alert) for filter_func in self.alert_filters):
            logger.info(f"Alert filtered out: {message}")
            return alert
        
        # Store alert
        with self.lock:
            self.alerts[alert_id] = alert
            
            # Trim if too many alerts
            if len(self.alerts) > self.max_alerts:
                # Remove oldest alerts
                oldest_ids = sorted(
                    self.alerts.keys(), 
                    key=lambda aid: self.alerts[aid].timestamp
                )[:len(self.alerts) - self.max_alerts]
                
                for old_id in oldest_ids:
                    del self.alerts[old_id]
        
        # Send notifications
        self._notify_channels(alert)
        
        # Call callback if set
        if self.on_alert_created:
            try:
                self.on_alert_created(alert)
            except Exception as e:
                logger.error(f"Error in on_alert_created callback: {e}")
        
        logger.info(f"Created alert {alert_id}: {message}")
        return alert
    
    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """
        Get an alert by ID.
        
        Args:
            alert_id: Alert ID
            
        Returns:
            The alert if found, None otherwise
        """
        with self.lock:
            return self.alerts.get(alert_id)
    
    def acknowledge_alert(
        self, 
        alert_id: str, 
        message: Optional[str] = None
    ) -> bool:
        """
        Acknowledge an alert.
        
        Args:
            alert_id: Alert ID
            message: Optional acknowledgement message
            
        Returns:
            True if alert was acknowledged, False if not found
        """
        with self.lock:
            alert = self.alerts.get(alert_id)
            if not alert:
                return False
                
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_at = time.time()
            alert.acknowledgement_message = message
        
        # Call callback if set
        if self.on_alert_updated:
            try:
                self.on_alert_updated(alert)
            except Exception as e:
                logger.error(f"Error in on_alert_updated callback: {e}")
                
        logger.info(f"Acknowledged alert {alert_id}")
        return True
    
    def resolve_alert(
        self, 
        alert_id: str, 
        message: Optional[str] = None
    ) -> bool:
        """
        Resolve an alert.
        
        Args:
            alert_id: Alert ID
            message: Optional resolution message
            
        Returns:
            True if alert was resolved, False if not found
        """
        with self.lock:
            alert = self.alerts.get(alert_id)
            if not alert:
                return False
                
            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = time.time()
            alert.resolution_message = message
        
        # Call callback if set
        if self.on_alert_updated:
            try:
                self.on_alert_updated(alert)
            except Exception as e:
                logger.error(f"Error in on_alert_updated callback: {e}")
                
        logger.info(f"Resolved alert {alert_id}")
        return True
    
    def get_alerts(
        self, 
        status: Optional[AlertStatus] = None, 
        alert_type: Optional[AlertType] = None,
        priority: Optional[AlertPriority] = None,
        source: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        limit: Optional[int] = None
    ) -> List[Alert]:
        """
        Get alerts with optional filtering.
        
        Args:
            status: Filter by status
            alert_type: Filter by type
            priority: Filter by priority
            source: Filter by source
            start_time: Filter by start time
            end_time: Filter by end time
            limit: Limit number of results
            
        Returns:
            List of alerts matching filters
        """
        with self.lock:
            # Start with all alerts
            alerts = list(self.alerts.values())
            
            # Apply filters
            if status:
                alerts = [a for a in alerts if a.status == status]
                
            if alert_type:
                alerts = [a for a in alerts if a.type == alert_type]
                
            if priority:
                alerts = [a for a in alerts if a.priority == priority]
                
            if source:
                alerts = [a for a in alerts if a.source == source]
                
            if start_time:
                alerts = [a for a in alerts if a.timestamp >= start_time]
                
            if end_time:
                alerts = [a for a in alerts if a.timestamp <= end_time]
                
            # Sort by timestamp (newest first)
            alerts.sort(key=lambda a: a.timestamp, reverse=True)
            
            # Apply limit
            if limit and limit > 0:
                alerts = alerts[:limit]
                
            return alerts
    
    def _notify_channels(self, alert: Alert) -> None:
        """
        Send alert to all enabled channels.
        
        Args:
            alert: Alert to send
        """
        for channel in self.channels:
            try:
                channel.send(alert)
            except Exception as e:
                logger.error(f"Error sending alert to channel {channel.name}: {e}")
    
    def save_alerts(self) -> bool:
        """
        Save alerts to storage.
        
        Returns:
            True if successful, False otherwise
        """
        # To be implemented in a future update
        return False
    
    def load_alerts(self) -> bool:
        """
        Load alerts from storage.
        
        Returns:
            True if successful, False otherwise
        """
        # To be implemented in a future update
        return False
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get status information about the alert manager.
        
        Returns:
            Dictionary with status information
        """
        with self.lock:
            total_alerts = len(self.alerts)
            
            # Count alerts by status
            status_counts = {}
            for status in AlertStatus:
                status_counts[status.name] = sum(1 for a in self.alerts.values() if a.status == status)
                
            # Count alerts by type
            type_counts = {}
            for atype in AlertType:
                type_counts[atype.name] = sum(1 for a in self.alerts.values() if a.type == atype)
                
            # Count alerts by priority
            priority_counts = {}
            for priority in AlertPriority:
                priority_counts[priority.name] = sum(1 for a in self.alerts.values() if a.priority == priority)
                
            # Get active channels
            active_channels = [channel.name for channel in self.channels if channel.enabled]
            
            return {
                "total_alerts": total_alerts,
                "status_counts": status_counts,
                "type_counts": type_counts,
                "priority_counts": priority_counts,
                "active_channels": active_channels,
                "storage_path": self.storage_path,
                "max_alerts": self.max_alerts
            } 