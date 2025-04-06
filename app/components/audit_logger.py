import json
import time
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum
from pathlib import Path

from app.utils.logger import get_logger

# Module logger
logger = get_logger('components.audit_logger')

class AuditEventType(Enum):
    """Types of audit events."""
    # Authentication events
    LOGIN = 'login'
    LOGOUT = 'logout'
    LOGIN_FAILED = 'login_failed'
    
    # User management events
    USER_CREATED = 'user_created'
    USER_DELETED = 'user_deleted'
    USER_ROLE_CHANGED = 'user_role_changed'
    USER_SITES_CHANGED = 'user_sites_changed'
    
    # Site management events
    SITE_CONNECTED = 'site_connected'
    SITE_DISCONNECTED = 'site_disconnected'
    SITE_STATUS_CHANGED = 'site_status_changed'
    
    # Network operations
    NETWORK_SCAN_STARTED = 'network_scan_started'
    NETWORK_SCAN_COMPLETED = 'network_scan_completed'
    DETECTION_STARTED = 'detection_started'
    DETECTION_STOPPED = 'detection_stopped'
    SPOOFING_STARTED = 'spoofing_started'
    SPOOFING_STOPPED = 'spoofing_stopped'
    
    # Configuration changes
    CONFIG_CHANGED = 'config_changed'
    
    # Security events
    THREAT_DETECTED = 'threat_detected'
    ALERT_GENERATED = 'alert_generated'
    COMMAND_EXECUTED = 'command_executed'

class AuditLogger:
    """Audit logging system for tracking security operations."""
    
    def __init__(self, log_dir: str = 'logs/audit'):
        """Initialize the audit logger.
        
        Args:
            log_dir: Directory to store audit logs
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Current log file
        self.current_log = self._get_log_file()
        logger.info(f"Audit logging initialized in {self.log_dir}")
    
    def _get_log_file(self) -> Path:
        """Get the current log file path.
        
        Returns:
            Path: Path to the current log file
        """
        date_str = datetime.now().strftime('%Y-%m-%d')
        return self.log_dir / f'audit_{date_str}.log'
    
    def _write_log(self, event: Dict[str, Any]):
        """Write an audit event to the log file.
        
        Args:
            event: Event data to log
        """
        # Check if we need to rotate the log file
        current_log = self._get_log_file()
        if current_log != self.current_log:
            self.current_log = current_log
        
        # Add timestamp if not present
        if 'timestamp' not in event:
            event['timestamp'] = datetime.now().isoformat()
        
        # Write to log file
        try:
            with open(self.current_log, 'a') as f:
                f.write(json.dumps(event) + '\n')
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
    
    def log_event(self, event_type: AuditEventType, username: str, 
                 details: Optional[Dict[str, Any]] = None, 
                 site_id: Optional[str] = None):
        """Log an audit event.
        
        Args:
            event_type: Type of event
            username: Username of the user performing the action
            details: Optional additional details about the event
            site_id: Optional site ID if the event is site-specific
        """
        event = {
            'type': event_type.value,
            'username': username,
            'details': details or {},
            'site_id': site_id
        }
        
        self._write_log(event)
        logger.info(f"Audit event logged: {event_type.value} by {username}")
    
    def get_events(self, start_time: Optional[datetime] = None,
                  end_time: Optional[datetime] = None,
                  event_type: Optional[AuditEventType] = None,
                  username: Optional[str] = None,
                  site_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get audit events matching the specified criteria.
        
        Args:
            start_time: Optional start time to filter events
            end_time: Optional end time to filter events
            event_type: Optional event type to filter
            username: Optional username to filter
            site_id: Optional site ID to filter
            
        Returns:
            List[Dict[str, Any]]: List of matching audit events
        """
        events = []
        
        # Get all log files in the date range
        log_files = []
        if start_time and end_time:
            current_date = start_time
            while current_date <= end_time:
                log_file = self.log_dir / f'audit_{current_date.strftime("%Y-%m-%d")}.log'
                if log_file.exists():
                    log_files.append(log_file)
                current_date = current_date.replace(day=current_date.day + 1)
        else:
            log_files = list(self.log_dir.glob('audit_*.log'))
        
        # Read and filter events
        for log_file in log_files:
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        event = json.loads(line)
                        
                        # Apply filters
                        if start_time and datetime.fromisoformat(event['timestamp']) < start_time:
                            continue
                        if end_time and datetime.fromisoformat(event['timestamp']) > end_time:
                            continue
                        if event_type and event['type'] != event_type.value:
                            continue
                        if username and event['username'] != username:
                            continue
                        if site_id and event.get('site_id') != site_id:
                            continue
                        
                        events.append(event)
            except Exception as e:
                logger.error(f"Error reading log file {log_file}: {e}")
        
        return events
    
    def clear_events(self, before: Optional[datetime] = None):
        """Clear audit events older than the specified date.
        
        Args:
            before: Optional date to clear events before
        """
        if not before:
            # Clear all events
            for log_file in self.log_dir.glob('audit_*.log'):
                try:
                    log_file.unlink()
                except Exception as e:
                    logger.error(f"Error deleting log file {log_file}: {e}")
        else:
            # Clear events before the specified date
            for log_file in self.log_dir.glob('audit_*.log'):
                try:
                    file_date = datetime.strptime(log_file.stem.split('_')[1], '%Y-%m-%d')
                    if file_date < before:
                        log_file.unlink()
                except Exception as e:
                    logger.error(f"Error deleting log file {log_file}: {e}") 