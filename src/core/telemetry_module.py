#!/usr/bin/env python3
"""
Telemetry Module for ARP Guard
Provides opt-in telemetry collection functionality for usage tracking and conversion analysis
"""

import os
import json
import uuid
import time
import logging
import threading
import platform
import tempfile
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass, field, asdict

from .module_interface import Module, ModuleConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
DEFAULT_COLLECTION_INTERVAL = 24 * 60 * 60  # 24 hours in seconds
DEFAULT_STORAGE_RETENTION = 30  # days


@dataclass
class TelemetryEvent:
    """Class representing a telemetry event"""
    event_type: str
    timestamp: float = field(default_factory=time.time)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    properties: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp).isoformat(),
            "properties": self.properties
        }


@dataclass
class TelemetryModuleConfig(ModuleConfig):
    """Configuration for telemetry module"""
    enabled: bool = False  # Telemetry is opt-in by default
    anonymize_data: bool = True
    collection_interval: int = DEFAULT_COLLECTION_INTERVAL
    storage_path: str = field(default_factory=lambda: os.path.join(tempfile.gettempdir(), "arpguard_telemetry"))
    storage_retention_days: int = DEFAULT_STORAGE_RETENTION
    upload_url: Optional[str] = None
    max_events_per_batch: int = 100
    allowed_event_types: Set[str] = field(default_factory=lambda: {
        "app_start",
        "app_stop",
        "feature_usage",
        "detection_run",
        "alert_generated",
        "error",
        "config_change"
    })
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = asdict(self)
        # Convert set to list for JSON serialization
        result["allowed_event_types"] = list(self.allowed_event_types)
        return result


class TelemetryModule(Module):
    """Module for collecting and managing telemetry data"""
    
    def __init__(self, config: Optional[TelemetryModuleConfig] = None):
        """
        Initialize telemetry module
        
        Args:
            config: Configuration for the telemetry module
        """
        # Create config if not provided
        config = config or TelemetryModuleConfig()
        
        # Initialize with a fixed module_id and name
        self.module_id = "telemetry"
        self.name = "Telemetry Module"
        self.config = config
        
        # Base class initialization with correct parameters
        # This is commented out to avoid the issue
        # super().__init__(module_id="telemetry", name="Telemetry Module", config=config)
        
        self.events: List[TelemetryEvent] = []
        self.installation_id: Optional[str] = None
        self.start_time: float = time.time()
        self.lock = threading.Lock()
        self.upload_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.event_handlers: Dict[str, List[Callable[[TelemetryEvent], None]]] = {}
        
        # For compatibility with CLI commands
        self.is_enabled = config.enabled
        self.collection_interval = config.collection_interval // 60  # Convert to minutes
        self.last_collection = "Never"
        self.data_points_collected = 0
    
    def initialize(self) -> bool:
        """
        Initialize the telemetry module
        
        Returns:
            True if initialized successfully
        """
        logger.info("Initializing telemetry module")
        
        # Create storage directory if it doesn't exist
        if not os.path.exists(self.config.storage_path):
            try:
                os.makedirs(self.config.storage_path, exist_ok=True)
                logger.info(f"Created telemetry storage directory: {self.config.storage_path}")
            except Exception as e:
                logger.error(f"Failed to create telemetry storage directory: {e}")
                return False
        
        # Load or generate installation ID
        self._load_or_generate_installation_id()
        
        # Log telemetry status
        if self.config.enabled:
            logger.info("Telemetry collection is enabled")
            # Start collection thread if enabled
            self._start_collection_thread()
        else:
            logger.info("Telemetry collection is disabled (opt-in required)")
        
        # Track initialization event
        self.track_event("app_start", {
            "version": "1.0.0",  # Replace with actual version
            "platform": platform.platform(),
            "python_version": platform.python_version()
        })
        
        return True
    
    def shutdown(self) -> bool:
        """
        Shutdown the telemetry module
        
        Returns:
            True if shutdown successfully
        """
        logger.info("Shutting down telemetry module")
        
        # Track shutdown event
        self.track_event("app_stop", {
            "uptime_seconds": time.time() - self.start_time
        })
        
        # Stop collection thread
        if self.upload_thread and self.upload_thread.is_alive():
            self.stop_event.set()
            self.upload_thread.join(timeout=2.0)
        
        # Save any pending events
        self._save_events()
        
        return True
    
    def track_event(self, event_type: str, properties: Optional[Dict[str, Any]] = None) -> bool:
        """
        Track a telemetry event
        
        Args:
            event_type: Type of event
            properties: Event properties
            
        Returns:
            True if event was tracked
        """
        # Don't track if telemetry is disabled
        if not self.config.enabled:
            return False
        
        # Check if event type is allowed
        if event_type not in self.config.allowed_event_types:
            logger.warning(f"Event type not allowed: {event_type}")
            return False
        
        # Create event
        event = TelemetryEvent(
            event_type=event_type,
            properties=properties or {}
        )
        
        # Add common properties
        if self.config.anonymize_data:
            event.properties["installation_id"] = self.installation_id
        
        # Add to events list with thread safety
        with self.lock:
            self.events.append(event)
        
        # Notify event handlers
        self._notify_event_handlers(event)
        
        return True
    
    def register_event_handler(self, event_type: str, handler: Callable[[TelemetryEvent], None]) -> None:
        """
        Register a handler for a specific event type
        
        Args:
            event_type: Type of event to handle
            handler: Handler function
        """
        with self.lock:
            if event_type not in self.event_handlers:
                self.event_handlers[event_type] = []
            self.event_handlers[event_type].append(handler)
    
    def _notify_event_handlers(self, event: TelemetryEvent) -> None:
        """Notify all handlers for an event"""
        handlers = []
        with self.lock:
            if event.event_type in self.event_handlers:
                handlers = self.event_handlers[event.event_type].copy()
        
        for handler in handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Error in telemetry event handler: {e}")
    
    def _load_or_generate_installation_id(self) -> None:
        """Load existing installation ID or generate a new one"""
        installation_file = os.path.join(self.config.storage_path, "installation_id.json")
        
        if os.path.exists(installation_file):
            try:
                with open(installation_file, 'r') as f:
                    data = json.load(f)
                    self.installation_id = data.get("installation_id")
                logger.info(f"Loaded installation ID: {self.installation_id}")
            except Exception as e:
                logger.error(f"Error loading installation ID: {e}")
                self.installation_id = str(uuid.uuid4())
        
        # Generate new ID if not found
        if not self.installation_id:
            self.installation_id = str(uuid.uuid4())
            logger.info(f"Generated new installation ID: {self.installation_id}")
            
            # Save to file
            try:
                with open(installation_file, 'w') as f:
                    json.dump({"installation_id": self.installation_id}, f)
            except Exception as e:
                logger.error(f"Error saving installation ID: {e}")
    
    def _start_collection_thread(self) -> None:
        """Start the background thread for telemetry collection"""
        if self.upload_thread and self.upload_thread.is_alive():
            return
        
        self.stop_event.clear()
        self.upload_thread = threading.Thread(
            target=self._collection_loop,
            daemon=True
        )
        self.upload_thread.start()
        logger.info("Started telemetry collection thread")
    
    def _collection_loop(self) -> None:
        """Background loop for periodic telemetry processing"""
        last_save_time = time.time()
        last_upload_time = time.time()
        last_cleanup_time = time.time()
        
        while not self.stop_event.is_set():
            current_time = time.time()
            
            # Save events every hour
            if current_time - last_save_time > 3600:
                self._save_events()
                last_save_time = current_time
            
            # Upload events based on collection interval
            if current_time - last_upload_time > self.config.collection_interval:
                self._upload_events()
                last_upload_time = current_time
            
            # Clean up old data once a day
            if current_time - last_cleanup_time > 86400:
                self._cleanup_old_data()
                last_cleanup_time = current_time
            
            # Sleep for a while to reduce CPU usage
            time.sleep(60)  # Check every minute
    
    def _save_events(self) -> None:
        """Save current events to disk"""
        if not self.events:
            return
        
        # Create filename with timestamp
        filename = os.path.join(
            self.config.storage_path,
            f"events_{int(time.time())}.json"
        )
        
        # Copy events with thread safety
        with self.lock:
            events_to_save = [event.to_dict() for event in self.events]
            self.events = []
        
        # Save to file
        try:
            with open(filename, 'w') as f:
                json.dump({
                    "saved_at": datetime.now().isoformat(),
                    "installation_id": self.installation_id,
                    "events": events_to_save
                }, f, indent=2)
            logger.info(f"Saved {len(events_to_save)} telemetry events to {filename}")
        except Exception as e:
            logger.error(f"Error saving telemetry events: {e}")
    
    def _upload_events(self) -> None:
        """Upload saved events to the telemetry service"""
        if not self.config.upload_url:
            logger.debug("No upload URL configured, skipping upload")
            return
        
        # Find event files
        try:
            files = [f for f in os.listdir(self.config.storage_path) 
                   if f.startswith("events_") and f.endswith(".json")]
        except Exception as e:
            logger.error(f"Error listing telemetry files: {e}")
            return
        
        if not files:
            return
        
        # Process each file
        for filename in files:
            full_path = os.path.join(self.config.storage_path, filename)
            try:
                # Load events
                with open(full_path, 'r') as f:
                    data = json.load(f)
                
                # Upload data
                logger.info(f"Would upload {len(data['events'])} events to {self.config.upload_url}")
                # In a real implementation, this would use requests or similar to upload
                # For now, we'll just simulate success
                
                # On successful upload, rename the file to mark as uploaded
                os.rename(full_path, full_path + ".uploaded")
                logger.info(f"Marked {filename} as uploaded")
                
            except Exception as e:
                logger.error(f"Error processing telemetry file {filename}: {e}")
    
    def _cleanup_old_data(self) -> None:
        """Remove old telemetry data beyond retention period"""
        try:
            retention_period = timedelta(days=self.config.storage_retention_days)
            cutoff_time = time.time() - retention_period.total_seconds()
            
            files = os.listdir(self.config.storage_path)
            for filename in files:
                if not (filename.startswith("events_") and 
                       (filename.endswith(".json") or filename.endswith(".json.uploaded"))):
                    continue
                
                full_path = os.path.join(self.config.storage_path, filename)
                file_time = os.path.getmtime(full_path)
                
                if file_time < cutoff_time:
                    os.remove(full_path)
                    logger.info(f"Removed old telemetry file: {filename}")
            
        except Exception as e:
            logger.error(f"Error cleaning up old telemetry data: {e}")
    
    def enable_telemetry(self) -> bool:
        """
        Enable telemetry collection
        
        Returns:
            True if successfully enabled
        """
        if self.config.enabled:
            logger.info("Telemetry is already enabled")
            return True
        
        # Update config
        self.config.enabled = True
        
        # Start collection thread
        self._start_collection_thread()
        
        # Log event
        logger.info("Telemetry collection enabled")
        
        # Track opt-in event
        self.track_event("config_change", {
            "setting": "telemetry_enabled",
            "value": True
        })
        
        return True
    
    def disable_telemetry(self) -> bool:
        """
        Disable telemetry collection
        
        Returns:
            True if successfully disabled
        """
        if not self.config.enabled:
            logger.info("Telemetry is already disabled")
            return True
        
        # Track opt-out event before disabling
        self.track_event("config_change", {
            "setting": "telemetry_enabled",
            "value": False
        })
        
        # Update config
        self.config.enabled = False
        
        # Stop collection thread
        if self.upload_thread and self.upload_thread.is_alive():
            self.stop_event.set()
            self.upload_thread.join(timeout=2.0)
            self.upload_thread = None
        
        # Save any pending events
        self._save_events()
        
        logger.info("Telemetry collection disabled")
        return True
    
    def get_telemetry_status(self) -> Dict[str, Any]:
        """
        Get current telemetry status
        
        Returns:
            Status dictionary
        """
        # Count saved event files
        event_files = []
        event_count = 0
        
        try:
            event_files = [f for f in os.listdir(self.config.storage_path) 
                         if f.startswith("events_") and f.endswith(".json")]
            
            # Get event count from the most recent file
            if event_files:
                newest_file = max(event_files, key=lambda f: os.path.getmtime(
                    os.path.join(self.config.storage_path, f)))
                
                with open(os.path.join(self.config.storage_path, newest_file), 'r') as f:
                    data = json.load(f)
                    event_count = len(data.get("events", []))
        except Exception as e:
            logger.error(f"Error getting telemetry stats: {e}")
        
        return {
            "enabled": self.config.enabled,
            "anonymize_data": self.config.anonymize_data,
            "installation_id": self.installation_id if not self.config.anonymize_data else "anonymized",
            "uptime_days": (time.time() - self.start_time) / 86400,
            "collection_interval_hours": self.config.collection_interval / 3600,
            "storage_path": self.config.storage_path,
            "storage_retention_days": self.config.storage_retention_days,
            "pending_events": len(self.events),
            "saved_event_files": len(event_files),
            "last_file_event_count": event_count,
            "upload_url": self.config.upload_url or "not configured"
        }
    
    def delete_all_telemetry_data(self) -> bool:
        """
        Delete all collected telemetry data
        
        Returns:
            True if successful
        """
        try:
            # Delete all event files
            files = os.listdir(self.config.storage_path)
            deleted_count = 0
            
            for filename in files:
                if filename.startswith("events_"):
                    os.remove(os.path.join(self.config.storage_path, filename))
                    deleted_count += 1
            
            # Clear pending events
            with self.lock:
                self.events = []
            
            logger.info(f"Deleted {deleted_count} telemetry files and cleared pending events")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting telemetry data: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """
        Get the current telemetry status.
        
        Returns:
            Dictionary with telemetry status
        """
        return {
            "enabled": self.is_enabled,
            "collection_interval": self.collection_interval,
            "last_collection": self.last_collection,
            "data_points": self.data_points_collected,
            "installation_id": self.installation_id
        }

    def enable(self) -> bool:
        """
        Enable telemetry collection.
        
        Returns:
            True if enabled successfully
        """
        # Call the existing method
        result = self.enable_telemetry()
        if result:
            self.is_enabled = True
        return result

    def disable(self) -> bool:
        """
        Disable telemetry collection.
        
        Returns:
            True if disabled successfully
        """
        # Call the existing method
        result = self.disable_telemetry()
        if result:
            self.is_enabled = False
        return result 