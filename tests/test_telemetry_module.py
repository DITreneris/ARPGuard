#!/usr/bin/env python3
"""
Unit tests for the Telemetry Module
"""

import os
import json
import time
import shutil
import unittest
import tempfile
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.telemetry_module import TelemetryModule, TelemetryModuleConfig, TelemetryEvent


class TestTelemetryModule(unittest.TestCase):
    """Test cases for the Telemetry Module"""

    def setUp(self):
        """Set up test environment"""
        # Create a temporary directory for telemetry storage
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test configuration
        self.config = TelemetryModuleConfig(
            enabled=False,  # Start with telemetry disabled
            anonymize_data=True,
            storage_path=self.temp_dir,
            collection_interval=60,  # 1 minute for testing
            storage_retention_days=1,  # 1 day for testing
            max_events_per_batch=10
        )
        
        # Create telemetry module with test configuration
        self.telemetry = TelemetryModule(self.config)
        
        # Initialize the module
        self.telemetry.initialize()

    def tearDown(self):
        """Clean up after tests"""
        # Shutdown telemetry module
        if hasattr(self, 'telemetry'):
            self.telemetry.shutdown()
        
        # Remove temporary directory
        if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_initialization(self):
        """Test module initialization"""
        # Verify that temporary directory was created
        self.assertTrue(os.path.exists(self.temp_dir))
        
        # Verify installation ID file was created
        installation_file = os.path.join(self.temp_dir, "installation_id.json")
        self.assertTrue(os.path.exists(installation_file))
        
        # Verify installation ID was generated
        with open(installation_file, 'r') as f:
            data = json.load(f)
            self.assertIn("installation_id", data)
            self.assertEqual(self.telemetry.installation_id, data["installation_id"])

    def test_enable_disable_telemetry(self):
        """Test enabling and disabling telemetry"""
        # Initially disabled
        self.assertFalse(self.telemetry.config.enabled)
        
        # Enable telemetry
        result = self.telemetry.enable_telemetry()
        self.assertTrue(result)
        self.assertTrue(self.telemetry.config.enabled)
        
        # Try to enable again (should return True but not change state)
        result = self.telemetry.enable_telemetry()
        self.assertTrue(result)
        self.assertTrue(self.telemetry.config.enabled)
        
        # Disable telemetry
        result = self.telemetry.disable_telemetry()
        self.assertTrue(result)
        self.assertFalse(self.telemetry.config.enabled)
        
        # Try to disable again (should return True but not change state)
        result = self.telemetry.disable_telemetry()
        self.assertTrue(result)
        self.assertFalse(self.telemetry.config.enabled)

    def test_event_tracking(self):
        """Test tracking telemetry events"""
        # Enable telemetry
        self.telemetry.enable_telemetry()
        
        # Note: Enabling telemetry automatically tracks an app_start event,
        # so we're starting with 1 event already
        
        # Track an event
        event_type = "test_event"
        properties = {"test_key": "test_value"}
        
        # Add event type to allowed events if not already included
        if event_type not in self.telemetry.config.allowed_event_types:
            self.telemetry.config.allowed_event_types.add(event_type)
        
        result = self.telemetry.track_event(event_type, properties)
        self.assertTrue(result)
        
        # Verify event was added to the queue (expect 2 events: app_start + our test event)
        self.assertEqual(len(self.telemetry.events), 2)
        
        # Find our test event
        test_events = [e for e in self.telemetry.events if e.event_type == event_type]
        self.assertEqual(len(test_events), 1)
        
        event = test_events[0]
        self.assertEqual(event.event_type, event_type)
        self.assertIn("test_key", event.properties)
        self.assertEqual(event.properties["test_key"], "test_value")
        
        # Disable telemetry and try to track another event
        self.telemetry.disable_telemetry()
        result = self.telemetry.track_event(event_type, properties)
        self.assertFalse(result)
        
        # Verify no new event was added
        self.assertEqual(len(self.telemetry.events), 0)  # Events are cleared when disabled

    def test_event_saving(self):
        """Test saving events to disk"""
        # Enable telemetry
        self.telemetry.enable_telemetry()
        
        # Note: Enabling telemetry automatically tracks an app_start event,
        # so we're starting with 1 event already
        
        # Track multiple events
        event_type = "test_event"
        if event_type not in self.telemetry.config.allowed_event_types:
            self.telemetry.config.allowed_event_types.add(event_type)
        
        for i in range(5):
            self.telemetry.track_event(event_type, {"index": i})
        
        # Verify events are in memory (5 test events + 1 app_start event)
        self.assertEqual(len(self.telemetry.events), 6)
        
        # Manually save events
        self.telemetry._save_events()
        
        # Verify events were cleared from memory
        self.assertEqual(len(self.telemetry.events), 0)
        
        # Find saved event file
        event_files = [f for f in os.listdir(self.temp_dir) 
                      if f.startswith("events_") and f.endswith(".json")]
        self.assertEqual(len(event_files), 1)
        
        # Check file contents
        with open(os.path.join(self.temp_dir, event_files[0]), 'r') as f:
            data = json.load(f)
            self.assertIn("events", data)
            self.assertEqual(len(data["events"]), 6)  # 5 test events + 1 app_start event
            
            # Find our test events
            test_events = [e for e in data["events"] if e["event_type"] == event_type]
            self.assertEqual(len(test_events), 5)
            
            # Check index values
            indices = sorted([e["properties"]["index"] for e in test_events])
            self.assertEqual(indices, [0, 1, 2, 3, 4])

    def test_status_reporting(self):
        """Test getting telemetry status"""
        # Initialize with some events
        self.telemetry.enable_telemetry()
        
        # Note: Enabling telemetry automatically tracks an app_start event,
        # so we're starting with 1 event already
        
        event_type = "test_event"
        if event_type not in self.telemetry.config.allowed_event_types:
            self.telemetry.config.allowed_event_types.add(event_type)
        
        for i in range(3):
            self.telemetry.track_event(event_type, {"index": i})
        
        # Get status (expect 4 events: 1 app_start + 3 test events)
        status = self.telemetry.get_telemetry_status()
        
        # Verify status fields
        self.assertTrue(status["enabled"])
        self.assertTrue(status["anonymize_data"])
        self.assertEqual(status["pending_events"], 4)  # 3 test events + 1 app_start event
        self.assertEqual(status["saved_event_files"], 0)
        
        # Save events and check status again
        self.telemetry._save_events()
        status = self.telemetry.get_telemetry_status()
        self.assertEqual(status["pending_events"], 0)
        self.assertEqual(status["saved_event_files"], 1)

    def test_data_cleanup(self):
        """Test cleanup of old telemetry data"""
        # Create some event files with old timestamps
        event_file_old = os.path.join(self.temp_dir, "events_123456789.json")
        with open(event_file_old, 'w') as f:
            json.dump({"events": []}, f)
        
        # Modify the file time to be older than retention period
        old_time = time.time() - (self.config.storage_retention_days * 86400 + 3600)
        os.utime(event_file_old, (old_time, old_time))
        
        # Create a newer file
        event_file_new = os.path.join(self.temp_dir, "events_987654321.json")
        with open(event_file_new, 'w') as f:
            json.dump({"events": []}, f)
        
        # Run cleanup
        self.telemetry._cleanup_old_data()
        
        # Verify old file was removed but new file remains
        self.assertFalse(os.path.exists(event_file_old))
        self.assertTrue(os.path.exists(event_file_new))

    def test_data_deletion(self):
        """Test complete deletion of telemetry data"""
        # Create some event files
        for i in range(3):
            event_file = os.path.join(self.temp_dir, f"events_{i}.json")
            with open(event_file, 'w') as f:
                json.dump({"events": []}, f)
        
        # Add some events in memory
        self.telemetry.enable_telemetry()
        event_type = "test_event"
        if event_type not in self.telemetry.config.allowed_event_types:
            self.telemetry.config.allowed_event_types.add(event_type)
        
        self.telemetry.track_event(event_type, {"test": True})
        
        # Delete all data
        result = self.telemetry.delete_all_telemetry_data()
        self.assertTrue(result)
        
        # Verify all files are gone
        event_files = [f for f in os.listdir(self.temp_dir) 
                      if f.startswith("events_")]
        self.assertEqual(len(event_files), 0)
        
        # Verify memory events are cleared
        self.assertEqual(len(self.telemetry.events), 0)

    @patch('threading.Thread')
    def test_collection_thread(self, mock_thread):
        """Test the collection thread lifecycle"""
        # Mock the thread to avoid actual background processing
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance
        
        # Enable telemetry and verify thread is started
        self.telemetry.enable_telemetry()
        mock_thread.assert_called_once()
        mock_thread_instance.start.assert_called_once()
        
        # Disable telemetry and verify thread is stopped
        self.telemetry.disable_telemetry()
        mock_thread_instance.join.assert_called_once()

    def test_event_handlers(self):
        """Test event handler registration and notification"""
        # Create a mock handler
        mock_handler = MagicMock()
        
        # Register the handler
        event_type = "test_event"
        self.telemetry.register_event_handler(event_type, mock_handler)
        
        # Enable telemetry and track an event
        self.telemetry.enable_telemetry()
        if event_type not in self.telemetry.config.allowed_event_types:
            self.telemetry.config.allowed_event_types.add(event_type)
        
        self.telemetry.track_event(event_type, {"test": True})
        
        # Verify handler was called
        mock_handler.assert_called_once()
        event = mock_handler.call_args[0][0]
        self.assertEqual(event.event_type, event_type)
        self.assertTrue(event.properties["test"])


if __name__ == "__main__":
    unittest.main() 