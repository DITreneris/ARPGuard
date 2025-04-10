import os
import sys
import json
import logging
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from functools import wraps

# Import the analytics schema
from src.analytics.schema import AnalyticsSchema
# Import the authentication module
from src.analytics.auth import analytics_auth

# Configure logging
logger = logging.getLogger("arp_guard.analytics.api")

class AnalyticsAPI:
    """API for accessing analytics data."""
    
    def __init__(self, db_path: str, host: str = "0.0.0.0", port: int = 5000):
        """
        Initialize the analytics API.
        
        Args:
            db_path: Path to the SQLite database file
            host: Host to bind the API server to
            port: Port to bind the API server to
        """
        self.db_path = db_path
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        CORS(self.app)  # Enable CORS for all routes
        
        # Create the analytics schema
        self.schema = AnalyticsSchema(db_path)
        self.schema.connect()
        
        # Register routes
        self._register_routes()
        
        logger.info(f"Initialized AnalyticsAPI with database at {db_path}")
        
    def _require_auth(self, f):
        """Decorator to require authentication for routes"""
        @wraps(f)
        def decorated(*args, **kwargs):
            # Get the token from the Authorization header
            auth_header = request.headers.get('Authorization')
            
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({"error": "Authentication required"}), 401
                
            token = auth_header.split(' ')[1]
            
            # Validate the token
            user = analytics_auth.validate_token(token, request.remote_addr)
            if not user:
                return jsonify({"error": "Invalid or expired token"}), 401
                
            # Add user info to request
            request.user = user
            
            return f(*args, **kwargs)
        return decorated
        
    def _check_permission(self, permission):
        """Decorator to check if user has required permission"""
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                # First ensure the user is authenticated
                if not hasattr(request, 'user'):
                    return jsonify({"error": "Authentication required"}), 401
                    
                # Get permissions for the user
                username = request.user.get('username')
                permissions = analytics_auth.get_user_permissions(username)
                
                # Check if user has the required permission
                if permission not in permissions:
                    return jsonify({"error": "Permission denied"}), 403
                    
                return f(*args, **kwargs)
            return decorated
        return decorator
    
    def _register_routes(self):
        """Register the API routes."""
        
        # Authentication routes
        @self.app.route("/api/auth/login", methods=["POST"])
        def login():
            try:
                data = request.get_json()
                username = data.get("username")
                password = data.get("password")
                
                if not username or not password:
                    return jsonify({"error": "Username and password required"}), 400
                
                # Authenticate user
                auth_result = analytics_auth.authenticate(
                    username, 
                    password,
                    request.headers.get("User-Agent", "Unknown"),
                    request.remote_addr
                )
                
                if not auth_result:
                    return jsonify({"error": "Invalid credentials"}), 401
                
                return jsonify(auth_result)
                
            except Exception as e:
                logger.error(f"Error during login: {str(e)}")
                return jsonify({"error": "Authentication failed"}), 500
        
        @self.app.route("/api/auth/logout", methods=["POST"])
        @self._require_auth
        def logout():
            try:
                auth_header = request.headers.get('Authorization')
                token = auth_header.split(' ')[1]
                
                # Revoke the token
                analytics_auth.revoke_token(token)
                
                return jsonify({"message": "Successfully logged out"})
                
            except Exception as e:
                logger.error(f"Error during logout: {str(e)}")
                return jsonify({"error": "Logout failed"}), 500
        
        @self.app.route("/api/auth/verify", methods=["GET"])
        @self._require_auth
        def verify_token():
            # If we get here, the token is valid
            return jsonify({
                "valid": True,
                "user": request.user
            })
        
        # User permissions route
        @self.app.route("/api/auth/permissions", methods=["GET"])
        @self._require_auth
        def get_permissions():
            username = request.user.get('username')
            permissions = analytics_auth.get_user_permissions(username)
            
            return jsonify({
                "username": username,
                "permissions": permissions
            })
        
        # Protected routes - Apply authentication to all data endpoints
        
        # Sessions endpoint (requires auth)
        @self.app.route("/api/sessions", methods=["GET"])
        @self._require_auth
        @self._check_permission("dashboard:view")
        def get_sessions():
            try:
                limit = int(request.args.get("limit", 100))
                
                sessions = self.schema.get_sessions(limit=limit)
                
                return jsonify({"sessions": sessions, "count": len(sessions)})
                
            except Exception as e:
                logger.error(f"Error getting sessions: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        # ... other routes with authentication ...
        
        # Dashboard data endpoint (combined data for the dashboard)
        @self.app.route("/api/dashboard", methods=["GET"])
        @self._require_auth
        @self._check_permission("dashboard:view")
        def get_dashboard_data():
            try:
                session_id = request.args.get("session_id")
                
                # Convert session_id to int if provided
                if session_id:
                    session_id = int(session_id)
                    
                    # Get the session
                    session = self.schema.get_session(session_id)
                    
                    if not session:
                        return jsonify({"error": f"Session {session_id} not found"}), 404
                else:
                    # Get the most recent session
                    sessions = self.schema.get_sessions(limit=1)
                    if not sessions:
                        return jsonify({"error": "No sessions found"}), 404
                    
                    session = sessions[0]
                    session_id = session["id"]
                
                # Get alerts (latest 10)
                alerts = self.schema.get_alerts(session_id=session_id, limit=10)
                
                # Get packet stats (latest 20)
                packet_stats = self.schema.get_packet_stats(session_id=session_id, limit=20)
                
                # Get system stats (latest 10)
                system_stats = self.schema.get_system_stats(session_id=session_id, limit=10)
                
                # Get alert counts by severity
                severity_counts = self.schema.get_alert_count_by_severity(session_id=session_id)
                
                # Get alert counts by rule
                rule_counts = self.schema.get_alert_count_by_rule(session_id=session_id)
                
                # Get alert counts by day (last 30 days)
                end_date = datetime.now()
                start_date = end_date - timedelta(days=30)
                day_counts = self.schema.get_alert_count_by_day(
                    session_id=session_id,
                    start_date=start_date,
                    end_date=end_date
                )
                
                # Compile all data
                dashboard_data = {
                    "session": session,
                    "alerts": alerts,
                    "packet_stats": packet_stats,
                    "system_stats": system_stats,
                    "alert_counts": {
                        "by_severity": severity_counts,
                        "by_rule": rule_counts,
                        "by_day": day_counts
                    }
                }
                
                return jsonify(dashboard_data)
            
            except Exception as e:
                logger.error(f"Error getting dashboard data: {str(e)}")
                return jsonify({"error": str(e)}), 500
                
        # Export endpoints
        @self.app.route("/api/export/csv", methods=["GET"])
        @self._require_auth
        @self._check_permission("analytics:export")
        def export_csv():
            try:
                # Export logic here with authentication
                pass
            except Exception as e:
                logger.error(f"Error exporting CSV: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route("/api/export/json", methods=["GET"])
        @self._require_auth
        @self._check_permission("analytics:export")
        def export_json():
            try:
                # Export logic here with authentication
                pass
            except Exception as e:
                logger.error(f"Error exporting JSON: {str(e)}")
                return jsonify({"error": str(e)}), 500
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """
        Parse a date string into a datetime object.
        
        Args:
            date_str: Date string in ISO format
            
        Returns:
            Datetime object, or None if the date string is None or invalid
        """
        if not date_str:
            return None
        
        try:
            return datetime.fromisoformat(date_str)
        except ValueError:
            logger.warning(f"Invalid date format: {date_str}")
            return None
    
    def start(self):
        """Start the API server."""
        logger.info(f"Starting AnalyticsAPI server on {self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port)

class AnalyticsCollector:
    """Collects analytics data from the detection module."""
    
    def __init__(self, db_path: str, collection_interval: int = 5):
        """
        Initialize the analytics collector.
        
        Args:
            db_path: Path to the SQLite database file
            collection_interval: Interval between data collections (seconds)
        """
        self.db_path = db_path
        self.collection_interval = collection_interval
        self.schema = AnalyticsSchema(db_path)
        self.schema.connect()
        self.session_id = None
        self.detection_module = None
        self.collection_thread = None
        self.running = False
        
        logger.info(f"Initialized AnalyticsCollector with database at {db_path}")
    
    def start(self, detection_module, interface: str = "unknown", 
             hostname: str = "unknown", is_lite: bool = False,
             metadata: Dict[str, Any] = None):
        """
        Start collecting analytics data.
        
        Args:
            detection_module: Detection module to collect data from
            interface: Network interface being monitored
            hostname: Name of the host
            is_lite: Whether this is a lite version
            metadata: Additional metadata
        """
        if self.running:
            logger.warning("AnalyticsCollector is already running")
            return
        
        self.detection_module = detection_module
        
        # Create a new session
        num_workers = None
        if hasattr(detection_module, "rule_processor") and hasattr(detection_module.rule_processor, "thread_pool"):
            num_workers = detection_module.rule_processor.thread_pool.num_workers
        
        self.session_id = self.schema.create_session(
            interface=interface,
            hostname=hostname,
            is_lite=is_lite,
            num_workers=num_workers,
            metadata=metadata
        )
        
        # Start collection thread
        self.running = True
        self.collection_thread = threading.Thread(target=self._collection_loop, daemon=True)
        self.collection_thread.start()
        
        # Register alert callback
        if hasattr(detection_module, "register_alert_callback"):
            detection_module.register_alert_callback(self._alert_callback)
        
        logger.info(f"Started AnalyticsCollector with session ID {self.session_id}")
    
    def stop(self):
        """Stop collecting analytics data."""
        if not self.running:
            logger.warning("AnalyticsCollector is not running")
            return
        
        # Stop collection thread
        self.running = False
        if self.collection_thread and self.collection_thread.is_alive():
            self.collection_thread.join(timeout=2.0)
        
        # End the session
        if self.session_id:
            self.schema.end_session(self.session_id)
        
        # Disconnect from the database
        self.schema.disconnect()
        
        logger.info(f"Stopped AnalyticsCollector for session ID {self.session_id}")
    
    def _collection_loop(self):
        """Main collection loop."""
        import time
        import psutil
        
        while self.running:
            try:
                # Collect stats from the detection module
                self._collect_stats()
                
                # Collect system stats
                self._collect_system_stats()
                
            except Exception as e:
                logger.error(f"Error collecting stats: {str(e)}")
            
            # Sleep until next collection
            time.sleep(self.collection_interval)
    
    def _collect_stats(self):
        """Collect stats from the detection module."""
        if not self.detection_module or not self.session_id:
            return
        
        try:
            # Get stats from the detection module
            stats = self.detection_module.get_stats()
            
            if not stats:
                return
            
            # Extract relevant data
            packets_processed = stats.get("packets_processed", 0)
            alerts_generated = stats.get("alerts", 0)
            processing_time = stats.get("processing_time", 0.0)
            packets_by_type = stats.get("packets_by_type", {})
            alerts_by_severity = stats.get("alerts_by_severity", {})
            alerts_by_rule = stats.get("alerts_by_rule", {})
            
            # Add packet stats to the database
            self.schema.add_packet_stats(
                session_id=self.session_id,
                packets_processed=packets_processed,
                alerts_generated=alerts_generated,
                processing_time=processing_time,
                packets_by_type=packets_by_type,
                alerts_by_severity=alerts_by_severity,
                alerts_by_rule=alerts_by_rule
            )
            
        except Exception as e:
            logger.error(f"Error collecting stats from detection module: {str(e)}")
    
    def _collect_system_stats(self):
        """Collect system stats."""
        if not self.session_id:
            return
        
        try:
            import psutil
            
            # Get CPU and memory usage
            cpu_usage = psutil.cpu_percent()
            memory_usage = psutil.virtual_memory().percent
            
            # Get thread count and queue sizes from detection module
            thread_count = None
            active_threads = None
            task_queue_size = None
            batch_queue_size = None
            
            if (hasattr(self.detection_module, "rule_processor") and 
                hasattr(self.detection_module.rule_processor, "thread_pool")):
                thread_pool = self.detection_module.rule_processor.thread_pool
                thread_stats = thread_pool.get_stats()
                
                if thread_stats:
                    worker_stats = thread_stats.get("workers", {})
                    task_stats = thread_stats.get("tasks", {})
                    
                    thread_count = worker_stats.get("total")
                    active_threads = worker_stats.get("active")
                    task_queue_size = task_stats.get("pending")
            
            # Check for batch queue size
            if (hasattr(self.detection_module, "packet_batch_queue") and 
                hasattr(self.detection_module.packet_batch_queue, "qsize")):
                batch_queue_size = self.detection_module.packet_batch_queue.qsize()
            
            # Add system stats to the database
            self.schema.add_system_stats(
                session_id=self.session_id,
                cpu_usage=cpu_usage,
                memory_usage=memory_usage,
                thread_count=thread_count,
                active_threads=active_threads,
                task_queue_size=task_queue_size,
                batch_queue_size=batch_queue_size
            )
            
        except Exception as e:
            logger.error(f"Error collecting system stats: {str(e)}")
    
    def _alert_callback(self, alert):
        """
        Callback for handling alerts.
        
        Args:
            alert: Alert data
        """
        if not self.session_id:
            return
        
        try:
            # Extract alert data
            rule = alert.get("rule")
            severity = alert.get("severity", "medium")
            source_ip = alert.get("source_ip")
            source_mac = alert.get("source_mac")
            target_ip = alert.get("target_ip")
            target_mac = alert.get("target_mac")
            details = alert.get("details")
            
            if not rule:
                return
            
            # Add alert to the database
            self.schema.add_alert(
                session_id=self.session_id,
                rule=rule,
                severity=severity,
                source_ip=source_ip,
                source_mac=source_mac,
                target_ip=target_ip,
                target_mac=target_mac,
                details=details
            )
            
        except Exception as e:
            logger.error(f"Error handling alert: {str(e)}")
    
    def log_user_action(self, action_type: str, action_details: Dict[str, Any] = None):
        """
        Log a user action.
        
        Args:
            action_type: Type of action
            action_details: Additional details about the action
        """
        if not self.session_id:
            return
        
        try:
            self.schema.add_user_action(
                session_id=self.session_id,
                action_type=action_type,
                action_details=action_details
            )
            
        except Exception as e:
            logger.error(f"Error logging user action: {str(e)}")

# Initialize threading for Flask
import threading 