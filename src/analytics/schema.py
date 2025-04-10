from datetime import datetime
from typing import List, Dict, Any, Optional, Union
import sqlite3
import json
import os
import logging

logger = logging.getLogger("arp_guard.analytics")

class AnalyticsSchema:
    """Schema for the analytics database."""
    
    def __init__(self, db_path: str):
        """
        Initialize the analytics schema.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self._ensure_dir_exists()
        self.connection = None
        self.connected = False
    
    def _ensure_dir_exists(self):
        """Ensure the directory for the database file exists."""
        directory = os.path.dirname(self.db_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
    
    def connect(self):
        """Connect to the database and create tables if they don't exist."""
        if self.connected:
            return
        
        try:
            self.connection = sqlite3.connect(self.db_path)
            self.connection.row_factory = sqlite3.Row
            self._create_tables()
            self.connected = True
            logger.info(f"Connected to analytics database at {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Error connecting to database: {str(e)}")
            raise
    
    def disconnect(self):
        """Disconnect from the database."""
        if self.connected and self.connection:
            self.connection.close()
            self.connection = None
            self.connected = False
            logger.info("Disconnected from analytics database")
    
    def _create_tables(self):
        """Create the database tables if they don't exist."""
        cursor = self.connection.cursor()
        
        # Create the detection_sessions table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS detection_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time TIMESTAMP NOT NULL,
            end_time TIMESTAMP,
            interface TEXT,
            hostname TEXT,
            is_lite BOOLEAN DEFAULT 0,
            num_workers INTEGER,
            version TEXT,
            metadata TEXT
        )
        ''')
        
        # Create the packet_stats table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS packet_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            packets_processed INTEGER NOT NULL,
            alerts_generated INTEGER NOT NULL,
            processing_time REAL NOT NULL,
            packets_by_type TEXT,
            alerts_by_severity TEXT,
            alerts_by_rule TEXT,
            FOREIGN KEY (session_id) REFERENCES detection_sessions(id)
        )
        ''')
        
        # Create the alerts table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            rule TEXT NOT NULL,
            source_ip TEXT,
            source_mac TEXT,
            target_ip TEXT,
            target_mac TEXT,
            severity TEXT NOT NULL,
            details TEXT,
            FOREIGN KEY (session_id) REFERENCES detection_sessions(id)
        )
        ''')
        
        # Create the system_stats table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            cpu_usage REAL,
            memory_usage REAL,
            thread_count INTEGER,
            active_threads INTEGER,
            task_queue_size INTEGER,
            batch_queue_size INTEGER,
            FOREIGN KEY (session_id) REFERENCES detection_sessions(id)
        )
        ''')
        
        # Create the user_actions table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            action_type TEXT NOT NULL,
            action_details TEXT,
            FOREIGN KEY (session_id) REFERENCES detection_sessions(id)
        )
        ''')
        
        # Create indices for faster queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_session_start_time ON detection_sessions(start_time)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_packet_stats_timestamp ON packet_stats(timestamp)')
        
        self.connection.commit()
        logger.info("Database tables created successfully")
    
    def create_session(self, interface: str, hostname: str, is_lite: bool = False,
                      num_workers: Optional[int] = None, version: str = "1.0.0",
                      metadata: Dict[str, Any] = None) -> int:
        """
        Create a new detection session.
        
        Args:
            interface: Network interface being monitored
            hostname: Name of the host
            is_lite: Whether this is a lite version
            num_workers: Number of worker threads (for parallel processing)
            version: Version of the software
            metadata: Additional metadata
            
        Returns:
            ID of the new session
        """
        if not self.connected:
            self.connect()
        
        cursor = self.connection.cursor()
        
        try:
            cursor.execute('''
            INSERT INTO detection_sessions 
            (start_time, interface, hostname, is_lite, num_workers, version, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                interface,
                hostname,
                1 if is_lite else 0,
                num_workers,
                version,
                json.dumps(metadata) if metadata else None
            ))
            
            self.connection.commit()
            session_id = cursor.lastrowid
            logger.info(f"Created new detection session with ID {session_id}")
            return session_id
        
        except sqlite3.Error as e:
            logger.error(f"Error creating session: {str(e)}")
            raise
    
    def end_session(self, session_id: int):
        """
        Mark a detection session as ended.
        
        Args:
            session_id: ID of the session to end
        """
        if not self.connected:
            self.connect()
        
        cursor = self.connection.cursor()
        
        try:
            cursor.execute('''
            UPDATE detection_sessions 
            SET end_time = ?
            WHERE id = ?
            ''', (
                datetime.now().isoformat(),
                session_id
            ))
            
            self.connection.commit()
            logger.info(f"Ended detection session with ID {session_id}")
        
        except sqlite3.Error as e:
            logger.error(f"Error ending session: {str(e)}")
            raise
    
    def add_packet_stats(self, session_id: int, packets_processed: int, alerts_generated: int,
                        processing_time: float, packets_by_type: Dict[str, int] = None,
                        alerts_by_severity: Dict[str, int] = None, 
                        alerts_by_rule: Dict[str, int] = None):
        """
        Add packet processing statistics.
        
        Args:
            session_id: ID of the session
            packets_processed: Number of packets processed
            alerts_generated: Number of alerts generated
            processing_time: Time spent processing packets (seconds)
            packets_by_type: Dictionary of packet counts by type
            alerts_by_severity: Dictionary of alert counts by severity
            alerts_by_rule: Dictionary of alert counts by rule
        """
        if not self.connected:
            self.connect()
        
        cursor = self.connection.cursor()
        
        try:
            cursor.execute('''
            INSERT INTO packet_stats
            (session_id, timestamp, packets_processed, alerts_generated, processing_time,
            packets_by_type, alerts_by_severity, alerts_by_rule)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_id,
                datetime.now().isoformat(),
                packets_processed,
                alerts_generated,
                processing_time,
                json.dumps(packets_by_type) if packets_by_type else None,
                json.dumps(alerts_by_severity) if alerts_by_severity else None,
                json.dumps(alerts_by_rule) if alerts_by_rule else None
            ))
            
            self.connection.commit()
        
        except sqlite3.Error as e:
            logger.error(f"Error adding packet stats: {str(e)}")
            raise
    
    def add_alert(self, session_id: int, rule: str, severity: str, 
                 source_ip: Optional[str] = None, source_mac: Optional[str] = None,
                 target_ip: Optional[str] = None, target_mac: Optional[str] = None,
                 details: Dict[str, Any] = None):
        """
        Add an alert.
        
        Args:
            session_id: ID of the session
            rule: Name of the rule that triggered the alert
            severity: Severity of the alert
            source_ip: Source IP address
            source_mac: Source MAC address
            target_ip: Target IP address
            target_mac: Target MAC address
            details: Additional details about the alert
        """
        if not self.connected:
            self.connect()
        
        cursor = self.connection.cursor()
        
        try:
            cursor.execute('''
            INSERT INTO alerts
            (session_id, timestamp, rule, source_ip, source_mac, target_ip, target_mac, severity, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_id,
                datetime.now().isoformat(),
                rule,
                source_ip,
                source_mac,
                target_ip,
                target_mac,
                severity,
                json.dumps(details) if details else None
            ))
            
            self.connection.commit()
        
        except sqlite3.Error as e:
            logger.error(f"Error adding alert: {str(e)}")
            raise
    
    def add_system_stats(self, session_id: int, cpu_usage: Optional[float] = None,
                        memory_usage: Optional[float] = None, thread_count: Optional[int] = None,
                        active_threads: Optional[int] = None, task_queue_size: Optional[int] = None,
                        batch_queue_size: Optional[int] = None):
        """
        Add system statistics.
        
        Args:
            session_id: ID of the session
            cpu_usage: CPU usage (percentage)
            memory_usage: Memory usage (percentage)
            thread_count: Number of threads
            active_threads: Number of active threads
            task_queue_size: Size of the task queue
            batch_queue_size: Size of the batch queue
        """
        if not self.connected:
            self.connect()
        
        cursor = self.connection.cursor()
        
        try:
            cursor.execute('''
            INSERT INTO system_stats
            (session_id, timestamp, cpu_usage, memory_usage, thread_count, active_threads, 
            task_queue_size, batch_queue_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_id,
                datetime.now().isoformat(),
                cpu_usage,
                memory_usage,
                thread_count,
                active_threads,
                task_queue_size,
                batch_queue_size
            ))
            
            self.connection.commit()
        
        except sqlite3.Error as e:
            logger.error(f"Error adding system stats: {str(e)}")
            raise
    
    def add_user_action(self, session_id: int, action_type: str, action_details: Dict[str, Any] = None):
        """
        Add a user action.
        
        Args:
            session_id: ID of the session
            action_type: Type of action
            action_details: Additional details about the action
        """
        if not self.connected:
            self.connect()
        
        cursor = self.connection.cursor()
        
        try:
            cursor.execute('''
            INSERT INTO user_actions
            (session_id, timestamp, action_type, action_details)
            VALUES (?, ?, ?, ?)
            ''', (
                session_id,
                datetime.now().isoformat(),
                action_type,
                json.dumps(action_details) if action_details else None
            ))
            
            self.connection.commit()
        
        except sqlite3.Error as e:
            logger.error(f"Error adding user action: {str(e)}")
            raise
    
    def get_sessions(self, limit: int = 100, offset: int = 0, 
                    start_date: Optional[datetime] = None, 
                    end_date: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Get a list of detection sessions.
        
        Args:
            limit: Maximum number of sessions to return
            offset: Number of sessions to skip
            start_date: Only include sessions starting on or after this date
            end_date: Only include sessions starting on or before this date
            
        Returns:
            List of session dictionaries
        """
        if not self.connected:
            self.connect()
        
        cursor = self.connection.cursor()
        
        query = "SELECT * FROM detection_sessions"
        params = []
        
        if start_date or end_date:
            query += " WHERE "
            
            if start_date:
                query += "start_time >= ?"
                params.append(start_date.isoformat())
                
                if end_date:
                    query += " AND "
            
            if end_date:
                query += "start_time <= ?"
                params.append(end_date.isoformat())
        
        query += " ORDER BY start_time DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        try:
            cursor.execute(query, params)
            sessions = []
            
            for row in cursor.fetchall():
                session = dict(row)
                if session["metadata"]:
                    session["metadata"] = json.loads(session["metadata"])
                sessions.append(session)
            
            return sessions
        
        except sqlite3.Error as e:
            logger.error(f"Error getting sessions: {str(e)}")
            raise
    
    def get_session(self, session_id: int) -> Dict[str, Any]:
        """
        Get a specific detection session.
        
        Args:
            session_id: ID of the session
            
        Returns:
            Session dictionary
        """
        if not self.connected:
            self.connect()
        
        cursor = self.connection.cursor()
        
        try:
            cursor.execute("SELECT * FROM detection_sessions WHERE id = ?", (session_id,))
            row = cursor.fetchone()
            
            if not row:
                return None
            
            session = dict(row)
            if session["metadata"]:
                session["metadata"] = json.loads(session["metadata"])
            
            return session
        
        except sqlite3.Error as e:
            logger.error(f"Error getting session: {str(e)}")
            raise
    
    def get_alerts(self, session_id: Optional[int] = None, limit: int = 100, offset: int = 0,
                  start_date: Optional[datetime] = None, end_date: Optional[datetime] = None,
                  severity: Optional[str] = None, rule: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get a list of alerts.
        
        Args:
            session_id: Only include alerts from this session
            limit: Maximum number of alerts to return
            offset: Number of alerts to skip
            start_date: Only include alerts generated on or after this date
            end_date: Only include alerts generated on or before this date
            severity: Only include alerts with this severity
            rule: Only include alerts triggered by this rule
            
        Returns:
            List of alert dictionaries
        """
        if not self.connected:
            self.connect()
        
        cursor = self.connection.cursor()
        
        query = "SELECT * FROM alerts"
        params = []
        where_clauses = []
        
        if session_id:
            where_clauses.append("session_id = ?")
            params.append(session_id)
        
        if start_date:
            where_clauses.append("timestamp >= ?")
            params.append(start_date.isoformat())
        
        if end_date:
            where_clauses.append("timestamp <= ?")
            params.append(end_date.isoformat())
        
        if severity:
            where_clauses.append("severity = ?")
            params.append(severity)
        
        if rule:
            where_clauses.append("rule = ?")
            params.append(rule)
        
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        try:
            cursor.execute(query, params)
            alerts = []
            
            for row in cursor.fetchall():
                alert = dict(row)
                if alert["details"]:
                    alert["details"] = json.loads(alert["details"])
                alerts.append(alert)
            
            return alerts
        
        except sqlite3.Error as e:
            logger.error(f"Error getting alerts: {str(e)}")
            raise
    
    def get_packet_stats(self, session_id: int, limit: int = 100, 
                        start_date: Optional[datetime] = None,
                        end_date: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Get packet processing statistics for a session.
        
        Args:
            session_id: ID of the session
            limit: Maximum number of stats entries to return
            start_date: Only include stats from on or after this date
            end_date: Only include stats from on or before this date
            
        Returns:
            List of packet stats dictionaries
        """
        if not self.connected:
            self.connect()
        
        cursor = self.connection.cursor()
        
        query = "SELECT * FROM packet_stats WHERE session_id = ?"
        params = [session_id]
        
        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date.isoformat())
        
        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date.isoformat())
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        try:
            cursor.execute(query, params)
            stats = []
            
            for row in cursor.fetchall():
                stat = dict(row)
                if stat["packets_by_type"]:
                    stat["packets_by_type"] = json.loads(stat["packets_by_type"])
                if stat["alerts_by_severity"]:
                    stat["alerts_by_severity"] = json.loads(stat["alerts_by_severity"])
                if stat["alerts_by_rule"]:
                    stat["alerts_by_rule"] = json.loads(stat["alerts_by_rule"])
                stats.append(stat)
            
            return stats
        
        except sqlite3.Error as e:
            logger.error(f"Error getting packet stats: {str(e)}")
            raise
    
    def get_system_stats(self, session_id: int, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get system statistics for a session.
        
        Args:
            session_id: ID of the session
            limit: Maximum number of stats entries to return
            
        Returns:
            List of system stats dictionaries
        """
        if not self.connected:
            self.connect()
        
        cursor = self.connection.cursor()
        
        try:
            cursor.execute('''
            SELECT * FROM system_stats 
            WHERE session_id = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
            ''', (session_id, limit))
            
            return [dict(row) for row in cursor.fetchall()]
        
        except sqlite3.Error as e:
            logger.error(f"Error getting system stats: {str(e)}")
            raise
    
    def get_user_actions(self, session_id: int, limit: int = 100, 
                        action_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get user actions for a session.
        
        Args:
            session_id: ID of the session
            limit: Maximum number of actions to return
            action_type: Only include actions of this type
            
        Returns:
            List of user action dictionaries
        """
        if not self.connected:
            self.connect()
        
        cursor = self.connection.cursor()
        
        query = "SELECT * FROM user_actions WHERE session_id = ?"
        params = [session_id]
        
        if action_type:
            query += " AND action_type = ?"
            params.append(action_type)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        try:
            cursor.execute(query, params)
            actions = []
            
            for row in cursor.fetchall():
                action = dict(row)
                if action["action_details"]:
                    action["action_details"] = json.loads(action["action_details"])
                actions.append(action)
            
            return actions
        
        except sqlite3.Error as e:
            logger.error(f"Error getting user actions: {str(e)}")
            raise
    
    def get_alert_count_by_day(self, session_id: Optional[int] = None,
                              start_date: Optional[datetime] = None,
                              end_date: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Get the number of alerts by day.
        
        Args:
            session_id: Only include alerts from this session
            start_date: Only include alerts generated on or after this date
            end_date: Only include alerts generated on or before this date
            
        Returns:
            List of dictionaries with date and count
        """
        if not self.connected:
            self.connect()
        
        cursor = self.connection.cursor()
        
        query = "SELECT date(timestamp) as date, COUNT(*) as count FROM alerts"
        params = []
        where_clauses = []
        
        if session_id:
            where_clauses.append("session_id = ?")
            params.append(session_id)
        
        if start_date:
            where_clauses.append("timestamp >= ?")
            params.append(start_date.isoformat())
        
        if end_date:
            where_clauses.append("timestamp <= ?")
            params.append(end_date.isoformat())
        
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        
        query += " GROUP BY date(timestamp) ORDER BY date"
        
        try:
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        
        except sqlite3.Error as e:
            logger.error(f"Error getting alert count by day: {str(e)}")
            raise
    
    def get_alert_count_by_severity(self, session_id: Optional[int] = None,
                                   start_date: Optional[datetime] = None,
                                   end_date: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Get the number of alerts by severity.
        
        Args:
            session_id: Only include alerts from this session
            start_date: Only include alerts generated on or after this date
            end_date: Only include alerts generated on or before this date
            
        Returns:
            List of dictionaries with severity and count
        """
        if not self.connected:
            self.connect()
        
        cursor = self.connection.cursor()
        
        query = "SELECT severity, COUNT(*) as count FROM alerts"
        params = []
        where_clauses = []
        
        if session_id:
            where_clauses.append("session_id = ?")
            params.append(session_id)
        
        if start_date:
            where_clauses.append("timestamp >= ?")
            params.append(start_date.isoformat())
        
        if end_date:
            where_clauses.append("timestamp <= ?")
            params.append(end_date.isoformat())
        
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        
        query += " GROUP BY severity ORDER BY count DESC"
        
        try:
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        
        except sqlite3.Error as e:
            logger.error(f"Error getting alert count by severity: {str(e)}")
            raise
    
    def get_alert_count_by_rule(self, session_id: Optional[int] = None,
                               start_date: Optional[datetime] = None,
                               end_date: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Get the number of alerts by rule.
        
        Args:
            session_id: Only include alerts from this session
            start_date: Only include alerts generated on or after this date
            end_date: Only include alerts generated on or before this date
            
        Returns:
            List of dictionaries with rule and count
        """
        if not self.connected:
            self.connect()
        
        cursor = self.connection.cursor()
        
        query = "SELECT rule, COUNT(*) as count FROM alerts"
        params = []
        where_clauses = []
        
        if session_id:
            where_clauses.append("session_id = ?")
            params.append(session_id)
        
        if start_date:
            where_clauses.append("timestamp >= ?")
            params.append(start_date.isoformat())
        
        if end_date:
            where_clauses.append("timestamp <= ?")
            params.append(end_date.isoformat())
        
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        
        query += " GROUP BY rule ORDER BY count DESC"
        
        try:
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        
        except sqlite3.Error as e:
            logger.error(f"Error getting alert count by rule: {str(e)}")
            raise 