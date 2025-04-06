import os
import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

from app.utils.logger import get_logger

# Module logger
logger = get_logger('utils.database')

class Database:
    """Database manager for ARPGuard using SQLite."""
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize the database connection.
        
        Args:
            db_path: Path to the SQLite database file. If None, uses default location.
        """
        if db_path is None:
            # Use default location in user's home directory
            home_dir = os.path.expanduser("~")
            app_dir = os.path.join(home_dir, ".arpguard")
            
            # Create directory if it doesn't exist
            os.makedirs(app_dir, exist_ok=True)
            
            db_path = os.path.join(app_dir, "arpguard.db")
            
        self.db_path = db_path
        self.conn = None
        
        # Initialize database
        self._initialize()
        
    def _initialize(self):
        """Initialize the database connection and create tables if they don't exist."""
        try:
            self.conn = sqlite3.connect(self.db_path)
            
            # Enable foreign keys
            self.conn.execute("PRAGMA foreign_keys = ON")
            
            # Create tables if they don't exist
            self._create_tables()
            
            logger.info(f"Database initialized: {self.db_path}")
            
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {e}")
            raise
        
    def _create_tables(self):
        """Create database tables if they don't exist."""
        cursor = self.conn.cursor()
        
        # Create capture_sessions table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS capture_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time TIMESTAMP NOT NULL,
            end_time TIMESTAMP,
            description TEXT,
            interface TEXT,
            filter TEXT,
            packet_count INTEGER DEFAULT 0,
            bytes_total INTEGER DEFAULT 0
        )
        ''')
        
        # Create packets table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            capture_time TIMESTAMP NOT NULL,
            protocol TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            src_mac TEXT,
            dst_mac TEXT,
            length INTEGER NOT NULL,
            info TEXT,
            data BLOB,
            FOREIGN KEY (session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE
        )
        ''')
        
        # Create protocol_stats table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS protocol_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            protocol TEXT NOT NULL,
            packet_count INTEGER NOT NULL,
            bytes_total INTEGER NOT NULL,
            FOREIGN KEY (session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE
        )
        ''')
        
        # Create ip_stats table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            ip_address TEXT NOT NULL,
            packets_sent INTEGER NOT NULL,
            packets_received INTEGER NOT NULL,
            bytes_sent INTEGER NOT NULL,
            bytes_received INTEGER NOT NULL,
            FOREIGN KEY (session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE
        )
        ''')
        
        # Create traffic_snapshots table (for time-series data)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            duration_seconds INTEGER NOT NULL,
            total_packets INTEGER NOT NULL,
            total_bytes INTEGER NOT NULL,
            packets_per_second REAL NOT NULL,
            bytes_per_second REAL NOT NULL,
            stats_json TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE
        )
        ''')
        
        # Create index for faster queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_time ON packets(capture_time)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol_stats_session ON protocol_stats(session_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_stats_session ON ip_stats(session_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_traffic_session ON traffic_snapshots(session_id)')
        
        self.conn.commit()
        
    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
            
    def __del__(self):
        """Destructor to ensure the database connection is closed."""
        self.close()
        
    def create_capture_session(self, 
                               description: Optional[str] = None,
                               interface: Optional[str] = None,
                               filter_str: Optional[str] = None) -> int:
        """Create a new capture session and return its ID.
        
        Args:
            description: Optional description of the capture session
            interface: Network interface used for capture
            filter_str: BPF filter string used
        
        Returns:
            int: ID of the created session
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                '''
                INSERT INTO capture_sessions 
                (start_time, description, interface, filter)
                VALUES (?, ?, ?, ?)
                ''',
                (datetime.now(), description, interface, filter_str)
            )
            
            self.conn.commit()
            session_id = cursor.lastrowid
            logger.info(f"Created capture session with ID: {session_id}")
            return session_id
            
        except sqlite3.Error as e:
            logger.error(f"Error creating capture session: {e}")
            raise
            
    def end_capture_session(self, session_id: int, 
                           packet_count: int, 
                           bytes_total: int) -> bool:
        """Mark a capture session as ended.
        
        Args:
            session_id: ID of the session to end
            packet_count: Total number of packets captured
            bytes_total: Total number of bytes captured
        
        Returns:
            bool: True if successful
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                '''
                UPDATE capture_sessions
                SET end_time = ?, packet_count = ?, bytes_total = ?
                WHERE id = ?
                ''',
                (datetime.now(), packet_count, bytes_total, session_id)
            )
            
            self.conn.commit()
            logger.info(f"Ended capture session {session_id} with {packet_count} packets")
            return True
            
        except sqlite3.Error as e:
            logger.error(f"Error ending capture session: {e}")
            return False
    
    def add_packet(self, session_id: int, packet_info: Dict[str, Any]) -> int:
        """Add a captured packet to the database.
        
        Args:
            session_id: ID of the capture session
            packet_info: Dictionary containing packet details
        
        Returns:
            int: ID of the inserted packet
        """
        try:
            # Extract packet fields
            protocol = packet_info.get('protocol', 'UNKNOWN')
            capture_time = packet_info.get('time', datetime.now())
            src_ip = packet_info.get('src_ip')
            dst_ip = packet_info.get('dst_ip')
            src_port = packet_info.get('src_port')
            dst_port = packet_info.get('dst_port')
            src_mac = packet_info.get('src_mac')
            dst_mac = packet_info.get('dst_mac')
            length = packet_info.get('length', 0)
            info = packet_info.get('info', '')
            
            # Serialize raw packet data if available
            data = None
            if 'raw_packet' in packet_info:
                # Store as binary data
                try:
                    data = bytes(packet_info['raw_packet'])
                except:
                    pass
            
            cursor = self.conn.cursor()
            cursor.execute(
                '''
                INSERT INTO packets
                (session_id, capture_time, protocol, src_ip, dst_ip, 
                 src_port, dst_port, src_mac, dst_mac, length, info, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (session_id, capture_time, protocol, src_ip, dst_ip, 
                 src_port, dst_port, src_mac, dst_mac, length, info, data)
            )
            
            self.conn.commit()
            return cursor.lastrowid
            
        except sqlite3.Error as e:
            logger.error(f"Error adding packet: {e}")
            # Continue without raising - we don't want to crash the capture
            return -1
    
    def add_protocol_stats(self, session_id: int, timestamp: datetime, 
                          stats: Dict[str, Dict[str, int]]) -> bool:
        """Add protocol statistics to the database.
        
        Args:
            session_id: ID of the capture session
            timestamp: Timestamp for the statistics
            stats: Dictionary with protocol statistics
                   Format: {'protocol_name': {'count': n, 'bytes': m}}
        
        Returns:
            bool: True if successful
        """
        try:
            cursor = self.conn.cursor()
            
            for protocol, data in stats.items():
                packet_count = data.get('count', 0)
                bytes_total = data.get('bytes', 0)
                
                cursor.execute(
                    '''
                    INSERT INTO protocol_stats
                    (session_id, timestamp, protocol, packet_count, bytes_total)
                    VALUES (?, ?, ?, ?, ?)
                    ''',
                    (session_id, timestamp, protocol, packet_count, bytes_total)
                )
            
            self.conn.commit()
            return True
            
        except sqlite3.Error as e:
            logger.error(f"Error adding protocol stats: {e}")
            return False
    
    def add_ip_stats(self, session_id: int, timestamp: datetime, 
                    ip_stats: Dict[str, Dict[str, int]]) -> bool:
        """Add IP address statistics to the database.
        
        Args:
            session_id: ID of the capture session
            timestamp: Timestamp for the statistics
            ip_stats: Dictionary with IP statistics
                      Format: {'ip_address': {'sent_packets': a, 'recv_packets': b,
                                            'sent_bytes': c, 'recv_bytes': d}}
        
        Returns:
            bool: True if successful
        """
        try:
            cursor = self.conn.cursor()
            
            for ip_address, data in ip_stats.items():
                packets_sent = data.get('sent_packets', 0)
                packets_received = data.get('recv_packets', 0)
                bytes_sent = data.get('sent_bytes', 0)
                bytes_received = data.get('recv_bytes', 0)
                
                cursor.execute(
                    '''
                    INSERT INTO ip_stats
                    (session_id, timestamp, ip_address, packets_sent, 
                     packets_received, bytes_sent, bytes_received)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''',
                    (session_id, timestamp, ip_address, packets_sent, 
                     packets_received, bytes_sent, bytes_received)
                )
            
            self.conn.commit()
            return True
            
        except sqlite3.Error as e:
            logger.error(f"Error adding IP stats: {e}")
            return False
    
    def add_traffic_snapshot(self, session_id: int, 
                            timestamp: datetime,
                            duration_seconds: float,
                            total_packets: int,
                            total_bytes: int,
                            packets_per_second: float,
                            bytes_per_second: float,
                            stats_json: Dict[str, Any]) -> bool:
        """Add a traffic snapshot to the database.
        
        Args:
            session_id: ID of the capture session
            timestamp: Timestamp for the snapshot
            duration_seconds: Duration of the capture in seconds
            total_packets: Total packets captured
            total_bytes: Total bytes captured
            packets_per_second: Packet rate
            bytes_per_second: Byte rate
            stats_json: Additional statistics as a dictionary
        
        Returns:
            bool: True if successful
        """
        try:
            cursor = self.conn.cursor()
            
            # Convert dictionary to JSON string
            stats_str = json.dumps(stats_json)
            
            cursor.execute(
                '''
                INSERT INTO traffic_snapshots
                (session_id, timestamp, duration_seconds, total_packets,
                 total_bytes, packets_per_second, bytes_per_second, stats_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (session_id, timestamp, duration_seconds, total_packets,
                 total_bytes, packets_per_second, bytes_per_second, stats_str)
            )
            
            self.conn.commit()
            return True
            
        except sqlite3.Error as e:
            logger.error(f"Error adding traffic snapshot: {e}")
            return False
    
    def get_capture_sessions(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get a list of capture sessions.
        
        Args:
            limit: Maximum number of sessions to return
        
        Returns:
            List of dictionaries with session details
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                '''
                SELECT id, start_time, end_time, description, interface,
                       filter, packet_count, bytes_total
                FROM capture_sessions
                ORDER BY start_time DESC
                LIMIT ?
                ''',
                (limit,)
            )
            
            sessions = []
            for row in cursor.fetchall():
                sessions.append({
                    'id': row[0],
                    'start_time': datetime.fromisoformat(row[1]),
                    'end_time': datetime.fromisoformat(row[2]) if row[2] else None,
                    'description': row[3],
                    'interface': row[4],
                    'filter': row[5],
                    'packet_count': row[6],
                    'bytes_total': row[7]
                })
            
            return sessions
            
        except sqlite3.Error as e:
            logger.error(f"Error getting capture sessions: {e}")
            return []
    
    def get_packets(self, session_id: int, 
                   start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None,
                   protocol: Optional[str] = None,
                   limit: int = 1000) -> List[Dict[str, Any]]:
        """Get packets from a capture session with optional filtering.
        
        Args:
            session_id: ID of the capture session
            start_time: Optional start time filter
            end_time: Optional end time filter
            protocol: Optional protocol filter
            limit: Maximum number of packets to return
        
        Returns:
            List of dictionaries with packet details
        """
        try:
            cursor = self.conn.cursor()
            
            query = '''
                SELECT id, capture_time, protocol, src_ip, dst_ip,
                       src_port, dst_port, src_mac, dst_mac, length, info
                FROM packets
                WHERE session_id = ?
            '''
            
            params = [session_id]
            
            if start_time:
                query += " AND capture_time >= ?"
                params.append(start_time.isoformat())
                
            if end_time:
                query += " AND capture_time <= ?"
                params.append(end_time.isoformat())
                
            if protocol:
                query += " AND protocol = ?"
                params.append(protocol)
                
            query += " ORDER BY capture_time ASC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            
            packets = []
            for row in cursor.fetchall():
                packets.append({
                    'id': row[0],
                    'time': datetime.fromisoformat(row[1]),
                    'protocol': row[2],
                    'src_ip': row[3],
                    'dst_ip': row[4],
                    'src_port': row[5],
                    'dst_port': row[6],
                    'src_mac': row[7],
                    'dst_mac': row[8],
                    'length': row[9],
                    'info': row[10]
                })
            
            return packets
            
        except sqlite3.Error as e:
            logger.error(f"Error getting packets: {e}")
            return []
    
    def get_protocol_distribution(self, session_id: int) -> Dict[str, int]:
        """Get protocol distribution for a capture session.
        
        Args:
            session_id: ID of the capture session
        
        Returns:
            Dictionary with protocols and their packet counts
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                '''
                SELECT protocol, COUNT(*) as count
                FROM packets
                WHERE session_id = ?
                GROUP BY protocol
                ORDER BY count DESC
                ''',
                (session_id,)
            )
            
            distribution = {}
            for row in cursor.fetchall():
                distribution[row[0]] = row[1]
            
            return distribution
            
        except sqlite3.Error as e:
            logger.error(f"Error getting protocol distribution: {e}")
            return {}
    
    def get_traffic_over_time(self, session_id: int) -> List[Dict[str, Any]]:
        """Get traffic snapshots over time for a capture session.
        
        Args:
            session_id: ID of the capture session
        
        Returns:
            List of dictionaries with traffic snapshot details
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                '''
                SELECT timestamp, total_packets, total_bytes,
                       packets_per_second, bytes_per_second, stats_json
                FROM traffic_snapshots
                WHERE session_id = ?
                ORDER BY timestamp ASC
                ''',
                (session_id,)
            )
            
            snapshots = []
            for row in cursor.fetchall():
                snapshot = {
                    'timestamp': datetime.fromisoformat(row[0]),
                    'total_packets': row[1],
                    'total_bytes': row[2],
                    'packets_per_second': row[3],
                    'bytes_per_second': row[4]
                }
                
                # Parse JSON stats
                try:
                    stats = json.loads(row[5])
                    snapshot['stats'] = stats
                except:
                    snapshot['stats'] = {}
                    
                snapshots.append(snapshot)
            
            return snapshots
            
        except sqlite3.Error as e:
            logger.error(f"Error getting traffic over time: {e}")
            return []
    
    def get_top_talkers(self, session_id: int, limit: int = 10) -> Dict[str, Dict[str, int]]:
        """Get top talkers (IP addresses) for a capture session.
        
        Args:
            session_id: ID of the capture session
            limit: Maximum number of talkers to return
        
        Returns:
            Dictionary with IP addresses and their traffic stats
        """
        try:
            cursor = self.conn.cursor()
            
            # Query for source IPs (sent packets)
            cursor.execute(
                '''
                SELECT src_ip, COUNT(*) as sent_count, SUM(length) as sent_bytes
                FROM packets
                WHERE session_id = ? AND src_ip IS NOT NULL
                GROUP BY src_ip
                ORDER BY sent_count DESC
                LIMIT ?
                ''',
                (session_id, limit)
            )
            
            # Process sent packets
            top_talkers = {}
            for row in cursor.fetchall():
                ip = row[0]
                top_talkers[ip] = {
                    'sent_packets': row[1],
                    'sent_bytes': row[2],
                    'recv_packets': 0,
                    'recv_bytes': 0
                }
            
            # Query for destination IPs (received packets)
            cursor.execute(
                '''
                SELECT dst_ip, COUNT(*) as recv_count, SUM(length) as recv_bytes
                FROM packets
                WHERE session_id = ? AND dst_ip IS NOT NULL
                GROUP BY dst_ip
                ''',
                (session_id,)
            )
            
            # Process received packets
            for row in cursor.fetchall():
                ip = row[0]
                if ip in top_talkers:
                    top_talkers[ip]['recv_packets'] = row[1]
                    top_talkers[ip]['recv_bytes'] = row[2]
                elif len(top_talkers) < limit:
                    # Add new entry if we have space
                    top_talkers[ip] = {
                        'sent_packets': 0,
                        'sent_bytes': 0,
                        'recv_packets': row[1],
                        'recv_bytes': row[2]
                    }
            
            # Sort by total packets
            sorted_talkers = {}
            for ip, stats in sorted(
                top_talkers.items(),
                key=lambda x: x[1]['sent_packets'] + x[1]['recv_packets'],
                reverse=True
            )[:limit]:
                sorted_talkers[ip] = stats
                
            return sorted_talkers
            
        except sqlite3.Error as e:
            logger.error(f"Error getting top talkers: {e}")
            return {}
    
    def get_session_summary(self, session_id: int) -> Dict[str, Any]:
        """Get a summary of a capture session.
        
        Args:
            session_id: ID of the capture session
        
        Returns:
            Dictionary with session summary
        """
        try:
            cursor = self.conn.cursor()
            
            # Get session details
            cursor.execute(
                '''
                SELECT start_time, end_time, description, interface,
                       filter, packet_count, bytes_total
                FROM capture_sessions
                WHERE id = ?
                ''',
                (session_id,)
            )
            
            row = cursor.fetchone()
            if not row:
                return {}
                
            start_time = datetime.fromisoformat(row[0])
            end_time = datetime.fromisoformat(row[1]) if row[1] else None
            
            # Calculate duration
            if end_time:
                duration_seconds = (end_time - start_time).total_seconds()
            else:
                duration_seconds = 0
                
            # Get protocol distribution
            protocol_dist = self.get_protocol_distribution(session_id)
            
            # Get top talkers
            top_talkers = self.get_top_talkers(session_id, 5)
            
            return {
                'id': session_id,
                'start_time': start_time,
                'end_time': end_time,
                'description': row[2],
                'interface': row[3],
                'filter': row[4],
                'packet_count': row[5],
                'bytes_total': row[6],
                'duration_seconds': duration_seconds,
                'protocol_distribution': protocol_dist,
                'top_talkers': top_talkers
            }
            
        except sqlite3.Error as e:
            logger.error(f"Error getting session summary: {e}")
            return {}
    
    def delete_session(self, session_id: int) -> bool:
        """Delete a capture session and all its associated data.
        
        Args:
            session_id: ID of the capture session
        
        Returns:
            bool: True if successful
        """
        try:
            cursor = self.conn.cursor()
            
            # Foreign key constraints will cascade the delete to related tables
            cursor.execute(
                "DELETE FROM capture_sessions WHERE id = ?",
                (session_id,)
            )
            
            self.conn.commit()
            logger.info(f"Deleted capture session {session_id}")
            return True
            
        except sqlite3.Error as e:
            logger.error(f"Error deleting session: {e}")
            return False
    
    def purge_old_sessions(self, days: int = 30) -> int:
        """Delete capture sessions older than the specified number of days.
        
        Args:
            days: Number of days to keep
        
        Returns:
            int: Number of deleted sessions
        """
        try:
            cursor = self.conn.cursor()
            
            # Calculate cutoff date
            cutoff_date = datetime.now().replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            cutoff_date = cutoff_date.replace(
                day=cutoff_date.day - days
            )
            
            # Get count of sessions to delete
            cursor.execute(
                "SELECT COUNT(*) FROM capture_sessions WHERE start_time < ?",
                (cutoff_date.isoformat(),)
            )
            count = cursor.fetchone()[0]
            
            # Delete old sessions
            cursor.execute(
                "DELETE FROM capture_sessions WHERE start_time < ?",
                (cutoff_date.isoformat(),)
            )
            
            self.conn.commit()
            logger.info(f"Purged {count} capture sessions older than {days} days")
            return count
            
        except sqlite3.Error as e:
            logger.error(f"Error purging old sessions: {e}")
            return 0

# Create a singleton instance
_db_instance = None

def get_database() -> Database:
    """Get the database singleton instance.
    
    Returns:
        Database: The database instance
    """
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance 