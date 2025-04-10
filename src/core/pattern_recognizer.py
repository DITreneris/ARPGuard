import logging
import time
import threading
from typing import Dict, List, Optional, Any, Set, Callable

from src.core.pattern_database import PatternDatabase, Pattern, PatternCategory
from src.core.pattern_matcher import PatternMatcher, MatchResult
from src.core.alert import AlertManager, AlertType, AlertPriority, Alert

logger = logging.getLogger(__name__)

class PatternRecognizer:
    """
    Main orchestrator for pattern-based ARP attack detection.
    
    This class integrates the pattern database, matcher, and alert system to
    detect and report ARP-based attacks in real-time.
    """
    
    def __init__(
        self,
        alert_manager: AlertManager,
        database_path: Optional[str] = None,
        min_confidence: float = 0.7,
        alert_cooldown: float = 60.0,  # seconds
        context_update_interval: float = 5.0  # seconds
    ):
        """
        Initialize the pattern recognizer.
        
        Args:
            alert_manager: Alert manager for sending alerts
            database_path: Path to pattern database file
            min_confidence: Minimum confidence score to generate alert
            alert_cooldown: Minimum time between alerts for the same pattern
            context_update_interval: Time between context updates
        """
        self.alert_manager = alert_manager
        self.database_path = database_path
        self.min_confidence = min_confidence
        self.alert_cooldown = alert_cooldown
        self.context_update_interval = context_update_interval
        
        # Initialize pattern database
        self.pattern_database = PatternDatabase(database_path)
        
        # Initialize pattern matcher
        self.pattern_matcher = PatternMatcher(self.pattern_database)
        
        # Internal state
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.last_context_update = 0.0
        self.last_alert_times: Dict[str, float] = {}  # pattern_id -> last alert time
        self.alerting_patterns: Set[str] = set()  # Set of currently alerting pattern IDs
        
        # Callback for external updates
        self.network_stats_callback: Optional[Callable[[], Dict[str, Any]]] = None
        
        # Alert counter for stats
        self.alert_counts: Dict[str, int] = {}  # pattern_id -> count
        self.total_packets_processed = 0
        self.total_matches = 0
    
    def set_network_stats_callback(self, callback: Callable[[], Dict[str, Any]]) -> None:
        """
        Set callback for retrieving network statistics.
        
        Args:
            callback: Function that returns a dict of network stats
        """
        self.network_stats_callback = callback
    
    def set_context_value(self, key: str, value: Any) -> None:
        """
        Set a value in the context.
        
        Args:
            key: Context key
            value: Value to set
        """
        self.pattern_matcher.update_context(key, value)
    
    def process_packet(self, packet_data: Dict[str, Any]) -> List[MatchResult]:
        """
        Process a packet and check for pattern matches.
        
        Args:
            packet_data: Dictionary containing packet data
            
        Returns:
            List of match results
        """
        self.total_packets_processed += 1
        
        # Update context at regular intervals
        current_time = time.time()
        if current_time - self.last_context_update >= self.context_update_interval:
            self._update_context()
            self.last_context_update = current_time
        
        # Process packet through pattern matcher
        match_results = self.pattern_matcher.process_packet(packet_data)
        
        # Generate alerts for matches
        if match_results:
            self.total_matches += len(match_results)
            self._generate_alerts(match_results, packet_data)
        
        return match_results
    
    def process_packet_batch(self, packet_batch: List[Dict[str, Any]]) -> List[MatchResult]:
        """
        Process a batch of packets.
        
        Args:
            packet_batch: List of packet data dictionaries
            
        Returns:
            List of match results
        """
        all_results = []
        
        for packet_data in packet_batch:
            results = self.process_packet(packet_data)
            all_results.extend(results)
        
        return all_results
    
    def _update_context(self) -> None:
        """Update context with current network statistics."""
        if self.network_stats_callback:
            try:
                network_stats = self.network_stats_callback()
                
                # Update rate-related context values
                if "packet_rate" in network_stats:
                    self.pattern_matcher.update_context("packet_rate", network_stats["packet_rate"])
                
                # Update other context values as needed
                for key, value in network_stats.items():
                    if key in [
                        "gateway_ip", 
                        "gateway_mac", 
                        "high_rate_threshold",
                        "multiple_targets_threshold",
                        "random_mac_threshold",
                        "rapid_changes_threshold"
                    ]:
                        self.pattern_matcher.update_context(key, value)
                        
            except Exception as e:
                logger.error(f"Error updating context from network stats: {e}")
    
    def _generate_alerts(self, match_results: List[MatchResult], packet_data: Dict[str, Any]) -> None:
        """
        Generate alerts for pattern matches.
        
        Args:
            match_results: List of match results
            packet_data: Original packet data
        """
        current_time = time.time()
        
        for match_result in match_results:
            pattern_id = match_result.pattern_id
            
            # Check if this pattern is in cooldown
            if pattern_id in self.last_alert_times:
                last_alert_time = self.last_alert_times[pattern_id]
                if current_time - last_alert_time < self.alert_cooldown:
                    # Still in cooldown, don't alert again
                    continue
            
            # Update alert count
            self.alert_counts[pattern_id] = self.alert_counts.get(pattern_id, 0) + 1
            
            # Determine alert priority based on match score and pattern severity
            severity = match_result.details.get("severity", 5)
            alert_priority = self._determine_alert_priority(match_result.score, severity)
            
            # Create alert
            alert_message = self._format_alert_message(match_result)
            self.alert_manager.create_alert(
                AlertType.PATTERN_MATCH,
                alert_priority,
                alert_message,
                source="pattern_recognizer",
                details={
                    "pattern_id": pattern_id,
                    "pattern_name": match_result.pattern_name,
                    "score": match_result.score,
                    "matched_features": match_result.matched_features,
                    "total_features": match_result.total_features,
                    "category": match_result.details.get("category"),
                    "severity": severity,
                    "packet_data": packet_data
                }
            )
            
            # Update last alert time
            self.last_alert_times[pattern_id] = current_time
            
            logger.info(f"Generated alert for pattern {pattern_id}: {match_result.pattern_name} (score: {match_result.score:.2f})")
            
            # Add to alerting patterns
            self.alerting_patterns.add(pattern_id)
    
    def _determine_alert_priority(self, score: float, severity: int) -> AlertPriority:
        """
        Determine alert priority based on match score and pattern severity.
        
        Args:
            score: Match score (0.0 - 1.0)
            severity: Pattern severity (1-10)
            
        Returns:
            Alert priority level
        """
        # Combine score and severity into a priority factor (0.0 - 10.0)
        priority_factor = score * severity
        
        if priority_factor >= 8.0:
            return AlertPriority.CRITICAL
        elif priority_factor >= 6.0:
            return AlertPriority.HIGH
        elif priority_factor >= 4.0:
            return AlertPriority.MEDIUM
        elif priority_factor >= 2.0:
            return AlertPriority.LOW
        else:
            return AlertPriority.INFO
    
    def _format_alert_message(self, match_result: MatchResult) -> str:
        """
        Format alert message based on match result.
        
        Args:
            match_result: Match result
            
        Returns:
            Formatted alert message
        """
        category = match_result.details.get("category", "unknown")
        score_pct = int(match_result.score * 100)
        
        return (
            f"ARP attack pattern detected: {match_result.pattern_name} "
            f"(category: {category}, confidence: {score_pct}%, "
            f"matched {len(match_result.matched_features)}/{match_result.total_features} features)"
        )
    
    def start_monitoring(self) -> None:
        """Start background monitoring thread."""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.thread.start()
        
        logger.info("Started pattern recognizer monitoring thread")
    
    def stop_monitoring(self) -> None:
        """Stop background monitoring thread."""
        if not self.running:
            return
        
        self.running = False
        
        if self.thread:
            try:
                self.thread.join(timeout=2.0)
            except Exception:
                pass
            
            self.thread = None
            
        logger.info("Stopped pattern recognizer monitoring thread")
    
    def _monitoring_loop(self) -> None:
        """Background monitoring loop."""
        while self.running:
            try:
                # Update context
                self._update_context()
                
                # Sleep for the update interval
                time.sleep(self.context_update_interval)
                
            except Exception as e:
                logger.error(f"Error in pattern recognizer monitoring loop: {e}")
                time.sleep(1.0)  # Avoid busy loop in case of errors
    
    def get_alerting_patterns(self) -> List[Pattern]:
        """
        Get list of currently alerting patterns.
        
        Returns:
            List of patterns that are currently generating alerts
        """
        return [
            self.pattern_database.get_pattern(pattern_id)
            for pattern_id in self.alerting_patterns
            if self.pattern_database.get_pattern(pattern_id) is not None
        ]
    
    def reset_alerting_patterns(self) -> None:
        """Reset the list of alerting patterns."""
        self.alerting_patterns.clear()
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get status information about the pattern recognizer.
        
        Returns:
            Dictionary with status information
        """
        # Get some database stats
        patterns = self.pattern_database.get_all_patterns()
        patterns_by_category = {}
        for pattern in patterns:
            category = pattern.category.name
            if category not in patterns_by_category:
                patterns_by_category[category] = 0
            patterns_by_category[category] += 1
        
        # Calculate top alerting patterns
        top_alerting = sorted(
            [(pattern_id, count) for pattern_id, count in self.alert_counts.items()],
            key=lambda x: x[1],
            reverse=True
        )[:5]  # Top 5
        
        return {
            "running": self.running,
            "database_path": self.database_path,
            "min_confidence": self.min_confidence,
            "alert_cooldown": self.alert_cooldown,
            "context_update_interval": self.context_update_interval,
            "total_patterns": len(patterns),
            "patterns_by_category": patterns_by_category,
            "total_packets_processed": self.total_packets_processed,
            "total_matches": self.total_matches,
            "alerting_patterns_count": len(self.alerting_patterns),
            "top_alerting_patterns": [
                {
                    "pattern_id": pattern_id,
                    "pattern_name": (
                        self.pattern_database.get_pattern(pattern_id).name
                        if self.pattern_database.get_pattern(pattern_id)
                        else "Unknown"
                    ),
                    "count": count
                }
                for pattern_id, count in top_alerting
            ]
        } 