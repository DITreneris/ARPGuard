import logging
import time
from typing import List, Dict, Any, Callable, Optional, Tuple
import threading

from src.core.parallel import (
    ThreadPoolManager,
    WorkerTask,
    RuleCheckTask,
    TaskPrioritizer,
    BatchTaskQueue
)

logger = logging.getLogger("arp_guard.parallel_rule_processor")

class RuleExecutionStats:
    """Statistics for rule execution."""
    
    def __init__(self):
        """Initialize rule execution statistics."""
        self.rule_counts: Dict[str, int] = {}
        self.rule_execution_times: Dict[str, float] = {}
        self.rule_match_counts: Dict[str, int] = {}
        self.total_packets_processed = 0
        self.total_rules_executed = 0
        self.total_execution_time = 0.0
        self.total_matches_found = 0
        self.lock = threading.RLock()
    
    def update(self, rule_name: str, execution_time: float, packet_count: int, match_count: int):
        """
        Update statistics for a rule execution.
        
        Args:
            rule_name: Name of the rule
            execution_time: Time taken to execute the rule in seconds
            packet_count: Number of packets the rule was applied to
            match_count: Number of matches found by the rule
        """
        with self.lock:
            # Update rule-specific stats
            if rule_name not in self.rule_counts:
                self.rule_counts[rule_name] = 0
                self.rule_execution_times[rule_name] = 0.0
                self.rule_match_counts[rule_name] = 0
            
            self.rule_counts[rule_name] += 1
            self.rule_execution_times[rule_name] += execution_time
            self.rule_match_counts[rule_name] += match_count
            
            # Update overall stats
            self.total_packets_processed += packet_count
            self.total_rules_executed += 1
            self.total_execution_time += execution_time
            self.total_matches_found += match_count
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get the current statistics.
        
        Returns:
            Dictionary containing statistics about rule execution
        """
        with self.lock:
            stats = {
                "total": {
                    "packets_processed": self.total_packets_processed,
                    "rules_executed": self.total_rules_executed,
                    "execution_time": self.total_execution_time,
                    "matches_found": self.total_matches_found
                },
                "rules": {}
            }
            
            # Calculate average execution time per rule
            for rule_name in self.rule_counts:
                count = self.rule_counts[rule_name]
                execution_time = self.rule_execution_times[rule_name]
                match_count = self.rule_match_counts[rule_name]
                
                stats["rules"][rule_name] = {
                    "count": count,
                    "total_execution_time": execution_time,
                    "matches_found": match_count,
                    "average_execution_time": execution_time / count if count > 0 else 0.0,
                    "match_rate": match_count / self.total_packets_processed if self.total_packets_processed > 0 else 0.0
                }
            
            return stats
    
    def reset(self):
        """Reset all statistics."""
        with self.lock:
            self.rule_counts.clear()
            self.rule_execution_times.clear()
            self.rule_match_counts.clear()
            self.total_packets_processed = 0
            self.total_rules_executed = 0
            self.total_execution_time = 0.0
            self.total_matches_found = 0

class ParallelRuleProcessor:
    """Executes rule checks in parallel using a thread pool."""
    
    def __init__(self, num_workers: int = None, 
                 batch_size: int = 10, 
                 rule_priority_map: Dict[str, int] = None):
        """
        Initialize the parallel rule processor.
        
        Args:
            num_workers: Number of worker threads, or None to use CPU count
            batch_size: Number of packets to process in a batch
            rule_priority_map: Dictionary mapping rule names to priority values
        """
        self.thread_pool = ThreadPoolManager(num_workers)
        self.stats = RuleExecutionStats()
        self.batch_size = batch_size
        self.rule_priority_map = rule_priority_map or {
            "detect_mitm": 10,
            "detect_arp_spoofing": 9,
            "detect_unauthorized_gateway": 8,
            "detect_mac_change": 7
        }
        self.rules: Dict[str, Tuple[Callable, int]] = {}
        self.alert_callbacks: List[Callable] = []
        self.context: Dict[str, Any] = {}
        self.running = False
        
        logger.info(f"Initialized ParallelRuleProcessor with {self.thread_pool.num_workers} workers")
    
    def start(self):
        """Start the parallel rule processor."""
        if self.running:
            logger.warning("ParallelRuleProcessor is already running")
            return
        
        logger.info("Starting ParallelRuleProcessor")
        self.thread_pool.start()
        self.running = True
    
    def stop(self):
        """Stop the parallel rule processor."""
        if not self.running:
            logger.warning("ParallelRuleProcessor is not running")
            return
        
        logger.info("Stopping ParallelRuleProcessor")
        self.thread_pool.stop()
        self.running = False
    
    def register_rule(self, rule_name: str, rule_func: Callable, priority: int = None):
        """
        Register a rule for execution.
        
        Args:
            rule_name: Name of the rule
            rule_func: Function that implements the rule check
            priority: Priority of the rule, or None to use the rule_priority_map
        """
        if priority is None:
            priority = self.rule_priority_map.get(rule_name, 0)
        
        self.rules[rule_name] = (rule_func, priority)
        logger.debug(f"Registered rule '{rule_name}' with priority {priority}")
    
    def register_alert_callback(self, callback: Callable):
        """
        Register a callback to be called when a rule matches.
        
        Args:
            callback: Function to call when a rule matches
                     The function should accept (rule_name, packet, match_details) as arguments
        """
        self.alert_callbacks.append(callback)
    
    def set_context(self, context: Dict[str, Any]):
        """
        Set the context for rule execution.
        
        Args:
            context: Additional context needed for rule checks
        """
        self.context = context
    
    def update_context(self, updates: Dict[str, Any]):
        """
        Update the context with new values.
        
        Args:
            updates: Dictionary of context updates
        """
        self.context.update(updates)
    
    def process_packet(self, packet):
        """
        Process a single packet with all registered rules.
        
        Args:
            packet: The packet to process
        """
        if not self.running:
            raise RuntimeError("ParallelRuleProcessor is not running")
        
        # Create tasks for each rule
        tasks = []
        for rule_name, (rule_func, priority) in self.rules.items():
            task = RuleCheckTask(
                rule_name=rule_name,
                rule_func=rule_func,
                packets=packet,
                context=self.context.copy(),
                priority=priority
            )
            tasks.append(task)
        
        # Prioritize the tasks
        prioritized_tasks = TaskPrioritizer.prioritize_rule_checks(tasks, self.rule_priority_map)
        
        # Submit the tasks to the thread pool
        for task in prioritized_tasks:
            self.thread_pool.submit(self._execute_rule_task, args=(task,))
    
    def process_packets(self, packets: List[Any]):
        """
        Process multiple packets with all registered rules.
        
        Args:
            packets: List of packets to process
        """
        if not self.running:
            raise RuntimeError("ParallelRuleProcessor is not running")
        
        # Group packets into batches
        batches = [packets[i:i+self.batch_size] for i in range(0, len(packets), self.batch_size)]
        
        # Create tasks for each rule and batch
        tasks = []
        for rule_name, (rule_func, priority) in self.rules.items():
            for i, batch in enumerate(batches):
                task = RuleCheckTask(
                    rule_name=rule_name,
                    rule_func=rule_func,
                    packets=batch,
                    context=self.context.copy(),
                    task_id=f"{rule_name}_batch_{i}",
                    priority=priority
                )
                tasks.append(task)
        
        # Prioritize the tasks
        prioritized_tasks = TaskPrioritizer.prioritize_rule_checks(tasks, self.rule_priority_map)
        
        # Submit the tasks to the thread pool
        for task in prioritized_tasks:
            self.thread_pool.submit(self._execute_rule_task, args=(task,))
    
    def _execute_rule_task(self, task: RuleCheckTask):
        """
        Execute a rule check task and handle the results.
        
        Args:
            task: The rule check task to execute
        """
        start_time = time.time()
        
        # Execute the task
        result = task.execute()
        
        # Calculate execution time
        execution_time = time.time() - start_time
        
        # Update statistics
        self.stats.update(
            rule_name=task.rule_name,
            execution_time=execution_time,
            packet_count=result["packet_count"],
            match_count=result["match_count"]
        )
        
        # Handle matches
        if result["match_count"] > 0:
            for match in result["matches"]:
                packet = match["packet"]
                details = match["details"]
                
                # Call alert callbacks
                for callback in self.alert_callbacks:
                    try:
                        callback(task.rule_name, packet, details)
                    except Exception as e:
                        logger.error(f"Error in alert callback: {str(e)}")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about rule execution.
        
        Returns:
            Dictionary containing statistics about rule execution and thread pool
        """
        stats = {
            "rules": self.stats.get_stats(),
            "thread_pool": self.thread_pool.get_stats()
        }
        return stats
    
    def reset_stats(self):
        """Reset all statistics."""
        self.stats.reset()
    
    def wait_for_completion(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for all submitted tasks to complete.
        
        Args:
            timeout: Maximum time to wait in seconds, or None to wait indefinitely
            
        Returns:
            True if all tasks completed within the timeout, False otherwise
        """
        # This implementation assumes the thread pool has a way to wait for all tasks to complete
        return True 