import logging
import time
import threading
from typing import List, Dict, Any, Optional, Callable
import queue

from src.core.detection_module import DetectionModule
from src.core.parallel_rule_processor import ParallelRuleProcessor
from src.core.parallel import ThreadPoolManager, BatchTaskQueue

logger = logging.getLogger("arp_guard.parallel_detection")

class ParallelDetectionModule(DetectionModule):
    """
    Enhanced version of the DetectionModule that uses parallel processing for rule checks.
    This class inherits from the base DetectionModule and overrides methods to use
    parallel processing where appropriate.
    """
    
    def __init__(self, interface=None, num_workers=None, batch_size=20, **kwargs):
        """
        Initialize the parallel detection module.
        
        Args:
            interface: Network interface to monitor
            num_workers: Number of worker threads for parallel processing, or None to use CPU count
            batch_size: Number of packets to process in a batch
            **kwargs: Additional arguments to pass to the base DetectionModule
        """
        # Initialize the base detection module
        super().__init__(interface=interface, **kwargs)
        
        # Initialize the parallel rule processor
        self.rule_processor = ParallelRuleProcessor(
            num_workers=num_workers,
            batch_size=batch_size,
            rule_priority_map={
                "detect_mitm": 10,
                "detect_arp_spoofing": 9,
                "detect_unauthorized_gateway": 8,
                "detect_mac_change": 7,
                "detect_arp_scan": 6,
                "detect_gratuitous_arp": 5
            }
        )
        
        # Initialize additional components for parallel processing
        self.packet_batch_queue = queue.Queue()
        self.batch_processing_thread = None
        self.batch_size = batch_size
        self.current_batch = []
        self.batch_lock = threading.RLock()
        self.last_batch_time = time.time()
        self.batch_timeout = 0.5  # seconds
        self.batch_processing_active = False
        
        # Register rules with the parallel rule processor
        self._register_rules()
        
        # Register alert callback
        self.rule_processor.register_alert_callback(self._handle_rule_match)
        
        logger.info(f"Initialized ParallelDetectionModule with {num_workers or 'auto'} workers, batch size {batch_size}")
    
    def _register_rules(self):
        """Register detection rules with the parallel rule processor."""
        # Register rules from the base DetectionModule
        # This assumes that the base class has rule methods that can be extracted
        rule_methods = {
            "detect_arp_spoofing": self._check_arp_spoofing,
            "detect_mitm": self._check_mitm_attack,
            "detect_unauthorized_gateway": self._check_unauthorized_gateway,
            "detect_mac_change": self._check_mac_change,
            "detect_arp_scan": self._check_arp_scan,
            "detect_gratuitous_arp": self._check_gratuitous_arp
        }
        
        for rule_name, rule_method in rule_methods.items():
            self.rule_processor.register_rule(rule_name, rule_method)
            logger.debug(f"Registered rule '{rule_name}'")
    
    def _handle_rule_match(self, rule_name: str, packet, details: Dict[str, Any]):
        """
        Handle a rule match from the parallel rule processor.
        
        Args:
            rule_name: Name of the rule that matched
            packet: The packet that matched the rule
            details: Additional details about the match
        """
        # Extract relevant information from the packet and details
        source_ip = getattr(packet, "psrc", None) or details.get("source_ip")
        source_mac = getattr(packet, "hwsrc", None) or details.get("source_mac")
        target_ip = getattr(packet, "pdst", None) or details.get("target_ip")
        target_mac = getattr(packet, "hwdst", None) or details.get("target_mac")
        severity = details.get("severity", "medium")
        
        # Create an alert
        alert = {
            "rule": rule_name,
            "timestamp": time.time(),
            "source_ip": source_ip,
            "source_mac": source_mac,
            "target_ip": target_ip,
            "target_mac": target_mac,
            "severity": severity,
            "details": details
        }
        
        # Add the alert to suspicious sources
        self._add_suspicious_source(source_ip, source_mac, rule_name, details)
        
        # Update statistics
        with self.stats_lock:
            self.stats["alerts"] += 1
            self.stats["alerts_by_severity"][severity] = self.stats["alerts_by_severity"].get(severity, 0) + 1
            self.stats["alerts_by_rule"][rule_name] = self.stats["alerts_by_rule"].get(rule_name, 0) + 1
        
        # Call alert callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {str(e)}")
    
    def start(self):
        """Start the parallel detection module."""
        if self.running:
            logger.warning("ParallelDetectionModule is already running")
            return
        
        logger.info("Starting ParallelDetectionModule")
        
        # Start the rule processor
        self.rule_processor.start()
        
        # Start batch processing thread
        self.batch_processing_active = True
        self.batch_processing_thread = threading.Thread(
            target=self._batch_processing_worker,
            daemon=True,
            name="BatchProcessingThread"
        )
        self.batch_processing_thread.start()
        
        # Start the base detection module
        super().start()
    
    def stop(self):
        """Stop the parallel detection module."""
        if not self.running:
            logger.warning("ParallelDetectionModule is not running")
            return
        
        logger.info("Stopping ParallelDetectionModule")
        
        # Stop batch processing
        self.batch_processing_active = False
        if self.batch_processing_thread and self.batch_processing_thread.is_alive():
            self.batch_processing_thread.join(timeout=2.0)
        
        # Stop the rule processor
        self.rule_processor.stop()
        
        # Stop the base detection module
        super().stop()
    
    def _process_packet(self, packet):
        """
        Process a packet by adding it to the current batch.
        
        Args:
            packet: The packet to process
        """
        with self.batch_lock:
            # Add the packet to the current batch
            self.current_batch.append(packet)
            
            # Update statistics
            with self.stats_lock:
                self.stats["packets_processed"] += 1
                packet_type = getattr(packet, "type", "unknown").lower()
                self.stats["packets_by_type"][packet_type] = self.stats["packets_by_type"].get(packet_type, 0) + 1
            
            # Check if the batch is full or the timeout has expired
            current_time = time.time()
            if (len(self.current_batch) >= self.batch_size or 
                current_time - self.last_batch_time >= self.batch_timeout):
                self._submit_batch()
    
    def _submit_batch(self):
        """Submit the current batch for processing and start a new batch."""
        if not self.current_batch:
            return
        
        # Create a copy of the current batch
        batch = list(self.current_batch)
        self.current_batch = []
        self.last_batch_time = time.time()
        
        # Submit the batch to the queue
        self.packet_batch_queue.put(batch)
        logger.debug(f"Submitted batch of {len(batch)} packets for processing")
    
    def _batch_processing_worker(self):
        """Worker thread that processes batches of packets from the queue."""
        logger.info("Batch processing worker started")
        
        while self.batch_processing_active:
            try:
                # Check if we need to submit the current batch due to timeout
                with self.batch_lock:
                    current_time = time.time()
                    if (self.current_batch and 
                        current_time - self.last_batch_time >= self.batch_timeout):
                        self._submit_batch()
                
                # Get a batch from the queue
                try:
                    batch = self.packet_batch_queue.get(block=True, timeout=0.5)
                except queue.Empty:
                    continue
                
                # Process the batch
                try:
                    # Update context with current state
                    self.rule_processor.set_context({
                        "arp_table": self.get_arp_table(),
                        "gateway_ips": self._get_gateway_ips(),
                        "suspicious_sources": self.get_suspicious_sources(),
                        "trusted_hosts": self.trusted_hosts
                    })
                    
                    # Process the packets in parallel
                    self.rule_processor.process_packets(batch)
                    
                    # Update statistics
                    with self.stats_lock:
                        self.stats["batches_processed"] += 1
                
                except Exception as e:
                    logger.error(f"Error processing batch: {str(e)}")
                
                # Mark the batch as done in the queue
                self.packet_batch_queue.task_done()
                
            except Exception as e:
                logger.error(f"Error in batch processing worker: {str(e)}")
        
        logger.info("Batch processing worker stopped")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about packet processing and rule execution.
        
        Returns:
            Dictionary containing statistics
        """
        # Get basic stats from the base class
        base_stats = super().get_stats()
        
        # Add parallel processing stats
        with self.stats_lock:
            stats = base_stats.copy()
            if not hasattr(stats, "batches_processed"):
                stats["batches_processed"] = 0
            
            # Add rule processor stats
            rule_stats = self.rule_processor.get_stats()
            stats["parallel"] = {
                "rule_processing": rule_stats["rules"],
                "thread_pool": rule_stats["thread_pool"],
                "batch_queue_size": self.packet_batch_queue.qsize(),
                "current_batch_size": len(self.current_batch)
            }
            
            return stats
    
    def wait_for_completion(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for all submitted packets to be processed.
        
        Args:
            timeout: Maximum time to wait in seconds, or None to wait indefinitely
            
        Returns:
            True if all packets were processed within the timeout, False otherwise
        """
        start_time = time.time()
        
        # Submit any remaining packets in the current batch
        with self.batch_lock:
            self._submit_batch()
        
        # Wait for the batch queue to be empty
        try:
            self.packet_batch_queue.join()
        except Exception:
            pass
        
        # Wait for the rule processor to complete all tasks
        return self.rule_processor.wait_for_completion(timeout) 