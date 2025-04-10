from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger("arp_guard.parallel")

class WorkerTask(ABC):
    """Abstract base class for tasks that can be executed by worker threads."""
    
    def __init__(self, task_id: str = None, priority: int = 0):
        """
        Initialize a worker task.
        
        Args:
            task_id: Unique identifier for this task
            priority: Priority level (higher numbers = higher priority)
        """
        self.task_id = task_id
        self.priority = priority
        self.result = None
        self.error = None
        self.metadata: Dict[str, Any] = {}
    
    @abstractmethod
    def execute(self) -> Any:
        """
        Execute the task and return the result.
        
        This method must be implemented by subclasses.
        
        Returns:
            The result of the task execution
        """
        pass
    
    def on_success(self, result: Any):
        """
        Called when the task is executed successfully.
        
        Args:
            result: The result returned by the execute method
        """
        self.result = result
    
    def on_error(self, error: Exception):
        """
        Called when an error occurs during task execution.
        
        Args:
            error: The exception that was raised
        """
        self.error = error
        logger.error(f"Error executing task {self.task_id}: {str(error)}")
    
    def on_complete(self):
        """Called when the task is completed, regardless of success or failure."""
        pass

class RuleCheckTask(WorkerTask):
    """Task for checking a specific rule on a packet or batch of packets."""
    
    def __init__(self, rule_name: str, rule_func, packets, context: Dict[str, Any] = None, 
                 task_id: str = None, priority: int = 0):
        """
        Initialize a rule check task.
        
        Args:
            rule_name: Name of the rule to check
            rule_func: Function that implements the rule check
            packets: Packet or list of packets to check
            context: Additional context needed for the rule check
            task_id: Unique identifier for this task
            priority: Priority level (higher numbers = higher priority)
        """
        super().__init__(task_id, priority)
        self.rule_name = rule_name
        self.rule_func = rule_func
        self.packets = packets if isinstance(packets, list) else [packets]
        self.context = context or {}
        self.metadata.update({
            "rule_name": rule_name,
            "packet_count": len(self.packets)
        })
    
    def execute(self) -> Dict[str, Any]:
        """
        Execute the rule check on all packets.
        
        Returns:
            Dictionary containing the results of the rule check
        """
        logger.debug(f"Executing rule check '{self.rule_name}' on {len(self.packets)} packets")
        
        results = {
            "rule_name": self.rule_name,
            "matches": [],
            "packet_count": len(self.packets),
            "match_count": 0
        }
        
        for packet in self.packets:
            try:
                match = self.rule_func(packet, self.context)
                if match:
                    results["matches"].append({
                        "packet": packet,
                        "details": match if isinstance(match, dict) else {"matched": True}
                    })
                    results["match_count"] += 1
            except Exception as e:
                logger.error(f"Error checking rule '{self.rule_name}' on packet: {str(e)}")
                # Continue processing other packets
        
        return results

class BatchProcessingTask(WorkerTask):
    """Task for processing a batch of packets with multiple operations."""
    
    def __init__(self, processor_func, packets, batch_id: str = None, 
                 options: Dict[str, Any] = None, task_id: str = None, priority: int = 0):
        """
        Initialize a batch processing task.
        
        Args:
            processor_func: Function that processes the batch of packets
            packets: List of packets to process
            batch_id: Identifier for this batch
            options: Options for batch processing
            task_id: Unique identifier for this task
            priority: Priority level (higher numbers = higher priority)
        """
        super().__init__(task_id, priority)
        self.processor_func = processor_func
        self.packets = packets
        self.batch_id = batch_id or f"batch_{id(self)}"
        self.options = options or {}
        self.metadata.update({
            "batch_id": self.batch_id,
            "packet_count": len(packets)
        })
    
    def execute(self) -> Dict[str, Any]:
        """
        Execute the batch processing.
        
        Returns:
            Dictionary containing the results of the batch processing
        """
        logger.debug(f"Processing batch {self.batch_id} with {len(self.packets)} packets")
        
        start_time = None
        try:
            import time
            start_time = time.time()
            result = self.processor_func(self.packets, self.options)
            processing_time = time.time() - start_time
            
            # Add processing time to result
            if isinstance(result, dict):
                result["processing_time"] = processing_time
            
            return result
        except Exception as e:
            logger.error(f"Error processing batch {self.batch_id}: {str(e)}")
            processing_time = time.time() - start_time if start_time else 0
            return {
                "error": str(e),
                "processing_time": processing_time,
                "success": False
            }

class TaskPrioritizer:
    """Utility class for prioritizing tasks based on various criteria."""
    
    @staticmethod
    def prioritize_packets_by_type(packets: List[Any], priority_map: Dict[str, int] = None) -> List[Any]:
        """
        Prioritize packets based on their type.
        
        Args:
            packets: List of packets to prioritize
            priority_map: Dictionary mapping packet types to priority values
            
        Returns:
            Sorted list of packets
        """
        if not priority_map:
            # Default priority map - can be customized
            priority_map = {
                "arp": 10,
                "icmp": 8,
                "tcp": 5,
                "udp": 3
            }
        
        def get_packet_priority(packet):
            # This assumes packets have a 'type' attribute or similar
            # Adjust this logic based on your actual packet structure
            packet_type = getattr(packet, "type", "").lower()
            return priority_map.get(packet_type, 0)
        
        return sorted(packets, key=get_packet_priority, reverse=True)
    
    @staticmethod
    def prioritize_tasks(tasks: List[WorkerTask]) -> List[WorkerTask]:
        """
        Prioritize tasks based on their priority attribute.
        
        Args:
            tasks: List of tasks to prioritize
            
        Returns:
            Sorted list of tasks
        """
        return sorted(tasks, key=lambda task: task.priority, reverse=True)
    
    @staticmethod
    def prioritize_rule_checks(tasks: List[RuleCheckTask], rule_priority_map: Dict[str, int] = None) -> List[RuleCheckTask]:
        """
        Prioritize rule check tasks based on rule importance.
        
        Args:
            tasks: List of rule check tasks to prioritize
            rule_priority_map: Dictionary mapping rule names to priority values
            
        Returns:
            Sorted list of rule check tasks
        """
        if not rule_priority_map:
            # Default rule priority map - can be customized
            rule_priority_map = {
                "detect_mitm": 10,
                "detect_arp_spoofing": 9,
                "detect_unauthorized_gateway": 8,
                "detect_mac_change": 7
            }
        
        def get_rule_priority(task):
            return rule_priority_map.get(task.rule_name, 0) + task.priority
        
        return sorted(tasks, key=get_rule_priority, reverse=True) 