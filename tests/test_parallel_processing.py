import unittest
import time
import threading
import random
from typing import List, Dict, Any

# Import the parallel processing classes
from src.core.parallel import (
    ThreadPoolManager,
    Task,
    Worker,
    WorkerTask,
    RuleCheckTask,
    BatchProcessingTask,
    TaskPrioritizer,
    PriorityTaskQueue,
    BatchTaskQueue,
    TaskScheduler
)

from src.core.parallel_rule_processor import ParallelRuleProcessor
from src.core.parallel_detection_module import ParallelDetectionModule

class MockPacket:
    """Mock packet class for testing."""
    
    def __init__(self, psrc, hwsrc, pdst, hwdst, packet_type="arp"):
        self.psrc = psrc
        self.hwsrc = hwsrc
        self.pdst = pdst
        self.hwdst = hwdst
        self.type = packet_type

class TestTask(WorkerTask):
    """Simple task implementation for testing."""
    
    def __init__(self, func, args=None, kwargs=None, task_id=None, priority=0):
        super().__init__(task_id, priority)
        self.func = func
        self.args = args or ()
        self.kwargs = kwargs or {}
    
    def execute(self):
        return self.func(*self.args, **self.kwargs)

class TestThreadPoolManager(unittest.TestCase):
    """Test the ThreadPoolManager class."""
    
    def test_init(self):
        """Test initializing the thread pool manager."""
        pool = ThreadPoolManager(2)
        self.assertEqual(pool.num_workers, 2)
        self.assertFalse(pool.running)
    
    def test_start_stop(self):
        """Test starting and stopping the thread pool."""
        pool = ThreadPoolManager(2)
        pool.start()
        self.assertTrue(pool.running)
        self.assertEqual(len(pool.workers), 2)
        
        pool.stop()
        self.assertFalse(pool.running)
        self.assertEqual(len(pool.workers), 0)
    
    def test_submit(self):
        """Test submitting a task to the thread pool."""
        pool = ThreadPoolManager(2)
        pool.start()
        
        # Define a simple task function
        def add(a, b):
            return a + b
        
        # Submit the task
        task = pool.submit(add, args=(1, 2))
        
        # Wait for the task to complete
        task.wait(timeout=1.0)
        
        # Check the result
        self.assertEqual(task.result, 3)
        
        pool.stop()
    
    def test_map(self):
        """Test mapping a function over a list of items."""
        pool = ThreadPoolManager(2)
        pool.start()
        
        # Define a simple task function
        def square(x):
            return x * x
        
        # Map the function over a list
        items = [1, 2, 3, 4, 5]
        tasks = pool.map(square, items)
        
        # Wait for all tasks to complete
        pool.wait_for_all(tasks, timeout=1.0)
        
        # Check the results
        results = pool.get_results(tasks)
        self.assertEqual(results, [1, 4, 9, 16, 25])
        
        pool.stop()

class TestWorkerTask(unittest.TestCase):
    """Test the WorkerTask class and its subclasses."""
    
    def test_rule_check_task(self):
        """Test the RuleCheckTask class."""
        # Define a simple rule function
        def check_is_gateway(packet, context):
            if packet.psrc in context.get("gateway_ips", []):
                return {"matched": True, "is_gateway": True}
            return None
        
        # Create a mock packet
        packet = MockPacket("192.168.1.1", "00:11:22:33:44:55", "192.168.1.2", "66:77:88:99:AA:BB")
        
        # Create a context with gateway IPs
        context = {"gateway_ips": ["192.168.1.1"]}
        
        # Create a RuleCheckTask
        task = RuleCheckTask(
            rule_name="check_is_gateway",
            rule_func=check_is_gateway,
            packets=packet,
            context=context
        )
        
        # Execute the task
        result = task.execute()
        
        # Check the result
        self.assertEqual(result["rule_name"], "check_is_gateway")
        self.assertEqual(result["packet_count"], 1)
        self.assertEqual(result["match_count"], 1)
        self.assertEqual(len(result["matches"]), 1)
        self.assertEqual(result["matches"][0]["packet"], packet)
        self.assertEqual(result["matches"][0]["details"]["matched"], True)
        self.assertEqual(result["matches"][0]["details"]["is_gateway"], True)
    
    def test_batch_processing_task(self):
        """Test the BatchProcessingTask class."""
        # Define a batch processing function
        def count_by_type(packets, options):
            counts = {}
            for packet in packets:
                packet_type = packet.type
                counts[packet_type] = counts.get(packet_type, 0) + 1
            return counts
        
        # Create some mock packets
        packets = [
            MockPacket("192.168.1.1", "00:11:22:33:44:55", "192.168.1.2", "66:77:88:99:AA:BB", "arp"),
            MockPacket("192.168.1.3", "CC:DD:EE:FF:00:11", "192.168.1.4", "22:33:44:55:66:77", "icmp"),
            MockPacket("192.168.1.5", "88:99:AA:BB:CC:DD", "192.168.1.6", "EE:FF:00:11:22:33", "arp")
        ]
        
        # Create a BatchProcessingTask
        task = BatchProcessingTask(
            processor_func=count_by_type,
            packets=packets,
            batch_id="test_batch"
        )
        
        # Execute the task
        result = task.execute()
        
        # Check the result
        self.assertEqual(result["arp"], 2)
        self.assertEqual(result["icmp"], 1)
        self.assertTrue("processing_time" in result)

class TestTaskPrioritizer(unittest.TestCase):
    """Test the TaskPrioritizer class."""
    
    def test_prioritize_tasks(self):
        """Test prioritizing tasks based on priority level."""
        # Create some test tasks with different priorities
        tasks = [
            TestTask(lambda: 1, task_id="task1", priority=1),
            TestTask(lambda: 2, task_id="task2", priority=3),
            TestTask(lambda: 3, task_id="task3", priority=2)
        ]
        
        # Prioritize the tasks
        prioritized = TaskPrioritizer.prioritize_tasks(tasks)
        
        # Check the order
        self.assertEqual([t.task_id for t in prioritized], ["task2", "task3", "task1"])
    
    def test_prioritize_rule_checks(self):
        """Test prioritizing rule check tasks based on rule importance."""
        # Create some rule check tasks
        tasks = [
            RuleCheckTask(rule_name="detect_mac_change", rule_func=lambda p, c: None, packets=[]),
            RuleCheckTask(rule_name="detect_mitm", rule_func=lambda p, c: None, packets=[]),
            RuleCheckTask(rule_name="detect_arp_spoofing", rule_func=lambda p, c: None, packets=[])
        ]
        
        # Define rule priorities
        rule_priorities = {
            "detect_mitm": 10,
            "detect_arp_spoofing": 8,
            "detect_mac_change": 6
        }
        
        # Prioritize the tasks
        prioritized = TaskPrioritizer.prioritize_rule_checks(tasks, rule_priorities)
        
        # Check the order
        self.assertEqual([t.rule_name for t in prioritized], ["detect_mitm", "detect_arp_spoofing", "detect_mac_change"])

class TestPriorityTaskQueue(unittest.TestCase):
    """Test the PriorityTaskQueue class."""
    
    def test_priority_queue(self):
        """Test that tasks are processed in priority order."""
        queue = PriorityTaskQueue()
        
        # Create some test tasks with different priorities
        tasks = [
            TestTask(lambda: 1, task_id="task1", priority=1),
            TestTask(lambda: 2, task_id="task2", priority=3),
            TestTask(lambda: 3, task_id="task3", priority=2)
        ]
        
        # Add tasks to the queue
        for task in tasks:
            queue.put(task)
        
        # Get tasks from the queue
        retrieved_tasks = []
        while not queue.empty():
            retrieved_tasks.append(queue.get())
        
        # Check the order
        self.assertEqual([t.task_id for t in retrieved_tasks], ["task2", "task3", "task1"])

class TestBatchTaskQueue(unittest.TestCase):
    """Test the BatchTaskQueue class."""
    
    def test_batch_processing(self):
        """Test that tasks are batched and processed correctly."""
        # Create a processor function that concatenates task IDs
        processed_batches = []
        
        def batch_processor(batch):
            processed_batches.append([task.task_id for task in batch])
        
        # Create a batch queue
        batch_queue = BatchTaskQueue(batch_size=2, batch_processor=batch_processor)
        
        # Start the batch queue
        batch_queue.start()
        
        # Add some tasks
        tasks = [TestTask(lambda: i, task_id=f"task{i}") for i in range(5)]
        for task in tasks:
            batch_queue.put(task)
        
        # Wait for processing to complete
        time.sleep(1)
        batch_queue.flush()
        time.sleep(1)
        
        # Stop the batch queue
        batch_queue.stop()
        
        # Check that tasks were batched correctly
        self.assertEqual(len(processed_batches), 3)
        self.assertEqual(len(processed_batches[0]), 2)
        self.assertEqual(len(processed_batches[1]), 2)
        self.assertEqual(len(processed_batches[2]), 1)

class TestParallelRuleProcessor(unittest.TestCase):
    """Test the ParallelRuleProcessor class."""
    
    def test_rule_registration(self):
        """Test registering rules with the processor."""
        processor = ParallelRuleProcessor(num_workers=2)
        
        # Register a rule
        def check_rule(packet, context):
            return {"matched": True}
        
        processor.register_rule("test_rule", check_rule)
        
        # Check that the rule was registered
        self.assertIn("test_rule", processor.rules)
    
    def test_process_packet(self):
        """Test processing a single packet."""
        processor = ParallelRuleProcessor(num_workers=2)
        processor.start()
        
        # Create a mock packet
        packet = MockPacket("192.168.1.1", "00:11:22:33:44:55", "192.168.1.2", "66:77:88:99:AA:BB")
        
        # Register a rule that always matches
        def always_match(packet, context):
            return {"matched": True}
        
        processor.register_rule("always_match", always_match)
        
        # Add a callback to track alerts
        alerts = []
        def alert_callback(rule_name, packet, details):
            alerts.append((rule_name, packet, details))
        
        processor.register_alert_callback(alert_callback)
        
        # Process the packet
        processor.process_packet(packet)
        
        # Wait for processing to complete
        time.sleep(1)
        
        # Check that the alert was generated
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0][0], "always_match")
        self.assertEqual(alerts[0][1], packet)
        
        processor.stop()
    
    def test_process_packets(self):
        """Test processing multiple packets."""
        processor = ParallelRuleProcessor(num_workers=2, batch_size=2)
        processor.start()
        
        # Create some mock packets
        packets = [
            MockPacket("192.168.1.1", "00:11:22:33:44:55", "192.168.1.2", "66:77:88:99:AA:BB"),
            MockPacket("192.168.1.3", "CC:DD:EE:FF:00:11", "192.168.1.4", "22:33:44:55:66:77"),
            MockPacket("192.168.1.5", "88:99:AA:BB:CC:DD", "192.168.1.6", "EE:FF:00:11:22:33")
        ]
        
        # Register a rule that checks for a specific source IP
        def check_source_ip(packet, context):
            if packet.psrc == "192.168.1.3":
                return {"matched": True, "reason": "specific_ip"}
            return None
        
        processor.register_rule("check_source_ip", check_source_ip)
        
        # Add a callback to track alerts
        alerts = []
        def alert_callback(rule_name, packet, details):
            alerts.append((rule_name, packet, details))
        
        processor.register_alert_callback(alert_callback)
        
        # Process the packets
        processor.process_packets(packets)
        
        # Wait for processing to complete
        time.sleep(1)
        
        # Check that the alert was generated for the matching packet
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0][0], "check_source_ip")
        self.assertEqual(alerts[0][1].psrc, "192.168.1.3")
        
        processor.stop()

class TestParallelDetectionModule(unittest.TestCase):
    """
    Test the ParallelDetectionModule class.
    
    Note: This test requires mock implementations of network interfaces and packet capture,
    which are not provided in this test file. The tests in this class are limited to
    initialization and basic functionality.
    """
    
    def test_init(self):
        """Test initializing the parallel detection module."""
        # This test just verifies that the module can be initialized
        # without raising exceptions
        try:
            module = ParallelDetectionModule(interface=None, num_workers=2)
            self.assertIsNotNone(module)
        except Exception as e:
            self.fail(f"ParallelDetectionModule initialization raised exception: {e}")
    
    def test_register_rules(self):
        """Test that rules are registered with the rule processor."""
        module = ParallelDetectionModule(interface=None, num_workers=2)
        
        # Check that some rules were registered
        self.assertTrue(len(module.rule_processor.rules) > 0)
    
    # Additional tests would require mock network interfaces and packet capture

if __name__ == "__main__":
    unittest.main() 