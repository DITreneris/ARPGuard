"""
Parallel processing module for ARP Guard.

This module provides functionality for executing tasks in parallel, with support for:
- Thread pool management
- Task prioritization
- Batch processing
- Worker thread interface
"""

import logging

from src.core.parallel.thread_pool import ThreadPoolManager, Task, Worker
from src.core.parallel.worker_interface import WorkerTask, RuleCheckTask, BatchProcessingTask, TaskPrioritizer
from src.core.parallel.task_queue import PriorityTaskQueue, BatchTaskQueue, TaskScheduler

# Setup logging
logger = logging.getLogger("arp_guard.parallel")
logger.setLevel(logging.INFO)

# Export main classes
__all__ = [
    'ThreadPoolManager',
    'Task',
    'Worker',
    'WorkerTask',
    'RuleCheckTask',
    'BatchProcessingTask',
    'TaskPrioritizer',
    'PriorityTaskQueue',
    'BatchTaskQueue',
    'TaskScheduler',
] 