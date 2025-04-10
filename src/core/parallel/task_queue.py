import queue
import threading
import logging
import time
from typing import List, Dict, Any, Optional, Callable, Tuple
import heapq

from src.core.parallel.worker_interface import WorkerTask

logger = logging.getLogger("arp_guard.parallel")

class PriorityTaskQueue:
    """A thread-safe priority queue for worker tasks."""
    
    def __init__(self, max_size: int = 0):
        """
        Initialize a new priority task queue.
        
        Args:
            max_size: Maximum number of tasks in the queue, or 0 for unlimited
        """
        self._queue = queue.PriorityQueue(maxsize=max_size)
        self._counter = 0  # Used to break ties when priorities are equal
        self._lock = threading.Lock()
        self._unfinished_tasks = 0
        self._all_tasks_done = threading.Condition(self._lock)
    
    def put(self, task: WorkerTask):
        """
        Add a task to the queue with the specified priority.
        
        Args:
            task: The task to add to the queue
        """
        with self._lock:
            self._counter += 1
            # Lower values have higher priority, so we negate the task priority
            priority = (-task.priority, self._counter)
            
            self._queue.put((priority, task))
            self._unfinished_tasks += 1
    
    def get(self, block: bool = True, timeout: Optional[float] = None) -> WorkerTask:
        """
        Get the next task from the queue.
        
        Args:
            block: If True, block until a task is available
            timeout: Maximum time to block in seconds, or None to block indefinitely
            
        Returns:
            The next task from the queue
            
        Raises:
            queue.Empty: If the queue is empty and block is False or timeout expires
        """
        priority, task = self._queue.get(block=block, timeout=timeout)
        return task
    
    def task_done(self):
        """Mark a task as done, allowing join() to return when all tasks are done."""
        with self._all_tasks_done:
            self._unfinished_tasks -= 1
            if self._unfinished_tasks <= 0:
                self._all_tasks_done.notify_all()
    
    def join(self):
        """Block until all tasks in the queue have been processed."""
        with self._all_tasks_done:
            while self._unfinished_tasks:
                self._all_tasks_done.wait()
    
    def qsize(self) -> int:
        """Return the approximate size of the queue."""
        return self._queue.qsize()
    
    def empty(self) -> bool:
        """Return True if the queue is empty, False otherwise."""
        return self._queue.empty()
    
    def full(self) -> bool:
        """Return True if the queue is full, False otherwise."""
        return self._queue.full()

class BatchTaskQueue:
    """A queue that batches tasks together for more efficient processing."""
    
    def __init__(self, batch_size: int = 10, batch_timeout: float = 1.0, 
                 batch_processor: Callable = None, max_queue_size: int = 0):
        """
        Initialize a new batch task queue.
        
        Args:
            batch_size: Maximum number of tasks in a batch
            batch_timeout: Maximum time to wait for a batch to fill up
            batch_processor: Function to process batches
            max_queue_size: Maximum number of batches in the queue, or 0 for unlimited
        """
        self._batch_size = batch_size
        self._batch_timeout = batch_timeout
        self._batch_processor = batch_processor
        self._queue = queue.Queue(maxsize=max_queue_size)
        self._current_batch: List[WorkerTask] = []
        self._batch_lock = threading.RLock()
        self._last_batch_time = time.time()
        self._batch_thread = threading.Thread(target=self._batch_worker, daemon=True)
        self._running = False
        self._unfinished_tasks = 0
        self._all_tasks_done = threading.Condition(self._batch_lock)
    
    def start(self):
        """Start the batch worker thread."""
        if not self._running:
            self._running = True
            self._batch_thread.start()
            logger.info("BatchTaskQueue started")
    
    def stop(self):
        """Stop the batch worker thread."""
        if self._running:
            self._running = False
            # Wait for the batch thread to terminate
            if self._batch_thread.is_alive():
                self._batch_thread.join(timeout=2.0)
            logger.info("BatchTaskQueue stopped")
    
    def put(self, task: WorkerTask):
        """
        Add a task to the current batch.
        
        If the batch is full or the timeout has expired, the batch is submitted to the queue.
        
        Args:
            task: The task to add to the batch
        """
        with self._batch_lock:
            self._current_batch.append(task)
            self._unfinished_tasks += 1
            
            # Check if the batch is full or the timeout has expired
            current_time = time.time()
            if (len(self._current_batch) >= self._batch_size or 
                current_time - self._last_batch_time >= self._batch_timeout):
                self._submit_batch()
    
    def _submit_batch(self):
        """Submit the current batch to the queue and start a new batch."""
        if not self._current_batch:
            return
        
        # Create a copy of the current batch
        batch = list(self._current_batch)
        self._current_batch = []
        self._last_batch_time = time.time()
        
        # Submit the batch to the queue
        self._queue.put(batch)
        logger.debug(f"Submitted batch of {len(batch)} tasks to queue")
    
    def _batch_worker(self):
        """Worker thread that processes batches from the queue."""
        while self._running:
            try:
                # Check if we need to submit the current batch due to timeout
                with self._batch_lock:
                    current_time = time.time()
                    if (self._current_batch and 
                        current_time - self._last_batch_time >= self._batch_timeout):
                        self._submit_batch()
                
                # Get a batch from the queue
                try:
                    batch = self._queue.get(block=True, timeout=0.5)
                except queue.Empty:
                    continue
                
                # Process the batch
                if self._batch_processor and batch:
                    try:
                        self._batch_processor(batch)
                    except Exception as e:
                        logger.error(f"Error processing batch: {str(e)}")
                
                # Mark tasks as done
                with self._batch_lock:
                    self._unfinished_tasks -= len(batch)
                    if self._unfinished_tasks <= 0:
                        self._all_tasks_done.notify_all()
                
                # Mark the batch as done in the queue
                self._queue.task_done()
            
            except Exception as e:
                logger.error(f"Error in batch worker: {str(e)}")
    
    def join(self):
        """Block until all tasks in the queue have been processed."""
        with self._all_tasks_done:
            while self._unfinished_tasks:
                self._all_tasks_done.wait()
    
    def qsize(self) -> int:
        """Return the approximate size of the queue."""
        with self._batch_lock:
            return self._queue.qsize() + (1 if self._current_batch else 0)
    
    def task_count(self) -> int:
        """Return the total number of tasks in the queue and current batch."""
        with self._batch_lock:
            queue_size = self._queue.qsize()
            batch_size = len(self._current_batch)
            return self._unfinished_tasks
    
    def flush(self):
        """
        Force submission of the current batch, even if it's not full or the timeout hasn't expired.
        
        This is useful when shutting down the queue to ensure all tasks are processed.
        """
        with self._batch_lock:
            self._submit_batch()
            
class TaskScheduler:
    """Schedules tasks based on priority and available resources."""
    
    def __init__(self, max_concurrent_tasks: int = None, 
                 prioritizer: Callable[[List[WorkerTask]], List[WorkerTask]] = None):
        """
        Initialize a new task scheduler.
        
        Args:
            max_concurrent_tasks: Maximum number of tasks to run concurrently
            prioritizer: Function to prioritize tasks
        """
        if max_concurrent_tasks is None:
            import multiprocessing
            max_concurrent_tasks = multiprocessing.cpu_count()
        
        self.max_concurrent_tasks = max_concurrent_tasks
        self.prioritizer = prioritizer or (lambda tasks: sorted(tasks, key=lambda t: t.priority, reverse=True))
        self.task_queue = PriorityTaskQueue()
        self.running_tasks: Dict[str, WorkerTask] = {}
        self.completed_tasks: Dict[str, WorkerTask] = {}
        self.lock = threading.RLock()
        self.task_available = threading.Event()
        self.scheduler_thread = threading.Thread(target=self._scheduler_worker, daemon=True)
        self.running = False
    
    def start(self):
        """Start the scheduler thread."""
        if not self.running:
            self.running = True
            self.scheduler_thread.start()
            logger.info("TaskScheduler started")
    
    def stop(self):
        """Stop the scheduler thread."""
        if self.running:
            self.running = False
            # Clear the task available event to wake up the scheduler thread
            self.task_available.set()
            # Wait for the scheduler thread to terminate
            if self.scheduler_thread.is_alive():
                self.scheduler_thread.join(timeout=2.0)
            logger.info("TaskScheduler stopped")
    
    def schedule_task(self, task: WorkerTask):
        """
        Schedule a task for execution.
        
        Args:
            task: The task to schedule
        """
        with self.lock:
            self.task_queue.put(task)
            self.task_available.set()
    
    def schedule_tasks(self, tasks: List[WorkerTask]):
        """
        Schedule multiple tasks for execution.
        
        Args:
            tasks: The tasks to schedule
        """
        with self.lock:
            for task in tasks:
                self.task_queue.put(task)
            self.task_available.set()
    
    def _scheduler_worker(self):
        """Worker thread that schedules tasks based on priority and available resources."""
        while self.running:
            try:
                # Wait for a task to be available
                self.task_available.wait(timeout=0.5)
                self.task_available.clear()
                
                if not self.running:
                    break
                
                with self.lock:
                    # Check if we can run more tasks
                    available_slots = self.max_concurrent_tasks - len(self.running_tasks)
                    if available_slots <= 0:
                        continue
                    
                    # Get tasks from the queue
                    tasks = []
                    try:
                        while available_slots > 0 and not self.task_queue.empty():
                            task = self.task_queue.get(block=False)
                            tasks.append(task)
                            available_slots -= 1
                    except queue.Empty:
                        pass
                    
                    if not tasks:
                        continue
                    
                    # Prioritize the tasks
                    tasks = self.prioritizer(tasks)
                    
                    # Start executing the tasks
                    for task in tasks:
                        self.running_tasks[task.task_id] = task
                        # Execute the task (this would normally be done by a worker thread)
                        threading.Thread(target=self._execute_task, args=(task,), daemon=True).start()
            
            except Exception as e:
                logger.error(f"Error in scheduler worker: {str(e)}")
    
    def _execute_task(self, task: WorkerTask):
        """
        Execute a task and handle the result.
        
        Args:
            task: The task to execute
        """
        try:
            result = task.execute()
            task.on_success(result)
        except Exception as e:
            task.on_error(e)
        finally:
            task.on_complete()
            with self.lock:
                # Move the task from running to completed
                if task.task_id in self.running_tasks:
                    del self.running_tasks[task.task_id]
                self.completed_tasks[task.task_id] = task
                # Mark the task as done in the queue
                self.task_queue.task_done()
                # Signal that a slot is available
                self.task_available.set()
    
    def get_task_status(self, task_id: str) -> Tuple[str, Optional[WorkerTask]]:
        """
        Get the status of a task.
        
        Args:
            task_id: ID of the task to check
            
        Returns:
            Tuple of (status, task) where status is one of 'running', 'completed', or 'not_found',
            and task is the WorkerTask object or None if not found
        """
        with self.lock:
            if task_id in self.running_tasks:
                return 'running', self.running_tasks[task_id]
            elif task_id in self.completed_tasks:
                return 'completed', self.completed_tasks[task_id]
            else:
                return 'not_found', None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the scheduler."""
        with self.lock:
            stats = {
                "running_tasks": len(self.running_tasks),
                "completed_tasks": len(self.completed_tasks),
                "queued_tasks": self.task_queue.qsize(),
                "max_concurrent_tasks": self.max_concurrent_tasks
            }
            return stats 