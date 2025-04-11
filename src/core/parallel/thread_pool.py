import threading
import queue
import logging
import time
from typing import Callable, Any, List, Dict, Optional, Tuple

logger = logging.getLogger("arp_guard.parallel")

class Task:
    """Represents a task to be executed by a worker thread."""
    
    def __init__(self, func: Callable, args: Tuple = None, kwargs: Dict = None, task_id: str = None):
        """
        Initialize a new task with the given function and parameters.
        
        Args:
            func: The function to execute
            args: Positional arguments for the function
            kwargs: Keyword arguments for the function
            task_id: Optional unique identifier for the task
        """
        self.func = func
        self.args = args or ()
        self.kwargs = kwargs or {}
        self.task_id = task_id or f"task_{id(self)}"
        self.result = None
        self.error = None
        self.completed = threading.Event()
        self.started = False
        self.start_time = None
        self.end_time = None
    
    def execute(self):
        """Execute the task and store the result or error."""
        if self.started:
            return
            
        self.started = True
        self.start_time = time.time()
        
        try:
            logger.debug(f"Executing task {self.task_id}")
            self.result = self.func(*self.args, **self.kwargs)
        except Exception as e:
            logger.error(f"Error executing task {self.task_id}: {str(e)}")
            self.error = e
        finally:
            self.end_time = time.time()
            self.completed.set()
    
    def wait(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for the task to complete.
        
        Args:
            timeout: Maximum time to wait in seconds, or None to wait indefinitely
            
        Returns:
            True if the task completed within the timeout, False otherwise
        """
        return self.completed.wait(timeout)
    
    @property
    def execution_time(self) -> Optional[float]:
        """Return the execution time of the task in seconds, or None if not completed."""
        if self.start_time is None or self.end_time is None:
            return None
        return self.end_time - self.start_time

class Worker(threading.Thread):
    """Worker thread that executes tasks from a queue."""
    
    def __init__(self, task_queue: queue.Queue, worker_id: int):
        """
        Initialize a new worker thread.
        
        Args:
            task_queue: Queue to get tasks from
            worker_id: Unique identifier for this worker
        """
        super().__init__(name=f"Worker-{worker_id}")
        self.task_queue = task_queue
        self.worker_id = worker_id
        self.daemon = True
        self.running = True
        self.idle = True
        self.tasks_processed = 0
        self.total_execution_time = 0.0
    
    def run(self):
        """Main worker loop that processes tasks from the queue."""
        logger.info(f"Worker {self.worker_id} started")
        
        while self.running:
            try:
                task = self.task_queue.get(block=True, timeout=0.5)
                self.idle = False
                
                # Execute the task
                start_time = time.time()
                task.execute()
                end_time = time.time()
                
                # Update statistics
                self.tasks_processed += 1
                self.total_execution_time += (end_time - start_time)
                
                # Mark the task as done in the queue
                self.task_queue.task_done()
                self.idle = True
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker {self.worker_id} encountered an error: {str(e)}")
        
        logger.info(f"Worker {self.worker_id} stopped")
    
    def stop(self):
        """Signal the worker to stop processing tasks."""
        self.running = False

class ThreadPoolManager:
    """Manages a pool of worker threads for parallel task execution."""
    
    def __init__(self, num_workers: int = None, min_workers: int = 2, max_workers: int = None):
        """
        Initialize the thread pool with adaptive scaling capabilities.
        
        Args:
            num_workers: Initial number of worker threads. If None, uses the number of CPU cores.
            min_workers: Minimum number of workers to maintain
            max_workers: Maximum number of workers allowed. If None, uses 2x CPU cores.
        """
        import multiprocessing
        cpu_count = multiprocessing.cpu_count()
        
        if num_workers is None:
            num_workers = cpu_count
        
        if max_workers is None:
            max_workers = cpu_count * 2
        
        self.initial_num_workers = num_workers
        self.min_workers = min(min_workers, num_workers)
        self.max_workers = max(max_workers, num_workers)
        self.num_workers = num_workers
        
        # Create high and low priority queues
        self.high_priority_queue = queue.Queue()
        self.normal_priority_queue = queue.Queue()
        self.low_priority_queue = queue.Queue()
        
        # Use normal priority as the default
        self.task_queue = self.normal_priority_queue
        
        self.workers: List[Worker] = []
        self.running = False
        self.tasks: Dict[str, Task] = {}
        self.lock = threading.RLock()
        
        # Performance monitoring
        self.total_tasks_submitted = 0
        self.total_tasks_completed = 0
        self.total_execution_time = 0.0
        self.task_latencies = []  # Time between submission and execution
        self.start_time = None
        
        # Adaptive scaling
        self.scaling_enabled = True
        self.scale_up_threshold = 0.8  # Scale up when 80% of workers are busy
        self.scale_down_threshold = 0.3  # Scale down when less than 30% of workers are busy
        self.last_scaling_time = 0
        self.scaling_cooldown = 10.0  # Seconds between scaling operations
        self.scaling_thread = None
        
        logger.info(f"Initializing ThreadPoolManager with {num_workers} workers (min={min_workers}, max={max_workers})")
    
    def start(self):
        """Start the worker threads and monitoring."""
        if self.running:
            logger.warning("ThreadPoolManager is already running")
            return
        
        logger.info("Starting ThreadPoolManager")
        with self.lock:
            # Create and start the worker threads
            self.workers = []
            for i in range(self.num_workers):
                self._create_worker(i)
            
            self.running = True
            self.start_time = time.time()
            
            # Start the adaptive scaling thread if enabled
            if self.scaling_enabled:
                self.scaling_thread = threading.Thread(
                    target=self._adaptive_scaling_worker,
                    daemon=True,
                    name="ThreadPool-AdaptiveScaling"
                )
                self.scaling_thread.start()
    
    def _create_worker(self, worker_id: int) -> Worker:
        """Create a new worker thread that checks all priority queues."""
        worker = AdaptiveWorker(
            high_priority_queue=self.high_priority_queue,
            normal_priority_queue=self.normal_priority_queue,
            low_priority_queue=self.low_priority_queue,
            worker_id=worker_id
        )
        worker.start()
        self.workers.append(worker)
        return worker
    
    def _remove_worker(self):
        """Remove a worker from the pool."""
        if len(self.workers) <= self.min_workers:
            return False
        
        # Find an idle worker to remove
        idle_workers = [w for w in self.workers if w.idle]
        if not idle_workers:
            return False
        
        worker = idle_workers[0]
        worker.stop()
        self.workers.remove(worker)
        logger.info(f"Removed worker {worker.worker_id}, pool size now {len(self.workers)}")
        return True
    
    def stop(self, wait_for_tasks: bool = True):
        """
        Stop the thread pool.
        
        Args:
            wait_for_tasks: If True, wait for pending tasks to complete
        """
        if not self.running:
            logger.warning("ThreadPoolManager is not running")
            return
        
        logger.info("Stopping ThreadPoolManager")
        
        # First stop the scaling thread
        if self.scaling_thread and self.scaling_thread.is_alive():
            self.scaling_enabled = False
            self.scaling_thread.join(timeout=2.0)
        
        if wait_for_tasks:
            logger.info("Waiting for pending tasks to complete")
            self.high_priority_queue.join()
            self.normal_priority_queue.join()
            self.low_priority_queue.join()
        
        with self.lock:
            # Signal all workers to stop
            for worker in self.workers:
                worker.stop()
            
            # Wait for all workers to terminate
            for worker in self.workers:
                worker.join(timeout=1.0)
            
            self.workers = []
            self.running = False
        
        logger.info("ThreadPoolManager stopped")
    
    def submit(self, func: Callable, args: Tuple = None, kwargs: Dict = None, 
               task_id: str = None, priority: int = 1) -> Task:
        """
        Submit a task to be executed by the thread pool.
        
        Args:
            func: The function to execute
            args: Positional arguments for the function
            kwargs: Keyword arguments for the function
            task_id: Optional unique identifier for the task
            priority: Task priority (0=low, 1=normal, 2=high)
            
        Returns:
            Task object that can be used to wait for and get the result
            
        Raises:
            RuntimeError: If the thread pool is not running
        """
        if not self.running:
            raise RuntimeError("ThreadPoolManager is not running")
        
        task = Task(func, args, kwargs, task_id)
        task.priority = priority
        task.submit_time = time.time()
        
        with self.lock:
            if task.task_id in self.tasks:
                raise ValueError(f"Task with ID {task.task_id} already exists")
            
            self.tasks[task.task_id] = task
            self.total_tasks_submitted += 1
        
        # Select the appropriate queue based on priority
        if priority == 2:  # High priority
            self.high_priority_queue.put(task)
        elif priority == 0:  # Low priority
            self.low_priority_queue.put(task)
        else:  # Normal priority (default)
            self.normal_priority_queue.put(task)
            
        return task
    
    def map(self, func: Callable, items: List[Any], priority: int = 1) -> List[Task]:
        """
        Apply a function to each item in a list using the thread pool.
        
        Args:
            func: The function to apply to each item
            items: List of items to process
            priority: Task priority (0=low, 1=normal, 2=high)
            
        Returns:
            List of Task objects corresponding to each item
        """
        tasks = []
        for i, item in enumerate(items):
            task = self.submit(func, args=(item,), task_id=f"map_{i}", priority=priority)
            tasks.append(task)
        
        return tasks
    
    def _adaptive_scaling_worker(self):
        """Worker thread that monitors load and adjusts the thread pool size."""
        logger.info("Adaptive scaling thread started")
        
        while self.running and self.scaling_enabled:
            try:
                # Get current load statistics
                stats = self.get_stats()
                active_workers = stats["workers"]["active"]
                total_workers = stats["workers"]["total"]
                
                # Calculate load percentage
                load_percentage = active_workers / total_workers if total_workers > 0 else 0
                
                current_time = time.time()
                cooldown_elapsed = current_time - self.last_scaling_time > self.scaling_cooldown
                
                if cooldown_elapsed:
                    # Check if we need to scale up
                    if load_percentage >= self.scale_up_threshold and total_workers < self.max_workers:
                        with self.lock:
                            new_workers = min(2, self.max_workers - total_workers)  # Add up to 2 workers at a time
                            logger.info(f"Scaling up: Adding {new_workers} worker(s), load={load_percentage:.2f}")
                            
                            for i in range(new_workers):
                                self._create_worker(len(self.workers))
                            
                            self.last_scaling_time = current_time
                    
                    # Check if we need to scale down
                    elif load_percentage <= self.scale_down_threshold and total_workers > self.min_workers:
                        with self.lock:
                            removed = self._remove_worker()
                            if removed:
                                logger.info(f"Scaling down: Removed 1 worker, load={load_percentage:.2f}")
                                self.last_scaling_time = current_time
                
                # Sleep before checking again
                time.sleep(2.0)
                
            except Exception as e:
                logger.error(f"Error in adaptive scaling thread: {str(e)}")
                time.sleep(5.0)  # Sleep longer on error
        
        logger.info("Adaptive scaling thread stopped")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detailed statistics about the thread pool."""
        with self.lock:
            active_workers = sum(1 for w in self.workers if not w.idle)
            tasks_processed = sum(w.tasks_processed for w in self.workers)
            total_execution_time = sum(w.total_execution_time for w in self.workers)
            
            # Calculate task latencies (if any)
            avg_latency = 0
            if self.task_latencies:
                avg_latency = sum(self.task_latencies) / len(self.task_latencies)
            
            # Calculate throughput (tasks per second)
            uptime = time.time() - self.start_time if self.start_time else 0
            throughput = self.total_tasks_completed / uptime if uptime > 0 else 0
            
            stats = {
                "workers": {
                    "total": len(self.workers),
                    "active": active_workers,
                    "idle": len(self.workers) - active_workers,
                    "min": self.min_workers,
                    "max": self.max_workers
                },
                "tasks": {
                    "submitted": self.total_tasks_submitted,
                    "completed": self.total_tasks_completed,
                    "pending": (
                        self.high_priority_queue.qsize() + 
                        self.normal_priority_queue.qsize() + 
                        self.low_priority_queue.qsize()
                    ),
                    "high_priority_pending": self.high_priority_queue.qsize(),
                    "normal_priority_pending": self.normal_priority_queue.qsize(),
                    "low_priority_pending": self.low_priority_queue.qsize(),
                    "processed": tasks_processed,
                    "total_execution_time": total_execution_time,
                    "avg_execution_time": total_execution_time / tasks_processed if tasks_processed > 0 else 0
                },
                "performance": {
                    "avg_latency": avg_latency,
                    "throughput": throughput,
                    "uptime": uptime
                }
            }
            
            return stats

    def _update_task_metrics(self, task: Task):
        """Update performance metrics when a task completes."""
        if task.start_time and task.end_time:
            execution_time = task.end_time - task.start_time
            
            with self.lock:
                self.total_tasks_completed += 1
                self.total_execution_time += execution_time
                
                # Calculate latency (time from submission to start of execution)
                if hasattr(task, 'submit_time') and task.submit_time:
                    latency = task.start_time - task.submit_time
                    # Keep the last 1000 latencies for stats
                    self.task_latencies.append(latency)
                    if len(self.task_latencies) > 1000:
                        self.task_latencies.pop(0)


class AdaptiveWorker(Worker):
    """Enhanced worker that processes tasks from multiple queues based on priority."""
    
    def __init__(self, high_priority_queue: queue.Queue, normal_priority_queue: queue.Queue, 
                 low_priority_queue: queue.Queue, worker_id: int):
        """
        Initialize a new adaptive worker thread.
        
        Args:
            high_priority_queue: Queue for high priority tasks
            normal_priority_queue: Queue for normal priority tasks
            low_priority_queue: Queue for low priority tasks
            worker_id: Unique identifier for this worker
        """
        super().__init__(normal_priority_queue, worker_id)
        self.high_priority_queue = high_priority_queue
        self.normal_priority_queue = normal_priority_queue
        self.low_priority_queue = low_priority_queue
        self.current_task = None
    
    def run(self):
        """Main worker loop that processes tasks from queues with priority handling."""
        logger.info(f"Worker {self.worker_id} started")
        
        while self.running:
            try:
                # Check queues in priority order
                task = None
                
                # Try to get a high priority task first
                try:
                    task = self.high_priority_queue.get(block=False)
                except queue.Empty:
                    pass
                
                # If no high priority task, try normal priority
                if task is None:
                    try:
                        task = self.normal_priority_queue.get(block=False)
                    except queue.Empty:
                        pass
                
                # If still no task, try low priority
                if task is None:
                    try:
                        task = self.low_priority_queue.get(block=False)
                    except queue.Empty:
                        pass
                
                # If all queues are empty, wait on the normal queue with timeout
                if task is None:
                    try:
                        task = self.normal_priority_queue.get(block=True, timeout=0.5)
                    except queue.Empty:
                        continue
                
                # Process the task
                self.idle = False
                self.current_task = task
                
                # Execute the task
                start_time = time.time()
                task.execute()
                end_time = time.time()
                
                # Update statistics
                self.tasks_processed += 1
                execution_time = end_time - start_time
                self.total_execution_time += execution_time
                
                # Mark the task as done in the appropriate queue
                if task in self.high_priority_queue.queue:
                    self.high_priority_queue.task_done()
                elif task in self.normal_priority_queue.queue:
                    self.normal_priority_queue.task_done()
                else:
                    self.low_priority_queue.task_done()
                
                self.current_task = None
                self.idle = True
                
            except Exception as e:
                logger.error(f"Worker {self.worker_id} encountered an error: {str(e)}")
        
        logger.info(f"Worker {self.worker_id} stopped") 