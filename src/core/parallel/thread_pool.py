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
    
    def __init__(self, num_workers: int = None):
        """
        Initialize the thread pool with the specified number of workers.
        
        Args:
            num_workers: Number of worker threads. If None, uses the number of CPU cores.
        """
        if num_workers is None:
            import multiprocessing
            num_workers = multiprocessing.cpu_count()
        
        self.num_workers = num_workers
        self.task_queue = queue.Queue()
        self.workers: List[Worker] = []
        self.running = False
        self.tasks: Dict[str, Task] = {}
        self.lock = threading.RLock()
        
        logger.info(f"Initializing ThreadPoolManager with {num_workers} workers")
    
    def start(self):
        """Start the worker threads."""
        if self.running:
            logger.warning("ThreadPoolManager is already running")
            return
        
        logger.info("Starting ThreadPoolManager")
        with self.lock:
            # Create and start the worker threads
            self.workers = [Worker(self.task_queue, i) for i in range(self.num_workers)]
            for worker in self.workers:
                worker.start()
            
            self.running = True
    
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
        if wait_for_tasks:
            logger.info("Waiting for pending tasks to complete")
            self.task_queue.join()
        
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
    
    def submit(self, func: Callable, args: Tuple = None, kwargs: Dict = None, task_id: str = None) -> Task:
        """
        Submit a task to be executed by the thread pool.
        
        Args:
            func: The function to execute
            args: Positional arguments for the function
            kwargs: Keyword arguments for the function
            task_id: Optional unique identifier for the task
            
        Returns:
            Task object that can be used to wait for and get the result
            
        Raises:
            RuntimeError: If the thread pool is not running
        """
        if not self.running:
            raise RuntimeError("ThreadPoolManager is not running")
        
        task = Task(func, args, kwargs, task_id)
        
        with self.lock:
            if task.task_id in self.tasks:
                raise ValueError(f"Task with ID {task.task_id} already exists")
            
            self.tasks[task.task_id] = task
        
        self.task_queue.put(task)
        return task
    
    def map(self, func: Callable, items: List[Any]) -> List[Task]:
        """
        Apply a function to each item in a list using the thread pool.
        
        Args:
            func: The function to apply to each item
            items: List of items to process
            
        Returns:
            List of Task objects corresponding to each item
        """
        tasks = []
        for i, item in enumerate(items):
            task = self.submit(func, args=(item,), task_id=f"map_{i}")
            tasks.append(task)
        
        return tasks
    
    def wait_for_all(self, tasks: List[Task], timeout: Optional[float] = None) -> bool:
        """
        Wait for all the given tasks to complete.
        
        Args:
            tasks: List of tasks to wait for
            timeout: Maximum time to wait in seconds, or None to wait indefinitely
            
        Returns:
            True if all tasks completed within the timeout, False otherwise
        """
        if timeout is not None:
            end_time = time.time() + timeout
        
        for task in tasks:
            if timeout is not None:
                remaining = end_time - time.time()
                if remaining <= 0 or not task.wait(remaining):
                    return False
            else:
                task.wait()
        
        return True
    
    def get_results(self, tasks: List[Task]) -> List[Any]:
        """
        Get the results of the given tasks.
        
        Args:
            tasks: List of tasks to get results from
            
        Returns:
            List of task results, with None for tasks that failed or didn't complete
        """
        return [task.result for task in tasks]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the thread pool."""
        with self.lock:
            active_workers = sum(1 for w in self.workers if not w.idle)
            tasks_processed = sum(w.tasks_processed for w in self.workers)
            total_execution_time = sum(w.total_execution_time for w in self.workers)
            
            stats = {
                "workers": {
                    "total": len(self.workers),
                    "active": active_workers,
                    "idle": len(self.workers) - active_workers
                },
                "tasks": {
                    "processed": tasks_processed,
                    "pending": self.task_queue.qsize(),
                    "total_execution_time": total_execution_time
                }
            }
            
            return stats 