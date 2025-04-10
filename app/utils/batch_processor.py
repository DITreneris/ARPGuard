import time
from typing import List, Any, Callable
import logging
from collections import deque

class AdaptiveBatchProcessor:
    def __init__(self, 
                 process_batch: Callable[[List[Any]], None],
                 initial_batch_size: int = 100,
                 min_batch_size: int = 10,
                 max_batch_size: int = 1000,
                 target_processing_time: float = 0.1):
        self.process_batch = process_batch
        self.batch_size = initial_batch_size
        self.min_batch_size = min_batch_size
        self.max_batch_size = max_batch_size
        self.target_processing_time = target_processing_time
        self.processing_times = deque(maxlen=10)
        self.current_batch = []
        
    def add_item(self, item: Any):
        """Add item to current batch"""
        self.current_batch.append(item)
        if len(self.current_batch) >= self.batch_size:
            self._process_current_batch()
            
    def _process_current_batch(self):
        """Process current batch and adjust batch size"""
        if not self.current_batch:
            return
            
        start_time = time.time()
        self.process_batch(self.current_batch)
        processing_time = time.time() - start_time
        
        self.processing_times.append(processing_time)
        self._adjust_batch_size(processing_time)
        
        self.current_batch = []
        
    def _adjust_batch_size(self, processing_time: float):
        """Adjust batch size based on processing time"""
        avg_processing_time = sum(self.processing_times) / len(self.processing_times)
        
        if avg_processing_time > self.target_processing_time:
            # Processing too slow, reduce batch size
            new_batch_size = max(
                self.min_batch_size,
                int(self.batch_size * (self.target_processing_time / avg_processing_time))
            )
        else:
            # Processing fast enough, increase batch size
            new_batch_size = min(
                self.max_batch_size,
                int(self.batch_size * (self.target_processing_time / avg_processing_time))
            )
            
        if new_batch_size != self.batch_size:
            logging.info(f"Adjusting batch size from {self.batch_size} to {new_batch_size}")
            self.batch_size = new_batch_size
            
    def flush(self):
        """Process remaining items in current batch"""
        if self.current_batch:
            self._process_current_batch()
            
    def get_stats(self) -> dict:
        """Get current batch processing statistics"""
        return {
            'current_batch_size': self.batch_size,
            'avg_processing_time': sum(self.processing_times) / max(1, len(self.processing_times)),
            'items_processed': len(self.current_batch)
        } 