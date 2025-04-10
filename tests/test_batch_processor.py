import unittest
import time
from app.utils.batch_processor import AdaptiveBatchProcessor

class TestAdaptiveBatchProcessor(unittest.TestCase):
    def setUp(self):
        self.processed_batches = []
        self.process_batch = lambda batch: self.processed_batches.append(batch)
        self.processor = AdaptiveBatchProcessor(
            process_batch=self.process_batch,
            initial_batch_size=5,
            min_batch_size=2,
            max_batch_size=10,
            target_processing_time=0.1
        )
        
    def test_basic_batching(self):
        """Test basic batch processing functionality"""
        for i in range(15):
            self.processor.add_item(i)
            
        self.assertEqual(len(self.processed_batches), 3)
        self.assertEqual(len(self.processed_batches[0]), 5)
        self.assertEqual(len(self.processed_batches[1]), 5)
        self.assertEqual(len(self.processed_batches[2]), 5)
        
    def test_batch_size_adjustment(self):
        """Test batch size adjustment based on processing time"""
        # Simulate slow processing
        def slow_process(batch):
            time.sleep(0.2)  # Twice the target processing time
            self.processed_batches.append(batch)
            
        processor = AdaptiveBatchProcessor(
            process_batch=slow_process,
            initial_batch_size=5,
            min_batch_size=2,
            max_batch_size=10,
            target_processing_time=0.1
        )
        
        for i in range(20):
            processor.add_item(i)
            
        # Batch size should decrease due to slow processing
        self.assertLess(processor.batch_size, 5)
        
    def test_flush(self):
        """Test flushing remaining items"""
        for i in range(7):
            self.processor.add_item(i)
            
        self.assertEqual(len(self.processed_batches), 1)
        self.processor.flush()
        self.assertEqual(len(self.processed_batches), 2)
        self.assertEqual(len(self.processed_batches[1]), 2)
        
    def test_stats(self):
        """Test statistics reporting"""
        for i in range(10):
            self.processor.add_item(i)
            
        stats = self.processor.get_stats()
        self.assertIn('current_batch_size', stats)
        self.assertIn('avg_processing_time', stats)
        self.assertIn('items_processed', stats)
        
    def test_min_max_bounds(self):
        """Test that batch size stays within bounds"""
        # Simulate very slow processing
        def very_slow_process(batch):
            time.sleep(1.0)
            self.processed_batches.append(batch)
            
        processor = AdaptiveBatchProcessor(
            process_batch=very_slow_process,
            initial_batch_size=5,
            min_batch_size=2,
            max_batch_size=10,
            target_processing_time=0.1
        )
        
        for i in range(20):
            processor.add_item(i)
            
        self.assertGreaterEqual(processor.batch_size, 2)
        self.assertLessEqual(processor.batch_size, 10)

    def test_concurrent_processing(self):
        """Test handling of concurrent item additions"""
        import threading
        
        def add_items(start, count):
            for i in range(start, start + count):
                self.processor.add_item(i)
        
        # Create multiple threads adding items concurrently
        threads = []
        for i in range(3):
            thread = threading.Thread(target=add_items, args=(i * 10, 10))
            threads.append(thread)
            thread.start()
            
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
            
        # Process remaining items
        self.processor.flush()
        
        # Verify all items were processed
        total_items = sum(len(batch) for batch in self.processed_batches)
        self.assertEqual(total_items, 30)
        
    def test_error_handling(self):
        """Test error handling during batch processing"""
        def error_process(batch):
            if len(batch) > 3:
                raise ValueError("Batch too large")
            self.processed_batches.append(batch)
            
        processor = AdaptiveBatchProcessor(
            process_batch=error_process,
            initial_batch_size=5,
            min_batch_size=2,
            max_batch_size=10,
            target_processing_time=0.1
        )
        
        # Add items that should trigger an error
        for i in range(10):
            try:
                processor.add_item(i)
            except ValueError:
                # Error should be caught and batch size should be reduced
                self.assertLess(processor.batch_size, 5)
                break
                
    def test_empty_batch_handling(self):
        """Test handling of empty batches"""
        # Test flush with empty batch
        self.processor.flush()
        self.assertEqual(len(self.processed_batches), 0)
        
        # Test adding empty items
        self.processor.add_item(None)
        self.processor.add_item([])
        self.processor.flush()
        
        self.assertEqual(len(self.processed_batches), 1)
        self.assertEqual(len(self.processed_batches[0]), 2)
        
    def test_performance_metrics(self):
        """Test detailed performance metrics collection"""
        def process_with_metrics(batch):
            time.sleep(0.05)  # Simulate processing time
            self.processed_batches.append(batch)
            
        processor = AdaptiveBatchProcessor(
            process_batch=process_with_metrics,
            initial_batch_size=5,
            min_batch_size=2,
            max_batch_size=10,
            target_processing_time=0.1
        )
        
        # Process multiple batches
        for i in range(20):
            processor.add_item(i)
            
        stats = processor.get_stats()
        self.assertGreater(stats['avg_processing_time'], 0)
        self.assertLess(stats['avg_processing_time'], 0.1)
        self.assertGreater(stats['items_processed'], 0)
        
    def test_batch_size_recovery(self):
        """Test batch size recovery after temporary slowdown"""
        processing_times = [0.2, 0.2, 0.2, 0.05, 0.05, 0.05]  # Slow then fast
        
        def variable_process(batch):
            time.sleep(processing_times.pop(0))
            self.processed_batches.append(batch)
            
        processor = AdaptiveBatchProcessor(
            process_batch=variable_process,
            initial_batch_size=5,
            min_batch_size=2,
            max_batch_size=10,
            target_processing_time=0.1
        )
        
        # Process items with varying processing times
        for i in range(30):
            processor.add_item(i)
            
        # Batch size should recover after processing speeds up
        self.assertGreater(processor.batch_size, 2)
        self.assertLess(processor.batch_size, 10)

if __name__ == '__main__':
    unittest.main() 