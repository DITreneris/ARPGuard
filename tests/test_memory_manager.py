import unittest
import time
import sys
import gc
from unittest.mock import patch, MagicMock, call

sys.path.append('.')  # Add the project root to path

from app.utils.memory_manager import MemoryManager, PacketMemoryOptimizer, ResourceType, MemoryStrategy


class TestMemoryManager(unittest.TestCase):
    """Test cases for the MemoryManager class."""

    def setUp(self):
        """Set up test fixtures."""
        self.memory_manager = MemoryManager(strategy=MemoryStrategy.BALANCED)
        
    def tearDown(self):
        """Clean up after tests."""
        self.memory_manager.stop_monitoring()
        
    @patch('app.utils.memory_manager.psutil')
    def test_get_memory_usage(self, mock_psutil):
        """Test memory usage retrieval."""
        # Set up the mock
        mock_memory = MagicMock()
        mock_memory.percent = 75.0  # 75% memory usage
        mock_psutil.virtual_memory.return_value = mock_memory
        
        # Call the method under test
        usage = self.memory_manager.get_memory_usage()
        
        # Verify the result
        self.assertEqual(usage, 0.75)
        mock_psutil.virtual_memory.assert_called_once()
        
    def test_memory_pressure_level(self):
        """Test memory pressure level calculation and callback."""
        # Create a mock callback
        callback = MagicMock()
        
        # Register the callback
        self.memory_manager.register_callback(ResourceType.MEMORY, callback)
        
        # Simulate memory pressure changes
        with patch.object(self.memory_manager, 'get_memory_usage') as mock_usage:
            # Test normal pressure (0)
            mock_usage.return_value = 0.5  # 50%
            self.memory_manager._monitoring_loop()  # Run one loop iteration
            self.assertEqual(self.memory_manager.memory_pressure, 0)
            
            # Test low pressure (1)
            mock_usage.return_value = 0.65  # 65%
            self.memory_manager._monitoring_loop()
            self.assertEqual(self.memory_manager.memory_pressure, 1)
            callback.assert_called_with(0, 1)
            
            # Test medium pressure (2)
            mock_usage.return_value = 0.80  # 80%
            self.memory_manager._monitoring_loop()
            self.assertEqual(self.memory_manager.memory_pressure, 2)
            callback.assert_called_with(1, 2)
            
            # Test high pressure (3)
            mock_usage.return_value = 0.90  # 90%
            self.memory_manager._monitoring_loop()
            self.assertEqual(self.memory_manager.memory_pressure, 3)
            callback.assert_called_with(2, 3)
            
            # Test critical pressure (4)
            mock_usage.return_value = 0.96  # 96%
            self.memory_manager._monitoring_loop()
            self.assertEqual(self.memory_manager.memory_pressure, 4)
            callback.assert_called_with(3, 4)
            
            # Test pressure decrease
            mock_usage.return_value = 0.70  # 70%
            self.memory_manager._monitoring_loop()
            self.assertEqual(self.memory_manager.memory_pressure, 1)
            callback.assert_called_with(4, 1)
            
    def test_strategy_adaptation(self):
        """Test strategy adaptation based on memory pressure."""
        self.memory_manager.strategy = MemoryStrategy.ADAPTIVE
        
        with patch.object(self.memory_manager, 'get_memory_usage') as mock_usage:
            # Test conservative strategy (low memory usage)
            mock_usage.return_value = 0.50  # 50%
            self.memory_manager.adapt_strategy()
            self.assertEqual(self.memory_manager.strategy, MemoryStrategy.CONSERVATIVE)
            
            # Test balanced strategy (higher memory usage)
            mock_usage.return_value = 0.90  # 90%
            self.memory_manager.adapt_strategy()
            self.assertEqual(self.memory_manager.strategy, MemoryStrategy.BALANCED)
            
            # Test aggressive strategy (critical memory usage)
            mock_usage.return_value = 0.96  # 96%
            self.memory_manager.adapt_strategy()
            self.assertEqual(self.memory_manager.strategy, MemoryStrategy.AGGRESSIVE)
            
    def test_packet_processing(self):
        """Test packet processing decisions based on memory pressure."""
        # Create some sample packets
        packet1 = {"id": 1, "data": "test packet 1"}
        packet2 = {"id": 2, "data": "test packet 2"}
        packet3 = {"id": 3, "data": "test packet 3"}
        
        # Test normal processing (no pressure)
        self.memory_manager.memory_pressure = 0
        self.assertTrue(self.memory_manager.process_packet(packet1))
        self.assertTrue(self.memory_manager.process_packet(packet2))
        self.assertTrue(self.memory_manager.process_packet(packet3))
        
        # Test packet sampling under high pressure
        self.memory_manager.memory_pressure = 3
        # Reset packet count to ensure predictable sampling
        self.memory_manager.packet_count = 0
        # Should process 1/4 packets (packet_count % (pressure+1) == 0)
        self.assertTrue(self.memory_manager.process_packet(packet1))  # packet_count=1, 1%4!=0, accept
        self.assertFalse(self.memory_manager.process_packet(packet2)) # packet_count=2, 2%4!=0, drop
        self.assertFalse(self.memory_manager.process_packet(packet3)) # packet_count=3, 3%4!=0, drop
        self.assertTrue(self.memory_manager.process_packet(packet1))  # packet_count=4, 4%4==0, accept
        
        # Check metrics
        self.assertEqual(self.memory_manager.metrics['total_packets_processed'], 5)
        self.assertEqual(self.memory_manager.metrics['total_packets_dropped'], 2)
        
    def test_packet_deduplication(self):
        """Test packet deduplication."""
        # Enable deduplication
        self.memory_manager.packet_deduplication = True
        
        # Create hashable packets
        class HashablePacket:
            def __init__(self, id, data):
                self.id = id
                self.data = data
                
            def __hash__(self):
                return hash(self.id)
        
        packet1 = HashablePacket(1, "test packet 1")
        packet2 = HashablePacket(2, "test packet 2")
        packet3 = HashablePacket(1, "test packet 1 duplicate")  # Same hash as packet1
        
        # Process packets
        self.assertTrue(self.memory_manager.process_packet(packet1))
        self.assertTrue(self.memory_manager.process_packet(packet2))
        self.assertFalse(self.memory_manager.process_packet(packet3))  # Should be detected as duplicate
        
        # Check metrics
        self.assertEqual(self.memory_manager.metrics['total_packets_processed'], 3)
        self.assertEqual(self.memory_manager.metrics['total_packets_deduplicated'], 1)
        
    def test_packet_storage_optimization(self):
        """Test packet storage optimization."""
        # Create a list of mock packets
        packets = [{"id": i, "data": f"test packet {i}"} for i in range(1000)]
        
        # Test with different strategies
        
        # Conservative strategy (should keep all packets)
        self.memory_manager.strategy = MemoryStrategy.CONSERVATIVE
        result = self.memory_manager.optimize_packet_storage(packets)
        self.assertEqual(len(result), 1000)
        
        # Aggressive strategy (should keep only a portion)
        self.memory_manager.strategy = MemoryStrategy.AGGRESSIVE
        result = self.memory_manager.optimize_packet_storage(packets)
        self.assertLess(len(result), 1000)
        
        # Test with explicit max size
        result = self.memory_manager.optimize_packet_storage(packets, max_size=500)
        self.assertEqual(len(result), 500)
        # Verify we kept the newest packets (highest IDs)
        self.assertEqual(result[0]["id"], 500)
        self.assertEqual(result[-1]["id"], 999)
        
    @patch('app.utils.memory_manager.gc')
    def test_garbage_collection(self, mock_gc):
        """Test garbage collection functionality."""
        # Set up mocks
        with patch.object(self.memory_manager, 'get_memory_usage') as mock_usage:
            mock_usage.side_effect = [0.9, 0.85]  # Before and after GC
            
            # Run garbage collection
            self.memory_manager._run_garbage_collection()
            
            # Verify GC was called
            mock_gc.collect.assert_called_once()
            
            # Verify metrics update
            self.assertEqual(self.memory_manager.metrics['gc_cycles'], 1)
            self.assertEqual(self.memory_manager.metrics['total_memory_reclaimed'], 0.05)
            
    def test_max_packet_buffer_size(self):
        """Test dynamic buffer size calculation."""
        # Set max buffer size
        self.memory_manager.max_packet_buffer = 10000
        
        # Test different strategies and memory conditions
        with patch.object(self.memory_manager, 'get_memory_usage') as mock_usage:
            # Test conservative strategy
            self.memory_manager.strategy = MemoryStrategy.CONSERVATIVE
            buffer_size = self.memory_manager.get_max_packet_buffer_size()
            self.assertEqual(buffer_size, 10000)
            
            # Test aggressive strategy
            self.memory_manager.strategy = MemoryStrategy.AGGRESSIVE
            buffer_size = self.memory_manager.get_max_packet_buffer_size()
            self.assertEqual(buffer_size, 2000)  # 20% of max
            
            # Test balanced strategy with 50% memory usage
            self.memory_manager.strategy = MemoryStrategy.BALANCED
            mock_usage.return_value = 0.5
            buffer_size = self.memory_manager.get_max_packet_buffer_size()
            self.assertEqual(buffer_size, 5000)  # 50% of max
            
            # Test balanced strategy with 90% memory usage
            mock_usage.return_value = 0.9
            buffer_size = self.memory_manager.get_max_packet_buffer_size()
            self.assertEqual(buffer_size, 1000)  # 10% of max
            
    def test_reset_metrics(self):
        """Test metrics reset functionality."""
        # Set some metrics
        self.memory_manager.metrics['total_packets_processed'] = 1000
        self.memory_manager.metrics['total_packets_dropped'] = 50
        self.memory_manager.packet_count = 1000
        self.memory_manager.packet_hashes = {1, 2, 3, 4, 5}
        
        # Reset metrics
        self.memory_manager.reset_metrics()
        
        # Verify reset
        self.assertEqual(self.memory_manager.metrics['total_packets_processed'], 0)
        self.assertEqual(self.memory_manager.metrics['total_packets_dropped'], 0)
        self.assertEqual(self.memory_manager.packet_count, 0)
        self.assertEqual(len(self.memory_manager.packet_hashes), 0)
        

class TestPacketMemoryOptimizer(unittest.TestCase):
    """Test cases for the PacketMemoryOptimizer class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.memory_manager = MemoryManager()
        self.optimizer = PacketMemoryOptimizer(self.memory_manager)
        
    def test_optimize_packet(self):
        """Test packet optimization."""
        # Create a test packet
        class TestPacket:
            def __init__(self):
                self.src = "192.168.1.1"
                self.dst = "192.168.1.2"
                self.proto = "TCP"
                self.len = 1500
                self.data = "X" * 2000  # Exceeds max_packet_payload
                
        packet = TestPacket()
        
        # Optimize the packet
        optimized = self.optimizer.optimize_packet(packet)
        
        # Verify optimization
        self.assertTrue(optimized['_optimized'])
        self.assertIn('_optimized_at', optimized)
        self.assertEqual(optimized['src'], packet.src)
        self.assertEqual(optimized['dst'], packet.dst)
        self.assertEqual(optimized['proto'], packet.proto)
        self.assertEqual(optimized['len'], packet.len)
        self.assertEqual(len(optimized['data']), self.optimizer.max_packet_payload)
        self.assertTrue(optimized['data_truncated'])
        
    def test_optimize_packet_with_to_dict(self):
        """Test optimization of packets with to_dict method."""
        # Create a test packet with to_dict method
        class DictPacket:
            def __init__(self):
                self.packet_data = {
                    'src': '10.0.0.1',
                    'dst': '10.0.0.2',
                    'type': 'IP',
                    'len': 500
                }
                
            def to_dict(self):
                return self.packet_data
                
        packet = DictPacket()
        
        # Optimize the packet
        optimized = self.optimizer.optimize_packet(packet)
        
        # Verify optimization
        self.assertEqual(optimized['src'], '10.0.0.1')
        self.assertEqual(optimized['dst'], '10.0.0.2')
        self.assertEqual(optimized['type'], 'IP')
        self.assertEqual(optimized['len'], 500)
        self.assertTrue(optimized['_optimized'])
        
    def test_batch_optimize(self):
        """Test batch optimization of packets."""
        # Create test packets
        packets = [
            {"id": 1, "data": "packet 1"},
            {"id": 2, "data": "packet 2"},
            {"id": 3, "data": "packet 3"},
            None  # Should be filtered out
        ]
        
        # Batch optimize
        with patch.object(self.optimizer, 'optimize_packet', side_effect=lambda p: {"optimized": p["id"]}) as mock_optimize:
            result = self.optimizer.batch_optimize(packets)
            
            # Verify results
            self.assertEqual(len(result), 3)  # None should be filtered out
            self.assertEqual(result, [{"optimized": 1}, {"optimized": 2}, {"optimized": 3}])
            self.assertEqual(mock_optimize.call_count, 3)
        
    def test_packet_caching(self):
        """Test packet caching with weak references."""
        # Enable storing raw packets with weak references
        self.optimizer.store_raw_packets = True
        self.optimizer.use_weak_refs = True
        
        # Create a test packet
        packet = {"id": 123, "data": "test packet"}
        
        # Optimize the packet
        optimized = self.optimizer.optimize_packet(packet)
        
        # Verify packet ID is stored
        self.assertIn('_packet_id', optimized)
        
        # Verify we can retrieve the raw packet
        raw_packet = self.optimizer.get_raw_packet(optimized)
        self.assertEqual(raw_packet, packet)
        
        # Test with non-weak references
        self.optimizer.use_weak_refs = False
        packet2 = {"id": 456, "data": "test packet 2"}
        optimized2 = self.optimizer.optimize_packet(packet2)
        
        self.assertIn('_raw_packet', optimized2)
        raw_packet2 = self.optimizer.get_raw_packet(optimized2)
        self.assertEqual(raw_packet2, str(packet2))
        
    def test_memory_usage_estimation(self):
        """Test memory usage estimation."""
        # Create a test packet info dictionary
        packet_info = {
            'timestamp': '2024-04-06T12:00:00.000000',
            'src': '192.168.1.1',
            'dst': '192.168.1.2',
            'protocol': 'TCP',
            'length': 1500,
            'data': 'X' * 500,
            'nested': {
                'field1': 'value1',
                'field2': 123
            },
            'list_field': ['item1', 'item2', 'item3']
        }
        
        # Estimate memory usage
        memory_usage = self.optimizer.estimate_memory_usage(packet_info)
        
        # We don't check exact value as it depends on implementation details,
        # but we can check it's reasonable and greater than zero
        self.assertGreater(memory_usage, 0)
        
        # Nested dictionaries should increase the size
        packet_info['another_nested'] = {'more': 'data', 'fields': ['a', 'b', 'c']}
        larger_memory_usage = self.optimizer.estimate_memory_usage(packet_info)
        self.assertGreater(larger_memory_usage, memory_usage)


if __name__ == '__main__':
    unittest.main() 