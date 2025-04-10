import unittest
import sys
import os
from datetime import datetime
import numpy as np
from unittest.mock import Mock, patch, MagicMock

from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt

from app.components.ml_detection import MachineLearningDetection

class TestMachineLearningDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        
    def setUp(self):
        # Mock the model and feature extraction
        with patch('app.ml.model.load_model', return_value=Mock()):
            with patch('app.utils.feature_extraction.extract_features', return_value=np.zeros((1, 20))):
                self.ml_detection = MachineLearningDetection()
                
        # Mock the model predictions
        self.ml_detection.model.predict = Mock(return_value=np.array([[0.9, 0.1]]))
        self.ml_detection.model.predict_proba = Mock(return_value=np.array([[0.1, 0.9]]))
        
    def tearDown(self):
        self.ml_detection.close()
        self.ml_detection.deleteLater()
        
    def test_initialization(self):
        """Test if ML detection component initializes correctly"""
        self.assertIsNotNone(self.ml_detection)
        self.assertIsNotNone(self.ml_detection.model_selector)
        self.assertIsNotNone(self.ml_detection.threshold_slider)
        self.assertIsNotNone(self.ml_detection.detection_table)
        self.assertIsNotNone(self.ml_detection.history_chart)
        
        # Check model selector population
        self.assertGreaterEqual(self.ml_detection.model_selector.count(), 1)
    
    def test_model_loading(self):
        """Test model loading functionality"""
        # Mock available models
        with patch('os.listdir', return_value=['model1.pkl', 'model2.pkl', 'not_a_model.txt']):
            with patch('os.path.isfile', return_value=True):
                with patch('app.ml.model.load_model', return_value=Mock()) as mock_load:
                    # Call refresh models
                    self.ml_detection.refresh_models()
                    
                    # Check that models were loaded
                    self.assertEqual(self.ml_detection.model_selector.count(), 2)
                    
                    # Select a model
                    self.ml_detection.model_selector.setCurrentIndex(1)
                    
                    # Verify model was loaded
                    mock_load.assert_called()
    
    def test_threshold_adjustment(self):
        """Test detection threshold adjustment"""
        # Initial threshold
        initial_threshold = self.ml_detection.detection_threshold
        
        # Move threshold slider
        self.ml_detection.threshold_slider.setValue(75)
        
        # Trigger the value changed signal
        self.ml_detection.threshold_slider.valueChanged.emit(75)
        
        # Verify threshold updated
        self.assertEqual(self.ml_detection.detection_threshold, 0.75)
        self.assertNotEqual(self.ml_detection.detection_threshold, initial_threshold)
    
    def test_packet_analysis(self):
        """Test packet analysis functionality"""
        # Create test packet
        test_packet = {
            "timestamp": datetime.now(),
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "AA:BB:CC:DD:EE:FF",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "protocol": "ARP",
            "length": 64,
            "info": "Who has 192.168.1.1? Tell 192.168.1.10",
            "raw_data": bytes([0] * 100)  # Mock raw packet data
        }
        
        # Extract features from packet
        with patch('app.utils.feature_extraction.extract_features', return_value=np.zeros((1, 20))):
            # Process packet
            result = self.ml_detection.analyze_packet(test_packet)
            
            # Verify analysis
            self.assertTrue(result["is_attack"])
            self.assertGreaterEqual(result["confidence"], 0.9)
            self.assertEqual(result["packet_id"], test_packet["timestamp"])
    
    def test_batch_analysis(self):
        """Test batch analysis functionality"""
        # Create test packets
        test_packets = [
            {
                "timestamp": datetime.now(),
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "AA:BB:CC:DD:EE:FF",
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.1",
                "protocol": "ARP",
                "length": 64,
                "info": "ARP Packet 1",
                "raw_data": bytes([0] * 100)
            },
            {
                "timestamp": datetime.now(),
                "src_mac": "66:77:88:99:AA:BB",
                "dst_mac": "CC:DD:EE:FF:00:11",
                "src_ip": "192.168.1.20",
                "dst_ip": "192.168.1.1",
                "protocol": "ARP",
                "length": 64,
                "info": "ARP Packet 2",
                "raw_data": bytes([1] * 100)
            }
        ]
        
        # Mock feature extraction
        with patch('app.utils.feature_extraction.extract_features', side_effect=[
            np.zeros((1, 20)),  # First packet features
            np.ones((1, 20))    # Second packet features
        ]):
            # Mock model prediction
            self.ml_detection.model.predict_proba = Mock(side_effect=[
                np.array([[0.1, 0.9]]),  # First packet prediction (attack)
                np.array([[0.8, 0.2]])   # Second packet prediction (normal)
            ])
            
            # Process packets in batch
            results = self.ml_detection.analyze_packets(test_packets)
            
            # Verify results
            self.assertEqual(len(results), 2)
            self.assertTrue(results[0]["is_attack"])
            self.assertFalse(results[1]["is_attack"])
    
    def test_attack_detection_signal(self):
        """Test attack detection signal emission"""
        # Create test packet
        test_packet = {
            "timestamp": datetime.now(),
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "AA:BB:CC:DD:EE:FF",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "protocol": "ARP",
            "length": 64,
            "info": "ARP Packet",
            "raw_data": bytes([0] * 100)
        }
        
        # Mock attack detection signal
        self.ml_detection.attack_detected = Mock()
        
        # Process packet
        with patch('app.utils.feature_extraction.extract_features', return_value=np.zeros((1, 20))):
            self.ml_detection.analyze_packet(test_packet)
            
            # Verify signal was emitted
            self.ml_detection.attack_detected.emit.assert_called_once()
    
    def test_detection_history(self):
        """Test detection history tracking"""
        # Initial history count
        initial_count = len(self.ml_detection.detection_history)
        
        # Create and process test packet
        test_packet = {
            "timestamp": datetime.now(),
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "AA:BB:CC:DD:EE:FF",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "protocol": "ARP",
            "length": 64,
            "info": "ARP Packet",
            "raw_data": bytes([0] * 100)
        }
        
        # Process packet
        with patch('app.utils.feature_extraction.extract_features', return_value=np.zeros((1, 20))):
            self.ml_detection.analyze_packet(test_packet)
            
            # Verify history was updated
            self.assertEqual(len(self.ml_detection.detection_history), initial_count + 1)
            
            # Verify entry in detection table
            self.assertEqual(self.ml_detection.detection_table.rowCount(), initial_count + 1)
    
    def test_feature_extraction(self):
        """Test feature extraction from packets"""
        # Create test packet
        test_packet = {
            "timestamp": datetime.now(),
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "AA:BB:CC:DD:EE:FF",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "protocol": "ARP",
            "length": 64,
            "info": "ARP Packet",
            "raw_data": bytes([0] * 100)
        }
        
        # Create mock feature vector
        mock_features = np.random.rand(1, 20)
        
        # Extract features
        with patch('app.utils.feature_extraction.extract_features', return_value=mock_features) as mock_extract:
            features = self.ml_detection.extract_packet_features(test_packet)
            
            # Verify feature extraction
            mock_extract.assert_called_once()
            np.testing.assert_array_equal(features, mock_features)
    
    def test_model_training(self):
        """Test model training functionality"""
        # Mock training data
        X_train = np.random.rand(100, 20)
        y_train = np.random.randint(0, 2, 100)
        
        # Mock file loader
        with patch('app.utils.data_loader.load_training_data', return_value=(X_train, y_train)):
            # Mock model training
            with patch('app.ml.model.train_model') as mock_train:
                # Train model
                self.ml_detection.train_new_model("test_model", "data.csv")
                
                # Verify model was trained
                mock_train.assert_called_once()
                
                # Verify model was saved
                self.assertEqual(mock_train.call_args[0][2], "test_model")
    
    def test_performance_evaluation(self):
        """Test model performance evaluation"""
        # Create mock metrics
        mock_metrics = {
            "accuracy": 0.95,
            "precision": 0.92,
            "recall": 0.94,
            "f1": 0.93,
            "confusion_matrix": np.array([[45, 5], [3, 47]])
        }
        
        # Mock evaluation function
        with patch('app.ml.evaluation.evaluate_model', return_value=mock_metrics) as mock_evaluate:
            # Evaluate current model
            metrics = self.ml_detection.evaluate_model()
            
            # Verify evaluation
            mock_evaluate.assert_called_once_with(self.ml_detection.model)
            self.assertEqual(metrics["accuracy"], 0.95)
            self.assertEqual(metrics["precision"], 0.92)
    
    def test_error_handling(self):
        """Test error handling in ML detection"""
        # Mock feature extraction to raise exception
        with patch('app.utils.feature_extraction.extract_features', side_effect=Exception("Feature extraction error")):
            # Create test packet
            test_packet = {
                "timestamp": datetime.now(),
                "protocol": "ARP",
                "raw_data": bytes([0] * 100)
            }
            
            # Mock error signal
            self.ml_detection.error_occurred = Mock()
            
            # Analyze packet with error
            result = self.ml_detection.analyze_packet(test_packet)
            
            # Verify error handling
            self.ml_detection.error_occurred.emit.assert_called_once()
            self.assertFalse(result["is_attack"])
            self.assertEqual(result["confidence"], 0.0)
            
if __name__ == '__main__':
    unittest.main() 