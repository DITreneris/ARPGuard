import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import torch
import torch.nn as nn
import torch.optim as optim
from collections import deque
import random
from typing import Dict, List, Any, Optional, Tuple
import logging
from datetime import datetime

from app.utils.logger import get_logger

logger = get_logger('components.ml_threat_detector')

class MLThreatDetector:
    """Machine Learning based threat detection system using hybrid Random Forest and Reinforcement Learning approach.
    
    This class maintains the legacy ML approach while serving as a bridge to the new ARPGuardML API.
    """
    
    def __init__(self):
        """Initialize the ML threat detector."""
        # Random Forest for initial threat classification
        self.rf_classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        # RL components
        self.state_size = 10  # Number of features
        self.action_size = 3  # Actions: [block, monitor, allow]
        self.memory = deque(maxlen=10000)
        self.gamma = 0.95    # Discount factor
        self.epsilon = 1.0   # Exploration rate
        self.epsilon_min = 0.01
        self.epsilon_decay = 0.995
        self.learning_rate = 0.001
        
        # Neural Network for Q-learning
        self.model = self._build_model()
        self.target_model = self._build_model()
        self.update_target_model()
        
        # Feature scaler
        self.scaler = StandardScaler()
        
        # Training data
        self.X_train = []
        self.y_train = []
        
        # Threat history
        self.threat_history = []
        
        # Bridge to the new ML API
        self.ml_integration = None
        self.use_ml_api = False
    
    def set_ml_integration(self, ml_integration):
        """Set the ML integration component.
        
        Args:
            ml_integration: MLIntegration instance
        """
        self.ml_integration = ml_integration
        self.use_ml_api = True
        logger.info("MLThreatDetector connected to ML integration")
    
    def _build_model(self) -> nn.Module:
        """Build the neural network model for Q-learning."""
        model = nn.Sequential(
            nn.Linear(self.state_size, 24),
            nn.ReLU(),
            nn.Linear(24, 24),
            nn.ReLU(),
            nn.Linear(24, self.action_size)
        )
        return model
    
    def update_target_model(self):
        """Update the target model with weights from the main model."""
        self.target_model.load_state_dict(self.model.state_dict())
    
    def remember(self, state: np.ndarray, action: int, reward: float, next_state: np.ndarray, done: bool):
        """Store experience in memory."""
        self.memory.append((state, action, reward, next_state, done))
    
    def act(self, state: np.ndarray) -> int:
        """Choose an action based on the current state."""
        if random.random() <= self.epsilon:
            return random.randrange(self.action_size)
        
        with torch.no_grad():
            state_tensor = torch.FloatTensor(state).unsqueeze(0)
            act_values = self.model(state_tensor)
            return torch.argmax(act_values[0]).item()
    
    def replay(self, batch_size: int):
        """Train the model using experience replay."""
        if len(self.memory) < batch_size:
            return
        
        minibatch = random.sample(self.memory, batch_size)
        states = torch.FloatTensor([i[0] for i in minibatch])
        actions = torch.LongTensor([i[1] for i in minibatch])
        rewards = torch.FloatTensor([i[2] for i in minibatch])
        next_states = torch.FloatTensor([i[3] for i in minibatch])
        dones = torch.FloatTensor([i[4] for i in minibatch])
        
        # Current Q values
        current_q_values = self.model(states).gather(1, actions.unsqueeze(1))
        
        # Next Q values from target model
        with torch.no_grad():
            next_q_values = self.target_model(next_states).max(1)[0]
            target_q_values = rewards + (1 - dones) * self.gamma * next_q_values
        
        # Compute loss and update
        loss = nn.MSELoss()(current_q_values.squeeze(), target_q_values)
        optimizer = optim.Adam(self.model.parameters(), lr=self.learning_rate)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        
        # Decay epsilon
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
    
    def extract_features(self, packet: Dict[str, Any]) -> np.ndarray:
        """Extract features from a network packet for ML analysis."""
        features = []
        
        # Basic packet features
        features.extend([
            packet.get('packet_length', 0),
            packet.get('protocol', 0),
            packet.get('src_port', 0),
            packet.get('dst_port', 0)
        ])
        
        # Traffic pattern features
        features.extend([
            packet.get('packets_per_second', 0),
            packet.get('bytes_per_second', 0),
            packet.get('unique_ports', 0),
            packet.get('connection_attempts', 0)
        ])
        
        # Threat intelligence features
        features.extend([
            packet.get('threat_score', 0),
            packet.get('reputation_score', 0)
        ])
        
        return np.array(features)
    
    def analyze_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a network packet using ML models.
        
        Args:
            packet: Dictionary containing packet information
            
        Returns:
            Dictionary with analysis results and recommended action
        """
        # If using ML API and integration is available, try to get anomaly detection results
        anomaly_result = None
        if self.use_ml_api and self.ml_integration and self.ml_integration.models_initialized:
            try:
                # Extract features for anomaly detection
                features = self.extract_features(packet)
                
                # Use the anomaly detector if available
                if self.ml_integration.ml_api.anomaly_detector:
                    is_anomaly, score, explanation = self.ml_integration.ml_api.detect_anomalies(
                        features.reshape(1, -1), explain=True
                    )
                    
                    if is_anomaly[0]:
                        anomaly_result = {
                            'is_anomaly': True,
                            'anomaly_score': float(score[0]),
                            'explanation': explanation
                        }
                        
                        logger.info(f"Anomaly detected for packet from {packet.get('src_ip', 'unknown')}")
            
            except Exception as e:
                logger.error(f"Error using ML API for anomaly detection: {e}")
        
        # Extract features for legacy model
        features = self.extract_features(packet)
        
        # Scale features
        if len(self.X_train) > 0:
            features = self.scaler.transform(features.reshape(1, -1))[0]
        
        # Get Random Forest prediction
        if len(self.X_train) > 0:
            rf_prediction = self.rf_classifier.predict_proba(features.reshape(1, -1))[0]
            threat_probability = rf_prediction[1]  # Probability of being a threat
        else:
            threat_probability = 0.5  # Default if not trained
        
        # Get RL action
        action = self.act(features)
        action_map = {0: 'block', 1: 'monitor', 2: 'allow'}
        
        # If anomaly detected, increase threat probability and change action
        if anomaly_result:
            threat_probability = max(threat_probability, anomaly_result['anomaly_score'])
            if threat_probability > 0.7:
                action = 0  # block
            elif threat_probability > 0.5:
                action = 1  # monitor
        
        # Store in history
        history_entry = {
            'timestamp': datetime.now(),
            'features': features.tolist(),
            'threat_probability': float(threat_probability),
            'action': action_map[action],
            'packet_info': packet
        }
        
        # Add anomaly information if available
        if anomaly_result:
            history_entry['is_anomaly'] = True
            history_entry['anomaly_score'] = anomaly_result['anomaly_score']
            history_entry['anomaly_explanation'] = anomaly_result['explanation']
        
        self.threat_history.append(history_entry)
        
        # Keep history to a reasonable size
        if len(self.threat_history) > 1000:
            self.threat_history = self.threat_history[-1000:]
        
        result = {
            'threat_probability': float(threat_probability),
            'recommended_action': action_map[action],
            'confidence': float(1.0 - self.epsilon)  # Use epsilon as confidence measure
        }
        
        # Add anomaly information if available
        if anomaly_result:
            result['is_anomaly'] = True
            result['anomaly_score'] = anomaly_result['anomaly_score']
            result['anomaly_explanation'] = anomaly_result['explanation']
        
        return result
    
    def train(self, X: np.ndarray, y: np.ndarray):
        """Train the ML models with new data.
        
        Args:
            X: Feature matrix
            y: Target labels
        """
        # Update training data
        self.X_train = X
        self.y_train = y
        
        # Scale features
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        
        # Train Random Forest
        self.rf_classifier.fit(X_scaled, y)
        
        # Train RL model
        batch_size = 32
        for _ in range(100):  # Number of training episodes
            self.replay(batch_size)
        
        # Update target model
        self.update_target_model()
        
        logger.info("ML models trained successfully")
    
    def get_threat_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get the history of analyzed threats.
        
        Args:
            limit: Optional limit on number of entries to return
            
        Returns:
            List of threat history entries
        """
        if limit is None:
            return self.threat_history
        return self.threat_history[-limit:] 