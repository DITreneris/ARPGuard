import logging
from logging.handlers import RotatingFileHandler
import os
from typing import Optional
from datetime import datetime

class DemoLogger:
    """Logging system for ARP Guard demo"""
    
    def __init__(self, log_file: str = "arpguard_demo.log", log_level: str = "INFO"):
        self.log_file = log_file
        self.log_level = getattr(logging, log_level.upper())
        self.logger = self._setup_logger()
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logger with file rotation and console output"""
        logger = logging.getLogger("arpguard_demo")
        logger.setLevel(self.log_level)
        
        # Create logs directory if it doesn't exist
        os.makedirs("logs", exist_ok=True)
        
        # File handler with rotation
        file_handler = RotatingFileHandler(
            os.path.join("logs", self.log_file),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(self.log_level)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(self.log_level)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def debug(self, message: str) -> None:
        """Log debug message"""
        self.logger.debug(message)
    
    def info(self, message: str) -> None:
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message: str) -> None:
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message: str) -> None:
        """Log error message"""
        self.logger.error(message)
    
    def critical(self, message: str) -> None:
        """Log critical message"""
        self.logger.critical(message)
    
    def log_demo_event(self, event_type: str, details: dict) -> None:
        """Log a demo-specific event with structured data"""
        self.info(f"Demo Event - {event_type}: {details}")
    
    def log_packet_event(self, packet_type: str, source: str, destination: str) -> None:
        """Log packet-related event"""
        self.debug(f"Packet Event - Type: {packet_type}, Source: {source}, Destination: {destination}")
    
    def log_alert_event(self, alert_type: str, severity: str, message: str) -> None:
        """Log alert-related event"""
        self.warning(f"Alert Event - Type: {alert_type}, Severity: {severity}, Message: {message}")
    
    def get_log_file_path(self) -> str:
        """Get the current log file path"""
        return os.path.join("logs", self.log_file)
    
    def rotate_logs(self) -> None:
        """Force log rotation"""
        for handler in self.logger.handlers:
            if isinstance(handler, RotatingFileHandler):
                handler.doRollover() 