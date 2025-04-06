import os
import logging
import logging.handlers
from datetime import datetime
from typing import Optional

from app.utils.config import get_config

# Default log directory
LOG_DIR = os.path.join(os.path.expanduser('~'), '.arpguard', 'logs')

# Log filename format
LOG_FILENAME_FORMAT = 'arpguard_{}.log'

# Log levels
LOG_LEVELS = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}

# Root logger
logger = logging.getLogger('arpguard')

def setup_logging(log_dir: Optional[str] = None, log_level: Optional[str] = None) -> None:
    """Set up logging for the application.
    
    Args:
        log_dir: The directory to store log files. If None, uses the default.
        log_level: The log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
                  If None, uses the level from the configuration.
    """
    # Get configuration
    config = get_config()
    
    # Set up log directory
    if log_dir is None:
        log_dir = LOG_DIR
        
    # Create log directory if it doesn't exist
    try:
        os.makedirs(log_dir, exist_ok=True)
    except Exception as e:
        print(f"Warning: Could not create log directory: {e}")
        log_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Determine log level
    if log_level is None:
        log_level = config.get('log_level', 'INFO')
        
    # Get the numeric log level
    numeric_level = LOG_LEVELS.get(log_level.upper(), logging.INFO)
    
    # Configure root logger
    logger.setLevel(numeric_level)
    
    # Remove any existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Log format
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File handler
    log_filename = LOG_FILENAME_FORMAT.format(datetime.now().strftime('%Y%m%d'))
    log_path = os.path.join(log_dir, log_filename)
    
    # Set up rotating file handler (max 5MB, max 5 backup files)
    file_handler = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=5*1024*1024, backupCount=5
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    logger.info(f"Logging initialized at level {log_level}")
    
    # Log debug information in debug mode
    if config.get('debug_mode', False):
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled")
        logger.debug(f"Log file: {log_path}")


def get_logger(name: str) -> logging.Logger:
    """Get a logger for a specific module.
    
    Args:
        name: The module name.
        
    Returns:
        logging.Logger: A logger instance for the module.
    """
    return logging.getLogger(f'arpguard.{name}')


# Initialize logging when module is imported
setup_logging()


# Module-level logger
module_logger = get_logger('utils.logger') 