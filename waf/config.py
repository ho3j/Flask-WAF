import logging
from concurrent_log_handler import ConcurrentRotatingFileHandler
import os
import time

# Define absolute path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, '../logs')
LOG_FILE = os.path.join(LOG_DIR, 'waf.log')
DB_PATH = os.path.join(BASE_DIR, '../db', 'waf.db')

# Create logs directory if it doesn't exist
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# Configure logging with concurrent rotation
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Create concurrent rotating file handler
handler = ConcurrentRotatingFileHandler(
    LOG_FILE,
    maxBytes=5 * 1024 * 1024,  # 5MB
    backupCount=10  # حداکثر 10 فایل آرشیوی
)
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

# Add handlers (file and console)
logger.handlers = []  # Clear existing handlers
logger.addHandler(handler)
logger.addHandler(logging.StreamHandler())

def clean_old_logs(max_age_days=30):
    """
    Delete log files older than max_age_days.
    
    Args:
        max_age_days (int): Maximum age of log files to keep (in days)
    
    Returns:
        tuple: (number of deleted files, total freed space in MB)
    """
    deleted_files = 0
    freed_space = 0
    log_dir = os.path.dirname(LOG_FILE)
    
    for f in os.listdir(log_dir):
        if f.startswith('waf.log'):  # شامل waf.log و waf.log.1 و غیره
            file_path = os.path.join(log_dir, f)
            try:
                if os.path.getmtime(file_path) < time.time() - max_age_days * 24 * 3600:
                    file_size = os.path.getsize(file_path)
                    os.remove(file_path)
                    deleted_files += 1
                    freed_space += file_size
            except (PermissionError, OSError) as e:
                logger.warning(f"Could not delete {file_path}: {e}")
    
    return deleted_files, freed_space / (1024 * 1024)  # Freed space in MB

def get_logs_size():
    """
    Calculate total size of log files.
    
    Returns:
        tuple: (total size in MB, list of log files with their sizes)
    """
    total_size = 0
    log_files = []
    log_dir = os.path.dirname(LOG_FILE)
    
    for f in os.listdir(log_dir):
        if f.startswith('waf.log'):
            file_path = os.path.join(log_dir, f)
            try:
                file_size = os.path.getsize(file_path)
                total_size += file_size
                log_files.append((f, file_size / (1024 * 1024)))  # Size in MB
            except OSError as e:
                logger.warning(f"Could not access {file_path}: {e}")
    
    return total_size / (1024 * 1024), log_files  # Total size in MB