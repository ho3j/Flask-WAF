import logging
import os

# Configure logging with file and console output
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("log/waf.log"),         # Log to waf.log file
        logging.StreamHandler()                     # Log to console
    ]
)

# Define absolute path 
BASE_DIR = os.path.dirname(os.path.abspath(__file__))   #config.py loc
DB_PATH = os.path.join(BASE_DIR, '../db', 'waf.db')
LOG_FILE = os.path.join(BASE_DIR, '../logs', 'waf.log')
