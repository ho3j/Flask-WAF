import logging

# Configure logging with file and console output
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("log/waf.log"),         # Log to waf.log file
        logging.StreamHandler()                     # Log to console
    ]
)

# Define absolute path to the log file
LOG_FILE = "res/logs/waf.log"
