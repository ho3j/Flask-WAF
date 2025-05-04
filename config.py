import logging

# Configure logging with file and console output
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("waf.log"),  # Log to waf.log file
        logging.StreamHandler()          # Log to console
    ]
)