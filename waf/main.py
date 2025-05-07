import sys
import os
from flask import Flask, send_from_directory
from waf.routes.waf_routes import waf_ns
from waf.routes.admin_routes import init_admin_routes
from waf.routes.auth_routes import init_auth_routes
from flask_restx import Api
from waf.db import init_db
import logging
from waf.config import LOG_FILE, clean_old_logs
import threading
import time

# Initialize Flask app
app = Flask(__name__, 
            static_folder='static', 
            template_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'templates')))
app.secret_key = 'super_secret_key_123'

# Log static and template folder paths for debugging
# logging.info(f"Static folder path: {app.static_folder}")
# logging.info(f"Template folder path: {app.template_folder}")

# Initialize Flask-RESTx API
api = Api(app, version='1.0', title='WAF API', description='Simple Web Application Firewall', doc='/docs')

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Define absolute path to res/ folder
RES_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'res'))

# Route to serve files from res/ folder
@app.route('/res/<path:filename>')
def serve_res(filename):
    logging.info(f"Serving file from res: {filename}")
    return send_from_directory(RES_FOLDER, filename)

# Initialize database
init_db()

# Register namespaces and routes
api.add_namespace(waf_ns)
init_admin_routes(app)
init_auth_routes(app)

# Periodic log cleanup
def periodic_log_cleanup():
    while True:
        deleted_files, freed_space = clean_old_logs(max_age_days=30)
        if deleted_files > 0:
            logging.info(f"Periodic cleanup: Deleted {deleted_files} log files, freed {freed_space:.2f} MB")
        time.sleep(24 * 3600)  # هر 24 ساعت

# Start cleanup thread
cleanup_thread = threading.Thread(target=periodic_log_cleanup, daemon=True)
cleanup_thread.start()

if __name__ == '__main__':
    app.run(debug=True, port=5000)