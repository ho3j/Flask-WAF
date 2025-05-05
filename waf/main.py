import sys
import os
from flask import Flask, send_from_directory
from waf.routes.waf_routes import waf_ns
from waf.routes.admin_routes import init_admin_routes
from waf.routes.auth_routes import init_auth_routes
from flask_restx import Api
from waf.db import init_db
import logging
from waf.config import LOG_FILE

# Initialize Flask app
app = Flask(__name__, static_folder='static')
app.secret_key = 'super_secret_key_123'  # Change this in production!

# Initialize Flask-RESTx API
api = Api(app, version='1.0', title='WAF API', description='Simple Web Application Firewall', doc='/docs')

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Log static folder path for debugging
logging.info(f"Static folder path: {app.static_folder}")

# Define absolute path to res/ folder
RES_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'res'))

# Route to serve files from res/ folder
@app.route('/res/<path:filename>')
def serve_res(filename):
    """
    Serve files from the res/ folder.
    
    Args:
        filename (str): Path to the file within res/
    
    Returns:
        File response
    """
    logging.info(f"Serving file from res: {filename}")
    return send_from_directory(RES_FOLDER, filename)

# Initialize database
init_db()

# Register namespaces and routes
api.add_namespace(waf_ns)
init_admin_routes(app)
init_auth_routes(app)

if __name__ == '__main__':
    app.run(debug=True, port=5000)