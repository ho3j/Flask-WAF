import sys
import os
from flask import Flask, request, Response, send_from_directory, render_template, make_response
from waf.routes.waf_routes import waf_ns
from waf.routes.admin_routes import init_admin_routes
from waf.routes.auth_routes import init_auth_routes
from flask_restx import Api
from waf.db import init_db
import logging
from waf.config import LOG_FILE, clean_old_logs
import threading
import time
from datetime import datetime
from werkzeug.wrappers import Response as WerkzeugResponse

# Initialize Flask app
app = Flask(__name__, 
            static_folder='static', 
            template_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'templates')))
app.secret_key = 'super_secret_key_123'

# Initialize Flask-RESTx API
api = Api(app, version='1.0', title='WAF API', description='Simple Web Application Firewall', doc='/docs')

# Setup logging with rotation
from logging.handlers import RotatingFileHandler
handler = RotatingFileHandler(
    LOG_FILE,
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s',
    '%Y-%m-%d %H:%M:%S'
))
logging.getLogger('').setLevel(logging.INFO)
logging.getLogger('').addHandler(handler)

# Log static and template folder paths for debugging
logging.info(f"Static folder path: {app.static_folder}")
logging.info(f"Template folder path: {app.template_folder}")

# Define absolute path to res/ folder
RES_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'res'))

# Route to serve files from res/ folder
@app.route('/res/<path:filename>')
def serve_res(filename):
    logging.info(f"Serving file from res: {filename}")
    try:
        return send_from_directory(RES_FOLDER, filename)
    except Exception as e:
        logging.error(f"Error serving file from res: {filename} - Error: {str(e)}")
        raise

# Route to serve favicon
@app.route('/favicon.ico')
def serve_favicon():
    favicon_path = os.path.join(RES_FOLDER, 'favicon.ico')
    if os.path.exists(favicon_path):
        return send_from_directory(RES_FOLDER, 'favicon.ico')
    else:
        logging.warning(f"Favicon not found: {favicon_path}")
        return Response("Favicon not found", status=404)

# تابع تشخیص حمله (نمونه - باید با منطق WAF خودت جایگزین بشه)
def detect_attack(request):
    """
    تشخیص حملات در درخواست HTTP.
    Returns: (attack_type, suspicious_param) یا (None, None) اگه حمله‌ای نباشه
    """
    suspicious_patterns = {
        'SQLi': ['SELECT *', 'UNION ALL', '1=1'],
        'XSS': ['<script>', 'alert(', 'onerror='],
        'CommandInjection': ['; rm -rf', '&&', '|']
    }
    
    for param, value in request.args.items():
        for attack_type, patterns in suspicious_patterns.items():
            for pattern in patterns:
                if pattern.lower() in value.lower():
                    return attack_type, param
    for param, value in request.form.items():
        for attack_type, patterns in suspicious_patterns.items():
            for pattern in patterns:
                if pattern.lower() in value.lower():
                    return attack_type, param
    return None, None

# فرضیه: تنظیمات WAF برای فوروارد به بک‌اند
FORWARDING_ENABLED = False  # باید با تنظیمات واقعی WAF خودت جایگزین بشه

# Middleware برای لاگ حملات، عملکرد، و مدیریت فوروارد
@app.before_request
def before_request():
    request.start_time = time.time()

@app.after_request
def after_request(response):
    client_ip = request.remote_addr
    request_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # لاگ درخواست
    logging.info(f"Request from IP {client_ip} - Method: {request.method} - URL: {request.url} - Headers: {dict(request.headers)}")
    
    # لاگ حمله
    attack_type, suspicious_param = detect_attack(request)
    if attack_type:
        action = "Blocked"
        logging.warning(f"Attack detected - Type: {attack_type} - IP: {client_ip} - URL: {request.url} - Parameter: {suspicious_param} - Action: {action}")
        response = make_response(render_template('blocked.html', message="Malicious input detected in your request."), 403)
        response.headers['Content-Type'] = 'text/html'
        return response
    
    # بررسی فوروارد به بک‌اند فقط برای درخواست‌های غیر-API، غیراستاتیک، و غیر-احراز هویت
    api_paths = ['/waf', '/docs', '/res', '/favicon.ico', '/login', '/logout', '/dashboard', '/blocked-ips', '/attack-logs', '/rules', '/settings', '/logs-management', '/about-developer']
    if not FORWARDING_ENABLED and not any(request.path.startswith(path) for path in api_paths):
        logging.info(f"Request is safe but forwarding to backend is disabled - IP: {client_ip} - URL: {request.url}")
        response = make_response(render_template('safe_but_disabled.html'))
        response.headers['Content-Type'] = 'text/html'
        return response
    
    # لاگ عملکرد
    duration = (time.time() - request.start_time) * 1000
    response_size = 0
    try:
        if isinstance(response, (Response, WerkzeugResponse)) and not response.direct_passthrough:
            response_size = len(response.get_data(as_text=True))
    except Exception as e:
        logging.warning(f"Error calculating response size: {str(e)}")
    
    log_level = logging.WARNING if duration > 1000 else logging.INFO
    logging.log(log_level, f"Request processed - URL: {request.url} - Response time: {duration:.2f}ms - Response size: {response_size/1024:.2f}KB")
    
    return response

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