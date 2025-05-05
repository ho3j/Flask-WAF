from flask import Flask, request, render_template_string, redirect, url_for, jsonify, make_response, session, flash
from flask_restx import Api, Resource, fields
from waf_utils import check_sql_injection, check_xss, check_command_injection, check_path_traversal, check_csrf, check_lfi
import logging
from config import *
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
from db import init_db, block_ip, get_blocked_ips, unblock_ip, log_attack, add_rule, get_rules, delete_rule, update_setting, get_setting, get_all_settings, get_user
import sqlite3
from datetime import datetime, timedelta
import redis
import bcrypt

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'super_secret_key_123'  # Change this in production!

# Initialize Flask-RESTx API
api = Api(app, version='1.0', title='WAF API', description='Simple Web Application Firewall', doc='/docs')

# Configure rate limiting
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# Connect to Redis for rate limiting
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0)
    redis_client.ping()
except redis.ConnectionError:
    logging.error("Cannot connect to Redis. Behavioral detection disabled.")
    redis_client = None

# Configuration for blocking
BLOCK_DURATION = get_setting('block_duration') or 300  # Duration in seconds (5 minutes)
REQUEST_LIMIT = get_setting('request_limit') or 100   # Maximum requests per minute
REQUEST_WINDOW = get_setting('request_window') or 60   # Time window in seconds

# Initialize the database
init_db()

# Define WAF namespace for API
waf_ns = api.namespace('waf', description='Main WAF endpoint')

def login_required(f):
    """
    Decorator to ensure user is logged in before accessing a route.
    """
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Display and handle the login page.
    
    Returns:
        Rendered HTML template for login page or redirect to dashboard
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = get_user(username)
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login - WAF Dashboard</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
        <style>
            body {
                font-family: 'Vazir', Arial, sans-serif;
                background: linear-gradient(135deg, #667eea, #764ba2);
                height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                margin: 0;
            }
            .login-container {
                background: white;
                padding: 2rem;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
                width: 100%;
                max-width: 400px;
            }
            .login-container img {
                display: block;
                margin: 0 auto 1.5rem;
                max-width: 150px;
            }
            .form-control {
                border-radius: 10px;
                border: 1px solid #ced4da;
                padding: 0.75rem;
            }
            .btn-primary {
                background: #667eea;
                border: none;
                border-radius: 10px;
                padding: 0.75rem;
                width: 100%;
                transition: background 0.3s;
            }
            .btn-primary:hover {
                background: #764ba2;
            }
            .alert {
                border-radius: 10px;
                margin-bottom: 1rem;
            }
            h2 {
                color: #333;
                text-align: center;
                margin-bottom: 1.5rem;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <img src="{{ url_for('static', filename='res/logo.png') }}" alt="WAF Logo">
            <h2>🔐 WAF Login</h2>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ 'success' if category == 'success' else 'danger' }}">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            <form method="POST">
                <div class="mb-3">
                    <label for="username" class="form-label">Username</label>
                    <input type="text" class="form-control" id="username" name="username" required>
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary">Login</button>
            </form>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_template)

@app.route('/logout')
def logout():
    """
    Log out the current user and redirect to login page.
    
    Returns:
        Redirect to login page
    """
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@waf_ns.route('/')
class WAF(Resource):
    @api.doc(description="WAF endpoint for GET/POST requests")
    def get(self):
        """Handle GET requests through the WAF."""
        return process_request()

    @api.doc(description="WAF endpoint for GET/POST requests")
    def post(self):
        """Handle POST requests through the WAF."""
        return process_request()

def process_request():
    """
    Process incoming requests, check for attacks, and forward safe requests to the backend.
    
    Returns:
        Flask response: Blocked response (403/429) or forwarded backend response
    """
    client_ip = request.remote_addr
    current_time = time.time()

    # Check request rate (behavioral detection)
    if redis_client and get_setting('rate_limiting'):
        try:
            key = f"rate:{client_ip}"
            count = redis_client.get(key)
            count = int(count) if count else 0
            if count >= REQUEST_LIMIT:
                log_attack(client_ip, "RateLimit", "Too many requests")
                block_ip(client_ip, BLOCK_DURATION)
                response = make_response(render_template_string("""
                <html>
                <head><meta charset='UTF-8'><title>Blocked</title>
                <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
                <style>
                    body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
                    h2 { color: #cc0000; }
                    p { font-size: 1.1rem; }
                </style>
                </head>
                <body>
                    <h2>⛔ Request Blocked</h2>
                    <p>Too many requests detected.</p>
                </body>
                </html>
                """), 429)
                response.headers['Content-Type'] = 'text/html'
                return response
            redis_client.incr(key)
            redis_client.expire(key, REQUEST_WINDOW)
        except redis.RedisError as e:
            logging.error(f"Redis error: {e}")

    # Check if IP is blocked
    blocked_ips = get_blocked_ips()
    if client_ip in blocked_ips:
        if current_time < blocked_ips[client_ip]:
            response = make_response(render_template_string("""
            <html>
            <head><meta charset='UTF-8'><title>Access Denied</title>
            <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
            <style>
                body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
                h2 { color: #cc0000; }
                p { font-size: 1.1rem; }
            </style>
            </head>
            <body>
                <h2>⛔ Access Denied</h2>
                <p>Your IP ({{ ip }}) is temporarily blocked due to suspicious activity.</p>
                <p>Please try again later.</p>
            </body>
            </html>""", ip=client_ip), 403)
            response.headers['Content-Type'] = 'text/html'
            return response
        else:
            unblock_ip(client_ip)

    # Check for CSRF in POST requests
    if check_csrf(request):
        log_attack(client_ip, "CSRF", "Invalid or missing CSRF token")
        block_ip(client_ip, BLOCK_DURATION)
        response = make_response(render_template_string("""
        <html>
        <head><meta charset='UTF-8'><title>Blocked</title>
        <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
        <style>
            body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
            h2 { color: #cc0000; }
            p { font-size: 1.1rem; }
        </style>
        </head>
        <body>
            <h2>⛔ Request Blocked</h2>
            <p>Invalid or missing CSRF token detected.</p>
        </body>
        </html>
        """), 403)
        response.headers['Content-Type'] = 'text/html'
        return response

    # Check request parameters for attacks
    params = request.args if request.method == 'GET' else request.form
    for key, value in params.items():
        logging.info(f"Checking params: {key}={value}")
        if check_sql_injection(value):
            log_attack(client_ip, "SQLi", f"{key}={value}")
            block_ip(client_ip, BLOCK_DURATION)
            response = make_response(render_template_string("""
            <html>
            <head><meta charset='UTF-8'><title>Blocked</title>
            <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
            <style>
                body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
                h2 { color: #cc0000; }
                p { font-size: 1.1rem; }
            </style>
            </head>
            <body>
                <h2>⛔ Request Blocked</h2>
                <p>Malicious input detected in your request.</p>
            </body>
            </html>
            """), 403)
            response.headers['Content-Type'] = 'text/html'
            return response
        if check_xss(value):
            log_attack(client_ip, "XSS", f"{key}={value}")
            block_ip(client_ip, BLOCK_DURATION)
            response = make_response(render_template_string("""
            <html>
            <head><meta charset='UTF-8'><title>Blocked</title>
            <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
            <style>
                body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
                h2 { color: #cc0000; }
                p { font-size: 1.1rem; }
            </style>
            </head>
            <body>
                <h2>⛔ Request Blocked</h2>
                <p>Malicious input detected in your request.</p>
            </body>
            </html>
            """), 403)
            response.headers['Content-Type'] = 'text/html'
            return response
        if check_command_injection(value):
            log_attack(client_ip, "CommandInjection", f"{key}={value}")
            block_ip(client_ip, BLOCK_DURATION)
            response = make_response(render_template_string("""
            <html>
            <head><meta charset='UTF-8'><title>Blocked</title>
            <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
            <style>
                body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
                h2 { color: #cc0000; }
                p { font-size: 1.1rem; }
            </style>
            </head>
            <body>
                <h2>⛔ Request Blocked</h2>
                <p>Attempt to execute malicious command detected.</p>
            </body>
            </html>
            """), 403)
            response.headers['Content-Type'] = 'text/html'
            return response
        if check_lfi(value):
            logging.info(f"LFI detected for: {key}={value}")
            log_attack(client_ip, "LFI", f"{key}={value}")
            block_ip(client_ip, BLOCK_DURATION)
            response = make_response(render_template_string("""
            <html>
            <head><meta charset='UTF-8'><title>Blocked</title>
            <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
            <style>
                body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
                h2 { color: #cc0000; }
                p { font-size: 1.1rem; }
            </style>
            </head>
            <body>
                <h2>⛔ Request Blocked</h2>
                <p>Attempt to include local files detected.</p>
            </body>
            </html>
            """), 403)
            response.headers['Content-Type'] = 'text/html'
            return response
        if check_path_traversal(value):
            log_attack(client_ip, "PathTraversal", f"{key}={value}")
            block_ip(client_ip, BLOCK_DURATION)
            response = make_response(render_template_string("""
            <html>
            <head><meta charset='UTF-8'><title>Blocked</title>
            <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
            <style>
                body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
                h2 { color: #cc0000; }
                p { font-size: 1.1rem; }
            </style>
            </head>
            <body>
                <h2>⛔ Request Blocked</h2>
                <p>Attempt to access unauthorized files detected.</p>
            </body>
            </html>
            """), 403)
            response.headers['Content-Type'] = 'text/html'
            return response

    # Check raw request body for attacks
    if request.data:
        raw = request.data.decode(errors='ignore')
        logging.info(f"Checking raw body: {raw}")
        if check_sql_injection(raw):
            log_attack(client_ip, "SQLi", "raw body")
            block_ip(client_ip, BLOCK_DURATION)
            return render_template_string("""
            <html>
            <head><title>Blocked</title>
            <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
            <style>
                body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
                h2 { color: #cc0000; }
                p { font-size: 1.1rem; }
            </style>
            </head>
            <body>
                <h2>⛔ Request Blocked</h2>
                <p>Malicious content detected in request body.</p>
            </body>
            </html>
            """), 403
        if check_xss(raw):
            log_attack(client_ip, "XSS", "raw body")
            block_ip(client_ip, BLOCK_DURATION)
            return {"message": "Blocked: Malicious raw body!"}, 403
        if check_command_injection(raw):
            log_attack(client_ip, "CommandInjection", "raw body")
            block_ip(client_ip, BLOCK_DURATION)
            return render_template_string("""
            <html>
            <head><title>Blocked</title>
            <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
            <style>
                body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
                h2 { color: #cc0000; }
                p { font-size: 1.1rem; }
            </style>
            </head>
            <body>
                <h2>⛔ Request Blocked</h2>
                <p>Attempt to execute malicious command in request body detected.</p>
            </body>
            </html>
            """), 403
        if check_lfi(raw):
            logging.info(f"LFI detected in raw body: {raw}")
            log_attack(client_ip, "LFI", "raw body")
            block_ip(client_ip, BLOCK_DURATION)
            return render_template_string("""
            <html>
            <head><title>Blocked</title>
            <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
            <style>
                body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
                h2 { color: #cc0000; }
                p { font-size: 1.1rem; }
            </style>
            </head>
            <body>
                <h2>⛔ Request Blocked</h2>
                <p>Attempt to include local files in request body detected.</p>
            </body>
            </html
            """), 403
        if check_path_traversal(raw):
            log_attack(client_ip, "PathTraversal", "raw body")
            block_ip(client_ip, BLOCK_DURATION)
            return render_template_string("""
            <html>
            <head><title>Blocked</title>
            <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
            <style>
                body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
                h2 { color: #cc0000; }
                p { font-size: 1.1rem; }
            </style>
            </head>
            <body>
                <h2>⛔ Request Blocked</h2>
                <p>Attempt to access unauthorized files in request body detected.</p>
            </body>
            </html
            """), 403

    # Check JSON data for attacks
    if request.is_json:
        json_data = request.get_json(silent=True)
        if isinstance(json_data, dict):
            for key, value in json_data.items():
                if isinstance(value, str):
                    if check_sql_injection(value):
                        log_attack(client_ip, "SQLi", f"json:{key}")
                        block_ip(client_ip, BLOCK_DURATION)
                        return render_template_string("""
                        <html>
                        <head><title>Blocked</title>
                        <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
                        <style>
                            body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
                            h2 { color: #cc0000; }
                            p { font-size: 1.1rem; }
                        </style>
                        </head>
                        <body>
                            <h2>⛔ Request Blocked</h2>
                            <p>Malicious JSON content detected in your request.</p>
                        </body>
                        </html
                        """), 403
                    if check_xss(value):
                        log_attack(client_ip, "XSS", f"json:{key}")
                        block_ip(client_ip, BLOCK_DURATION)
                        return {"message": "Blocked: Malicious JSON content!"}, 403
                    if check_command_injection(value):
                        log_attack(client_ip, "CommandInjection", f"json:{key}")
                        block_ip(client_ip, BLOCK_DURATION)
                        return render_template_string("""
                        <html>
                        <head><title>Blocked</title>
                        <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
                        <style>
                            body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
                            h2 { color: #cc0000; }
                            p { font-size: 1.1rem; }
                        </style>
                        </head>
                        <body>
                            <h2>⛔ Request Blocked</h2>
                            <p>Attempt to execute malicious command in JSON content detected.</p>
                        </body>
                        </html
                        """), 403
                    if check_lfi(value):
                        logging.info(f"LFI detected in JSON: {key}={value}")
                        log_attack(client_ip, "LFI", f"json:{key}")
                        block_ip(client_ip, BLOCK_DURATION)
                        return render_template_string("""
                        <html>
                        <head><title>Blocked</title>
                        <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
                        <style>
                            body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
                            h2 { color: #cc0000; }
                            p { font-size: 1.1rem; }
                        </style>
                        </head>
                        <body>
                            <h2>⛔ Request Blocked</h2>
                            <p>Attempt to include local files in JSON content detected.</p>
                        </body>
                        </html
                        """), 403
                    if check_path_traversal(value):
                        log_attack(client_ip, "PathTraversal", f"json:{key}")
                        block_ip(client_ip, BLOCK_DURATION)
                        return render_template_string("""
                        <html>
                        <head><title>Blocked</title>
                        <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
                        <style>
                            body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
                            h2 { color: #cc0000; }
                            p { font-size: 1.1rem; }
                        </style>
                        </head>
                        <body>
                            <h2>⛔ Request Blocked</h2>
                            <p>Attempt to access unauthorized files in JSON content detected.</p>
                        </body>
                        </html
                        """), 403

    # Check uploaded file names for attacks
    for field_name, file in request.files.items():
        filename = file.filename
        if check_sql_injection(filename):
            log_attack(client_ip, "SQLi", f"filename:{filename}")
            block_ip(client_ip, BLOCK_DURATION)
            return render_template_string("""
            <html>
            <head><title>Blocked</title>
            <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
            <style>
                body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
                h2 { color: #cc0000; }
                p { font-size: 1.1rem; }
            </style>
            </head>
            <body>
                <h2>⛔ Request Blocked</h2>
                <p>Malicious filename detected in uploaded file.</p>
            </body>
            </html
            """), 403
        if check_xss(filename):
            log_attack(client_ip, "XSS", f"filename:{filename}")
            block_ip(client_ip, BLOCK_DURATION)
            return {"message": "Blocked: Malicious filename!"}, 403
        if check_command_injection(filename):
            log_attack(client_ip, "CommandInjection", f"filename:{filename}")
            block_ip(client_ip, BLOCK_DURATION)
            return render_template_string("""
            <html>
            <head><title>Blocked</title>
            <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
            <style>
                body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
                h2 { color: #cc0000; }
                p { font-size: 1.1rem; }
            </style>
            </head>
            <body>
                <h2>⛔ Request Blocked</h2>
                <p>Attempt to execute malicious command in filename detected.</p>
            </body>
            </html
            """), 403
        if check_lfi(filename):
            logging.info(f"LFI detected in filename: {filename}")
            log_attack(client_ip, "LFI", f"filename:{filename}")
            block_ip(client_ip, BLOCK_DURATION)
            return render_template_string("""
            <html>
            <head><title>Blocked</title>
            <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
            <style>
                body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
                h2 { color: #cc0000; }
                p { font-size: 1.1rem; }
            </style>
            </head>
            <body>
                <h2>⛔ Request Blocked</h2>
                <p>Attempt to include local files in filename detected.</p>
            </body>
            </html
            """), 403
        if check_path_traversal(filename):
            log_attack(client_ip, "PathTraversal", f"filename:{filename}")
            block_ip(client_ip, BLOCK_DURATION)
            return render_template_string("""
            <html>
            <head><title>Blocked</title>
            <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
            <style>
                body { font-family: 'Vazir', Arial, sans-serif; background-color: #fff0f0; padding: 2rem; text-align: center; }
                h2 { color: #cc0000; }
                p { font-size: 1.1rem; }
            </style>
            </head>
            <body>
                <h2>⛔ Request Blocked</h2>
                <p>Attempt to access unauthorized files in filename detected.</p>
            </body>
            </html
            """), 403

    # Forward safe requests to the backend if enabled
    if get_setting('forward_to_backend'):
        backend_url = "http://localhost:8888"
        try:
            if request.method == "GET":
                forwarded = requests.get(
                    backend_url,
                    headers={k: v for k, v in request.headers if k.lower() != 'host'},
                    params=request.args
                )
            else:
                forwarded = requests.post(
                    backend_url,
                    headers={k: v for k, v in request.headers if k.lower() != 'host'},
                    data=request.form
                )
            response = make_response(forwarded.text, forwarded.status_code)
            response.headers['Content-Type'] = 'text/html'
            return response
        except Exception as e:
            logging.error(f"Error forwarding to backend: {str(e)}")
            return {"message": "Error connecting to backend server."}, 502
    else:
        # Return a simple response if forwarding is disabled
        return {"message": "Request is safe but forwarding to backend is disabled."}, 200

@api.route('/blocked-ips')
class BlockedIPs(Resource):
    @api.doc(description="View currently blocked IPs")
    def get(self):
        """Retrieve a list of currently blocked IPs with remaining block time."""
        current_time = time.time()
        db_blocked = get_blocked_ips()
        result = {}
        for ip, expiry in db_blocked.items():
            remaining = int(expiry - current_time)
            if remaining > 0:
                result[ip] = f"{remaining} seconds"
        return result

@app.route('/dashboard')
@login_required
def dashboard():
    """
    Display the WAF dashboard with attack statistics and recent logs.
    
    Returns:
        Rendered HTML template for the dashboard
    """
    current_time = time.time()
    conn = sqlite3.connect("waf.db")
    c = conn.cursor()
    
    # Total number of attacks
    c.execute("SELECT COUNT(*) FROM attack_logs")
    total_attacks = c.fetchone()[0]
    
    # Count of attacks by type
    c.execute("SELECT attack_type, COUNT(*) FROM attack_logs GROUP BY attack_type")
    attack_counts = dict(c.fetchall())
    
    # Recent attacks (last 5)
    c.execute("SELECT ip, attack_type, parameter, timestamp FROM attack_logs ORDER BY timestamp DESC LIMIT 5")
    recent_attacks = [
        {'ip': r[0], 'attack_type': r[1], 'parameter': r[2], 'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r[3]))}
        for r in c.fetchall()
    ]
    
    # Number of active blocked IPs
    db_blocked = get_blocked_ips()
    active_blocks = sum(1 for ip, expiry in db_blocked.items() if expiry > current_time)
    
    # Data for attack chart (last 7 days)
    c.execute("""
        SELECT strftime('%Y-%m-%d', timestamp, 'unixepoch') as day, COUNT(*)
        FROM attack_logs
        WHERE timestamp > ?
        GROUP BY day
        ORDER BY day
    """, (current_time - 7 * 24 * 3600,))
    chart_data = c.fetchall()
    chart_labels = [row[0] for row in chart_data]
    chart_values = [row[1] for row in chart_data]
    
    conn.close()
    
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>WAF Dashboard</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
        <style>
            body { font-family: 'Vazir', Arial, sans-serif; background-color: #f4f6f9; padding: 20px; }
            .card { margin-bottom: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            .card-header { background-color: #cc0000; color: white; font-weight: bold; }
            canvas { max-width: 100%; }
            .btn-primary { background-color: #007bff; border: none; }
            .btn-primary:hover { background-color: #0056b3; }
            h1 { color: #333; }
            .navbar { margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-light bg-light">
            <div class="container-fluid">
                <a class="navbar-brand" href="#">WAF Dashboard</a>
                <div>
                    <span class="navbar-text me-3">Welcome, {{ session.username }}</span>
                    <a href="/logout" class="btn btn-outline-danger">Logout</a>
                </div>
            </div>
        </nav>
        <div class="container">
            <h1 class="text-center my-4">🔐 WAF Dashboard</h1>
            <div class="row">
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">Total Attacks</div>
                        <div class="card-body">
                            <h3>{{ total_attacks }}</h3>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">Blocked IPs</div>
                        <div class="card-body">
                            <h3>{{ active_blocks }}</h3>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">Attack Types</div>
                        <div class="card-body">
                            <p>SQLi: {{ attack_counts.get('SQLi', 0) }}</p>
                            <p>XSS: {{ attack_counts.get('XSS', 0) }}</p>
                            <p>CommandInjection: {{ attack_counts.get('CommandInjection', 0) }}</p>
                            <p>PathTraversal: {{ attack_counts.get('PathTraversal', 0) }}</p>
                            <p>CSRF: {{ attack_counts.get('CSRF', 0) }}</p>
                            <p>LFI: {{ attack_counts.get('LFI', 0) }}</p>
                        </div>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-header">Attack Chart (Last 7 Days)</div>
                <div class="card-body">
                    <canvas id="attackChart"></canvas>
                </div>
            </div>
            <div class="card">
                <div class="card-header">Recent Attacks</div>
                <div class="card-body">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>IP</th>
                                <th>Attack Type</th>
                                <th>Parameter</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for attack in recent_attacks %}
                            <tr>
                                <td>{{ attack.ip }}</td>
                                <td>{{ attack.attack_type }}</td>
                                <td>{{ attack.parameter }}</td>
                                <td>{{ attack.time }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="text-center my-4">
                <a href="/analytics/html" class="btn btn-primary">📊 Analytics</a>
                <a href="/settings/html" class="btn btn-primary">⚙️ WAF Settings</a>
                <a href="/blocked-ips/html" class="btn btn-primary">View Blocked IPs</a>
                <a href="/attack-logs/html" class="btn btn-primary">View Attack Logs</a>
                <a href="/rules/html" class="btn btn-primary">Manage Rules</a>
            </div>
        </div>
        <script>
            const ctx = document.getElementById('attackChart').getContext('2d');
            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: {{ chart_labels | tojson }},
                    datasets: [{
                        label: 'Number of Attacks',
                        data: {{ chart_values | tojson }},
                        borderColor: '#cc0000',
                        fill: false
                    }]
                },
                options: { scales: { y: { beginAtZero: true } } }
            });
        </script>
    </body>
    </html>
    """
    return render_template_string(html_template, 
        total_attacks=total_attacks, 
        active_blocks=active_blocks, 
        attack_counts=attack_counts, 
        recent_attacks=recent_attacks, 
        chart_labels=chart_labels, 
        chart_values=chart_values
    )

@app.route('/blocked-ips/html')
@login_required
def show_blocked_ips_html():
    """
    Display a page showing currently blocked IPs with options to unblock or clear all.
    
    Returns:
        Rendered HTML template for blocked IPs
    """
    current_time = time.time()
    db_blocked = get_blocked_ips()
    active_ips = []

    for ip, expiry in db_blocked.items():
        remaining = int(expiry - current_time)
        if remaining > 0:
            active_ips.append((ip, remaining))

    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Blocked IPs</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
        <style>
            body { font-family: 'Vazir', Arial, sans-serif; background-color: #f4f6f9; padding: 20px; }
            .table { background: white; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            .btn-danger { background-color: #cc0000; border: none; }
            .btn-primary { background-color: #007bff; border: none; }
            .btn-primary:hover { background-color: #0056b3; }
            .alert { border-radius: 10px; }
            h1 { color: #333; }
            .navbar { margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-light bg-light">
            <div class="container-fluid">
                <a class="navbar-brand" href="#">WAF Dashboard</a>
                <div>
                    <span class="navbar-text me-3">Welcome, {{ session.username }}</span>
                    <a href="/logout" class="btn btn-outline-danger">Logout</a>
                </div>
            </div>
        </nav>
        <div class="container">
            <h1 class="my-4">⛔ Blocked IPs</h1>
            {% if active_ips %}
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Time Remaining</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {% for ip, time_left in active_ips %}
                    <tr>
                        <td>{{ ip }}</td>
                        <td>{{ time_left }} seconds</td>
                        <td><a class="btn btn-primary btn-sm" href="/unblock/{{ ip }}">Unblock</a></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <form method="POST" action="/blocked-ips/clear" class="mt-3">
                <button type="submit" class="btn btn-danger">🗑 Clear All IPs</button>
            </form>
            {% else %}
            <p class="alert alert-success">✅ No IPs are currently blocked.</p>
            {% endif %}
            <a href="/dashboard" class="btn btn-secondary mt-3">🔙 Back to Dashboard</a>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_template, active_ips=active_ips)

@app.route('/attack-logs/html', methods=['GET', 'POST'])
@login_required
def show_attack_logs_html():
    """
    Display a page showing attack logs with filtering options.
    
    Returns:
        Rendered HTML template for attack logs
    """
    conn = sqlite3.connect("waf.db")
    c = conn.cursor()
    
    # Filter and search parameters
    attack_type = request.form.get('attack_type', '') if request.method == 'POST' else request.args.get('attack_type', '')
    time_filter = request.form.get('time_filter', 'all') if request.method == 'POST' else request.args.get('time_filter', 'all')
    search_ip = request.form.get('search_ip', '') if request.method == 'POST' else request.args.get('search_ip', '')
    
    query = "SELECT ip, attack_type, parameter, timestamp FROM attack_logs WHERE 1=1"
    params = []
    
    if attack_type:
        query += " AND attack_type = ?"
        params.append(attack_type)
    
    if time_filter != 'all':
        current_time = time.time()
        if time_filter == '24h':
            query += " AND timestamp > ?"
            params.append(current_time - 24 * 3600)
        elif time_filter == '7d':
            query += " AND timestamp > ?"
            params.append(current_time - 7 * 24 * 3600)
    
    if search_ip:
        query += " AND ip LIKE ?"
        params.append(f'%{search_ip}%')
    
    query += " ORDER BY timestamp DESC"
    c.execute(query, params)
    logs = c.fetchall()
    conn.close()
    
    logs_fmt = [(ip, typ, param, time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))) for ip, typ, param, ts in logs]
    
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Attack Logs</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
        <style>
            body { font-family: 'Vazir', Arial, sans-serif; background-color: #f4f6f9; padding: 20px; }
            .table { background: white; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            .btn-danger { background-color: #cc0000; border: none; }
            .btn-primary { background-color: #007bff; border: none; }
            .btn-primary:hover { background-color: #0056b3; }
            .form-label { font-weight: bold; }
            h1 { color: #333; }
            .navbar { margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-light bg-light">
            <div class="container-fluid">
                <a class="navbar-brand" href="#">WAF Dashboard</a>
                <div>
                    <span class="navbar-text me-3">Welcome, {{ session.username }}</span>
                    <a href="/logout" class="btn btn-outline-danger">Logout</a>
                </div>
            </div>
        </nav>
        <div class="container">
            <h1 class="my-4">📜 Attack Logs</h1>
            <form method="POST" class="mb-4">
                <div class="row">
                    <div class="col-md-3">
                        <label for="attack_type" class="form-label">Attack Type</label>
                        <select name="attack_type" class="form-select">
                            <option value="">All</option>
                            <option value="SQLi" {% if attack_type == 'SQLi' %}selected{% endif %}>SQLi</option>
                            <option value="XSS" {% if attack_type == 'XSS' %}selected{% endif %}>XSS</option>
                            <option value="CommandInjection" {% if attack_type == 'CommandInjection' %}selected{% endif %}>Command Injection</option>
                            <option value="PathTraversal" {% if attack_type == 'PathTraversal' %}selected{% endif %}>Path Traversal</option>
                            <option value="CSRF" {% if attack_type == 'CSRF' %}selected{% endif %}>CSRF</option>
                            <option value="LFI" {% if attack_type == 'LFI' %}selected{% endif %}>LFI</option>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label for="time_filter" class="form-label">Time Range</label>
                        <select name="time_filter" class="form-select">
                            <option value="all" {% if time_filter == 'all' %}selected{% endif %}>All</option>
                            <option value="24h" {% if time_filter == '24h' %}selected{% endif %}>Last 24 Hours</option>
                            <option value="7d" {% if time_filter == '7d' %}selected{% endif %}>Last 7 Days</option>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label for="search_ip" class="form-label">Search IP</label>
                        <input type="text" name="search_ip" class="form-control" value="{{ search_ip }}">
                    </div>
                    <div class="col-md-3 d-flex align-items-end">
                        <button type="submit" class="btn btn-primary">Filter</button>
                    </div>
                </div>
            </form>
            <form method="POST" action="/attack-logs/clear" class="mb-4">
                <button type="submit" class="btn btn-danger">🧹 Clear All Logs</button>
            </form>
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>Attack Type</th>
                        <th>Parameter</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    {% for log in logs %}
                    <tr>
                        <td>{{ log[0] }}</td>
                        <td>{{ log[1] }}</td>
                        <td>{{ log[2] }}</td>
                        <td>{{ log[3] }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <a href="/dashboard" class="btn btn-secondary">🔙 Back to Dashboard</a>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_template, logs=logs_fmt, attack_type=attack_type, time_filter=time_filter, search_ip=search_ip)

@app.route('/rules/html', methods=['GET', 'POST'])
@login_required
def manage_rules_html():
    """
    Display a page for managing detection rules (add, view, delete).
    
    Returns:
        Rendered HTML template for rule management
    """
    if request.method == 'POST':
        pattern = request.form.get('pattern')
        attack_type = request.form.get('attack_type')
        description = request.form.get('description')
        action = request.form.get('action', 'block')
        if pattern and attack_type:
            add_rule(pattern, attack_type, description, action)
            return redirect(url_for('manage_rules_html'))
    
    rules = get_rules()
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Manage Rules</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
        <style>
            body { font-family: 'Vazir', Arial, sans-serif; background-color: #f4f6f9; padding: 20px; }
            .table { background: white; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            .btn-danger { background-color: #cc0000; border: none; }
            .btn-primary { background-color: #007bff; border: none; }
            .btn-primary:hover { background-color: #0056b3; }
            .form-label { font-weight: bold; }
            h1 { color: #333; }
            .navbar { margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-light bg-light">
            <div class="container-fluid">
                <a class="navbar-brand" href="#">WAF Dashboard</a>
                <div>
                    <span class="navbar-text me-3">Welcome, {{ session.username }}</span>
                    <a href="/logout" class="btn btn-outline-danger">Logout</a>
                </div>
            </div>
        </nav>
        <div class="container">
            <h1 class="my-4">⚙️ Manage Rules</h1>
            <form method="POST" class="mb-4">
                <div class="mb-3">
                    <label for="pattern" class="form-label">Pattern</label>
                    <input type="text" name="pattern" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label for="attack_type" class="form-label">Attack Type</label>
                    <select name="attack_type" class="form-select" required>
                        <option value="SQLi">SQLi</option>
                        <option value="XSS">XSS</option>
                        <option value="CommandInjection">Command Injection</option>
                        <option value="PathTraversal">Path Traversal</option>
                        <option value="LFI">LFI</option>
                    </select>
                </div>
                <div class="mb-3">
                    <label for="description" class="form-label">Description</label>
                    <input type="text" name="description" class="form-control">
                </div>
                <div class="mb-3">
                    <label for="action" class="form-label">Action</label>
                    <select name="action" class="form-select">
                        <option value="block">Block</option>
                        <option value="log">Log Only</option>
                    </select>
                </div>
                <button type="submit" class="btn btn-primary">Add Rule</button>
            </form>
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Pattern</th>
                        <th>Attack Type</th>
                        <th>Description</th>
                        <th>Action</th>
                        <th>Delete</th>
                    </tr>
                </thead>
                <tbody>
                    {% for rule in rules %}
                    <tr>
                        <td>{{ rule.id }}</td>
                        <td>{{ rule.pattern }}</td>
                        <td>{{ rule.attack_type }}</td>
                        <td>{{ rule.description }}</td>
                        <td>{{ rule.action }}</td>
                        <td><a class="btn btn-danger btn-sm" href="/rules/delete/{{ rule.id }}">Delete</a></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <a href="/dashboard" class="btn btn-secondary">🔙 Back to Dashboard</a>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_template, rules=rules)

@app.route('/analytics/html', methods=['GET', 'POST'])
@login_required
def analytics_html():
    """
    Display a page for analyzing attack patterns with charts and top IPs.
    
    Returns:
        Rendered HTML template for analytics
    """
    conn = sqlite3.connect("waf.db")
    c = conn.cursor()
    
    # Filter parameters
    time_filter = request.form.get('time_filter', '7d') if request.method == 'POST' else request.args.get('time_filter', '7d')
    
    current_time = time.time()
    time_condition = ""
    params = []
    
    if time_filter == '24h':
        time_condition = "WHERE timestamp > ?"
        params.append(current_time - 24 * 3600)
    elif time_filter == '7d':
        time_condition = "WHERE timestamp > ?"
        params.append(current_time - 7 * 24 * 3600)
    
    # Attack types chart
    c.execute(f"""
        SELECT attack_type, COUNT(*) 
        FROM attack_logs 
        {time_condition} 
        GROUP BY attack_type
    """, params)
    attack_types_data = c.fetchall()
    attack_types_labels = [row[0] for row in attack_types_data]
    attack_types_values = [row[1] for row in attack_types_data]
    
    # Attacks per day chart
    c.execute(f"""
        SELECT strftime('%Y-%m-%d', timestamp, 'unixepoch') as day, COUNT(*)
        FROM attack_logs
        {time_condition}
        GROUP BY day
        ORDER BY day
    """, params)
    daily_data = c.fetchall()
    daily_labels = [row[0] for row in daily_data]
    daily_values = [row[1] for row in daily_data]
    
    # Top IPs
    c.execute(f"""
        SELECT ip, COUNT(*) as attack_count, MAX(timestamp) as last_seen
        FROM attack_logs
        {time_condition}
        GROUP BY ip
        ORDER BY attack_count DESC
        LIMIT 10
    """, params)
    top_ips = [
        {'ip': row[0], 'attack_count': row[1], 'last_seen': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(row[2]))}
        for row in c.fetchall()
    ]
    
    conn.close()
    
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Attack Analytics</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
        <style>
            body { font-family: 'Vazir', Arial, sans-serif; background-color: #f4f6f9; padding: 20px; }
            .card { margin-bottom: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            .card-header { background-color: #cc0000; color: white; font-weight: bold; }
            canvas { max-width: 100%; }
            .btn-primary { background-color: #007bff; border: none; }
            .btn-primary:hover { background-color: #0056b3; }
            .table { background: white; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            h1 { color: #333; }
            .navbar { margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-light bg-light">
            <div class="container-fluid">
                <a class="navbar-brand" href="#">WAF Dashboard</a>
                <div>
                    <span class="navbar-text me-3">Welcome, {{ session.username }}</span>
                    <a href="/logout" class="btn btn-outline-danger">Logout</a>
                </div>
            </div>
        </nav>
        <div class="container">
            <h1 class="my-4">📊 Attack Analytics</h1>
            <form method="POST" class="mb-4">
                <div class="row">
                    <div class="col-md-3">
                        <label for="time_filter" class="form-label">Time Range</label>
                        <select name="time_filter" class="form-select">
                            <option value="24h" {% if time_filter == '24h' %}selected{% endif %}>Last 24 Hours</option>
                            <option value="7d" {% if time_filter == '7d' %}selected{% endif %}>Last 7 Days</option>
                            <option value="all" {% if time_filter == 'all' %}selected{% endif %}>All</option>
                        </select>
                    </div>
                    <div class="col-md-3 d-flex align-items-end">
                        <button type="submit" class="btn btn-primary">Apply Filter</button>
                    </div>
                </div>
            </form>
            <div class="card">
                <div class="card-header">Attacks by Type</div>
                <div class="card-body">
                    <canvas id="attackTypesChart"></canvas>
                </div>
            </div>
            <div class="card">
                <div class="card-header">Attacks Per Day</div>
                <div class="card-body">
                    <canvas id="dailyAttacksChart"></canvas>
                </div>
            </div>
            <div class="card">
                <div class="card-header">Top Attacking IPs</div>
                <div class="card-body">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>IP</th>
                                <th>Attack Count</th>
                                <th>Last Seen</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for ip in top_ips %}
                            <tr>
                                <td>{{ ip.ip }}</td>
                                <td>{{ ip.attack_count }}</td>
                                <td>{{ ip.last_seen }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            <a href="/dashboard" class="btn btn-secondary">🔙 Back to Dashboard</a>
        </div>
        <script>
            const typesCtx = document.getElementById('attackTypesChart').getContext('2d');
            new Chart(typesCtx, {
                type: 'bar',
                data: {
                    labels: {{ attack_types_labels | tojson }},
                    datasets: [{
                        label: 'Number of Attacks',
                        data: {{ attack_types_values | tojson }},
                        backgroundColor: '#cc0000'
                    }]
                },
                options: { scales: { y: { beginAtZero: true } } }
            });

            const dailyCtx = document.getElementById('dailyAttacksChart').getContext('2d');
            new Chart(dailyCtx, {
                type: 'line',
                data: {
                    labels: {{ daily_labels | tojson }},
                    datasets: [{
                        label: 'Number of Attacks',
                        data: {{ daily_values | tojson }},
                        borderColor: '#cc0000',
                        fill: false
                    }]
                },
                options: { scales: { y: { beginAtZero: true } } }
            });
        </script>
    </body>
    </html>
    """
    return render_template_string(html_template, 
        attack_types_labels=attack_types_labels,
        attack_types_values=attack_types_values,
        daily_labels=daily_labels,
        daily_values=daily_values,
        top_ips=top_ips,
        time_filter=time_filter
    )

@app.route('/settings/html', methods=['GET', 'POST'])
@login_required
def manage_settings_html():
    """
    Display a page for managing WAF settings (enable/disable features).
    
    Returns:
        Rendered HTML template for settings management
    """
    if request.method == 'POST':
        settings = get_all_settings()
        for setting in settings:
            key = setting['key']
            if key in ['block_duration', 'request_limit', 'request_window']:
                value = int(request.form.get(key, 0))
            else:
                value = 1 if request.form.get(key) == 'on' else 0
            update_setting(key, value)
        return redirect(url_for('manage_settings_html'))
    
    settings = get_all_settings()
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Manage WAF Settings</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
        <style>
            body { font-family: 'Vazir', Arial, sans-serif; background-color: #f4f6f9; padding: 20px; }
            .table { background: white; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            .btn-primary { background-color: #007bff; border: none; }
            .btn-primary:hover { background-color: #0056b3; }
            .form-label { font-weight: bold; }
            h1 { color: #333; }
            .navbar { margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-light bg-light">
            <div class="container-fluid">
                <a class="navbar-brand" href="#">WAF Dashboard</a>
                <div>
                    <span class="navbar-text me-3">Welcome, {{ session.username }}</span>
                    <a href="/logout" class="btn btn-outline-danger">Logout</a>
                </div>
            </div>
        </nav>
        <div class="container">
            <h1 class="my-4">⚙️ Manage WAF Settings</h1>
            <form method="POST" class="mb-4">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>Feature</th>
                            <th>Description</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for setting in settings %}
                        <tr>
                            <td>{{ setting.key.replace('_', ' ').title() }}</td>
                            <td>{{ setting.description }}</td>
                            <td>
                                {% if setting.key in ['block_duration', 'request_limit', 'request_window'] %}
                                    <input type="number" name="{{ setting.key }}" class="form-control" value="{{ setting.value }}">
                                {% else %}
                                    <input type="checkbox" name="{{ setting.key }}" {% if setting.value %}checked{% endif %}>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                <button type="submit" class="btn btn-primary">Save Settings</button>
            </form>
            <a href="/dashboard" class="btn btn-secondary">🔙 Back to Dashboard</a>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_template, settings=settings)

@app.route('/rules/delete/<int:rule_id>')
@login_required
def delete_rule_route(rule_id):
    """
    Delete a detection rule and redirect to the rules management page.
    
    Args:
        rule_id (int): ID of the rule to delete
        
    Returns:
        Redirect to the rules management page
    """
    delete_rule(rule_id)
    return redirect(url_for('manage_rules_html'))

@app.route('/attack-logs/clear', methods=['POST'])
@login_required
def clear_attack_logs():
    """
    Clear all attack logs from the database and redirect to the logs page.
    
    Returns:
        Redirect to the attack logs page
    """
    conn = sqlite3.connect("waf.db")
    c = conn.cursor()
    c.execute("DELETE FROM attack_logs")
    conn.commit()
    conn.close()
    return redirect(url_for('show_attack_logs_html'))

@app.route('/unblock/<ip>')
@login_required
def unblock_ip_route(ip):
    """
    Unblock an IP address and display a confirmation page.
    
    Args:
        ip (str): IP address to unblock
        
    Returns:
        Rendered HTML template confirming the unblock
    """
    unblock_ip(ip)
    return render_template_string("""
        <html>
        <head>
            <meta charset="UTF-8">
            <title>IP Unblocked</title>
            <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
            <style>
                body { font-family: 'Vazir', Arial, sans-serif; background-color: #f0fff0; padding: 2rem; text-align: center; }
                h2 { color: #2e7d32; }
                a { color: #007bff; text-decoration: none; }
                a:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <h2>✅ IP {{ ip }} has been unblocked.</h2>
            <a href='/blocked-ips/html'>🔙 Back to Blocked IPs</a>
        </body>
        </html>
    """, ip=ip)

@app.route('/blocked-ips/clear', methods=['POST'])
@login_required
def clear_blocked_ips():
    """
    Clear all blocked IPs from the database and redirect to the blocked IPs page.
    
    Returns:
        Redirect to the blocked IPs page
    """
    conn = sqlite3.connect("waf.db")
    c = conn.cursor()
    c.execute("DELETE FROM blocked_ips")
    conn.commit()
    conn.close()
    return redirect(url_for('show_blocked_ips_html'))

if __name__ == '__main__':
    # Run the Flask app in debug mode on port 5000
    app.run(debug=True, port=5000)