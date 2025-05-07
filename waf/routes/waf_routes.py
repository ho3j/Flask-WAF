from flask_restx import Resource, Namespace
from flask import request, render_template, make_response
from waf.waf_utils import check_sql_injection, check_xss, check_command_injection, check_path_traversal, check_csrf, check_lfi
import logging
import requests
from waf.db import block_ip, get_blocked_ips, unblock_ip, log_attack, get_setting
import time

waf_ns = Namespace('waf', description='Main WAF endpoint')

@waf_ns.route('/')
class WAF(Resource):
    @waf_ns.doc(description="WAF endpoint for GET/POST requests")
    def get(self):
        """Handle GET requests through the WAF."""
        return process_request()

    @waf_ns.doc(description="WAF endpoint for GET/POST requests")
    def post(self):
        """Handle POST requests through the WAF."""
        return process_request()

@waf_ns.route('/blocked-ips')
class BlockedIPs(Resource):
    @waf_ns.doc(description="View currently blocked IPs")
    def get(self):
        """Retrieve a list of currently blocked IPs with remaining block time."""
        current_time = time.time()
        db_blocked = get_blocked_ips()
        result = {}
        for entry in db_blocked:
            ip = entry['ip']
            expiry = entry['expires_at']
            if expiry is None or expiry > current_time:
                remaining = int(expiry - current_time) if expiry else 0
                result[ip] = f"{remaining} seconds"
        return result

@waf_ns.route('/blocked-ips/html')
class BlockedIPsHTML(Resource):
    @waf_ns.doc(description="View currently blocked IPs in HTML format")
    def get(self):
        """Retrieve a list of currently blocked IPs with remaining block time in HTML."""
        current_time = time.time()
        db_blocked = get_blocked_ips()
        blocked_ips = []
        for entry in db_blocked:
            ip = entry['ip']
            expiry = entry['expires_at']
            if expiry is None or expiry > current_time:
                remaining = int(expiry - current_time) if expiry else 0
                blocked_ips.append({'ip': ip, 'remaining': remaining})
        return render_template('blocked_ips.html', blocked_ips=blocked_ips)

def process_request():
    """
    Process incoming requests, check for attacks, and forward safe requests to the backend.
    
    Returns:
        Flask response: Blocked response (403/429), forwarded backend response, or safe request page
    """
    client_ip = request.remote_addr
    current_time = time.time()
    BLOCK_DURATION = get_setting('block_duration') or 300

    # Log Accept header and forward_to_backend setting for debugging
    accept_header = request.headers.get('Accept', '')
    forward_to_backend = get_setting('forward_to_backend')
    logging.info(f"Accept header: {accept_header}")
    logging.info(f"forward_to_backend: {forward_to_backend}")

    # Check if IP is blocked
    blocked_ips = get_blocked_ips()
    if client_ip in blocked_ips:
        if blocked_ips[client_ip] is None or current_time < blocked_ips[client_ip]:
            logging.info(f"IP {client_ip} is blocked. Rendering blocked.html")
            response = make_response(render_template('blocked.html', ip=client_ip, message="Your IP is temporarily blocked due to suspicious activity."), 403)
            response.headers['Content-Type'] = 'text/html'
            return response
        else:
            unblock_ip(client_ip)

    # Check for CSRF in POST requests
    if check_csrf(request):
        log_attack(client_ip, "CSRF", "Invalid or missing CSRF token")
        block_ip(client_ip, BLOCK_DURATION)
        logging.info(f"CSRF detected from IP {client_ip}. Rendering blocked.html")
        response = make_response(render_template('blocked.html', message="Invalid or missing CSRF token detected."), 403)
        response.headers['Content-Type'] = 'text/html'
        return response

    # Check request parameters for attacks
    params = request.args if request.method == 'GET' else request.form
    for key, value in params.items():
        logging.info(f"Checking params: {key}={value}")
        if check_sql_injection(value):
            log_attack(client_ip, "SQLi", f"{key}={value}")
            block_ip(client_ip, BLOCK_DURATION)
            logging.info(f"SQLi detected from IP {client_ip}. Rendering blocked.html")
            response = make_response(render_template('blocked.html', message="Malicious input detected in your request."), 403)
            response.headers['Content-Type'] = 'text/html'
            return response
        if check_xss(value):
            log_attack(client_ip, "XSS", f"{key}={value}")
            block_ip(client_ip, BLOCK_DURATION)
            logging.info(f"XSS detected from IP {client_ip}. Rendering blocked.html")
            response = make_response(render_template('blocked.html', message="Malicious input detected in your request."), 403)
            response.headers['Content-Type'] = 'text/html'
            return response
        if check_command_injection(value):
            log_attack(client_ip, "CommandInjection", f"{key}={value}")
            block_ip(client_ip, BLOCK_DURATION)
            logging.info(f"CommandInjection detected from IP {client_ip}. Rendering blocked.html")
            response = make_response(render_template('blocked.html', message="Attempt to execute malicious command detected."), 403)
            response.headers['Content-Type'] = 'text/html'
            return response
        if check_lfi(value):
            logging.info(f"LFI detected for: {key}={value}")
            log_attack(client_ip, "LFI", f"{key}={value}")
            block_ip(client_ip, BLOCK_DURATION)
            logging.info(f"LFI detected from IP {client_ip}. Rendering blocked.html")
            response = make_response(render_template('blocked.html', message="Attempt to include local files detected."), 403)
            response.headers['Content-Type'] = 'text/html'
            return response
        if check_path_traversal(value):
            log_attack(client_ip, "PathTraversal", f"{key}={value}")
            block_ip(client_ip, BLOCK_DURATION)
            logging.info(f"PathTraversal detected from IP {client_ip}. Rendering blocked.html")
            response = make_response(render_template('blocked.html', message="Attempt to access unauthorized files detected."), 403)
            response.headers['Content-Type'] = 'text/html'
            return response

    # Check raw request body for attacks
    if request.data:
        raw = request.data.decode(errors='ignore')
        logging.info(f"Checking raw body: {raw}")
        if check_sql_injection(raw):
            log_attack(client_ip, "SQLi", "raw body")
            block_ip(client_ip, BLOCK_DURATION)
            logging.info(f"SQLi detected in raw body from IP {client_ip}. Rendering blocked.html")
            response = make_response(render_template('blocked.html', message="Malicious content detected in request body."), 403)
            response.headers['Content-Type'] = 'text/html'
            return response
        if check_xss(raw):
            log_attack(client_ip, "XSS", "raw body")
            block_ip(client_ip, BLOCK_DURATION)
            logging.info(f"XSS detected in raw body from IP {client_ip}. Returning JSON")
            response = make_response({"message": "Blocked: Malicious raw body!"}, 403)
            response.headers['Content-Type'] = 'application/json'
            return response
        if check_command_injection(raw):
            log_attack(client_ip, "CommandInjection", "raw body")
            block_ip(client_ip, BLOCK_DURATION)
            logging.info(f"CommandInjection detected in raw body from IP {client_ip}. Rendering blocked.html")
            response = make_response(render_template('blocked.html', message="Attempt to execute malicious command in request body detected."), 403)
            response.headers['Content-Type'] = 'text/html'
            return response
        if check_lfi(raw):
            logging.info(f"LFI detected in raw body: {raw}")
            log_attack(client_ip, "LFI", "raw body")
            block_ip(client_ip, BLOCK_DURATION)
            logging.info(f"LFI detected in raw body from IP {client_ip}. Rendering blocked.html")
            response = make_response(render_template('blocked.html', message="Attempt to include local files in request body detected."), 403)
            response.headers['Content-Type'] = 'text/html'
            return response
        if check_path_traversal(raw):
            log_attack(client_ip, "PathTraversal", "raw body")
            block_ip(client_ip, BLOCK_DURATION)
            logging.info(f"PathTraversal detected in raw body from IP {client_ip}. Rendering blocked.html")
            response = make_response(render_template('blocked.html', message="Attempt to access unauthorized files in request body detected."), 403)
            response.headers['Content-Type'] = 'text/html'
            return response

    # Check JSON data for attacks
    if request.is_json:
        json_data = request.get_json(silent=True)
        if isinstance(json_data, dict):
            for key, value in json_data.items():
                if isinstance(value, str):
                    if check_sql_injection(value):
                        log_attack(client_ip, "SQLi", f"json:{key}")
                        block_ip(client_ip, BLOCK_DURATION)
                        logging.info(f"SQLi detected in JSON from IP {client_ip}. Rendering blocked.html")
                        response = make_response(render_template('blocked.html', message="Malicious JSON content detected in your request."), 403)
                        response.headers['Content-Type'] = 'text/html'
                        return response
                    if check_xss(value):
                        log_attack(client_ip, "XSS", f"json:{key}")
                        block_ip(client_ip, BLOCK_DURATION)
                        logging.info(f"XSS detected in JSON from IP {client_ip}. Returning JSON")
                        response = make_response({"message": "Blocked: Malicious JSON content!"}, 403)
                        response.headers['Content-Type'] = 'application/json'
                        return response
                    if check_command_injection(value):
                        log_attack(client_ip, "CommandInjection", f"json:{key}")
                        block_ip(client_ip, BLOCK_DURATION)
                        logging.info(f"CommandInjection detected in JSON from IP {client_ip}. Rendering blocked.html")
                        response = make_response(render_template('blocked.html', message="Attempt to execute malicious command in JSON content detected."), 403)
                        response.headers['Content-Type'] = 'text/html'
                        return response
                    if check_lfi(value):
                        logging.info(f"LFI detected in JSON: {key}={value}")
                        log_attack(client_ip, "LFI", f"json:{key}")
                        block_ip(client_ip, BLOCK_DURATION)
                        logging.info(f"LFI detected in JSON from IP {client_ip}. Rendering blocked.html")
                        response = make_response(render_template('blocked.html', message="Attempt to include local files in JSON content detected."), 403)
                        response.headers['Content-Type'] = 'text/html'
                        return response
                    if check_path_traversal(value):
                        log_attack(client_ip, "PathTraversal", f"json:{key}")
                        block_ip(client_ip, BLOCK_DURATION)
                        logging.info(f"PathTraversal detected in JSON from IP {client_ip}. Rendering blocked.html")
                        response = make_response(render_template('blocked.html', message="Attempt to access unauthorized files in JSON content detected."), 403)
                        response.headers['Content-Type'] = 'text/html'
                        return response

    # Check uploaded file names for attacks
    for field_name, file in request.files.items():
        filename = file.filename
        if check_sql_injection(filename):
            log_attack(client_ip, "SQLi", f"filename:{filename}")
            block_ip(client_ip, BLOCK_DURATION)
            logging.info(f"SQLi detected in filename from IP {client_ip}. Rendering blocked.html")
            response = make_response(render_template('blocked.html', message="Malicious filename detected in uploaded file."), 403)
            response.headers['Content-Type'] = 'text/html'
            return response
        if check_xss(filename):
            log_attack(client_ip, "XSS", f"filename:{filename}")
            block_ip(client_ip, BLOCK_DURATION)
            logging.info(f"XSS detected in filename from IP {client_ip}. Returning JSON")
            response = make_response({"message": "Blocked: Malicious filename!"}, 403)
            response.headers['Content-Type'] = 'application/json'
            return response
        if check_command_injection(filename):
            log_attack(client_ip, "CommandInjection", f"filename:{filename}")
            block_ip(client_ip, BLOCK_DURATION)
            logging.info(f"CommandInjection detected in filename from IP {client_ip}. Rendering blocked.html")
            response = make_response(render_template('blocked.html', message="Attempt to execute malicious command in filename detected."), 403)
            response.headers['Content-Type'] = 'text/html'
            return response
        if check_lfi(filename):
            logging.info(f"LFI detected in filename: {filename}")
            log_attack(client_ip, "LFI", f"filename:{filename}")
            block_ip(client_ip, BLOCK_DURATION)
            logging.info(f"LFI detected in filename from IP {client_ip}. Rendering blocked.html")
            response = make_response(render_template('blocked.html', message="Attempt to include local files in filename detected."), 403)
            response.headers['Content-Type'] = 'text/html'
            return response
        if check_path_traversal(filename):
            log_attack(client_ip, "PathTraversal", f"filename:{filename}")
            block_ip(client_ip, BLOCK_DURATION)
            logging.info(f"PathTraversal detected in filename from IP {client_ip}. Rendering blocked.html")
            response = make_response(render_template('blocked.html', message="Attempt to access unauthorized files in filename detected."), 403)
            response.headers['Content-Type'] = 'text/html'
            return response

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
            logging.info(f"Forwarded to backend successfully. Status: {forwarded.status_code}")
            response = make_response(forwarded.text, forwarded.status_code)
            response.headers['Content-Type'] = 'text/html'
            return response
        except Exception as e:
            logging.error(f"Error forwarding to backend: {str(e)}")
            if 'text/html' in accept_header.lower():
                logging.info(f"Backend error for HTML request from IP {client_ip}. Rendering error.html")
                response = make_response(render_template('error.html', message="Error connecting to backend server."), 502)
                response.headers['Content-Type'] = 'text/html'
                return response
            logging.info(f"Backend error for non-HTML request from IP {client_ip}. Returning JSON")
            response = make_response({"message": "Error connecting to backend server."}, 502)
            response.headers['Content-Type'] = 'application/json'
            return response
    else:
        # برای درخواست‌های HTML (مرورگر)، صفحه safe_request.html رندر کن
        if 'text/html' in accept_header.lower():
            logging.info(f"Safe HTML request from IP {client_ip}. Rendering safe_request.html")
            response = make_response(render_template('safe_request.html'))
            response.headers['Content-Type'] = 'text/html'
            return response
        # برای API یا درخواست‌های غیر-HTML، پاسخ JSON برگردون
        logging.info(f"Safe non-HTML request from IP {client_ip}. Returning JSON")
        response = make_response({"message": "Request is safe but forwarding to backend is disabled."}, 200)
        response.headers['Content-Type'] = 'application/json'
        return response