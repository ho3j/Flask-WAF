from flask_restx import Resource, Namespace
from flask import request, render_template_string, make_response
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

def process_request():
    """
    Process incoming requests, check for attacks, and forward safe requests to the backend.
    
    Returns:
        Flask response: Blocked response (403/429) or forwarded backend response
    """
    client_ip = request.remote_addr
    current_time = time.time()
    BLOCK_DURATION = get_setting('block_duration') or 300

    # Check if IP is blocked
    blocked_ips = get_blocked_ips()
    if client_ip in blocked_ips:
        if blocked_ips[client_ip] is None or current_time < blocked_ips[client_ip]:
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
            </html>
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
            </html>
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
                        </html>
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
                        </html>
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
                        </html>
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
                        </html>
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
            </html>
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
            </html>
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
            </html>
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
            </html>
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