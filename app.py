from flask import Flask, request, render_template_string, redirect, url_for, jsonify, make_response
from flask_restx import Api, Resource, fields
from waf_utils import check_sql_injection, check_xss
import logging
from config import *
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
from db import init_db, block_ip, get_blocked_ips, unblock_ip, log_attack
import sqlite3

app = Flask(__name__)
api = Api(app, version='1.0', title='WAF API', description='Simple Web Application Firewall', doc='/docs')

# محدودیت نرخ
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# تنظیمات بلاک
BLOCK_DURATION = 300  # ثانیه = 5 دقیقه

# اجرای اولیه دیتابیس
init_db()

waf_ns = api.namespace('waf', description='Main WAF endpoint')

@waf_ns.route('/')
class WAF(Resource):
    @api.doc(description="WAF endpoint for GET/POST requests")
    def get(self):
        return process_request()

    @api.doc(description="WAF endpoint for GET/POST requests")
    def post(self):
        return process_request()

def process_request():
    client_ip = request.remote_addr
    current_time = time.time()

    blocked_ips = get_blocked_ips()
    if client_ip in blocked_ips:
        if current_time < blocked_ips[client_ip]:
            response = make_response(render_template_string("""<html>
            <head><meta charset='UTF-8'><title>Access Denied</title></head>
            <body style='font-family: Arial; background-color: #fff0f0; padding: 2rem;'>
                <h2>⛔️ Access Denied</h2>
                <p>Your IP ({{ ip }}) is temporarily blocked due to suspicious activity.</p>
                <p>Please try again later.</p>
            </body>
            </html>""", ip=client_ip), 403)
            response.headers['Content-Type'] = 'text/html'
            return response
        else:
            unblock_ip(client_ip)

    params = request.args if request.method == 'GET' else request.form
    for key, value in params.items():
        if check_sql_injection(value):
            log_attack(client_ip, "SQLi", f"{key}={value}")
            block_ip(client_ip, BLOCK_DURATION)
            response = make_response(render_template_string("""
            <html>
            <head><meta charset='UTF-8'><title>Blocked</title></head>
            <body style='font-family: Arial; background-color: #fff0f0; padding: 2rem;'>
                <h2>🚫 Request Blocked</h2>
                <p>Malicious input was detected in your request.</p>
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
            <head><meta charset='UTF-8'><title>Blocked</title></head>
            <body style='font-family: Arial; background-color: #fff0f0; padding: 2rem;'>
                <h2>🚫 Request Blocked</h2>
                <p>Malicious input was detected in your request.</p>
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
            <head><meta charset='UTF-8'><title>Blocked</title></head>
            <body style='font-family: Arial; background-color: #fff0f0; padding: 2rem;'>
                <h2>🚫 Request Blocked</h2>
                <p>Malicious input was detected in your request.</p>
            </body>
            </html>
            """), 403)
            response.headers['Content-Type'] = 'text/html'
            return response
        if check_xss(value):
            log_attack(client_ip, "XSS", f"{key}={value}")
            block_ip(client_ip, BLOCK_DURATION)
            return render_template_string("""
            <html>
            <head><title>Blocked</title></head>
            <body style='font-family: Arial; background-color: #fff0f0; padding: 2rem;'>
                <h2>🚫 Request Blocked</h2>
                <p>Malicious input was detected in your request.</p>
            </body>
            </html>
        """), 403

    if request.data:
        raw = request.data.decode(errors='ignore')
        if check_sql_injection(raw):
            log_attack(client_ip, "SQLi", "raw body")
            block_ip(client_ip, BLOCK_DURATION)
            return render_template_string("""
            <html>
            <head><title>Blocked</title></head>
            <body style='font-family: Arial; background-color: #fff0f0; padding: 2rem;'>
                <h2>🚫 Request Blocked</h2>
                <p>Malicious content was detected in request body.</p>
            </body>
            </html>
        """), 403
        if check_xss(raw):
            log_attack(client_ip, "XSS", "raw body")
            block_ip(client_ip, BLOCK_DURATION)
            return {"message": "Blocked: Malicious raw body!"}, 403

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
            <head><title>Blocked</title></head>
            <body style='font-family: Arial; background-color: #fff0f0; padding: 2rem;'>
                <h2>🚫 Request Blocked</h2>
                <p>Malicious JSON content was detected in your request.</p>
            </body>
            </html>
        """), 403
                    if check_xss(value):
                        log_attack(client_ip, "XSS", f"json:{key}")
                        block_ip(client_ip, BLOCK_DURATION)
                        return {"message": "Blocked: Malicious JSON content!"}, 403

    for field_name, file in request.files.items():
        filename = file.filename
        if check_sql_injection(filename):
            log_attack(client_ip, "SQLi", f"filename:{filename}")
            block_ip(client_ip, BLOCK_DURATION)
            return render_template_string("""
            <html>
            <head><title>Blocked</title></head>
            <body style='font-family: Arial; background-color: #fff0f0; padding: 2rem;'>
                <h2>🚫 Request Blocked</h2>
                <p>Malicious filename was detected in uploaded file.</p>
            </body>
            </html>
        """), 403
        if check_xss(filename):
            log_attack(client_ip, "XSS", f"filename:{filename}")
            block_ip(client_ip, BLOCK_DURATION)
            return {"message": "Blocked: Malicious filename!"}, 403

    backend_url = "http://localhost:8000"
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

@api.route('/blocked-ips')
class BlockedIPs(Resource):
    @api.doc(description="View currently blocked IPs")
    def get(self):
        current_time = time.time()
        db_blocked = get_blocked_ips()
        result = {}
        for ip, expiry in db_blocked.items():
            remaining = int(expiry - current_time)
            if remaining > 0:
                result[ip] = f"{remaining} seconds"
        return result


@app.route('/blocked-ips/html')
def show_blocked_ips_html():
    current_time = time.time()
    db_blocked = get_blocked_ips()
    active_ips = []

    for ip, expiry in db_blocked.items():
        remaining = int(expiry - current_time)
        if remaining > 0:
            active_ips.append((ip, remaining))

    html_template = """
    <!DOCTYPE html>
    <html lang=\"en\">
    <head>
        <meta charset=\"UTF-8\">
        <title>Blocked IPs</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f7f7f7; padding: 2rem; }
            h1 { color: #cc0000; }
            table { border-collapse: collapse; width: 80%; background: white; }
            th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
            th { background-color: #cc0000; color: white; }
            tr:nth-child(even) { background-color: #f2f2f2; }
            a.button {
                padding: 6px 12px;
                background-color: #007bff;
                color: white;
                border-radius: 4px;
                text-decoration: none;
            }
            a.button:hover {
                background-color: #0056b3;
            }
        </style>
    </head>
    <body>
        <h1>⛔️ Blocked IP Addresses</h1>
        {% if active_ips %}
        <table>
            <tr>
                <th>IP Address</th>
                <th>Time Remaining</th>
                <th>Action</th>
            </tr>
            {% for ip, time_left in active_ips %}
            <tr>
                <td>{{ ip }}</td>
                <td>{{ time_left }} seconds</td>
                <td><a class=\"button\" href=\"/unblock/{{ ip }}\">Unblock</a></td>
            </tr>
            {% endfor %}
        </table>
        <form method=\"POST\" action=\"/blocked-ips/clear\" style=\"margin-top: 20px;\">
            <button type=\"submit\" style=\"padding: 8px 16px; background-color: #dc3545; color: white; border: none; border-radius: 4px;\">🗑 Clear All Blocked IPs</button>
        </form>
        {% else %}
        <p>✅ No IPs are currently blocked.</p>
        {% endif %}
    </body>
    </html>
    """
    return render_template_string(html_template, active_ips=active_ips)




@app.route('/attack-logs')
def get_attack_logs():
    conn = sqlite3.connect("waf.db")
    c = conn.cursor()
    c.execute("SELECT ip, attack_type, parameter, timestamp FROM attack_logs ORDER BY timestamp DESC")
    logs = c.fetchall()
    conn.close()
    result = []
    for ip, typ, param, ts in logs:
        result.append({
            "ip": ip,
            "type": typ,
            "parameter": param,
            "time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
        })
    return jsonify(result)

@app.route('/attack-logs/html')
def show_attack_logs_html():
    conn = sqlite3.connect("waf.db")
    c = conn.cursor()
    c.execute("SELECT ip, attack_type, parameter, timestamp FROM attack_logs ORDER BY timestamp DESC")
    logs = c.fetchall()
    conn.close()

    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Attack Logs</title>
        <style>
            body { font-family: Arial; background-color: #f9f9f9; padding: 20px; }
            h1 { color: #cc0000; }
            table { border-collapse: collapse; width: 100%; background: white; }
            th, td { border: 1px solid #ccc; padding: 8px; }
            th { background-color: #cc0000; color: white; }
        </style>
    </head>
    <body>
        <form method="POST" action="/attack-logs/clear" style="margin-bottom: 20px;">
            <button type="submit" style="padding: 8px 16px; background-color: #d9534f; color: white; border: none; border-radius: 4px;">🧹 Clear All Logs</button>
        </form>
        <table>
            <tr>
                <th>IP</th><th>Type</th><th>Parameter</th><th>Time</th>
            </tr>
            {% for log in logs %}
            <tr>
                <td>{{ log[0] }}</td>
                <td>{{ log[1] }}</td>
                <td>{{ log[2] }}</td>
                <td>{{ log[3] }}</td>
            </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """
    logs_fmt = [(ip, typ, param, time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))) for ip, typ, param, ts in logs]
    return render_template_string(html_template, logs=logs_fmt)

@app.route('/attack-logs/clear', methods=['POST'])
def clear_attack_logs():
    conn = sqlite3.connect("waf.db")
    c = conn.cursor()
    c.execute("DELETE FROM attack_logs")
    conn.commit()
    conn.close()
    return redirect(url_for('show_attack_logs_html'))


@app.route('/unblock/<ip>')
def unblock_ip_route(ip):
    unblock_ip(ip)
    return render_template_string("""
        <html>
        <head><title>IP Unblocked</title></head>
        <body style='font-family: Arial; background-color: #f0fff0; padding: 2rem;'>
            <h2>✅ IP {{ ip }} has been unblocked.</h2>
            <a href='/blocked-ips/html'>🔙 Back to Blocked IPs</a>
        </body>
        </html>
    """, ip=ip)


@app.route('/blocked-ips/clear', methods=['POST'])
def clear_blocked_ips():
    conn = sqlite3.connect("waf.db")
    c = conn.cursor()
    c.execute("DELETE FROM blocked_ips")
    conn.commit()
    conn.close()
    return redirect(url_for('show_blocked_ips_html'))


if __name__ == '__main__':
    app.run(debug=True, port=5000)
