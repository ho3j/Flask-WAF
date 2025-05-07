from flask import request, render_template_string, redirect, url_for, session, flash
from waf.db import get_blocked_ips, unblock_ip, log_attack, add_rule, get_rules, delete_rule, update_setting, get_all_settings, get_setting
import sqlite3
from datetime import datetime, timedelta
import time
from waf.config import DB_PATH, clean_old_logs, get_logs_size


def login_required(f):
    """
    Decorator to ensure user is logged in before accessing a route.
    """
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def init_admin_routes(app):
    """
    Initialize admin routes for the Flask app.
    
    Args:
        app: Flask application instance
    """
    @app.route('/dashboard')
    @login_required
    def dashboard():
        """
        Display the WAF dashboard with attack statistics and recent logs.
        
        Returns:
            Rendered HTML template for the dashboard
        """
        current_time = time.time()
        conn = sqlite3.connect(DB_PATH)
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
        conn = sqlite3.connect(DB_PATH)
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
        conn = sqlite3.connect(DB_PATH)
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
                if key == 'learning_mode' and request.form.get(key) == 'on':
                    # Set learning mode expiry to 7 days from now
                    expiry = time.time() + 7 * 24 * 3600
                    value = 1
                    update_setting(key, value, expiry)
                elif key == 'learning_mode':
                    update_setting(key, 0, None)
                elif key in ['block_duration', 'request_limit', 'request_window']:
                    value = int(request.form.get(key, 0))
                    update_setting(key, value)
                else:
                    value = 1 if request.form.get(key) == 'on' else 0
                    update_setting(key, value)
            return redirect(url_for('manage_settings_html'))
        
        settings = get_all_settings()
        current_time = time.time()
        learning_mode_expiry = None
        learning_mode_remaining = None
        for setting in settings:
            if setting['key'] == 'learning_mode' and setting['value'] == 1 and setting['learning_mode_expiry']:
                learning_mode_expiry = setting['learning_mode_expiry']
                remaining_seconds = max(0, int(learning_mode_expiry - current_time))
                days = remaining_seconds // (24 * 3600)
                hours = (remaining_seconds % (24 * 3600)) // 3600
                learning_mode_remaining = f"{days} days, {hours} hours"
        
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
                .expiry-info { color: #666; font-size: 0.9rem; }
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
                                <td>
                                    {{ setting.description }}
                                    {% if setting.key == 'learning_mode' and learning_mode_remaining %}
                                        <br><span class="expiry-info">Expires in: {{ learning_mode_remaining }}</span>
                                    {% endif %}
                                </td>
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
        return render_template_string(html_template, settings=settings, learning_mode_remaining=learning_mode_remaining)

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
        conn = sqlite3.connect(DB_PATH)
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
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM blocked_ips")
        conn.commit()
        conn.close()
        return redirect(url_for('show_blocked_ips_html'))
    
    @app.route('/logs-management/html', methods=['GET', 'POST'])
    @login_required
    def manage_logs_html():
        """
        Display a page for managing log files (size monitoring and cleanup).
        """
        # Handle manual cleanup
        if request.method == 'POST' and 'cleanup' in request.form:
            max_age_days = int(request.form.get('max_age_days', 30))
            deleted_files, freed_space = clean_old_logs(max_age_days)
            flash(f"Cleaned {deleted_files} log files, freed {freed_space:.2f} MB", 'success')

        # Get log size info
        total_size_mb, log_files = get_logs_size()
        warning_threshold = 100  # MB
        is_warning = total_size_mb > warning_threshold

        html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Log Management</title>
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
                .alert-warning { background-color: #fff3cd; color: #856404; }
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
                <h1 class="my-4">📂 Log Management</h1>
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }}">{{ message }}</div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                <div class="card mb-4">
                    <div class="card-header">Log Files Size</div>
                    <div class="card-body">
                        <p>Total Size: <strong>{{ total_size_mb | round(2) }} MB</strong></p>
                        {% if is_warning %}
                            <p class="alert alert-warning">⚠️ Log files are using more than {{ warning_threshold }} MB!</p>
                        {% endif %}
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>File Name</th>
                                    <th>Size (MB)</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for file_name, file_size in log_files %}
                                <tr>
                                    <td>{{ file_name }}</td>
                                    <td>{{ file_size | round(2) }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
                <div class="card mb-4">
                    <div class="card-header">Clean Old Logs</div>
                    <div class="card-body">
                        <form method="POST">
                            <div class="mb-3">
                                <label for="max_age_days" class="form-label">Maximum Age (days)</label>
                                <input type="number" name="max_age_days" class="form-control" value="30" min="1">
                            </div>
                            <button type="submit" name="cleanup" class="btn btn-danger">🧹 Clean Old Logs</button>
                        </form>
                    </div>
                </div>
                <a href="/dashboard" class="btn btn-secondary">🔙 Back to Dashboard</a>
            </div>
        </body>
        </html>
        """
        return render_template_string(html_template, 
                                     total_size_mb=total_size_mb, 
                                     log_files=log_files, 
                                     is_warning=is_warning, 
                                     warning_threshold=warning_threshold)