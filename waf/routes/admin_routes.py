from flask import request, render_template, redirect, url_for, session, flash
from waf.db import get_blocked_ips, unblock_ip, log_attack, add_rule, get_rules, delete_rule, update_setting, get_all_settings, get_setting
import sqlite3
from datetime import datetime, timedelta
import time
from waf.config import DB_PATH, clean_old_logs, get_logs_size

def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def init_admin_routes(app):
    @app.route('/dashboard')
    @login_required
    def dashboard():
        current_time = time.time()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM attack_logs")
        total_attacks = c.fetchone()[0]
        c.execute("SELECT attack_type, COUNT(*) FROM attack_logs GROUP BY attack_type")
        attack_counts = dict(c.fetchall())
        c.execute("SELECT ip, attack_type, parameter, timestamp FROM attack_logs ORDER BY timestamp DESC LIMIT 5")
        recent_attacks = [
            {'ip': r[0], 'attack_type': r[1], 'parameter': r[2], 'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r[3]))}
            for r in c.fetchall()
        ]
        db_blocked = get_blocked_ips()
        active_blocks = sum(1 for ip, expiry in db_blocked.items() if expiry > current_time)
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
        return render_template('dashboard.html', 
                             total_attacks=total_attacks, 
                             active_blocks=active_blocks, 
                             attack_counts=attack_counts, 
                             recent_attacks=recent_attacks, 
                             chart_labels=chart_labels, 
                             chart_values=chart_values)

    @app.route('/blocked-ips/html')
    @login_required
    def show_blocked_ips_html():
        current_time = time.time()
        db_blocked = get_blocked_ips()
        active_ips = []
        for ip, expiry in db_blocked.items():
            remaining = int(expiry - current_time)
            if remaining > 0:
                active_ips.append((ip, remaining))
        return render_template('blocked_ips.html', active_ips=active_ips)

    @app.route('/attack-logs/html', methods=['GET', 'POST'])
    @login_required
    def show_attack_logs_html():
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
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
        return render_template('attack_logs.html', 
                             logs=logs_fmt, 
                             attack_type=attack_type, 
                             time_filter=time_filter, 
                             search_ip=search_ip)

    @app.route('/rules/html', methods=['GET', 'POST'])
    @login_required
    def manage_rules_html():
        if request.method == 'POST':
            pattern = request.form.get('pattern')
            attack_type = request.form.get('attack_type')
            description = request.form.get('description')
            action = request.form.get('action', 'block')
            if pattern and attack_type:
                add_rule(pattern, attack_type, description, action)
                return redirect(url_for('manage_rules_html'))
        rules = get_rules()
        return render_template('rules.html', rules=rules)

    @app.route('/settings/html', methods=['GET', 'POST'])
    @login_required
    def manage_settings_html():
        if request.method == 'POST':
            settings = get_all_settings()
            for setting in settings:
                key = setting['key']
                if key == 'learning_mode' and request.form.get(key) == 'on':
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
        return render_template('settings.html', 
                             settings=settings, 
                             learning_mode_remaining=learning_mode_remaining)

    @app.route('/logs-management/html', methods=['GET', 'POST'])
    @login_required
    def manage_logs_html():
        if request.method == 'POST' and 'cleanup' in request.form:
            max_age_days = int(request.form.get('max_age_days', 30))
            deleted_files, freed_space = clean_old_logs(max_age_days)
            flash(f"Cleaned {deleted_files} log files, freed {freed_space:.2f} MB", 'success')
        total_size_mb, log_files = get_logs_size()
        warning_threshold = 100
        is_warning = total_size_mb > warning_threshold
        return render_template('logs_management.html', 
                             total_size_mb=total_size_mb, 
                             log_files=log_files, 
                             is_warning=is_warning, 
                             warning_threshold=warning_threshold)

    @app.route('/about-developer/html')
    @login_required
    def about_developer_html():
        return render_template('about_developer.html')

    @app.route('/rules/delete/<int:rule_id>')
    @login_required
    def delete_rule_route(rule_id):
        delete_rule(rule_id)
        return redirect(url_for('manage_rules_html'))

    @app.route('/attack-logs/clear', methods=['POST'])
    @login_required
    def clear_attack_logs():
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM attack_logs")
        conn.commit()
        conn.close()
        return redirect(url_for('show_attack_logs_html'))

    @app.route('/unblock/<ip>')
    @login_required
    def unblock_ip_route(ip):
        unblock_ip(ip)
        return render_template('unblock_ip.html', ip=ip)

    @app.route('/blocked-ips/clear', methods=['POST'])
    @login_required
    def clear_blocked_ips():
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM blocked_ips")
        conn.commit()
        conn.close()
        return redirect(url_for('show_blocked_ips_html'))