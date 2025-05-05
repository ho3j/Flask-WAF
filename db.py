import sqlite3
import time
import bcrypt

# Path to the SQLite database file
DB_PATH = "waf.db"

def init_db():
    """
    Initialize the SQLite database and create tables if they don't exist.
    Tables: blocked_ips, attack_logs, rules, settings, users
    """
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        # Table for blocked IPs
        c.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                expiry REAL
            )
        ''')
        # Table for attack logs
        c.execute('''
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                attack_type TEXT,
                parameter TEXT,
                timestamp REAL
            )
        ''')
        # Table for detection rules
        c.execute('''
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                description TEXT,
                action TEXT DEFAULT 'block',
                created_at REAL
            )
        ''')
        # Table for WAF settings
        c.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL,
                description TEXT,
                updated_at REAL
            )
        ''')
        # Table for users
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        ''')
        # Initialize default settings
        default_settings = [
            ('sql_injection_detection', 1, 'Enable SQL Injection detection', time.time()),
            ('xss_detection', 1, 'Enable XSS detection', time.time()),
            ('command_injection_detection', 1, 'Enable Command Injection detection', time.time()),
            ('path_traversal_detection', 1, 'Enable Path Traversal detection', time.time()),
            ('csrf_detection', 1, 'Enable CSRF detection', time.time()),
            ('lfi_detection', 1, 'Enable Local File Inclusion detection', time.time()),
            ('rate_limiting', 1, 'Enable rate limiting with Redis', time.time()),
            ('forward_to_backend', 1, 'Enable forwarding safe requests to backend', time.time()),
            ('attack_logging', 1, 'Enable logging of detected attacks', time.time()),
            ('block_duration', 300, 'Duration of IP block in seconds', time.time()),
            ('request_limit', 100, 'Maximum requests per minute for rate limiting', time.time()),
            ('request_window', 60, 'Time window in seconds for rate limiting', time.time()),
            ('learning_mode', 0, 'Enable Learning Mode (log attacks without blocking)', time.time())
        ]
        c.executemany('''
            INSERT OR IGNORE INTO settings (key, value, description, updated_at)
            VALUES (?, ?, ?, ?)
        ''', default_settings)
        # Initialize default user (admin:admin)
        admin_password = bcrypt.hashpw('admin'.encode('utf-8'), bcrypt.gensalt())
        c.execute('''
            INSERT OR IGNORE INTO users (username, password)
            VALUES (?, ?)
        ''', ('admin', admin_password.decode('utf-8')))
        conn.commit()

def block_ip(ip, duration_seconds):
    """
    Add or update a blocked IP with an expiration time.
    
    Args:
        ip (str): IP address to block
        duration_seconds (int): Duration of the block in seconds
    """
    expiry = time.time() + duration_seconds
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("REPLACE INTO blocked_ips (ip, expiry) VALUES (?, ?)", (ip, expiry))
        conn.commit()

def get_blocked_ips():
    """
    Retrieve all blocked IPs from the database.
    
    Returns:
        dict: Dictionary mapping IPs to their expiration times
    """
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT ip, expiry FROM blocked_ips")
        return dict(c.fetchall())

def unblock_ip(ip):
    """
    Remove an IP from the blocked IPs list.
    
    Args:
        ip (str): IP address to unblock
    """
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        conn.commit()

def log_attack(ip, attack_type, parameter):
    """
    Log a detected attack to the database.
    
    Args:
        ip (str): IP address of the attacker
        attack_type (str): Type of attack (e.g., SQLi, XSS, LFI)
        parameter (str): Malicious input parameter
    """
    if not get_setting('attack_logging'):
        return
    timestamp = time.time()
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO attack_logs (ip, attack_type, parameter, timestamp)
            VALUES (?, ?, ?, ?)
        """, (ip, attack_type, parameter, timestamp))
        conn.commit()

def add_rule(pattern, attack_type, description, action='block'):
    """
    Add a new detection rule to the database.
    
    Args:
        pattern (str): Regex pattern for detection
        attack_type (str): Type of attack (e.g., SQLi, XSS, LFI)
        description (str): Description of the rule
        action (str): Action to take (default: 'block')
    """
    timestamp = time.time()
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO rules (pattern, attack_type, description, action, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (pattern, attack_type, description, action, timestamp))
        conn.commit()

def get_rules():
    """
    Retrieve all detection rules from the database.
    
    Returns:
        list: List of dictionaries containing rule details
    """
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT id, pattern, attack_type, description, action, created_at FROM rules")
        return [{'id': r[0], 'pattern': r[1], 'attack_type': r[2], 'description': r[3], 'action': r[4], 'created_at': r[5]} for r in c.fetchall()]

def delete_rule(rule_id):
    """
    Delete a detection rule from the database.
    
    Args:
        rule_id (int): ID of the rule to delete
    """
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
        conn.commit()

def update_setting(key, value):
    """
    Update a setting in the database.
    
    Args:
        key (str): Setting key (e.g., sql_injection_detection, block_duration)
        value (int): Value for the setting (1/0 for boolean, number for durations/limits)
    """
    timestamp = time.time()
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            UPDATE settings SET value = ?, updated_at = ?
            WHERE key = ?
        """, (value, timestamp, key))
        conn.commit()

def get_setting(key):
    """
    Retrieve a setting value from the database.
    
    Args:
        key (str): Setting key
        
    Returns:
        int: Setting value (1/0 for boolean settings, number for durations/limits) or 0 if not found
    """
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = ?", (key,))
        result = c.fetchone()
        return result[0] if result else 0

def get_all_settings():
    """
    Retrieve all settings from the database.
    
    Returns:
        list: List of dictionaries containing setting details
    """
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT key, value, description, updated_at FROM settings")
        return [{'key': r[0], 'value': r[1], 'description': r[2], 'updated_at': r[3]} for r in c.fetchall()]

def get_user(username):
    """
    Retrieve a user from the database by username.
    
    Args:
        username (str): Username to look up
        
    Returns:
        dict: User details (id, username, password) or None if not found
    """
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        if result:
            return {'id': result[0], 'username': result[1], 'password': result[2]}
        return None