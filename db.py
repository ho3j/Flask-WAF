import sqlite3
import time

# Path to the SQLite database file
DB_PATH = "waf.db"

def init_db():
    """
    Initialize the SQLite database and create tables if they don't exist.
    Tables: blocked_ips, attack_logs, rules
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
        attack_type (str): Type of attack (e.g., SQLi, XSS)
        parameter (str): Malicious input parameter
    """
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
        attack_type (str): Type of attack (e.g., SQLi, XSS)
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