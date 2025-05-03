import sqlite3
import time

DB_PATH = "waf.db"

# اتصال به دیتابیس و ساخت جدول‌ها اگر وجود ندارند
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        # جدول IPهای بلاک‌شده
        c.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                expiry REAL
            )
        ''')
        # جدول لاگ حملات
        c.execute('''
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                attack_type TEXT,
                parameter TEXT,
                timestamp REAL
            )
        ''')
        conn.commit()

# افزودن یا به‌روزرسانی IP بلاک‌شده
def block_ip(ip, duration_seconds):
    expiry = time.time() + duration_seconds
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("REPLACE INTO blocked_ips (ip, expiry) VALUES (?, ?)", (ip, expiry))
        conn.commit()

# بارگذاری IPهای بلاک‌شده از دیتابیس
def get_blocked_ips():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT ip, expiry FROM blocked_ips")
        return dict(c.fetchall())

# حذف IP از لیست بلاک‌شده
def unblock_ip(ip):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        conn.commit()

# ثبت یک حمله جدید
def log_attack(ip, attack_type, parameter):
    timestamp = time.time()
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO attack_logs (ip, attack_type, parameter, timestamp)
            VALUES (?, ?, ?, ?)
        """, (ip, attack_type, parameter, timestamp))
        conn.commit()
