# 🔐 Flask WAF (Web Application Firewall)

A lightweight Web Application Firewall built with Python and Flask. It detects and blocks basic SQL Injection and XSS attacks, logs them, and supports IP blocking with an HTML-based admin panel.

---

## 🧩 Project Structure

| File / Folder        | Description |
|----------------------|-------------|
| `app.py`             | Main WAF app with `/waf/` route, IP blocking, logging, forwarding, and admin endpoints |
| `backend.py`         | Simulated backend server to test forwarding from WAF |
| `waf_utils.py`       | Regex-based detection functions for SQLi and XSS |
| `waf_patterns.py`    | Contains regex patterns used for detecting SQLi and XSS (imported in `waf_utils.py`) |
| `db.py`              | SQLite DB helpers: initialization, logging, blocking, etc. |
| `config.py`          | Configuration values like block duration, DB path, etc. |
| `waf.db`             | SQLite DB file (should be excluded via `.gitignore`) |
| `test_waf.py`        | Test suite using `pytest` for WAF logic |
| `README.md`          | This file |

---

## 🚀 Getting Started

### 1. Start Backend (port 8000)
```bash
python backend.py
```

### 2. Start WAF (port 5000)
```bash
python app.py
```

---

## 🧪 Run Tests

```bash
python -m pytest test_waf.py -v
```

---

## 📋 Useful Routes

| Route                   | Description |
|-------------------------|-------------|
| `/waf/`                 | Main WAF-protected endpoint |
| `/blocked-ips/html`     | View blocked IPs (with unblock & clear buttons) |
| `/attack-logs/html`     | View logged attacks (with clear button) |
| `/docs`                 | Swagger-based API documentation |

---

## 🔒 Features

- Regex-based SQLi and XSS detection
- IP blocking with auto-unblock after timeout
- HTML admin panels for logs and blocks
- SQLite storage for persistence
- Request forwarding to real backend
- Rate limiting using `Flask-Limiter`
- Full testing with `pytest`

---

## 👨‍💻 Author

Created by [Hossein Jalili](https://github.com/ho3j)

---

## 📝 License

MIT License - Free to use and modify.
