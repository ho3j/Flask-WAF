# 🔐 Flask WAF (Web Application Firewall)

A lightweight, extensible Web Application Firewall (WAF) built with Python and Flask. This project provides robust protection against common web attacks, including SQL Injection (SQLi), Cross-Site Scripting (XSS), Command Injection, Path Traversal, and Cross-Site Request Forgery (CSRF). It features IP blocking, attack logging, a user-friendly HTML-based admin panel, and dynamic rule management. The WAF forwards safe requests to a backend server and includes comprehensive testing with `pytest`.

---

## 🧩 Project Structure

| File / Folder        | Description |
|----------------------|-------------|
| `app.py`             | Main WAF application with `/waf/` route, IP blocking, logging, request forwarding, and admin endpoints for dashboard, logs, and rule management |
| `backend.py`         | Simulated backend server running on port 8888 to test WAF request forwarding |
| `waf_utils.py`       | Functions for detecting attacks (SQLi, XSS, Command Injection, Path Traversal, CSRF) using regex and database rules |
| `waf_patterns.py`    | Regex patterns for detecting various attacks (imported by `waf_utils.py`) |
| `db.py`              | SQLite database helpers for initializing tables, managing blocked IPs, logging attacks, and storing dynamic rules |
| `config.py`          | Configuration for logging, including file and console output settings |
| `waf.db`             | SQLite database file (should be excluded via `.gitignore`) |
| `test_waf.py`        | Test suite using `pytest` to validate WAF functionality |
| `README.md`          | Project documentation (this file) |

---

## 🚀 Getting Started

### Prerequisites
To run the Flask-WAF project, ensure you have the following installed:
- **Python 3.8+**: Download from [python.org](https://www.python.org/downloads/).
- **pip**: Python package manager (included with Python).
- **Redis** (optional): For rate limiting. Install via:
  - Linux: `sudo apt-get install redis-server`
  - Windows: Use [Redis for Windows](https://github.com/microsoftarchive/redis) or Docker.
  - macOS: `brew install redis`
- A web browser (e.g., Chrome, Firefox) for accessing the admin panel.

### Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/ho3j/flask-waf.git
   cd flask-waf
   ```

2. **Create a Virtual Environment** (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   Create a `requirements.txt` file with the following content:
   ```
   Flask==2.3.2
   Flask-RESTx==1.1.0
   requests==2.31.0
   Flask-Limiter==3.5.0
   redis==5.0.1
   ```
   Then install:
   ```bash
   pip install -r requirements.txt
   ```

4. **Start the Backend Server**:
   The backend server runs on port 8888 and simulates a target application.
   ```bash
   python backend.py
   ```

5. **Start the WAF**:
   The WAF runs on port 5000 and intercepts requests to `/waf/`.
   ```bash
   python app.py
   ```

6. **Access the Admin Panel**:
   Open a browser and navigate to:
   - Dashboard: `http://localhost:5000/dashboard`
   - Blocked IPs: `http://localhost:5000/blocked-ips/html`
   - Attack Logs: `http://localhost:5000/attack-logs/html`
   - Rule Management: `http://localhost:5000/rules/html`
   - API Docs: `http://localhost:5000/docs`

---

## 🧪 Running Tests

The project includes a test suite using `pytest` to validate WAF functionality.

1. **Install pytest**:
   ```bash
   pip install pytest
   ```

2. **Run Tests**:
   ```bash
   python -m pytest test_waf.py -v
   ```
   The tests cover:
   - Safe GET and POST requests
   - Detection of SQLi and XSS attacks
   - Request forwarding to the backend

---

## 📋 Useful Routes

| Route                   | Description |
|-------------------------|-------------|
| `/waf/`                 | Main WAF-protected endpoint for filtering incoming requests |
| `/dashboard`            | Dashboard displaying attack statistics, recent logs, and a 7-day attack chart |
| `/blocked-ips/html`     | View currently blocked IPs with options to unblock or clear all |
| `/attack-logs/html`     | View logged attacks with filtering by type, time range, and IP |
| `/rules/html`           | Manage detection rules (add, view, delete) |
| `/docs`                 | Swagger-based API documentation for WAF endpoints |

---

## 🔒 Features

- **Attack Detection**:
  - **SQL Injection (SQLi)**: Detects malicious SQL queries (e.g., `OR 1=1`, `UNION SELECT`).
  - **Cross-Site Scripting (XSS)**: Identifies script injections (e.g., `<script>alert('xss')</script>`).
  - **Command Injection**: Blocks attempts to execute system commands (e.g., `;whoami`).
  - **Path Traversal**: Prevents unauthorized file access (e.g., `../../etc/passwd`).
  - **Cross-Site Request Forgery (CSRF)**: Validates POST requests for CSRF tokens and valid headers.

- **IP Blocking**:
  - Automatically blocks IPs that send malicious requests.
  - Configurable block duration (default: 5 minutes).
  - Auto-unblock after expiration.
  - Admin panel to view, unblock, or clear blocked IPs.

- **Attack Logging**:
  - Stores attack details (IP, type, parameter, timestamp) in a SQLite database.
  - Admin panel with filtering options to view logs.

- **Dynamic Rule Management**:
  - Add, view, and delete custom regex-based detection rules via the admin panel.
  - Supports multiple attack types and actions (block or log).

- **Request Forwarding**:
  - Forwards safe requests to a backend server (default: `http://localhost:8888`).
  - Preserves headers and parameters.

- **Rate Limiting**:
  - Uses Redis to limit requests per IP (default: 100 requests per minute).
  - Blocks IPs exceeding the limit with a 429 response.

- **Admin Panel**:
  - HTML-based interface with Bootstrap for a modern, responsive design.
  - Includes a dashboard, blocked IPs list, attack logs, and rule management.

- **Testing**:
  - Comprehensive `pytest` suite to validate attack detection and request handling.

---

## 🛠 Usage Examples

### 1. Testing Attack Detection
Send malicious requests to `/waf/` to test detection:
```bash
# SQL Injection
curl "http://localhost:5000/waf/?query=OR%201=1"

# XSS
curl "http://localhost:5000/waf/?q=%3Cscript%3Ealert('xss')%3C/script%3E"

# Command Injection
curl "http://localhost:5000/waf/?cmd=%3Bwhoami"

# Path Traversal
curl "http://localhost:5000/waf/?path=../../../etc/passwd"

# CSRF (POST without token)
curl -X POST "http://localhost:5000/waf/" -d "test=value"
```
Each request should return a 403 response, log the attack, and block the IP.

### 2. Adding a Custom Rule
1. Go to `http://localhost:5000/rules/html`.
2. Add a rule, e.g.:
   - **Pattern**: `\bwhoami\b`
   - **Attack Type**: `CommandInjection`
   - **Description**: `Detects whoami command execution attempt`
   - **Action**: `block`
3. Test the rule:
   ```bash
   curl "http://localhost:5000/waf/?cmd=whoami"
   ```
   Expect a 403 response and a log entry.

### 3. Viewing Attack Logs
1. Go to `http://localhost:5000/attack-logs/html`.
2. Use filters to view specific attacks:
   - **Attack Type**: Select `SQLi`, `XSS`, etc.
   - **Time Range**: Choose `Last 24 Hours` or `Last 7 Days`.
   - **IP**: Search for a specific IP (e.g., `127.0.0.1`).

### 4. Managing Blocked IPs
1. Go to `http://localhost:5000/blocked-ips/html`.
2. View blocked IPs and remaining block time.
3. Click "Unblock" to remove an IP or "Clear All IPs" to unblock all.

---

## 🧑‍💻 Development

### Adding New Attack Types
To add a new attack type (e.g., `Custom`):
1. In `waf_utils.py`, add a new detection function (e.g., `check_custom`).
2. Update `app.py` to check for the new attack type in `process_request`.
3. Add the new type to the dropdown in `/rules/html`.

### Extending Tests
Add new test cases to `test_waf.py` for custom rules or attack types:
```python
def test_custom_rule(client):
    client.post('/rules/html', data={
        'pattern': r'\btest\b',
        'attack_type': 'Custom',
        'description': 'Detect test keyword',
        'action': 'block'
    })
    response = client.get('/waf/?query=test')
    assert response.status_code == 403
```

---

## 🔍 Troubleshooting

- **Redis Connection Error**:
  - Ensure Redis is running (`redis-cli ping` should return `PONG`).
  - If unavailable, disable Redis in `app.py` by setting `redis_client = None`.

- **Database Issues**:
  - Check if `waf.db` exists in the project directory.
  - Verify SQLite is installed (`pip install pysqlite3` if needed).

- **UI Not Displaying Correctly**:
  - Ensure the Vazir font CDN (`https://cdn.fontcdn.ir/Vazir`) is accessible.
  - Clear browser cache or use a different browser.

- **Tests Failing**:
  - Ensure the backend server (`python backend.py`) is running on port 8888.
  - Check that all dependencies are installed (`pip install -r requirements.txt`).

For additional help, contact the author or open an issue on the [GitHub repository](https://github.com/ho3j/flask-waf).

---

## 👨‍💻 Author

Created by [Hossein Jalili](https://github.com/ho3j)

---

## 📝 License

MIT License - Free to use and modify.