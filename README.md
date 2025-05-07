# 🔐 Flask WAF (Web Application Firewall)

A lightweight, extensible Web Application Firewall (WAF) built with Python and Flask. This project provides robust protection against common web attacks, including SQL Injection (SQLi), Cross-Site Scripting (XSS), Command Injection, Path Traversal, Local File Inclusion (LFI), and Cross-Site Request Forgery (CSRF). It features IP blocking, attack logging, a user-friendly HTML-based admin panel, dynamic rule management, a learning mode for monitoring without blocking, and comprehensive testing with `pytest`. The WAF intercepts and filters requests to a backend server, ensuring only safe requests are forwarded.

---

## 🧩 Project Structure

| File / Folder                  | Description |
|--------------------------------|-------------|
| `backend.py`                   | Simulated backend server running on port 8888 to test WAF request forwarding |
| `waf/main.py`                  | Main WAF application entry point, initializing Flask and RESTx API |
| `waf/db.py`                    | SQLite database helpers for initializing tables, managing blocked IPs, logging attacks, and storing rules |
| `waf/config.py`                | Configuration for database path and logging (file output in `logs/waf.log`) |
| `waf/waf_utils.py`             | Functions for detecting attacks (SQLi, XSS, Command Injection, Path Traversal, LFI, CSRF) |
| `waf/waf_patterns.py`          | Regex patterns for detecting various attacks |
| `waf/routes/waf_routes.py`     | Main WAF endpoint (`/waf/`) for filtering requests and IP blocking |
| `waf/routes/admin_routes.py`   | Admin panel routes for dashboard, logs, blocked IPs, rules, settings, and log management |
| `waf/routes/auth_routes.py`    | Authentication routes for login and logout |
| `tests/test_waf.py`            | Comprehensive test suite using `pytest` to validate WAF functionality |
| `tests/test_log_rotation.py`   | Tests for log rotation and cleanup functionality |
| `requirements.txt`             | Project dependencies |
| `db/waf.db`                    | SQLite database file (generated at runtime, excluded via `.gitignore`) |
| `logs/waf.log`                 | Log file for WAF activities |
| `res/logo.png`                 | Logo for admin panel UI |
| `templates/*.html`             | HTML templates for admin panel, error pages, and safe request responses |
| `static/images/developer.png`  | Image for the "About Developer" page |

---

## 🚀 Getting Started

### Prerequisites
To run the Flask-WAF project, ensure you have the following installed:
- **Python 3.8+**: Download from [python.org](https://www.python.org/downloads/).
- **pip**: Python package manager (included with Python).
- A web browser (e.g., Chrome, Firefox) for accessing the admin panel.

**Note**: Redis is not required as rate limiting is not currently implemented.

### Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/ho3j/flask-waf.git
   cd flask-waf
   ```

2. **Create a Virtual Environment** (recommended):
   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # Linux/macOS
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   Ensure `requirements.txt` contains:
   ```
   flask==2.3.2
   flask-restx==1.1.0
   requests==2.31.0
   bcrypt==4.0.1
   pytest==8.3.5
   ```
   Then install:
   ```bash
   pip install -r requirements.txt
   ```

4. **Create Log and Database Directories** (if not exist):
   ```bash
   # Windows
   mkdir logs db
   # Linux/macOS
   mkdir -p logs db
   ```

5. **Start the Backend Server**:
   The backend server simulates a target application on port 8888.
   ```bash
   python backend.py
   ```

6. **Start the WAF**:
   The WAF runs on port 5000 and intercepts requests to `/waf/`.
   ```bash
   python waf/main.py
   ```

7. **Access the Admin Panel**:
   Open a browser and navigate to:
   - Login: `http://localhost:5000/login` (default credentials: `admin`/`admin`)
   - Dashboard: `http://localhost:5000/dashboard`
   - Blocked IPs: `http://localhost:5000/blocked-ips/html`
   - Attack Logs: `http://localhost:5000/attack-logs/html`
   - Rule Management: `http://localhost:5000/rules/html`
   - Settings: `http://localhost:5000/settings/html`
   - Log Management: `http://localhost:5000/logs-management/html`
   - About Developer: `http://localhost:5000/about-developer/html`
   - API Docs: `http://localhost:5000/docs`

---

## 🧪 Running Tests

The project includes a comprehensive test suite using `pytest` to validate WAF functionality.

1. **Install pytest** (if not already installed):
   ```bash
   pip install pytest
   ```

2. **Ensure Backend is Running** (for forwarding tests):
   Start the backend server on port 8888:
   ```bash
   python backend.py
   ```

3. **Run Tests**:
   ```bash
   # Windows
   set PYTHONPATH=.
   python -m pytest tests/test_waf.py -v
   # Linux/macOS
   export PYTHONPATH=.
   python -m pytest tests/test_waf.py -v
   ```
   The test suite covers:
   - Safe GET/POST requests with and without backend forwarding
   - Detection of SQLi, XSS, Command Injection, Path Traversal, LFI, and CSRF attacks
   - JSON payload and file upload attack detection
   - IP blocking and unblocking
   - Authentication (login, logout, invalid credentials)
   - Admin panel route rendering (dashboard, blocked IPs, logs, rules, settings)
   - Non-API path handling with `safe_but_disabled.html`

---

## 📋 Useful Routes

| Route                        | Description |
|------------------------------|-------------|
| `/waf/`                      | Main WAF-protected endpoint for filtering incoming requests |
| `/login`                     | Login page for admin panel (default: `admin`/`admin`) |
| `/logout`                    | Log out the current user |
| `/dashboard`                 | Dashboard with attack statistics, recent logs, and a 7-day attack chart |
| `/blocked-ips/html`          | View and manage blocked IPs (unblock or clear all) |
| `/attack-logs/html`          | View and filter attack logs by type, time, or IP |
| `/rules/html`                | Add, view, or delete custom detection rules |
| `/settings/html`             | Enable/disable WAF features and configure settings (e.g., block duration, learning mode) |
| `/logs-management/html`      | Manage log files (clean up old logs and view log size) |
| `/about-developer/html`      | Information about the developer |
| `/docs`                      | Swagger-based API documentation for WAF endpoints |

---

## 🔒 Features

- **Attack Detection**:
  - **SQL Injection (SQLi)**: Blocks malicious SQL queries (e.g., `OR 1=1`, `UNION SELECT`).
  - **Cross-Site Scripting (XSS)**: Detects script injections (e.g., `<script>alert('xss')</script>`).
  - **Command Injection**: Prevents system command execution (e.g., `;whoami`).
  - **Path Traversal**: Blocks unauthorized file access (e.g., `../../etc/passwd`).
  - **Local File Inclusion (LFI)**: Detects attempts to include local files (e.g., `/etc/passwd`).
  - **Cross-Site Request Forgery (CSRF)**: Validates POST requests for CSRF tokens and headers.
  - **JSON Payloads**: Checks JSON data for malicious content.
  - **File Uploads**: Scans uploaded file names for attack patterns.

- **Learning Mode**:
  - Monitors attacks without blocking (logs only).
  - Configurable via `/settings/html` with a 7-day expiry.
  - Ideal for analyzing traffic before enabling full blocking.

- **IP Blocking**:
  - Automatically blocks IPs sending malicious requests (default: 5 minutes).
  - Configurable block duration via `/settings/html`.
  - Auto-unblock after expiration.
  - Admin panel to view, unblock, or clear blocked IPs.

- **Attack Logging**:
  - Logs attack details (IP, type, parameter, timestamp) to SQLite database.
  - Filterable logs in admin panel by attack type, time range, or IP.

- **Dynamic Rule Management**:
  - Add, view, or delete custom regex-based rules via `/rules/html`.
  - Supports multiple attack types (SQLi, XSS, etc.) and actions (block or log).

- **Request Forwarding**:
  - Forwards safe requests to the backend (`http://localhost:8888`) if `forward_to_backend` is enabled.
  - Displays `safe_request.html` for safe API requests when forwarding is disabled.
  - Displays `safe_but_disabled.html` for non-API paths when `FORWARDING_ENABLED` is disabled.
  - Preserves headers and parameters.

- **Admin Panel**:
  - Responsive HTML interface with Bootstrap and Poppins font.
  - Features dashboard, blocked IPs, attack logs, rule management, settings, log management, and developer info.
  - Authentication with username/password (bcrypt-secured).

- **Optimized Performance**:
  - Database queries optimized with indexing and caching for `get_blocked_ips()` (response time ~19ms for safe requests).
  - Efficient attack detection using regex patterns.

- **Testing**:
  - Comprehensive `pytest` suite covering attack detection, request forwarding, IP blocking, authentication, and admin panel routes.
  - Tests for `safe_request.html` and `safe_but_disabled.html` rendering.

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

# LFI
curl "http://localhost:5000/waf/?file=/etc/passwd"

# CSRF (POST without token)
curl -X POST "http://localhost:5000/waf/" -d "test=value"

# JSON Payload
curl -X POST "http://localhost:5000/waf/" -H "Content-Type: application/json" -d '{"msg": "<script>alert(\"xss\")</script>", "csrf_token": "dummy"}'

# File Upload
curl -X POST "http://localhost:5000/waf/" -F "file=@test.txt;filename=../../etc/passwd" -F "csrf_token=dummy"
```
Each request should return a 403 response, log the attack, and block the IP (unless in Learning Mode).

### 2. Testing Safe Requests
- **With Forwarding Disabled**:
  ```bash
  curl -H "Accept: text/html" "http://localhost:5000/waf/?name=hossein"
  ```
  Returns `safe_request.html` with "Request Approved".

- **With Forwarding Enabled**:
  ```bash
  curl "http://localhost:5000/waf/?name=hossein"
  ```
  Forwards to backend and returns "Backend Response".

- **Non-API Path**:
  ```bash
  curl -H "Accept: text/html" "http://localhost:5000/test-path"
  ```
  Returns `safe_but_disabled.html` with "Non-API Request Blocked" if `FORWARDING_ENABLED` is disabled.

### 3. Enabling Learning Mode
1. Go to `http://localhost:5000/settings/html`.
2. Enable **Learning Mode** (checkbox).
3. Save settings (sets a 7-day expiry).
4. Send a malicious request:
   ```bash
   curl "http://localhost:5000/waf/?query=OR%201=1"
   ```
   The request will be logged but not blocked. Check logs at `http://localhost:5000/attack-logs/html`.

### 4. Adding a Custom Rule
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

### 5. Viewing Attack Logs
1. Go to `http://localhost:5000/attack-logs/html`.
2. Filter logs by:
   - **Attack Type**: SQLi, XSS, etc.
   - **Time Range**: Last 24 hours, last 7 days, or all.
   - **IP**: Search for a specific IP (e.g., `127.0.0.1`).

### 6. Managing Blocked IPs
1. Go to `http://localhost:5000/blocked-ips/html`.
2. View blocked IPs and remaining block time.
3. Use "Unblock" to remove an IP or "Clear All IPs" to unblock all.

### 7. Managing Logs
1. Go to `http://localhost:5000/logs-management/html`.
2. Clean up old log files (default: older than 30 days).
3. View total log size and warning if it exceeds 100 MB.

---

## 🧑‍💻 Development

### Adding New Attack Types
To add a new attack type (e.g., `Custom`):
1. In `waf/waf_utils.py`, add a new detection function (e.g., `check_custom`).
2. Update `waf/routes/waf_routes.py` to check for the new attack type in `process_request`.
3. Add the new type to the dropdown in `/rules/html`.

### Extending Tests
Add new test cases to `tests/test_waf.py` for custom rules or attack types:
```python
def test_custom_rule(client):
    response = client.post('/rules/html', data={
        'pattern': r'\btest\b',
        'attack_type': 'Custom',
        'description': 'Detect test keyword',
        'action': 'block'
    })
    response = client.get('/waf/?query=test')
    assert response.status_code == 403
```

### Notes for Developers
- **Learning Mode**: Logs attacks without blocking, ideal for initial deployment. Set via `/settings/html` with a 7-day expiry.
- **Deprecation Warning**: `flask_restx` has a deprecated dependency (`jsonschema.RefResolver`). Consider upgrading or switching to `flask-smorest` in future releases.
- **Windows Users**: Ensure `logs` and `db` directories exist (`mkdir logs db`) to avoid errors.
- **Package Structure**: The `waf` directory is a Python package, requiring `__init__.py` files in `waf` and `waf/routes`.
- **Database Optimization**: Uses indexing and caching for `get_blocked_ips()` to achieve ~19ms response times.

---

## 🔍 Troubleshooting

- **Database Issues**:
  - Ensure `db/waf.db` is writable in `D:\CoDe\waf\db`.
  - Verify `DB_PATH` in `waf/config.py` points to `D:\CoDe\waf\db\waf.db`.
  - Install `pysqlite3` if SQLite issues persist (`pip install pysqlite3`).

- **UI Not Displaying Correctly**:
  - Check if Bootstrap and Poppins font CDNs are accessible.
  - Clear browser cache or try another browser.

- **Tests Failing**:
  - Ensure `backend.py` is running on port 8888 (`python backend.py`).
  - Verify all dependencies are installed (`pip install -r requirements.txt`).
  - Set `PYTHONPATH` to the project root:
    ```bash
    set PYTHONPATH=.  # Windows
    export PYTHONPATH=.  # Linux/macOS
    ```
  - Check `tests/test_waf.py` exists in `D:\CoDe\waf\tests`.

- **ModuleNotFoundError**:
  - Confirm `__init__.py` files exist in `waf` and `waf/routes`.
  - Run tests with `PYTHONPATH`:
    ```bash
    set PYTHONPATH=.
    python -m pytest tests/test_waf.py -v
    ```

- **Learning Mode Not Working**:
  - Check `/settings/html` to ensure Learning Mode is enabled.
  - Verify the expiry time in the admin panel (default: 7 days).

For additional help, contact the author or open an issue on the [GitHub repository](https://github.com/ho3j/flask-waf).

---

## 👨‍💻 Author

Created by [Hossein Jalili](https://github.com/ho3j)

---

## 📝 License

MIT License - Free to use and modify.