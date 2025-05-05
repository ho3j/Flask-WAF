🔐 Flask WAF (Web Application Firewall)
A lightweight, extensible Web Application Firewall (WAF) built with Python and Flask. This project provides robust protection against common web attacks, including SQL Injection (SQLi), Cross-Site Scripting (XSS), Command Injection, Path Traversal, Local File Inclusion (LFI), and Cross-Site Request Forgery (CSRF). It features IP blocking, attack logging, a user-friendly HTML-based admin panel, dynamic rule management, a learning mode for monitoring without blocking, and comprehensive testing with pytest. The WAF intercepts and filters requests to a backend server, ensuring only safe requests are forwarded.

🧩 Project Structure



File / Folder
Description



main.py
Main WAF application entry point, initializing Flask and RESTx API


backend.py
Simulated backend server running on port 8888 to test WAF request forwarding


waf/db.py
SQLite database helpers for initializing tables, managing blocked IPs, logging attacks, and storing rules


waf/config.py
Configuration for logging (file and console output)


waf/waf_utils.py
Functions for detecting attacks (SQLi, XSS, Command Injection, Path Traversal, LFI, CSRF)


waf/waf_patterns.py
Regex patterns for detecting various attacks


waf/routes/waf_routes.py
Main WAF endpoint (/waf/) for filtering requests and IP blocking


waf/routes/admin_routes.py
Admin panel routes for dashboard, logs, blocked IPs, rules, and settings


waf/routes/auth_routes.py
Authentication routes for login and logout


test_waf.py
Comprehensive test suite using pytest to validate WAF functionality


requirements.txt
Project dependencies


waf.db
SQLite database file (generated at runtime, excluded via .gitignore)


res/logs/waf.log
Log file for WAF activities


res/logo.png
Optional logo for admin panel UI



🚀 Getting Started
Prerequisites
To run the Flask-WAF project, ensure you have the following installed:

Python 3.8+: Download from python.org.
pip: Python package manager (included with Python).
Redis (optional): For rate limiting. Install via:
Linux: sudo apt-get install redis-server
Windows: Use Redis for Windows or Docker.
macOS: brew install redis


A web browser (e.g., Chrome, Firefox) for accessing the admin panel.

Installation

Clone the Repository:
git clone https://github.com/ho3j/flask-waf.git
cd flask-waf


Create a Virtual Environment (recommended):
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate


Install Dependencies:Ensure requirements.txt contains:
flask==2.3.2
flask-restx==1.1.0
requests==2.31.0
flask-limiter==3.5.0
redis==5.0.1
bcrypt==4.0.1
pytest==8.3.5

Then install:
pip install -r requirements.txt


Create Log Directory (if not exists):
# Windows
mkdir res\logs
# Linux/macOS
mkdir -p res/logs


Start the Backend Server:The backend server simulates a target application on port 8888.
python backend.py


Start the WAF:The WAF runs on port 5000 and intercepts requests to /waf/.
python main.py


Access the Admin Panel:Open a browser and navigate to:

Login: http://localhost:5000/login (default credentials: admin/admin)
Dashboard: http://localhost:5000/dashboard
Blocked IPs: http://localhost:5000/blocked-ips/html
Attack Logs: http://localhost:5000/attack-logs/html
Rule Management: http://localhost:5000/rules/html
Analytics: http://localhost:5000/analytics/html
Settings: http://localhost:5000/settings/html
API Docs: http://localhost:5000/docs




🧪 Running Tests
The project includes a comprehensive test suite using pytest to validate WAF functionality.

Install pytest (if not already installed):
pip install pytest


Ensure Backend is Running:Start the backend server (python backend.py) on port 8888, as some tests rely on it.

Run Tests:
set PYTHONPATH=.  # Windows
export PYTHONPATH=.  # Linux/macOS
python -m pytest test_waf.py -v

The test suite covers:

Safe GET and POST requests
Detection of SQLi, XSS, Command Injection, Path Traversal, LFI, and CSRF attacks
JSON payload and file upload attack detection
IP blocking and unblocking
Authentication (login, logout, invalid credentials)
Admin panel route rendering (dashboard, blocked IPs)




📋 Useful Routes



Route
Description



/waf/
Main WAF-protected endpoint for filtering incoming requests


/login
Login page for admin panel (default: admin/admin)


/logout
Log out the current user


/dashboard
Dashboard with attack statistics, recent logs, and a 7-day attack chart


/blocked-ips/html
View and manage blocked IPs (unblock or clear all)


/attack-logs/html
View and filter attack logs by type, time, or IP


/rules/html
Add, view, or delete custom detection rules


/analytics/html
Analyze attack patterns with charts and top attacking IPs


/settings/html
Enable/disable WAF features and configure settings (e.g., block duration, learning mode)


/docs
Swagger-based API documentation for WAF endpoints



🔒 Features

Attack Detection:

SQL Injection (SQLi): Blocks malicious SQL queries (e.g., OR 1=1, UNION SELECT).
Cross-Site Scripting (XSS): Detects script injections (e.g., <script>alert('xss')</script>).
Command Injection: Prevents system command execution (e.g., ;whoami).
Path Traversal: Blocks unauthorized file access (e.g., ../../etc/passwd).
Local File Inclusion (LFI): Detects attempts to include local files (e.g., /etc/passwd).
Cross-Site Request Forgery (CSRF): Validates POST requests for CSRF tokens and headers.
JSON Payloads: Checks JSON data for malicious content.
File Uploads: Scans uploaded file names for attack patterns.


Learning Mode:

Enables monitoring of attacks without blocking (logs attacks only).
Configurable via /settings/html with a default 7-day expiry.
Useful for analyzing traffic and tuning rules before enabling full blocking.


IP Blocking:

Automatically blocks IPs sending malicious requests (default: 5 minutes).
Configurable block duration via /settings/html.
Auto-unblock after expiration.
Admin panel to view, unblock, or clear blocked IPs.


Attack Logging:

Logs attack details (IP, type, parameter, timestamp) to SQLite database.
Filterable logs in admin panel by attack type, time range, or IP.


Dynamic Rule Management:

Add, view, or delete custom regex-based rules via /rules/html.
Supports multiple attack types (SQLi, XSS, etc.) and actions (block or log).


Request Forwarding:

Forwards safe requests to the backend (http://localhost:8888).
Preserves headers and parameters.


Rate Limiting (optional):

Uses Redis to limit requests per IP (default: 100/minute).
Returns 429 response for IPs exceeding the limit.


Admin Panel:

Responsive HTML interface with Bootstrap and Vazir font.
Features dashboard, blocked IPs, attack logs, rule management, analytics, and settings.
Authentication with username/password (bcrypt-secured).


Testing:

Comprehensive pytest suite covering attack detection, request forwarding, IP blocking, authentication, and JSON/file upload handling.
Tests for admin panel routes and learning mode functionality.




🛠 Usage Examples
1. Testing Attack Detection
Send malicious requests to /waf/ to test detection:
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

Each request should return a 403 response, log the attack, and block the IP (unless in Learning Mode).
2. Enabling Learning Mode

Go to http://localhost:5000/settings/html.
Enable Learning Mode (checkbox).
Save settings (sets a 7-day expiry).
Send a malicious request:curl "http://localhost:5000/waf/?query=OR%201=1"

The request will be logged but not blocked. Check logs at http://localhost:5000/attack-logs/html.

3. Adding a Custom Rule

Go to http://localhost:5000/rules/html.
Add a rule, e.g.:
Pattern: \bwhoami\b
Attack Type: CommandInjection
Description: Detects whoami command execution attempt
Action: block


Test the rule:curl "http://localhost:5000/waf/?cmd=whoami"



4. Viewing Attack Logs

Go to http://localhost:5000/attack-logs/html.
Filter logs by:
Attack Type: SQLi, XSS, etc.
Time Range: Last 24 hours, last 7 days, or all.
IP: Search for a specific IP (e.g., 127.0.0.1).



5. Managing Blocked IPs

Go to http://localhost:5000/blocked-ips/html.
View blocked IPs and remaining block time.
Use "Unblock" to remove an IP or "Clear All IPs" to unblock all.

6. Analyzing Attack Patterns

Go to http://localhost:5000/analytics/html.
View charts for attack types and daily attack counts.
Check top attacking IPs with attack counts and last seen timestamps.


🧑‍💻 Development
Adding New Attack Types
To add a new attack type (e.g., Custom):

In waf/waf_utils.py, add a new detection function (e.g., check_custom).
Update waf/routes/waf_routes.py to check for the new attack type in process_request.
Add the new type to the dropdown in /rules/html.

Extending Tests
Add new test cases to test_waf.py for custom rules or attack types:
def test_custom_rule(client):
    response = client.post('/rules/html', data={
        'pattern': r'\btest\b',
        'attack_type': 'Custom',
        'description': 'Detect test keyword',
        'action': 'block'
    })
    response = client.get('/waf/?query=test')
    assert response.status_code == 403

Notes for Developers

Learning Mode: When enabled, the WAF logs attacks without blocking, ideal for initial deployment to analyze traffic. Set via /settings/html with a 7-day expiry.
Deprecation Warning: The project uses flask_restx, which has a deprecated dependency (jsonschema.RefResolver). Consider upgrading to newer versions or switching to alternatives like flask-smorest in future releases.
Windows Users: Ensure the res/logs directory exists (mkdir res\logs) to avoid logging errors.
Package Structure: The waf directory is a Python package, requiring __init__.py files in waf and waf/routes.


🔍 Troubleshooting

Redis Connection Error:

Verify Redis is running (redis-cli ping should return PONG).
Disable rate limiting in waf/routes/waf_routes.py by setting redis_client = None if Redis is unavailable.


Database Issues:

Ensure waf.db is writable in the project directory.
Install pysqlite3 if SQLite issues persist (pip install pysqlite3).


UI Not Displaying Correctly:

Check if the Vazir font CDN (https://cdn.fontcdn.ir/Vazir) is accessible.
Clear browser cache or try another browser.


Tests Failing:

Ensure backend.py is running on port 8888 (python backend.py).
Verify all dependencies are installed (pip install -r requirements.txt).
Set PYTHONPATH to the project root:set PYTHONPATH=.  # Windows
export PYTHONPATH=.  # Linux/macOS




ModuleNotFoundError:

Confirm main.py and the waf package structure are correct.
Ensure __init__.py files exist in waf and waf/routes.


Learning Mode Not Working:

Check /settings/html to ensure Learning Mode is enabled.
Verify the expiry time in the admin panel (default: 7 days).



For additional help, contact the author or open an issue on the GitHub repository.

👨‍💻 Author
Created by Hossein Jalili

📝 License
MIT License - Free to use and modify.
