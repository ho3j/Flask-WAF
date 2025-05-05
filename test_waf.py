import pytest
import sqlite3
from waf.main import app
from waf.db import init_db, get_user
import bcrypt

@pytest.fixture
def client():
    """
    Create a test client for the Flask app, initialize the database, and clear blocked IPs before each test.
    
    Returns:
        Flask test client
    """
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test_secret_key'  # Set a test secret key for sessions
    
    # Initialize the database
    init_db()
    
    # Clear blocked_ips and attack_logs tables
    conn = sqlite3.connect("waf.db")
    c = conn.cursor()
    c.execute("DELETE FROM blocked_ips")
    c.execute("DELETE FROM attack_logs")
    conn.commit()
    conn.close()
    
    with app.test_client() as client:
        yield client

@pytest.fixture
def logged_in_client(client):
    """
    Create a test client with a logged-in session for testing protected routes.
    
    Args:
        client: Flask test client fixture
    
    Returns:
        Flask test client with a logged-in session
    """
    # Log in as the default admin user
    with client.session_transaction() as session:
        user = get_user('admin')
        if not user:
            # Create admin user if it doesn't exist
            admin_password = bcrypt.hashpw('admin'.encode('utf-8'), bcrypt.gensalt())
            conn = sqlite3.connect("waf.db")
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                     ('admin', admin_password.decode('utf-8')))
            conn.commit()
            conn.close()
            user = {'id': 1, 'username': 'admin'}
        
        session['user_id'] = user['id']
        session['username'] = user['username']
    
    return client

def test_clean_get(client):
    """
    Test a safe GET request to ensure it forwards to the backend.
    """
    response = client.get('/waf/?name=hossein&age=30')
    assert response.status_code == 200
    assert b"Backend Response" in response.data

def test_sql_injection_get(client):
    """
    Test SQL Injection detection in a GET request.
    """
    response = client.get("/waf/?query=1%20OR%201=1")
    assert response.status_code == 403
    assert b"Blocked" in response.data or b"Access Denied" in response.data

def test_xss_get(client):
    """
    Test XSS detection in a GET request.
    """
    response = client.get('/waf/?q=%3Cscript%3Ealert(%22xss%22)%3C/script%3E')
    assert response.status_code == 403
    assert b"Blocked" in response.data or b"Access Denied" in response.data

def test_command_injection_get(client):
    """
    Test Command Injection detection in a GET request.
    """
    response = client.get('/waf/?cmd=%3Bwhoami')
    assert response.status_code == 403
    assert b"Blocked" in response.data or b"Access Denied" in response.data

def test_path_traversal_get(client):
    """
    Test Path Traversal detection in a GET request.
    """
    response = client.get('/waf/?path=../../../etc/passwd')
    assert response.status_code == 403
    assert b"Blocked" in response.data or b"Access Denied" in response.data

def test_lfi_get(client):
    """
    Test Local File Inclusion (LFI) detection in a GET request.
    """
    response = client.get('/waf/?file=/etc/passwd')
    assert response.status_code == 403
    assert b"Blocked" in response.data or b"Access Denied" in response.data

def test_csrf_post(client):
    """
    Test CSRF detection in a POST request without a token.
    """
    response = client.post('/waf/', data={"test": "value"}, headers={})
    assert response.status_code == 403
    assert b"Blocked" in response.data or b"Access Denied" in response.data

def test_sql_injection_post(client):
    """
    Test SQL Injection detection in a POST request.
    """
    response = client.post('/waf/', 
                          data={"email": "' OR '1'='1", "csrf_token": "dummy"}, 
                          headers={"Origin": "http://127.0.0.1:5000", "Host": "127.0.0.1:5000"})
    assert response.status_code == 403
    assert b"Blocked" in response.data or b"Access Denied" in response.data

def test_xss_post(client):
    """
    Test XSS detection in a POST request.
    """
    response = client.post('/waf/', 
                          data={"msg": '<img src=x onerror=alert(1)>', "csrf_token": "dummy"}, 
                          headers={"Origin": "http://127.0.0.1:5000", "Host": "127.0.0.1:5000"})
    assert response.status_code == 403
    assert b"Blocked" in response.data or b"Access Denied" in response.data

def test_command_injection_post(client):
    """
    Test Command Injection detection in a POST request.
    """
    response = client.post('/waf/', 
                          data={"cmd": ";whoami", "csrf_token": "dummy"}, 
                          headers={"Origin": "http://127.0.0.1:5000", "Host": "127.0.0.1:5000"})
    assert response.status_code == 403
    assert b"Blocked" in response.data or b"Access Denied" in response.data

def test_path_traversal_post(client):
    """
    Test Path Traversal detection in a POST request.
    """
    response = client.post('/waf/', 
                          data={"path": "/etc/shadow", "csrf_token": "dummy"}, 
                          headers={"Origin": "http://127.0.0.1:5000", "Host": "127.0.0.1:5000"})
    assert response.status_code == 403
    assert b"Blocked" in response.data or b"Access Denied" in response.data

def test_lfi_post(client):
    """
    Test Local File Inclusion (LFI) detection in a POST request.
    """
    response = client.post('/waf/', 
                          data={"file": "include(/etc/passwd)", "csrf_token": "dummy"}, 
                          headers={"Origin": "http://127.0.0.1:5000", "Host": "127.0.0.1:5000"})
    assert response.status_code == 403
    assert b"Blocked" in response.data or b"Access Denied" in response.data

def test_clean_post(client):
    """
    Test a safe POST request to ensure it forwards to the backend.
    """
    response = client.post('/waf/', 
                          data={"comment": "Hello world", "csrf_token": "dummy"}, 
                          headers={"Origin": "http://127.0.0.1:5000", "Host": "127.0.0.1:5000"})
    assert response.status_code == 200
    assert b"Backend Response" in response.data

def test_forward_to_backend(client):
    """
    Test forwarding a safe GET request to the backend.
    """
    response = client.get('/waf/?test=hello')
    assert response.status_code == 200
    assert b"Backend Response" in response.data

def test_json_input(client):
    """
    Test JSON input with a malicious payload for XSS detection.
    """
    response = client.post('/waf/', 
                          json={"msg": "<script>alert('xss')</script>", "csrf_token": "dummy"}, 
                          headers={"Origin": "http://127.0.0.1:5000", "Host": "127.0.0.1:5000", "Content-Type": "application/json"})
    assert response.status_code == 403
    assert b"Blocked" in response.data or b"Access Denied" in response.data

def test_file_upload_filename(client):
    """
    Test file upload with a malicious filename for Path Traversal detection.
    """
    from io import BytesIO
    data = {
        "csrf_token": "dummy",
        "file": (BytesIO(b"test content"), "../../etc/passwd")
    }
    response = client.post('/waf/',
                          data=data,
                          content_type='multipart/form-data',
                          headers={"Origin": "http://127.0.0.1:5000", "Host": "127.0.0.1:5000"})
    assert response.status_code == 403
    assert b"Blocked" in response.data or b"Access Denied" in response.data

def test_blocked_ip(client):
    """
    Test that a blocked IP receives a 403 response.
    """
    # Trigger an attack to block the IP
    client.get('/waf/?query=1%20OR%201=1')
    
    # Subsequent request should be blocked
    response = client.get('/waf/?test=hello')
    assert response.status_code == 403
    assert b"Access Denied" in response.data

def test_dashboard(logged_in_client):
    """
    Test the dashboard page rendering for a logged-in user.
    """
    response = logged_in_client.get('/dashboard')
    assert response.status_code == 200
    assert b"WAF Dashboard" in response.data

def test_blocked_ips_page(logged_in_client):
    """
    Test the blocked IPs page after triggering an IP block for a logged-in user.
    """
    logged_in_client.get('/waf/?query=1%20OR%201=1')  # Trigger IP block
    response = logged_in_client.get('/blocked-ips/html')
    assert response.status_code == 200
    assert b"Blocked IPs" in response.data

def test_login(client):
    """
    Test the login functionality with valid credentials.
    """
    response = client.post('/login', 
                          data={"username": "admin", "password": "admin"}, 
                          follow_redirects=True)
    assert response.status_code == 200
    assert b"WAF Dashboard" in response.data

def test_invalid_login(client):
    """
    Test the login functionality with invalid credentials.
    """
    response = client.post('/login', 
                          data={"username": "admin", "password": "wrong"}, 
                          follow_redirects=True)
    assert response.status_code == 200
    assert b"Invalid username or password" in response.data

def test_logout(logged_in_client):
    """
    Test the logout functionality.
    """
    response = logged_in_client.get('/logout', follow_redirects=True)
    assert response.status_code == 200
    assert b"WAF Login" in response.data