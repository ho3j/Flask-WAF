import pytest
import sqlite3
# from app import app

@pytest.fixture
def client():
    """
    Create a test client for the Flask app and clear blocked IPs before each test.
    
    Returns:
        Flask test client
    """
    app.config['TESTING'] = True
    # Clear blocked_ips table
    conn = sqlite3.connect("waf.db")
    c = conn.cursor()
    c.execute("DELETE FROM blocked_ips")
    conn.commit()
    conn.close()
    with app.test_client() as client:
        yield client

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
    response = client.post('/waf/', data={"email": "' OR '1'='1", "csrf_token": "dummy"}, headers={"Origin": "http://127.0.0.1:5000", "Host": "127.0.0.1:5000"})
    assert response.status_code == 403
    assert b"Blocked" in response.data or b"Access Denied" in response.data

def test_xss_post(client):
    """
    Test XSS detection in a POST request.
    """
    response = client.post('/waf/', data={"msg": '<img src=x onerror=alert(1)>', "csrf_token": "dummy"}, headers={"Origin": "http://127.0.0.1:5000", "Host": "127.0.0.1:5000"})
    assert response.status_code == 403
    assert b"Blocked" in response.data or b"Access Denied" in response.data

def test_command_injection_post(client):
    """
    Test Command Injection detection in a POST request.
    """
    response = client.post('/waf/', data={"cmd": ";whoami", "csrf_token": "dummy"}, headers={"Origin": "http://127.0.0.1:5000", "Host": "127.0.0.1:5000"})
    assert response.status_code == 403
    assert b"Blocked" in response.data or b"Access Denied" in response.data

def test_path_traversal_post(client):
    """
    Test Path Traversal detection in a POST request.
    """
    response = client.post('/waf/', data={"path": "/etc/shadow", "csrf_token": "dummy"}, headers={"Origin": "http://127.0.0.1:5000", "Host": "127.0.0.1:5000"})
    assert response.status_code == 403
    assert b"Blocked" in response.data or b"Access Denied" in response.data

def test_clean_post(client):
    """
    Test a safe POST request to ensure it forwards to the backend.
    """
    response = client.post('/waf/', data={"comment": "Hello world", "csrf_token": "dummy"}, headers={"Origin": "http://127.0.0.1:5000", "Host": "127.0.0.1:5000"})
    assert response.status_code == 200
    assert b"Backend Response" in response.data

def test_forward_to_backend(client):
    """
    Test forwarding a safe GET request to the backend.
    """
    response = client.get('/waf/?test=hello')
    assert response.status_code == 200
    assert b"Backend Response" in response.data

# def test_rate_limiting(client):
#     """
#     Test rate limiting by sending excessive requests (requires Redis).
#     """
#     for _ in range(101):
#         response = client.get('/waf/?test=ratelimit')
#         if response.status_code == 429:
#             break
#     assert response.status_code == 429
#     assert b"Blocked" in response.data or b"Access Denied" in response.data

def test_dashboard(client):
    """
    Test the dashboard page rendering.
    """
    response = client.get('/dashboard')
    assert response.status_code == 200
    assert b"WAF Dashboard" in response.data

def test_blocked_ips_page(client):
    """
    Test the blocked IPs page after triggering an IP block.
    """
    client.get('/waf/?query=1%20OR%201=1')  # Trigger IP block
    response = client.get('/blocked-ips/html')
    assert response.status_code == 200
    assert b"Blocked IPs" in response.data