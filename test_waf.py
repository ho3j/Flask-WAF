import pytest
from app import app

@pytest.fixture
def client():
    """
    Create a test client for the Flask app.
    
    Returns:
        Flask test client
    """
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_clean_get(client):
    """
    Test a safe GET request.
    """
    response = client.get('/?name=hossein&age=30')
    assert response.status_code == 200
    assert b"Backend Response" in response.data

def test_sql_injection_get(client):
    """
    Test SQL Injection detection in GET request.
    """
    response = client.get("/?query=1 OR 1=1")
    assert response.status_code == 403
    assert b"Blocked" in response.data

def test_xss_get(client):
    """
    Test XSS detection in GET request.
    """
    response = client.get('/?q=<script>alert("xss")</script>')
    assert response.status_code == 403
    assert b"Blocked" in response.data

def test_sql_injection_post(client):
    """
    Test SQL Injection detection in POST request.
    """
    response = client.post('/', data={"email": "' OR '1'='1"})
    assert response.status_code == 403
    assert b"Blocked" in response.data

def test_xss_post(client):
    """
    Test XSS detection in POST request.
    """
    response = client.post('/', data={"msg": '<img src=x onerror=alert(1)>'})
    assert response.status_code == 403
    assert b"Blocked" in response.data

def test_clean_post(client):
    """
    Test a safe POST request.
    """
    response = client.post('/', data={"comment": "Hello world"})
    assert response.status_code == 200
    assert b"Backend Response" in response.data

def test_forward_to_backend(client):
    """
    Test forwarding a safe request to the backend.
    """
    response = client.get('/?test=hello')
    assert response.status_code == 200
    assert b"Backend Response" in response.data