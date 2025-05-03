import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

# تست درخواست سالم GET
def test_clean_get(client):
    response = client.get('/?name=hossein&age=30')
    assert response.status_code == 200
    assert b"Backend Response" in response.data

# تست SQL Injection GET
def test_sql_injection_get(client):
    response = client.get("/?query=1 OR 1=1")
    assert response.status_code == 403
    assert b"Blocked" in response.data

# تست XSS در GET
def test_xss_get(client):
    response = client.get('/?q=<script>alert("xss")</script>')
    assert response.status_code == 403
    assert b"Blocked" in response.data

# تست SQL Injection در POST
def test_sql_injection_post(client):
    response = client.post('/', data={"email": "' OR '1'='1"})
    assert response.status_code == 403
    assert b"Blocked" in response.data

# تست XSS در POST
def test_xss_post(client):
    response = client.post('/', data={"msg": '<img src=x onerror=alert(1)>'})
    assert response.status_code == 403
    assert b"Blocked" in response.data

# تست درخواست POST سالم
def test_clean_post(client):
    response = client.post('/', data={"comment": "Hello world"})
    assert response.status_code == 200
    assert b"Backend Response" in response.data


# تست اینکه درخواست سالم فوروارد بشه به backend
def test_forward_to_backend(client):
    response = client.get('/?test=hello')
    assert response.status_code == 200
    assert b"Backend Response" in response.data
