from flask import request, render_template_string, redirect, url_for, session, flash
from waf.db import get_user
import bcrypt
import logging
import os

def init_auth_routes(app):
    """
    Initialize authentication routes for the Flask app.
    
    Args:
        app: Flask application instance
    """
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """
        Display and handle the login page.
        
        Returns:
            Rendered HTML template for login page or redirect to dashboard
        """
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            user = get_user(username)
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                session['user_id'] = user['id']
                session['username'] = user['username']
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'danger')
        
        # Log the resource file path for debugging
        logo_path = url_for('serve_res', filename='logo.png')
        logo_full_path = os.path.join('res', 'logo.png')
        logging.info(f"Logo URL: {logo_path}")
        logging.info(f"Logo file path: {logo_full_path}")
        logging.info(f"Logo file exists: {os.path.exists(logo_full_path)}")
        
        html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login - WAF Dashboard</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdn.fontcdn.ir/Vazir/Vazir.css" rel="stylesheet">
            <style>
                body {
                    font-family: 'Vazir', Arial, sans-serif;
                    background: linear-gradient(135deg, #667eea, #764ba2);
                    height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    margin: 0;
                }
                .login-container {
                    background: white;
                    padding: 2rem;
                    border-radius: 15px;
                    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
                    width: 100%;
                    max-width: 400px;
                }
                .login-container img {
                    display: block;
                    margin: 0 auto 1.5rem;
                    max-width: 150px;
                }
                .form-control {
                    border-radius: 10px;
                    border: 1px solid #ced4da;
                    padding: 0.75rem;
                }
                .btn-primary {
                    background: #667eea;
                    border: none;
                    border-radius: 10px;
                    padding: 0.75rem;
                    width: 100%;
                    transition: background 0.3s;
                }
                .btn-primary:hover {
                    background: #764ba2;
                }
                .alert {
                    border-radius: 10px;
                    margin-bottom: 1rem;
                }
                h2 {
                    color: #333;
                    text-align: center;
                    margin-bottom: 1.5rem;
                }
            </style>
        </head>
        <body>
            <div class="login-container">
                <img src="{{ url_for('serve_res', filename='logo.png') }}" alt="WAF Logo">
                <h2>🔐 WAF Login</h2>
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ 'success' if category == 'success' else 'danger' }}">{{ message }}</div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                <form method="POST">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
            </div>
        </body>
        </html>
        """
        return render_template_string(html_template)

    @app.route('/logout')
    def logout():
        """
        Log out the current user and redirect to login page.
        
        Returns:
            Redirect to login page
        """
        session.pop('user_id', None)
        session.pop('username', None)
        flash('You have been logged out.', 'success')
        return redirect(url_for('login'))