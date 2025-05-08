from flask import request, render_template_string, redirect, url_for, session, flash
from waf.db import get_user
import bcrypt
import logging
import os
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont
import random
import string
import base64
from io import BytesIO
import time

def generate_captcha():
    # تولید متن تصادفی
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    
    # ایجاد تصویر
    image = Image.new('RGB', (200, 80), color='white')
    draw = ImageDraw.Draw(image)
    
    # فونت (پیش‌فرض یا فونت دلخواه اگر موجود باشد)
    try:
        font = ImageFont.truetype("arial.ttf", 40)
    except:
        font = ImageFont.load_default()
    
    # افزودن متن با اعوجاج
    draw.text((10, 20), captcha_text, fill='black', font=font)
    
    # افزودن نویز
    for _ in range(50):
        x, y = random.randint(0, 200), random.randint(0, 80)
        draw.point((x, y), fill='gray')
    
    # ذخیره تصویر به Base64
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    # ذخیره پاسخ در session
    session['captcha_answer'] = captcha_text
    session['captcha_expiry'] = time.time() + 120  # 2 دقیقه
    
    return img_str

def init_auth_routes(app):
    """
    Initialize authentication routes for the Flask app.
    
    Args:
        app: Flask application instance
    """
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """
        Display and handle the login page with CAPTCHA.
        
        Returns:
            Rendered HTML template for login page or redirect to dashboard
        """
        client_ip = request.remote_addr
        request_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
        
        if request.method == 'POST':
            captcha_answer = request.form.get('captcha')
            if session.get('captcha_answer') and time.time() < session.get('captcha_expiry', 0):
                if captcha_answer.upper() == session['captcha_answer']:
                    username = request.form.get('username')
                    password = request.form.get('password')
                    user = get_user(username)
                    
                    # لاگ درخواست لاگین
                    logging.info(f"Login attempt by user '{username}' from IP {client_ip} - Method: POST - URL: {request.url} - Headers: {dict(request.headers)}")
                    
                    if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                        session['user_id'] = user['id']
                        session['username'] = user['username']
                        flash('Login successful!', 'success')
                        logging.info(f"Login successful for user '{username}' from IP {client_ip} at {request_time}")
                        return redirect(url_for('dashboard'))
                    else:
                        flash('Invalid username or password.', 'danger')
                        logging.error(f"Login failed for user '{username}' from IP {client_ip} - Reason: Invalid credentials")
                else:
                    flash('Invalid CAPTCHA.', 'danger')
                    logging.error(f"Login failed for IP {client_ip} - Reason: Invalid CAPTCHA")
            else:
                flash('CAPTCHA expired or invalid.', 'danger')
                logging.error(f"Login failed for IP {client_ip} - Reason: CAPTCHA expired")
        
        # تولید CAPTCHA جدید
        captcha_img = generate_captcha()
        
        # Log the resource file path for debugging
        logo_path = url_for('serve_res', filename='logo.png')
        logo_full_path = os.path.join('res', 'logo.png')
        logging.info(f"Logo URL: {logo_path}")
        logging.info(f"Logo file path: {logo_full_path}")
        logging.info(f"Logo file exists: {os.path.exists(logo_full_path)}")
        
        # لاگ درخواست GET برای صفحه لاگین
        logging.info(f"GET request for login page from IP {client_ip} - URL: {request.url} - Headers: {dict(request.headers)}")
        
        html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login - Shark WAF Dashboard</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
            <style>
                body {
                    font-family: 'Poppins', sans-serif;
                    background: linear-gradient(135deg, #0284c7, #38bdf8, #f4f6f9);
                    background-size: 200% 200%;
                    animation: gradientShift 15s ease infinite;
                    height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    margin: 0;
                    position: relative;
                    overflow: hidden;
                    font-size: 0.9rem; /* کاهش فونت کلی */
                }
                @keyframes gradientShift {
                    0% { background-position: 0% 50%; }
                    50% { background-position: 100% 50%; }
                    100% { background-position: 0% 50%; }
                }
                .bubble-container {
                    position: absolute;
                    width: 100%;
                    height: 100%;
                    top: 0;
                    left: 0;
                    z-index: 0;
                    pointer-events: none;
                }
                .bubble {
                    position: absolute;
                    border-radius: 50%;
                    background: rgba(2, 132, 199, 0.7);
                    box-shadow: inset 0 0 10px rgba(255, 255, 255, 0.5);
                    animation: bubbleFloat 12s linear infinite;
                    pointer-events: none;
                }
                .bubble:nth-child(1) { width: 30px; height: 30px; left: 15%; top: 10%; animation-duration: 10s; opacity: 0.8; }
                .bubble:nth-child(2) { width: 20px; height: 20px; left: 25%; top: 60%; animation-duration: 8s; opacity: 0.6; background: rgba(255, 255, 255, 0.8); }
                .bubble:nth-child(3) { width: 25px; height: 25px; left: 40%; top: 80%; animation-duration: 14s; opacity: 0.7; background: rgba(251, 146, 60, 0.7); }
                .bubble:nth-child(4) { width: 15px; height: 15px; left: 55%; top: 20%; animation-duration: 9s; opacity: 0.5; background: rgba(56, 189, 248, 0.7); }
                .bubble:nth-child(5) { width: 35px; height: 35px; left: 70%; top: 50%; animation-duration: 11s; opacity: 0.6; }
                .bubble:nth-child(6) { width: 18px; height: 18px; left: 85%; top: 30%; animation-duration: 7s; opacity: 0.8; background: rgba(255, 255, 255, 0.7); }
                .bubble:nth-child(7) { width: 22px; height: 22px; left: 30%; top: 70%; animation-duration: 13s; opacity: 0.5; background: rgba(107, 114, 128, 0.7); }
                .bubble:nth-child(8) { width: 28px; height: 28px; left: 50%; top: 15%; animation-duration: 6s; opacity: 0.7; background: rgba(2, 132, 199, 0.7); }
                @keyframes bubbleFloat {
                    0% { transform: translateY(0) translateX(0) scale(1); opacity: 0.7; }
                    25% { transform: translateY(-100px) translateX(30px) scale(1.2); opacity: 0.5; }
                    50% { transform: translateY(-200px) translateX(-20px) scale(0.9); opacity: 0.3; }
                    75% { transform: translateY(-100px) translateX(20px) scale(1.1); opacity: 0.5; }
                    100% { transform: translateY(0) translateX(0) scale(1); opacity: 0.7; }
                }
                .login-container {
                    background: rgba(255, 255, 255, 0.95);
                    padding: 1.5rem; /* کاهش padding */
                    border-radius: 10px; /* کمی کوچکتر */
                    box-shadow: 0 0 15px rgba(2, 132, 199, 0.5);
                    width: 100%;
                    max-width: 350px; /* کاهش عرض ظرف */
                    position: relative;
                    backdrop-filter: blur(5px);
                    animation: floatIn 0.8s ease-in-out;
                    border: 2px solid rgba(2, 132, 199, 0.3);
                    z-index: 1;
                }
                @keyframes floatIn {
                    0% { opacity: 0; transform: translateY(30px) scale(0.9); }
                    60% { opacity: 0.7; transform: translateY(-10px) scale(1.05); }
                    100% { opacity: 1; transform: translateY(0) scale(1); }
                }
                .login-container img {
                    display: block;
                    margin: 0 auto 1.5rem; /* کاهش margin */
                    max-width: 150px; /* کاهش اندازه لوگو */
                    width: 100%;
                    height: auto;
                    object-fit: contain;
                    transition: transform 0.3s ease, filter 0.3s ease;
                }
                .login-container img:hover {
                    transform: scale(1.1);
                    filter: drop-shadow(0 0 10px rgba(2, 132, 199, 0.7));
                }
                .form-control {
                    border-radius: 6px; /* کاهش شعاع گوشه */
                    border: 1px solid #ced4da;
                    padding: 0.5rem; /* کاهش padding */
                    font-size: 0.9rem; /* کاهش اندازه فونت */
                    transition: border-color 0.3s ease;
                    height: 2rem; /* کاهش ارتفاع */
                }
                .form-control:focus {
                    border-color: #0284c7;
                    box-shadow: 0 0 5px rgba(2, 132, 199, 0.5);
                }
                .btn-primary {
                    background: #0284c7;
                    border: none;
                    border-radius: 6px; /* کاهش شعاع گوشه */
                    padding: 0.5rem; /* کاهش padding */
                    width: 100%;
                    font-weight: 600;
                    font-size: 0.9rem; /* کاهش اندازه فونت */
                    transition: background 0.3s, box-shadow 0.3s;
                    height: 2rem; /* کاهش ارتفاع */
                }
                .btn-primary:hover {
                    background: #38bdf8;
                    box-shadow: 0 0 10px rgba(2, 132, 199, 0.7);
                }
                .alert {
                    border-radius: 6px; /* کاهش شعاع گوشه */
                    margin-bottom: 0.8rem; /* کاهش margin */
                    border: 1px solid rgba(2, 132, 199, 0.3);
                    font-size: 0.8rem; /* کاهش اندازه فونت */
                }
                h2 {
                    color: #0284c7;
                    text-align: center;
                    margin-bottom: 1rem; /* کاهش margin */
                    font-weight: 600;
                    font-size: 1.3rem; /* کاهش اندازه فونت */
                    text-shadow: 0 0 5px rgba(255, 255, 255, 0.5);
                }
                .form-label {
                    font-size: 0.85rem; /* کاهش اندازه فونت لیبل */
                }
                .mb-3 {
                    margin-bottom: 0.8rem !important; /* کاهش فاصله بین المان‌ها */
                }
                @media (max-width: 576px) {
                    .login-container {
                        margin: 0.8rem;
                        padding: 1rem; /* کاهش padding در موبایل */
                    }
                    .login-container img {
                        max-width: 120px; /* کاهش اندازه لوگو در موبایل */
                    }
                    .bubble:nth-child(n+5) {
                        display: none;
                    }
                    h2 {
                        font-size: 1.1rem; /* کاهش اندازه فونت در موبایل */
                    }
                    .form-control, .btn-primary {
                        font-size: 0.8rem; /* کاهش فونت در موبایل */
                        height: 1.8rem; /* کاهش ارتفاع در موبایل */
                    }
                    .form-label {
                        font-size: 0.8rem; /* کاهش فونت لیبل در موبایل */
                    }
                }
            </style>
        </head>
        <body>
            <div class="bubble-container">
                <div class="bubble"></div>
                <div class="bubble"></div>
                <div class="bubble"></div>
                <div class="bubble"></div>
                <div class="bubble"></div>
                <div class="bubble"></div>
                <div class="bubble"></div>
                <div class="bubble"></div>
            </div>
            <div class="login-container">
                <img src="{{ url_for('serve_res', filename='logo.png') }}" alt="Shark WAF Logo">
                <h2><i class="fas fa-shark me-2"></i> Shark WAF Login</h2>
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% set category, message = messages[-1] %}
                        <div class="alert alert-{{ 'success' if category == 'success' else 'danger' }}">{{ message }}</div>
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
                    <div class="mb-3">
                        <label for="captcha" class="form-label">Enter CAPTCHA</label>
                        <img src="data:image/png;base64,{{ captcha_img }}" alt="CAPTCHA">
                        <input type="text" class="form-control" id="captcha" name="captcha" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
            </div>
        </body>
        </html>
        """
        return render_template_string(html_template, captcha_img=captcha_img)

    @app.route('/logout')
    def logout():
        """
        Log out the current user and redirect to login page.
        
        Returns:
            Redirect to login page
        """
        client_ip = request.remote_addr
        request_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
        username = session.get('username', 'unknown')
        
        # لاگ لاگ‌اوت
        logging.info(f"User '{username}' logged out from IP {client_ip} at {request_time}")
        
        session.pop('user_id', None)
        session.pop('username', None)
        flash('You have been logged out.', 'success')
        return redirect(url_for('login'))