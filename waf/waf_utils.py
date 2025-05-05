from urllib.parse import unquote
from waf.waf_patterns import sql_patterns, xss_patterns, command_injection_patterns, path_traversal_patterns, lfi_patterns
import logging
import re
from waf.db import get_rules, get_setting

def is_text_like(s):
    """
    Check if the input is a string-like value suitable for attack detection.
    
    Args:
        s: Input to check
        
    Returns:
        bool: True if input is a string longer than 2 characters and not numeric
    """
    result = isinstance(s, str) and len(s) > 2 and not s.isdigit()
    logging.info(f"is_text_like check: {s} -> {result}")
    return result

def check_sql_injection(input_string):
    """
    Detect SQL Injection attempts in the input string.
    
    Args:
        input_string (str): Input to check for SQLi patterns
        
    Returns:
        bool: True if SQLi detected, False otherwise
    """
    if not get_setting('sql_injection_detection'):
        logging.info("SQLi detection is disabled")
        return False
    if not is_text_like(input_string):
        return False
    decoded = unquote(input_string)
    logging.info(f"Checking SQLi for decoded input: {decoded}")
    
    # Check static patterns
    for pattern, desc in sql_patterns:
        if pattern.search(decoded):
            logging.warning(f"SQL Injection: {desc} | Input: {decoded}")
            return True
    
    # Check database rules
    rules = get_rules()
    for rule in rules:
        if rule['attack_type'] == 'SQLi':
            try:
                if re.search(rule['pattern'], decoded, re.IGNORECASE):
                    logging.warning(f"SQL Injection: {rule['description']} | Input: {decoded}")
                    return True
            except re.error:
                logging.error(f"Invalid regex pattern in rule {rule['id']}: {rule['pattern']}")
    
    return False

def check_xss(input_string):
    """
    Detect Cross-Site Scripting (XSS) attempts in the input string.
    
    Args:
        input_string (str): Input to check for XSS patterns
        
    Returns:
        bool: True if XSS detected, False otherwise
    """
    if not get_setting('xss_detection'):
        logging.info("XSS detection is disabled")
        return False
    if not is_text_like(input_string):
        return False
    decoded = unquote(input_string)
    logging.info(f"Checking XSS for decoded input: {decoded}")
    
    # Check static patterns
    for pattern, desc in xss_patterns:
        if pattern.search(decoded):
            logging.warning(f"XSS Detected: {desc} | Input: {decoded}")
            return True
    
    # Check database rules
    rules = get_rules()
    for rule in rules:
        if rule['attack_type'] == 'XSS':
            try:
                if re.search(rule['pattern'], decoded, re.IGNORECASE):
                    logging.warning(f"XSS Detected: {rule['description']} | Input: {decoded}")
                    return True
            except re.error:
                logging.error(f"Invalid regex pattern in rule {rule['id']}: {rule['pattern']}")
    
    return False

def check_command_injection(input_string):
    """
    Detect Command Injection attempts in the input string.
    
    Args:
        input_string (str): Input to check for command injection patterns
        
    Returns:
        bool: True if command injection detected, False otherwise
    """
    if not get_setting('command_injection_detection'):
        logging.info("Command Injection detection is disabled")
        return False
    if not is_text_like(input_string):
        return False
    decoded = unquote(input_string)
    logging.info(f"Checking Command Injection for decoded input: {decoded}")
    
    for pattern, desc in command_injection_patterns:
        if pattern.search(decoded):
            logging.warning(f"Command Injection: {desc} | Input: {decoded}")
            return True
    
    rules = get_rules()
    for rule in rules:
        if rule['attack_type'] == 'CommandInjection':
            try:
                if re.search(rule['pattern'], decoded, re.IGNORECASE):
                    logging.warning(f"Command Injection: {rule['description']} | Input: {decoded}")
                    return True
            except re.error:
                logging.error(f"Invalid regex pattern in rule {rule['id']}: {rule['pattern']}")
    
    return False

def check_path_traversal(input_string):
    """
    Detect Path Traversal attempts in the input string.
    
    Args:
        input_string (str): Input to check for path traversal patterns
        
    Returns:
        bool: True if path traversal detected, False otherwise
    """
    if not get_setting('path_traversal_detection'):
        logging.info("Path Traversal detection is disabled")
        return False
    if not is_text_like(input_string):
        return False
    decoded = unquote(input_string)
    logging.info(f"Checking Path Traversal for decoded input: {decoded}")
    
    for pattern, desc in path_traversal_patterns:
        if pattern.search(decoded):
            logging.warning(f"Path Traversal: {desc} | Input: {decoded}")
            return True
    
    rules = get_rules()
    for rule in rules:
        if rule['attack_type'] == 'PathTraversal':
            try:
                if re.search(rule['pattern'], decoded, re.IGNORECASE):
                    logging.warning(f"Path Traversal: {rule['description']} | Input: {decoded}")
                    return True
            except re.error:
                logging.error(f"Invalid regex pattern in rule {rule['id']}: {rule['pattern']}")
    
    return False

def check_csrf(request):
    """
    Detect Cross-Site Request Forgery (CSRF) attempts in POST requests.
    
    Args:
        request: Flask request object
        
    Returns:
        bool: True if CSRF detected, False otherwise
    """
    if not get_setting('csrf_detection'):
        logging.info("CSRF detection is disabled")
        return False
    if request.method != 'POST':
        return False
    
    # Check for CSRF token (assumes backend app sends token in header or form)
    csrf_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
    if not csrf_token:
        logging.warning("CSRF Detected: Missing CSRF token")
        return True
    
    # Check Referer and Origin headers
    referer = request.headers.get('Referer')
    origin = request.headers.get('Origin')
    host = request.headers.get('Host')
    
    if not referer and not origin:
        logging.warning("CSRF Detected: Missing Referer and Origin headers")
        return True
    
    valid_origins = [f"https://{host}", f"http://{host}"]
    if origin and origin not in valid_origins:
        logging.warning(f"CSRF Detected: Invalid Origin header: {origin}")
        return True
    
    return False

def check_lfi(input_string):
    """
    Detect Local File Inclusion (LFI) attempts in the input string.
    
    Args:
        input_string (str): Input to check for LFI patterns
        
    Returns:
        bool: True if LFI detected, False otherwise
    """
    if not get_setting('lfi_detection'):
        logging.info("LFI detection is disabled")
        return False
    if not is_text_like(input_string):
        logging.info(f"Input not text-like: {input_string}")
        return False
    decoded = unquote(input_string)
    logging.info(f"Checking LFI for decoded input: {decoded}")
    
    # Check static patterns
    for pattern, desc in lfi_patterns:
        if pattern.search(decoded):
            logging.warning(f"LFI Detected: {desc} | Input: {decoded}")
            return True
        else:
            logging.info(f"No match for pattern {desc} | Input: {decoded}")
    
    # Check database rules
    rules = get_rules()
    for rule in rules:
        if rule['attack_type'] == 'LFI':
            try:
                if re.search(rule['pattern'], decoded, re.IGNORECASE):
                    logging.warning(f"LFI Detected: {rule['description']} | Input: {decoded}")
                    return True
            except re.error:
                logging.error(f"Invalid regex pattern in rule {rule['id']}: {rule['pattern']}")
    
    return False