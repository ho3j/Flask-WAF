from urllib.parse import unquote
from waf_patterns import sql_patterns, xss_patterns
import logging

def is_text_like(s):
    return isinstance(s, str) and len(s) > 2 and not s.isdigit()

def check_sql_injection(input_string):
    if not is_text_like(input_string):
        return False
    decoded = unquote(input_string)
    for pattern, desc in sql_patterns:
        if pattern.search(decoded):
            logging.warning(f"SQL Injection: {desc} | Input: {decoded}")
            return True
    return False

def check_xss(input_string):
    if not is_text_like(input_string):
        return False
    decoded = unquote(input_string)
    for pattern, desc in xss_patterns:
        if pattern.search(decoded):
            logging.warning(f"XSS Detected: {desc} | Input: {decoded}")
            return True
    return False
