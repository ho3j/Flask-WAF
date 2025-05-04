import re

# SQL Injection patterns
sql_patterns = [
    (re.compile(r"(?i)\b(UNION(\s+ALL)?\s+SELECT)\b"), "UNION SELECT"),
    (re.compile(r"(?i)\bSELECT\s.+\sFROM\s.+"), "SELECT FROM"),
    (re.compile(r"(?i)\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b"), "DML commands"),
    (re.compile(r"(?i)\b(DROP|ALTER|CREATE)\s+TABLE\b"), "DDL commands"),
    (re.compile(r"(?i)\b(OR|AND)\b\s+\d+=\d+"), "Logic condition"),
    (re.compile(r"(?i)'?\s*or\s*'1'='1"), "Classic OR '1'='1"),
]

# XSS patterns
xss_patterns = [
    (re.compile(r"(?i)<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>"), "Script tag"),
    (re.compile(r"(?i)on\w+\s*=\s*['\"][^'\"]*['\"]"), "JS event handler"),
    (re.compile(r"(?i)javascript:\s*[^\"'>]+"), "JavaScript URI"),
    (re.compile(r"(?i)<[^>]+(style|src|href)\s*=\s*['\"][^'\"]*(expression|javascript):"), "Attr JavaScript"),
    (re.compile(r"(?i)<img\s+[^>]*onerror\s*="), "IMG onerror XSS"),
]

# Command Injection patterns
command_injection_patterns = [
    (re.compile(r"(?i)[;&|]\s*(cat|rm|ls|whoami|id|pwd|curl|wget)\b"), "System command execution"),
    (re.compile(r"(?i)\b(echo|exec|system|shell_exec)\s*\("), "PHP/Shell command functions"),
    (re.compile(r"(?i)\$\(|\`"), "Shell command substitution"),
]

# Path Traversal patterns
path_traversal_patterns = [
    (re.compile(r"(?i)(\.\./|\.\.\\\\|/etc/|/var/|\\\\etc\\\\|\\\\var\\\\)"), "Directory traversal"),
    (re.compile(r"(?i)\b(file://|php://|data://)"), "File protocol access"),
]