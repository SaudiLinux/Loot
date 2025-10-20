#!/usr/bin/env python3
"""
Reconnaissance Module - Advanced Information Gathering
Author: Sayer Linux (SayerLinux1@gmail.com)
Description: Comprehensive reconnaissance and information gathering module
"""

import requests
import socket
import ssl
import dns.resolver
import dns.reversename
import json
import time
import concurrent.futures
import re
import random
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style

class ReconModule:
    """Advanced reconnaissance and information gathering module"""
    
    def __init__(self, timeout=30, threads=10):
        self.timeout = timeout
        self.threads = threads
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        
        # Common paths for discovery
        self.common_paths = [
            'admin', 'administrator', 'wp-admin', 'dashboard', 'control', 'panel',
            'login', 'signin', 'sign_in', 'log_in', 'auth', 'authenticate',
            'api', 'api/v1', 'api/v2', 'rest', 'graphql', 'swagger', 'docs',
            'backup', 'backups', 'old', 'temp', 'tmp', 'test', 'dev', 'development',
            'config', 'configuration', 'settings', 'env', 'environment',
            'phpinfo', 'info', 'phpmyadmin', 'mysql', 'database',
            'uploads', 'upload', 'files', 'documents', 'media',
            '.git', '.svn', '.htaccess', 'robots.txt', 'sitemap.xml',
            'error', 'errors', 'logs', 'debug', 'trace'
        ]
        
        # Backup file extensions
        self.backup_extensions = ['.bak', '.backup', '.old', '.orig', '.save', '.copy', '.tmp', '.swp', '.swo']
        
        # Common subdomains
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
            'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'docs',
            'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web'
        ]
    
    def scan(self, target):
        """Perform comprehensive reconnaissance on target"""
        print(f"{Fore.GREEN}[+] Starting comprehensive reconnaissance on {target}{Style.RESET_ALL}")
        
        # Parse target URL
        parsed = urlparse(target)
        domain = parsed.netloc
        
        recon_results = {
            'target': target,
            'domain': domain,
            'timestamp': time.time(),
            'dns_info': {},
            'ssl_info': {},
            'server_info': {},
            'subdomains': [],
            'admin_panels': [],
            'backup_files': [],
            'hidden_files': [],
            'error_pages': [],
            'technology_stack': {},
            'vulnerabilities': []
        }
        
        try:
            # DNS Information Gathering
            print(f"{Fore.YELLOW}[*] Gathering DNS information{Style.RESET_ALL}")
            recon_results['dns_info'] = self.gather_dns_info(domain)
            
            # SSL Certificate Analysis
            print(f"{Fore.YELLOW}[*] Analyzing SSL certificate{Style.RESET_ALL}")
            recon_results['ssl_info'] = self.analyze_ssl_certificate(domain)
            
            # Server Information Detection
            print(f"{Fore.YELLOW}[*] Detecting server information{Style.RESET_ALL}")
            recon_results['server_info'] = self.detect_server_info(target)
            
            # Subdomain Enumeration
            print(f"{Fore.YELLOW}[*] Enumerating subdomains{Style.RESET_ALL}")
            recon_results['subdomains'] = self.enumerate_subdomains(domain)
            
            # Admin Panel Discovery
            print(f"{Fore.YELLOW}[*] Discovering admin panels{Style.RESET_ALL}")
            recon_results['admin_panels'] = self.discover_admin_panels(target)
            
            # Backup File Discovery
            print(f"{Fore.YELLOW}[*] Searching for backup files{Style.RESET_ALL}")
            recon_results['backup_files'] = self.discover_backup_files(target)
            
            # Hidden File Discovery
            print(f"{Fore.YELLOW}[*] Discovering hidden files{Style.RESET_ALL}")
            recon_results['hidden_files'] = self.discover_hidden_files(target)
            
            # Error Page Analysis
            print(f"{Fore.YELLOW}[*] Analyzing error pages{Style.RESET_ALL}")
            recon_results['error_pages'] = self.analyze_error_pages(target)
            
            # Technology Stack Detection
            print(f"{Fore.YELLOW}[*] Detecting technology stack{Style.RESET_ALL}")
            recon_results['technology_stack'] = self.detect_technology_stack(target)
            
            # Generate vulnerability findings
            recon_results['vulnerabilities'] = self.generate_vulnerability_findings(recon_results)
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error during reconnaissance: {e}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] Reconnaissance completed successfully{Style.RESET_ALL}")
        return recon_results
    
    def gather_dns_info(self, domain):
        """Gather comprehensive DNS information"""
        dns_info = {}
        
        try:
            # A Record
            try:
                answers = dns.resolver.resolve(domain, 'A')
                dns_info['A_records'] = [str(rdata) for rdata in answers]
            except:
                dns_info['A_records'] = []
            
            # AAAA Record (IPv6)
            try:
                answers = dns.resolver.resolve(domain, 'AAAA')
                dns_info['AAAA_records'] = [str(rdata) for rdata in answers]
            except:
                dns_info['AAAA_records'] = []
            
            # MX Record
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                dns_info['MX_records'] = [{'preference': rdata.preference, 'exchange': str(rdata.exchange)} for rdata in answers]
            except:
                dns_info['MX_records'] = []
            
            # NS Record
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                dns_info['NS_records'] = [str(rdata) for rdata in answers]
            except:
                dns_info['NS_records'] = []
            
            # TXT Record
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                dns_info['TXT_records'] = [str(rdata) for rdata in answers]
            except:
                dns_info['TXT_records'] = []
            
            # CNAME Record
            try:
                answers = dns.resolver.resolve(domain, 'CNAME')
                dns_info['CNAME_records'] = [str(rdata) for rdata in answers]
            except:
                dns_info['CNAME_records'] = []
            
            # SOA Record
            try:
                answers = dns.resolver.resolve(domain, 'SOA')
                for rdata in answers:
                    dns_info['SOA_record'] = {
                        'primary_ns': str(rdata.mname),
                        'responsible_email': str(rdata.rname),
                        'serial': rdata.serial,
                        'refresh': rdata.refresh,
                        'retry': rdata.retry,
                        'expire': rdata.expire,
                        'minimum': rdata.minimum
                    }
            except:
                dns_info['SOA_record'] = {}
            
            # Reverse DNS lookup
            try:
                if dns_info['A_records']:
                    ip = dns_info['A_records'][0]
                    reverse_name = dns.reversename.from_address(ip)
                    reverse_answer = dns.resolver.resolve(reverse_name, 'PTR')
                    dns_info['reverse_dns'] = [str(rdata) for rdata in reverse_answer]
            except:
                dns_info['reverse_dns'] = []
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error gathering DNS info: {e}{Style.RESET_ALL}")
        
        return dns_info
    
    def analyze_ssl_certificate(self, domain):
        """Analyze SSL certificate information"""
        ssl_info = {}
        
        try:
            context = ssl.create_default_context()
            
            # Try different ports
            for port in [443, 8443, 8080]:
                try:
                    with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            cert = ssock.getpeercert()
                            
                            ssl_info = {
                                'port': port,
                                'subject': dict(x[0] for x in cert['subject']),
                                'issuer': dict(x[0] for x in cert['issuer']),
                                'version': cert['version'],
                                'serial_number': cert['serialNumber'],
                                'not_before': cert['notBefore'],
                                'not_after': cert['notAfter'],
                                'san': [x[1] for x in cert.get('subjectAltName', []) if x[0] == 'DNS'],
                                'cipher': ssock.cipher(),
                                'protocol': ssock.version()
                            }
                            
                            # Check certificate validity
                            from datetime import datetime
                            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            ssl_info['expired'] = datetime.now() > not_after
                            
                            break
                            
                except:
                    continue
        
        except Exception as e:
            print(f"{Fore.RED}[-] Error analyzing SSL certificate: {e}{Style.RESET_ALL}")
        
        return ssl_info
    
    def detect_server_info(self, target):
        """Detect server information and headers"""
        server_info = {}
        
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': random.choice(self.user_agents)})
            
            response = session.get(target, timeout=self.timeout)
            
            # Extract server information from headers
            headers = response.headers
            server_info = {
                'server': headers.get('Server', 'Unknown'),
                'powered_by': headers.get('X-Powered-By', ''),
                'content_type': headers.get('Content-Type', ''),
                'content_length': headers.get('Content-Length', ''),
                'status_code': response.status_code,
                'cookies': dict(response.cookies),
                'headers': dict(headers)
            }
            
            # Check for security headers
            security_headers = {
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'X-XSS-Protection': headers.get('X-XSS-Protection'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'Referrer-Policy': headers.get('Referrer-Policy'),
                'Permissions-Policy': headers.get('Permissions-Policy')
            }
            
            server_info['security_headers'] = security_headers
            
            # Check for common server technologies
            server_technologies = []
            server_header = server_info['server'].lower()
            powered_by = server_info['powered_by'].lower()
            
            if 'apache' in server_header:
                server_technologies.append('Apache')
            if 'nginx' in server_header:
                server_technologies.append('Nginx')
            if 'iis' in server_header:
                server_technologies.append('IIS')
            if 'php' in powered_by:
                server_technologies.append('PHP')
            if 'asp.net' in powered_by:
                server_technologies.append('ASP.NET')
            if 'express' in powered_by:
                server_technologies.append('Express.js')
            
            server_info['detected_technologies'] = server_technologies
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error detecting server info: {e}{Style.RESET_ALL}")
        
        return server_info
    
    def enumerate_subdomains(self, domain):
        """Enumerate subdomains using various techniques"""
        discovered_subdomains = []
        
        try:
            # Method 1: DNS brute force with common subdomains
            def check_subdomain(subdomain):
                full_domain = f"{subdomain}.{domain}"
                try:
                    answers = dns.resolver.resolve(full_domain, 'A')
                    return {
                        'subdomain': full_domain,
                        'ip_addresses': [str(rdata) for rdata in answers],
                        'method': 'dns_bruteforce'
                    }
                except:
                    return None
            
            # Use thread pool for faster enumeration
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(check_subdomain, sub) for sub in self.common_subdomains]
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        discovered_subdomains.append(result)
                        print(f"{Fore.GREEN}[+] Found subdomain: {result['subdomain']} -> {result['ip_addresses'][0]}{Style.RESET_ALL}")
            
            # Method 2: Certificate transparency logs (if available)
            try:
                cert_url = f"https://crt.sh/?q=%.{domain}&output=json"
                response = requests.get(cert_url, timeout=self.timeout)
                
                if response.status_code == 200:
                    cert_data = response.json()
                    for entry in cert_data:
                        subdomain = entry.get('name_value', '').strip()
                        if subdomain and subdomain not in [s['subdomain'] for s in discovered_subdomains]:
                            # Verify subdomain exists
                            try:
                                answers = dns.resolver.resolve(subdomain, 'A')
                                discovered_subdomains.append({
                                    'subdomain': subdomain,
                                    'ip_addresses': [str(rdata) for rdata in answers],
                                    'method': 'certificate_transparency'
                                })
                                print(f"{Fore.GREEN}[+] Found subdomain via CT: {subdomain}{Style.RESET_ALL}")
                            except:
                                pass
            except:
                pass
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error enumerating subdomains: {e}{Style.RESET_ALL}")
        
        return discovered_subdomains
    
    def discover_admin_panels(self, target):
        """Discover admin panels and management interfaces"""
        admin_panels = []
        
        try:
            admin_paths = [
                'admin', 'administrator', 'admin.php', 'admin.html', 'admin.asp',
                'wp-admin', 'wp-login.php', 'dashboard', 'control', 'panel',
                'cpanel', 'webadmin', 'manage', 'management', 'backend',
                'cms', 'administrator.php', 'administrator.html', 'administrator.asp',
                'login', 'logon', 'signin', 'sign_in', 'auth', 'authenticate',
                'wp-admin/', 'admin/', 'administrator/', 'dashboard/', 'control/'
            ]
            
            def check_admin_path(path):
                try:
                    session = requests.Session()
                    session.headers.update({'User-Agent': random.choice(self.user_agents)})
                    
                    url = urljoin(target, path)
                    response = session.get(url, timeout=self.timeout, allow_redirects=False)
                    
                    # Check for admin panel indicators
                    if response.status_code in [200, 401, 403]:
                        # Check response content for admin indicators
                        content = response.text.lower()
                        admin_indicators = [
                            'admin', 'login', 'password', 'username', 'dashboard',
                            'control panel', 'management', 'authentication',
                            'administrator', 'sign in', 'log in'
                        ]
                        
                        for indicator in admin_indicators:
                            if indicator in content:
                                return {
                                    'url': url,
                                    'status_code': response.status_code,
                                    'title': self.extract_page_title(response.text),
                                    'type': 'admin_panel',
                                    'confidence': 'high'
                                }
                    
                    return None
                    
                except:
                    return None
            
            # Use thread pool for faster discovery
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(check_admin_path, path) for path in admin_paths]
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result and result not in admin_panels:
                        admin_panels.append(result)
                        print(f"{Fore.GREEN}[+] Found admin panel: {result['url']} (Status: {result['status_code']}){Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error discovering admin panels: {e}{Style.RESET_ALL}")
        
        return admin_panels
    
    def discover_backup_files(self, target):
        """Discover backup files and copies"""
        backup_files = []
        
        try:
            # Parse target to get base filename
            parsed = urlparse(target)
            path = parsed.path
            base_name = path.split('/')[-1] if path.split('/')[-1] else 'index'
            
            # Generate backup file variations
            backup_variations = []
            
            # Original file with backup extensions
            for ext in self.backup_extensions:
                backup_variations.append(f"{base_name}{ext}")
                if '.' in base_name:
                    name, ext_orig = base_name.rsplit('.', 1)
                    backup_variations.append(f"{name}{ext}.{ext_orig}")
            
            # Common backup patterns
            backup_patterns = [
                f"{base_name}.backup", f"{base_name}.old", f"{base_name}.copy",
                f"{base_name}.orig", f"{base_name}.save", f"{base_name}.tmp",
                f"backup_{base_name}", f"old_{base_name}", f"copy_{base_name}",
                f"{base_name}~", f".{base_name}.swp", f".{base_name}.swo"
            ]
            
            backup_variations.extend(backup_patterns)
            
            def check_backup_file(filename):
                try:
                    session = requests.Session()
                    session.headers.update({'User-Agent': random.choice(self.user_agents)})
                    
                    url = urljoin(target, filename)
                    response = session.get(url, timeout=self.timeout)
                    
                    if response.status_code == 200 and len(response.content) > 0:
                        return {
                            'url': url,
                            'size': len(response.content),
                            'content_type': response.headers.get('Content-Type', ''),
                            'last_modified': response.headers.get('Last-Modified', ''),
                            'type': 'backup_file'
                        }
                    
                    return None
                    
                except:
                    return None
            
            # Use thread pool for faster discovery
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(check_backup_file, filename) for filename in backup_variations]
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result and result not in backup_files:
                        backup_files.append(result)
                        print(f"{Fore.GREEN}[+] Found backup file: {result['url']} ({result['size']} bytes){Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error discovering backup files: {e}{Style.RESET_ALL}")
        
        return backup_files
    
    def discover_hidden_files(self, target):
        """Discover hidden files and directories"""
        hidden_files = []
        
        try:
            hidden_paths = [
                '.htaccess', '.htpasswd', '.git/config', '.git/HEAD', '.svn/entries',
                '.env', '.DS_Store', 'config.php', 'configuration.php', 'wp-config.php',
                'database.php', 'settings.php', 'config.inc.php', 'php.ini',
                'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
                '.well-known/security.txt', 'security.txt', 'humans.txt'
            ]
            
            def check_hidden_path(path):
                try:
                    session = requests.Session()
                    session.headers.update({'User-Agent': random.choice(self.user_agents)})
                    
                    url = urljoin(target, path)
                    response = session.get(url, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        return {
                            'url': url,
                            'size': len(response.content),
                            'content_type': response.headers.get('Content-Type', ''),
                            'type': 'hidden_file',
                            'sensitive': self.is_sensitive_file(path)
                        }
                    
                    return None
                    
                except:
                    return None
            
            # Use thread pool for faster discovery
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(check_hidden_path, path) for path in hidden_paths]
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result and result not in hidden_files:
                        hidden_files.append(result)
                        sensitivity = "SENSITIVE" if result['sensitive'] else ""
                        print(f"{Fore.GREEN}[+] Found hidden file: {result['url']} {sensitivity}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error discovering hidden files: {e}{Style.RESET_ALL}")
        
        return hidden_files
    
    def analyze_error_pages(self, target):
        """Analyze error pages for information disclosure"""
        error_pages = []
        
        try:
            error_tests = [
                ('nonexistent-page-12345', 404),
                ('../etc/passwd', 400),
                ('<script>alert(1)</script>', 400),
                ('../../../../../../../../etc/passwd', 400)
            ]
            
            for test_path, expected_status in error_tests:
                try:
                    session = requests.Session()
                    session.headers.update({'User-Agent': random.choice(self.user_agents)})
                    
                    url = urljoin(target, test_path)
                    response = session.get(url, timeout=self.timeout)
                    
                    # Analyze error page for information disclosure
                    info_disclosure = self.check_information_disclosure(response.text)
                    
                    if info_disclosure or response.status_code != expected_status:
                        error_pages.append({
                            'url': url,
                            'status_code': response.status_code,
                            'expected_status': expected_status,
                            'title': self.extract_page_title(response.text),
                            'information_disclosure': info_disclosure,
                            'server_header': response.headers.get('Server', ''),
                            'type': 'error_page'
                        })
                        
                        if info_disclosure:
                            print(f"{Fore.YELLOW}[!] Information disclosure detected in error page: {url}{Style.RESET_ALL}")
                
                except:
                    continue
        
        except Exception as e:
            print(f"{Fore.RED}[-] Error analyzing error pages: {e}{Style.RESET_ALL}")
        
        return error_pages
    
    def detect_technology_stack(self, target):
        """Detect technology stack and frameworks"""
        tech_stack = {}
        
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': random.choice(self.user_agents)})
            
            response = session.get(target, timeout=self.timeout)
            
            # Analyze headers for technology indicators
            headers = response.headers
            tech_indicators = []
            
            # Web servers
            server = headers.get('Server', '').lower()
            if 'apache' in server:
                tech_indicators.append('Apache HTTP Server')
            if 'nginx' in server:
                tech_indicators.append('Nginx')
            if 'iis' in server:
                tech_indicators.append('Microsoft IIS')
            if 'tomcat' in server:
                tech_indicators.append('Apache Tomcat')
            
            # Programming languages and frameworks
            powered_by = headers.get('X-Powered-By', '').lower()
            if 'php' in powered_by:
                tech_indicators.append('PHP')
            if 'asp.net' in powered_by:
                tech_indicators.append('ASP.NET')
            if 'express' in powered_by:
                tech_indicators.append('Express.js')
            if 'django' in powered_by:
                tech_indicators.append('Django')
            if 'flask' in powered_by:
                tech_indicators.append('Flask')
            
            # Content management systems
            content = response.text.lower()
            if 'wp-content' in content or 'wordpress' in content:
                tech_indicators.append('WordPress')
            if 'drupal' in content:
                tech_indicators.append('Drupal')
            if 'joomla' in content:
                tech_indicators.append('Joomla')
            if 'magento' in content:
                tech_indicators.append('Magento')
            
            # JavaScript frameworks
            if 'react' in content:
                tech_indicators.append('React')
            if 'angular' in content:
                tech_indicators.append('Angular')
            if 'vue.js' in content or 'vuejs' in content:
                tech_indicators.append('Vue.js')
            if 'jquery' in content:
                tech_indicators.append('jQuery')
            if 'bootstrap' in content:
                tech_indicators.append('Bootstrap')
            
            # Database indicators
            if 'mysql' in content or 'mysqli' in content:
                tech_indicators.append('MySQL')
            if 'postgresql' in content:
                tech_indicators.append('PostgreSQL')
            if 'mongodb' in content:
                tech_indicators.append('MongoDB')
            if 'sqlite' in content:
                tech_indicators.append('SQLite')
            
            # Check for specific files that indicate technologies
            tech_files = [
                ('wp-json/wp/v2/', 'WordPress REST API'),
                ('xmlrpc.php', 'WordPress XML-RPC'),
                ('.git/HEAD', 'Git Repository'),
                ('package.json', 'Node.js/npm'),
                ('composer.json', 'PHP Composer'),
                ('requirements.txt', 'Python pip'),
                ('Gemfile', 'Ruby Bundler')
            ]
            
            detected_files = []
            for file_path, tech_name in tech_files:
                try:
                    file_url = urljoin(target, file_path)
                    file_response = session.get(file_url, timeout=self.timeout)
                    if file_response.status_code == 200:
                        detected_files.append({
                            'file': file_path,
                            'technology': tech_name,
                            'url': file_url
                        })
                        if tech_name not in tech_indicators:
                            tech_indicators.append(tech_name)
                except:
                    continue
            
            tech_stack = {
                'detected_technologies': list(set(tech_indicators)),
                'detected_files': detected_files,
                'server_header': headers.get('Server', ''),
                'powered_by_header': headers.get('X-Powered-By', ''),
                'content_type': headers.get('Content-Type', ''),
                'framework_version': self.extract_framework_version(response.text)
            }
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error detecting technology stack: {e}{Style.RESET_ALL}")
        
        return tech_stack
    
    def extract_page_title(self, html_content):
        """Extract page title from HTML content"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            title = soup.find('title')
            return title.get_text().strip() if title else 'No Title'
        except:
            return 'No Title'
    
    def is_sensitive_file(self, filepath):
        """Check if a file is sensitive"""
        sensitive_patterns = [
            'config', 'password', 'passwd', 'secret', 'key', 'credential',
            'database', 'db', 'sql', 'backup', 'dump', 'env', 'environment'
        ]
        
        filepath_lower = filepath.lower()
        for pattern in sensitive_patterns:
            if pattern in filepath_lower:
                return True
        
        return False
    
    def check_information_disclosure(self, content):
        """Check for information disclosure in content"""
        disclosure_patterns = [
            'mysql_error', 'mysql_fetch_array', 'ORA-', 'Oracle error',
            'Microsoft OLE DB Provider', 'ODBC SQL Server Driver',
            'PostgreSQL query failed', 'SQLite error',
            'Warning:', 'Fatal error:', 'Parse error:', 'Notice:',
            'Stack trace:', 'Call stack:', 'Exception:',
            '/var/www/', '/home/', '/etc/', 'C:\\', 'D:\\',
            'localhost', '127.0.0.1', '::1', '0.0.0.0'
        ]
        
        content_lower = content.lower()
        findings = []
        
        for pattern in disclosure_patterns:
            if pattern.lower() in content_lower:
                findings.append(pattern)
        
        return findings if findings else None
    
    def extract_framework_version(self, content):
        """Extract framework version from content"""
        version_patterns = [
            r'WordPress ([0-9]+\.[0-9]+\.[0-9]+)',
            r'jQuery v([0-9]+\.[0-9]+\.[0-9]+)',
            r'Bootstrap v([0-9]+\.[0-9]+\.[0-9]+)',
            r'AngularJS v([0-9]+\.[0-9]+\.[0-9]+)',
            r'React v([0-9]+\.[0-9]+\.[0-9]+)',
            r'PHP/([0-9]+\.[0-9]+\.[0-9]+)',
            r'Apache/([0-9]+\.[0-9]+\.[0-9]+)',
            r'nginx/([0-9]+\.[0-9]+\.[0-9]+)'
        ]
        
        versions = []
        for pattern in version_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            versions.extend(matches)
        
        return versions
    
    def generate_vulnerability_findings(self, recon_results):
        """Generate vulnerability findings based on reconnaissance results"""
        vulnerabilities = []
        
        # Check for missing security headers
        server_info = recon_results.get('server_info', {})
        security_headers = server_info.get('security_headers', {})
        
        missing_headers = []
        important_headers = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy'
        ]
        
        for header in important_headers:
            if not security_headers.get(header):
                missing_headers.append(header)
        
        if missing_headers:
            vulnerabilities.append({
                'id': 'recon_001',
                'name': 'Missing Security Headers',
                'severity': 'medium',
                'description': f'Missing important security headers: {", ".join(missing_headers)}',
                'location': recon_results['target'],
                'type': 'misconfiguration',
                'recommendation': f'Implement the following security headers: {", ".join(missing_headers)}',
                'confidence': 'high'
            })
        
        # Check for exposed admin panels
        admin_panels = recon_results.get('admin_panels', [])
        for panel in admin_panels:
            if panel['status_code'] == 200:
                vulnerabilities.append({
                    'id': f'recon_002_{len(vulnerabilities)}',
                    'name': 'Exposed Admin Panel',
                    'severity': 'high',
                    'description': f'Admin panel accessible without authentication: {panel["url"]}',
                    'location': panel['url'],
                    'type': 'information_disclosure',
                    'recommendation': 'Restrict access to admin panels using IP whitelisting or additional authentication',
                    'confidence': 'high'
                })
        
        # Check for backup files
        backup_files = recon_results.get('backup_files', [])
        for backup in backup_files:
            vulnerabilities.append({
                'id': f'recon_003_{len(vulnerabilities)}',
                'name': 'Exposed Backup File',
                'severity': 'high',
                'description': f'Sensitive backup file exposed: {backup["url"]}',
                'location': backup['url'],
                'type': 'information_disclosure',
                'recommendation': 'Remove backup files from web-accessible directories',
                'confidence': 'high'
            })
        
        # Check for hidden files
        hidden_files = recon_results.get('hidden_files', [])
        for hidden in hidden_files:
            if hidden.get('sensitive'):
                vulnerabilities.append({
                    'id': f'recon_004_{len(vulnerabilities)}',
                    'name': 'Exposed Sensitive File',
                    'severity': 'high',
                    'description': f'Sensitive configuration file exposed: {hidden["url"]}',
                    'location': hidden['url'],
                    'type': 'information_disclosure',
                    'recommendation': 'Move sensitive configuration files outside web root',
                    'confidence': 'high'
                })
        
        # Check for information disclosure in error pages
        error_pages = recon_results.get('error_pages', [])
        for error in error_pages:
            if error.get('information_disclosure'):
                vulnerabilities.append({
                    'id': f'recon_005_{len(vulnerabilities)}',
                    'name': 'Information Disclosure in Error Page',
                    'severity': 'medium',
                    'description': f'Error page reveals sensitive information: {error["url"]}',
                    'location': error['url'],
                    'type': 'information_disclosure',
                    'recommendation': 'Configure custom error pages that do not reveal system information',
                    'confidence': 'medium'
                })
        
        # Check for expired SSL certificate
        ssl_info = recon_results.get('ssl_info', {})
        if ssl_info.get('expired'):
            vulnerabilities.append({
                'id': 'recon_006',
                'name': 'Expired SSL Certificate',
                'severity': 'high',
                'description': 'SSL certificate has expired',
                'location': recon_results['target'],
                'type': 'cryptographic',
                'recommendation': 'Renew SSL certificate immediately',
                'confidence': 'high'
            })
        
        # Check for weak SSL configuration
        if ssl_info.get('protocol') and 'TLSv1.0' in ssl_info['protocol']:
            vulnerabilities.append({
                'id': 'recon_007',
                'name': 'Weak SSL/TLS Protocol',
                'severity': 'high',
                'description': f'Weak SSL/TLS protocol in use: {ssl_info["protocol"]}',
                'location': recon_results['target'],
                'type': 'cryptographic',
                'recommendation': 'Upgrade to TLS 1.2 or higher',
                'confidence': 'high'
            })
        
        return vulnerabilities