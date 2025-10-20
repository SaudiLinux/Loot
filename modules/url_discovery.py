#!/usr/bin/env python3
"""
URL Discovery Module for LOOT - Advanced Web Application Discovery
Author: Sayer Linux (SayerLinux1@gmail.com)
"""

import requests
import re
import time
import random
import urllib.parse
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style
import concurrent.futures
from bs4 import BeautifulSoup
import json
import xml.etree.ElementTree as ET

class URLDiscovery:
    def __init__(self):
        self.timeout = 30
        self.threads = 10
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
        ]
        
        # Common paths to discover
        self.common_paths = [
            # Admin and Management
            'admin', 'administrator', 'manage', 'management', 'dashboard', 'control', 'panel',
            'cpanel', 'webadmin', 'sysadmin', 'moderator', 'moderate',
            
            # Authentication
            'login', 'signin', 'authenticate', 'auth', 'logout', 'signout', 'register',
            'signup', 'create_account', 'forgot_password', 'reset_password',
            
            # API Endpoints
            'api', 'api/v1', 'api/v2', 'rest', 'graphql', 'swagger', 'openapi',
            'api/docs', 'api/documentation', 'swagger.json', 'openapi.json',
            
            # Configuration and Settings
            'config', 'configuration', 'settings', 'preferences', 'options', 'setup',
            'install', 'installation', 'configure', 'admin/config',
            
            # User Management
            'user', 'users', 'profile', 'account', 'member', 'members', 'customer',
            'client', 'admin/user', 'admin/users', 'user/profile',
            
            # Content Management
            'content', 'contents', 'page', 'pages', 'post', 'posts', 'article',
            'articles', 'blog', 'news', 'media', 'upload', 'uploads', 'files',
            'file_manager', 'media_manager', 'gallery', 'images', 'img',
            
            # Database and Backend
            'database', 'db', 'phpmyadmin', 'mysql', 'pgsql', 'sqlite', 'adminer',
            'webadmin', 'phpinfo', 'info', 'php_version', 'server_info',
            
            # Backup and Archives
            'backup', 'backups', 'archive', 'archives', 'old', 'previous', 'bak',
            'temp', 'tmp', 'cache', 'sessions', 'logs', 'log',
            
            # Development and Testing
            'test', 'testing', 'debug', 'development', 'dev', 'staging', 'demo',
            'sandbox', 'playground', 'lab', 'experiment',
            
            # Common Applications
            'wordpress', 'wp-admin', 'wp-login', 'drupal', 'joomla', 'magento',
            'prestashop', 'opencart', 'laravel', 'django', 'rails', 'node',
            
            # Hidden and System Files
            '.htaccess', '.htpasswd', '.git', '.svn', '.env', '.DS_Store',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'humans.txt',
            'security.txt', '.well-known', 'favicon.ico',
            
            # Documentation
            'docs', 'documentation', 'help', 'support', 'faq', 'manual',
            'guide', 'tutorial', 'readme', 'license', 'changelog',
            
            # Services and Tools
            'mail', 'email', 'webmail', 'smtp', 'imap', 'pop', 'ftp', 'sftp',
            'ssh', 'telnet', 'vnc', 'rdp', 'remote', 'console', 'terminal',
            
            # Security and Monitoring
            'security', 'firewall', 'antivirus', 'scan', 'scanner', 'monitor',
            'monitoring', 'analytics', 'tracking', 'stats', 'statistics'
        ]
        
        # File extensions to test
        self.file_extensions = [
            '.php', '.asp', '.aspx', '.jsp', '.html', '.htm', '.js', '.css',
            '.json', '.xml', '.txt', '.log', '.bak', '.backup', '.old',
            '.sql', '.db', '.sqlite', '.config', '.conf', '.ini', '.yml',
            '.yaml', '.properties', '.env', '.git', '.svn', '.htaccess'
        ]
        
        # Common parameters to test
        self.common_parameters = [
            'id', 'page', 'file', 'path', 'url', 'redirect', 'return', 'next',
            'callback', 'jsonp', 'format', 'type', 'action', 'do', 'task',
            'cmd', 'command', 'exec', 'execute', 'run', 'eval', 'code',
            'include', 'require', 'template', 'view', 'content', 'data'
        ]

    def discover_urls(self, target, stealth_mode=True):
        """Main URL discovery function"""
        print(f"{Fore.CYAN}[*] Starting URL discovery on {target}{Style.RESET_ALL}")
        
        results = {
            'target': target,
            'discovered_urls': [],
            'admin_panels': [],
            'api_endpoints': [],
            'hidden_files': [],
            'backup_files': [],
            'sensitive_endpoints': [],
            'parameters': [],
            'subdomains': [],
            'directories': [],
            'files': [],
            'vulnerabilities': []
        }
        
        try:
            # Normalize target URL
            if not target.startswith(('http://', 'https://')):
                target = 'https://' + target
            
            base_domain = urlparse(target).netloc
            
            # Discover URLs using multiple techniques
            print(f"{Fore.YELLOW}[*] Discovering common paths...{Style.RESET_ALL}")
            discovered = self.discover_common_paths(target, stealth_mode)
            results['discovered_urls'].extend(discovered)
            
            print(f"{Fore.YELLOW}[*] Crawling for links...{Style.RESET_ALL}")
            crawled = self.crawl_for_links(target)
            results['discovered_urls'].extend(crawled)
            
            print(f"{Fore.YELLOW}[*] Testing for admin panels...{Style.RESET_ALL}")
            admin_panels = self.find_admin_panels(target)
            results['admin_panels'] = admin_panels
            results['discovered_urls'].extend(admin_panels)
            
            print(f"{Fore.YELLOW}[*] Discovering API endpoints...{Style.RESET_ALL}")
            api_endpoints = self.find_api_endpoints(target)
            results['api_endpoints'] = api_endpoints
            results['discovered_urls'].extend(api_endpoints)
            
            print(f"{Fore.YELLOW}[*] Looking for hidden files...{Style.RESET_ALL}")
            hidden_files = self.find_hidden_files(target)
            results['hidden_files'] = hidden_files
            results['discovered_urls'].extend(hidden_files)
            
            print(f"{Fore.YELLOW}[*] Searching for backup files...{Style.RESET_ALL}")
            backup_files = self.find_backup_files(target)
            results['backup_files'] = backup_files
            results['discovered_urls'].extend(backup_files)
            
            print(f"{Fore.YELLOW}[*] Testing parameters...{Style.RESET_ALL}")
            parameters = self.test_parameters(target)
            results['parameters'] = parameters
            
            print(f"{Fore.YELLOW}[*] Discovering subdomains...{Style.RESET_ALL}")
            subdomains = self.discover_subdomains(target)
            results['subdomains'] = subdomains
            
            # Categorize discovered URLs
            self.categorize_urls(results)
            
            # Create vulnerability entries for sensitive findings
            self.create_vulnerability_entries(results)
            
            # Remove duplicates
            results['discovered_urls'] = list(set(results['discovered_urls']))
            
            print(f"{Fore.GREEN}[+] URL discovery completed! Found {len(results['discovered_urls'])} URLs{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error in URL discovery: {e}{Style.RESET_ALL}")
        
        return results

    def discover_common_paths(self, target, stealth_mode=True):
        """Discover common paths and directories"""
        discovered = []
        
        def check_path(path):
            try:
                session = requests.Session()
                session.headers.update({'User-Agent': random.choice(self.user_agents)})
                
                url = urljoin(target, path)
                response = session.get(url, timeout=self.timeout, allow_redirects=False)
                
                if response.status_code in [200, 401, 403, 301, 302]:
                    result = {
                        'url': url,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('content-type', 'unknown'),
                        'content_length': len(response.content),
                        'discovery_method': 'common_path'
                    }
                    
                    if response.status_code == 200:
                        print(f"{Fore.GREEN}[+] Found: {url} ({response.status_code}){Style.RESET_ALL}")
                    elif response.status_code in [401, 403]:
                        print(f"{Fore.YELLOW}[!] Protected: {url} ({response.status_code}){Style.RESET_ALL}")
                    
                    return result
                
                # Also test with file extensions
                for ext in self.file_extensions:
                    file_url = url + ext
                    response = session.head(file_url, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        result = {
                            'url': file_url,
                            'status_code': response.status_code,
                            'content_type': response.headers.get('content-type', 'unknown'),
                            'content_length': response.headers.get('content-length', 0),
                            'discovery_method': 'file_extension'
                        }
                        print(f"{Fore.GREEN}[+] Found file: {file_url}{Style.RESET_ALL}")
                        return result
                
                return None
                
            except requests.RequestException:
                return None
        
        # Use thread pool for faster discovery
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_path, path) for path in self.common_paths]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result['url'])
                
                if stealth_mode:
                    time.sleep(random.uniform(0.1, 0.5))
        
        return discovered

    def crawl_for_links(self, target):
        """Crawl the target for links"""
        discovered = []
        
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': random.choice(self.user_agents)})
            
            response = session.get(target, timeout=self.timeout)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Find all links
                for link in soup.find_all(['a', 'link', 'script', 'img', 'form']):
                    href = link.get('href') or link.get('src') or link.get('action')
                    
                    if href:
                        absolute_url = urljoin(target, href)
                        
                        # Only include URLs from the same domain
                        if urlparse(absolute_url).netloc == urlparse(target).netloc:
                            discovered.append(absolute_url)
                
                # Find comments that might contain URLs
                comments = soup.find_all(string=lambda text: isinstance(text, str) and ('http' in text or 'www' in text))
                for comment in comments:
                    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', comment)
                    for url in urls:
                        if urlparse(url).netloc == urlparse(target).netloc:
                            discovered.append(url)
                
                # Find JavaScript variables that might contain URLs
                scripts = soup.find_all('script')
                for script in scripts:
                    if script.string:
                        js_urls = re.findall(r'["\']([^"\']*\/(?:api|admin|user|config)[^"\']*)["\']', script.string)
                        for js_url in js_urls:
                            absolute_url = urljoin(target, js_url)
                            if urlparse(absolute_url).netloc == urlparse(target).netloc:
                                discovered.append(absolute_url)
            
            print(f"{Fore.GREEN}[+] Crawled {len(discovered)} URLs from page{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error crawling: {e}{Style.RESET_ALL}")
        
        return discovered

    def find_admin_panels(self, target):
        """Find admin panels and management interfaces"""
        admin_paths = [
            'admin', 'administrator', 'manage', 'management', 'dashboard', 'control',
            'panel', 'cpanel', 'webadmin', 'sysadmin', 'moderator', 'backend',
            'admin.php', 'admin.asp', 'admin.aspx', 'admin.jsp', 'admin.html',
            'login.php', 'login.asp', 'login.aspx', 'login.jsp', 'signin.php',
            'wp-admin', 'wp-login.php', 'drupal/admin', 'joomla/administrator',
            'phpmyadmin', 'mysqladmin', 'adminer', 'webadmin', 'pma'
        ]
        
        discovered = []
        
        def check_admin_path(path):
            try:
                session = requests.Session()
                session.headers.update({'User-Agent': random.choice(self.user_agents)})
                
                url = urljoin(target, path)
                response = session.get(url, timeout=self.timeout, allow_redirects=False)
                
                if response.status_code in [200, 401, 403]:
                    result = {
                        'url': url,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('content-type', 'unknown'),
                        'discovery_method': 'admin_panel'
                    }
                    
                    if response.status_code == 200:
                        print(f"{Fore.GREEN}[+] Admin panel found: {url}{Style.RESET_ALL}")
                    elif response.status_code == 401:
                        print(f"{Fore.YELLOW}[!] Admin panel (auth required): {url}{Style.RESET_ALL}")
                    
                    return result
                
                return None
                
            except requests.RequestException:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(check_admin_path, path) for path in admin_paths]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)
        
        return discovered

    def find_api_endpoints(self, target):
        """Find API endpoints"""
        api_paths = [
            'api', 'api/v1', 'api/v2', 'api/v3', 'rest', 'graphql',
            'swagger', 'swagger.json', 'openapi.json', 'api/docs',
            'api/documentation', 'api/explorer', 'api/console',
            'services', 'service', 'endpoints', 'endpoint'
        ]
        
        discovered = []
        
        def check_api_path(path):
            try:
                session = requests.Session()
                session.headers.update({'User-Agent': random.choice(self.user_agents)})
                
                url = urljoin(target, path)
                
                # Test with different HTTP methods
                for method in ['GET', 'POST', 'OPTIONS']:
                    try:
                        if method == 'GET':
                            response = session.get(url, timeout=self.timeout)
                        elif method == 'POST':
                            response = session.post(url, timeout=self.timeout)
                        elif method == 'OPTIONS':
                            response = session.options(url, timeout=self.timeout)
                        
                        if response.status_code in [200, 401, 403]:
                            result = {
                                'url': url,
                                'status_code': response.status_code,
                                'method': method,
                                'content_type': response.headers.get('content-type', 'unknown'),
                                'discovery_method': 'api_endpoint'
                            }
                            
                            if response.status_code == 200:
                                print(f"{Fore.GREEN}[+] API endpoint: {url} ({method}){Style.RESET_ALL}")
                            
                            return result
                    
                    except requests.RequestException:
                        continue
                
                return None
                
            except Exception:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(check_api_path, path) for path in api_paths]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)
        
        return discovered

    def find_hidden_files(self, target):
        """Find hidden files and directories"""
        hidden_files = [
            '.htaccess', '.htpasswd', '.git/config', '.git/HEAD', '.svn/entries',
            '.DS_Store', '.env', '.env.local', '.env.production', '.env.development',
            'config.php', 'config.inc.php', 'configuration.php', 'settings.php',
            'wp-config.php', 'database.php', 'db.php', 'connection.php',
            'phpinfo.php', 'info.php', 'phpversion.php', 'version.php',
            'error_log', 'error.log', 'access_log', 'access.log',
            'backup.zip', 'backup.tar.gz', 'backup.sql', 'database.sql',
            'site.zip', 'site.tar.gz', 'www.zip', 'public_html.zip',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'humans.txt',
            '.well-known/security.txt', '.well-known/robots.txt',
            'favicon.ico', 'apple-touch-icon.png', 'manifest.json'
        ]
        
        discovered = []
        
        def check_hidden_file(filename):
            try:
                session = requests.Session()
                session.headers.update({'User-Agent': random.choice(self.user_agents)})
                
                url = urljoin(target, filename)
                response = session.head(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    result = {
                        'url': url,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('content-type', 'unknown'),
                        'content_length': response.headers.get('content-length', 0),
                        'discovery_method': 'hidden_file'
                    }
                    
                    print(f"{Fore.GREEN}[+] Hidden file: {filename}{Style.RESET_ALL}")
                    return result
                
                return None
                
            except requests.RequestException:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(check_hidden_file, filename) for filename in hidden_files]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)
        
        return discovered

    def find_backup_files(self, target):
        """Find backup files and old versions"""
        backup_patterns = [
            'backup', 'bak', 'old', 'prev', 'previous', 'copy', 'archive',
            'tmp', 'temp', 'test', 'dev', 'development', 'staging'
        ]
        
        extensions = ['.zip', '.tar', '.tar.gz', '.sql', '.db', '.json', '.xml']
        
        discovered = []
        
        def check_backup_pattern(pattern, ext):
            try:
                session = requests.Session()
                session.headers.update({'User-Agent': random.choice(self.user_agents)})
                
                # Test different backup naming patterns
                backup_names = [
                    f"{pattern}{ext}",
                    f"site{ext}",
                    f"www{ext}",
                    f"public_html{ext}",
                    f"backup_{pattern}{ext}",
                    f"{pattern}_backup{ext}",
                    f"old_{pattern}{ext}",
                    f"{pattern}_old{ext}"
                ]
                
                for backup_name in backup_names:
                    url = urljoin(target, backup_name)
                    response = session.head(url, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        result = {
                            'url': url,
                            'status_code': response.status_code,
                            'content_type': response.headers.get('content-type', 'unknown'),
                            'content_length': response.headers.get('content-length', 0),
                            'discovery_method': 'backup_file'
                        }
                        
                        print(f"{Fore.GREEN}[+] Backup file: {backup_name}{Style.RESET_ALL}")
                        discovered.append(result)
                        break
                
            except requests.RequestException:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            for pattern in backup_patterns[:5]:  # Limit to avoid too many requests
                for ext in extensions:
                    futures.append(executor.submit(check_backup_pattern, pattern, ext))
            
            for future in concurrent.futures.as_completed(futures):
                pass  # Results are added directly to discovered list
        
        return discovered

    def test_parameters(self, target):
        """Test for interesting parameters"""
        parameters = []
        
        # Extract existing parameters from discovered URLs
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': random.choice(self.user_agents)})
            
            response = session.get(target, timeout=self.timeout)
            
            if response.status_code == 200:
                # Look for forms and extract parameter names
                soup = BeautifulSoup(response.content, 'html.parser')
                
                for form in soup.find_all('form'):
                    for input_field in form.find_all(['input', 'select', 'textarea']):
                        param_name = input_field.get('name')
                        if param_name:
                            parameters.append({
                                'name': param_name,
                                'type': input_field.get('type', 'text'),
                                'form_action': form.get('action', ''),
                                'discovery_method': 'form_analysis'
                            })
                
                # Look for JavaScript that might reveal parameters
                scripts = soup.find_all('script')
                for script in scripts:
                    if script.string:
                        # Find AJAX calls and API endpoints
                        ajax_params = re.findall(r'\$\.(?:get|post|ajax)\s*\(\s*["\']([^"\']+)["\'].*?\{([^}]+)\}', script.string, re.DOTALL)
                        for endpoint, params in ajax_params:
                            param_matches = re.findall(r'(\w+)\s*:\s*([^,\}]+)', params)
                            for param_name, param_value in param_matches:
                                parameters.append({
                                    'name': param_name,
                                    'endpoint': endpoint,
                                    'value': param_value.strip(),
                                    'discovery_method': 'javascript_analysis'
                                })
                
                print(f"{Fore.GREEN}[+] Found {len(parameters)} parameters from page analysis{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error analyzing parameters: {e}{Style.RESET_ALL}")
        
        return parameters

    def discover_subdomains(self, target):
        """Discover subdomains"""
        subdomains = []
        
        try:
            base_domain = urlparse(target).netloc
            
            # Common subdomain patterns
            subdomain_prefixes = [
                'www', 'api', 'admin', 'mail', 'ftp', 'blog', 'shop', 'store',
                'app', 'mobile', 'dev', 'test', 'staging', 'demo', 'beta',
                'support', 'help', 'docs', 'wiki', 'forum', 'community',
                'cdn', 'static', 'media', 'assets', 'images', 'img', 'css',
                'js', 'scripts', 'assets', 'files', 'uploads', 'downloads',
                'secure', 'ssl', 'vpn', 'remote', 'ssh', 'sftp', 'webmail',
                'email', 'smtp', 'imap', 'pop', 'mx', 'ns1', 'ns2', 'dns'
            ]
            
            def check_subdomain(prefix):
                try:
                    subdomain = f"{prefix}.{base_domain}"
                    url = f"https://{subdomain}"
                    
                    session = requests.Session()
                    session.headers.update({'User-Agent': random.choice(self.user_agents)})
                    
                    response = session.head(url, timeout=self.timeout)
                    
                    if response.status_code in [200, 301, 302, 401, 403]:
                        result = {
                            'subdomain': subdomain,
                            'url': url,
                            'status_code': response.status_code,
                            'discovery_method': 'subdomain_bruteforce'
                        }
                        
                        print(f"{Fore.GREEN}[+] Subdomain found: {subdomain}{Style.RESET_ALL}")
                        return result
                    
                    return None
                    
                except requests.RequestException:
                    return None
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(check_subdomain, prefix) for prefix in subdomain_prefixes]
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        subdomains.append(result)
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error discovering subdomains: {e}{Style.RESET_ALL}")
        
        return subdomains

    def categorize_urls(self, results):
        """Categorize discovered URLs"""
        for url_info in results['discovered_urls']:
            if isinstance(url_info, dict):
                url = url_info['url']
                
                # Categorize by path patterns
                if any(admin_word in url.lower() for admin_word in ['admin', 'manage', 'control', 'panel']):
                    results['admin_panels'].append(url_info)
                elif any(api_word in url.lower() for api_word in ['api', 'rest', 'graphql', 'swagger']):
                    results['api_endpoints'].append(url_info)
                elif any(sensitive_word in url.lower() for sensitive_word in ['.env', 'config', 'backup', '.htaccess']):
                    results['sensitive_endpoints'].append(url_info)
                elif any(dir_word in url.lower() for dir_word in ['upload', 'files', 'temp', 'cache']):
                    results['directories'].append(url_info)
                elif any(file_ext in url.lower() for file_ext in ['.php', '.asp', '.jsp', '.html']):
                    results['files'].append(url_info)

    def create_vulnerability_entries(self, results):
        """Create vulnerability entries for sensitive findings"""
        vuln_id = 1
        
        # Check for exposed admin panels
        for admin_panel in results['admin_panels']:
            if isinstance(admin_panel, dict) and admin_panel.get('status_code') == 200:
                vuln = {
                    'id': f'url_admin_exposed_{vuln_id}',
                    'name': 'Admin Panel Exposed',
                    'severity': 'high',
                    'description': f'Admin panel is accessible at {admin_panel["url"]}',
                    'location': admin_panel['url'],
                    'type': 'information_disclosure',
                    'proof': f'HTTP {admin_panel.get("status_code", "unknown")} response',
                    'recommendation': 'Restrict access to admin panels or implement proper authentication'
                }
                results['vulnerabilities'].append(vuln)
                vuln_id += 1
        
        # Check for exposed backup files
        for backup_file in results['backup_files']:
            if isinstance(backup_file, dict):
                vuln = {
                    'id': f'url_backup_exposed_{vuln_id}',
                    'name': 'Backup File Exposed',
                    'severity': 'high',
                    'description': f'Backup file is accessible at {backup_file["url"]}',
                    'location': backup_file['url'],
                    'type': 'information_disclosure',
                    'proof': f'HTTP {backup_file.get("status_code", "unknown")} response',
                    'recommendation': 'Remove backup files from public access'
                }
                results['vulnerabilities'].append(vuln)
                vuln_id += 1
        
        # Check for exposed hidden files
        for hidden_file in results['hidden_files']:
            if isinstance(hidden_file, dict):
                vuln = {
                    'id': f'url_hidden_exposed_{vuln_id}',
                    'name': 'Hidden File Exposed',
                    'severity': 'medium',
                    'description': f'Hidden file is accessible at {hidden_file["url"]}',
                    'location': hidden_file['url'],
                    'type': 'information_disclosure',
                    'proof': f'HTTP {hidden_file.get("status_code", "unknown")} response',
                    'recommendation': 'Remove hidden files from public access or properly secure them'
                }
                results['vulnerabilities'].append(vuln)
                vuln_id += 1

    def scan_target(self, target, stealth_mode=True):
        """Alias for discover_urls to maintain compatibility"""
        return self.discover_urls(target, stealth_mode)