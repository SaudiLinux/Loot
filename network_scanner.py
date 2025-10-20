#!/usr/bin/env python3
"""
Advanced Network Scanner Module
Author: Sayer Linux (SayerLinux1@gmail.com)
Description: Comprehensive network scanning and enumeration capabilities
"""

import socket
import threading
import time
import json
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
import subprocess
import platform
import struct
import random

class AdvancedNetworkScanner:
    """Advanced network scanning and enumeration module"""
    
    def __init__(self, timeout=3, threads=100):
        self.timeout = timeout
        self.threads = threads
        self.results = {
            'hosts': {},
            'open_ports': {},
            'services': {},
            'os_detection': {},
            'vulnerabilities': []
        }
        
        # Common ports and their services
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'RPC',
            139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch'
        }
        
        # Vulnerability signatures
        self.vulnerability_signatures = {
            'FTP': ['Anonymous login allowed', 'Weak authentication'],
            'SSH': ['Weak key exchange', 'Old protocol version'],
            'Telnet': ['Unencrypted communication', 'Weak authentication'],
            'SMTP': ['Open relay', 'Weak authentication'],
            'SMB': ['Anonymous access', 'Weak authentication'],
            'RDP': ['Weak encryption', 'BlueKeep vulnerability'],
            'MySQL': ['Weak authentication', 'Anonymous access'],
            'MSSQL': ['Weak authentication', 'xp_cmdshell enabled']
        }
    
    def scan_host(self, host, ports=None):
        """Scan a single host"""
        print(f"{Fore.YELLOW}[*] Scanning host: {host}{Style.RESET_ALL}")
        
        if ports is None:
            ports = list(self.common_ports.keys())
        
        open_ports = []
        services = []
        
        # Use threading for faster scanning
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(self.check_port, host, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open = future.result()
                    if is_open:
                        open_ports.append(port)
                        service_info = self.identify_service(host, port)
                        services.append(service_info)
                        print(f"{Fore.GREEN}[+] Port {port} is open - {service_info['service']}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[-] Error scanning port {port}: {e}{Style.RESET_ALL}")
        
        # Perform additional enumeration
        host_info = {
            'ip': host,
            'open_ports': open_ports,
            'services': services,
            'os_info': self.detect_os(host),
            'vulnerabilities': self.check_vulnerabilities(services)
        }
        
        return host_info
    
    def check_port(self, host, port):
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def identify_service(self, host, port):
        """Identify service running on port"""
        service_name = self.common_ports.get(port, 'Unknown')
        version = 'Unknown'
        banner = ''
        
        try:
            # Try to grab banner
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Send probe based on port
            if port in [80, 8080]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                sock.send(b"USER anonymous\r\n")
            elif port == 22:
                sock.send(b"SSH-2.0-OpenSSH_7.4\r\n")
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Extract version information
            if banner:
                version = self.extract_version(banner, service_name)
        except Exception as e:
            banner = f"Error: {str(e)}"
        
        return {
            'port': port,
            'service': service_name,
            'version': version,
            'banner': banner,
            'state': 'open'
        }
    
    def extract_version(self, banner, service):
        """Extract version information from banner"""
        if service == 'HTTP':
            if 'Server:' in banner:
                return banner.split('Server:')[1].split('\r\n')[0].strip()
        elif service == 'SSH':
            lines = banner.split('\n')
            if lines:
                return lines[0]
        elif service == 'FTP':
            lines = banner.split('\n')
            if lines:
                return lines[0]
        
        return 'Unknown'
    
    def detect_os(self, host):
        """Attempt OS detection using various techniques"""
        os_info = {'os': 'Unknown', 'method': 'None', 'confidence': 'Low'}
        
        try:
            # Method 1: TTL-based detection
            ttl = self.get_ttl(host)
            if ttl:
                if ttl <= 64:
                    os_info.update({'os': 'Linux/Unix', 'method': 'TTL', 'confidence': 'Medium'})
                elif ttl <= 128:
                    os_info.update({'os': 'Windows', 'method': 'TTL', 'confidence': 'Medium'})
            
            # Method 2: TCP/IP fingerprinting
            tcp_fingerprint = self.tcp_fingerprint(host)
            if tcp_fingerprint:
                os_info.update({'tcp_fingerprint': tcp_fingerprint})
            
            # Method 3: Service-based detection
            services = self.results.get('services', {}).get(host, [])
            for service in services:
                if service['service'] == 'SMB' and service['port'] == 445:
                    if 'Windows' not in os_info['os']:
                        os_info.update({'os': 'Windows', 'method': 'SMB Service', 'confidence': 'High'})
                elif service['service'] == 'SSH' and 'OpenSSH' in service['banner']:
                    if 'Linux' not in os_info['os']:
                        os_info.update({'os': 'Linux/Unix', 'method': 'SSH Banner', 'confidence': 'High'})
        
        except Exception as e:
            os_info['error'] = str(e)
        
        return os_info
    
    def get_ttl(self, host):
        """Get TTL value using ping"""
        try:
            system = platform.system().lower()
            if system == 'windows':
                cmd = ['ping', '-n', '1', host]
            else:
                cmd = ['ping', '-c', '1', host]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            output = result.stdout
            
            # Extract TTL from output
            if 'ttl=' in output.lower():
                ttl_line = [line for line in output.split('\n') if 'ttl=' in line.lower()][0]
                ttl = int(ttl_line.split('ttl=')[1].split()[0])
                return ttl
        except Exception:
            pass
        return None
    
    def tcp_fingerprint(self, host):
        """Basic TCP fingerprinting"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Try to connect and analyze response
            result = sock.connect_ex((host, 80))
            if result == 0:
                # Send a crafted packet and analyze response
                sock.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
                response = sock.recv(1024)
                sock.close()
                
                # Basic fingerprinting based on response
                if b'IIS' in response:
                    return {'server': 'IIS', 'os_family': 'Windows'}
                elif b'Apache' in response:
                    return {'server': 'Apache', 'os_family': 'Linux/Unix'}
                elif b'nginx' in response:
                    return {'server': 'nginx', 'os_family': 'Linux/Unix'}
            
        except Exception:
            pass
        
        return None
    
    def check_vulnerabilities(self, services):
        """Check for common vulnerabilities"""
        vulnerabilities = []
        
        for service in services:
            service_name = service['service']
            port = service['port']
            banner = service['banner']
            
            # Check for service-specific vulnerabilities
            if service_name in self.vulnerability_signatures:
                for vuln in self.vulnerability_signatures[service_name]:
                    vulnerabilities.append({
                        'id': f'VULN-{port}-{len(vulnerabilities) + 1}',
                        'name': vuln,
                        'severity': self.get_vulnerability_severity(vuln),
                        'description': f"Potential {vuln} on {service_name} (port {port})",
                        'service': service_name,
                        'port': port,
                        'banner': banner
                    })
            
            # Check for weak authentication
            if service_name in ['FTP', 'SSH', 'Telnet', 'SMB']:
                vulnerabilities.append({
                    'id': f'VULN-{port}-AUTH',
                    'name': 'Weak Authentication Mechanism',
                    'severity': 'High',
                    'description': f"{service_name} service may have weak authentication",
                    'service': service_name,
                    'port': port
                })
        
        return vulnerabilities
    
    def get_vulnerability_severity(self, vulnerability):
        """Get severity level for vulnerability"""
        severity_map = {
            'Anonymous login allowed': 'Critical',
            'Weak authentication': 'High',
            'Unencrypted communication': 'High',
            'Open relay': 'High',
            'Anonymous access': 'Critical',
            'Weak encryption': 'Medium',
            'BlueKeep vulnerability': 'Critical'
        }
        
        return severity_map.get(vulnerability, 'Medium')
    
    def scan_network_range(self, network_range, ports=None):
        """Scan a network range"""
        print(f"{Fore.CYAN}[*] Scanning network range: {network_range}{Style.RESET_ALL}")
        
        try:
            # Parse network range
            network = ipaddress.ip_network(network_range, strict=False)
            hosts = list(network.hosts())
            
            print(f"{Fore.YELLOW}[*] Found {len(hosts)} hosts in range{Style.RESET_ALL}")
            
            # Scan each host
            results = {}
            for host in hosts[:50]:  # Limit to first 50 hosts for demo
                host_str = str(host)
                try:
                    host_result = self.scan_host(host_str, ports)
                    if host_result['open_ports']:
                        results[host_str] = host_result
                        print(f"{Fore.GREEN}[+] Host {host_str} is active{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[-] Error scanning {host_str}: {e}{Style.RESET_ALL}")
            
            return {
                'network_range': network_range,
                'hosts_scanned': len(hosts),
                'active_hosts': len(results),
                'results': results
            }
            
        except Exception as e:
            print(f"{Fore.RED}[-] Invalid network range: {e}{Style.RESET_ALL}")
            return None
    
    def perform_service_enumeration(self, host, port):
        """Perform detailed service enumeration"""
        print(f"{Fore.YELLOW}[*] Enumerating service on {host}:{port}{Style.RESET_ALL}")
        
        enumeration_result = {
            'port': port,
            'service': self.common_ports.get(port, 'Unknown'),
            'enumeration': {}
        }
        
        try:
            if port == 21:  # FTP
                enumeration_result['enumeration'] = self.enumerate_ftp(host, port)
            elif port == 22:  # SSH
                enumeration_result['enumeration'] = self.enumerate_ssh(host, port)
            elif port == 80:  # HTTP
                enumeration_result['enumeration'] = self.enumerate_http(host, port)
            elif port == 445:  # SMB
                enumeration_result['enumeration'] = self.enumerate_smb(host, port)
            elif port == 3389:  # RDP
                enumeration_result['enumeration'] = self.enumerate_rdp(host, port)
            elif port == 3306:  # MySQL
                enumeration_result['enumeration'] = self.enumerate_mysql(host, port)
        except Exception as e:
            enumeration_result['enumeration']['error'] = str(e)
        
        return enumeration_result
    
    def enumerate_ftp(self, host, port):
        """Enumerate FTP service"""
        ftp_info = {}
        
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=self.timeout)
            
            # Check for anonymous login
            try:
                ftp.login()
                ftp_info['anonymous_login'] = True
                ftp_info['anonymous_files'] = ftp.nlst()
            except:
                ftp_info['anonymous_login'] = False
            
            # Get welcome message
            ftp_info['welcome_message'] = ftp.getwelcome()
            ftp.quit()
            
        except Exception as e:
            ftp_info['error'] = str(e)
        
        return ftp_info
    
    def enumerate_ssh(self, host, port):
        """Enumerate SSH service"""
        ssh_info = {}
        
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Try to connect and get banner
            try:
                ssh.connect(host, port=port, username='test', password='test', timeout=self.timeout)
            except paramiko.AuthenticationException:
                ssh_info['authentication_required'] = True
            except Exception as e:
                ssh_info['connection_error'] = str(e)
            
            ssh.close()
            
        except ImportError:
            ssh_info['error'] = 'paramiko library not available'
        except Exception as e:
            ssh_info['error'] = str(e)
        
        return ssh_info
    
    def enumerate_http(self, host, port):
        """Enumerate HTTP service"""
        http_info = {}
        
        try:
            import requests
            
            # Check for common directories
            common_dirs = ['/admin', '/login', '/uploads', '/backup', '/config', '/test', '/phpmyadmin']
            found_dirs = []
            
            for directory in common_dirs:
                try:
                    url = f"http://{host}:{port}{directory}"
                    response = requests.get(url, timeout=self.timeout)
                    if response.status_code == 200:
                        found_dirs.append(directory)
                except:
                    pass
            
            http_info['directories'] = found_dirs
            
            # Get server header
            try:
                response = requests.get(f"http://{host}:{port}", timeout=self.timeout)
                http_info['server'] = response.headers.get('Server', 'Unknown')
                http_info['status_code'] = response.status_code
            except:
                pass
            
        except ImportError:
            http_info['error'] = 'requests library not available'
        except Exception as e:
            http_info['error'] = str(e)
        
        return http_info
    
    def enumerate_smb(self, host, port):
        """Enumerate SMB service"""
        smb_info = {}
        
        try:
            # Try to connect using smbprotocol or similar
            smb_info['smb_available'] = True
            smb_info['note'] = 'Detailed SMB enumeration requires additional libraries'
        except Exception as e:
            smb_info['error'] = str(e)
        
        return smb_info
    
    def enumerate_rdp(self, host, port):
        """Enumerate RDP service"""
        rdp_info = {}
        
        try:
            # Basic RDP enumeration
            rdp_info['rdp_available'] = True
            rdp_info['note'] = 'Detailed RDP enumeration requires additional libraries'
        except Exception as e:
            rdp_info['error'] = str(e)
        
        return rdp_info
    
    def enumerate_mysql(self, host, port):
        """Enumerate MySQL service"""
        mysql_info = {}
        
        try:
            import pymysql
            
            # Try to connect
            try:
                conn = pymysql.connect(host=host, port=port, user='root', password='', connect_timeout=self.timeout)
                mysql_info['anonymous_access'] = True
                conn.close()
            except pymysql.err.OperationalError:
                mysql_info['authentication_required'] = True
            except Exception as e:
                mysql_info['connection_error'] = str(e)
                
        except ImportError:
            mysql_info['error'] = 'pymysql library not available'
        except Exception as e:
            mysql_info['error'] = str(e)
        
        return mysql_info
    
    def generate_report(self, scan_results):
        """Generate detailed scan report"""
        report = {
            'scan_summary': {
                'total_hosts': len(scan_results.get('results', {})),
                'total_open_ports': sum(len(host['open_ports']) for host in scan_results.get('results', {}).values()),
                'total_vulnerabilities': sum(len(host['vulnerabilities']) for host in scan_results.get('results', {}).values()),
                'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            },
            'detailed_results': scan_results,
            'recommendations': self.generate_recommendations(scan_results)
        }
        
        return report
    
    def generate_recommendations(self, scan_results):
        """Generate security recommendations based on scan results"""
        recommendations = []
        
        for host, host_data in scan_results.get('results', {}).items():
            for vuln in host_data.get('vulnerabilities', []):
                if vuln['severity'] == 'Critical':
                    recommendations.append(f"Immediately address critical vulnerability: {vuln['name']} on {host}:{vuln['port']}")
                elif vuln['severity'] == 'High':
                    recommendations.append(f"Address high-severity vulnerability: {vuln['name']} on {host}:{vuln['port']}")
            
            # Service-specific recommendations
            for service in host_data.get('services', []):
                if service['service'] == 'FTP' and service['port'] == 21:
                    recommendations.append(f"Review FTP configuration on {host} - consider disabling anonymous access")
                elif service['service'] == 'SSH' and service['port'] == 22:
                    recommendations.append(f"Ensure SSH is properly configured on {host} - disable root login and use key authentication")
                elif service['service'] == 'SMB' and service['port'] == 445:
                    recommendations.append(f"Review SMB configuration on {host} - ensure proper access controls")
        
        # General recommendations
        recommendations.extend([
            "Implement network segmentation to limit exposure",
            "Deploy intrusion detection/prevention systems",
            "Regularly update and patch all systems",
            "Conduct regular vulnerability assessments",
            "Implement proper logging and monitoring"
        ])
        
        return list(set(recommendations))  # Remove duplicates


def main():
    """Main function for standalone usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced Network Scanner")
    parser.add_argument('target', help='Target IP address or network range (e.g., 192.168.1.1 or 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', help='Port range (e.g., 1-1000 or 22,80,443)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=int, default=3, help='Connection timeout in seconds (default: 3)')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('--enumerate', action='store_true', help='Perform detailed service enumeration')
    
    args = parser.parse_args()
    
    # Parse ports
    ports = None
    if args.ports:
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = [int(p) for p in args.ports.split(',')]
    
    # Initialize scanner
    scanner = AdvancedNetworkScanner(timeout=args.timeout, threads=args.threads)
    
    print(f"{Fore.CYAN}=== Advanced Network Scanner ==={Style.RESET_ALL}")
    print(f"Target: {args.target}")
    print(f"Ports: {args.ports or 'Common ports'}")
    print(f"Threads: {args.threads}")
    print(f"Timeout: {args.timeout} seconds")
    print("-" * 50)
    
    try:
        # Determine if target is a single host or network range
        if '/' in args.target:
            # Network range scan
            results = scanner.scan_network_range(args.target, ports)
        else:
            # Single host scan
            results = scanner.scan_host(args.target, ports)
            results = {'results': {args.target: results}}
        
        # Perform detailed enumeration if requested
        if args.enumerate and 'results' in results:
            print(f"\n{Fore.CYAN}=== Service Enumeration ==={Style.RESET_ALL}")
            for host, host_data in results['results'].items():
                for service in host_data.get('services', []):
                    enum_result = scanner.perform_service_enumeration(host, service['port'])
                    service['enumeration'] = enum_result['enumeration']
        
        # Generate report
        report = scanner.generate_report(results)
        
        # Display results
        print(f"\n{Fore.CYAN}=== Scan Results ==={Style.RESET_ALL}")
        print(f"Total hosts found: {report['scan_summary']['total_hosts']}")
        print(f"Total open ports: {report['scan_summary']['total_open_ports']}")
        print(f"Total vulnerabilities: {report['scan_summary']['total_vulnerabilities']}")
        
        # Display detailed results
        if 'results' in results:
            for host, host_data in results['results'].items():
                print(f"\n{Fore.GREEN}[+] Host: {host}{Style.RESET_ALL}")
                print(f"  OS: {host_data.get('os_info', {}).get('os', 'Unknown')}")
                print(f"  Open ports: {len(host_data.get('open_ports', []))}")
                print(f"  Vulnerabilities: {len(host_data.get('vulnerabilities', []))}")
                
                for service in host_data.get('services', []):
                    print(f"    Port {service['port']}: {service['service']} ({service['version']})")
                
                for vuln in host_data.get('vulnerabilities', []):
                    severity_color = Fore.RED if vuln['severity'] == 'Critical' else Fore.YELLOW
                    print(f"    {severity_color}[{vuln['severity']}] {vuln['name']}{Style.RESET_ALL}")
        
        # Display recommendations
        print(f"\n{Fore.CYAN}=== Recommendations ==={Style.RESET_ALL}")
        for rec in report['recommendations']:
            print(f"  - {rec}")
        
        # Save results if output file specified
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\n{Fore.GREEN}[+] Results saved to {args.output}{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[-] Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()