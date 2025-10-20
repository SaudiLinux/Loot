#!/usr/bin/env python3
"""
Advanced Penetration Testing Tool (APT Tool)
Author: Sayer Linux (SayerLinux1@gmail.com)
Description: Comprehensive penetration testing framework with multiple modules
"""

import argparse
import sys
import os
import json
import datetime
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

class APTFramework:
    """Advanced Penetration Testing Framework"""
    
    def __init__(self):
        self.banner = f"""
{Fore.RED}    ██████╗ ███████╗████████╗████████╗███████╗███████╗███████╗██████╗ 
    ██╔══██╗██╔════╝╚══██╔══╝╚══██╔══╝██╔════╝██╔════╝██╔════╝██╔══██╗
    ██████╔╝█████╗     ██║      ██║   █████╗  ███████╗█████╗  ██████╔╝
    ██╔═══╝ ██╔══╝     ██║      ██║   ██╔══╝  ╚════██║██╔══╝  ██╔══██╗
    ██║     ███████╗   ██║      ██║   ███████╗███████║███████╗██║  ██║
    ╚═╝     ╚══════╝   ╚═╝      ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.CYAN} Advanced Penetration Testing Framework v2.0
 Author: Sayer Linux (SayerLinux1@gmail.com)
{Style.RESET_ALL}
        """
        
        self.modules = {
            'network_scanner': NetworkScanner(),
            'web_scanner': WebScanner(),
            'exploitation': ExploitationModule(),
            'post_exploitation': PostExploitationModule(),
            'privilege_escalation': PrivilegeEscalationModule(),
            'reporting': ReportingModule()
        }
        
        self.results = {
            'scan_results': {},
            'vulnerabilities': [],
            'exploitation_results': {},
            'post_exploitation_results': {},
            'privilege_escalation_results': {},
            'timestamp': datetime.datetime.now().isoformat()
        }
    
    def print_banner(self):
        print(self.banner)
    
    def run_network_scan(self, target, ports="1-1000"):
        """Run network scanning and enumeration"""
        print(f"{Fore.YELLOW}[*] Starting network scan on {target}{Style.RESET_ALL}")
        results = self.modules['network_scanner'].scan(target, ports)
        self.results['scan_results']['network'] = results
        return results
    
    def run_web_scan(self, target):
        """Run web application security scanning"""
        print(f"{Fore.YELLOW}[*] Starting web scan on {target}{Style.RESET_ALL}")
        results = self.modules['web_scanner'].scan(target)
        self.results['scan_results']['web'] = results
        return results
    
    def run_exploitation(self, target, vulnerabilities):
        """Run exploitation attempts"""
        print(f"{Fore.YELLOW}[*] Starting exploitation on {target}{Style.RESET_ALL}")
        results = self.modules['exploitation'].exploit(target, vulnerabilities)
        self.results['exploitation_results'] = results
        return results
    
    def run_post_exploitation(self, compromised_systems):
        """Run post-exploitation activities"""
        print(f"{Fore.YELLOW}[*] Starting post-exploitation{Style.RESET_ALL}")
        results = self.modules['post_exploitation'].run(compromised_systems)
        self.results['post_exploitation_results'] = results
        return results
    
    def run_privilege_escalation(self, systems):
        """Run privilege escalation attempts"""
        print(f"{Fore.YELLOW}[*] Starting privilege escalation{Style.RESET_ALL}")
        results = self.modules['privilege_escalation'].escalate(systems)
        self.results['privilege_escalation_results'] = results
        return results
    
    def generate_report(self):
        """Generate comprehensive penetration testing report"""
        print(f"{Fore.YELLOW}[*] Generating comprehensive report{Style.RESET_ALL}")
        report = self.modules['reporting'].generate(self.results)
        return report
    
    def run_full_assessment(self, target, ports="1-1000"):
        """Run full penetration testing assessment"""
        print(f"{Fore.GREEN}[+] Starting full assessment on {target}{Style.RESET_ALL}")
        
        # Phase 1: Network Scanning
        network_results = self.run_network_scan(target, ports)
        
        # Phase 2: Web Scanning (if web services detected)
        web_results = self.run_web_scan(target)
        
        # Collect all vulnerabilities
        all_vulnerabilities = []
        if 'vulnerabilities' in network_results:
            all_vulnerabilities.extend(network_results['vulnerabilities'])
        if 'vulnerabilities' in web_results:
            all_vulnerabilities.extend(web_results['vulnerabilities'])
        
        # Phase 3: Exploitation (if vulnerabilities found)
        exploitation_results = {}
        if all_vulnerabilities:
            exploitation_results = self.run_exploitation(target, all_vulnerabilities)
        
        # Phase 4: Post-Exploitation (if successful exploitation)
        post_exploitation_results = {}
        if exploitation_results and any(result.get('success') for result in exploitation_results.values()):
            compromised_systems = [target]  # Simplified for demo
            post_exploitation_results = self.run_post_exploitation(compromised_systems)
        
        # Phase 5: Privilege Escalation
        privilege_escalation_results = {}
        if post_exploitation_results:
            privilege_escalation_results = self.run_privilege_escalation(compromised_systems)
        
        # Generate final report
        final_report = self.generate_report()
        
        return {
            'network_scan': network_results,
            'web_scan': web_results,
            'exploitation': exploitation_results,
            'post_exploitation': post_exploitation_results,
            'privilege_escalation': privilege_escalation_results,
            'report': final_report
        }


class NetworkScanner:
    """Network scanning and enumeration module"""
    
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443]
    
    def scan(self, target, ports="1-1000"):
        """Perform network scan"""
        print(f"{Fore.CYAN}[*] Scanning {target} on ports {ports}{Style.RESET_ALL}")
        
        # Simulate network scanning
        open_ports = []
        services = []
        
        # Parse port range
        if '-' in ports:
            start, end = map(int, ports.split('-'))
            port_list = range(start, end + 1)
        else:
            port_list = map(int, ports.split(','))
        
        # Simulate port scanning
        for port in list(port_list)[:20]:  # Limit for demo
            if port in self.common_ports:
                open_ports.append(port)
                service = self.get_service_name(port)
                services.append({
                    'port': port,
                    'service': service,
                    'version': 'Unknown',
                    'state': 'open'
                })
        
        # Simulate vulnerability detection
        vulnerabilities = []
        if 22 in open_ports:
            vulnerabilities.append({
                'id': 'VULN-001',
                'name': 'SSH Weak Configuration',
                'severity': 'Medium',
                'description': 'SSH service may have weak configuration',
                'port': 22
            })
        
        if 445 in open_ports:
            vulnerabilities.append({
                'id': 'VULN-002',
                'name': 'SMB Service Detected',
                'severity': 'High',
                'description': 'SMB service detected, potential for exploitation',
                'port': 445
            })
        
        return {
            'target': target,
            'open_ports': open_ports,
            'services': services,
            'vulnerabilities': vulnerabilities,
            'scan_type': 'network'
        }
    
    def get_service_name(self, port):
        """Get service name for port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'RPC',
            139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        return services.get(port, 'Unknown')


class WebScanner:
    """Web application security scanner"""
    
    def __init__(self):
        self.common_paths = ['/admin', '/login', '/uploads', '/backup', '/config', '/test', '/dev']
        self.vulnerability_patterns = [
            {'pattern': 'SQL syntax', 'type': 'SQL Injection'},
            {'pattern': 'XPath error', 'type': 'XPath Injection'},
            {'pattern': 'LDAP error', 'type': 'LDAP Injection'},
            {'pattern': 'Java.lang', 'type': 'Java Exception'},
            {'pattern': 'PHP Warning', 'type': 'PHP Error'},
            {'pattern': 'Microsoft OLE DB', 'type': 'Database Error'}
        ]
    
    def scan(self, target):
        """Perform web application security scan"""
        print(f"{Fore.CYAN}[*] Scanning web application on {target}{Style.RESET_ALL}")
        
        # Simulate web scanning
        findings = []
        vulnerabilities = []
        
        # Check common paths
        for path in self.common_paths[:3]:  # Limit for demo
            findings.append({
                'path': path,
                'status': 'found',
                'type': 'directory'
            })
        
        # Simulate vulnerability detection
        vulnerabilities.extend([
            {
                'id': 'WEB-001',
                'name': 'SQL Injection',
                'severity': 'Critical',
                'description': 'Potential SQL injection vulnerability in login form',
                'url': f'{target}/login.php',
                'parameter': 'username'
            },
            {
                'id': 'WEB-002',
                'name': 'XSS Vulnerability',
                'severity': 'High',
                'description': 'Reflected XSS in search functionality',
                'url': f'{target}/search.php',
                'parameter': 'q'
            }
        ])
        
        return {
            'target': target,
            'findings': findings,
            'vulnerabilities': vulnerabilities,
            'scan_type': 'web'
        }


class ExploitationModule:
    """Exploitation module"""
    
    def __init__(self):
        self.exploit_payloads = {
            'SQL Injection': "' OR 1=1--",
            'XSS': "<script>alert('XSS')</script>",
            'Command Injection': "; id;",
            'LDAP Injection': "*)(uid=*",
            'XPath Injection': "' or '1'='1"
        }
    
    def exploit(self, target, vulnerabilities):
        """Attempt to exploit vulnerabilities"""
        print(f"{Fore.CYAN}[*] Attempting exploitation on {target}{Style.RESET_ALL}")
        
        results = {}
        
        for vuln in vulnerabilities:
            vuln_id = vuln['id']
            vuln_type = vuln['name']
            
            print(f"{Fore.YELLOW}[*] Trying to exploit {vuln_id}: {vuln_type}{Style.RESET_ALL}")
            
            # Simulate exploitation attempt
            success = self.simulate_exploitation(vuln)
            
            results[vuln_id] = {
                'vulnerability': vuln,
                'success': success,
                'payload_used': self.exploit_payloads.get(vuln_type, 'Generic payload'),
                'timestamp': datetime.datetime.now().isoformat()
            }
            
            if success:
                print(f"{Fore.GREEN}[+] Successfully exploited {vuln_id}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Failed to exploit {vuln_id}{Style.RESET_ALL}")
        
        return results
    
    def simulate_exploitation(self, vulnerability):
        """Simulate exploitation (replace with real exploits)"""
        # Simulate 30% success rate for demo
        import random
        return random.random() < 0.3


class PostExploitationModule:
    """Post-exploitation activities"""
    
    def __init__(self):
        self.post_exploit_actions = [
            'System Information Gathering',
            'User Enumeration',
            'Network Discovery',
            'Credential Harvesting',
            'Persistence Establishment',
            'Data Exfiltration'
        ]
    
    def run(self, compromised_systems):
        """Run post-exploitation activities"""
        print(f"{Fore.CYAN}[*] Running post-exploitation activities{Style.RESET_ALL}")
        
        results = {}
        
        for system in compromised_systems:
            system_results = []
            
            for action in self.post_exploit_actions:
                print(f"{Fore.YELLOW}[*] Performing: {action}{Style.RESET_ALL}")
                
                # Simulate post-exploitation activity
                result = self.simulate_post_exploit_action(action)
                system_results.append({
                    'action': action,
                    'result': result,
                    'timestamp': datetime.datetime.now().isoformat()
                })
            
            results[system] = system_results
        
        return results
    
    def simulate_post_exploit_action(self, action):
        """Simulate post-exploitation action"""
        # Simulate realistic results
        if action == 'System Information Gathering':
            return {
                'os': 'Linux Ubuntu 20.04',
                'kernel': '5.4.0-42-generic',
                'hostname': 'target-server',
                'uptime': '15 days'
            }
        elif action == 'User Enumeration':
            return ['root', 'admin', 'www-data', 'mysql', 'backup']
        elif action == 'Credential Harvesting':
            return {
                'hashes': ['$6$randomhash1', '$6$randomhash2'],
                'passwords': ['weakpassword123', 'admin123']
            }
        else:
            return f"Simulated result for {action}"


class PrivilegeEscalationModule:
    """Privilege escalation module"""
    
    def __init__(self):
        self.escalation_techniques = [
            'Kernel Exploitation',
            'SUID Binary Abuse',
            'Sudo Misconfiguration',
            'Cron Job Manipulation',
            'Service Exploitation',
            'Path Hijacking'
        ]
    
    def escalate(self, systems):
        """Attempt privilege escalation"""
        print(f"{Fore.CYAN}[*] Attempting privilege escalation{Style.RESET_ALL}")
        
        results = {}
        
        for system in systems:
            escalation_results = []
            
            for technique in self.escalation_techniques:
                print(f"{Fore.YELLOW}[*] Trying: {technique}{Style.RESET_ALL}")
                
                # Simulate privilege escalation attempt
                success = self.simulate_escalation(technique)
                
                escalation_results.append({
                    'technique': technique,
                    'success': success,
                    'timestamp': datetime.datetime.now().isoformat()
                })
                
                if success:
                    print(f"{Fore.GREEN}[+] Successfully escalated privileges using {technique}{Style.RESET_ALL}")
            
            results[system] = escalation_results
        
        return results
    
    def simulate_escalation(self, technique):
        """Simulate privilege escalation attempt"""
        import random
        # Simulate 20% success rate for demo
        return random.random() < 0.2


class ReportingModule:
    """Report generation module"""
    
    def generate(self, results):
        """Generate comprehensive report"""
        print(f"{Fore.CYAN}[*] Generating comprehensive report{Style.RESET_ALL}")
        
        report = {
            'timestamp': datetime.datetime.now().isoformat(),
            'summary': self.generate_summary(results),
            'detailed_findings': self.generate_detailed_findings(results),
            'recommendations': self.generate_recommendations(results),
            'risk_assessment': self.generate_risk_assessment(results)
        }
        
        # Save report to file
        self.save_report(report)
        
        return report
    
    def generate_summary(self, results):
        """Generate executive summary"""
        total_vulnerabilities = 0
        critical_vulnerabilities = 0
        successful_exploits = 0
        
        if 'scan_results' in results:
            for scan_type, scan_data in results['scan_results'].items():
                if 'vulnerabilities' in scan_data:
                    total_vulnerabilities += len(scan_data['vulnerabilities'])
                    critical_vulnerabilities += len([v for v in scan_data['vulnerabilities'] if v.get('severity') == 'Critical'])
        
        if 'exploitation_results' in results:
            for exploit_id, exploit_data in results['exploitation_results'].items():
                if exploit_data.get('success'):
                    successful_exploits += 1
        
        return {
            'total_vulnerabilities': total_vulnerabilities,
            'critical_vulnerabilities': critical_vulnerabilities,
            'successful_exploits': successful_exploits,
            'overall_risk': 'High' if critical_vulnerabilities > 0 else 'Medium' if total_vulnerabilities > 0 else 'Low'
        }
    
    def generate_detailed_findings(self, results):
        """Generate detailed findings"""
        findings = []
        
        if 'scan_results' in results:
            for scan_type, scan_data in results['scan_results'].items():
                if 'vulnerabilities' in scan_data:
                    for vuln in scan_data['vulnerabilities']:
                        findings.append({
                            'type': 'Vulnerability',
                            'severity': vuln.get('severity', 'Unknown'),
                            'title': vuln.get('name', 'Unknown'),
                            'description': vuln.get('description', 'No description'),
                            'location': vuln.get('url', vuln.get('port', 'Unknown'))
                        })
        
        return findings
    
    def generate_recommendations(self, results):
        """Generate security recommendations"""
        recommendations = []
        
        summary = self.generate_summary(results)
        
        if summary['critical_vulnerabilities'] > 0:
            recommendations.extend([
                "Immediately patch all critical vulnerabilities",
                "Implement emergency response procedures",
                "Conduct immediate security assessment"
            ])
        
        if summary['total_vulnerabilities'] > 0:
            recommendations.extend([
                "Implement regular vulnerability scanning",
                "Establish patch management procedures",
                "Deploy intrusion detection systems"
            ])
        
        recommendations.extend([
            "Conduct regular security awareness training",
            "Implement defense-in-depth security strategy",
            "Establish incident response procedures"
        ])
        
        return recommendations
    
    def generate_risk_assessment(self, results):
        """Generate risk assessment"""
        summary = self.generate_summary(results)
        
        return {
            'overall_risk_level': summary['overall_risk'],
            'risk_factors': [
                f"{summary['critical_vulnerabilities']} critical vulnerabilities",
                f"{summary['total_vulnerabilities']} total vulnerabilities",
                f"{summary['successful_exploits']} successful exploitation attempts"
            ],
            'business_impact': 'High' if summary['critical_vulnerabilities'] > 0 else 'Medium'
        }
    
    def save_report(self, report):
        """Save report to file"""
        filename = f"penetration_test_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"{Fore.GREEN}[+] Report saved to {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to save report: {e}{Style.RESET_ALL}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Advanced Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python penetration_testing_tool.py -t 192.168.1.1 --full-assessment
  python penetration_testing_tool.py -t 192.168.1.1 --network-scan --ports 1-1000
  python penetration_testing_tool.py -t https://example.com --web-scan
  python penetration_testing_tool.py -t 192.168.1.1 --exploit --vuln-file vulnerabilities.json
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target IP or URL')
    parser.add_argument('--full-assessment', action='store_true', help='Run full assessment')
    parser.add_argument('--network-scan', action='store_true', help='Run network scan only')
    parser.add_argument('--web-scan', action='store_true', help='Run web scan only')
    parser.add_argument('--exploit', action='store_true', help='Run exploitation')
    parser.add_argument('--post-exploitation', action='store_true', help='Run post-exploitation')
    parser.add_argument('--privilege-escalation', action='store_true', help='Run privilege escalation')
    parser.add_argument('--ports', default='1-1000', help='Port range (e.g., 1-1000 or 22,80,443)')
    parser.add_argument('--vuln-file', help='Vulnerability file for exploitation')
    parser.add_argument('--output', help='Output report file')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout')
    
    args = parser.parse_args()
    
    framework = APTFramework()
    framework.print_banner()
    
    try:
        if args.full_assessment:
            results = framework.run_full_assessment(args.target, args.ports)
        elif args.network_scan:
            results = framework.run_network_scan(args.target, args.ports)
        elif args.web_scan:
            results = framework.run_web_scan(args.target)
        elif args.exploit and args.vuln_file:
            # Load vulnerabilities from file
            with open(args.vuln_file, 'r') as f:
                vulnerabilities = json.load(f)
            results = framework.run_exploitation(args.target, vulnerabilities)
        elif args.post_exploitation:
            # Simplified for demo
            compromised_systems = [args.target]
            results = framework.run_post_exploitation(compromised_systems)
        elif args.privilege_escalation:
            # Simplified for demo
            systems = [args.target]
            results = framework.run_privilege_escalation(systems)
        else:
            parser.print_help()
            return
        
        print(f"{Fore.GREEN}[+] Assessment completed successfully!{Style.RESET_ALL}")
        
        # Display summary
        if 'summary' in results:
            summary = results['summary']
            print(f"\n{Fore.CYAN}=== ASSESSMENT SUMMARY ==={Style.RESET_ALL}")
            print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
            print(f"Critical Vulnerabilities: {summary['critical_vulnerabilities']}")
            print(f"Successful Exploits: {summary['successful_exploits']}")
            print(f"Overall Risk: {summary['overall_risk']}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[-] Assessment interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()