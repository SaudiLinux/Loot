#!/usr/bin/env python3
"""
Loot - Advanced Cybersecurity Testing Tool
Author: Sayer Linux (SayerLinux1@gmail.com)
Description: Comprehensive security testing suite with AI-powered capabilities
"""

import argparse
import sys
import os
from datetime import datetime
from colorama import init, Fore, Style

# Import modules
from modules.recon import ReconModule
from modules.stealth import StealthModule
from modules.vuln_scanner import VulnScanner
from modules.exploiter import Exploiter
from modules.poc_demo import POCGenerator
from modules.reporter import Reporter
from modules.zero_day_module import ZeroDayModule

init(autoreset=True)

class Loot:
    def __init__(self):
        self.banner = f"""
{Fore.RED} ██╗     ██╗  ██╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██║     ██║ ██╔╝██╔═══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██║     █████╔╝ ██║   ██║█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║     ██╔═██╗ ██║   ██║██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ███████╗██║  ██╗╚██████╔╝██║     ╚██████╗╚██████╔╝██║ ╚████║
 ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝      ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{Style.RESET_ALL}
{Fore.CYAN} Advanced Cybersecurity Testing Tool v1.0
 Author: Sayer Linux (SayerLinux1@gmail.com)
{Style.RESET_ALL}
        """
        self.modules = {
            'recon': ReconModule(),
            'stealth': StealthModule(),
            'scanner': VulnScanner(),
            'exploiter': Exploiter(),
            'poc': POCGenerator(),
            'reporter': Reporter(),
            'zero_day': ZeroDayModule()
        }
    
    def print_banner(self):
        print(self.banner)
    
    def run_recon(self, target):
        """Run reconnaissance module"""
        print(f"{Fore.YELLOW}[*] Starting reconnaissance on {target}{Style.RESET_ALL}")
        return self.modules['recon'].scan(target)
    
    def run_stealth(self, target):
        """Run stealth and WAF bypass module"""
        print(f"{Fore.YELLOW}[*] Starting stealth operations on {target}{Style.RESET_ALL}")
        return self.modules['stealth'].bypass_waf(target)
    
    def run_scanner(self, target):
        """Run AI-powered vulnerability scanner"""
        print(f"{Fore.YELLOW}[*] Starting vulnerability scan on {target}{Style.RESET_ALL}")
        return self.modules['scanner'].scan(target)
    
    def run_exploiter(self, target, vuln_info):
        """Run exploitation module"""
        print(f"{Fore.YELLOW}[*] Starting exploitation on {target}{Style.RESET_ALL}")
        return self.modules['exploiter'].exploit(target, vuln_info)
    
    def run_poc(self, target, vuln_info):
        """Generate proof of concept"""
        print(f"{Fore.YELLOW}[*] Generating proof of concept for {target}{Style.RESET_ALL}")
        return self.modules['poc'].generate(target, vuln_info)
    
    def run_zero_day_display(self, args=None):
        """Run zero-day vulnerability display"""
        print(f"{Fore.YELLOW}[*] Starting zero-day vulnerability display{Style.RESET_ALL}")
        return self.modules['zero_day'].run_zero_day_display(args)
    
    def generate_report(self, results):
        """Generate comprehensive report"""
        print(f"{Fore.YELLOW}[*] Generating report{Style.RESET_ALL}")
        return self.modules['reporter'].generate(results)
    
    def run_all(self, target):
        """Run all modules in sequence"""
        print(f"{Fore.GREEN}[+] Starting comprehensive scan on {target}{Style.RESET_ALL}")
        
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'recon': self.run_recon(target),
            'stealth': self.run_stealth(target),
            'vulnerabilities': self.run_scanner(target),
            'exploitation': {},
            'poc': {},
            'report': None
        }
        
        # Run exploitation for each vulnerability found
        for vuln in results['vulnerabilities']:
            exploit_result = self.run_exploiter(target, vuln)
            results['exploitation'][vuln['id']] = exploit_result
            
            # Generate POC for successful exploits
            if exploit_result.get('success'):
                poc_result = self.run_poc(target, vuln)
                results['poc'][vuln['id']] = poc_result
        
        # Generate final report
        results['report'] = self.generate_report(results)
        
        return results

def main():
    parser = argparse.ArgumentParser(
        description="Loot - Advanced Cybersecurity Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python loot.py -t https://example.com --all
  python loot.py -t https://example.com --recon
  python loot.py -t https://example.com --stealth
  python loot.py -t https://example.com --scan
  python loot.py -t https://example.com --exploit --vuln-id 1
        """
    )
    
    parser.add_argument('-t', '--target', help='Target URL to scan')
    parser.add_argument('--all', action='store_true', help='Run all modules')
    parser.add_argument('--recon', action='store_true', help='Run reconnaissance only')
    parser.add_argument('--stealth', action='store_true', help='Run stealth operations only')
    parser.add_argument('--scan', action='store_true', help='Run vulnerability scanner only')
    parser.add_argument('--exploit', action='store_true', help='Run exploitation module')
    parser.add_argument('--vuln-id', type=str, help='Vulnerability ID to exploit')
    parser.add_argument('--poc', action='store_true', help='Generate proof of concept')
    parser.add_argument('--zero-day', action='store_true', help='Display zero-day vulnerabilities')
    parser.add_argument('--output', type=str, default='loot_report.html', help='Output report file')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout')
    parser.add_argument('--user-agent', type=str, help='Custom User-Agent string')
    parser.add_argument('--proxy', type=str, help='Proxy URL')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.zero_day and not args.target:
        parser.error("Target URL is required unless using --zero-day")
    
    if args.zero_day and (args.all or args.recon or args.stealth or args.scan or args.exploit or args.poc):
        parser.error("Cannot use --zero-day with other scanning options")
    
    loot = Loot()
    loot.print_banner()
    
    try:
        if args.all:
            results = loot.run_all(args.target)
        elif args.recon:
            results = loot.run_recon(args.target)
        elif args.stealth:
            results = loot.run_stealth(args.target)
        elif args.scan:
            results = loot.run_scanner(args.target)
        elif args.exploit and args.vuln_id:
            vuln_info = {'id': args.vuln_id}
            results = loot.run_exploiter(args.target, vuln_info)
        elif args.poc and args.vuln_id:
            vuln_info = {'id': args.vuln_id}
            results = loot.run_poc(args.target, vuln_info)
        elif args.zero_day:
            results = loot.run_zero_day_display(args)
        else:
            parser.print_help()
            return
        
        print(f"{Fore.GREEN}[+] Scan completed successfully!{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[-] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()