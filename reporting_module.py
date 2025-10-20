#!/usr/bin/env python3
"""
Advanced Reporting and Documentation Module
Author: Sayer Linux (SayerLinux1@gmail.com)
Description: Comprehensive reporting system for penetration testing results
"""

import os
import sys
import json
import datetime
import hashlib
import time
from colorama import Fore, Style


class AdvancedReportingSystem:
    """Advanced reporting and documentation system for penetration testing"""
    
    def __init__(self, project_name="PenTest_Project"):
        self.project_name = project_name
        self.report_timestamp = datetime.datetime.now()
        self.report_id = self.generate_report_id()
        self.vulnerabilities = []
        self.network_data = {}
        self.web_app_data = {}
        self.exploitation_data = {}
    
    def generate_report_id(self):
        """Generate unique report ID"""
        timestamp = self.report_timestamp.strftime('%Y%m%d_%H%M%S')
        random_hash = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        return f"RPT_{timestamp}_{random_hash}"
    
    def add_vulnerability(self, vulnerability_data):
        """Add vulnerability to report"""
        vulnerability = {
            'id': vulnerability_data.get('id', f"VULN-{len(self.vulnerabilities) + 1:03d}"),
            'name': vulnerability_data.get('name', 'Unknown Vulnerability'),
            'severity': vulnerability_data.get('severity', 'Unknown'),
            'cvss_score': vulnerability_data.get('cvss_score', 0.0),
            'description': vulnerability_data.get('description', ''),
            'affected_systems': vulnerability_data.get('affected_systems', []),
            'remediation': vulnerability_data.get('remediation', ''),
            'risk_rating': self.calculate_risk_rating(vulnerability_data.get('cvss_score', 0.0))
        }
        
        self.vulnerabilities.append(vulnerability)
        return vulnerability
    
    def calculate_risk_rating(self, cvss_score):
        """Calculate risk rating based on CVSS score"""
        if cvss_score >= 9.0:
            return 'Critical'
        elif cvss_score >= 7.0:
            return 'High'
        elif cvss_score >= 4.0:
            return 'Medium'
        else:
            return 'Low'
    
    def generate_executive_summary(self):
        """Generate executive summary"""
        total_vulns = len(self.vulnerabilities)
        critical_count = len([v for v in self.vulnerabilities if v['risk_rating'] == 'Critical'])
        high_count = len([v for v in self.vulnerabilities if v['risk_rating'] == 'High'])
        medium_count = len([v for v in self.vulnerabilities if v['risk_rating'] == 'Medium'])
        low_count = len([v for v in self.vulnerabilities if v['risk_rating'] == 'Low'])
        
        if critical_count > 0:
            risk_summary = "CRITICAL: Immediate action required."
        elif high_count > 0:
            risk_summary = "HIGH RISK: Significant security issues require prompt attention."
        elif medium_count > 0:
            risk_summary = "MEDIUM RISK: Moderate security issues should be addressed."
        else:
            risk_summary = "LOW RISK: Minor security issues identified."
        
        return f"""# Executive Summary

**Project:** {self.project_name}  
**Report ID:** {self.report_id}  
**Date:** {self.report_timestamp.strftime('%Y-%m-%d')}  

## Key Findings Summary

- **Total Vulnerabilities:** {total_vulns}
- **Critical:** {critical_count}
- **High:** {high_count}
- **Medium:** {medium_count}
- **Low:** {low_count}

### Risk Assessment
{risk_summary}
"""
    
    def generate_comprehensive_report(self, output_format='all', output_path=None):
        """Generate comprehensive report"""
        print(f"{Fore.CYAN}[*] Generating comprehensive report{Style.RESET_ALL}")
        
        reports_generated = {}
        
        try:
            executive_summary = self.generate_executive_summary()
            full_report = f"# Penetration Testing Report\n\n{executive_summary}"
            
            if output_format in ['all', 'markdown']:
                if output_path:
                    markdown_path = output_path
                else:
                    markdown_path = f"penetration_test_report_{self.report_id}.md"
                
                with open(markdown_path, 'w') as f:
                    f.write(full_report)
                
                reports_generated['markdown'] = markdown_path
                print(f"{Fore.GREEN}[+] Markdown report: {markdown_path}{Style.RESET_ALL}")
            
            if output_format in ['all', 'json']:
                json_report = json.dumps({
                    'report_metadata': {
                        'project_name': self.project_name,
                        'report_id': self.report_id,
                        'timestamp': self.report_timestamp.isoformat()
                    },
                    'vulnerabilities': self.vulnerabilities
                }, indent=2)
                
                if output_path:
                    json_path = output_path.replace('.md', '.json')
                else:
                    json_path = f"penetration_test_report_{self.report_id}.json"
                
                with open(json_path, 'w') as f:
                    f.write(json_report)
                
                reports_generated['json'] = json_path
                print(f"{Fore.GREEN}[+] JSON report: {json_path}{Style.RESET_ALL}")
            
            return reports_generated
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error generating report: {e}{Style.RESET_ALL}")
            return reports_generated


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced Reporting System")
    parser.add_argument('--project-name', default="PenTest_Project", help='Project name')
    parser.add_argument('--add-vulnerability', action='store_true', help='Add sample vulnerability')
    parser.add_argument('--generate-report', choices=['all', 'markdown', 'json'], default='all', help='Report format')
    parser.add_argument('-o', '--output', help='Output file path')
    
    args = parser.parse_args()
    
    print(f"{Fore.CYAN}=== Advanced Reporting System ==={Style.RESET_ALL}")
    
    try:
        reporting = AdvancedReportingSystem(args.project_name)
        
        if args.add_vulnerability:
            sample_vuln = {
                'name': 'SQL Injection in Login Form',
                'severity': 'Critical',
                'cvss_score': 9.8,
                'description': 'SQL injection vulnerability in login form',
                'affected_systems': ['web.example.com'],
                'remediation': 'Implement parameterized queries'
            }
            reporting.add_vulnerability(sample_vuln)
            print(f"{Fore.GREEN}[+] Sample vulnerability added{Style.RESET_ALL}")
        
        if args.generate_report:
            reports = reporting.generate_comprehensive_report(args.generate_report, args.output)
            for format_type, file_path in reports.items():
                print(f"{Fore.GREEN}[+] {format_type.upper()} report: {file_path}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] Reporting completed!{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())