#!/usr/bin/env python3
"""
Reporter Module - Generate comprehensive security assessment reports
Author: Sayer Linux (SayerLinux1@gmail.com)
"""

import os
import json
import csv
import time
import datetime
from colorama import Fore, Style
import requests
import subprocess
from urllib.parse import urlparse
import platform
import socket

try:
    from jinja2 import Template
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] Jinja2 not available. Install with: pip install jinja2{Style.RESET_ALL}")

try:
    import pdfkit
    PDFKIT_AVAILABLE = True
except ImportError:
    PDFKIT_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] pdfkit not available. Install with: pip install pdfkit{Style.RESET_ALL}")

try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] matplotlib not available. Install with: pip install matplotlib{Style.RESET_ALL}")

class Reporter:
    def __init__(self):
        self.reports_dir = "reports"
        self.templates_dir = "templates"
        self.assets_dir = "assets"
        self.ensure_directories()
        
        # Report templates
        self.report_templates = {
            'html': self.generate_html_report,
            'json': self.generate_json_report,
            'csv': self.generate_csv_report,
            'markdown': self.generate_markdown_report,
            'pdf': self.generate_pdf_report,
            'executive_summary': self.generate_executive_summary
        }
        
        # Risk assessment matrix
        self.risk_matrix = {
            'critical': {'score': 10, 'color': '#FF0000', 'description': 'Critical Risk'},
            'high': {'score': 8, 'color': '#FF6600', 'description': 'High Risk'},
            'medium': {'score': 6, 'color': '#FFCC00', 'description': 'Medium Risk'},
            'low': {'score': 4, 'color': '#00CC00', 'description': 'Low Risk'},
            'info': {'score': 2, 'color': '#0099FF', 'description': 'Informational'}
        }
    
    def ensure_directories(self):
        """Ensure report directories exist"""
        for directory in [self.reports_dir, self.templates_dir, self.assets_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)
    
    def generate_report(self, scan_results, report_format='html', output_file=None):
        """Generate comprehensive security assessment report"""
        print(f"{Fore.CYAN}[*] Generating {report_format.upper()} report...{Style.RESET_ALL}")
        
        # Process scan results
        processed_results = self.process_scan_results(scan_results)
        
        # Generate report based on format
        if report_format in self.report_templates:
            return self.report_templates[report_format](processed_results, output_file)
        else:
            print(f"{Fore.RED}[-] Unsupported report format: {report_format}{Style.RESET_ALL}")
            return None
    
    def process_scan_results(self, scan_results):
        """Process and analyze scan results"""
        processed = {
            'scan_metadata': scan_results.get('metadata', {}),
            'target_info': scan_results.get('target_info', {}),
            'vulnerabilities': [],
            'exploitation_results': scan_results.get('exploitation_results', []),
            'poc_results': scan_results.get('poc_results', []),
            'statistics': {},
            'risk_assessment': {},
            'recommendations': []
        }
        
        # Process vulnerabilities from all modules
        all_vulnerabilities = []
        
        # From reconnaissance
        if 'recon_results' in scan_results:
            for vuln in scan_results['recon_results'].get('vulnerabilities', []):
                vuln['source'] = 'Reconnaissance'
                all_vulnerabilities.append(vuln)
        
        # From vulnerability scanner
        if 'vuln_scan_results' in scan_results:
            for vuln in scan_results['vuln_scan_results'].get('vulnerabilities', []):
                vuln['source'] = 'Vulnerability Scanner'
                all_vulnerabilities.append(vuln)
        
        # From stealth module
        if 'stealth_results' in scan_results:
            for vuln in scan_results['stealth_results'].get('vulnerabilities', []):
                vuln['source'] = 'Stealth Module'
                all_vulnerabilities.append(vuln)
        
        # Process and deduplicate vulnerabilities
        processed['vulnerabilities'] = self.deduplicate_vulnerabilities(all_vulnerabilities)
        
        # Generate statistics
        processed['statistics'] = self.generate_statistics(processed['vulnerabilities'], scan_results)
        
        # Generate risk assessment
        processed['risk_assessment'] = self.generate_risk_assessment(processed['vulnerabilities'])
        
        # Generate recommendations
        processed['recommendations'] = self.generate_recommendations(processed['vulnerabilities'])
        
        return processed
    
    def deduplicate_vulnerabilities(self, vulnerabilities):
        """Remove duplicate vulnerabilities"""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            # Create unique identifier
            vuln_id = f"{vuln.get('type', 'unknown')}_{vuln.get('url', 'unknown')}_{vuln.get('parameter', 'unknown')}"
            
            if vuln_id not in seen:
                seen.add(vuln_id)
                unique_vulns.append(vuln)
        
        return unique_vulns
    
    def generate_statistics(self, vulnerabilities, scan_results):
        """Generate vulnerability statistics"""
        stats = {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_distribution': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'vulnerability_types': {},
            'exploitation_success_rate': 0,
            'poc_generated': 0,
            'screenshots_captured': 0,
            'scan_duration': 'Unknown'
        }
        
        # Count by severity
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium').lower()
            if severity in stats['severity_distribution']:
                stats['severity_distribution'][severity] += 1
        
        # Count by vulnerability type
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            if vuln_type in stats['vulnerability_types']:
                stats['vulnerability_types'][vuln_type] += 1
            else:
                stats['vulnerability_types'][vuln_type] = 1
        
        # Calculate exploitation success rate
        total_exploits = 0
        successful_exploits = 0
        
        for result in scan_results.get('exploitation_results', []):
            total_exploits += len(result.get('exploitation_attempts', []))
            successful_exploits += len(result.get('successful_exploits', []))
        
        if total_exploits > 0:
            stats['exploitation_success_rate'] = round((successful_exploits / total_exploits) * 100, 2)
        
        # Count POCs and screenshots
        for poc_result in scan_results.get('poc_results', []):
            if poc_result.get('screenshots'):
                stats['screenshots_captured'] += len(poc_result['screenshots'])
            if poc_result.get('proof_documents'):
                stats['poc_generated'] += 1
        
        # Calculate scan duration
        metadata = scan_results.get('metadata', {})
        if metadata.get('start_time') and metadata.get('end_time'):
            start = datetime.datetime.fromisoformat(metadata['start_time'])
            end = datetime.datetime.fromisoformat(metadata['end_time'])
            stats['scan_duration'] = str(end - start)
        
        return stats
    
    def generate_risk_assessment(self, vulnerabilities):
        """Generate risk assessment"""
        risk_assessment = {
            'overall_risk_score': 0,
            'risk_level': 'low',
            'critical_vulnerabilities': [],
            'high_risk_vulnerabilities': [],
            'attack_surface': 'minimal',
            'exposure_assessment': {}
        }
        
        # Calculate overall risk score
        total_score = 0
        critical_count = 0
        high_count = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium').lower()
            score = self.risk_matrix.get(severity, {}).get('score', 4)
            total_score += score
            
            if severity == 'critical':
                critical_count += 1
                risk_assessment['critical_vulnerabilities'].append(vuln)
            elif severity == 'high':
                high_count += 1
                risk_assessment['high_risk_vulnerabilities'].append(vuln)
        
        # Calculate average risk score
        if vulnerabilities:
            risk_assessment['overall_risk_score'] = round(total_score / len(vulnerabilities), 2)
        
        # Determine risk level
        if critical_count > 0:
            risk_assessment['risk_level'] = 'critical'
        elif high_count > 0:
            risk_assessment['risk_level'] = 'high'
        elif risk_assessment['overall_risk_score'] >= 6:
            risk_assessment['risk_level'] = 'medium'
        else:
            risk_assessment['risk_level'] = 'low'
        
        # Determine attack surface
        if critical_count > 3 or high_count > 5:
            risk_assessment['attack_surface'] = 'extensive'
        elif critical_count > 0 or high_count > 2:
            risk_assessment['attack_surface'] = 'significant'
        elif high_count > 0 or len(vulnerabilities) > 5:
            risk_assessment['attack_surface'] = 'moderate'
        else:
            risk_assessment['attack_surface'] = 'minimal'
        
        return risk_assessment
    
    def generate_recommendations(self, vulnerabilities):
        """Generate security recommendations"""
        recommendations = []
        
        # Group vulnerabilities by type for recommendations
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            if vuln_type in vuln_types:
                vuln_types[vuln_type].append(vuln)
            else:
                vuln_types[vuln_type] = [vuln]
        
        # Generate recommendations for each vulnerability type
        for vuln_type, vulns in vuln_types.items():
            if 'sql' in vuln_type.lower():
                recommendations.append({
                    'category': 'SQL Injection',
                    'priority': 'high',
                    'title': 'Implement Input Validation and Parameterized Queries',
                    'description': 'Use prepared statements with parameterized queries to prevent SQL injection attacks. Validate and sanitize all user inputs.',
                    'vulnerabilities_count': len(vulns),
                    'implementation_steps': [
                        'Replace dynamic SQL queries with parameterized queries',
                        'Implement input validation for all user inputs',
                        'Use stored procedures where possible',
                        'Apply principle of least privilege to database users',
                        'Enable SQL query logging and monitoring'
                    ]
                })
            
            elif 'xss' in vuln_type.lower():
                recommendations.append({
                    'category': 'Cross-Site Scripting (XSS)',
                    'priority': 'high',
                    'title': 'Implement Output Encoding and Content Security Policy',
                    'description': 'Encode all user-supplied data before rendering in web pages. Implement Content Security Policy (CSP) headers.',
                    'vulnerabilities_count': len(vulns),
                    'implementation_steps': [
                        'Encode all output data based on context (HTML, JavaScript, CSS, URL)',
                        'Implement Content Security Policy (CSP) headers',
                        'Use modern web frameworks with built-in XSS protection',
                        'Validate and sanitize all user inputs',
                        'Implement proper session management'
                    ]
                })
            
            elif 'lfi' in vuln_type.lower() or 'rfi' in vuln_type.lower():
                recommendations.append({
                    'category': 'File Inclusion Vulnerabilities',
                    'priority': 'critical',
                    'title': 'Implement Secure File Access Controls',
                    'description': 'Use whitelisting for allowed files, validate file paths, and implement proper access controls.',
                    'vulnerabilities_count': len(vulns),
                    'implementation_steps': [
                        'Use whitelisting approach for allowed files',
                        'Validate and sanitize file paths',
                        'Use absolute paths instead of relative paths',
                        'Implement proper file access controls',
                        'Disable unnecessary PHP settings (allow_url_include, allow_url_fopen)'
                    ]
                })
            
            elif 'command' in vuln_type.lower():
                recommendations.append({
                    'category': 'Command Injection',
                    'priority': 'critical',
                    'title': 'Avoid System Command Execution with User Input',
                    'description': 'Avoid using system commands with user input. Use safe alternatives and proper input validation.',
                    'vulnerabilities_count': len(vulns),
                    'implementation_steps': [
                        'Avoid using system() or exec() functions with user input',
                        'Use safe programming language features instead of system commands',
                        'Implement strict input validation and sanitization',
                        'Use parameterized commands where necessary',
                        'Apply principle of least privilege to application processes'
                    ]
                })
            
            elif 'idor' in vuln_type.lower():
                recommendations.append({
                    'category': 'Insecure Direct Object References',
                    'priority': 'medium',
                    'title': 'Implement Proper Access Control and Authorization',
                    'description': 'Implement proper authorization checks to ensure users can only access resources they are authorized to access.',
                    'vulnerabilities_count': len(vulns),
                    'implementation_steps': [
                        'Implement proper authorization checks for all resource access',
                        'Use indirect object references instead of direct ones',
                        'Validate user permissions before accessing resources',
                        'Implement proper session management',
                        'Log all access attempts for security monitoring'
                    ]
                })
        
        # Add general security recommendations
        recommendations.append({
            'category': 'General Security',
            'priority': 'medium',
            'title': 'Implement Comprehensive Security Controls',
            'description': 'Implement defense-in-depth security controls including WAF, security headers, and regular security assessments.',
            'vulnerabilities_count': len(vulnerabilities),
            'implementation_steps': [
                'Deploy Web Application Firewall (WAF)',
                'Implement security headers (HSTS, X-Frame-Options, X-Content-Type-Options)',
                'Conduct regular security assessments and penetration testing',
                'Implement secure coding practices and code reviews',
                'Maintain up-to-date software and security patches'
            ]
        })
        
        return recommendations
    
    def generate_html_report(self, processed_results, output_file=None):
        """Generate HTML report"""
        if output_file is None:
            output_file = os.path.join(self.reports_dir, f"security_assessment_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; }
        .section { margin: 30px 0; padding: 20px; border-left: 4px solid #667eea; background: #f9f9f9; }
        .vulnerability { background: white; margin: 15px 0; padding: 15px; border-radius: 5px; border-left: 4px solid #ff6600; }
        .severity-critical { border-left-color: #FF0000; }
        .severity-high { border-left-color: #FF6600; }
        .severity-medium { border-left-color: #FFCC00; }
        .severity-low { border-left-color: #00CC00; }
        .severity-info { border-left-color: #0099FF; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2em; font-weight: bold; color: #667eea; }
        .recommendation { background: #e8f5e8; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #28a745; }
        .risk-indicator { display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; }
        .risk-critical { background-color: #FF0000; }
        .risk-high { background-color: #FF6600; }
        .risk-medium { background-color: #FFCC00; }
        .risk-low { background-color: #00CC00; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #667eea; color: white; }
        .screenshot-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }
        .screenshot { background: white; padding: 10px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .screenshot img { width: 100%; height: auto; border-radius: 5px; }
        .timeline { position: relative; padding-left: 30px; }
        .timeline::before { content: ''; position: absolute; left: 15px; top: 0; bottom: 0; width: 2px; background: #667eea; }
        .timeline-item { position: relative; margin: 20px 0; padding: 15px; background: white; border-radius: 5px; }
        .timeline-item::before { content: ''; position: absolute; left: -22px; top: 20px; width: 12px; height: 12px; background: #667eea; border-radius: 50%; }
        .footer { text-align: center; padding: 20px; color: #666; border-top: 1px solid #eee; margin-top: 40px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Assessment Report</h1>
            <p>Comprehensive Security Analysis and Vulnerability Assessment</p>
            <p><strong>Generated:</strong> {{ timestamp }} | <strong>Target:</strong> {{ target_info.domain }}</p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{{ statistics.total_vulnerabilities }}</div>
                    <div>Total Vulnerabilities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ statistics.severity_distribution.critical }}</div>
                    <div>Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ statistics.severity_distribution.high }}</div>
                    <div>High Risk</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ statistics.exploitation_success_rate }}%</div>
                    <div>Exploitation Success Rate</div>
                </div>
            </div>
            
            <p><strong>Overall Risk Level:</strong> <span class="risk-indicator risk-{{ risk_assessment.risk_level }}">{{ risk_assessment.risk_level.upper() }}</span></p>
            <p><strong>Attack Surface:</strong> {{ risk_assessment.attack_surface }}</p>
            <p><strong>Scan Duration:</strong> {{ statistics.scan_duration }}</p>
        </div>
        
        <div class="section">
            <h2>Risk Assessment</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                    <th>Percentage</th>
                    <th>Description</th>
                </tr>
                {% for severity, count in statistics.severity_distribution.items() %}
                <tr>
                    <td><span class="risk-indicator risk-{{ severity }}">{{ severity.upper() }}</span></td>
                    <td>{{ count }}</td>
                    <td>{{ "%.1f"|format((count/statistics.total_vulnerabilities*100)) if statistics.total_vulnerabilities > 0 else 0 }}%</td>
                    <td>{{ risk_matrix[severity].description }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        
        <div class="section">
            <h2>Vulnerability Details</h2>
            {% for vulnerability in vulnerabilities %}
            <div class="vulnerability severity-{{ vulnerability.severity }}">
                <h3>{{ vulnerability.type }} - {{ vulnerability.name }}</h3>
                <p><strong>Severity:</strong> <span class="risk-indicator risk-{{ vulnerability.severity }}">{{ vulnerability.severity.upper() }}</span></p>
                <p><strong>URL:</strong> {{ vulnerability.url }}</p>
                <p><strong>Parameter:</strong> {{ vulnerability.parameter or 'N/A' }}</p>
                <p><strong>Description:</strong> {{ vulnerability.description }}</p>
                {% if vulnerability.impact %}
                <p><strong>Impact:</strong> {{ vulnerability.impact }}</p>
                {% endif %}
                {% if vulnerability.recommendation %}
                <p><strong>Recommendation:</strong> {{ vulnerability.recommendation }}</p>
                {% endif %}
                {% if vulnerability.payload %}
                <p><strong>Payload:</strong> <code>{{ vulnerability.payload }}</code></p>
                {% endif %}
                <p><strong>Source:</strong> {{ vulnerability.source }}</p>
            </div>
            {% endfor %}
        </div>
        
        <div class="section">
            <h2>Exploitation Results</h2>
            {% for exploit_result in exploitation_results %}
            <div class="vulnerability">
                <h3>{{ exploit_result.vulnerability_type }}</h3>
                <p><strong>Total Attempts:</strong> {{ exploit_result.exploitation_attempts|length }}</p>
                <p><strong>Successful:</strong> {{ exploit_result.successful_exploits|length }}</p>
                <p><strong>Failed:</strong> {{ exploit_result.failed_exploits|length }}</p>
                {% if exploit_result.data_extracted %}
                <p><strong>Data Extracted:</strong> {{ exploit_result.data_extracted|length }} items</p>
                {% endif %}
                {% if exploit_result.system_access %}
                <p><strong>System Access:</strong> Yes</p>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        
        <div class="section">
            <h2>Proof of Concept</h2>
            {% for poc in poc_results %}
            <div class="vulnerability">
                <h3>{{ poc.vulnerability.type }}</h3>
                <p><strong>Screenshots:</strong> {{ poc.screenshots|length }}</p>
                <p><strong>Proof Documents:</strong> {{ poc.proof_documents|length }}</p>
                <p><strong>Generated:</strong> {{ poc.timestamp }}</p>
                
                {% if poc.screenshots %}
                <h4>Screenshots</h4>
                <div class="screenshot-grid">
                    {% for screenshot in poc.screenshots %}
                    <div class="screenshot">
                        <img src="file://{{ screenshot.path }}" alt="{{ screenshot.description }}">
                        <p>{{ screenshot.description }}</p>
                    </div>
                    {% endfor %}
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        
        <div class="section">
            <h2>Timeline</h2>
            <div class="timeline">
                {% for phase in poc_results[0].timeline.phases if poc_results %}
                <div class="timeline-item">
                    <h4>{{ phase.phase }}</h4>
                    <p>{{ phase.description }}</p>
                    <p><strong>Status:</strong> {{ phase.status }}</p>
                </div>
                {% endfor %}
            </div>
        </div>
        
        <div class="section">
            <h2>Security Recommendations</h2>
            {% for recommendation in recommendations %}
            <div class="recommendation">
                <h3>{{ recommendation.title }}</h3>
                <p><strong>Category:</strong> {{ recommendation.category }}</p>
                <p><strong>Priority:</strong> {{ recommendation.priority.upper() }}</p>
                <p>{{ recommendation.description }}</p>
                <p><strong>Affects {{ recommendation.vulnerabilities_count }} vulnerabilities</strong></p>
                <h4>Implementation Steps:</h4>
                <ol>
                    {% for step in recommendation.implementation_steps %}
                    <li>{{ step }}</li>
                    {% endfor %}
                </ol>
            </div>
            {% endfor %}
        </div>
        
        <div class="footer">
            <p>Generated by LOOT Security Assessment Tool</p>
            <p>Developer: Sayer Linux (SayerLinux1@gmail.com)</p>
            <p>Report generated on {{ timestamp }}</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Prepare data for template
        template_data = {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'target_info': processed_results['target_info'],
            'statistics': processed_results['statistics'],
            'risk_assessment': processed_results['risk_assessment'],
            'vulnerabilities': processed_results['vulnerabilities'],
            'exploitation_results': processed_results['exploitation_results'],
            'poc_results': processed_results['poc_results'],
            'recommendations': processed_results['recommendations'],
            'risk_matrix': self.risk_matrix
        }
        
        try:
            if JINJA_AVAILABLE:
                template = Template(html_template)
                html_content = template.render(**template_data)
            else:
                # Simple string replacement if Jinja2 not available
                html_content = html_template
                for key, value in template_data.items():
                    html_content = html_content.replace(f"{{{{ {key} }}}}", str(value))
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"{Fore.GREEN}[+] HTML report generated: {output_file}{Style.RESET_ALL}")
            return output_file
            
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to generate HTML report: {str(e)}{Style.RESET_ALL}")
            return None
    
    def generate_json_report(self, processed_results, output_file=None):
        """Generate JSON report"""
        if output_file is None:
            output_file = os.path.join(self.reports_dir, f"security_assessment_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        try:
            # Add metadata
            processed_results['metadata'] = {
                'report_type': 'security_assessment',
                'generated_by': 'LOOT Security Assessment Tool',
                'developer': 'Sayer Linux',
                'developer_email': 'SayerLinux1@gmail.com',
                'generated_at': datetime.datetime.now().isoformat(),
                'report_version': '1.0'
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(processed_results, f, indent=2, default=str)
            
            print(f"{Fore.GREEN}[+] JSON report generated: {output_file}{Style.RESET_ALL}")
            return output_file
            
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to generate JSON report: {str(e)}{Style.RESET_ALL}")
            return None
    
    def generate_csv_report(self, processed_results, output_file=None):
        """Generate CSV report"""
        if output_file is None:
            output_file = os.path.join(self.reports_dir, f"vulnerabilities_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['type', 'name', 'severity', 'url', 'parameter', 'description', 'impact', 'recommendation', 'source', 'timestamp']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for vuln in processed_results['vulnerabilities']:
                    writer.writerow({
                        'type': vuln.get('type', ''),
                        'name': vuln.get('name', ''),
                        'severity': vuln.get('severity', ''),
                        'url': vuln.get('url', ''),
                        'parameter': vuln.get('parameter', ''),
                        'description': vuln.get('description', ''),
                        'impact': vuln.get('impact', ''),
                        'recommendation': vuln.get('recommendation', ''),
                        'source': vuln.get('source', ''),
                        'timestamp': vuln.get('timestamp', '')
                    })
            
            print(f"{Fore.GREEN}[+] CSV report generated: {output_file}{Style.RESET_ALL}")
            return output_file
            
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to generate CSV report: {str(e)}{Style.RESET_ALL}")
            return None
    
    def generate_markdown_report(self, processed_results, output_file=None):
        """Generate Markdown report"""
        if output_file is None:
            output_file = os.path.join(self.reports_dir, f"security_assessment_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("# Security Assessment Report\n\n")
                f.write(f"**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
                f.write(f"**Target:** {processed_results['target_info'].get('domain', 'Unknown')}  \n")
                f.write(f"**Developer:** Sayer Linux (SayerLinux1@gmail.com)**  \n\n")
                
                f.write("## Executive Summary\n\n")
                f.write(f"- **Total Vulnerabilities:** {processed_results['statistics']['total_vulnerabilities']}\n")
                f.write(f"- **Critical:** {processed_results['statistics']['severity_distribution']['critical']}\n")
                f.write(f"- **High Risk:** {processed_results['statistics']['severity_distribution']['high']}\n")
                f.write(f"- **Exploitation Success Rate:** {processed_results['statistics']['exploitation_success_rate']}%\n")
                f.write(f"- **Overall Risk Level:** {processed_results['risk_assessment']['risk_level'].upper()}\n")
                f.write(f"- **Attack Surface:** {processed_results['risk_assessment']['attack_surface']}\n\n")
                
                f.write("## Vulnerability Summary\n\n")
                f.write("| Severity | Count | Percentage |\n")
                f.write("|----------|-------|------------|\n")
                for severity, count in processed_results['statistics']['severity_distribution'].items():
                    percentage = (count / processed_results['statistics']['total_vulnerabilities'] * 100) if processed_results['statistics']['total_vulnerabilities'] > 0 else 0
                    f.write(f"| {severity.upper()} | {count} | {percentage:.1f}% |\n")
                
                f.write("\n## Vulnerability Details\n\n")
                for vuln in processed_results['vulnerabilities']:
                    f.write(f"### {vuln['type']} - {vuln['name']}\n\n")
                    f.write(f"**Severity:** {vuln['severity'].upper()}  \n")
                    f.write(f"**URL:** {vuln.get('url', 'N/A')}  \n")
                    f.write(f"**Parameter:** {vuln.get('parameter', 'N/A')}  \n")
                    f.write(f"**Description:** {vuln.get('description', 'N/A')}  \n")
                    if vuln.get('impact'):
                        f.write(f"**Impact:** {vuln['impact']}  \n")
                    if vuln.get('recommendation'):
                        f.write(f"**Recommendation:** {vuln['recommendation']}  \n")
                    f.write(f"**Source:** {vuln.get('source', 'Unknown')}  \n\n")
                
                f.write("## Security Recommendations\n\n")
                for rec in processed_results['recommendations']:
                    f.write(f"### {rec['title']}\n\n")
                    f.write(f"**Category:** {rec['category']}  \n")
                    f.write(f"**Priority:** {rec['priority'].upper()}  \n")
                    f.write(f"**Description:** {rec['description']}  \n")
                    f.write(f"**Affects:** {rec['vulnerabilities_count']} vulnerabilities  \n")
                    f.write("**Implementation Steps:**\n")
                    for step in rec['implementation_steps']:
                        f.write(f"1. {step}\n")
                    f.write("\n")
            
            print(f"{Fore.GREEN}[+] Markdown report generated: {output_file}{Style.RESET_ALL}")
            return output_file
            
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to generate Markdown report: {str(e)}{Style.RESET_ALL}")
            return None
    
    def generate_pdf_report(self, processed_results, output_file=None):
        """Generate PDF report"""
        if output_file is None:
            output_file = os.path.join(self.reports_dir, f"security_assessment_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        
        try:
            # First generate HTML report
            html_file = output_file.replace('.pdf', '.html')
            self.generate_html_report(processed_results, html_file)
            
            # Convert HTML to PDF
            if PDFKIT_AVAILABLE:
                pdfkit.from_file(html_file, output_file)
                print(f"{Fore.GREEN}[+] PDF report generated: {output_file}{Style.RESET_ALL}")
                
                # Clean up HTML file
                if os.path.exists(html_file):
                    os.remove(html_file)
                
                return output_file
            else:
                print(f"{Fore.YELLOW}[!] pdfkit not available, keeping HTML version{Style.RESET_ALL}")
                return html_file
                
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to generate PDF report: {str(e)}{Style.RESET_ALL}")
            return None
    
    def generate_executive_summary(self, processed_results, output_file=None):
        """Generate executive summary report"""
        if output_file is None:
            output_file = os.path.join(self.reports_dir, f"executive_summary_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Summary - Security Assessment</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px; }
        .summary-box { background: #f9f9f9; padding: 20px; border-radius: 10px; margin: 20px 0; }
        .risk-indicator { display: inline-block; padding: 10px 20px; border-radius: 25px; color: white; font-weight: bold; font-size: 1.2em; }
        .risk-critical { background-color: #FF0000; }
        .risk-high { background-color: #FF6600; }
        .risk-medium { background-color: #FFCC00; }
        .risk-low { background-color: #00CC00; }
        .stat-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin: 20px 0; }
        .stat-item { text-align: center; padding: 15px; background: white; border-radius: 5px; }
        .stat-number { font-size: 2em; font-weight: bold; color: #667eea; }
        .recommendation { background: #e8f5e8; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #28a745; }
        .footer { text-align: center; padding: 20px; color: #666; border-top: 1px solid #eee; margin-top: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Executive Summary</h1>
            <h2>Security Assessment Report</h2>
            <p>{{ timestamp }} | {{ target_info.domain }}</p>
        </div>
        
        <div class="summary-box">
            <h3>Overall Risk Assessment</h3>
            <p><strong>Risk Level:</strong> <span class="risk-indicator risk-{{ risk_assessment.risk_level }}">{{ risk_assessment.risk_level.upper() }}</span></p>
            <p><strong>Attack Surface:</strong> {{ risk_assessment.attack_surface }}</p>
            <p><strong>Risk Score:</strong> {{ risk_assessment.overall_risk_score }}/10</p>
        </div>
        
        <div class="stat-grid">
            <div class="stat-item">
                <div class="stat-number">{{ statistics.total_vulnerabilities }}</div>
                <div>Total Vulnerabilities Found</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">{{ statistics.severity_distribution.critical }}</div>
                <div>Critical Vulnerabilities</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">{{ statistics.severity_distribution.high }}</div>
                <div>High Risk Issues</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">{{ statistics.exploitation_success_rate }}%</div>
                <div>Exploitation Success Rate</div>
            </div>
        </div>
        
        <div class="summary-box">
            <h3>Key Findings</h3>
            <ul>
                <li>Total of {{ statistics.total_vulnerabilities }} security vulnerabilities identified</li>
                <li>{{ statistics.severity_distribution.critical }} critical and {{ statistics.severity_distribution.high }} high-risk vulnerabilities require immediate attention</li>
                <li>Attack surface assessment: {{ risk_assessment.attack_surface }}</li>
                <li>{{ statistics.exploitation_success_rate }}% of attempted exploits were successful</li>
                <li>Scan completed in {{ statistics.scan_duration }}</li>
            </ul>
        </div>
        
        <div class="summary-box">
            <h3>Immediate Actions Required</h3>
            {% for rec in recommendations[:3] %}
            <div class="recommendation">
                <strong>{{ rec.title }}</strong><br>
                {{ rec.description }}
            </div>
            {% endfor %}
        </div>
        
        <div class="footer">
            <p>Generated by LOOT Security Assessment Tool</p>
            <p>Developer: Sayer Linux (SayerLinux1@gmail.com)</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Prepare data for template
        template_data = {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'target_info': processed_results['target_info'],
            'statistics': processed_results['statistics'],
            'risk_assessment': processed_results['risk_assessment'],
            'recommendations': processed_results['recommendations'][:3]  # Top 3 recommendations
        }
        
        try:
            if JINJA_AVAILABLE:
                template = Template(html_template)
                html_content = template.render(**template_data)
            else:
                html_content = html_template
                for key, value in template_data.items():
                    html_content = html_content.replace(f"{{{{ {key} }}}}", str(value))
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"{Fore.GREEN}[+] Executive summary generated: {output_file}{Style.RESET_ALL}")
            return output_file
            
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to generate executive summary: {str(e)}{Style.RESET_ALL}")
            return None
    
    def generate_charts(self, processed_results, output_dir=None):
        """Generate charts and graphs"""
        if output_dir is None:
            output_dir = self.assets_dir
        
        if not MATPLOTLIB_AVAILABLE:
            print(f"{Fore.YELLOW}[!] matplotlib not available, skipping charts{Style.RESET_ALL}")
            return []
        
        charts = []
        
        try:
            # Severity distribution pie chart
            plt.figure(figsize=(10, 6))
            severity_data = processed_results['statistics']['severity_distribution']
            labels = list(severity_data.keys())
            sizes = list(severity_data.values())
            colors = ['#FF0000', '#FF6600', '#FFCC00', '#00CC00', '#0099FF']
            
            plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
            plt.title('Vulnerability Severity Distribution')
            plt.axis('equal')
            
            chart_path = os.path.join(output_dir, 'severity_distribution.png')
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            charts.append(chart_path)
            
            # Vulnerability types bar chart
            plt.figure(figsize=(12, 6))
            vuln_types = processed_results['statistics']['vulnerability_types']
            types = list(vuln_types.keys())
            counts = list(vuln_types.values())
            
            plt.bar(types, counts, color='#667eea')
            plt.title('Vulnerabilities by Type')
            plt.xlabel('Vulnerability Type')
            plt.ylabel('Count')
            plt.xticks(rotation=45)
            
            chart_path = os.path.join(output_dir, 'vulnerability_types.png')
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            charts.append(chart_path)
            
            print(f"{Fore.GREEN}[+] Generated {len(charts)} charts{Style.RESET_ALL}")
            return charts
            
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to generate charts: {str(e)}{Style.RESET_ALL}")
            return []