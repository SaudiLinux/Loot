#!/usr/bin/env python3
"""
Proof of Concept Generator Module - Screenshot and Demo Generation
Author: Sayer Linux (SayerLinux1@gmail.com)
"""

import os
import json
import time
import base64
import subprocess
import tempfile
from datetime import datetime
from colorama import Fore, Style
import requests
import threading
import socket
from urllib.parse import urlparse

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] Selenium not available. Install with: pip install selenium webdriver-manager{Style.RESET_ALL}")

try:
    import pyautogui
    PYAUTOGUI_AVAILABLE = True
except ImportError:
    PYAUTOGUI_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] PyAutoGUI not available. Install with: pip install pyautogui{Style.RESET_ALL}")

try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] PIL not available. Install with: pip install pillow{Style.RESET_ALL}")

class POCGenerator:
    def __init__(self):
        self.screenshots = []
        self.demo_videos = []
        self.proof_documents = []
        self.temp_dir = tempfile.mkdtemp()
        self.webdriver = None
        self.setup_webdriver()
        
        # Exploitation demos
        self.exploitation_demos = {
            'sql_injection': self.demo_sql_injection,
            'xss': self.demo_xss,
            'lfi': self.demo_lfi,
            'rfi': self.demo_rfi,
            'command_injection': self.demo_command_injection,
            'xxe': self.demo_xxe,
            'ssrf': self.demo_ssrf,
            'idor': self.demo_idor
        }
    
    def setup_webdriver(self):
        """Setup Chrome webdriver for screenshots"""
        if not SELENIUM_AVAILABLE:
            return
        
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--disable-features=VizDisplayCompositor')
            
            service = Service(ChromeDriverManager().install())
            self.webdriver = webdriver.Chrome(service=service, options=chrome_options)
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Could not setup webdriver: {str(e)}{Style.RESET_ALL}")
            self.webdriver = None
    
    def generate_poc(self, vulnerability, exploitation_result, target):
        """Generate comprehensive proof of concept"""
        print(f"{Fore.CYAN}[*] Generating proof of concept...{Style.RESET_ALL}")
        
        poc_result = {
            'vulnerability': vulnerability,
            'exploitation_result': exploitation_result,
            'screenshots': [],
            'demo_files': [],
            'proof_documents': [],
            'timestamp': datetime.now().isoformat(),
            'target': target
        }
        
        # Generate vulnerability-specific demo
        vuln_type = vulnerability['type'].lower()
        
        if 'sql' in vuln_type:
            poc_result['screenshots'].extend(self.demo_sql_injection(vulnerability, exploitation_result, target))
        elif 'xss' in vuln_type:
            poc_result['screenshots'].extend(self.demo_xss(vulnerability, exploitation_result, target))
        elif 'lfi' in vuln_type:
            poc_result['screenshots'].extend(self.demo_lfi(vulnerability, exploitation_result, target))
        elif 'rfi' in vuln_type:
            poc_result['screenshots'].extend(self.demo_rfi(vulnerability, exploitation_result, target))
        elif 'command' in vuln_type:
            poc_result['screenshots'].extend(self.demo_command_injection(vulnerability, exploitation_result, target))
        elif 'xxe' in vuln_type:
            poc_result['screenshots'].extend(self.demo_xxe(vulnerability, exploitation_result, target))
        elif 'ssrf' in vuln_type:
            poc_result['screenshots'].extend(self.demo_ssrf(vulnerability, exploitation_result, target))
        elif 'idor' in vuln_type:
            poc_result['screenshots'].extend(self.demo_idor(vulnerability, exploitation_result, target))
        
        # Generate general screenshots
        poc_result['screenshots'].extend(self.capture_general_screenshots(vulnerability, exploitation_result, target))
        
        # Generate proof document
        proof_doc = self.generate_proof_document(vulnerability, exploitation_result, poc_result['screenshots'])
        poc_result['proof_documents'].append(proof_doc)
        
        # Generate exploitation timeline
        timeline = self.generate_exploitation_timeline(exploitation_result)
        poc_result['timeline'] = timeline
        
        return poc_result
    
    def demo_sql_injection(self, vulnerability, exploitation_result, target):
        """Demonstrate SQL injection exploitation"""
        screenshots = []
        
        print(f"{Fore.YELLOW}[*] Creating SQL injection demo...{Style.RESET_ALL}")
        
        # Capture before exploitation
        before_screenshot = self.capture_webpage(target, "before_exploitation")
        if before_screenshot:
            screenshots.append(before_screenshot)
        
        # Capture exploitation attempts
        for i, attempt in enumerate(exploitation_result['successful_exploits'][:3]):
            if 'data_extraction' in attempt['technique'].lower():
                # Create exploitation URL
                vuln_url = vulnerability.get('url', target)
                payload = attempt['payload']
                
                # Capture exploitation screenshot
                exploit_screenshot = self.capture_exploitation_attempt(vuln_url, payload, f"sql_injection_{i+1}")
                if exploit_screenshot:
                    screenshots.append(exploit_screenshot)
                
                # Create data extraction proof
                if attempt.get('data_extracted'):
                    data_proof = self.create_data_extraction_proof(attempt['data_extracted'], f"sql_data_{i+1}")
                    if data_proof:
                        screenshots.append(data_proof)
        
        # Capture authentication bypass if successful
        auth_bypasses = [a for a in exploitation_result['successful_exploits'] if 'authentication' in a['technique'].lower()]
        if auth_bypasses:
            auth_screenshot = self.capture_auth_bypass(target, auth_bypasses[0], "auth_bypass")
            if auth_screenshot:
                screenshots.append(auth_screenshot)
        
        return screenshots
    
    def demo_xss(self, vulnerability, exploitation_result, target):
        """Demonstrate XSS exploitation"""
        screenshots = []
        
        print(f"{Fore.YELLOW}[*] Creating XSS demo...{Style.RESET_ALL}")
        
        # Capture normal page
        normal_screenshot = self.capture_webpage(target, "normal_page")
        if normal_screenshot:
            screenshots.append(normal_screenshot)
        
        # Capture XSS payload injection
        for i, attempt in enumerate(exploitation_result['successful_exploits'][:2]):
            payload = attempt['payload']
            
            # Create XSS demo screenshot
            xss_screenshot = self.capture_xss_demo(target, payload, f"xss_payload_{i+1}")
            if xss_screenshot:
                screenshots.append(xss_screenshot)
            
            # Create cookie stealing demo
            if 'cookie' in payload.lower():
                cookie_proof = self.create_cookie_stealing_proof(payload, f"cookie_steal_{i+1}")
                if cookie_proof:
                    screenshots.append(cookie_proof)
        
        return screenshots
    
    def demo_lfi(self, vulnerability, exploitation_result, target):
        """Demonstrate LFI exploitation"""
        screenshots = []
        
        print(f"{Fore.YELLOW}[*] Creating LFI demo...{Style.RESET_ALL}")
        
        # Capture normal parameter usage
        normal_screenshot = self.capture_parameter_usage(target, vulnerability, "normal_usage")
        if normal_screenshot:
            screenshots.append(normal_screenshot)
        
        # Capture file inclusion attempts
        for i, attempt in enumerate(exploitation_result['successful_exploits'][:3]):
            payload = attempt['payload']
            
            # Create LFI exploitation screenshot
            lfi_screenshot = self.capture_lfi_exploitation(target, payload, f"lfi_exploit_{i+1}")
            if lfi_screenshot:
                screenshots.append(lfi_screenshot)
            
            # Create file content proof
            if attempt.get('data_extracted'):
                file_proof = self.create_file_content_proof(attempt['data_extracted'], f"file_content_{i+1}")
                if file_proof:
                    screenshots.append(file_proof)
        
        return screenshots
    
    def demo_rfi(self, vulnerability, exploitation_result, target):
        """Demonstrate RFI exploitation"""
        screenshots = []
        
        print(f"{Fore.YELLOW}[*] Creating RFI demo...{Style.RESET_ALL}")
        
        # Capture before exploitation
        before_screenshot = self.capture_webpage(target, "before_rfi")
        if before_screenshot:
            screenshots.append(before_screenshot)
        
        # Capture remote file inclusion
        for i, attempt in enumerate(exploitation_result['successful_exploits'][:2]):
            payload = attempt['payload']
            
            # Create RFI exploitation screenshot
            rfi_screenshot = self.capture_rfi_exploitation(target, payload, f"rfi_exploit_{i+1}")
            if rfi_screenshot:
                screenshots.append(rfi_screenshot)
            
            # Create remote shell proof
            if attempt.get('system_access'):
                shell_proof = self.create_remote_shell_proof(payload, f"remote_shell_{i+1}")
                if shell_proof:
                    screenshots.append(shell_proof)
        
        return screenshots
    
    def demo_command_injection(self, vulnerability, exploitation_result, target):
        """Demonstrate command injection exploitation"""
        screenshots = []
        
        print(f"{Fore.YELLOW}[*] Creating command injection demo...{Style.RESET_ALL}")
        
        # Capture normal input
        normal_screenshot = self.capture_input_field(target, vulnerability, "normal_input")
        if normal_screenshot:
            screenshots.append(normal_screenshot)
        
        # Capture command execution
        for i, attempt in enumerate(exploitation_result['successful_exploits'][:3]):
            payload = attempt['payload']
            
            # Create command injection screenshot
            cmd_screenshot = self.capture_command_injection(target, payload, f"cmd_inject_{i+1}")
            if cmd_screenshot:
                screenshots.append(cmd_screenshot)
            
            # Create command output proof
            if attempt.get('data_extracted'):
                output_proof = self.create_command_output_proof(attempt['data_extracted'], f"cmd_output_{i+1}")
                if output_proof:
                    screenshots.append(output_proof)
        
        return screenshots
    
    def demo_xxe(self, vulnerability, exploitation_result, target):
        """Demonstrate XXE exploitation"""
        screenshots = []
        
        print(f"{Fore.YELLOW}[*] Creating XXE demo...{Style.RESET_ALL}")
        
        # Capture normal XML usage
        normal_screenshot = self.capture_xml_usage(target, "normal_xml")
        if normal_screenshot:
            screenshots.append(normal_screenshot)
        
        # Capture XXE exploitation
        for i, attempt in enumerate(exploitation_result['successful_exploits'][:2]):
            payload = attempt['payload']
            
            # Create XXE exploitation screenshot
            xxe_screenshot = self.capture_xxe_exploitation(target, payload, f"xxe_exploit_{i+1}")
            if xxe_screenshot:
                screenshots.append(xxe_screenshot)
            
            # Create file content proof
            if attempt.get('data_extracted'):
                file_proof = self.create_xxe_file_proof(attempt['data_extracted'], f"xxe_file_{i+1}")
                if file_proof:
                    screenshots.append(file_proof)
        
        return screenshots
    
    def demo_ssrf(self, vulnerability, exploitation_result, target):
        """Demonstrate SSRF exploitation"""
        screenshots = []
        
        print(f"{Fore.YELLOW}[*] Creating SSRF demo...{Style.RESET_ALL}")
        
        # Capture normal URL usage
        normal_screenshot = self.capture_url_usage(target, vulnerability, "normal_url")
        if normal_screenshot:
            screenshots.append(normal_screenshot)
        
        # Capture SSRF exploitation
        for i, attempt in enumerate(exploitation_result['successful_exploits'][:3]):
            payload = attempt['payload']
            
            # Create SSRF exploitation screenshot
            ssrf_screenshot = self.capture_ssrf_exploitation(target, payload, f"ssrf_exploit_{i+1}")
            if ssrf_screenshot:
                screenshots.append(ssrf_screenshot)
            
            # Create internal service proof
            if attempt.get('data_extracted'):
                service_proof = self.create_internal_service_proof(attempt['data_extracted'], f"internal_service_{i+1}")
                if service_proof:
                    screenshots.append(service_proof)
        
        return screenshots
    
    def demo_idor(self, vulnerability, exploitation_result, target):
        """Demonstrate IDOR exploitation"""
        screenshots = []
        
        print(f"{Fore.YELLOW}[*] Creating IDOR demo...{Style.RESET_ALL}")
        
        # Capture normal parameter usage
        normal_screenshot = self.capture_parameter_usage(target, vulnerability, "normal_param")
        if normal_screenshot:
            screenshots.append(normal_screenshot)
        
        # Capture IDOR exploitation
        for i, attempt in enumerate(exploitation_result['successful_exploits'][:3]):
            payload = attempt['payload']
            
            # Create IDOR exploitation screenshot
            idor_screenshot = self.capture_idor_exploitation(target, payload, f"idor_exploit_{i+1}")
            if idor_screenshot:
                screenshots.append(idor_screenshot)
            
            # Create unauthorized access proof
            if attempt.get('data_extracted'):
                access_proof = self.create_unauthorized_access_proof(attempt['data_extracted'], f"unauth_access_{i+1}")
                if access_proof:
                    screenshots.append(access_proof)
        
        return screenshots
    
    def capture_webpage(self, url, filename):
        """Capture webpage screenshot"""
        if not self.webdriver:
            return None
        
        try:
            self.webdriver.get(url)
            time.sleep(2)
            
            screenshot_path = os.path.join(self.temp_dir, f"{filename}.png")
            self.webdriver.save_screenshot(screenshot_path)
            
            return {
                'type': 'webpage_screenshot',
                'filename': f"{filename}.png",
                'path': screenshot_path,
                'description': f"Screenshot of {url}",
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to capture webpage: {str(e)}{Style.RESET_ALL}")
            return None
    
    def capture_exploitation_attempt(self, url, payload, filename):
        """Capture exploitation attempt"""
        if not self.webdriver:
            return None
        
        try:
            # Create exploitation URL
            exploit_url = url.replace("PAYLOAD", payload)
            
            self.webdriver.get(exploit_url)
            time.sleep(3)
            
            screenshot_path = os.path.join(self.temp_dir, f"{filename}.png")
            self.webdriver.save_screenshot(screenshot_path)
            
            return {
                'type': 'exploitation_screenshot',
                'filename': f"{filename}.png",
                'path': screenshot_path,
                'description': f"Exploitation attempt with payload: {payload[:50]}...",
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to capture exploitation: {str(e)}{Style.RESET_ALL}")
            return None
    
    def capture_xss_demo(self, target, payload, filename):
        """Capture XSS demo"""
        if not self.webdriver:
            return None
        
        try:
            # Navigate to vulnerable page
            self.webdriver.get(target)
            time.sleep(2)
            
            # Inject payload (simplified demo)
            try:
                # Try to find input fields
                inputs = self.webdriver.find_elements(By.TAG_NAME, "input")
                if inputs:
                    inputs[0].clear()
                    inputs[0].send_keys(payload)
                    inputs[0].submit()
                    time.sleep(2)
            except:
                pass
            
            screenshot_path = os.path.join(self.temp_dir, f"{filename}.png")
            self.webdriver.save_screenshot(screenshot_path)
            
            return {
                'type': 'xss_demo_screenshot',
                'filename': f"{filename}.png",
                'path': screenshot_path,
                'description': f"XSS payload injection demo",
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to capture XSS demo: {str(e)}{Style.RESET_ALL}")
            return None
    
    def create_data_extraction_proof(self, extracted_data, filename):
        """Create data extraction proof"""
        try:
            proof_path = os.path.join(self.temp_dir, f"{filename}.txt")
            
            with open(proof_path, 'w') as f:
                f.write("DATA EXTRACTION PROOF\n")
                f.write("=" * 50 + "\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write("=" * 50 + "\n\n")
                
                for item in extracted_data:
                    f.write(f"• {item}\n")
            
            return {
                'type': 'data_extraction_proof',
                'filename': f"{filename}.txt",
                'path': proof_path,
                'description': f"Proof of extracted data ({len(extracted_data)} items)",
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to create data proof: {str(e)}{Style.RESET_ALL}")
            return None
    
    def capture_general_screenshots(self, vulnerability, exploitation_result, target):
        """Capture general screenshots"""
        screenshots = []
        
        # Capture vulnerability details
        vuln_details = self.create_vulnerability_details_screenshot(vulnerability, "vulnerability_details")
        if vuln_details:
            screenshots.append(vuln_details)
        
        # Capture exploitation summary
        exploit_summary = self.create_exploitation_summary_screenshot(exploitation_result, "exploitation_summary")
        if exploit_summary:
            screenshots.append(exploit_summary)
        
        # Capture system access proof
        if exploitation_result.get('system_access'):
            access_proof = self.create_system_access_proof(exploitation_result, "system_access")
            if access_proof:
                screenshots.append(access_proof)
        
        return screenshots
    
    def create_vulnerability_details_screenshot(self, vulnerability, filename):
        """Create vulnerability details screenshot"""
        try:
            if PIL_AVAILABLE:
                # Create image with vulnerability details
                img = Image.new('RGB', (800, 600), color='white')
                draw = ImageDraw.Draw(img)
                
                # Add text
                draw.text((10, 10), "VULNERABILITY DETAILS", fill='black')
                draw.text((10, 50), f"Type: {vulnerability['type']}", fill='black')
                draw.text((10, 80), f"Severity: {vulnerability.get('severity', 'Unknown')}", fill='black')
                draw.text((10, 110), f"URL: {vulnerability.get('url', 'N/A')}", fill='black')
                
                screenshot_path = os.path.join(self.temp_dir, f"{filename}.png")
                img.save(screenshot_path)
                
                return {
                    'type': 'vulnerability_details',
                    'filename': f"{filename}.png",
                    'path': screenshot_path,
                    'description': "Vulnerability details summary",
                    'timestamp': datetime.now().isoformat()
                }
            
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to create vulnerability details: {str(e)}{Style.RESET_ALL}")
            
        return None
    
    def create_exploitation_summary_screenshot(self, exploitation_result, filename):
        """Create exploitation summary screenshot"""
        try:
            if PIL_AVAILABLE:
                # Create image with exploitation summary
                img = Image.new('RGB', (800, 600), color='white')
                draw = ImageDraw.Draw(img)
                
                # Add text
                draw.text((10, 10), "EXPLOITATION SUMMARY", fill='black')
                draw.text((10, 50), f"Total Attempts: {len(exploitation_result['exploitation_attempts'])}", fill='black')
                draw.text((10, 80), f"Successful: {len(exploitation_result['successful_exploits'])}", fill='green')
                draw.text((10, 110), f"Failed: {len(exploitation_result['failed_exploits'])}", fill='red')
                
                if exploitation_result.get('data_extracted'):
                    draw.text((10, 140), f"Data Extracted: {len(exploitation_result['data_extracted'])} items", fill='blue')
                
                screenshot_path = os.path.join(self.temp_dir, f"{filename}.png")
                img.save(screenshot_path)
                
                return {
                    'type': 'exploitation_summary',
                    'filename': f"{filename}.png",
                    'path': screenshot_path,
                    'description': "Exploitation summary",
                    'timestamp': datetime.now().isoformat()
                }
            
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to create exploitation summary: {str(e)}{Style.RESET_ALL}")
            
        return None
    
    def generate_proof_document(self, vulnerability, exploitation_result, screenshots):
        """Generate comprehensive proof document"""
        try:
            doc_path = os.path.join(self.temp_dir, "proof_document.md")
            
            with open(doc_path, 'w') as f:
                f.write(f"# Proof of Concept - {vulnerability['type']}\n\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"**Target:** {exploitation_result['target']}\n\n")
                f.write(f"**Vulnerability Type:** {vulnerability['type']}\n\n")
                f.write(f"**Severity:** {vulnerability.get('severity', 'Unknown')}\n\n")
                
                f.write("## Exploitation Results\n\n")
                f.write(f"- **Total Attempts:** {len(exploitation_result['exploitation_attempts'])}\n")
                f.write(f"- **Successful Exploits:** {len(exploitation_result['successful_exploits'])}\n")
                f.write(f"- **Failed Exploits:** {len(exploitation_result['failed_exploits'])}\n")
                f.write(f"- **System Access:** {'Yes' if exploitation_result.get('system_access') else 'No'}\n\n")
                
                if exploitation_result.get('data_extracted'):
                    f.write("## Extracted Data\n\n")
                    for item in exploitation_result['data_extracted']:
                        f.write(f"- {item}\n")
                    f.write("\n")
                
                f.write("## Screenshots\n\n")
                for screenshot in screenshots:
                    f.write(f"### {screenshot['description']}\n")
                    f.write(f"- File: {screenshot['filename']}\n")
                    f.write(f"- Type: {screenshot['type']}\n")
                    f.write(f"- Timestamp: {screenshot['timestamp']}\n\n")
                
                if exploitation_result.get('proof_of_concept'):
                    poc = exploitation_result['proof_of_concept']
                    f.write("## Proof of Concept Details\n\n")
                    f.write(f"**Impact:** {poc.get('impact', 'Not specified')}\n\n")
                    f.write(f"**Recommendation:** {poc.get('recommendation', 'Not specified')}\n\n")
                    
                    if poc.get('exploitation_steps'):
                        f.write("### Exploitation Steps\n\n")
                        for step in poc['exploitation_steps']:
                            f.write(f"1. **{step['technique']}**\n")
                            f.write(f"   - Payload: `{step['payload']}`\n")
                            f.write(f"   - Result: {step['result']}\n\n")
            
            return {
                'type': 'proof_document',
                'filename': 'proof_document.md',
                'path': doc_path,
                'description': 'Comprehensive proof of concept document',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to generate proof document: {str(e)}{Style.RESET_ALL}")
            return None
    
    def generate_exploitation_timeline(self, exploitation_result):
        """Generate exploitation timeline"""
        timeline = {
            'start_time': exploitation_result.get('timestamp'),
            'duration': 'Unknown',
            'phases': []
        }
        
        # Add reconnaissance phase
        timeline['phases'].append({
            'phase': 'Reconnaissance',
            'description': 'Target scanning and vulnerability identification',
            'status': 'completed'
        })
        
        # Add exploitation phase
        timeline['phases'].append({
            'phase': 'Exploitation',
            'description': f'Attempted {len(exploitation_result["exploitation_attempts"])} exploitation techniques',
            'status': 'completed',
            'successful_exploits': len(exploitation_result['successful_exploits'])
        })
        
        # Add post-exploitation phase
        if exploitation_result.get('data_extracted') or exploitation_result.get('system_access'):
            timeline['phases'].append({
                'phase': 'Post-Exploitation',
                'description': 'Data extraction and system access',
                'status': 'completed',
                'data_extracted': len(exploitation_result.get('data_extracted', []))
            })
        
        return timeline
    
    def cleanup(self):
        """Cleanup temporary files"""
        try:
            if self.webdriver:
                self.webdriver.quit()
            
            # Clean up temp directory
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Cleanup warning: {str(e)}{Style.RESET_ALL}")
    
    def __del__(self):
        """Destructor"""
        self.cleanup()