#!/usr/bin/env python3
"""
Zero-Day Vulnerability Display Tool - CLI Interface
Author: Sayer Linux (SayerLinux1@gmail.com)
"""

import argparse
import sys
import os
from colorama import Fore, Style, init

# Add the parent directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.zero_day_display import ZeroDayDisplay

# Initialize colorama
init(autoreset=True)

def print_banner():
    """Print the tool banner"""
    banner = f"""
{Fore.RED}{'='*80}
{Fore.RED}{' '*25}🔥 ZERO-DAY VULNERABILITY DISPLAY 🔥{Fore.RED}{' '*25}
{Fore.RED}{'='*80}
{Fore.CYAN}
  ███████╗███████╗ ██████╗ █████╗ ███████╗██╗  ██╗
  ╚══███╔╝██╔════╝██╔════╝██╔══██╗██╔════╝██║  ██║
    ███╔╝ █████╗  ██║     ███████║███████╗███████║
   ███╔╝  ██╔══╝  ██║     ██╔══██║╚════██║██╔══██║
  ███████╗███████╗╚██████╗██║  ██║███████║██║  ██║
  ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.GREEN}Advanced Zero-Day Vulnerability Management & Display Tool{Style.RESET_ALL}
{Fore.YELLOW}Author: Sayer Linux (SayerLinux1@gmail.com){Style.RESET_ALL}
{Fore.RED}{'='*80}{Style.RESET_ALL}
"""
    print(banner)

def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description='Zero-Day Vulnerability Display Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.CYAN}Examples:{Style.RESET_ALL}
  {Fore.GREEN}python zero_day_tool.py{Style.RESET_ALL}                    # Display all zero-days
  {Fore.GREEN}python zero_day_tool.py --severity Critical{Style.RESET_ALL}    # Show only critical
  {Fore.GREEN}python zero_day_tool.py --status Public{Style.RESET_ALL}         # Show public disclosures
  {Fore.GREEN}python zero_day_tool.py --search log4j{Style.RESET_ALL}          # Search for Log4j
  {Fore.GREEN}python zero_day_tool.py --interactive{Style.RESET_ALL}           # Interactive mode
  {Fore.GREEN}python zero_day_tool.py --export results.json{Style.RESET_ALL}    # Export to JSON
  {Fore.GREEN}python zero_day_tool.py --add-vuln{Style.RESET_ALL}             # Add new vulnerability
        """
    )
    
    # Add arguments
    parser.add_argument(
        '--severity', '-s',
        choices=['Critical', 'High', 'Medium', 'Low'],
        help='Filter by severity level'
    )
    
    parser.add_argument(
        '--status', '-st',
        choices=['Public', 'Limited', 'Private'],
        help='Filter by disclosure status'
    )
    
    parser.add_argument(
        '--search', '-q',
        type=str,
        help='Search term for vulnerability title, description, or tags'
    )
    
    parser.add_argument(
        '--interactive', '-i',
        action='store_true',
        help='Run in interactive mode'
    )
    
    parser.add_argument(
        '--export', '-e',
        type=str,
        metavar='FILENAME',
        help='Export results to JSON file'
    )
    
    parser.add_argument(
        '--import', '-im',
        dest='import_file',
        type=str,
        metavar='FILENAME',
        help='Import vulnerabilities from JSON file'
    )
    
    parser.add_argument(
        '--add-vuln', '-a',
        action='store_true',
        help='Add a new zero-day vulnerability (interactive)'
    )
    
    parser.add_argument(
        '--list-tags', '-t',
        action='store_true',
        help='List all available vulnerability tags'
    )
    
    parser.add_argument(
        '--statistics', '--stats',
        action='store_true',
        help='Show detailed statistics'
    )
    
    parser.add_argument(
        '--generate-exploit', '-g',
        type=str,
        metavar='VULN_ID',
        help='Generate exploit template for specific vulnerability'
    )
    
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Initialize the zero-day display tool
    display = ZeroDayDisplay()
    
    # Handle import if specified
    if args.import_file:
        display.import_from_json(args.import_file)
    
    # Handle add vulnerability
    if args.add_vuln:
        add_new_vulnerability(display)
        return
    
    # Handle list tags
    if args.list_tags:
        list_all_tags(display)
        return
    
    # Handle statistics
    if args.statistics:
        show_statistics(display)
        return
    
    # Handle exploit generation
    if args.generate_exploit:
        generate_exploit_template(display, args.generate_exploit)
        return
    
    # Handle interactive mode
    if args.interactive:
        interactive_mode(display)
        return
    
    # Display vulnerabilities with filters
    display.display_zero_days(
        filter_severity=args.severity,
        filter_status=args.status,
        search_term=args.search
    )
    
    # Handle export
    if args.export:
        display.export_to_json(args.export)

def add_new_vulnerability(display):
    """Interactive mode for adding new vulnerabilities"""
    print(f"\n{Fore.CYAN}📝 ADD NEW ZERO-DAY VULNERABILITY{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    
    try:
        vuln_data = {}
        
        # Basic information
        vuln_data['title'] = input(f"{Fore.WHITE}Vulnerability Title: {Style.RESET_ALL}").strip()
        vuln_data['severity'] = input(f"{Fore.WHITE}Severity (Critical/High/Medium/Low): {Style.RESET_ALL}").strip()
        vuln_data['cvss_score'] = float(input(f"{Fore.WHITE}CVSS Score (0-10): {Style.RESET_ALL}").strip())
        
        # Affected systems
        systems_input = input(f"{Fore.WHITE}Affected Systems (comma-separated): {Style.RESET_ALL}").strip()
        vuln_data['affected_systems'] = [s.strip() for s in systems_input.split(',')]
        
        vuln_data['description'] = input(f"{Fore.WHITE}Description: {Style.RESET_ALL}").strip()
        vuln_data['disclosure_status'] = input(f"{Fore.WHITE}Disclosure Status (Public/Limited/Private): {Style.RESET_ALL}").strip()
        
        exploit_available = input(f"{Fore.WHITE}Exploit Available (yes/no): {Style.RESET_ALL}").strip().lower()
        vuln_data['exploit_available'] = exploit_available in ['yes', 'y', 'true']
        
        vuln_data['exploit_complexity'] = input(f"{Fore.WHITE}Exploit Complexity (Low/Medium/High): {Style.RESET_ALL}").strip()
        vuln_data['impact'] = input(f"{Fore.WHITE}Impact Description: {Style.RESET_ALL}").strip()
        vuln_data['mitigation'] = input(f"{Fore.WHITE}Mitigation Steps: {Style.RESET_ALL}").strip()
        
        # Tags
        tags_input = input(f"{Fore.WHITE}Tags (comma-separated): {Style.RESET_ALL}").strip()
        vuln_data['tags'] = [t.strip() for t in tags_input.split(',')]
        
        # References
        refs_input = input(f"{Fore.WHITE}References (comma-separated URLs): {Style.RESET_ALL}").strip()
        vuln_data['references'] = [r.strip() for r in refs_input.split(',')] if refs_input else []
        
        # Add the vulnerability
        vuln_id = display.add_zero_day(vuln_data)
        print(f"\n{Fore.GREEN}✅ Vulnerability added successfully with ID: {vuln_id}{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️  Operation cancelled by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}❌ Error adding vulnerability: {str(e)}{Style.RESET_ALL}")

def list_all_tags(display):
    """List all available vulnerability tags"""
    print(f"\n{Fore.CYAN}🏷️  AVAILABLE VULNERABILITY TAGS{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*40}{Style.RESET_ALL}")
    
    all_tags = set()
    for vuln in display.zero_day_database:
        all_tags.update(vuln.get('tags', []))
    
    if all_tags:
        for tag in sorted(all_tags):
            print(f"{Fore.YELLOW}• {tag}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}No tags found.{Style.RESET_ALL}")

def show_statistics(display):
    """Show detailed statistics"""
    print(f"\n{Fore.CYAN}📊 DETAILED STATISTICS{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    
    total = len(display.zero_day_database)
    
    # Severity breakdown
    severities = {}
    statuses = {}
    tags = {}
    
    for vuln in display.zero_day_database:
        # Severity
        sev = vuln.get('severity', 'Unknown')
        severities[sev] = severities.get(sev, 0) + 1
        
        # Status
        status = vuln.get('disclosure_status', 'Unknown')
        statuses[status] = statuses.get(status, 0) + 1
        
        # Tags
        for tag in vuln.get('tags', []):
            tags[tag] = tags.get(tag, 0) + 1
    
    print(f"\n{Fore.WHITE}Total Vulnerabilities: {Fore.YELLOW}{total}{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}Severity Distribution:{Style.RESET_ALL}")
    for sev, count in severities.items():
        color = Fore.RED if sev == 'Critical' else Fore.MAGENTA if sev == 'High' else Fore.YELLOW if sev == 'Medium' else Fore.GREEN
        print(f"  {color}{sev}: {count}{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}Disclosure Status:{Style.RESET_ALL}")
    for status, count in statuses.items():
        print(f"  {Fore.WHITE}{status}: {count}{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}Top Tags:{Style.RESET_ALL}")
    sorted_tags = sorted(tags.items(), key=lambda x: x[1], reverse=True)
    for tag, count in sorted_tags[:10]:
        print(f"  {Fore.YELLOW}{tag}: {count}{Style.RESET_ALL}")

def generate_exploit_template(display, vuln_id):
    """Generate exploit template for specific vulnerability"""
    print(f"\n{Fore.CYAN}🔧 GENERATE EXPLOIT TEMPLATE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    
    # Find the vulnerability
    vuln = None
    for v in display.zero_day_database:
        if v['id'] == vuln_id:
            vuln = v
            break
    
    if not vuln:
        print(f"{Fore.RED}❌ Vulnerability with ID {vuln_id} not found.{Style.RESET_ALL}")
        return
    
    print(f"{Fore.GREEN}Generating exploit template for: {vuln['title']}{Style.RESET_ALL}")
    
    # Generate exploit template
    exploit_code = display.exploit_generator.generate_exploit_template(vuln)
    
    print(f"\n{Fore.CYAN}Generated Exploit Template:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'─'*60}{Style.RESET_ALL}")
    print(exploit_code)
    print(f"{Fore.YELLOW}{'─'*60}{Style.RESET_ALL}")
    
    # Save to file option
    save_option = input(f"\n{Fore.WHITE}Save exploit template to file? (yes/no): {Style.RESET_ALL}").strip().lower()
    if save_option in ['yes', 'y']:
        filename = f"exploit_{vuln_id.lower()}.py"
        with open(filename, 'w') as f:
            f.write(exploit_code)
        print(f"{Fore.GREEN}✅ Exploit template saved to {filename}{Style.RESET_ALL}")

def interactive_mode(display):
    """Interactive mode for the tool"""
    print(f"\n{Fore.CYAN}🚀 INTERACTIVE MODE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}Available commands:{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}show all{Style.RESET_ALL}     - Show all vulnerabilities")
    print(f"  {Fore.YELLOW}show critical{Style.RESET_ALL} - Show critical vulnerabilities")
    print(f"  {Fore.YELLOW}search <term>{Style.RESET_ALL} - Search vulnerabilities")
    print(f"  {Fore.YELLOW}add{Style.RESET_ALL}         - Add new vulnerability")
    print(f"  {Fore.YELLOW}stats{Style.RESET_ALL}       - Show statistics")
    print(f"  {Fore.YELLOW}export <file>{Style.RESET_ALL} - Export to JSON")
    print(f"  {Fore.YELLOW}help{Style.RESET_ALL}        - Show this help")
    print(f"  {Fore.YELLOW}quit{Style.RESET_ALL}        - Exit the tool")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    
    while True:
        try:
            command = input(f"\n{Fore.WHITE}zero-day> {Style.RESET_ALL}").strip().lower()
            
            if command == 'quit' or command == 'exit':
                print(f"{Fore.GREEN}👋 Goodbye!{Style.RESET_ALL}")
                break
            elif command == 'help':
                print(f"{Fore.WHITE}Available commands:{Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}show all{Style.RESET_ALL}     - Show all vulnerabilities")
                print(f"  {Fore.YELLOW}show critical{Style.RESET_ALL} - Show critical vulnerabilities")
                print(f"  {Fore.YELLOW}search <term>{Style.RESET_ALL} - Search vulnerabilities")
                print(f"  {Fore.YELLOW}add{Style.RESET_ALL}         - Add new vulnerability")
                print(f"  {Fore.YELLOW}stats{Style.RESET_ALL}       - Show statistics")
                print(f"  {Fore.YELLOW}export <file>{Style.RESET_ALL} - Export to JSON")
                print(f"  {Fore.YELLOW}help{Style.RESET_ALL}        - Show this help")
                print(f"  {Fore.YELLOW}quit{Style.RESET_ALL}        - Exit the tool")
            elif command == 'show all':
                display.display_zero_days()
            elif command == 'show critical':
                display.display_zero_days(filter_severity="Critical")
            elif command.startswith('search '):
                search_term = command[7:].strip()
                display.display_zero_days(search_term=search_term)
            elif command == 'add':
                add_new_vulnerability(display)
            elif command == 'stats':
                show_statistics(display)
            elif command.startswith('export '):
                filename = command[7:].strip()
                display.export_to_json(filename)
            else:
                print(f"{Fore.RED}❌ Unknown command. Type 'help' for available commands.{Style.RESET_ALL}")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}⚠️  Use 'quit' to exit.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Error: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()