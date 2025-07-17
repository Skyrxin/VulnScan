"""
Main Web Application Vulnerability Scanner

A comprehensive security scanner for web applications with endpoint discovery
and vulnerability testing capabilities.
"""

import argparse
import json
import sys
import os
from datetime import datetime
from urllib.parse import urlparse

# Add modules directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'modules'))

from modules.endpoint_discovery import EndpointDiscovery
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.status_checker import StatusChecker
from colorama import init, Fore, Style

# Try to import report generator, create a simple fallback if not available
try:
    from modules.report_generator import ReportGenerator
except ImportError:
    class ReportGenerator:
        def print_summary_report(self, vulnerabilities):
            if not vulnerabilities:
                print(f"{Fore.GREEN}[+] No vulnerabilities detected!{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[*] Found {len(vulnerabilities)} vulnerabilities{Style.RESET_ALL}")
                for vuln in vulnerabilities:
                    severity_color = Fore.RED if vuln.get('severity') == 'High' else Fore.YELLOW if vuln.get('severity') == 'Medium' else Fore.BLUE
                    print(f"{severity_color}[{vuln.get('severity', 'Unknown')}] {vuln.get('type', 'Unknown')}: {vuln.get('url', 'N/A')}{Style.RESET_ALL}")
        
        def generate_detailed_report(self, vulnerabilities, output_file):
            import json
            import time
            with open(output_file, 'w') as f:
                json.dump({'vulnerabilities': vulnerabilities, 'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')}, f, indent=2)
            print(f"{Fore.GREEN}[+] Report saved to: {output_file}{Style.RESET_ALL}")

# Initialize colorama for Windows compatibility
init(autoreset=True)

class WebVulnScanner:
    def __init__(self, verbose=False, fast_mode=False):
        self.endpoint_discovery = EndpointDiscovery(fast_mode=fast_mode)
        self.vulnerability_scanner = VulnerabilityScanner(verbose=verbose, fast_mode=fast_mode)
        self.status_checker = StatusChecker()
        
    def print_banner(self):
        """Print the scanner banner"""
        banner = f"""
{Fore.CYAN}    ╔══════════════════════════════════════════════════════════════╗
    ║                        VulnScan V1.0                         ║
    ║                  Web Vulnerability Scanner                   ║
    ║                         By Skyrxin                           ║
    ╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}Target Security Testing Areas:{Style.RESET_ALL}
{Fore.GREEN}• SQL Injection (SQLi)           • Cross-Site Scripting (XSS)
• CSRF Vulnerabilities          • Insecure Direct Object References
• Exposed Debug Tools           • File Disclosure
• Weak Authentication          • Missing HTTPS/TLS
• Broken Access Control        • Session Management Issues{Style.RESET_ALL}

"""
        print(banner)

    def discover_endpoints(self, target_url, save_file=None, wordlist_file=None):
        """Discover endpoints and optionally save results"""
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Starting endpoint discovery for: {target_url}")
        
        # Discover endpoints
        endpoints = self.endpoint_discovery.discover(target_url, wordlist_file)
        
        # Check status codes with color coding
        print(f"\n{Fore.BLUE}[INFO]{Style.RESET_ALL} Checking endpoint status codes...")
        checked_endpoints = self.status_checker.check_endpoints(endpoints)
        
        # Display results
        self.display_endpoints(checked_endpoints)
        
        # Save if requested
        if save_file:
            self.save_endpoints(checked_endpoints, save_file)
            print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Endpoints saved to: {save_file}")
        
        return checked_endpoints

    def display_endpoints(self, endpoints):
        """Display endpoints with color-coded status"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}DISCOVERED ENDPOINTS")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        for endpoint in endpoints:
            status_color = self.get_status_color(endpoint['status_code'])
            status_text = f"{endpoint['status_code']} {endpoint['status_text']}"
            
            print(f"{status_color}[{status_text:>12}]{Style.RESET_ALL} {endpoint['url']}")
            
            if endpoint.get('redirect_url'):
                print(f"{Fore.YELLOW}              └─> Redirects to: {endpoint['redirect_url']}{Style.RESET_ALL}")

    def get_status_color(self, status_code):
        """Get color for status code"""
        if status_code == 200:
            return Fore.GREEN
        elif 300 <= status_code < 400:
            return Fore.YELLOW
        elif 400 <= status_code < 500:
            return Fore.RED
        elif status_code >= 500:
            return Fore.MAGENTA
        else:
            return Fore.WHITE

    def save_endpoints(self, endpoints, filename):
        """Save endpoints to JSON file"""
        os.makedirs('results', exist_ok=True)
        filepath = os.path.join('results', filename)
        
        data = {
            'scan_date': datetime.now().isoformat(),
            'total_endpoints': len(endpoints),
            'endpoints': endpoints
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def load_endpoints(self, filename):
        """Load endpoints from JSON file"""
        filepath = os.path.join('results', filename) if not os.path.exists(filename) else filename
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            return data['endpoints']
        except FileNotFoundError:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} File not found: {filepath}")
            return []
        except json.JSONDecodeError:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Invalid JSON file: {filepath}")
            return []

    def scan_vulnerabilities(self, endpoints, target_url=None):
        """Scan endpoints for vulnerabilities"""
        print(f"\n{Fore.BLUE}[INFO]{Style.RESET_ALL} Starting vulnerability assessment...")
        
        # Filter endpoints that are good candidates for testing
        testable_endpoints = [ep for ep in endpoints if ep['status_code'] == 200]
        
        if not testable_endpoints:
            print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} No testable endpoints found (200 OK status)")
            return
        
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Testing {len(testable_endpoints)} endpoints for vulnerabilities...")
        
        # Run vulnerability scans
        results = self.vulnerability_scanner.scan_all(testable_endpoints, target_url)
        
        # Display results
        self.display_vulnerability_results(results)
        
        # Save results
        self.save_vulnerability_results(results)
        
        return results

    def display_vulnerability_results(self, results):
        """Display vulnerability scan results"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}VULNERABILITY SCAN RESULTS")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        total_vulns = sum(len(vulns) for vulns in results.values())
        
        if total_vulns == 0:
            print(f"{Fore.GREEN}[GOOD]{Style.RESET_ALL} No vulnerabilities detected!")
            return
        
        for vuln_type, vulnerabilities in results.items():
            if vulnerabilities:
                print(f"\n{Fore.RED}[CRITICAL] {vuln_type.upper()} VULNERABILITIES FOUND:{Style.RESET_ALL}")
                for vuln in vulnerabilities:
                    print(f"  {Fore.RED}•{Style.RESET_ALL} {vuln['url']}")
                    print(f"    {Fore.YELLOW}Payload:{Style.RESET_ALL} {vuln.get('payload', 'N/A')}")
                    if vuln.get('evidence'):
                        print(f"    {Fore.YELLOW}Evidence:{Style.RESET_ALL} {vuln['evidence']}")

    def save_vulnerability_results(self, results):
        """Save vulnerability results to file"""
        os.makedirs('results', exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vulnerability_scan_{timestamp}.json"
        filepath = os.path.join('results', filename)
        
        data = {
            'scan_date': datetime.now().isoformat(),
            'results': results
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Vulnerability results saved to: {filepath}")

def main():
    parser = argparse.ArgumentParser(
        description="Web Application Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Discover endpoints only
  python scanner.py --target https://example.com --discover-only
  
  # Discover and save endpoints with custom wordlist
  python scanner.py --target https://example.com --discover-only --wordlist custom_wordlist.txt --save-endpoints results.json
  
  # Load endpoints and scan for vulnerabilities
  python scanner.py --load-endpoints results.json --scan-vulnerabilities
  
  # Full scan (discover + test vulnerabilities)
  python scanner.py --target https://example.com --scan-all
  
  # Skip specific vulnerability tests
  python scanner.py --target https://example.com --scan-all --skip sqli,xss
  
  # Run only specific vulnerability tests
  python scanner.py --target https://example.com --scan-all --only csrf,idor
        """
    )
    
    # Target options
    parser.add_argument('--target', '-t', help='Target URL to scan')
    parser.add_argument('--load-endpoints', help='Load endpoints from JSON file')
    
    # Discovery options
    parser.add_argument('--discover-only', action='store_true', 
                       help='Only discover endpoints, don\'t test vulnerabilities')
    parser.add_argument('--save-endpoints', help='Save discovered endpoints to JSON file')
    parser.add_argument('--wordlist', default='wordlists/common_endpoints.txt',
                       help='Path to custom wordlist file for endpoint discovery (default: wordlists/common_endpoints.txt)')
    parser.add_argument('--threads', type=int, default=10,
                       help='Number of threads for discovery (default: 10)')
    
    # Scanning options
    parser.add_argument('--scan-vulnerabilities', action='store_true',
                       help='Scan for vulnerabilities (use with --load-endpoints)')
    parser.add_argument('--scan-all', action='store_true',
                       help='Discover endpoints and scan for vulnerabilities')
    
    # Vulnerability selection options
    parser.add_argument('--skip', help='Skip specific vulnerability tests (comma-separated): sqli,xss,csrf,idor,debug,files,auth,tls,access')
    parser.add_argument('--only', help='Run only specific vulnerability tests (comma-separated): sqli,xss,csrf,idor,debug,files,auth,tls,access')
    
    # Output options
    parser.add_argument('--output', '-o', help='Output file for detailed report')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--fast', action='store_true', help='Fast scan mode (fewer endpoints and payloads for quicker results)')
    
    args = parser.parse_args()
    
    # Print banner
    WebVulnScanner(verbose=args.verbose, fast_mode=args.fast).print_banner()
    
    try:
        # Validate arguments
        if not args.target and not args.load_endpoints:
            print(f"{Fore.RED}[!] Error: Must specify either --target or --load-endpoints{Style.RESET_ALL}")
            parser.print_help()
            return
        
        # Parse vulnerability selection options
        available_scans = ['sqli', 'xss', 'csrf', 'idor', 'debug', 'files', 'auth', 'tls', 'access']
        
        if args.skip and args.only:
            print(f"{Fore.RED}[!] Error: Cannot use both --skip and --only options{Style.RESET_ALL}")
            return
        
        selected_scans = available_scans.copy()
        
        if args.skip:
            skip_scans = [scan.strip().lower() for scan in args.skip.split(',')]
            invalid_scans = [scan for scan in skip_scans if scan not in available_scans]
            if invalid_scans:
                print(f"{Fore.RED}[!] Error: Invalid scan types to skip: {', '.join(invalid_scans)}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Available scans: {', '.join(available_scans)}{Style.RESET_ALL}")
                return
            selected_scans = [scan for scan in selected_scans if scan not in skip_scans]
            print(f"{Fore.YELLOW}[*] Skipping vulnerability tests: {', '.join(skip_scans)}{Style.RESET_ALL}")
        
        if args.only:
            only_scans = [scan.strip().lower() for scan in args.only.split(',')]
            invalid_scans = [scan for scan in only_scans if scan not in available_scans]
            if invalid_scans:
                print(f"{Fore.RED}[!] Error: Invalid scan types: {', '.join(invalid_scans)}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Available scans: {', '.join(available_scans)}{Style.RESET_ALL}")
                return
            selected_scans = only_scans
            print(f"{Fore.YELLOW}[*] Running only vulnerability tests: {', '.join(only_scans)}{Style.RESET_ALL}")
        
        if args.fast:
            print(f"{Fore.CYAN}[*] Fast scan mode enabled - using optimized settings for quicker results{Style.RESET_ALL}")
        
        endpoints = []
        
        # Phase 1: Endpoint Discovery
        if args.target:
            print(f"\n{Fore.CYAN}[*] Phase 1: Endpoint Discovery{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Target: {args.target}{Style.RESET_ALL}")
            
            # Verify wordlist file exists before starting
            if not os.path.exists(args.wordlist):
                print(f"{Fore.RED}[!] Error: Wordlist file not found: {args.wordlist}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Please check the file path or use the default wordlist{Style.RESET_ALL}")
                return
            
            discovery = EndpointDiscovery(threads=args.threads, timeout=10, fast_mode=args.fast)
            endpoints = discovery.discover(args.target, args.wordlist)
            
            if args.save_endpoints:
                discovery.save_endpoints(endpoints, args.save_endpoints)
                print(f"{Fore.GREEN}[+] Endpoints saved to: {args.save_endpoints}{Style.RESET_ALL}")
        
        # Load endpoints from file
        elif args.load_endpoints:
            print(f"\n{Fore.CYAN}[*] Loading endpoints from: {args.load_endpoints}{Style.RESET_ALL}")
            if not os.path.exists(args.load_endpoints):
                print(f"{Fore.RED}[!] Error: File not found: {args.load_endpoints}{Style.RESET_ALL}")
                return
            
            with open(args.load_endpoints, 'r') as f:
                data = json.load(f)
                endpoints = data.get('endpoints', [])
            
            print(f"{Fore.GREEN}[+] Loaded {len(endpoints)} endpoints{Style.RESET_ALL}")
        
        # Phase 2: Vulnerability Scanning
        if (args.scan_vulnerabilities or args.scan_all) and endpoints:
            print(f"\n{Fore.CYAN}[*] Phase 2: Vulnerability Scanning{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Testing {len(endpoints)} endpoints for vulnerabilities{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Selected vulnerability tests: {', '.join(selected_scans)}{Style.RESET_ALL}")
            
            scanner = VulnerabilityScanner(verbose=args.verbose, fast_mode=args.fast)
            results = scanner.scan_vulnerabilities(endpoints, selected_scans)
            
            # Generate report
            report_gen = ReportGenerator()
            
            # Flatten results for reporting
            all_vulnerabilities = []
            for vuln_category, vuln_list in results.items():
                all_vulnerabilities.extend(vuln_list)
            
            if args.output:
                report_gen.generate_detailed_report(all_vulnerabilities, args.output)
                print(f"\n{Fore.GREEN}[+] Detailed report saved to: {args.output}{Style.RESET_ALL}")
            else:
                report_gen.print_summary_report(all_vulnerabilities)
        
        elif args.discover_only:
            print(f"\n{Fore.GREEN}[+] Endpoint discovery completed. Found {len(endpoints)} endpoints.{Style.RESET_ALL}")
            if not args.save_endpoints:
                print(f"{Fore.YELLOW}[*] Use --save-endpoints to save results for later vulnerability testing{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] Scan completed successfully!{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] An error occurred: {str(e)}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()
