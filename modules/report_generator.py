"""
Report Generator Module

Generates comprehensive reports for vulnerability scan results.
Supports console output, JSON, HTML, and other formats.
"""

import json
import time
from datetime import datetime
from colorama import Fore, Style
import os

class ReportGenerator:
    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def print_summary_report(self, vulnerabilities):
        """Print a summary report to console"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}VULNERABILITY SCAN SUMMARY")
        print(f"{'='*70}{Style.RESET_ALL}")
        
        if not vulnerabilities:
            print(f"{Fore.GREEN}[+] No vulnerabilities detected! 🎉{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] This could mean the target is secure or the tests need refinement{Style.RESET_ALL}")
            return
        
        # Count vulnerabilities by severity
        severity_count = {'High': 0, 'Medium': 0, 'Low': 0}
        vuln_types = {}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            vuln_type = vuln.get('type', 'Unknown')
            
            if severity in severity_count:
                severity_count[severity] += 1
            
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        # Print severity summary
        total_vulns = len(vulnerabilities)
        print(f"\n{Fore.WHITE}📊 SEVERITY BREAKDOWN:{Style.RESET_ALL}")
        print(f"  {Fore.RED}🔴 High:   {severity_count['High']:>3}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}🟡 Medium: {severity_count['Medium']:>3}{Style.RESET_ALL}")
        print(f"  {Fore.BLUE}🔵 Low:    {severity_count['Low']:>3}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}📋 Total:  {total_vulns:>3}{Style.RESET_ALL}")
        
        # Print vulnerability types
        print(f"\n{Fore.WHITE}🎯 VULNERABILITY TYPES:{Style.RESET_ALL}")
        for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  • {vuln_type}: {count}")
        
        # Print detailed findings
        print(f"\n{Fore.WHITE}🔍 DETAILED FINDINGS:{Style.RESET_ALL}")
        
        # Group by severity for better readability
        for severity in ['High', 'Medium', 'Low']:
            severity_vulns = [v for v in vulnerabilities if v.get('severity') == severity]
            if not severity_vulns:
                continue
                
            color = Fore.RED if severity == 'High' else Fore.YELLOW if severity == 'Medium' else Fore.BLUE
            print(f"\n{color}{'▼' * 5} {severity.upper()} SEVERITY VULNERABILITIES {'▼' * 5}{Style.RESET_ALL}")
            
            for i, vuln in enumerate(severity_vulns, 1):
                print(f"\n{color}[{i}] {vuln.get('type', 'Unknown')}{Style.RESET_ALL}")
                print(f"    🌐 URL: {vuln.get('url', 'N/A')}")
                print(f"    📝 Description: {vuln.get('description', 'N/A')}")
                if vuln.get('timestamp'):
                    print(f"    ⏰ Detected: {vuln.get('timestamp')}")
        
        # Risk assessment
        print(f"\n{Fore.WHITE}⚠️  RISK ASSESSMENT:{Style.RESET_ALL}")
        if severity_count['High'] > 0:
            print(f"  {Fore.RED}🚨 CRITICAL: Immediate attention required for High severity vulnerabilities{Style.RESET_ALL}")
        elif severity_count['Medium'] > 0:
            print(f"  {Fore.YELLOW}⚠️  MODERATE: Address Medium severity vulnerabilities soon{Style.RESET_ALL}")
        elif severity_count['Low'] > 0:
            print(f"  {Fore.BLUE}ℹ️  LOW: Consider addressing Low severity vulnerabilities{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    
    def generate_detailed_report(self, vulnerabilities, output_file):
        """Generate a detailed report in JSON format"""
        try:
            # Ensure output directory exists
            output_dir = os.path.dirname(output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # Generate report data
            report_data = {
                'scan_info': {
                    'timestamp': self.timestamp,
                    'tool': 'Web Vulnerability Scanner v1.0',
                    'total_vulnerabilities': len(vulnerabilities)
                },
                'summary': self._generate_summary(vulnerabilities),
                'vulnerabilities': vulnerabilities,
                'recommendations': self._generate_recommendations(vulnerabilities)
            }
            
            # Determine output format based on file extension
            if output_file.endswith('.html'):
                self._generate_html_report(report_data, output_file)
            elif output_file.endswith('.csv'):
                self._generate_csv_report(vulnerabilities, output_file)
            else:  # Default to JSON
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            print(f"{Fore.GREEN}[+] Detailed report saved to: {output_file}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error generating report: {str(e)}{Style.RESET_ALL}")
    
    def _generate_summary(self, vulnerabilities):
        """Generate summary statistics"""
        if not vulnerabilities:
            return {
                'total': 0,
                'by_severity': {'High': 0, 'Medium': 0, 'Low': 0},
                'by_type': {}
            }
        
        severity_count = {'High': 0, 'Medium': 0, 'Low': 0}
        type_count = {}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            vuln_type = vuln.get('type', 'Unknown')
            
            if severity in severity_count:
                severity_count[severity] += 1
            
            type_count[vuln_type] = type_count.get(vuln_type, 0) + 1
        
        return {
            'total': len(vulnerabilities),
            'by_severity': severity_count,
            'by_type': type_count
        }
    
    def _generate_recommendations(self, vulnerabilities):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if not vulnerabilities:
            recommendations.append({
                'priority': 'Info',
                'title': 'No Vulnerabilities Found',
                'description': 'Continue regular security assessments and maintain current security practices.'
            })
            return recommendations
        
        # Check for specific vulnerability types and provide recommendations
        vuln_types = [v.get('type', '') for v in vulnerabilities]
        
        if any('SQL Injection' in vtype for vtype in vuln_types):
            recommendations.append({
                'priority': 'Critical',
                'title': 'SQL Injection Vulnerabilities',
                'description': 'Implement parameterized queries, input validation, and use prepared statements. Consider using an ORM framework.'
            })
        
        if any('XSS' in vtype for vtype in vuln_types):
            recommendations.append({
                'priority': 'High',
                'title': 'Cross-Site Scripting (XSS)',
                'description': 'Implement proper input sanitization, output encoding, and Content Security Policy (CSP) headers.'
            })
        
        if any('CSRF' in vtype for vtype in vuln_types):
            recommendations.append({
                'priority': 'Medium',
                'title': 'CSRF Protection',
                'description': 'Implement CSRF tokens for all state-changing operations and verify the origin of requests.'
            })
        
        if any('IDOR' in vtype for vtype in vuln_types):
            recommendations.append({
                'priority': 'High',
                'title': 'Access Control',
                'description': 'Implement proper authorization checks and use indirect object references or UUIDs instead of sequential IDs.'
            })
        
        if any('Debug' in vtype for vtype in vuln_types):
            recommendations.append({
                'priority': 'Medium',
                'title': 'Debug Endpoints',
                'description': 'Remove or secure debug endpoints in production environments. Implement proper access controls.'
            })
        
        if any('File Disclosure' in vtype for vtype in vuln_types):
            recommendations.append({
                'priority': 'Critical',
                'title': 'File Disclosure',
                'description': 'Implement proper file access controls, validate file paths, and avoid exposing sensitive files.'
            })
        
        if any('Authentication' in vtype for vtype in vuln_types):
            recommendations.append({
                'priority': 'Critical',
                'title': 'Authentication Security',
                'description': 'Implement strong password policies, multi-factor authentication, and secure session management.'
            })
        
        if any('TLS' in vtype or 'HTTP' in vtype for vtype in vuln_types):
            recommendations.append({
                'priority': 'Medium',
                'title': 'Transport Security',
                'description': 'Enforce HTTPS, implement HSTS headers, and ensure proper TLS configuration.'
            })
        
        # General recommendations
        recommendations.append({
            'priority': 'Info',
            'title': 'Regular Security Testing',
            'description': 'Conduct regular vulnerability assessments and penetration testing to identify new security issues.'
        })
        
        return recommendations
    
    def _generate_html_report(self, report_data, output_file):
        """Generate an HTML report"""
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; }}
        .severity-high {{ border-left-color: #dc3545; }}
        .severity-medium {{ border-left-color: #ffc107; }}
        .severity-low {{ border-left-color: #28a745; }}
        .vulnerability {{ margin-bottom: 20px; padding: 15px; border-radius: 8px; border-left: 4px solid #ccc; }}
        .vuln-high {{ border-left-color: #dc3545; background: #fff5f5; }}
        .vuln-medium {{ border-left-color: #ffc107; background: #fffbf0; }}
        .vuln-low {{ border-left-color: #28a745; background: #f8fff8; }}
        .recommendations {{ background: #e3f2fd; padding: 20px; border-radius: 8px; margin-top: 30px; }}
        .timestamp {{ color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Web Vulnerability Scan Report</h1>
            <p class="timestamp">Generated on {report_data['scan_info']['timestamp']}</p>
        </div>
        
        <div class="summary">
            <div class="card">
                <h3>📊 Total Vulnerabilities</h3>
                <h2>{report_data['summary']['total']}</h2>
            </div>
            <div class="card severity-high">
                <h3>🔴 High Severity</h3>
                <h2>{report_data['summary']['by_severity']['High']}</h2>
            </div>
            <div class="card severity-medium">
                <h3>🟡 Medium Severity</h3>
                <h2>{report_data['summary']['by_severity']['Medium']}</h2>
            </div>
            <div class="card severity-low">
                <h3>🔵 Low Severity</h3>
                <h2>{report_data['summary']['by_severity']['Low']}</h2>
            </div>
        </div>
        
        <h2>🔍 Vulnerability Details</h2>
"""
        
        # Add vulnerabilities
        for vuln in report_data['vulnerabilities']:
            severity = vuln.get('severity', 'Unknown').lower()
            severity_class = f"vuln-{severity}" if severity in ['high', 'medium', 'low'] else ""
            
            html_content += f"""
        <div class="vulnerability {severity_class}">
            <h3>{vuln.get('type', 'Unknown Vulnerability')}</h3>
            <p><strong>Severity:</strong> {vuln.get('severity', 'Unknown')}</p>
            <p><strong>URL:</strong> <code>{vuln.get('url', 'N/A')}</code></p>
            <p><strong>Description:</strong> {vuln.get('description', 'N/A')}</p>
            <p><strong>Detected:</strong> {vuln.get('timestamp', 'N/A')}</p>
        </div>
"""
        
        # Add recommendations
        html_content += """
        <div class="recommendations">
            <h2>💡 Security Recommendations</h2>
"""
        
        for rec in report_data['recommendations']:
            html_content += f"""
            <div style="margin-bottom: 15px;">
                <h4>{rec['title']} ({rec['priority']})</h4>
                <p>{rec['description']}</p>
            </div>
"""
        
        html_content += """
        </div>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _generate_csv_report(self, vulnerabilities, output_file):
        """Generate a CSV report"""
        import csv
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(['Type', 'Severity', 'URL', 'Description', 'Timestamp'])
            
            # Write vulnerabilities
            for vuln in vulnerabilities:
                writer.writerow([
                    vuln.get('type', ''),
                    vuln.get('severity', ''),
                    vuln.get('url', ''),
                    vuln.get('description', ''),
                    vuln.get('timestamp', '')
                ])
    
    def generate_quick_summary(self, vulnerabilities):
        """Generate a quick one-line summary"""
        if not vulnerabilities:
            return f"{Fore.GREEN}✅ No vulnerabilities found{Style.RESET_ALL}"
        
        total = len(vulnerabilities)
        high = len([v for v in vulnerabilities if v.get('severity') == 'High'])
        medium = len([v for v in vulnerabilities if v.get('severity') == 'Medium'])
        low = len([v for v in vulnerabilities if v.get('severity') == 'Low'])
        
        return f"{Fore.YELLOW}📋 Found {total} vulnerabilities: {Fore.RED}{high} High{Style.RESET_ALL}, {Fore.YELLOW}{medium} Medium{Style.RESET_ALL}, {Fore.BLUE}{low} Low{Style.RESET_ALL}"
