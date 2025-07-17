"""
Status Checker Module

Checks endpoint status codes and provides color-coded visualization
for easy identification of interesting endpoints.
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from colorama import Fore, Style

class StatusChecker:
    def __init__(self, threads=20, timeout=10):
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def check_endpoints(self, endpoints):
        """Check status codes for a list of endpoints"""
        if not endpoints:
            return []
        
        # If endpoints already have status codes, return them
        if all('status_code' in ep for ep in endpoints):
            return endpoints
        
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Checking status codes for {len(endpoints)} endpoints...")
        
        # Convert to URLs if needed
        urls = []
        for ep in endpoints:
            if isinstance(ep, str):
                urls.append(ep)
            elif isinstance(ep, dict) and 'url' in ep:
                urls.append(ep['url'])
        
        checked_endpoints = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {
                executor.submit(self.check_single_endpoint, url): url 
                for url in urls
            }
            
            with tqdm(total=len(urls), desc="Checking status", 
                     bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.CYAN, Style.RESET_ALL)) as pbar:
                
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        result = future.result()
                        if result:
                            checked_endpoints.append(result)
                    except Exception as e:
                        # Create a basic entry for failed requests
                        checked_endpoints.append({
                            'url': url,
                            'status_code': 0,
                            'status_text': 'Connection Failed',
                            'error': str(e)
                        })
                    finally:
                        pbar.update(1)
        
        # Sort by status code for better visualization
        checked_endpoints.sort(key=lambda x: (x['status_code'], x['url']))
        
        return checked_endpoints

    def check_single_endpoint(self, url):
        """Check status code for a single endpoint"""
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            
            endpoint_data = {
                'url': url,
                'status_code': response.status_code,
                'status_text': response.reason or self.get_status_text(response.status_code),
                'content_length': len(response.content),
                'content_type': response.headers.get('content-type', ''),
                'server': response.headers.get('server', ''),
                'response_time': response.elapsed.total_seconds()
            }
            
            # Handle redirects
            if 300 <= response.status_code < 400:
                redirect_url = response.headers.get('location')
                if redirect_url:
                    endpoint_data['redirect_url'] = redirect_url
            
            # Detect interesting headers
            interesting_headers = self.detect_interesting_headers(response.headers)
            if interesting_headers:
                endpoint_data['interesting_headers'] = interesting_headers
            
            # Detect technology stack
            tech_stack = self.detect_technology(response.headers, response.content)
            if tech_stack:
                endpoint_data['technology'] = tech_stack
            
            return endpoint_data
            
        except requests.exceptions.Timeout:
            return {
                'url': url,
                'status_code': 0,
                'status_text': 'Request Timeout',
                'error': 'timeout'
            }
        except requests.exceptions.ConnectionError:
            return {
                'url': url,
                'status_code': 0,
                'status_text': 'Connection Error',
                'error': 'connection_error'
            }
        except requests.exceptions.RequestException as e:
            return {
                'url': url,
                'status_code': 0,
                'status_text': 'Request Failed',
                'error': str(e)
            }

    def get_status_text(self, status_code):
        """Get human-readable status text for status code"""
        status_texts = {
            200: 'OK',
            201: 'Created',
            202: 'Accepted',
            204: 'No Content',
            301: 'Moved Permanently',
            302: 'Found',
            304: 'Not Modified',
            400: 'Bad Request',
            401: 'Unauthorized',
            403: 'Forbidden',
            404: 'Not Found',
            405: 'Method Not Allowed',
            408: 'Request Timeout',
            410: 'Gone',
            429: 'Too Many Requests',
            500: 'Internal Server Error',
            501: 'Not Implemented',
            502: 'Bad Gateway',
            503: 'Service Unavailable',
            504: 'Gateway Timeout'
        }
        return status_texts.get(status_code, 'Unknown')

    def detect_interesting_headers(self, headers):
        """Detect interesting security headers or misconfigurations"""
        interesting = []
        
        # Security headers that might be missing or misconfigured
        security_headers = {
            'x-frame-options': 'X-Frame-Options',
            'x-content-type-options': 'X-Content-Type-Options',
            'x-xss-protection': 'X-XSS-Protection',
            'strict-transport-security': 'HSTS',
            'content-security-policy': 'CSP',
            'x-powered-by': 'Technology Disclosure',
            'server': 'Server Banner',
            'set-cookie': 'Cookie Settings'
        }
        
        for header_name, description in security_headers.items():
            if header_name in headers:
                value = headers[header_name]
                interesting.append({
                    'header': description,
                    'value': value
                })
        
        # Check for potentially dangerous headers
        dangerous_headers = ['x-debug', 'x-dev', 'x-staging']
        for header in headers:
            if any(dangerous in header.lower() for dangerous in dangerous_headers):
                interesting.append({
                    'header': f'Debug Header: {header}',
                    'value': headers[header],
                    'risk': 'high'
                })
        
        return interesting

    def detect_technology(self, headers, content):
        """Detect technology stack from headers and content"""
        tech_stack = []
        
        # From headers
        server = headers.get('server', '').lower()
        powered_by = headers.get('x-powered-by', '').lower()
        
        if 'apache' in server:
            tech_stack.append('Apache')
        if 'nginx' in server:
            tech_stack.append('Nginx')
        if 'iis' in server:
            tech_stack.append('IIS')
        if 'php' in powered_by:
            tech_stack.append('PHP')
        if 'asp.net' in powered_by:
            tech_stack.append('ASP.NET')
        
        # From content (basic detection)
        try:
            content_str = content.decode('utf-8', errors='ignore').lower()
            
            if 'wordpress' in content_str or 'wp-content' in content_str:
                tech_stack.append('WordPress')
            if 'drupal' in content_str:
                tech_stack.append('Drupal')
            if 'joomla' in content_str:
                tech_stack.append('Joomla')
            if 'laravel' in content_str:
                tech_stack.append('Laravel')
            if 'django' in content_str:
                tech_stack.append('Django')
            if 'flask' in content_str:
                tech_stack.append('Flask')
            if 'react' in content_str:
                tech_stack.append('React')
            if 'angular' in content_str:
                tech_stack.append('Angular')
            if 'vue' in content_str:
                tech_stack.append('Vue.js')
                
        except:
            pass  # Skip content analysis if it fails
        
        return list(set(tech_stack))  # Remove duplicates

    def get_status_color(self, status_code):
        """Get color for status code display"""
        if status_code == 200:
            return Fore.GREEN
        elif 201 <= status_code <= 299:
            return Fore.LIGHTGREEN_EX
        elif 300 <= status_code <= 399:
            return Fore.YELLOW
        elif 400 <= status_code <= 499:
            return Fore.RED
        elif status_code >= 500:
            return Fore.MAGENTA
        else:
            return Fore.WHITE

    def get_status_priority(self, status_code):
        """Get priority level for status code (for sorting interesting endpoints)"""
        priorities = {
            200: 1,  # Most interesting - working endpoints
            403: 2,  # Forbidden - might be bypassable
            401: 3,  # Unauthorized - authentication required
            500: 4,  # Server errors - potential for exploitation
            302: 5,  # Redirects - might leak information
            301: 6,  # Permanent redirects
            404: 10, # Not found - least interesting
        }
        return priorities.get(status_code, 7)

    def filter_interesting_endpoints(self, endpoints):
        """Filter and return most interesting endpoints for vulnerability testing"""
        interesting = []
        
        for endpoint in endpoints:
            status_code = endpoint.get('status_code', 0)
            
            # Include endpoints that are likely to be interesting for security testing
            if status_code in [200, 201, 401, 403, 500, 502, 503]:
                interesting.append(endpoint)
            
            # Include redirects that might be exploitable
            elif 300 <= status_code < 400 and endpoint.get('redirect_url'):
                interesting.append(endpoint)
        
        # Sort by priority (most interesting first)
        interesting.sort(key=lambda x: self.get_status_priority(x.get('status_code', 999)))
        
        return interesting
