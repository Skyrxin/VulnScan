"""
Endpoint Discovery Module

Discovers and enumerates web application endpoints using various techniques
including wordlist fuzzing, directory bruteforcing, and intelligent crawling.
"""

import requests
import threading
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import time
import os
from colorama import Fore, Style

class EndpointDiscovery:
    def __init__(self, threads=30, timeout=5, fast_mode=False):
        self.threads = threads
        self.timeout = timeout
        self.fast_mode = fast_mode
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Default common endpoints wordlist
        self.default_wordlist = [
            'admin', 'login', 'dashboard', 'config', 'api', 'upload', 'files',
            'backup', 'test', 'debug', 'dev', 'staging', 'prod', 'console',
            'panel', 'management', 'cms', 'wp-admin', 'administrator', 'users',
            'accounts', 'profile', 'settings', 'logs', 'status', 'health',
            'info', 'version', 'robots.txt', 'sitemap.xml', '.env', '.git',
            'phpmyadmin', 'adminer', 'grafana', 'kibana', 'jenkins',
            'swagger', 'api-docs', 'documentation', 'docs', 'help',
            'search', 'download', 'downloads', 'uploads', 'media',
            'images', 'css', 'js', 'assets', 'static', 'public',
            'private', 'internal', 'secure', 'restricted', 'hidden'
        ]
        
        # Common file extensions to check
        self.extensions = ['', '.php', '.asp', '.aspx', '.jsp', '.html', '.htm', '.json', '.xml']
        
        # Common subdirectories
        self.subdirectories = ['', 'admin/', 'api/', 'v1/', 'v2/', 'beta/', 'test/']

    def discover(self, target_url, wordlist_file=None):
        """Main endpoint discovery method"""
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Starting endpoint discovery...")
        
        # Normalize target URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        # Load wordlist
        wordlist = self.load_wordlist(wordlist_file)
        
        # Generate endpoint combinations
        endpoints_to_test = self.generate_endpoints(target_url, wordlist)
        
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Testing {len(endpoints_to_test)} potential endpoints...")
        
        # Test endpoints concurrently
        discovered_endpoints = self.test_endpoints_concurrent(endpoints_to_test)
        
        # Add some intelligent discovery
        discovered_endpoints.extend(self.intelligent_discovery(target_url))
        
        # Remove duplicates
        unique_endpoints = self.remove_duplicates(discovered_endpoints)
        
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Discovered {len(unique_endpoints)} endpoints")
        
        return unique_endpoints

    def load_wordlist(self, wordlist_file=None):
        """Load wordlist from file or use default"""
        if wordlist_file and os.path.exists(wordlist_file):
            try:
                with open(wordlist_file, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
                
                # In fast mode, limit wordlist size
                if self.fast_mode and len(wordlist) > 50:
                    wordlist = wordlist[:50]
                    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Fast mode: Limited to first 50 words from {wordlist_file}")
                else:
                    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Loaded {len(wordlist)} words from {wordlist_file}")
                return wordlist
            except Exception as e:
                print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Could not load wordlist: {e}")
        
        wordlist = self.default_wordlist
        if self.fast_mode:
            wordlist = self.default_wordlist[:20]  # Use only first 20 default words in fast mode
            print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Fast mode: Using reduced default wordlist ({len(wordlist)} words)")
        else:
            print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Using default wordlist ({len(wordlist)} words)")
        return wordlist

    def generate_endpoints(self, base_url, wordlist):
        """Generate all endpoint combinations to test"""
        endpoints = []
        
        # Use fewer extensions in fast mode
        extensions = self.extensions[:3] if self.fast_mode else self.extensions
        subdirectories = self.subdirectories[:3] if self.fast_mode else self.subdirectories
        
        for subdir in subdirectories:
            for word in wordlist:
                for ext in extensions:
                    endpoint = urljoin(base_url, subdir + word + ext)
                    endpoints.append(endpoint)
        
        # Add some specific endpoints
        specific_endpoints = [
            urljoin(base_url, '.well-known/security.txt'),
            urljoin(base_url, '.htaccess'),
            urljoin(base_url, 'web.config'),
            urljoin(base_url, 'crossdomain.xml'),
            urljoin(base_url, 'clientaccesspolicy.xml'),
            urljoin(base_url, 'favicon.ico'),
            urljoin(base_url, 'apple-touch-icon.png'),
        ]
        
        endpoints.extend(specific_endpoints)
        return list(set(endpoints))  # Remove duplicates

    def test_endpoints_concurrent(self, endpoints):
        """Test endpoints concurrently"""
        discovered = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all tasks
            future_to_url = {
                executor.submit(self.test_endpoint, url): url 
                for url in endpoints
            }
            
            # Process results with progress bar
            with tqdm(total=len(endpoints), desc="Testing endpoints", 
                     bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.GREEN, Style.RESET_ALL)) as pbar:
                
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        result = future.result()
                        if result:
                            discovered.append(result)
                    except Exception as e:
                        pass  # Skip failed requests
                    finally:
                        pbar.update(1)
        
        return discovered

    def test_endpoint(self, url):
        """Test a single endpoint"""
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            
            # Consider any response (except certain errors) as discovered
            if response.status_code not in [404, 410]:
                endpoint_data = {
                    'url': url,
                    'status_code': response.status_code,
                    'status_text': response.reason or '',
                    'content_length': len(response.content),
                    'content_type': response.headers.get('content-type', ''),
                    'server': response.headers.get('server', ''),
                }
                
                # Handle redirects
                if 300 <= response.status_code < 400:
                    redirect_url = response.headers.get('location')
                    if redirect_url:
                        endpoint_data['redirect_url'] = redirect_url
                
                return endpoint_data
                
        except requests.exceptions.RequestException:
            pass  # Skip failed requests
        
        return None

    def intelligent_discovery(self, base_url):
        """Intelligent discovery based on response analysis"""
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Performing intelligent discovery...")
        
        discovered = []
        
        # Try to find robots.txt and sitemap.xml
        robots_url = urljoin(base_url, 'robots.txt')
        sitemap_url = urljoin(base_url, 'sitemap.xml')
        
        for url in [robots_url, sitemap_url]:
            result = self.test_endpoint(url)
            if result:
                discovered.append(result)
                
                # Parse robots.txt for additional paths
                if 'robots.txt' in url and result['status_code'] == 200:
                    try:
                        response = self.session.get(url, timeout=self.timeout)
                        robot_paths = self.parse_robots_txt(response.text, base_url)
                        for path_url in robot_paths:
                            path_result = self.test_endpoint(path_url)
                            if path_result:
                                discovered.append(path_result)
                    except:
                        pass
        
        # Check for common API endpoints
        api_endpoints = [
            '/api/v1/users', '/api/v2/users', '/api/users',
            '/api/v1/admin', '/api/v2/admin', '/api/admin',
            '/api/v1/config', '/api/v2/config', '/api/config',
            '/rest/api/2/user', '/rest/api/latest/user',
            '/graphql', '/v1/graphql', '/v2/graphql'
        ]
        
        for endpoint in api_endpoints:
            full_url = urljoin(base_url, endpoint)
            result = self.test_endpoint(full_url)
            if result:
                discovered.append(result)
        
        return discovered

    def parse_robots_txt(self, robots_content, base_url):
        """Parse robots.txt for additional endpoints"""
        paths = []
        lines = robots_content.split('\n')
        
        for line in lines:
            line = line.strip()
            if line.startswith('Disallow:') or line.startswith('Allow:'):
                path = line.split(':', 1)[1].strip()
                if path and path != '/':
                    full_url = urljoin(base_url, path.lstrip('/'))
                    paths.append(full_url)
        
        return paths

    def remove_duplicates(self, endpoints):
        """Remove duplicate endpoints"""
        seen_urls = set()
        unique_endpoints = []
        
        for endpoint in endpoints:
            if endpoint['url'] not in seen_urls:
                seen_urls.add(endpoint['url'])
                unique_endpoints.append(endpoint)
        
        return unique_endpoints

    def save_endpoints(self, endpoints, filename):
        """Save discovered endpoints to JSON file"""
        import json
        from datetime import datetime
        
        # Create results directory if it doesn't exist
        os.makedirs('results', exist_ok=True)
        
        # Determine filepath
        if not filename.startswith('results/') and not os.path.dirname(filename):
            filepath = os.path.join('results', filename)
        else:
            filepath = filename
        
        # Prepare data to save
        data = {
            'scan_date': datetime.now().isoformat(),
            'total_endpoints': len(endpoints),
            'endpoints': endpoints
        }
        
        # Save to file
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Endpoints saved to: {filepath}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to save endpoints: {e}")
            return False
