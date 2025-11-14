# 🔍 INFORMATION GATHERING | FINGERPRINT WEB SERVER

## Comprehensive Web Server Fingerprinting & Identification

### 1 Banner Grabbing Techniques
- **Basic Banner Grabbing:**
  - Netcat banner grabbing testing
  - Telnet HTTP header retrieval
  - cURL header analysis testing
  - Wget server identification testing
  - OpenSSL s_client connection testing
  - HTTPie header inspection testing
  - PowerShell Invoke-WebRequest testing
  - Python requests library testing

- **Advanced Banner Collection:**
  - HTTP response header analysis
  - Server header field extraction
  - X-Powered-By header analysis
  - X-AspNet-Version header inspection
  - Custom header identification
  - Error message analysis
  - HTTP verb response testing
  - Protocol version testing

### 2 HTTP Response Analysis
- **Header-Based Fingerprinting:**
  - Server header field analysis
  - X-Powered-By header examination
  - Via header proxy identification
  - X-AspNet-Version detection
  - Set-Cookie header analysis
  - Content-Type header patterns
  - Accept-Ranges header inspection
  - Connection header behavior

- **Response Code Analysis:**
  - 404 error page signatures
  - 500 error page patterns
  - 301/302 redirect behavior
  - 403 forbidden page styles
  - 401 unauthorized responses
  - Custom error page detection
  - Default page identification
  - Maintenance page recognition

### 3 Active Fingerprinting Methods
- **Protocol Behavior Testing:**
  - HTTP method support testing (GET, POST, PUT, DELETE, OPTIONS, TRACE)
  - HTTP version support analysis
  - Header order and formatting
  - Date header format analysis
  - ETag header pattern analysis
  - Keep-Alive behavior testing
  - Chunked encoding support
  - Compression method support

- **Request Manipulation:**
  - Malformed request testing
  - Overflow header testing
  - Invalid method testing
  - Unicode path testing
  - URL encoding variations
  - Case sensitivity testing
  - Space padding testing
  - Special character testing

### 4 Passive Fingerprinting Techniques
- **Traffic Analysis:**
  - TCP window size analysis
  - TCP timestamp examination
  - IP TTL value analysis
  - TCP sequence number analysis
  - MSS (Maximum Segment Size) analysis
  - TCP options fingerprinting
  - Initial sequence number patterns
  - TCP flag combinations

- **Statistical Analysis:**
  - Response time patterns
  - Packet size distribution
  - Connection establishment timing
  - Session duration analysis
  - Request/response ratio analysis
  - Error rate patterns
  - Traffic volume analysis
  - Behavioral profiling

### 5 Web Server Software Identification
- **Apache HTTP Server:**
  - Apache version detection testing
  - Apache module identification
  - Apache Tomcat recognition
  - Apache Traffic Server detection
  - Apache configuration analysis
  - Apache module signature testing
  - Apache error page patterns
  - Apache default file patterns

- **Nginx Identification:**
  - Nginx version detection testing
  - Nginx Plus recognition
  - Nginx configuration analysis
  - Nginx module detection
  - Nginx error page patterns
  - Nginx load balancer detection
  - Nginx reverse proxy identification
  - Nginx caching behavior

- **Microsoft IIS:**
  - IIS version detection testing
  - ASP.NET framework identification
  - IIS module detection
  - IIS application pool analysis
  - IIS error page patterns
  - IIS default file signatures
  - IIS header patterns
  - IIS authentication methods

- **Other Web Servers:**
  - LiteSpeed detection testing
  - Lighttpd identification
  - Cherokee server detection
  - Gunicorn recognition
  - uWSGI server identification
  - Caddy server detection
  - Jetty server recognition
  - Node.js HTTP server detection

### 6 Application Server Fingerprinting
- **Java Application Servers:**
  - Tomcat version detection
  - JBoss/WildFly identification
  - WebSphere recognition
  - WebLogic detection
  - GlassFish identification
  - Jetty server detection
  - Resin server recognition
  - Spring Boot detection

- **PHP Application Servers:**
  - PHP-FPM detection testing
  - Apache mod_php identification
  - HHVM recognition testing
  - Litespeed LSAPI detection
  - PHP built-in server identification
  - WP-CLI recognition testing
  - Drush server detection
  - Laravel artisan server identification

- **Python Application Servers:**
  - Gunicorn detection testing
  - uWSGI identification
  - Waitress recognition
  - Django development server
  - Flask built-in server
  - Tornado server detection
  - Twisted web identification
  - CherryPy recognition

- **Ruby Application Servers:**
  - Unicorn detection testing
  - Puma server identification
  - Thin server recognition
  - Passenger detection
  - WEBrick identification
  - Rails server detection
  - Rack server recognition
  - Sinatra server identification

### 7 CDN & Reverse Proxy Detection
- **Content Delivery Networks:**
  - CloudFront detection testing
  - Cloudflare identification
  - Akamai recognition testing
  - Fastly detection
  - Google Cloud CDN identification
  - Azure CDN recognition
  - StackPath detection
  - Sucuri identification

- **Reverse Proxies:**
  - Nginx reverse proxy detection
  - Apache mod_proxy identification
  - HAProxy recognition testing
  - Varnish cache detection
  - Squid proxy identification
  - Traefik recognition
  - Envoy proxy detection
  - IIS ARR identification

### 8 Security Filter Identification
- **Web Application Firewalls:**
  - ModSecurity detection testing
  - Cloudflare WAF identification
  - AWS WAF recognition
  - Imperva WAF detection
  - F5 BIG-IP identification
  - Citrix NetScaler recognition
  - FortiWeb detection
  - Barracuda WAF identification

- **Security Headers Analysis:**
  - X-Frame-Options header testing
  - X-XSS-Protection header analysis
  - Content-Security-Policy detection
  - Strict-Transport-Security analysis
  - X-Content-Type-Options testing
  - Referrer-Policy header analysis
  - Feature-Policy header detection
  - Permissions-Policy analysis

### 9 Framework & CMS Detection
- **Web Frameworks:**
  - Django detection testing
  - Ruby on Rails identification
  - Laravel recognition testing
  - Express.js detection
  - Spring Boot identification
  - ASP.NET MVC recognition
  - Flask detection testing
  - Symfony identification

- **Content Management Systems:**
  - WordPress detection testing
  - Joomla identification
  - Drupal recognition testing
  - Magento detection
  - Shopify identification
  - Wix recognition
  - Squarespace detection
  - Ghost identification

### 10 Automated Fingerprinting Framework
```yaml
Web Server Fingerprinting Pipeline:
  Discovery Phase:
    - Initial banner grabbing
    - HTTP header collection
    - Response code analysis
    - Default page identification
    - Error page analysis
    - SSL/TLS certificate inspection
    - Port scanning and service detection
    - Technology stack profiling

  Active Fingerprinting Phase:
    - HTTP method testing
    - Header manipulation testing
    - Malformed request testing
    - Protocol behavior analysis
    - Application-specific probes
    - Framework detection requests
    - WAF detection testing
    - Load balancer detection

  Passive Analysis Phase:
    - Traffic pattern analysis
    - Timing analysis
    - Behavioral profiling
    - Statistical analysis
    - Protocol fingerprinting
    - OS fingerprinting correlation
    - Network stack analysis
    - Application behavior monitoring

  Validation Phase:
    - Cross-verification of findings
    - Confidence level assessment
    - Version accuracy validation
    - False positive elimination
    - Manual verification
    - Tool correlation analysis
    - Historical data comparison
    - Reporting preparation
```

### 11 Testing Tools and Commands
```bash
# Basic Banner Grabbing
nc -v target.com 80
echo -e "HEAD / HTTP/1.1\nHost: target.com\n\n" | nc target.com 80
telnet target.com 80

# HTTP Header Analysis
curl -I http://target.com
wget --server-response --spider http://target.com
http HEAD http://target.com

# Advanced HTTP Analysis
curl -v -X OPTIONS http://target.com
curl -v -X TRACE http://target.com
curl -H "Custom-Header: test" http://target.com

# SSL/TLS Inspection
openssl s_client -connect target.com:443 -servername target.com
nmap --script ssl-cert -p 443 target.com
testssl.sh target.com:443

# Automated Fingerprinting
nmap -sV --script http-enum,http-title -p 80,443 target.com
whatweb -v target.com
wappalyzer target.com

# Specialized Tools
httprint -h target.com -s /usr/share/httprint/signatures.txt
nikto -h target.com -Display 1234
skipfish -o output_dir http://target.com
```

### 12 Advanced Fingerprinting Payloads
```python
# Comprehensive Web Server Fingerprinting Tool
import requests
import socket
import ssl
import re
from urllib.parse import urljoin

class WebServerFingerprinter:
    def __init__(self, target_url):
        self.target_url = target_url
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; WebFingerprinter/1.0)'
        })

    def basic_banner_grab(self):
        """Perform basic banner grabbing"""
        try:
            # HTTP banner grabbing
            response = self.session.head(self.target_url, timeout=10)
            self.results['http_headers'] = dict(response.headers)
            self.results['response_time'] = response.elapsed.total_seconds()
            
            # Extract server information
            server_header = response.headers.get('Server', '')
            powered_by = response.headers.get('X-Powered-By', '')
            
            self.results['server_banner'] = server_header
            self.results['powered_by'] = powered_by
            
        except requests.RequestException as e:
            self.results['banner_error'] = str(e)

    def advanced_header_analysis(self):
        """Perform advanced HTTP header analysis"""
        test_headers = {
            'Request-Methods': self.test_http_methods(),
            'Header-Order': self.analyze_header_order(),
            'Custom-Headers': self.test_custom_headers(),
            'Security-Headers': self.check_security_headers()
        }
        self.results['advanced_headers'] = test_headers

    def test_http_methods(self):
        """Test supported HTTP methods"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT']
        supported_methods = {}
        
        for method in methods:
            try:
                response = self.session.request(method, self.target_url, timeout=5)
                supported_methods[method] = {
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'headers': dict(response.headers)
                }
            except requests.RequestException:
                supported_methods[method] = 'Error or timeout'
        
        return supported_methods

    def analyze_header_order(self):
        """Analyze header order and formatting"""
        try:
            # Send request and capture raw response
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(10)
            conn.connect((self.target_url.replace('http://', '').replace('https://', '').split('/')[0], 80))
            
            request = f"HEAD / HTTP/1.1\r\nHost: {self.target_url}\r\n\r\n"
            conn.send(request.encode())
            
            response = b""
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                response += data
            
            conn.close()
            
            # Analyze header order and formatting
            header_lines = response.decode().split('\r\n')
            header_order = [line.split(':')[0] for line in header_lines if ':' in line]
            
            return {
                'raw_response': response.decode()[:500],
                'header_order': header_order,
                'response_format': self.analyze_response_format(response.decode())
            }
            
        except Exception as e:
            return {'error': str(e)}

    def test_custom_headers(self):
        """Test server response to custom headers"""
        custom_tests = {
            'overflow_header': 'A' * 10000,
            'unicode_header': 'Test: 🚀',
            'special_chars': 'Test: <script>alert(1)</script>',
            'multiple_spaces': 'Test:    value   ',
            'tab_chars': 'Test:\tvalue'
        }
        
        results = {}
        
        for test_name, test_value in custom_tests.items():
            try:
                headers = {'X-Test-Header': test_value}
                response = self.session.get(self.target_url, headers=headers, timeout=5)
                results[test_name] = {
                    'status_code': response.status_code,
                    'response_time': response.elapsed.total_seconds(),
                    'header_echoed': 'X-Test-Header' in response.headers
                }
            except requests.RequestException as e:
                results[test_name] = {'error': str(e)}
        
        return results

    def check_security_headers(self):
        """Check for security-related headers"""
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Feature-Policy',
            'Permissions-Policy'
        ]
        
        present_headers = {}
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            for header in security_headers:
                if header in response.headers:
                    present_headers[header] = response.headers[header]
                else:
                    present_headers[header] = 'Not Present'
                    
        except requests.RequestException as e:
            present_headers['error'] = str(e)
        
        return present_headers

    def ssl_tls_fingerprinting(self):
        """Perform SSL/TLS fingerprinting"""
        try:
            hostname = self.target_url.replace('http://', '').replace('https://', '').split('/')[0]
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    tls_version = ssock.version()
                    
                    self.results['ssl_tls'] = {
                        'certificate': cert,
                        'cipher_suite': cipher,
                        'tls_version': tls_version,
                        'certificate_chain': len(ssock.getpeercertchain()) if ssock.getpeercertchain() else 0
                    }
                    
        except Exception as e:
            self.results['ssl_tls_error'] = str(e)

    def framework_detection(self):
        """Detect web frameworks and CMS"""
        framework_signatures = {
            'wordpress': [
                '/wp-content/',
                '/wp-admin/',
                'wp-json',
                'wordpress'
            ],
            'drupal': [
                '/sites/default/',
                'drupal.js',
                'Drupal.settings'
            ],
            'joomla': [
                '/media/jui/',
                '/administrator/',
                'Joomla!'
            ],
            'django': [
                '/static/admin/',
                'csrfmiddlewaretoken',
                'Django'
            ],
            'rails': [
                '/assets/application-',
                'rails.js',
                'Ruby on Rails'
            ],
            'laravel': [
                '/vendor/laravel/',
                'csrf-token',
                'Laravel'
            ]
        }
        
        detected_frameworks = {}
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            content = response.text.lower()
            headers = str(response.headers).lower()
            
            for framework, signatures in framework_signatures.items():
                matches = []
                for signature in signatures:
                    if signature.lower() in content or signature.lower() in headers:
                        matches.append(signature)
                
                if matches:
                    detected_frameworks[framework] = {
                        'confidence': len(matches) / len(signatures),
                        'matched_signatures': matches
                    }
                    
        except requests.RequestException as e:
            detected_frameworks['error'] = str(e)
        
        self.results['frameworks'] = detected_frameworks

    def error_page_analysis(self):
        """Analyze error pages for fingerprinting"""
        error_paths = [
            '/nonexistent-page-12345',
            '/../etc/passwd',
            '/wp-admin/test',
            '/administrator/test',
            '/.git/config',
            '/server-status',
            '/phpinfo.php'
        ]
        
        error_responses = {}
        
        for path in error_paths:
            try:
                url = urljoin(self.target_url, path)
                response = self.session.get(url, timeout=5)
                
                error_responses[path] = {
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'server_header': response.headers.get('Server', ''),
                    'page_title': self.extract_page_title(response.text),
                    'unique_strings': self.extract_unique_strings(response.text)
                }
                
            except requests.RequestException as e:
                error_responses[path] = {'error': str(e)}
        
        self.results['error_pages'] = error_responses

    def extract_page_title(self, html):
        """Extract page title from HTML"""
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        return title_match.group(1) if title_match else 'No title'

    def extract_unique_strings(self, text):
        """Extract unique strings for fingerprinting"""
        # Look for common framework strings, error messages, etc.
        patterns = [
            r'Apache/(\d+\.\d+\.\d+)',
            r'nginx/(\d+\.\d+\.\d+)',
            r'Microsoft-IIS/(\d+)',
            r'PHP/(\d+\.\d+\.\d+)',
            r'WordPress (\d+\.\d+\.\d+)',
            r'Drupal (\d+)'
        ]
        
        found_strings = []
        for pattern in patterns:
            matches = re.findall(pattern, text)
            found_strings.extend(matches)
        
        return found_strings

    def generate_fingerprint_report(self):
        """Generate comprehensive fingerprint report"""
        self.basic_banner_grab()
        self.advanced_header_analysis()
        self.ssl_tls_fingerprinting()
        self.framework_detection()
        self.error_page_analysis()
        
        return self.results

# Advanced Passive Fingerprinting
class PassiveFingerprinter:
    def __init__(self, pcap_file=None):
        self.pcap_file = pcap_file
        self.fingerprints = {}

    def analyze_tcp_behavior(self):
        """Analyze TCP stack behavior for OS fingerprinting"""
        # This would typically use pcap analysis
        tcp_fingerprints = {
            'window_size': self.analyze_window_size(),
            'ttl_values': self.analyze_ttl(),
            'tcp_options': self.analyze_tcp_options(),
            'mss_values': self.analyze_mss(),
            'timestamp_behavior': self.analyze_timestamps()
        }
        return tcp_fingerprints

    def analyze_http_traffic_patterns(self):
        """Analyze HTTP traffic patterns"""
        patterns = {
            'request_intervals': self.analyze_request_timing(),
            'response_sizes': self.analyze_response_sizes(),
            'header_patterns': self.analyze_header_patterns(),
            'error_rates': self.analyze_error_rates()
        }
        return patterns
```

### 13 Continuous Fingerprinting Monitoring
```python
# Web Server Fingerprinting Monitor
class ServerFingerprintMonitor:
    def __init__(self, target_domains):
        self.target_domains = target_domains
        self.known_fingerprints = {}
        self.change_detection_threshold = 0.8

    def setup_continuous_monitoring(self):
        """Set up continuous fingerprint monitoring"""
        for domain in self.target_domains:
            current_fp = self.get_current_fingerprint(domain)
            previous_fp = self.known_fingerprints.get(domain)
            
            if previous_fp:
                similarity = self.compare_fingerprints(current_fp, previous_fp)
                if similarity < self.change_detection_threshold:
                    self.alert_fingerprint_change(domain, current_fp, previous_fp, similarity)
            
            self.known_fingerprints[domain] = current_fp

    def get_current_fingerprint(self, domain):
        """Get current server fingerprint"""
        fingerprinter = WebServerFingerprinter(f"https://{domain}")
        return fingerprinter.generate_fingerprint_report()

    def compare_fingerprints(self, fp1, fp2):
        """Compare two fingerprints for similarity"""
        # Simple similarity calculation based on key attributes
        matching_attributes = 0
        total_attributes = 0
        
        for key in set(fp1.keys()) | set(fp2.keys()):
            if key in fp1 and key in fp2:
                if fp1[key] == fp2[key]:
                    matching_attributes += 1
                total_attributes += 1
        
        return matching_attributes / total_attributes if total_attributes > 0 else 0

    def alert_fingerprint_change(self, domain, current_fp, previous_fp, similarity):
        """Alert on fingerprint changes"""
        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'domain': domain,
            'similarity_score': similarity,
            'changes': self.identify_changes(current_fp, previous_fp),
            'current_fingerprint': current_fp,
            'previous_fingerprint': previous_fp,
            'severity': self.calculate_change_severity(current_fp, previous_fp)
        }
        
        self.report_to_security_team(alert_data)
        logger.warning(f"Server fingerprint change detected: {alert_data}")

    def identify_changes(self, current, previous):
        """Identify specific changes between fingerprints"""
        changes = {}
        
        for key in set(current.keys()) | set(previous.keys()):
            current_val = current.get(key)
            previous_val = previous.get(key)
            
            if current_val != previous_val:
                changes[key] = {
                    'from': previous_val,
                    'to': current_val
                }
        
        return changes

# Automated Fingerprinting Database
class FingerprintDatabase:
    def __init__(self):
        self.signatures = self.load_signatures()
    
    def load_signatures(self):
        """Load web server signatures"""
        return {
            'apache': {
                'headers': ['Apache', 'Apache/2'],
                'error_patterns': ['Apache', 'httpd'],
                'default_pages': ['index.html', 'test.php'],
                'ports': [80, 443, 8080]
            },
            'nginx': {
                'headers': ['nginx'],
                'error_patterns': ['nginx'],
                'default_pages': ['index.html', 'welcome to nginx'],
                'ports': [80, 443]
            },
            'iis': {
                'headers': ['Microsoft-IIS', 'X-Powered-By: ASP.NET'],
                'error_patterns': ['IIS', 'Microsoft'],
                'default_pages': ['iisstart.html'],
                'ports': [80, 443]
            },
            'tomcat': {
                'headers': ['Apache-Coyote', 'Tomcat'],
                'error_patterns': ['Tomcat', 'Apache'],
                'default_pages': ['tomcat.css'],
                'ports': [8080, 8443]
            }
        }
    
    def identify_server(self, fingerprint):
        """Identify web server based on fingerprint"""
        scores = {}
        
        for server_type, signatures in self.signatures.items():
            score = 0
            total = 0
            
            # Check headers
            server_header = fingerprint.get('server_banner', '').lower()
            for header_pattern in signatures['headers']:
                if header_pattern.lower() in server_header:
                    score += 1
                total += 1
            
            # Check error patterns
            error_pages = fingerprint.get('error_pages', {})
            for error_data in error_pages.values():
                if 'unique_strings' in error_data:
                    for pattern in signatures['error_patterns']:
                        if any(pattern.lower() in s.lower() for s in error_data['unique_strings']):
                            score += 1
                            total += 1
            
            if total > 0:
                scores[server_type] = score / total
        
        # Return server with highest score
        return max(scores.items(), key=lambda x: x[1]) if scores else ('unknown', 0)
```

### 14 Risk Assessment Matrix
```yaml
Web Server Fingerprinting Risk Assessment:
  Critical Risk Exposures:
    - Outdated server versions with known vulnerabilities
    - Default installations with demo content
    - Verbose error messages revealing system information
    - Unnecessary HTTP methods enabled (PUT, DELETE, TRACE)
    - Missing security headers
    - Exposed administrative interfaces
    - Unpatched security vulnerabilities
    - Default credentials accessible

  High Risk Exposures:
    - Server version disclosure in headers
    - Framework version information exposure
    - Directory listing enabled
    - Backup files accessible
    - Configuration files exposed
    - Unnecessary services running
    - Weak SSL/TLS configurations
    - Missing security patches

  Medium Risk Exposures:
    - Server type disclosure
    - Technology stack information
    - Custom error pages missing
    - Unusual open ports
    - Non-standard configurations
    - Development features enabled
    - Debug information exposure
    - Sample files present

  Low Risk Exposures:
    - Server header present but generic
    - Standard configurations
    - Common ports only
    - Security headers partially implemented
    - Normal error messages
    - Standard authentication methods
    - Typical traffic patterns
    - Common framework usage
```

### 15 Defense & Obfuscation Testing
```python
# Web Server Obfuscation Tester
class ServerObfuscationTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.test_results = {}

    def test_header_obfuscation(self):
        """Test server header obfuscation effectiveness"""
        tests = {
            'server_header_removed': self.check_server_header_removed(),
            'powered_by_removed': self.check_powered_by_removed(),
            'custom_headers': self.check_custom_headers(),
            'header_consistency': self.check_header_consistency()
        }
        return tests

    def check_server_header_removed(self):
        """Check if Server header is removed or obfuscated"""
        try:
            response = requests.head(self.target_url, timeout=10)
            server_header = response.headers.get('Server', '')
            
            if not server_header:
                return {'status': 'PASS', 'message': 'Server header removed'}
            elif server_header in ['', ' ', 'Unknown']:
                return {'status': 'PASS', 'message': 'Server header obfuscated'}
            else:
                return {'status': 'FAIL', 'message': f'Server header exposed: {server_header}'}
                
        except Exception as e:
            return {'status': 'ERROR', 'message': str(e)}

    def test_error_page_obfuscation(self):
        """Test error page information leakage"""
        error_tests = {}
        error_paths = ['/nonexistent', '/../etc/passwd', '/admin/test']
        
        for path in error_paths:
            try:
                url = urljoin(self.target_url, path)
                response = requests.get(url, timeout=5)
                
                analysis = {
                    'status_code': response.status_code,
                    'server_info_leaked': self.analyze_error_leakage(response.text),
                    'stack_trace_present': 'stack trace' in response.text.lower(),
                    'framework_info': self.extract_framework_info(response.text)
                }
                
                error_tests[path] = analysis
                
            except Exception as e:
                error_tests[path] = {'error': str(e)}
        
        return error_tests

    def analyze_error_leakage(self, error_content):
        """Analyze error content for information leakage"""
        leakage_indicators = [
            'Apache/', 'nginx/', 'Microsoft-IIS/', 'PHP/',
            'Windows', 'Linux', 'Unix',
            'file path', 'absolute path',
            'database', 'sql query'
        ]
        
        found_leaks = []
        for indicator in leakage_indicators:
            if indicator.lower() in error_content.lower():
                found_leaks.append(indicator)
        
        return found_leaks

    def test_http_method_restriction(self):
        """Test HTTP method restrictions"""
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
        method_results = {}
        
        for method in dangerous_methods:
            try:
                response = requests.request(method, self.target_url, timeout=5)
                method_results[method] = {
                    'allowed': response.status_code not in [405, 501, 403],
                    'status_code': response.status_code,
                    'risk_level': 'HIGH' if response.status_code not in [405, 501, 403] else 'LOW'
                }
            except Exception as e:
                method_results[method] = {'error': str(e)}
        
        return method_results

    def generate_obfuscation_report(self):
        """Generate comprehensive obfuscation report"""
        report = {
            'header_obfuscation': self.test_header_obfuscation(),
            'error_page_obfuscation': self.test_error_page_obfuscation(),
            'method_restriction': self.test_http_method_restriction(),
            'overall_obfuscation_score': self.calculate_obfuscation_score(),
            'recommendations': self.generate_obfuscation_recommendations()
        }
        return report
```

### 16 Remediation Checklist
```markdown
## ✅ WEB SERVER FINGERPRINTING REMEDIATION CHECKLIST

### Header Obfuscation:
- [ ] Remove or obfuscate Server header
- [ ] Remove X-Powered-By header
- [ ] Remove X-AspNet-Version header
- [ ] Remove X-AspNetMvc-Version header
- [ ] Remove X-Runtime header
- [ ] Remove X-Version header
- [ ] Remove Via header when possible
- [ ] Implement custom header configurations

### Error Page Security:
- [ ] Implement custom error pages
- [ ] Remove stack traces from production
- [ ] Obfuscate framework information
- [ ] Remove file path disclosures
- [ ] Customize 404 error pages
- [ ] Customize 500 error pages
- [ ] Remove server signatures from errors
- [ ] Implement generic error messages

### HTTP Method Security:
- [ ] Disable unnecessary HTTP methods (PUT, DELETE, TRACE)
- [ ] Implement proper OPTIONS response
- [ ] Restrict CONNECT method
- [ ] Configure HEAD method properly
- [ ] Validate HTTP method usage
- [ ] Implement method whitelisting
- [ ] Monitor for method abuse
- [ ] Regular method auditing

### Server Configuration:
- [ ] Change default ports when possible
- [ ] Remove default files and pages
- [ ] Disable directory listing
- [ ] Secure configuration files
- [ ] Remove sample applications
- [ ] Disable server status pages
- [ ] Remove backup files
- [ ] Secure log files

### SSL/TLS Configuration:
- [ ] Remove SSLv2, SSLv3 support
- [ ] Prefer TLS  and above
- [ ] Implement strong cipher suites
- [ ] Remove weak ciphers
- [ ] Implement certificate pinning
- [ ] Configure proper certificate chain
- [ ] Implement HSTS header
- [ ] Regular certificate updates

### Framework Security:
- [ ] Remove framework identification
- [ ] Obfuscate CMS signatures
- [ ] Remove version information
- [ ] Secure administrative interfaces
- [ ] Implement proper access controls
- [ ] Remove development features
- [ ] Secure configuration files
- [ ] Regular framework updates

### Monitoring & Detection:
- [ ] Implement fingerprinting detection
- [ ] Monitor for reconnaissance activity
- [ ] Set up alerting for fingerprinting attempts
- [ ] Regular security scanning
- [ ] Implement WAF with fingerprint protection
- [ ] Monitor header changes
- [ ] Track configuration modifications
- [ ] Implement change detection

### Network Security:
- [ ] Implement network segmentation
- [ ] Configure firewalls properly
- [ ] Use reverse proxies for obfuscation
- [ ] Implement load balancer security
- [ ] Configure IDS/IPS systems
- [ ] Implement rate limiting
- [ ] Use CDN for additional obfuscation
- [ ] Regular network security audits
```

### 17 Secure Configuration Examples
```nginx
# Secure Nginx Configuration for Fingerprinting Protection
server {
    listen 80;
    server_name example.com;
    
    # Remove server tokens
    server_tokens off;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Remove unnecessary headers
    more_clear_headers 'X-Powered-By';
    more_clear_headers 'X-Runtime';
    more_clear_headers 'X-Version';
    
    # Custom error pages
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    
    location = /404.html {
        internal;
        # Simple generic error page
        return 404 'Page not found';
    }
    
    location = /50x.html {
        internal;
        # Simple generic error page
        return 500 'Server error';
    }
    
    # Disable unnecessary methods
    if ($request_method !~ ^(GET|POST|HEAD)$ ) {
        return 405;
    }
    
    # Restrict access to sensitive files
    location ~ /\. {
        deny all;
        return 404;
    }
    
    location ~* \.(log|sql|bak|backup|old)$ {
        deny all;
        return 404;
    }
}

# Apache Configuration for Fingerprinting Protection
ServerTokens Prod
ServerSignature Off
TraceEnable Off

# Remove version information
Header unset X-Powered-By
Header unset X-Version
Header unset X-Runtime

# Security headers
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-XSS-Protection "1; mode=block"
Header always set X-Content-Type-Options "nosniff"

# Restrict HTTP methods
<LimitExcept GET POST HEAD>
    Deny from all
</LimitExcept>
```

```python
# Django Settings for Fingerprinting Protection
# settings.py

# Security settings
DEBUG = False
SECRET_KEY = os.environ.get('SECRET_KEY')

# Remove framework identification
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'

# Custom error handlers
handler404 = 'myapp.views.custom_404'
handler500 = 'myapp.views.custom_500'

# Remove powered-by header
SECURE_HIDE_POWERED_BY = True

# Middleware to remove identifying headers
class RemoveServerHeaderMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if 'Server' in response:
            del response['Server']
        if 'X-Powered-By' in response:
            del response['X-Powered-By']
        return response
```

### 18 Testing Completion Checklist
```markdown
## ✅ WEB SERVER FINGERPRINTING TESTING COMPLETION CHECKLIST

### Banner Grabbing Testing:
- [ ] Netcat banner grabbing completed
- [ ] Telnet header retrieval completed
- [ ] cURL header analysis completed
- [ ] Wget server identification completed
- [ ] OpenSSL connection testing completed
- [ ] HTTPie inspection completed
- [ ] PowerShell testing completed
- [ ] Python requests testing completed

### HTTP Header Analysis:
- [ ] Server header analysis completed
- [ ] X-Powered-By header examination completed
- [ ] Custom header identification completed
- [ ] Security header analysis completed
- [ ] Response code analysis completed
- [ ] Header order analysis completed
- [ ] Date format analysis completed
- [ ] ETag pattern analysis completed

### Active Fingerprinting:
- [ ] HTTP method testing completed
- [ ] Protocol version testing completed
- [ ] Malformed request testing completed
- [ ] Header manipulation testing completed
- [ ] Overflow testing completed
- [ ] URL encoding testing completed
- [ ] Case sensitivity testing completed
- [ ] Special character testing completed

### Passive Fingerprinting:
- [ ] TCP window analysis completed
- [ ] TTL value analysis completed
- [ ] TCP sequence analysis completed
- [ ] Timing analysis completed
- [ ] Traffic pattern analysis completed
- [ ] Behavioral profiling completed
- [ ] Statistical analysis completed
- [ ] Protocol analysis completed

### Server Software Identification:
- [ ] Apache detection testing completed
- [ ] Nginx identification testing completed
- [ ] IIS detection testing completed
- [ ] Tomcat recognition testing completed
- [ ] Other server detection completed
- [ ] Version identification completed
- [ ] Module detection completed
- [ ] Configuration analysis completed

### Application Server Detection:
- [ ] Java server detection completed
- [ ] PHP server detection completed
- [ ] Python server detection completed
- [ ] Ruby server detection completed
- [ ]  NET server detection completed
- [ ] Node.js detection completed
- [ ] Framework detection completed
- [ ] CMS detection completed

### Security Controls Testing:
- [ ] WAF detection testing completed
- [ ] Reverse proxy detection completed
- [ ] CDN identification completed
- [ ] Load balancer detection completed
- [ ] Security header testing completed
- [ ] Access control testing completed
- [ ] Error handling testing completed
- [ ] Obfuscation testing completed

### Impact Assessment:
- [ ] Information exposure assessment completed
- [ ] Risk classification completed
- [ ] Vulnerability mapping completed
- [ ] Attack surface analysis completed
- [ ] Remediation priority assignment completed
- [ ] Security control evaluation completed
- [ ] Monitoring recommendation development completed
- [ ] Reporting completion
```

### 19 Executive Reporting Template
```markdown
# Web Server Fingerprinting Assessment Report

## Executive Summary
- Total servers fingerprinted: [Number]
- Critical information exposures: [Number]
- High-risk configuration issues: [Number]
- Outdated server versions: [Number]
- Security control gaps: [Number]
- Overall fingerprinting resistance score: [A-F Grade]

## Critical Findings
### [Critical Finding Title]
- **Exposure Type:** [Server Version/Configuration/Error Information]
- **Server Software:** [Apache/Nginx/IIS/Tomcat]
- **Version:** [Detected Version]
- **Risk Level:** [Critical/High/Medium/Low]
- **Impact:** [Reconnaissance/Vulnerability Identification/Attack Planning]
- **Remediation Priority:** [Immediate/High/Medium/Low]

## Technical Analysis
### Fingerprinting Methodology
1. **Detection Techniques**
   - Primary method: [Banner Grabbing/Header Analysis/Error Analysis]
   - Confidence level: [High/Medium/Low]
   - Verification methods: [Multiple Tools/Manual Verification/Cross-Validation]

2. **Identified Information**
   - Server software: [Name and Version]
   - Operating system: [OS Type and Version]
   - Framework details: [Framework and Version]
   - Modules and components: [List of Identified Components]
   - Configuration details: [Key Configuration Elements]

3. **Security Implications**
   - Known vulnerabilities: [List of CVEs or Vulnerabilities]
   - Attack surface: [Exposed Services/Interfaces]
   - Reconnaissance value: [Information Useful for Attackers]
   - Compliance impact: [Regulatory or Policy Violations]

## Proof of Concept
### Fingerprinting Demonstration
```http
[Example of fingerprinting commands and responses]
```

### Verification Results
- [ ] Server identification confirmed
- [ ] Version accuracy validated
- [ ] Configuration details verified
- [ ] Security implications assessed
- [ ] Attack feasibility evaluated
- [ ] Remediation requirements identified
- [ ] Monitoring gaps documented
- [ ] Risk scoring completed

## Remediation Recommendations
### Immediate Actions
- [ ] Obfuscate or remove server headers
- [ ] Implement custom error pages
- [ ] Disable unnecessary HTTP methods
- [ ] Update server software
- [ ] Apply security patches

### Medium-term Improvements
- [ ] Implement security headers
- [ ] Configure reverse proxy obfuscation
- [ ] Enhance monitoring and detection
- [ ] Conduct security training
- [ ] Implement WAF protections

### Long-term Strategies
- [ ] Establish server hardening standards
- [ ] Implement continuous security monitoring
- [ ] Develop incident response procedures
- [ ] Regular security assessments
- [ ] Security automation implementation

## Risk Assessment Summary
- **Overall Risk Level:** [Critical/High/Medium/Low]
- **Business Impact:** [Severe/Moderate/Minor]
- **Exploitation Likelihood:** [Certain/Likely/Possible/Unlikely]
- **Remediation Timeline:** [Immediate/1-2 weeks/1+ month]
- **Compliance Impact:** [Regulatory violations/Standards non-compliance]
- **Attack Surface:** [Significant/Moderate/Limited]
- **Security Control Gaps:** [Major/Moderate/Minor]
```

This comprehensive Web Server Fingerprinting checklist provides security professionals with complete methodology for identifying, analyzing, and mitigating web server information disclosure vulnerabilities. The framework covers active and passive fingerprinting techniques, server software identification, security control assessment, and continuous monitoring strategies to protect organizations from reconnaissance and targeted attacks.