# 🔐 API SECURITY TESTING | SECURITY MISCONFIGURATION

## 1 Comprehensive Security Misconfiguration Testing Methodology

### 1.1 Security Misconfiguration Testing Framework
```yaml
Security_Misconfiguration_Testing_Framework:
  Identification_Phase:
    - API infrastructure configuration analysis
    - Server security headers assessment
    - TLS/SSL configuration review
    - CORS policy evaluation
    - HTTP methods and verb testing
    - Error handling and information leakage
    - Directory and file exposure testing

  Exploitation_Phase:
    - Security header bypass testing
    - TLS/SSL vulnerability exploitation
    - CORS misconfiguration exploitation
    - HTTP method abuse testing
    - Information disclosure exploitation
    - Directory traversal testing
    - Default configuration abuse

  Validation_Phase:
    - Security control effectiveness testing
    - Configuration hardening validation
    - Information leakage prevention verification
    - Access control enforcement testing
    - Encryption implementation validation
    - Logging and monitoring verification
```

### 1.2 Security Misconfiguration Attack Vectors
- **Server Configuration Issues:**
  - Missing security headers
  - Weak TLS/SSL configurations
  - Unnecessary HTTP methods enabled
  - Verbose error messages
  - Directory listing enabled
  - Default files and installations

- **Application Configuration Issues:**
  - Improper CORS configurations
  - Missing content security policies
  - Insecure cookie settings
  - Exposed development features
  - Debug mode enabled in production
  - Unprotected admin interfaces

## 2 Security Misconfiguration Testing Techniques

### 2.1 Security Headers Testing
```python
# Security Headers Testing Tool
import requests
import json
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
import asyncio
import aiohttp
import ssl
import OpenSSL
from urllib.parse import urljoin

@dataclass
class SecurityConfigResult:
    vulnerability_type: str
    component: str
    misconfiguration: str
    severity: str
    evidence: str
    recommendation: str
    risk_score: int

class SecurityHeadersTester:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.vulnerabilities: List[SecurityConfigResult] = []
        self.required_headers = {
            'Strict-Transport-Security': 'high',
            'Content-Security-Policy': 'high',
            'X-Content-Type-Options': 'medium',
            'X-Frame-Options': 'medium',
            'X-XSS-Protection': 'low',
            'Referrer-Policy': 'low',
            'Permissions-Policy': 'medium'
        }
        
    async def test_security_headers(self) -> List[SecurityConfigResult]:
        """Test for missing or misconfigured security headers"""
        results = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.base_url) as response:
                    headers = dict(response.headers)
                    
                    # Check for missing security headers
                    for header, severity in self.required_headers.items():
                        if header not in headers:
                            result = SecurityConfigResult(
                                vulnerability_type="Missing Security Header",
                                component="HTTP Headers",
                                misconfiguration=f"Missing {header}",
                                severity=severity.title(),
                                evidence=f"Header {header} not present in response",
                                recommendation=f"Implement {header} with secure values",
                                risk_score=self.calculate_risk_score(severity)
                            )
                            results.append(result)
                    
                    # Test existing header configurations
                    header_results = await self.test_header_configurations(headers)
                    results.extend(header_results)
        
        except Exception as e:
            print(f"Error testing security headers: {e}")
        
        return results

    async def test_header_configurations(self, headers: Dict[str, str]) -> List[SecurityConfigResult]:
        """Test configuration of existing security headers"""
        results = []
        
        # Test HSTS configuration
        if 'Strict-Transport-Security' in headers:
            hsts_results = self.test_hsts_header(headers['Strict-Transport-Security'])
            results.extend(hsts_results)
        
        # Test CSP configuration
        if 'Content-Security-Policy' in headers:
            csp_results = self.test_csp_header(headers['Content-Security-Policy'])
            results.extend(csp_results)
        
        # Test X-Frame-Options
        if 'X-Frame-Options' in headers:
            xfo_results = self.test_xframe_header(headers['X-Frame-Options'])
            results.extend(xfo_results)
        
        # Test CORS headers
        cors_results = await self.test_cors_headers()
        results.extend(cors_results)
        
        return results

    def test_hsts_header(self, hsts_value: str) -> List[SecurityConfigResult]:
        """Test HSTS header configuration"""
        results = []
        
        issues = []
        
        # Check for max-age
        if 'max-age=0' in hsts_value:
            issues.append("HSTS max-age set to 0 (disables HSTS)")
        elif 'max-age' not in hsts_value:
            issues.append("HSTS max-age not specified")
        else:
            # Extract max-age value
            import re
            match = re.search(r'max-age=(\d+)', hsts_value)
            if match:
                max_age = int(match.group(1))
                if max_age < 31536000:  # Less than 1 year
                    issues.append(f"HSTS max-age too short: {max_age}")
        
        # Check for includeSubDomains
        if 'includeSubDomains' not in hsts_value:
            issues.append("HSTS includeSubDomains missing")
        
        # Check for preload
        if 'preload' not in hsts_value:
            issues.append("HSTS preload directive missing")
        
        for issue in issues:
            results.append(SecurityConfigResult(
                vulnerability_type="HSTS Misconfiguration",
                component="Strict-Transport-Security",
                misconfiguration=issue,
                severity="High",
                evidence=f"HSTS header: {hsts_value}",
                recommendation="Configure HSTS with max-age=31536000; includeSubDomains; preload",
                risk_score=7
            ))
        
        return results

    def test_csp_header(self, csp_value: str) -> List[SecurityConfigResult]:
        """Test Content Security Policy configuration"""
        results = []
        
        issues = []
        
        # Check for unsafe directives
        unsafe_patterns = [
            "'unsafe-inline'", "'unsafe-eval'", "data:", "http:", "*"
        ]
        
        for pattern in unsafe_patterns:
            if pattern in csp_value:
                issues.append(f"CSP contains unsafe directive: {pattern}")
        
        # Check for missing default-src
        if 'default-src' not in csp_value:
            issues.append("CSP missing default-src directive")
        
        # Check script-src configuration
        if 'script-src' in csp_value:
            script_src = csp_value.split('script-src')[1].split(';')[0]
            if "'unsafe-inline'" in script_src and "'self'" not in script_src:
                issues.append("CSP script-src allows unsafe-inline without self")
        
        for issue in issues:
            results.append(SecurityConfigResult(
                vulnerability_type="CSP Misconfiguration",
                component="Content-Security-Policy",
                misconfiguration=issue,
                severity="Medium",
                evidence=f"CSP header: {csp_value}",
                recommendation="Implement strict CSP without unsafe directives",
                risk_score=5
            ))
        
        return results

    def test_xframe_header(self, xframe_value: str) -> List[SecurityConfigResult]:
        """Test X-Frame-Options header configuration"""
        results = []
        
        valid_values = ['DENY', 'SAMEORIGIN']
        
        if xframe_value not in valid_values:
            results.append(SecurityConfigResult(
                vulnerability_type="X-Frame-Options Misconfiguration",
                component="X-Frame-Options",
                misconfiguration=f"Invalid value: {xframe_value}",
                severity="Medium",
                evidence=f"X-Frame-Options: {xframe_value}",
                recommendation="Set X-Frame-Options to DENY or SAMEORIGIN",
                risk_score=4
            ))
        
        return results

    async def test_cors_headers(self) -> List[SecurityConfigResult]:
        """Test CORS header configurations"""
        results = []
        
        # Test CORS with different origins
        test_origins = [
            'https://malicious.com',
            'http://evil.com',
            'null',
            self.base_url
        ]
        
        for origin in test_origins:
            cors_results = await self.test_cors_origin(origin)
            results.extend(cors_results)
        
        return results

    async def test_cors_origin(self, origin: str) -> List[SecurityConfigResult]:
        """Test CORS configuration with specific origin"""
        results = []
        
        try:
            headers = {'Origin': origin}
            
            async with aiohttp.ClientSession() as session:
                # Test preflight request
                async with session.options(
                    self.base_url,
                    headers=headers
                ) as response:
                    
                    cors_headers = dict(response.headers)
                    
                    # Check Access-Control-Allow-Origin
                    if 'Access-Control-Allow-Origin' in cors_headers:
                        allowed_origin = cors_headers['Access-Control-Allow-Origin']
                        
                        if allowed_origin == '*':
                            results.append(SecurityConfigResult(
                                vulnerability_type="CORS Misconfiguration",
                                component="CORS Headers",
                                misconfiguration="Access-Control-Allow-Origin set to *",
                                severity="High",
                                evidence=f"CORS allows all origins: {allowed_origin}",
                                recommendation="Restrict CORS to specific trusted origins",
                                risk_score=8
                            ))
                        elif allowed_origin == origin and origin not in [self.base_url, 'null']:
                            results.append(SecurityConfigResult(
                                vulnerability_type="CORS Misconfiguration",
                                component="CORS Headers",
                                misconfiguration=f"Reflects arbitrary origin: {origin}",
                                severity="High",
                                evidence=f"CORS reflects origin: {allowed_origin}",
                                recommendation="Validate and whitelist CORS origins",
                                risk_score=7
                            ))
        
        except Exception as e:
            print(f"Error testing CORS origin {origin}: {e}")
        
        return results

    def calculate_risk_score(self, severity: str) -> int:
        """Calculate risk score based on severity"""
        risk_scores = {
            'high': 8,
            'medium': 5,
            'low': 2
        }
        return risk_scores.get(severity, 1)
```

### 2.2 TLS/SSL Configuration Testing
```python
# TLS/SSL Configuration Testing Tool
class TLSConfigurationTester:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.vulnerabilities: List[SecurityConfigResult] = []
        
    async def test_tls_configuration(self) -> List[SecurityConfigResult]:
        """Comprehensive TLS/SSL configuration testing"""
        results = []
        
        # Extract hostname and port from URL
        from urllib.parse import urlparse
        parsed_url = urlparse(self.base_url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        
        # Test TLS protocol support
        protocol_results = await self.test_tls_protocols(hostname, port)
        results.extend(protocol_results)
        
        # Test cipher suites
        cipher_results = await self.test_cipher_suites(hostname, port)
        results.extend(cipher_results)
        
        # Test certificate validation
        cert_results = await self.test_certificate(hostname, port)
        results.extend(cert_results)
        
        return results

    async def test_tls_protocols(self, hostname: str, port: int) -> List[SecurityConfigResult]:
        """Test supported TLS protocols"""
        results = []
        
        protocols = {
            'SSLv2': ssl.PROTOCOL_SSLv2,
            'SSLv3': ssl.PROTOCOL_SSLv3,
            'TLSv1': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
            'TLSv1.3': getattr(ssl, 'PROTOCOL_TLSv1_3', None)
        }
        
        for protocol_name, protocol_constant in protocols.items():
            if protocol_constant is None:
                continue
                
            try:
                context = ssl.SSLContext(protocol_constant)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Try to connect with this protocol
                reader, writer = await asyncio.open_connection(
                    hostname, port, ssl=context
                )
                writer.close()
                await writer.wait_closed()
                
                # If connection successful, protocol is supported
                if protocol_name in ['SSLv2', 'SSLv3', 'TLSv1']:
                    results.append(SecurityConfigResult(
                        vulnerability_type="Weak TLS Protocol",
                        component="TLS Configuration",
                        misconfiguration=f"Supports insecure protocol: {protocol_name}",
                        severity="High",
                        evidence=f"Server accepts connections using {protocol_name}",
                        recommendation=f"Disable {protocol_name} support",
                        risk_score=9
                    ))
                
            except Exception:
                # Protocol not supported, which is good for weak protocols
                pass
        
        return results

    async def test_cipher_suites(self, hostname: str, port: int) -> List[SecurityConfigResult]:
        """Test supported cipher suites"""
        results = []
        
        weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'SHA1', 'NULL', 'EXPORT', 'ANON'
        ]
        
        try:
            # Get certificate and cipher info
            cert = ssl.get_server_certificate((hostname, port))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            
            # Test connection with various cipher suites
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.open_connection(
                hostname, port, ssl=context
            )
            
            ssl_socket = writer.get_extra_info('ssl_object')
            cipher = ssl_socket.cipher()
            
            if cipher:
                cipher_name = cipher[0]
                # Check for weak ciphers
                for weak_cipher in weak_ciphers:
                    if weak_cipher in cipher_name.upper():
                        results.append(SecurityConfigResult(
                            vulnerability_type="Weak Cipher Suite",
                            component="TLS Configuration",
                            misconfiguration=f"Uses weak cipher: {cipher_name}",
                            severity="High",
                            evidence=f"Server uses weak cipher: {cipher_name}",
                            recommendation="Disable weak cipher suites",
                            risk_score=8
                        ))
                        break
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            print(f"Error testing cipher suites: {e}")
        
        return results

    async def test_certificate(self, hostname: str, port: int) -> List[SecurityConfigResult]:
        """Test certificate configuration"""
        results = []
        
        try:
            cert = ssl.get_server_certificate((hostname, port))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            
            # Check certificate expiration
            not_after = x509.get_notAfter().decode('utf-8')
            expiration_date = datetime.strptime(not_after, '%Y%m%d%H%M%SZ')
            days_until_expiry = (expiration_date - datetime.now()).days
            
            if days_until_expiry < 30:
                results.append(SecurityConfigResult(
                    vulnerability_type="Certificate Expiration",
                    component="TLS Certificate",
                    misconfiguration=f"Certificate expires in {days_until_expiry} days",
                    severity="Medium",
                    evidence=f"Certificate expiration: {expiration_date}",
                    recommendation="Renew certificate before expiration",
                    risk_score=5
                ))
            
            # Check certificate subject
            subject = x509.get_subject()
            common_name = subject.CN
            
            if common_name != hostname:
                results.append(SecurityConfigResult(
                    vulnerability_type="Certificate Name Mismatch",
                    component="TLS Certificate",
                    misconfiguration=f"Certificate CN {common_name} doesn't match hostname {hostname}",
                    severity="Medium",
                    evidence=f"Certificate CN: {common_name}, Hostname: {hostname}",
                    recommendation="Ensure certificate CN matches hostname",
                    risk_score=4
                ))
            
            # Check key size
            public_key = x509.get_pubkey()
            key_bits = public_key.bits()
            
            if key_bits < 2048:
                results.append(SecurityConfigResult(
                    vulnerability_type="Weak Key Size",
                    component="TLS Certificate",
                    misconfiguration=f"Certificate key size too small: {key_bits} bits",
                    severity="High",
                    evidence=f"Certificate key size: {key_bits} bits",
                    recommendation="Use certificates with at least 2048-bit keys",
                    risk_score=7
                ))
            
        except Exception as e:
            print(f"Error testing certificate: {e}")
        
        return results
```

### 2.3 HTTP Methods and Verb Testing
```python
# HTTP Methods and Verb Testing Tool
class HTTPMethodsTester:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.vulnerabilities: List[SecurityConfigResult] = []
        
    async def test_http_methods(self, endpoints: List[Dict]) -> List[SecurityConfigResult]:
        """Test HTTP methods and verbs for misconfigurations"""
        results = []
        
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']
        
        for endpoint in endpoints:
            endpoint_results = await self.test_endpoint_methods(endpoint, dangerous_methods)
            results.extend(endpoint_results)
            
            # Test HTTP verb tampering
            verb_results = await self.test_http_verb_tampering(endpoint)
            results.extend(verb_results)
        
        return results

    async def test_endpoint_methods(self, endpoint: Dict, dangerous_methods: List[str]) -> List[SecurityConfigResult]:
        """Test dangerous HTTP methods on endpoints"""
        results = []
        
        url = f"{self.base_url}{endpoint['url']}"
        
        for method in dangerous_methods:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.request(
                        method,
                        url,
                        allow_redirects=False
                    ) as response:
                        
                        # Check if dangerous method is allowed
                        if response.status not in [405, 501]:  # Not Method Not Allowed
                            results.append(SecurityConfigResult(
                                vulnerability_type="Dangerous HTTP Method",
                                component="HTTP Methods",
                                misconfiguration=f"HTTP {method} method enabled",
                                severity="Medium",
                                evidence=f"HTTP {method} method returns status {response.status}",
                                recommendation=f"Disable HTTP {method} method if not required",
                                risk_score=5
                            ))
            
            except Exception as e:
                print(f"Error testing HTTP method {method}: {e}")
        
        return results

    async def test_http_verb_tampering(self, endpoint: Dict) -> List[SecurityConfigResult]:
        """Test HTTP verb tampering vulnerabilities"""
        results = []
        
        url = f"{self.base_url}{endpoint['url']}"
        original_method = endpoint.get('method', 'GET')
        
        # Test method override techniques
        override_techniques = [
            {'X-HTTP-Method-Override': 'DELETE'},
            {'X-Method-Override': 'DELETE'},
            {'X-HTTP-Method': 'DELETE'},
            {'_method': 'DELETE'}
        ]
        
        for override in override_techniques:
            try:
                headers = {'Content-Type': 'application/json'}
                headers.update(override)
                
                async with aiohttp.ClientSession() as session:
                    if original_method == 'GET':
                        async with session.get(url, headers=headers) as response:
                            if response.status == 200:
                                results.append(SecurityConfigResult(
                                    vulnerability_type="HTTP Verb Tampering",
                                    component="HTTP Method Handling",
                                    misconfiguration="HTTP method override accepted",
                                    severity="Medium",
                                    evidence=f"Method override {list(override.keys())[0]} accepted",
                                    recommendation="Disable HTTP method overriding",
                                    risk_score=6
                                ))
                    elif original_method == 'POST':
                        async with session.post(
                            url,
                            headers=headers,
                            json=endpoint.get('test_data', {})
                        ) as response:
                            if response.status in [200, 201]:
                                # Check if the override was processed
                                response_data = await response.text()
                                if 'delete' in response_data.lower():
                                    results.append(SecurityConfigResult(
                                        vulnerability_type="HTTP Verb Tampering",
                                        component="HTTP Method Handling",
                                        misconfiguration="HTTP method override processed",
                                        severity="High",
                                        evidence=f"Method override {list(override.keys())[0]} processed as DELETE",
                                        recommendation="Disable HTTP method overriding",
                                        risk_score=7
                                    ))
            
            except Exception as e:
                print(f"Error testing HTTP verb tampering: {e}")
        
        return results

    async def test_options_method(self, endpoints: List[Dict]) -> List[SecurityConfigResult]:
        """Test OPTIONS method for information disclosure"""
        results = []
        
        for endpoint in endpoints:
            url = f"{self.base_url}{endpoint['url']}"
            
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.options(url) as response:
                        
                        if response.status == 200:
                            allow_header = response.headers.get('Allow', '')
                            
                            if allow_header:
                                # Check for dangerous methods in Allow header
                                dangerous_methods = ['PUT', 'DELETE', 'TRACE']
                                for method in dangerous_methods:
                                    if method in allow_header:
                                        results.append(SecurityConfigResult(
                                            vulnerability_type="Information Disclosure",
                                            component="OPTIONS Method",
                                            misconfiguration=f"OPTIONS reveals {method} method",
                                            severity="Low",
                                            evidence=f"OPTIONS method reveals: {allow_header}",
                                            recommendation="Limit information in OPTIONS responses",
                                            risk_score=2
                                        ))
            
            except Exception as e:
                print(f"Error testing OPTIONS method: {e}")
        
        return results
```

## 3 Information Disclosure Testing

### 3.1 Error Handling and Information Leakage
```python
# Error Handling and Information Leakage Testing Tool
class InformationDisclosureTester:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.vulnerabilities: List[SecurityConfigResult] = []
        
    async def test_information_disclosure(self, endpoints: List[Dict]) -> List[SecurityConfigResult]:
        """Test for information disclosure vulnerabilities"""
        results = []
        
        # Test error handling
        error_results = await self.test_error_handling(endpoints)
        results.extend(error_results)
        
        # Test directory listing
        directory_results = await self.test_directory_listing()
        results.extend(directory_results)
        
        # Test backup file exposure
        backup_results = await self.test_backup_files()
        results.extend(backup_results)
        
        # Test verbose responses
        verbose_results = await self.test_verbose_responses(endpoints)
        results.extend(verbose_results)
        
        return results

    async def test_error_handling(self, endpoints: List[Dict]) -> List[SecurityConfigResult]:
        """Test error handling for information leakage"""
        results = []
        
        for endpoint in endpoints:
            url = f"{self.base_url}{endpoint['url']}"
            
            # Test with malformed requests
            malformed_tests = [
                {'method': 'POST', 'data': 'invalid json'},
                {'method': 'GET', 'params': {'invalid': 'parameter'}},
                {'method': 'POST', 'data': {'malformed': 'data'}}
            ]
            
            for test in malformed_tests:
                try:
                    async with aiohttp.ClientSession() as session:
                        if test['method'] == 'POST':
                            headers = {'Content-Type': 'application/json'}
                            async with session.post(
                                url,
                                headers=headers,
                                data=test['data'] if isinstance(test['data'], str) else json.dumps(test['data'])
                            ) as response:
                                
                                await self.analyze_error_response(response, endpoint, results)
                        
                        elif test['method'] == 'GET':
                            async with session.get(url, params=test.get('params', {})) as response:
                                await self.analyze_error_response(response, endpoint, results)
                
                except Exception as e:
                    print(f"Error testing error handling: {e}")
        
        return results

    async def analyze_error_response(self, response, endpoint: Dict, results: List[SecurityConfigResult]):
        """Analyze error responses for information leakage"""
        if response.status >= 400:
            response_text = await response.text()
            
            # Check for stack traces
            stack_trace_indicators = [
                'stack trace', 'exception', 'at line', 'file://',
                'internal error', 'debug', 'traceback'
            ]
            
            for indicator in stack_trace_indicators:
                if indicator.lower() in response_text.lower():
                    results.append(SecurityConfigResult(
                        vulnerability_type="Information Disclosure",
                        component="Error Handling",
                        misconfiguration="Stack trace in error response",
                        severity="Medium",
                        evidence=f"Error response contains: {indicator}",
                        recommendation="Implement generic error messages",
                        risk_score=5
                    ))
                    break
            
            # Check for database information
            db_indicators = [
                'sql', 'database', 'query', 'column', 'table',
                'mysql', 'postgresql', 'oracle', 'mongo'
            ]
            
            for indicator in db_indicators:
                if indicator.lower() in response_text.lower():
                    results.append(SecurityConfigResult(
                        vulnerability_type="Information Disclosure",
                        component="Error Handling",
                        misconfiguration="Database information in error response",
                        severity="Low",
                        evidence=f"Error response contains: {indicator}",
                        recommendation="Sanitize error messages",
                        risk_score=3
                    ))
                    break
            
            # Check for server information
            server_indicators = [
                'apache', 'nginx', 'iis', 'tomcat', 'jetty',
                'server version', 'powered by'
            ]
            
            for indicator in server_indicators:
                if indicator.lower() in response_text.lower():
                    results.append(SecurityConfigResult(
                        vulnerability_type="Information Disclosure",
                        component="Error Handling",
                        misconfiguration="Server information in error response",
                        severity="Low",
                        evidence=f"Error response contains: {indicator}",
                        recommendation="Remove server identification",
                        risk_score=2
                    ))
                    break

    async def test_directory_listing(self) -> List[SecurityConfigResult]:
        """Test for directory listing enabled"""
        results = []
        
        common_directories = [
            '/admin/', '/backup/', '/logs/', '/tmp/', '/uploads/',
            '/images/', '/css/', '/js/', '/api/', '/doc/'
        ]
        
        for directory in common_directories:
            url = f"{self.base_url}{directory}"
            
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url) as response:
                        
                        if response.status == 200:
                            content = await response.text()
                            
                            # Check for directory listing indicators
                            indicators = [
                                'Index of', 'Directory listing for',
                                '<title>Directory</title>', 'Parent Directory'
                            ]
                            
                            for indicator in indicators:
                                if indicator in content:
                                    results.append(SecurityConfigResult(
                                        vulnerability_type="Directory Listing",
                                        component="Web Server",
                                        misconfiguration=f"Directory listing enabled: {directory}",
                                        severity="Low",
                                        evidence=f"Directory listing found at: {url}",
                                        recommendation="Disable directory listing",
                                        risk_score=3
                                    ))
                                    break
            
            except Exception as e:
                print(f"Error testing directory listing {directory}: {e}")
        
        return results

    async def test_backup_files(self) -> List[SecurityConfigResult]:
        """Test for backup file exposure"""
        results = []
        
        backup_extensions = [
            '.bak', '.backup', '.old', '.tmp', '.temp',
            '.swp', '.swo', '.save', '.orig', '.copy'
        ]
        
        common_files = [
            '/.env', '/config.json', '/settings.py', '/web.config',
            '/package.json', '/composer.json', '/pom.xml'
        ]
        
        # Test common files with backup extensions
        for base_file in common_files:
            for extension in backup_extensions:
                test_file = f"{base_file}{extension}"
                url = f"{self.base_url}{test_file}"
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url) as response:
                            
                            if response.status == 200:
                                results.append(SecurityConfigResult(
                                    vulnerability_type="Backup File Exposure",
                                    component="File System",
                                    misconfiguration=f"Backup file accessible: {test_file}",
                                    severity="Medium",
                                    evidence=f"Backup file found at: {url}",
                                    recommendation="Remove backup files from web root",
                                    risk_score=5
                                ))
                
                except Exception as e:
                    print(f"Error testing backup file {test_file}: {e}")
        
        return results

    async def test_verbose_responses(self, endpoints: List[Dict]) -> List[SecurityConfigResult]:
        """Test for verbose response information"""
        results = []
        
        for endpoint in endpoints:
            url = f"{self.base_url}{endpoint['url']}"
            
            try:
                async with aiohttp.ClientSession() as session:
                    if endpoint.get('method') == 'GET':
                        async with session.get(url) as response:
                            if response.status == 200:
                                headers = dict(response.headers)
                                response_text = await response.text()
                                
                                # Check for verbose headers
                                verbose_headers = [
                                    'X-Powered-By', 'Server', 'X-AspNet-Version',
                                    'X-AspNetMvc-Version', 'X-Runtime'
                                ]
                                
                                for header in verbose_headers:
                                    if header in headers:
                                        results.append(SecurityConfigResult(
                                            vulnerability_type="Information Disclosure",
                                            component="HTTP Headers",
                                            misconfiguration=f"Verbose header: {header}",
                                            severity="Low",
                                            evidence=f"Header {header}: {headers[header]}",
                                            recommendation="Remove verbose headers",
                                            risk_score=2
                                        ))
                
            except Exception as e:
                print(f"Error testing verbose responses: {e}")
        
        return results
```

### 3.2 Debug Mode and Development Features
```python
# Debug Mode and Development Features Testing Tool
class DebugModeTester:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.vulnerabilities: List[SecurityConfigResult] = []
        
    async def test_debug_features(self, endpoints: List[Dict]) -> List[SecurityConfigResult]:
        """Test for enabled debug mode and development features"""
        results = []
        
        # Test common debug endpoints
        debug_endpoints = [
            '/debug', '/console', '/_debug', '/_console',
            '/phpinfo', '/info', '/status', '/metrics',
            '/actuator', '/health', '/env', '/config'
        ]
        
        for debug_endpoint in debug_endpoints:
            url = f"{self.base_url}{debug_endpoint}"
            
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url) as response:
                        
                        if response.status == 200:
                            content = await response.text()
                            
                            # Check for debug information
                            debug_indicators = [
                                'debug', 'development', 'environment',
                                'configuration', 'variables', 'phpinfo'
                            ]
                            
                            for indicator in debug_indicators:
                                if indicator in content.lower():
                                    results.append(SecurityConfigResult(
                                        vulnerability_type="Debug Mode Enabled",
                                        component="Application Configuration",
                                        misconfiguration=f"Debug endpoint accessible: {debug_endpoint}",
                                        severity="High",
                                        evidence=f"Debug endpoint found: {url}",
                                        recommendation="Disable debug mode in production",
                                        risk_score=8
                                    ))
                                    break
            
            except Exception as e:
                print(f"Error testing debug endpoint {debug_endpoint}: {e}")
        
        # Test debug parameters
        debug_results = await self.test_debug_parameters(endpoints)
        results.extend(debug_results)
        
        return results

    async def test_debug_parameters(self, endpoints: List[Dict]) -> List[SecurityConfigResult]:
        """Test debug parameters in requests"""
        results = []
        
        debug_parameters = [
            'debug', 'development', 'test', 'verbose',
            'show_errors', 'display_errors', 'trace'
        ]
        
        for endpoint in endpoints:
            url = f"{self.base_url}{endpoint['url']}"
            
            for param in debug_parameters:
                try:
                    async with aiohttp.ClientSession() as session:
                        if endpoint.get('method') == 'GET':
                            async with session.get(url, params={param: 'true'}) as response:
                                if response.status == 200:
                                    content = await response.text()
                                    
                                    # Check if debug parameter affected response
                                    if 'debug' in content.lower() or 'error' in content.lower():
                                        results.append(SecurityConfigResult(
                                            vulnerability_type="Debug Parameter",
                                            component="Application Configuration",
                                            misconfiguration=f"Debug parameter accepted: {param}",
                                            severity="Medium",
                                            evidence=f"Debug parameter {param} affects response",
                                            recommendation="Ignore debug parameters in production",
                                            risk_score=6
                                        ))
                
                except Exception as e:
                    print(f"Error testing debug parameter {param}: {e}")
        
        return results
```

## 4 Comprehensive Security Misconfiguration Testing Framework

### 4.1 Complete Security Misconfiguration Testing Suite
```python
# Comprehensive Security Misconfiguration Testing Framework
class ComprehensiveSecurityConfigTester:
    def __init__(self, base_url: str, endpoints: List[Dict]):
        self.base_url = base_url
        self.endpoints = endpoints
        self.results: List[SecurityConfigResult] = []
        
        # Initialize testers
        self.headers_tester = SecurityHeadersTester(base_url)
        self.tls_tester = TLSConfigurationTester(base_url)
        self.methods_tester = HTTPMethodsTester(base_url)
        self.disclosure_tester = InformationDisclosureTester(base_url)
        self.debug_tester = DebugModeTester(base_url)
        
    async def run_comprehensive_tests(self) -> Dict[str, Any]:
        """Run comprehensive security misconfiguration testing"""
        test_results = {
            'security_headers': [],
            'tls_configuration': [],
            'http_methods': [],
            'information_disclosure': [],
            'debug_features': [],
            'cors_misconfiguration': []
        }
        
        # Run all test types
        print("Testing Security Headers...")
        headers_results = await self.headers_tester.test_security_headers()
        test_results['security_headers'].extend(headers_results)
        
        print("Testing TLS Configuration...")
        tls_results = await self.tls_tester.test_tls_configuration()
        test_results['tls_configuration'].extend(tls_results)
        
        print("Testing HTTP Methods...")
        methods_results = await self.methods_tester.test_http_methods(self.endpoints)
        test_results['http_methods'].extend(methods_results)
        
        print("Testing Information Disclosure...")
        disclosure_results = await self.disclosure_tester.test_information_disclosure(self.endpoints)
        test_results['information_disclosure'].extend(disclosure_results)
        
        print("Testing Debug Features...")
        debug_results = await self.debug_tester.test_debug_features(self.endpoints)
        test_results['debug_features'].extend(debug_results)
        
        print("Testing CORS Configuration...")
        cors_results = await self.headers_tester.test_cors_headers()
        test_results['cors_misconfiguration'].extend(cors_results)
        
        # Generate comprehensive report
        report = await self.generate_comprehensive_report(test_results)
        
        return report

    async def generate_comprehensive_report(self, test_results: Dict[str, List[SecurityConfigResult]]) -> Dict[str, Any]:
        """Generate comprehensive security misconfiguration report"""
        # Flatten all results
        all_results = []
        for category in test_results.values():
            all_results.extend(category)
        
        # Calculate statistics
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        
        for result in all_results:
            severity_counts[result.severity] += 1
        
        total_vulnerabilities = len(all_results)
        
        # Calculate overall risk score
        total_risk_score = sum(result.risk_score for result in all_results)
        average_risk_score = total_risk_score / max(len(all_results), 1)
        
        # Generate recommendations
        recommendations = self.generate_recommendations(test_results)
        
        report = {
            'summary': {
                'total_vulnerabilities': total_vulnerabilities,
                'severity_breakdown': severity_counts,
                'total_risk_score': total_risk_score,
                'average_risk_score': round(average_risk_score, 2),
                'test_categories': list(test_results.keys()),
                'overall_risk_level': self.calculate_overall_risk(severity_counts, average_risk_score)
            },
            'detailed_findings': test_results,
            'recommendations': recommendations,
            'risk_analysis': await self.perform_risk_analysis(test_results)
        }
        
        return report

    def calculate_overall_risk(self, severity_counts: Dict[str, int], average_risk_score: float) -> str:
        """Calculate overall risk level"""
        if severity_counts['Critical'] > 0 or average_risk_score >= 7:
            return 'Critical'
        elif severity_counts['High'] > 0 or average_risk_score >= 5:
            return 'High'
        elif severity_counts['Medium'] > 0 or average_risk_score >= 3:
            return 'Medium'
        else:
            return 'Low'

    def generate_recommendations(self, test_results: Dict[str, List[SecurityConfigResult]]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if test_results['security_headers']:
            recommendations.extend([
                "Implement missing security headers (HSTS, CSP, X-Frame-Options, etc.)",
                "Configure security headers with secure values",
                "Remove verbose headers (X-Powered-By, Server, etc.)",
                "Implement proper CORS policies"
            ])
        
        if test_results['tls_configuration']:
            recommendations.extend([
                "Disable weak TLS protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1)",
                "Disable weak cipher suites",
                "Ensure certificates are valid and not expiring soon",
                "Use strong certificate key sizes (≥ 2048 bits)"
            ])
        
        if test_results['http_methods']:
            recommendations.extend([
                "Disable unnecessary HTTP methods (PUT, DELETE, TRACE, etc.)",
                "Implement proper HTTP method override protection",
                "Limit information in OPTIONS responses",
                "Validate and sanitize all HTTP method usage"
            ])
        
        if test_results['information_disclosure']:
            recommendations.extend([
                "Implement generic error messages",
                "Disable directory listing",
                "Remove backup files from web root",
                "Sanitize all error responses"
            ])
        
        if test_results['debug_features']:
            recommendations.extend([
                "Disable debug mode in production",
                "Remove or protect debug endpoints",
                "Ignore debug parameters in production",
                "Implement environment-specific configurations"
            ])
        
        if test_results['cors_misconfiguration']:
            recommendations.extend([
                "Implement strict CORS policies",
                "Whitelist specific origins instead of using wildcards",
                "Validate CORS origins server-side",
                "Limit CORS to necessary endpoints only"
            ])
        
        return list(set(recommendations))

    async def perform_risk_analysis(self, test_results: Dict[str, List[SecurityConfigResult]]) -> Dict[str, Any]:
        """Perform detailed risk analysis"""
        risk_analysis = {
            'high_risk_misconfigurations': [],
            'common_patterns': [],
            'immediate_actions': [],
            'compliance_issues': []
        }
        
        # Identify high-risk misconfigurations
        for category, results in test_results.items():
            for result in results:
                if result.risk_score >= 7:
                    risk_analysis['high_risk_misconfigurations'].append({
                        'category': category,
                        'misconfiguration': result.misconfiguration,
                        'risk_score': result.risk_score,
                        'recommendation': result.recommendation
                    })
        
        # Identify common patterns
        misconfiguration_counts = {}
        for category, results in test_results.items():
            for result in results:
                misconfig = result.misconfiguration
                if misconfig not in misconfiguration_counts:
                    misconfiguration_counts[misconfig] = 0
                misconfiguration_counts[misconfig] += 1
        
        common_misconfigs = sorted(misconfiguration_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        risk_analysis['common_patterns'] = common_misconfigs
        
        # Identify immediate actions
        immediate_risks = [r for r in risk_analysis['high_risk_misconfigurations'] if r['risk_score'] >= 8]
        risk_analysis['immediate_actions'] = immediate_risks
        
        # Identify compliance issues
        compliance_standards = {
            'PCI_DSS': ['TLS configuration', 'Security headers', 'Information disclosure'],
            'OWASP_ASVS': ['All categories'],
            'NIST_CSF': ['TLS configuration', 'Security headers']
        }
        
        risk_analysis['compliance_issues'] = compliance_standards
        
        return risk_analysis

# Usage Example
async def main():
    # API endpoints to test
    endpoints = [
        {
            'url': '/api/users',
            'method': 'GET'
        },
        {
            'url': '/api/users',
            'method': 'POST',
            'test_data': {'username': 'test', 'email': 'test@example.com'}
        },
        {
            'url': '/api/admin',
            'method': 'GET'
        }
    ]
    
    # Run comprehensive testing
    tester = ComprehensiveSecurityConfigTester('https://api.example.com', endpoints)
    report = await tester.run_comprehensive_tests()
    
    print(json.dumps(report, indent=2, default=lambda x: x.__dict__))

# Run the comprehensive security misconfiguration tester
# asyncio.run(main())
```

## 5 Security Configuration Protection and Mitigation

### 5.1 Secure Configuration Implementation
```python
# Secure Configuration Protection Framework
class SecureConfigurationProtection:
    def __init__(self):
        self.hardening_measures = {}
        
    def implement_secure_configuration(self) -> Dict[str, Any]:
        """Implement secure configuration patterns"""
        patterns = {
            'web_server_hardening': [
                'Disable server version banners',
                'Remove default files and installations',
                'Disable directory listing',
                'Configure proper MIME types',
                'Set secure file permissions',
                'Implement request size limits'
            ],
            'application_hardening': [
                'Disable debug mode in production',
                'Implement proper error handling',
                'Use environment-specific configurations',
                'Secure configuration files',
                'Implement security headers',
                'Configure CORS properly'
            ],
            'tls_hardening': [
                'Disable weak TLS protocols',
                'Disable weak cipher suites',
                'Implement HSTS',
                'Use strong certificate key sizes',
                'Enable certificate transparency',
                'Implement OCSP stapling'
            ],
            'api_hardening': [
                'Disable unnecessary HTTP methods',
                'Implement rate limiting',
                'Validate all inputs',
                'Implement proper authentication',
                'Use secure session management',
                'Implement comprehensive logging'
            ]
        }
        return patterns

    def create_configuration_checklist(self) -> Dict[str, List[str]]:
        """Create security configuration checklist"""
        checklist = {
            'pre_deployment': [
                "Review and harden web server configuration",
                "Remove default accounts and files",
                "Disable unnecessary services and modules",
                "Implement security headers",
                "Configure TLS/SSL properly",
                "Set up proper error handling",
                "Disable debug and development features",
                "Implement proper file permissions",
                "Configure logging and monitoring",
                "Set up backup and recovery procedures"
            ],
            'post_deployment': [
                "Run security configuration scans",
                "Test security headers implementation",
                "Verify TLS/SSL configuration",
                "Check for information disclosure",
                "Test error handling",
                "Verify access controls",
                "Monitor for configuration changes",
                "Regularly update and patch systems",
                "Review security logs",
                "Conduct periodic security assessments"
            ]
        }
        return checklist

    def implement_configuration_monitoring(self) -> List[str]:
        """Implement configuration monitoring and alerting"""
        monitoring_measures = [
            # Continuous monitoring
            "Monitor for configuration changes",
            "Alert on security header changes",
            "Monitor TLS/SSL certificate expiration",
            "Track security configuration compliance",
            
            # Automated checks
            "Implement configuration validation scripts",
            "Run regular security scans",
            "Monitor for information disclosure",
            "Check for debug mode activation",
            
            # Compliance monitoring
            "Monitor compliance with security standards",
            "Track configuration drift",
            "Alert on policy violations",
            "Generate security configuration reports"
        ]
        return monitoring_measures
```

This comprehensive framework for testing Security Misconfiguration in APIs provides extensive coverage for identifying configuration vulnerabilities across web servers, application settings, TLS/SSL configurations, and API-specific settings. The framework includes testing for security headers, TLS configurations, HTTP methods, information disclosure, debug features, and CORS misconfigurations, along with detailed reporting and mitigation recommendations.