# Testing for Insecure Direct Object References

## Comprehensive IDOR Vulnerability Testing

### 1 IDOR Detection & Enumeration
- **Object Reference Analysis:**
  - Direct object reference identification
  - Parameter naming pattern analysis
  - Object ID format recognition
  - Sequential vs non-sequential ID testing
  - UUID/GUID pattern analysis
  - Hash-based reference testing
  - Encoded reference analysis
  - Composite key identification

- **Endpoint Discovery:**
  - API endpoint enumeration for object references
  - Hidden parameter discovery
  - URL path object reference testing
  - RESTful resource identification
  - GraphQL field enumeration
  - Bulk operation endpoint discovery
  - Export functionality testing
  - Search endpoint analysis

### 2 Object Reference Manipulation
- **Sequential ID Testing:**
  - Incremental ID enumeration (+1, +100, +1000)
  - Decremental ID testing (-1, -100)
  - Pattern-based ID prediction
  - Timestamp-based ID analysis
  - User-specific ID range testing
  - Concurrent ID access testing
  - ID wrapping attacks
  - Negative ID testing

- **Non-Sequential ID Testing:**
  - UUID manipulation attempts
  - Hash cracking and prediction
  - Base64 encoded ID manipulation
  - Custom encoding scheme analysis
  - Checksum bypass attempts
  - Signed reference manipulation
  - Token replay attacks
  - Reference collision testing

### 3 Parameter-Based IDOR
- **Query Parameter Manipulation:**
  - ID parameter tampering (id, user_id, document_id)
  - Resource parameter manipulation
  - Reference parameter modification
  - Filter parameter exploitation
  - Pagination parameter testing
  - Sort parameter manipulation
  - Scope parameter modification
  - Context parameter tampering

- **POST Data Manipulation:**
  - JSON payload ID modification
  - XML entity reference manipulation
  - Form data ID tampering
  - Hidden field reference modification
  - Array parameter manipulation
  - Nested object reference testing
  - Batch operation ID manipulation
  - Multipart form ID testing

### 4 URL Path IDOR
- **RESTful URL Manipulation:**
  - Path segment ID modification (/users/123 → /users/124)
  - Resource hierarchy traversal
  - Nested resource access testing
  - Collection endpoint manipulation
  - Sub-resource reference testing
  - URL-encoded ID manipulation
  - Path parameter modification
  - Route segment manipulation

- **File Path References:**
  - File ID to path mapping testing
  - Document reference manipulation
  - Image ID to file path testing
  - Download reference tampering
  - Backup file reference testing
  - Temporary file access attempts
  - Log file reference manipulation
  - Configuration file access

### 5 API-Based IDOR
- **REST API IDOR Testing:**
  - Endpoint resource ID manipulation
  - Bulk operation ID testing
  - Batch request ID manipulation
  - Pagination IDOR testing
  - Filter bypass through ID manipulation
  - Search result IDOR testing
  - Export functionality ID manipulation
  - Import reference testing

- **GraphQL IDOR Testing:**
  - Node ID manipulation testing
  - Global ID prediction attempts
  - Field-level IDOR testing
  - Mutation input ID manipulation
  - Query variable ID tampering
  - Interface implementation testing
  - Union type IDOR testing
  - Connection edge manipulation

### 6 State-Based IDOR
- **Session-Dependent References:**
  - Session-bound object reference testing
  - User context reference manipulation
  - Stateful reference tampering
  - Workflow state IDOR testing
  - Multi-step process reference manipulation
  - Temporary reference exploitation
  - Cache reference manipulation
  - Token-bound reference testing

- **Context Manipulation:**
  - Tenant context bypass testing
  - Organization context manipulation
  - Project scope reference testing
  - Environment context bypass
  - Location-based reference testing
  - Time-bound reference manipulation
  - Role context manipulation
  - Permission context bypass

### 7 Mass Assignment IDOR
- **Bulk Operation Testing:**
  - Batch request ID manipulation
  - Bulk update IDOR testing
  - Mass assignment reference testing
  - Array parameter ID manipulation
  - Collection operation testing
  - Import/export IDOR testing
  - Sync operation reference manipulation
  - Replication IDOR testing

- **Batch Request Manipulation:**
  - JSON batch request ID tampering
  - Multipart request reference manipulation
  - Parallel operation ID testing
  - Chunked request IDOR testing
  - Stream processing reference testing
  - Queue-based IDOR testing
  - Async operation reference manipulation
  - Webhook reference testing

### 8 Indirect Object Reference Testing
- **Reference Mapping Exploitation:**
  - Indirect reference to direct mapping
  - Token to ID mapping testing
  - Hash to object mapping
  - Temporary reference exploitation
  - Short URL reference testing
  - Share link manipulation
  - Public reference testing
  - Obfuscated reference cracking

- **Cross-Reference Testing:**
  - Multiple reference system testing
  - Reference translation attacks
  - Alias reference manipulation
  - Synonym reference testing
  - Alternate ID system exploitation
  - Legacy reference testing
  - Migration reference manipulation
  - Backup reference testing

### 9 Business Logic IDOR
- **Workflow Exploitation:**
  - Order process IDOR testing
  - Approval workflow reference manipulation
  - Multi-step process ID testing
  - State transition IDOR testing
  - Progress reference manipulation
  - Status-based IDOR testing
  - Conditional reference testing
  - Dependency chain exploitation

- **Domain-Specific IDOR:**
  - Financial transaction ID manipulation
  - Healthcare record reference testing
  - E-commerce order ID tampering
  - Educational record manipulation
  - Government record testing
  - Social media reference manipulation
  - Communication reference testing
  - Inventory reference manipulation

### 10 Advanced IDOR Techniques
- **Timing Attack IDOR:**
  - Response time analysis for object existence
  - Error message timing attacks
  - Cache timing IDOR testing
  - Database query timing analysis
  - Network latency exploitation
  - Concurrent access timing attacks
  - Rate limit timing analysis
  - Load-based timing attacks

- **Race Condition IDOR:**
  - Simultaneous access attempts
  - Parallel request ID manipulation
  - Concurrent modification testing
  - Lock bypass attempts
  - Transaction race conditions
  - State race exploitation
  - Cache race condition testing
  - Database race exploitation

### 11 Automated IDOR Testing Framework
```yaml
IDOR Security Assessment Pipeline:
  Discovery Phase:
    - Object reference endpoint discovery
    - Parameter naming pattern analysis
    - ID format and structure analysis
    - API endpoint enumeration
    - Business workflow mapping
    - Reference type identification
    - Access control mechanism analysis
    - Data flow mapping

  Analysis Phase:
    - ID predictability assessment
    - Reference encoding analysis
    - Access control evaluation
    - Business logic review
    - Data sensitivity assessment
    - Impact analysis
    - Exploitation complexity evaluation
    - Risk exposure calculation

  Testing Phase:
    - Direct reference manipulation
    - Parameter tampering testing
    - URL path manipulation
    - API endpoint testing
    - Business logic exploitation
    - Mass assignment testing
    - Indirect reference testing
    - Advanced technique testing

  Validation Phase:
    - Vulnerability confirmation
    - Business impact verification
    - Data exposure assessment
    - Remediation effectiveness validation
    - Monitoring capability verification
    - Documentation accuracy verification
    - Management approval and sign-off
    - Continuous monitoring setup
```

### 12 IDOR Testing Tools & Commands
```bash
# IDOR Endpoint Discovery
python3 idor_discovery.py --url https://target.com --methods all
gobuster dir -u https://target.com -w /usr/share/wordlists/api_endpoints.txt
burp suite --target https://target.com --idor-scan

# Sequential ID Testing
python3 sequential_idor.py --url https://target.com/users/ --start 1 --end 1000
ffuf -w ids.txt -u https://target.com/users/FUZZ -mc 200
patator http_fuzz url=https://target.com/api/user?id=FILE0 0=sequential_ids.txt

# UUID/Hash Testing
python3 uuid_analyzer.py --url https://target.com --uuid-patterns all
hashcat -m 0 -a 3 object_hashes.txt ?l?l?l?l?l?l?l?l
python3 hash_prediction.py --hashes hashes.txt --algorithm md5,sha1

# API IDOR Testing
python3 api_idor.py --base-url https://api.target.com --endpoints endpoints.json
postman --collection idor_tests.json --environment production
curl -X GET https://api.target.com/v1/users/123 --header "Authorization: Bearer token"

# GraphQL IDOR Testing
python3 graphql_idor.py --url https://target.com/graphql --queries idor_queries.txt
graphql-map -u https://target.com/graphql -s idor_queries.graphql

# Advanced IDOR Testing
python3 race_idor.py --url https://target.com/transfer --threads 20 --user-ids 100-200
python3 timing_idor.py --url https://target.com/profile --id-param user_id --samples 100

# Automated Comprehensive Testing
metasploit auxiliary/scanner/http/idor
idor_detector --target https://target.com --config idor_rules.json
zap.sh -cmd -quickurl https://target.com -quickout idor_report.html
```

### 13 Advanced IDOR Testing Implementation
```python
# Comprehensive Insecure Direct Object References Testing Tool
import requests
import json
import re
import hashlib
import base64
import time
import uuid
from urllib.parse import urljoin, urlparse, parse_qs
import threading
from concurrent.futures import ThreadPoolExecutor
import logging

class IDORTester:
    def __init__(self, target_url, config):
        self.target_url = target_url
        self.config = config
        self.session = requests.Session()
        self.test_results = {
            'sequential_idor': {},
            'non_sequential_idor': {},
            'parameter_manipulation': {},
            'url_path_idor': {},
            'api_idor': {},
            'business_logic_idor': {},
            'mass_assignment_idor': {},
            'advanced_idor': {}
        }
        
        # Configure session
        if config.get('headers'):
            self.session.headers.update(config['headers'])
        
        if config.get('proxies'):
            self.session.proxies.update(config['proxies'])
        
        # Configure logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def comprehensive_idor_testing(self):
        """Perform comprehensive IDOR vulnerability testing"""
        self.logger.info(f"Starting IDOR vulnerability testing for {self.target_url}")
        
        # Execute all testing methods
        self.test_sequential_idor()
        self.test_non_sequential_idor()
        self.test_parameter_manipulation()
        self.test_url_path_idor()
        self.test_api_idor()
        self.test_business_logic_idor()
        self.test_mass_assignment_idor()
        self.test_advanced_idor()
        
        return {
            'test_results': self.test_results,
            'security_assessment': self.perform_security_assessment(),
            'risk_analysis': self.perform_risk_analysis(),
            'remediation_recommendations': self.generate_recommendations()
        }

    def test_sequential_idor(self):
        """Test sequential IDOR vulnerabilities"""
        self.logger.info("Testing sequential IDOR vulnerabilities")
        
        sequential_tests = {
            'user_references': [],
            'document_references': [],
            'order_references': [],
            'resource_references': []
        }
        
        # Test user ID references
        sequential_tests['user_references'] = self.test_sequential_user_references()
        
        # Test document references
        sequential_tests['document_references'] = self.test_sequential_document_references()
        
        # Test order references
        sequential_tests['order_references'] = self.test_sequential_order_references()
        
        self.test_results['sequential_idor'] = sequential_tests

    def test_sequential_user_references(self):
        """Test sequential user ID references"""
        user_id_tests = []
        
        # Common user endpoints
        user_endpoints = [
            '/api/users/',
            '/user/profile/',
            '/account/details/',
            '/profile/view/',
            '/users/'
        ]
        
        for endpoint in user_endpoints:
            base_url = urljoin(self.target_url, endpoint)
            
            # Test sequential user IDs
            for user_id in range(1, 11):  # Test first 10 users
                test_url = f"{base_url}{user_id}"
                
                try:
                    response = self.session.get(test_url, allow_redirects=False)
                    
                    test_result = {
                        'endpoint': endpoint,
                        'user_id': user_id,
                        'test_url': test_url,
                        'status_code': response.status_code,
                        'access_granted': False,
                        'sensitive_data_exposed': False
                    }
                    
                    # Check if access was granted
                    if response.status_code == 200:
                        test_result['access_granted'] = True
                        
                        # Check for sensitive data exposure
                        sensitive_patterns = [
                            r'email', r'password', r'phone', r'address',
                            r'ssn', r'credit.card', r'private', r'confidential',
                            r'salary', r'birth.date', r'medical'
                        ]
                        
                        for pattern in sensitive_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                test_result['sensitive_data_exposed'] = True
                                test_result['severity'] = 'high'
                                self.logger.warning(f"IDOR vulnerability found: {test_url}")
                                break
                    
                    user_id_tests.append(test_result)
                    
                except Exception as e:
                    self.logger.error(f"Error testing user ID {user_id} at {endpoint}: {e}")
        
        return user_id_tests

    def test_sequential_document_references(self):
        """Test sequential document ID references"""
        document_tests = []
        
        # Common document endpoints
        document_endpoints = [
            '/api/documents/',
            '/documents/view/',
            '/files/download/',
            '/attachments/',
            '/reports/'
        ]
        
        for endpoint in document_endpoints:
            base_url = urljoin(self.target_url, endpoint)
            
            # Test sequential document IDs
            for doc_id in range(1, 11):  # Test first 10 documents
                test_url = f"{base_url}{doc_id}"
                
                try:
                    response = self.session.get(test_url, allow_redirects=False)
                    
                    test_result = {
                        'endpoint': endpoint,
                        'document_id': doc_id,
                        'test_url': test_url,
                        'status_code': response.status_code,
                        'access_granted': False,
                        'file_downloaded': False
                    }
                    
                    # Check if access was granted
                    if response.status_code == 200:
                        test_result['access_granted'] = True
                        
                        # Check if file was downloaded
                        content_type = response.headers.get('Content-Type', '')
                        content_length = response.headers.get('Content-Length', '0')
                        
                        if any(ct in content_type.lower() for ct in ['pdf', 'doc', 'xls', 'image', 'octet-stream']):
                            test_result['file_downloaded'] = True
                            test_result['severity'] = 'critical'
                            self.logger.critical(f"Document IDOR vulnerability found: {test_url}")
                        
                        # Check for sensitive content in response
                        if len(response.text) > 1000:  # Likely file content
                            test_result['file_downloaded'] = True
                            test_result['severity'] = 'critical'
                    
                    document_tests.append(test_result)
                    
                except Exception as e:
                    self.logger.error(f"Error testing document ID {doc_id} at {endpoint}: {e}")
        
        return document_tests

    def test_non_sequential_idor(self):
        """Test non-sequential IDOR vulnerabilities"""
        self.logger.info("Testing non-sequential IDOR vulnerabilities")
        
        non_sequential_tests = {
            'uuid_references': [],
            'hash_references': [],
            'encoded_references': [],
            'composite_references': []
        }
        
        # Test UUID references
        non_sequential_tests['uuid_references'] = self.test_uuid_references()
        
        # Test hash references
        non_sequential_tests['hash_references'] = self.test_hash_references()
        
        self.test_results['non_sequential_idor'] = non_sequential_tests

    def test_uuid_references(self):
        """Test UUID-based object references"""
        uuid_tests = []
        
        # Common UUID endpoints
        uuid_endpoints = [
            '/api/files/',
            '/documents/',
            '/resources/',
            '/assets/'
        ]
        
        # Generate test UUIDs
        test_uuids = [
            str(uuid.uuid4()),  # Random UUID
            '00000000-0000-0000-0000-000000000000',  # Null UUID
            '11111111-1111-1111-1111-111111111111',  # Sequential-like
            'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',  # Pattern-based
            'ffffffff-ffff-ffff-ffff-ffffffffffff'   # Max UUID
        ]
        
        for endpoint in uuid_endpoints:
            base_url = urljoin(self.target_url, endpoint)
            
            for test_uuid in test_uuids:
                test_url = f"{base_url}{test_uuid}"
                
                try:
                    response = self.session.get(test_url, allow_redirects=False)
                    
                    test_result = {
                        'endpoint': endpoint,
                        'uuid': test_uuid,
                        'test_url': test_url,
                        'status_code': response.status_code,
                        'access_granted': False
                    }
                    
                    if response.status_code == 200:
                        test_result['access_granted'] = True
                        test_result['severity'] = 'medium'
                        self.logger.warning(f"UUID IDOR vulnerability found: {test_url}")
                    
                    uuid_tests.append(test_result)
                    
                except Exception as e:
                    self.logger.error(f"Error testing UUID {test_uuid} at {endpoint}: {e}")
        
        return uuid_tests

    def test_parameter_manipulation(self):
        """Test parameter-based IDOR vulnerabilities"""
        self.logger.info("Testing parameter-based IDOR vulnerabilities")
        
        param_tests = {
            'query_parameters': [],
            'post_parameters': [],
            'json_payloads': [],
            'hidden_parameters': []
        }
        
        # Test query parameters
        param_tests['query_parameters'] = self.test_query_parameter_idor()
        
        # Test POST parameters
        param_tests['post_parameters'] = self.test_post_parameter_idor()
        
        self.test_results['parameter_manipulation'] = param_tests

    def test_query_parameter_idor(self):
        """Test query parameter IDOR vulnerabilities"""
        query_tests = []
        
        # Common ID parameters
        id_parameters = ['id', 'user_id', 'document_id', 'file_id', 'order_id', 'account_id']
        
        # Test endpoints with ID parameters
        test_endpoints = [
            '/api/user',
            '/document/view',
            '/file/download',
            '/order/details',
            '/account/info'
        ]
        
        for endpoint in test_endpoints:
            url = urljoin(self.target_url, endpoint)
            
            for param in id_parameters:
                # Test with different ID values
                for test_id in [1, 2, 100, 1000]:
                    test_url = f"{url}?{param}={test_id}"
                    
                    try:
                        response = self.session.get(test_url, allow_redirects=False)
                        
                        test_result = {
                            'endpoint': endpoint,
                            'parameter': param,
                            'test_id': test_id,
                            'test_url': test_url,
                            'status_code': response.status_code,
                            'access_granted': False
                        }
                        
                        if response.status_code == 200:
                            test_result['access_granted'] = True
                            
                            # Check if different content is returned
                            original_response = self.session.get(f"{url}?{param}=1")
                            if test_id != 1 and response.text != original_response.text:
                                test_result['different_content'] = True
                                test_result['severity'] = 'high'
                                self.logger.warning(f"Query parameter IDOR found: {test_url}")
                        
                        query_tests.append(test_result)
                        
                    except Exception as e:
                        self.logger.error(f"Error testing query parameter {param} with ID {test_id}: {e}")
        
        return query_tests

    def test_url_path_idor(self):
        """Test URL path-based IDOR vulnerabilities"""
        self.logger.info("Testing URL path-based IDOR vulnerabilities")
        
        path_tests = {
            'restful_paths': [],
            'nested_resources': [],
            'file_paths': [],
            'hierarchical_paths': []
        }
        
        # Test RESTful paths
        path_tests['restful_paths'] = self.test_restful_path_idor()
        
        # Test nested resources
        path_tests['nested_resources'] = self.test_nested_resource_idor()
        
        self.test_results['url_path_idor'] = path_tests

    def test_restful_path_idor(self):
        """Test RESTful URL path IDOR vulnerabilities"""
        restful_tests = []
        
        # Common RESTful resource patterns
        resource_patterns = [
            '/users/{id}',
            '/documents/{id}',
            '/orders/{id}',
            '/products/{id}',
            '/accounts/{id}',
            '/files/{id}',
            '/images/{id}',
            '/videos/{id}'
        ]
        
        for pattern in resource_patterns:
            base_path = pattern.replace('{id}', '')
            base_url = urljoin(self.target_url, base_path)
            
            # Test with different IDs
            for test_id in [1, 2, 100, 1000]:
                test_url = f"{base_url}{test_id}"
                
                try:
                    response = self.session.get(test_url, allow_redirects=False)
                    
                    test_result = {
                        'pattern': pattern,
                        'test_id': test_id,
                        'test_url': test_url,
                        'status_code': response.status_code,
                        'access_granted': False
                    }
                    
                    if response.status_code == 200:
                        test_result['access_granted'] = True
                        test_result['severity'] = 'high'
                        self.logger.warning(f"RESTful path IDOR found: {test_url}")
                    
                    restful_tests.append(test_result)
                    
                except Exception as e:
                    self.logger.error(f"Error testing RESTful path {pattern} with ID {test_id}: {e}")
        
        return restful_tests

    def test_api_idor(self):
        """Test API-based IDOR vulnerabilities"""
        self.logger.info("Testing API-based IDOR vulnerabilities")
        
        api_tests = {
            'rest_api': [],
            'graphql': [],
            'bulk_operations': [],
            'batch_requests': []
        }
        
        # Test REST API endpoints
        api_tests['rest_api'] = self.test_rest_api_idor()
        
        # Test bulk operations
        api_tests['bulk_operations'] = self.test_bulk_operation_idor()
        
        self.test_results['api_idor'] = api_tests

    def test_rest_api_idor(self):
        """Test REST API IDOR vulnerabilities"""
        rest_api_tests = []
        
        # Common REST API endpoints
        api_endpoints = [
            '/api/v1/users/',
            '/api/v1/documents/',
            '/api/v1/orders/',
            '/api/v1/accounts/',
            '/api/v2/users/',
            '/api/v2/resources/'
        ]
        
        for endpoint in api_endpoints:
            base_url = urljoin(self.target_url, endpoint)
            
            # Test different HTTP methods with ID manipulation
            test_ids = [1, 2, 100]
            
            for test_id in test_ids:
                test_url = f"{base_url}{test_id}"
                
                # Test GET
                try:
                    get_response = self.session.get(test_url, allow_redirects=False)
                    
                    get_test = {
                        'endpoint': endpoint,
                        'method': 'GET',
                        'test_id': test_id,
                        'test_url': test_url,
                        'status_code': get_response.status_code,
                        'access_granted': False
                    }
                    
                    if get_response.status_code == 200:
                        get_test['access_granted'] = True
                        get_test['severity'] = 'high'
                    
                    rest_api_tests.append(get_test)
                    
                except Exception as e:
                    self.logger.error(f"Error testing GET {test_url}: {e}")
                
                # Test PUT/PATCH if GET was successful
                if get_response.status_code == 200:
                    update_data = {'name': 'test', 'description': 'IDOR test'}
                    
                    try:
                        put_response = self.session.put(test_url, json=update_data, allow_redirects=False)
                        
                        put_test = {
                            'endpoint': endpoint,
                            'method': 'PUT',
                            'test_id': test_id,
                            'test_url': test_url,
                            'status_code': put_response.status_code,
                            'access_granted': False
                        }
                        
                        if put_response.status_code in [200, 204]:
                            put_test['access_granted'] = True
                            put_test['severity'] = 'critical'
                            self.logger.critical(f"REST API IDOR (PUT) found: {test_url}")
                        
                        rest_api_tests.append(put_test)
                        
                    except Exception as e:
                        self.logger.error(f"Error testing PUT {test_url}: {e}")
        
        return rest_api_tests

    def test_business_logic_idor(self):
        """Test business logic IDOR vulnerabilities"""
        self.logger.info("Testing business logic IDOR vulnerabilities")
        
        business_tests = {
            'workflow_references': [],
            'state_references': [],
            'approval_references': [],
            'transaction_references': []
        }
        
        # Test workflow references
        business_tests['workflow_references'] = self.test_workflow_idor()
        
        # Test state references
        business_tests['state_references'] = self.test_state_based_idor()
        
        self.test_results['business_logic_idor'] = business_tests

    def test_workflow_idor(self):
        """Test workflow-based IDOR vulnerabilities"""
        workflow_tests = []
        
        # Common workflow endpoints
        workflow_endpoints = [
            '/workflow/approve/',
            '/process/complete/',
            '/order/ship/',
            '/document/review/',
            '/task/complete/'
        ]
        
        for endpoint in workflow_endpoints:
            base_url = urljoin(self.target_url, endpoint)
            
            # Test with different workflow instance IDs
            for instance_id in [1, 2, 100]:
                test_url = f"{base_url}{instance_id}"
                
                try:
                    # Test POST to workflow action
                    response = self.session.post(test_url, data={'action': 'approve'}, allow_redirects=False)
                    
                    test_result = {
                        'endpoint': endpoint,
                        'instance_id': instance_id,
                        'test_url': test_url,
                        'status_code': response.status_code,
                        'action_performed': False
                    }
                    
                    if response.status_code in [200, 302]:
                        test_result['action_performed'] = True
                        test_result['severity'] = 'critical'
                        self.logger.critical(f"Workflow IDOR found: {test_url}")
                    
                    workflow_tests.append(test_result)
                    
                except Exception as e:
                    self.logger.error(f"Error testing workflow {endpoint} with ID {instance_id}: {e}")
        
        return workflow_tests

    def test_advanced_idor(self):
        """Test advanced IDOR techniques"""
        self.logger.info("Testing advanced IDOR techniques")
        
        advanced_tests = {
            'timing_attacks': [],
            'race_conditions': [],
            'mass_assignment': [],
            'indirect_references': []
        }
        
        # Test timing attacks
        advanced_tests['timing_attacks'] = self.test_timing_idor()
        
        # Test race conditions
        advanced_tests['race_conditions'] = self.test_race_condition_idor()
        
        self.test_results['advanced_idor'] = advanced_tests

    def test_timing_idor(self):
        """Test timing-based IDOR detection"""
        timing_tests = []
        
        # Endpoints to test with timing analysis
        timing_endpoints = [
            '/api/users/',
            '/documents/',
            '/files/'
        ]
        
        for endpoint in timing_endpoints:
            base_url = urljoin(self.target_url, endpoint)
            
            # Test valid and invalid IDs for timing differences
            test_ids = [1, 999999]  # Likely valid and invalid
            
            timing_results = {}
            
            for test_id in test_ids:
                test_url = f"{base_url}{test_id}"
                
                try:
                    # Measure response time
                    times = []
                    for _ in range(5):  # Multiple samples
                        start_time = time.time()
                        response = self.session.get(test_url, allow_redirects=False)
                        end_time = time.time()
                        times.append(end_time - start_time)
                    
                    avg_time = sum(times) / len(times)
                    
                    timing_results[test_id] = {
                        'average_time': avg_time,
                        'status_code': response.status_code,
                        'response_length': len(response.text)
                    }
                    
                except Exception as e:
                    self.logger.error(f"Error in timing test for {test_url}: {e}")
            
            # Analyze timing differences
            if len(timing_results) == 2:
                valid_time = timing_results[1]['average_time']
                invalid_time = timing_results[999999]['average_time']
                
                timing_diff = abs(valid_time - invalid_time)
                
                test_result = {
                    'endpoint': endpoint,
                    'timing_difference': timing_diff,
                    'potential_idor': timing_diff > 0.1,  # 100ms threshold
                    'valid_id_time': valid_time,
                    'invalid_id_time': invalid_time
                }
                
                if test_result['potential_idor']:
                    test_result['severity'] = 'medium'
                    self.logger.warning(f"Timing-based IDOR indicator found: {endpoint}")
                
                timing_tests.append(test_result)
        
        return timing_tests

    def perform_security_assessment(self):
        """Perform comprehensive security assessment"""
        self.logger.info("Performing security assessment")
        
        assessment = {
            'overall_risk_level': self.calculate_idor_risk(),
            'sequential_idor_risk': self.calculate_sequential_risk(),
            'api_idor_risk': self.calculate_api_risk(),
            'business_logic_risk': self.calculate_business_logic_risk(),
            'data_exposure_level': self.calculate_data_exposure()
        }
        
        return assessment

    def calculate_idor_risk(self):
        """Calculate overall risk level for IDOR vulnerabilities"""
        risk_indicators = []
        
        # Check all test categories for security issues
        for category, findings in self.test_results.items():
            if isinstance(findings, dict):
                for subcategory, subfindings in findings.items():
                    if isinstance(subfindings, list):
                        for finding in subfindings:
                            if isinstance(finding, dict):
                                if (finding.get('access_granted', False) or 
                                    finding.get('sensitive_data_exposed', False) or 
                                    finding.get('file_downloaded', False) or
                                    finding.get('action_performed', False)):
                                    severity = finding.get('severity', 'medium')
                                    risk_indicators.append(severity)
        
        if not risk_indicators:
            return 'low'
        
        if 'critical' in risk_indicators:
            return 'critical'
        elif 'high' in risk_indicators:
            return 'high'
        elif 'medium' in risk_indicators:
            return 'medium'
        else:
            return 'low'

    def perform_risk_analysis(self):
        """Perform comprehensive risk analysis"""
        risk_analysis = {
            'critical_risks': [],
            'high_risks': [],
            'medium_risks': [],
            'low_risks': []
        }
        
        # Aggregate findings from all test categories
        all_findings = []
        
        for category, findings in self.test_results.items():
            if isinstance(findings, dict):
                for subcategory, subfindings in findings.items():
                    if isinstance(subfindings, list):
                        for finding in subfindings:
                            if isinstance(finding, dict):
                                finding['category'] = f"{category}.{subcategory}"
                                all_findings.append(finding)
        
        # Categorize risks
        for finding in all_findings:
            if (finding.get('access_granted', False) or 
                finding.get('sensitive_data_exposed', False) or 
                finding.get('file_downloaded', False) or
                finding.get('action_performed', False)):
                
                risk_level = finding.get('severity', 'medium')
                
                risk_entry = {
                    'category': finding.get('category', 'Unknown'),
                    'description': self.get_idor_finding_description(finding),
                    'impact': self.get_idor_impact(finding),
                    'remediation': self.get_idor_remediation(finding)
                }
                
                risk_analysis[f"{risk_level}_risks"].append(risk_entry)
        
        return risk_analysis

    def generate_recommendations(self):
        """Generate comprehensive security recommendations"""
        recommendations = {
            'immediate_actions': [],
            'short_term_improvements': [],
            'long_term_strategies': []
        }
        
        # Immediate actions for critical risks
        risk_analysis = self.perform_risk_analysis()
        for risk in risk_analysis['critical_risks']:
            recommendations['immediate_actions'].append({
                'action': f"Fix {risk['category']} vulnerability",
                'description': risk['description'],
                'remediation': risk['remediation']
            })
        
        # Short-term improvements
        recommendations['short_term_improvements'].extend([
            "Implement proper access control checks for all object references",
            "Use indirect reference maps instead of direct object references",
            "Add proper authorization checks for all API endpoints",
            "Implement input validation for all ID parameters",
            "Add comprehensive logging for object access attempts"
        ])
        
        # Long-term strategies
        recommendations['long_term_strategies'].extend([
            "Implement attribute-based access control (ABAC) system",
            "Deploy comprehensive IDOR monitoring and detection",
            "Establish regular security testing for object references",
            "Implement zero-trust architecture for data access",
            "Develop comprehensive security training for IDOR prevention"
        ])
        
        return recommendations

# Advanced IDOR Monitoring System
class IDORMonitor:
    def __init__(self, target_systems, monitoring_interval=3600):
        self.target_systems = target_systems
        self.monitoring_interval = monitoring_interval
        self.idor_baseline = {}

    def setup_continuous_monitoring(self):
        """Set up continuous IDOR vulnerability monitoring"""
        self.logger.info("Setting up IDOR vulnerability monitoring")
        
        # Establish baseline
        for system in self.target_systems:
            tester = IDORTester(system['url'], system['config'])
            baseline = tester.comprehensive_idor_testing()
            self.idor_baseline[system['name']] = baseline
        
        self.start_monitoring_loop()

    def detect_idor_changes(self):
        """Detect changes in IDOR vulnerabilities"""
        changes_detected = {}
        
        for system_name, baseline in self.idor_baseline.items():
            system_config = next((s for s in self.target_systems if s['name'] == system_name), None)
            if system_config:
                current_tester = IDORTester(system_config['url'], system_config['config'])
                current_results = current_tester.comprehensive_idor_testing()
                
                changes = self.compare_idor_results(baseline, current_results)
                
                if changes:
                    changes_detected[system_name] = {
                        'changes': changes,
                        'security_impact': self.assess_change_impact(changes),
                        'timestamp': time.time()
                    }
                
                self.idor_baseline[system_name] = current_results
        
        return changes_detected
```

### 14 IDOR Risk Assessment Matrix
```yaml
IDOR Risk Assessment:
  Critical Risks:
    - Direct access to other users' sensitive data (PII, financial, medical)
    - Ability to modify/delete other users' data or resources
    - Access to administrative functions through ID manipulation
    - File download IDOR exposing confidential documents
    - Mass assignment IDOR affecting multiple records
    - Business logic IDOR allowing unauthorized actions
    - API IDOR with write operations (PUT, POST, DELETE)
    - No access control checks on object references

  High Risks:
    - Read-only access to other users' non-sensitive data
    - Access to limited administrative functions
    - IDOR in less critical business workflows
    - Partial data exposure through IDOR
    - API IDOR with read operations (GET)
    - Indirect object reference vulnerabilities
    - Limited mass assignment IDOR
    - Information disclosure aiding other attacks

  Medium Risks:
    - IDOR with complex exploitation requirements
    - Limited data exposure with low sensitivity
    - Theoretical IDOR with unproven impact
    - IDOR in deprecated or legacy endpoints
    - Partial access control implementation
    - Basic input validation missing
    - Limited logging and monitoring
    - Minor information disclosure

  Low Risks:
    - IDOR with negligible business impact
    - Access to public or non-sensitive data
    - Theoretical vulnerabilities with high complexity
    - UI-based IDOR with no data exposure
    - Documentation exposure
    - Version information disclosure
    - Low-impact configuration issues
    - Non-sensitive data exposure
```

### 15 IDOR Protection Testing
```python
# IDOR Protection Effectiveness Tester
class IDORProtectionTester:
    def __init__(self, target_environments):
        self.target_environments = target_environments

    def test_protection_effectiveness(self):
        """Test IDOR protection effectiveness"""
        protection_tests = {}
        
        for env in self.target_environments:
            tester = IDORTester(env['url'], env['config'])
            results = tester.comprehensive_idor_testing()
            
            protection_tests[env['name']] = {
                'sequential_protection': self.test_sequential_protection(results),
                'api_protection': self.test_api_protection(results),
                'business_logic_protection': self.test_business_logic_protection(results),
                'access_control_effectiveness': self.test_access_control_effectiveness(results),
                'overall_protection_score': self.calculate_protection_score(results)
            }
        
        return protection_tests

    def generate_protection_report(self):
        """Generate comprehensive protection report"""
        protection_tests = self.test_protection_effectiveness()
        
        report = {
            'protection_analysis': protection_tests,
            'security_gaps': self.identify_protection_gaps(protection_tests),
            'compliance_status': self.assess_idor_compliance(),
            'improvement_recommendations': self.generate_protection_recommendations()
        }
        
        return report
```

### 16 IDOR Remediation Checklist
```markdown
## ✅ INSECURE DIRECT OBJECT REFERENCES REMEDIATION CHECKLIST

### Access Control Implementation:
- [ ] Implement proper server-side access control checks for all object references
- [ ] Use principle of least privilege for object access
- [ ] Implement proper authorization checks before object access
- [ ] Add comprehensive access control lists (ACLs)
- [ ] Implement proper error handling for unauthorized access attempts
- [ ] Add proper logging and monitoring for object access
- [ ] Regular access control reviews and audits
- [ ] Implement automated access control testing

### Indirect Reference Maps:
- [ ] Use indirect reference maps instead of direct object references
- [ ] Implement secure mapping between indirect and direct references
- [ ] Add proper validation for indirect references
- [ ] Use cryptographically strong indirect references
- [ ] Implement proper expiration for temporary references
- [ ] Add proper revocation mechanisms for indirect references
- [ ] Regular security testing for indirect reference implementation
- [ ] Monitor for indirect reference manipulation attempts

### Input Validation:
- [ ] Implement comprehensive input validation for all ID parameters
- [ ] Add proper type and range validation for object references
- [ ] Use allow lists for valid object reference patterns
- [ ] Implement proper encoding/decoding validation
- [ ] Add proper sanitization for object reference inputs
- [ ] Implement business logic validation for object access
- [ ] Regular security testing for input validation
- [ ] Monitor for input validation bypass attempts

### API Security:
- [ ] Implement proper API authentication and authorization
- [ ] Add comprehensive input validation for API endpoints
- [ ] Implement rate limiting for API object access
- [ ] Add proper error handling without information disclosure
- [ ] Implement API versioning with security updates
- [ ] Add comprehensive API monitoring
- [ ] Regular security testing for API endpoints
- [ ] Monitor for API-based IDOR attempts

### Business Logic Protection:
- [ ] Implement proper business logic validation
- [ ] Add workflow state validation for object access
- [ ] Implement proper order of operations validation
- [ ] Add transaction integrity checks
- [ ] Implement proper state machine validation
- [ ] Add race condition protection
- [ ] Regular security testing for business logic
- [ ] Monitor for business logic bypass attempts

### Session Management:
- [ ] Implement proper session binding to user context
- [ ] Add session validation for object access requests
- [ ] Implement proper session expiration
- [ ] Add concurrent session control
- [ ] Implement session invalidation on privilege changes
- [ ] Use secure cookie attributes (HttpOnly, Secure, SameSite)
- [ ] Regular security testing for session management
- [ ] Monitor for session manipulation attempts

### Data Protection:
- [ ] Implement proper data classification and sensitivity labeling
- [ ] Add data encryption for sensitive object storage
- [ ] Implement proper data access logging
- [ ] Add data loss prevention (DLP) controls
- [ ] Implement proper data backup and recovery security
- [ ] Add data retention and disposal policies
- [ ] Regular security testing for data protection
- [ ] Monitor for data exposure attempts

### Monitoring & Detection:
- [ ] Implement real-time object access monitoring
- [ ] Add anomalous access pattern detection
- [ ] Implement IDOR attempt detection and alerting
- [ ] Add comprehensive audit logging
- [ ] Implement user behavior analytics
- [ ] Add automated response to IDOR attempts
- [ ] Regular security log reviews
- [ ] Continuous security monitoring
```

### 17 IDOR Testing Completion Checklist
```markdown
## ✅ INSECURE DIRECT OBJECT REFERENCES TESTING COMPLETION CHECKLIST

### Detection & Enumeration Testing:
- [ ] Direct object reference identification completed
- [ ] Parameter naming pattern analysis done
- [ ] Object ID format recognition testing completed
- [ ] Sequential vs non-sequential ID testing done
- [ ] UUID/GUID pattern analysis completed
- [ ] Hash-based reference testing done
- [ ] Encoded reference analysis completed
- [ ] Composite key identification testing done

### Object Reference Manipulation Testing:
- [ ] Sequential ID enumeration testing completed
- [ ] Decremental ID testing done
- [ ] Pattern-based ID prediction testing completed
- [ ] Timestamp-based ID analysis done
- [ ] User-specific ID range testing completed
- [ ] UUID manipulation attempts done
- [ ] Hash cracking and prediction testing completed
- [ ] Base64 encoded ID manipulation testing done

### Parameter-Based Testing:
- [ ] Query parameter ID manipulation testing completed
- [ ] Resource parameter manipulation done
- [ ] Reference parameter modification testing completed
- [ ] Filter parameter exploitation testing done
- [ ] JSON payload ID modification testing completed
- [ ] XML entity reference manipulation done
- [ ] Hidden field reference modification testing completed
- [ ] Array parameter manipulation testing done

### URL Path Testing:
- [ ] RESTful URL path manipulation testing completed
- [ ] Path segment ID modification testing done
- [ ] Resource hierarchy traversal testing completed
- [ ] Nested resource access testing done
- [ ] File path reference testing completed
- [ ] Document reference manipulation testing done
- [ ] Download reference tampering testing completed
- [ ] Backup file reference testing done

### API-Based Testing:
- [ ] REST API endpoint IDOR testing completed
- [ ] Resource ID manipulation testing done
- [ ] Bulk operation ID testing completed
- [ ] Batch request ID manipulation testing done
- [ ] GraphQL node ID manipulation testing completed
- [ ] Global ID prediction attempts done
- [ ] Field-level IDOR testing completed
- [ ] Mutation input ID manipulation testing done

### Business Logic Testing:
- [ ] Workflow reference IDOR testing completed
- [ ] State reference manipulation testing done
- [ ] Approval reference testing completed
- [ ] Multi-step process ID testing done
- [ ] Order process IDOR testing completed
- [ ] Financial transaction ID manipulation testing done
- [ ] Healthcare record reference testing completed
- [ ] E-commerce order ID tampering testing done

### Advanced Technique Testing:
- [ ] Timing attack IDOR testing completed
- [ ] Response time analysis done
- [ ] Race condition IDOR testing completed
- [ ] Simultaneous access attempts testing done
- [ ] Mass assignment IDOR testing completed
- [ ] Batch request manipulation testing done
- [ ] Indirect reference testing completed
- [ ] Reference mapping exploitation testing done
```

### 18 IDOR Executive Reporting Template
```markdown
# Insecure Direct Object References Security Assessment Report

## Executive Summary
- **Assessment Scope:** [Object reference systems and endpoints tested]
- **Assessment Period:** [Date range]
- **Testing Techniques Applied:** [Number and types of IDOR tests]
- **Critical Vulnerabilities:** [Critical findings count]
- **Overall Risk Level:** [High/Medium/Low]
- **Key Recommendations:** [Priority actions]

## Critical Findings
### [Critical Finding Title]
- **Vulnerability Type:** [Sequential IDOR, API IDOR, Business Logic IDOR, etc.]
- **Risk Level:** Critical
- **Description:** [Detailed vulnerability description]
- **Impact:** [Potential security impact analysis]
- **Remediation Priority:** Immediate

## Technical Analysis
### IDOR Vulnerability Posture
- **Sequential IDOR Vulnerabilities:** [Count and risk summary]
- **API IDOR Issues:** [Vulnerability count and severity]
- **Business Logic IDOR Gaps:** [Bypass count and impact]
- **Data Exposure Risks:** [Exposure count and severity]

### Security Control Assessment
- **Access Control Effectiveness:** [Control coverage percentage]
- **Input Validation Quality:** [Validation effectiveness evaluation]
- **API Security Strength:** [API security rating]
- **Monitoring Capability:** [Detection effectiveness assessment]

## Risk Assessment
### Critical Priority Risks
1. **[Risk Title]**
   - **Description:** [Detailed risk explanation]
   - **Impact:** [Business impact analysis]
   - **Likelihood:** [Probability assessment]
   - **Remediation:** [Specific mitigation steps]

### High Priority Risks
1. **[Risk Title]**
   - **Description:** [Detailed risk explanation]
   - **Impact:** [Business impact analysis]
   - **Likelihood:** [Probability assessment]
   - **Remediation:** [Specific mitigation steps]

## Recommendations
### Immediate Actions (1-7 days)
- [ ] [Patch critical sequential IDOR vulnerabilities]
- [ ] [Fix API endpoints with missing access controls]
- [ ] [Implement server-side authorization checks]

### Short-term Improvements (1-4 weeks)
- [ ] [Implement indirect reference mapping]
- [ ] [Enhance input validation for object references]
- [ ] [Add comprehensive IDOR monitoring]

### Long-term Strategies (1-6 months)
- [ ] [Implement attribute-based access control (ABAC)]
- [ ] [Deploy advanced IDOR detection systems]
- [ ] [Establish comprehensive object reference security framework]

## Compliance Status
- **Regulatory Compliance:** [NIST, PCI DSS, HIPAA, GDPR, etc. compliance level]
- **Industry Standards:** [Security standards alignment]
- **Internal Policies:** [Policy compliance evaluation]
- **Audit Readiness:** [Audit preparedness assessment]

## Security Maturity Assessment
- **IDOR Security Maturity:** [Maturity level rating]
- **Access Control Effectiveness:** [Control effectiveness score]
- **Input Validation Quality:** [Validation quality rating]
- **Overall IDOR Protection:** [Comprehensive security assessment]

## Appendices
### Detailed Vulnerability Analysis
- Vulnerability descriptions and proof-of-concept
- Technical details and exploitation methods
- Risk classification and impact analysis
- Remediation guidance and references

### Testing Methodology
- Tools and techniques used
- Scope and limitations
- Testing environment details
- Quality assurance measures

### Risk Classification Matrix
- Risk scoring methodology
- Impact assessment criteria
- Likelihood evaluation framework
- Remediation priority guidelines
```

This comprehensive Insecure Direct Object References Testing checklist provides complete methodology for identifying, assessing, and mitigating IDOR vulnerabilities across web applications, APIs, and enterprise systems. The framework covers sequential and non-sequential reference testing, parameter manipulation, URL path exploitation, API-based IDOR, business logic vulnerabilities, mass assignment issues, and advanced techniques to prevent unauthorized data access, privilege escalation, and information disclosure through robust object reference security implementation and continuous security testing.