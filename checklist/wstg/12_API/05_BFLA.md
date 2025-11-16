# API | Broken Function Level Authorization

## 1.0 Comprehensive API Broken Function Level Authorization Testing

### 1.1 Understanding BFLAC (Broken Function Level Authorization Control)

```yaml
API BFLAC Attack Vectors:
  Horizontal Privilege Escalation:
    - User A accessing User B's resources
    - Same role unauthorized data access
    - IDOR (Insecure Direct Object Reference)
    - Parameter manipulation attacks
    
  Vertical Privilege Escalation:
    - Regular user accessing admin functions
    - Privileged function exposure
    - Role-based access control bypass
    - Administrative endpoint access
    
  Function-Level Authorization Bypass:
    - Direct API endpoint access
    - HTTP method manipulation
    - Parameter tampering
    - API version manipulation
```

### 1.2 API BFLAC Testing Methodology

```python
# API Broken Function Level Authorization Testing Framework
import requests
import json
import re
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional
import concurrent.futures

class APIBFLACTester:
    def __init__(self, target_url, user_credentials):
        self.target_url = target_url
        self.user_credentials = user_credentials  # Dict with different role credentials
        self.vulnerabilities = []
        self.sessions = {}
        
    def authenticate_users(self):
        """Authenticate all provided user credentials"""
        print("Authenticating users with different roles...")
        
        for role, creds in self.user_credentials.items():
            try:
                session = requests.Session()
                
                # Handle different authentication methods
                if 'token' in creds:
                    session.headers.update({'Authorization': f'Bearer {creds["token"]}'})
                elif 'api_key' in creds:
                    session.headers.update({'X-API-Key': creds['api_key']})
                elif 'username' in creds and 'password' in creds:
                    login_endpoint = creds.get('login_endpoint', '/api/auth/login')
                    response = session.post(
                        f"{self.target_url}{login_endpoint}",
                        json={'username': creds['username'], 'password': creds['password']}
                    )
                    
                    if response.status_code == 200:
                        # Extract token from response
                        token = response.json().get('token')
                        if token:
                            session.headers.update({'Authorization': f'Bearer {token}'})
                
                self.sessions[role] = session
                print(f"Authenticated as {role}")
                
            except Exception as e:
                print(f"Failed to authenticate {role}: {e}")
    
    def test_horizontal_privilege_escalation(self, endpoints_with_ids):
        """Test horizontal privilege escalation (same role, different users)"""
        print("Testing horizontal privilege escalation...")
        
        vulnerabilities = []
        
        for endpoint_template, test_cases in endpoints_with_ids.items():
            for test_case in test_cases:
                user_a = test_case['user_a']
                user_b_resource = test_case['user_b_resource']
                expected_status = test_case.get('expected_status', 403)
                
                if user_a in self.sessions:
                    # Replace placeholder with actual resource ID
                    endpoint = endpoint_template.replace('{id}', user_b_resource)
                    
                    # Test various HTTP methods
                    methods_to_test = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
                    
                    for method in methods_to_test:
                        try:
                            if method == 'GET':
                                response = self.sessions[user_a].get(f"{self.target_url}{endpoint}")
                            elif method == 'POST':
                                response = self.sessions[user_a].post(f"{self.target_url}{endpoint}")
                            elif method == 'PUT':
                                response = self.sessions[user_a].put(f"{self.target_url}{endpoint}")
                            elif method == 'PATCH':
                                response = self.sessions[user_a].patch(f"{self.target_url}{endpoint}")
                            elif method == 'DELETE':
                                response = self.sessions[user_a].delete(f"{self.target_url}{endpoint}")
                            
                            if response.status_code != expected_status:
                                vulnerabilities.append({
                                    'type': 'Horizontal Privilege Escalation',
                                    'endpoint': endpoint,
                                    'method': method,
                                    'attacker_role': user_a,
                                    'target_resource': user_b_resource,
                                    'expected_status': expected_status,
                                    'actual_status': response.status_code,
                                    'severity': 'High',
                                    'description': f'User {user_a} accessed {user_b_resource}\'s resource via {method}'
                                })
                                
                        except Exception as e:
                            print(f"Error testing {method} on {endpoint}: {e}")
        
        return vulnerabilities
    
    def test_vertical_privilege_escalation(self, admin_endpoints):
        """Test vertical privilege escalation (lower role accessing higher role functions)"""
        print("Testing vertical privilege escalation...")
        
        vulnerabilities = []
        
        # Test each non-admin role against admin endpoints
        non_admin_roles = [role for role in self.sessions.keys() if role != 'admin']
        
        for role in non_admin_roles:
            for endpoint_info in admin_endpoints:
                endpoint = endpoint_info['endpoint']
                method = endpoint_info.get('method', 'GET')
                expected_status = endpoint_info.get('expected_status', 403)
                
                try:
                    if method == 'GET':
                        response = self.sessions[role].get(f"{self.target_url}{endpoint}")
                    elif method == 'POST':
                        response = self.sessions[role].post(f"{self.target_url}{endpoint}")
                    elif method == 'PUT':
                        response = self.sessions[role].put(f"{self.target_url}{endpoint}")
                    elif method == 'PATCH':
                        response = self.sessions[role].patch(f"{self.target_url}{endpoint}")
                    elif method == 'DELETE':
                        response = self.sessions[role].delete(f"{self.target_url}{endpoint}")
                    
                    if response.status_code != expected_status:
                        vulnerabilities.append({
                            'type': 'Vertical Privilege Escalation',
                            'endpoint': endpoint,
                            'method': method,
                            'attacker_role': role,
                            'expected_status': expected_status,
                            'actual_status': response.status_code,
                            'severity': 'Critical',
                            'description': f'Role {role} accessed admin endpoint {endpoint}'
                        })
                        
                except Exception as e:
                    print(f"Error testing {method} on {endpoint} as {role}: {e}")
        
        return vulnerabilities
    
    def test_idor_vulnerabilities(self, endpoints_with_patterns):
        """Test Insecure Direct Object Reference vulnerabilities"""
        print("Testing IDOR vulnerabilities...")
        
        vulnerabilities = []
        
        for endpoint_pattern, test_config in endpoints_with_patterns.items():
            test_role = test_config['test_role']
            id_patterns = test_config['id_patterns']
            
            if test_role in self.sessions:
                for id_pattern in id_patterns:
                    # Test sequential IDs
                    if id_pattern['type'] == 'sequential':
                        for i in range(id_pattern['start'], id_pattern['start'] + id_pattern['count']):
                            endpoint = endpoint_pattern.replace('{id}', str(i))
                            
                            try:
                                response = self.sessions[test_role].get(f"{self.target_url}{endpoint}")
                                
                                if response.status_code == 200:
                                    # Check if we accessed unauthorized data
                                    content = response.text
                                    if self.detect_sensitive_data(content):
                                        vulnerabilities.append({
                                            'type': 'IDOR - Sequential ID',
                                            'endpoint': endpoint,
                                            'test_role': test_role,
                                            'accessed_id': i,
                                            'severity': 'High',
                                            'description': f'Accessed resource with sequential ID {i}'
                                        })
                                        
                            except Exception as e:
                                print(f"Error testing ID {i} on {endpoint}: {e}")
                    
                    # Test UUID patterns
                    elif id_pattern['type'] == 'uuid':
                        # Test with predictable UUIDs or UUIDs from other sources
                        test_uuids = id_pattern['test_uuids']
                        for uuid in test_uuids:
                            endpoint = endpoint_pattern.replace('{id}', uuid)
                            
                            try:
                                response = self.sessions[test_role].get(f"{self.target_url}{endpoint}")
                                
                                if response.status_code == 200:
                                    vulnerabilities.append({
                                        'type': 'IDOR - UUID',
                                        'endpoint': endpoint,
                                        'test_role': test_role,
                                        'accessed_uuid': uuid,
                                        'severity': 'High',
                                        'description': f'Accessed resource with UUID {uuid}'
                                    })
                                    
                            except Exception as e:
                                print(f"Error testing UUID {uuid} on {endpoint}: {e}")
        
        return vulnerabilities
    
    def test_parameter_tampering(self, endpoints_with_parameters):
        """Test parameter tampering for authorization bypass"""
        print("Testing parameter tampering...")
        
        vulnerabilities = []
        
        for endpoint_info in endpoints_with_parameters:
            endpoint = endpoint_info['endpoint']
            method = endpoint_info.get('method', 'GET')
            test_role = endpoint_info['test_role']
            parameters = endpoint_info['parameters']
            
            if test_role in self.sessions:
                for param_test in parameters:
                    param_name = param_test['name']
                    tampered_values = param_test['tampered_values']
                    
                    for tampered_value in tampered_values:
                        # Prepare request with tampered parameter
                        if method == 'GET':
                            params = {param_name: tampered_value}
                            response = self.sessions[test_role].get(
                                f"{self.target_url}{endpoint}", 
                                params=params
                            )
                        else:
                            data = {param_name: tampered_value}
                            if method == 'POST':
                                response = self.sessions[test_role].post(
                                    f"{self.target_url}{endpoint}", 
                                    json=data
                                )
                            elif method == 'PUT':
                                response = self.sessions[test_role].put(
                                    f"{self.target_url}{endpoint}", 
                                    json=data
                                )
                        
                        if response.status_code == 200:
                            vulnerabilities.append({
                                'type': 'Parameter Tampering',
                                'endpoint': endpoint,
                                'method': method,
                                'parameter': param_name,
                                'tampered_value': tampered_value,
                                'test_role': test_role,
                                'severity': 'High',
                                'description': f'Bypassed authorization by tampering {param_name} with {tampered_value}'
                            })
        
        return vulnerabilities
    
    def test_http_method_manipulation(self, endpoints):
        """Test HTTP method manipulation for authorization bypass"""
        print("Testing HTTP method manipulation...")
        
        vulnerabilities = []
        
        for endpoint_info in endpoints:
            endpoint = endpoint_info['endpoint']
            allowed_methods = endpoint_info['allowed_methods']
            test_role = endpoint_info['test_role']
            
            if test_role in self.sessions:
                # Test all HTTP methods, even those not in allowed_methods
                all_methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
                
                for method in all_methods:
                    if method not in allowed_methods:
                        try:
                            if method == 'GET':
                                response = self.sessions[test_role].get(f"{self.target_url}{endpoint}")
                            elif method == 'POST':
                                response = self.sessions[test_role].post(f"{self.target_url}{endpoint}")
                            elif method == 'PUT':
                                response = self.sessions[test_role].put(f"{self.target_url}{endpoint}")
                            elif method == 'PATCH':
                                response = self.sessions[test_role].patch(f"{self.target_url}{endpoint}")
                            elif method == 'DELETE':
                                response = self.sessions[test_role].delete(f"{self.target_url}{endpoint}")
                            elif method == 'HEAD':
                                response = self.sessions[test_role].head(f"{self.target_url}{endpoint}")
                            elif method == 'OPTIONS':
                                response = self.sessions[test_role].options(f"{self.target_url}{endpoint}")
                            
                            if response.status_code not in [405, 403]:  # Not Method Not Allowed or Forbidden
                                vulnerabilities.append({
                                    'type': 'HTTP Method Manipulation',
                                    'endpoint': endpoint,
                                    'method': method,
                                    'test_role': test_role,
                                    'response_status': response.status_code,
                                    'severity': 'Medium',
                                    'description': f'Accessed endpoint with disallowed method {method}'
                                })
                                
                        except Exception as e:
                            print(f"Error testing {method} on {endpoint}: {e}")
        
        return vulnerabilities
    
    def test_mass_assignment(self, endpoints_with_objects):
        """Test mass assignment vulnerabilities"""
        print("Testing mass assignment vulnerabilities...")
        
        vulnerabilities = []
        
        for endpoint_info in endpoints_with_objects:
            endpoint = endpoint_info['endpoint']
            method = endpoint_info.get('method', 'POST')
            test_role = endpoint_info['test_role']
            base_object = endpoint_info['base_object']
            privileged_fields = endpoint_info['privileged_fields']
            
            if test_role in self.sessions:
                # Create object with privileged fields
                malicious_object = base_object.copy()
                for field in privileged_fields:
                    malicious_object[field] = 'malicious_value'
                
                try:
                    if method == 'POST':
                        response = self.sessions[test_role].post(
                            f"{self.target_url}{endpoint}", 
                            json=malicious_object
                        )
                    elif method == 'PUT':
                        response = self.sessions[test_role].put(
                            f"{self.target_url}{endpoint}", 
                            json=malicious_object
                        )
                    elif method == 'PATCH':
                        response = self.sessions[test_role].patch(
                            f"{self.target_url}{endpoint}", 
                            json=malicious_object
                        )
                    
                    if response.status_code == 200:
                        # Check if privileged fields were accepted
                        response_data = response.json()
                        for field in privileged_fields:
                            if field in response_data and response_data[field] == 'malicious_value':
                                vulnerabilities.append({
                                    'type': 'Mass Assignment',
                                    'endpoint': endpoint,
                                    'method': method,
                                    'test_role': test_role,
                                    'privileged_field': field,
                                    'severity': 'High',
                                    'description': f'Successfully set privileged field {field} via mass assignment'
                                })
                                
                except Exception as e:
                    print(f"Error testing mass assignment on {endpoint}: {e}")
        
        return vulnerabilities
    
    def detect_sensitive_data(self, content):
        """Detect sensitive data in response content"""
        sensitive_patterns = [
            r'password[":\s]+[^,\]}]+',
            r'email[":\s]+[^,\]}]+',
            r'credit_card[":\s]+[^,\]}]+',
            r'ssn[":\s]+[^,\]}]+',
            r'phone[":\s]+[^,\]}]+',
            r'address[":\s]+[^,\]}]+'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def comprehensive_bflac_testing(self, test_scenarios):
        """Perform comprehensive BFLAC testing"""
        print("Starting comprehensive API Broken Function Level Authorization testing...")
        
        # Authenticate all users first
        self.authenticate_users()
        
        all_vulnerabilities = []
        
        # Horizontal Privilege Escalation Testing
        if test_scenarios.get('horizontal_escalation'):
            horizontal_vulns = self.test_horizontal_privilege_escalation(
                test_scenarios['horizontal_escalation']
            )
            all_vulnerabilities.extend(horizontal_vulns)
        
        # Vertical Privilege Escalation Testing
        if test_scenarios.get('vertical_escalation'):
            vertical_vulns = self.test_vertical_privilege_escalation(
                test_scenarios['vertical_escalation']
            )
            all_vulnerabilities.extend(vertical_vulns)
        
        # IDOR Testing
        if test_scenarios.get('idor_testing'):
            idor_vulns = self.test_idor_vulnerabilities(
                test_scenarios['idor_testing']
            )
            all_vulnerabilities.extend(idor_vulns)
        
        # Parameter Tampering Testing
        if test_scenarios.get('parameter_tampering'):
            param_vulns = self.test_parameter_tampering(
                test_scenarios['parameter_tampering']
            )
            all_vulnerabilities.extend(param_vulns)
        
        # HTTP Method Manipulation Testing
        if test_scenarios.get('http_method_manipulation'):
            method_vulns = self.test_http_method_manipulation(
                test_scenarios['http_method_manipulation']
            )
            all_vulnerabilities.extend(method_vulns)
        
        # Mass Assignment Testing
        if test_scenarios.get('mass_assignment'):
            mass_assignment_vulns = self.test_mass_assignment(
                test_scenarios['mass_assignment']
            )
            all_vulnerabilities.extend(mass_assignment_vulns)
        
        return all_vulnerabilities

# Usage Example
user_credentials = {
    'admin': {
        'username': 'admin',
        'password': 'admin123',
        'login_endpoint': '/api/auth/login'
    },
    'user': {
        'username': 'testuser',
        'password': 'user123',
        'login_endpoint': '/api/auth/login'
    },
    'viewer': {
        'username': 'viewer',
        'password': 'viewer123',
        'login_endpoint': '/api/auth/login'
    }
}

tester = APIBFLACTester('https://api.example.com', user_credentials)

test_scenarios = {
    'horizontal_escalation': {
        '/api/users/{id}/profile': [
            {'user_a': 'user', 'user_b_resource': '123', 'expected_status': 403},
            {'user_a': 'user', 'user_b_resource': '456', 'expected_status': 403}
        ],
        '/api/orders/{id}': [
            {'user_a': 'user', 'user_b_resource': '789', 'expected_status': 403}
        ]
    },
    'vertical_escalation': [
        {'endpoint': '/api/admin/users', 'method': 'GET', 'expected_status': 403},
        {'endpoint': '/api/admin/system/config', 'method': 'GET', 'expected_status': 403},
        {'endpoint': '/api/admin/logs', 'method': 'GET', 'expected_status': 403}
    ],
    'idor_testing': {
        '/api/users/{id}/profile': {
            'test_role': 'user',
            'id_patterns': [
                {'type': 'sequential', 'start': 1, 'count': 10},
                {'type': 'uuid', 'test_uuids': ['uuid1', 'uuid2', 'uuid3']}
            ]
        }
    },
    'parameter_tampering': [
        {
            'endpoint': '/api/user/profile',
            'method': 'GET',
            'test_role': 'user',
            'parameters': [
                {'name': 'user_id', 'tampered_values': ['admin', '1', '0']},
                {'name': 'role', 'tampered_values': ['admin', 'superuser']}
            ]
        }
    ],
    'http_method_manipulation': [
        {
            'endpoint': '/api/users/123',
            'allowed_methods': ['GET'],
            'test_role': 'user'
        }
    ],
    'mass_assignment': [
        {
            'endpoint': '/api/users',
            'method': 'POST',
            'test_role': 'user',
            'base_object': {'username': 'test', 'email': 'test@example.com'},
            'privileged_fields': ['is_admin', 'role', 'permissions']
        }
    ]
}

vulnerabilities = tester.comprehensive_bflac_testing(test_scenarios)
```

## 2.0 Advanced BFLAC Attack Techniques

### 2.1 JWT Claim Manipulation

```python
# JWT Claim Manipulation for Authorization Bypass
import jwt
import json

class JWTClaimManipulator:
    def __init__(self):
        self.vulnerabilities = []
    
    def test_jwt_role_manipulation(self, original_token, secret_key=None):
        """Test JWT role/claim manipulation"""
        print("Testing JWT claim manipulation...")
        
        try:
            # Decode token without verification to get payload
            decoded_payload = jwt.decode(original_token, options={"verify_signature": False})
            header = jwt.get_unverified_header(original_token)
            
            # Test various claim manipulations
            claim_manipulations = [
                {'role': 'admin'},
                {'is_admin': True},
                {'user_type': 'administrator'},
                {'permissions': ['read', 'write', 'delete', 'admin']},
                {'scope': 'admin'},
                {'groups': ['admin', 'superuser']}
            ]
            
            for manipulation in claim_manipulations:
                modified_payload = decoded_payload.copy()
                modified_payload.update(manipulation)
                
                # Try to re-sign with different methods
                signing_methods = [
                    ('HS256', secret_key) if secret_key else None,
                    ('none', '')  # "none" algorithm
                ]
                
                for alg, key in signing_methods:
                    if alg:
                        try:
                            forged_token = jwt.encode(modified_payload, key, algorithm=alg)
                            
                            self.vulnerabilities.append({
                                'type': 'JWT Claim Manipulation',
                                'manipulated_claims': manipulation,
                                'algorithm': alg,
                                'forged_token': forged_token,
                                'severity': 'Critical',
                                'description': f'Modified JWT claims with {manipulation} using {alg}'
                            })
                            
                        except Exception as e:
                            continue
            
        except Exception as e:
            print(f"JWT manipulation failed: {e}")
        
        return self.vulnerabilities
    
    def test_jwt_algorithm_confusion(self, original_token, public_key):
        """Test JWT algorithm confusion attacks"""
        try:
            decoded_payload = jwt.decode(original_token, options={"verify_signature": False})
            header = jwt.get_unverified_header(original_token)
            
            # Modify role to admin
            decoded_payload['role'] = 'admin'
            
            # Try algorithm confusion: RS256 to HS256
            forged_token = jwt.encode(decoded_payload, public_key, algorithm='HS256')
            
            self.vulnerabilities.append({
                'type': 'JWT Algorithm Confusion',
                'forged_token': forged_token,
                'severity': 'Critical',
                'description': 'Algorithm confusion attack successful'
            })
            
        except Exception as e:
            print(f"Algorithm confusion failed: {e}")
        
        return self.vulnerabilities

# JWT Attack Example
jwt_attacker = JWTClaimManipulator()
original_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

jwt_vulns = jwt_attacker.test_jwt_role_manipulation(original_token, 'weak_secret')
```

### 2.2 GraphQL Authorization Bypass

```python
# GraphQL Authorization Bypass Testing
class GraphQLBFLACTester:
    def __init__(self, target_url, user_sessions):
        self.target_url = target_url
        self.user_sessions = user_sessions
        self.vulnerabilities = []
    
    def test_graphql_introspection(self, roles):
        """Test GraphQL introspection for sensitive information"""
        print("Testing GraphQL introspection...")
        
        introspection_query = """
        query {
          __schema {
            types {
              name
              fields {
                name
                type {
                  name
                  kind
                  ofType {
                    name
                    kind
                  }
                }
              }
            }
          }
        }
        """
        
        for role, session in self.user_sessions.items():
            try:
                response = session.post(
                    self.target_url,
                    json={'query': introspection_query}
                )
                
                if response.status_code == 200:
                    schema_data = response.json()
                    
                    # Look for sensitive types and fields
                    sensitive_indicators = ['admin', 'user', 'password', 'email', 'delete', 'update']
                    
                    for type_info in schema_data.get('data', {}).get('__schema', {}).get('types', []):
                        type_name = type_info.get('name', '').lower()
                        fields = type_info.get('fields', [])
                        
                        for indicator in sensitive_indicators:
                            if indicator in type_name:
                                self.vulnerabilities.append({
                                    'type': 'GraphQL Introspection Exposure',
                                    'role': role,
                                    'sensitive_type': type_name,
                                    'severity': 'Medium',
                                    'description': f'Discovered sensitive type {type_name} via introspection'
                                })
                                break
                        
                        for field in fields:
                            field_name = field.get('name', '').lower()
                            for indicator in sensitive_indicators:
                                if indicator in field_name:
                                    self.vulnerabilities.append({
                                        'type': 'GraphQL Field Exposure',
                                        'role': role,
                                        'sensitive_field': field_name,
                                        'parent_type': type_name,
                                        'severity': 'Medium',
                                        'description': f'Discovered sensitive field {field_name} in {type_name}'
                                    })
                                    
            except Exception as e:
                print(f"GraphQL introspection failed for {role}: {e}")
    
    def test_graphql_field_manipulation(self, test_queries):
        """Test GraphQL field manipulation for authorization bypass"""
        print("Testing GraphQL field manipulation...")
        
        for role, session in self.user_sessions.items():
            for query_info in test_queries:
                query = query_info['query']
                expected_errors = query_info.get('expected_errors', True)
                
                try:
                    response = session.post(
                        self.target_url,
                        json={'query': query}
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        
                        # Check if we got data without errors
                        if 'errors' not in result and result.get('data'):
                            self.vulnerabilities.append({
                                'type': 'GraphQL Field Manipulation',
                                'role': role,
                                'query': query,
                                'severity': 'High',
                                'description': 'Accessed unauthorized data via GraphQL field manipulation'
                            })
                            
                except Exception as e:
                    print(f"GraphQL query failed for {role}: {e}")
    
    def test_graphql_batch_operations(self, roles):
        """Test GraphQL batch operations for authorization bypass"""
        print("Testing GraphQL batch operations...")
        
        batch_query = """
        query BatchQuery {
          user1: user(id: 1) { id email role }
          user2: user(id: 2) { id email role }
          user3: user(id: 3) { id email role }
          admin: adminFunctions { users systemConfig }
        }
        """
        
        for role, session in self.user_sessions.items():
            try:
                response = session.post(
                    self.target_url,
                    json={'query': batch_query}
                )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # Check if we got admin data
                    if result.get('data', {}).get('admin'):
                        self.vulnerabilities.append({
                            'type': 'GraphQL Batch Operation Bypass',
                            'role': role,
                            'severity': 'High',
                            'description': 'Accessed admin functions via GraphQL batch query'
                        })
                        
            except Exception as e:
                print(f"GraphQL batch query failed for {role}: {e}")

# GraphQL Testing Example
graphql_tester = GraphQLBFLACTester('https://api.example.com/graphql', tester.sessions)

test_queries = [
    {
        'query': """
        query {
          users {
            id
            email
            passwordHash
            role
          }
        }
        """,
        'expected_errors': True
    },
    {
        'query': """
        query {
          adminDashboard {
            systemStats
            userData
            config
          }
        }
        """,
        'expected_errors': True
    }
]

graphql_tester.test_graphql_introspection(['user', 'admin'])
graphql_tester.test_graphql_field_manipulation(test_queries)
graphql_tester.test_graphql_batch_operations(['user', 'viewer'])
```

## 3.0 Automated BFLAC Testing Framework

### 3.1 Comprehensive Testing Suite

```python
# API Broken Function Level Authorization Security Scanner
class APIBFLACScanner:
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
        
    def run_comprehensive_scan(self, endpoints_config, user_credentials):
        """Run comprehensive BFLAC security scan"""
        print("Starting API Broken Function Level Authorization Security Scan...")
        
        # Initialize tester
        tester = APIBFLACTester(self.base_url, user_credentials)
        
        scan_tests = [
            (self.scan_horizontal_escalation, endpoints_config.get('horizontal_endpoints', {})),
            (self.scan_vertical_escalation, endpoints_config.get('vertical_endpoints', [])),
            (self.scan_idor_vulnerabilities, endpoints_config.get('idor_endpoints', {})),
            (self.scan_parameter_tampering, endpoints_config.get('parameter_endpoints', [])),
            (self.scan_http_method_manipulation, endpoints_config.get('method_endpoints', [])),
            (self.scan_mass_assignment, endpoints_config.get('mass_assignment_endpoints', []))
        ]
        
        for scan_method, endpoints in scan_tests:
            if endpoints:
                try:
                    vulnerabilities = scan_method(tester, endpoints)
                    self.categorize_vulnerabilities(vulnerabilities)
                except Exception as e:
                    print(f"Error in {scan_method.__name__}: {e}")
        
        return self.generate_report()
    
    def scan_horizontal_escalation(self, tester, endpoints):
        """Scan for horizontal privilege escalation"""
        return tester.test_horizontal_privilege_escalation(endpoints)
    
    def scan_vertical_escalation(self, tester, endpoints):
        """Scan for vertical privilege escalation"""
        return tester.test_vertical_privilege_escalation(endpoints)
    
    def scan_idor_vulnerabilities(self, tester, endpoints):
        """Scan for IDOR vulnerabilities"""
        return tester.test_idor_vulnerabilities(endpoints)
    
    def scan_parameter_tampering(self, tester, endpoints):
        """Scan for parameter tampering vulnerabilities"""
        return tester.test_parameter_tampering(endpoints)
    
    def scan_http_method_manipulation(self, tester, endpoints):
        """Scan for HTTP method manipulation vulnerabilities"""
        return tester.test_http_method_manipulation(endpoints)
    
    def scan_mass_assignment(self, tester, endpoints):
        """Scan for mass assignment vulnerabilities"""
        return tester.test_mass_assignment(endpoints)
    
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
                "Implement proper role-based access control (RBAC)",
                "Add authorization checks on all API endpoints",
                "Use centralized authorization middleware",
                "Implement proper session management",
                "Add audit logging for authorization attempts"
            ])
        
        if self.results['medium']:
            recommendations.extend([
                "Validate user permissions for each resource access",
                "Implement proper input validation",
                "Use UUIDs instead of sequential IDs",
                "Add rate limiting on sensitive endpoints",
                "Implement proper error handling without information disclosure"
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

scanner = APIBFLACScanner('https://api.example.com', scanner_config)

user_credentials = {
    'admin': {'username': 'admin', 'password': 'admin123', 'login_endpoint': '/api/auth/login'},
    'user': {'username': 'user', 'password': 'user123', 'login_endpoint': '/api/auth/login'},
    'viewer': {'username': 'viewer', 'password': 'viewer123', 'login_endpoint': '/api/auth/login'}
}

endpoints_config = {
    'horizontal_endpoints': {
        '/api/users/{id}/profile': [
            {'user_a': 'user', 'user_b_resource': '123', 'expected_status': 403},
            {'user_a': 'user', 'user_b_resource': '456', 'expected_status': 403}
        ]
    },
    'vertical_endpoints': [
        {'endpoint': '/api/admin/users', 'method': 'GET', 'expected_status': 403},
        {'endpoint': '/api/admin/config', 'method': 'GET', 'expected_status': 403}
    ],
    'idor_endpoints': {
        '/api/users/{id}': {
            'test_role': 'user',
            'id_patterns': [
                {'type': 'sequential', 'start': 1, 'count': 20}
            ]
        }
    },
    'parameter_endpoints': [
        {
            'endpoint': '/api/user',
            'method': 'GET',
            'test_role': 'user',
            'parameters': [
                {'name': 'user_id', 'tampered_values': ['admin', '1']}
            ]
        }
    ],
    'method_endpoints': [
        {
            'endpoint': '/api/users/123',
            'allowed_methods': ['GET'],
            'test_role': 'user'
        }
    ],
    'mass_assignment_endpoints': [
        {
            'endpoint': '/api/users',
            'method': 'POST',
            'test_role': 'user',
            'base_object': {'username': 'test', 'email': 'test@example.com'},
            'privileged_fields': ['is_admin', 'role']
        }
    ]
}

report = scanner.run_comprehensive_scan(endpoints_config, user_credentials)

print(f"Scan completed. Risk Score: {report['risk_score']:.1f}/10")
print(f"Critical vulnerabilities: {report['scan_summary']['critical_count']}")
```

## 4.0 Advanced BFLAC Protection & Detection

### 4.1 Protection Mechanisms Implementation

```python
# BFLAC Protection Validator
class BFLACProtectionValidator:
    def __init__(self, base_url, test_credentials):
        self.base_url = base_url
        self.test_credentials = test_credentials
        self.protection_issues = []
        self.sessions = {}
    
    def validate_authorization_checks(self, endpoints):
        """Validate authorization checks on endpoints"""
        print("Validating authorization checks...")
        
        self.authenticate_users()
        
        for endpoint_info in endpoints:
            endpoint = endpoint_info['endpoint']
            method = endpoint_info.get('method', 'GET')
            allowed_roles = endpoint_info['allowed_roles']
            test_roles = endpoint_info['test_roles']
            
            for test_role in test_roles:
                if test_role not in allowed_roles and test_role in self.sessions:
                    # This role should not have access
                    try:
                        if method == 'GET':
                            response = self.sessions[test_role].get(f"{self.base_url}{endpoint}")
                        elif method == 'POST':
                            response = self.sessions[test_role].post(f"{self.base_url}{endpoint}")
                        elif method == 'PUT':
                            response = self.sessions[test_role].put(f"{self.base_url}{endpoint}")
                        elif method == 'DELETE':
                            response = self.sessions[test_role].delete(f"{self.base_url}{endpoint}")
                        
                        if response.status_code != 403:
                            self.protection_issues.append({
                                'type': 'Missing Authorization Check',
                                'endpoint': endpoint,
                                'method': method,
                                'unauthorized_role': test_role,
                                'response_status': response.status_code,
                                'severity': 'High',
                                'description': f'Role {test_role} accessed endpoint without proper authorization'
                            })
                            
                    except Exception as e:
                        print(f"Error testing {endpoint} with {test_role}: {e}")
    
    def validate_resource_ownership(self, endpoints_with_ownership):
        """Validate resource ownership checks"""
        print("Validating resource ownership checks...")
        
        for endpoint_template, test_cases in endpoints_with_ownership.items():
            for test_case in test_cases:
                user_role = test_case['user_role']
                user_resource = test_case['user_resource']
                other_resource = test_case['other_resource']
                
                if user_role in self.sessions:
                    # Test accessing own resource (should work)
                    own_endpoint = endpoint_template.replace('{id}', user_resource)
                    response_own = self.sessions[user_role].get(f"{self.base_url}{own_endpoint}")
                    
                    # Test accessing other user's resource (should fail)
                    other_endpoint = endpoint_template.replace('{id}', other_resource)
                    response_other = self.sessions[user_role].get(f"{self.base_url}{other_endpoint}")
                    
                    if response_other.status_code == 200:
                        self.protection_issues.append({
                            'type': 'Missing Resource Ownership Check',
                            'endpoint': endpoint_template,
                            'user_role': user_role,
                            'accessed_resource': other_resource,
                            'severity': 'High',
                            'description': f'User accessed resource belonging to another user'
                        })
    
    def validate_jwt_implementation(self, jwt_tokens):
        """Validate JWT implementation security"""
        print("Validating JWT implementation...")
        
        for role, token in jwt_tokens.items():
            try:
                # Test token without verification
                decoded = jwt.decode(token, options={"verify_signature": False})
                
                # Check for weak claims
                if decoded.get('role') == 'admin':
                    # Try to modify and re-sign
                    decoded['role'] = 'superadmin'
                    
                    # Test with common weak secrets
                    weak_secrets = ['secret', 'password', 'key', '123456']
                    for secret in weak_secrets:
                        try:
                            forged = jwt.encode(decoded, secret, algorithm='HS256')
                            # If no error, weak secret might be used
                            self.protection_issues.append({
                                'type': 'Weak JWT Secret',
                                'role': role,
                                'weak_secret': secret,
                                'severity': 'High',
                                'description': f'JWT might be using weak secret: {secret}'
                            })
                            break
                        except:
                            continue
                
                # Check token expiration
                if 'exp' not in decoded:
                    self.protection_issues.append({
                        'type': 'JWT Missing Expiration',
                        'role': role,
                        'severity': 'Medium',
                        'description': 'JWT token has no expiration claim'
                    })
                    
            except Exception as e:
                print(f"JWT validation failed for {role}: {e}")
    
    def validate_rate_limiting(self, sensitive_endpoints):
        """Validate rate limiting on sensitive endpoints"""
        print("Validating rate limiting...")
        
        for endpoint_info in sensitive_endpoints:
            endpoint = endpoint_info['endpoint']
            test_role = endpoint_info['test_role']
            max_requests = endpoint_info.get('max_requests', 10)
            
            if test_role in self.sessions:
                # Make rapid requests
                for i in range(max_requests + 5):
                    response = self.sessions[test_role].get(f"{self.base_url}{endpoint}")
                    
                    if response.status_code == 429:  # Rate limited
                        break
                else:
                    self.protection_issues.append({
                        'type': 'Missing Rate Limiting',
                        'endpoint': endpoint,
                        'test_role': test_role,
                        'requests_made': max_requests + 5,
                        'severity': 'Medium',
                        'description': 'No rate limiting detected on sensitive endpoint'
                    })
    
    def authenticate_users(self):
        """Authenticate test users"""
        for role, creds in self.test_credentials.items():
            try:
                session = requests.Session()
                response = session.post(
                    f"{self.base_url}{creds['login_endpoint']}",
                    json={'username': creds['username'], 'password': creds['password']}
                )
                
                if response.status_code == 200:
                    token = response.json().get('token')
                    if token:
                        session.headers.update({'Authorization': f'Bearer {token}'})
                        self.sessions[role] = session
                        
            except Exception as e:
                print(f"Authentication failed for {role}: {e}")
    
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
        
        if 'Missing Authorization Check' in issue_types:
            recommendations.append("Implement proper authorization checks on all endpoints")
        
        if 'Missing Resource Ownership Check' in issue_types:
            recommendations.append("Add resource ownership validation for user-specific resources")
        
        if 'Weak JWT Secret' in issue_types:
            recommendations.append("Use strong, randomly generated JWT secrets")
        
        if 'JWT Missing Expiration' in issue_types:
            recommendations.append("Add expiration claims to all JWT tokens")
        
        if 'Missing Rate Limiting' in issue_types:
            recommendations.append("Implement rate limiting on sensitive endpoints")
        
        if not recommendations:
            recommendations.append("Maintain current protection measures and conduct regular security testing")
        
        return recommendations

# Protection Validation Example
validator = BFLACProtectionValidator('https://api.example.com', user_credentials)

# Define endpoints to validate
validation_endpoints = [
    {
        'endpoint': '/api/admin/users',
        'method': 'GET',
        'allowed_roles': ['admin'],
        'test_roles': ['user', 'viewer']
    },
    {
        'endpoint': '/api/admin/config',
        'method': 'GET',
        'allowed_roles': ['admin'],
        'test_roles': ['user', 'viewer']
    }
]

ownership_endpoints = {
    '/api/users/{id}/profile': [
        {'user_role': 'user', 'user_resource': 'user123', 'other_resource': 'user456'}
    ]
}

validator.validate_authorization_checks(validation_endpoints)
validator.validate_resource_ownership(ownership_endpoints)

protection_report = validator.generate_protection_report()
print(f"Protection Level: {protection_report['protection_level']}")
```

## 5.0 BFLAC Testing Checklist & Report

### 5.1 Comprehensive Testing Checklist

```markdown
# API Broken Function Level Authorization Testing Checklist

## 🔍 Horizontal Privilege Escalation
- [ ] User A accessing User B's resources
- [ ] Same-role unauthorized data access
- [ ] IDOR vulnerability testing
- [ ] Resource enumeration via sequential IDs
- [ ] UUID prediction testing

## 🔐 Vertical Privilege Escalation
- [ ] Regular user accessing admin functions
- [ ] Privileged endpoint exposure
- [ ] Role-based access control testing
- [ ] Administrative function access
- [ ] Superuser privilege testing

## 🎯 Function-Level Authorization Bypass
- [ ] Direct API endpoint access testing
- [ ] HTTP method manipulation
- [ ] Parameter tampering attacks
- [ ] API version manipulation
- [ ] Endpoint path traversal

## 🔑 Authentication Bypass
- [ ] JWT claim manipulation
- [ ] Token forgery testing
- [ ] Session fixation attacks
- [ ] Cookie manipulation
- [ ] API key leakage testing

## 📊 Mass Assignment Testing
- [ ] Privileged field manipulation
- [ ] Object property injection
- [ ] JSON payload manipulation
- [ ] Partial object updates
- [ ] Batch operation testing

## 🗄️ GraphQL Security Testing
- [ ] Introspection query testing
- [ ] Field manipulation attacks
- [ ] Batch query authorization
- [ ] Directive manipulation
- [ ] Query complexity attacks

## 🛡️ Protection Mechanism Validation
- [ ] Authorization middleware testing
- [ ] Resource ownership validation
- [ ] Rate limiting implementation
- [ ] Input validation testing
- [ ] Audit logging verification
```

### 5.2 Executive Security Report Template

```python
# BFLAC Security Report Generator
class BFLACReportGenerator:
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
            'Vertical Privilege Escalation': 'Complete system compromise',
            'Horizontal Privilege Escalation': 'Data breach and privacy violation',
            'IDOR - Sequential ID': 'Unauthorized data access',
            'JWT Claim Manipulation': 'Authentication system compromise',
            'Mass Assignment': 'Privilege escalation and data manipulation'
        }
        
        return impact_mapping.get(vulnerability.get('type'), 'Authorization system compromise')
    
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
                    'attacker_role': vuln.get('attacker_role', 'N/A'),
                    'evidence': vuln.get('evidence', ''),
                    'remediation': self.get_remediation(vuln.get('type'))
                })
        
        return technical_details
    
    def get_remediation(self, vulnerability_type):
        """Get remediation guidance for vulnerability type"""
        remediation_guide = {
            'Vertical Privilege Escalation': 'Implement proper role-based access control and authorization checks',
            'Horizontal Privilege Escalation': 'Add resource ownership validation and user context checks',
            'IDOR - Sequential ID': 'Use UUIDs instead of sequential IDs and implement proper access controls',
            'JWT Claim Manipulation': 'Use strong JWT secrets and validate token signatures properly',
            'Mass Assignment': 'Implement allow-list for object properties and use DTOs',
            'Parameter Tampering': 'Validate all input parameters and implement proper authorization checks'
        }
        
        return remediation_guide.get(vulnerability_type, 'Review and implement proper authorization controls')
    
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
                'business_impact': 'Critical - System Compromise',
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
                'business_impact': 'Medium - Privacy Violation',
                'likelihood': 'Medium',
                'recommended_timeline': '1 month'
            },
            'low': {
                'count': len(self.scan_results.get('low', [])),
                'business_impact': 'Low - Information Disclosure',
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
            'testing_methodology': 'Comprehensive API Broken Function Level Authorization assessment',
            'tools_used': ['Custom Python testing framework', 'JWT manipulation tools'],
            'scope': self.company_info.get('scope', 'All API endpoints with authorization requirements'),
            'testing_approach': 'Horizontal and vertical privilege escalation testing, IDOR testing, parameter tampering',
            'contact_information': self.company_info.get('contact', 'Security Team')
        }

# Report Generation Example
company_info = {
    'name': 'Example API Service',
    'date': '2024-01-15',
    'scope': 'All API endpoints with authorization requirements',
    'contact': 'security@example.com'
}

# Assuming scan_results from previous scanning
report_generator = BFLACReportGenerator(scanner.results, company_info)
comprehensive_report = report_generator.generate_comprehensive_report()

# Print report summary
exec_summary = comprehensive_report['executive_summary']
print(f"BFLAC Assessment for: {exec_summary['company_name']}")
print(f"Overall Risk: {exec_summary['overall_risk_level']}")
print(f"Critical Issues: {exec_summary['critical_vulnerabilities']}")
print(f"High Issues: {exec_summary['high_vulnerabilities']}")
```

This comprehensive API Broken Function Level Authorization testing framework provides security professionals with advanced tools and methodologies to identify, exploit, and report authorization vulnerabilities in modern API implementations. The framework covers horizontal and vertical privilege escalation, IDOR vulnerabilities, parameter tampering, JWT manipulation, and provides actionable remediation guidance for protecting APIs against authorization bypass attacks.