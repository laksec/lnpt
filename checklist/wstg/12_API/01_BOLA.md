# 🔐 API SECURITY TESTING | BROKEN OBJECT LEVEL AUTHORIZATION (BOLA)

## 1 Comprehensive BOLA Testing Methodology

### 1.1 BOLA Testing Framework
```yaml
BOLA_Testing_Framework:
  Identification_Phase:
    - Object ID enumeration and analysis
    - API endpoint mapping with object references
    - User role and privilege assessment
    - Object ownership relationships mapping
    - Direct object reference identification
    - Indirect object reference discovery

  Exploitation_Phase:
    - Horizontal privilege escalation testing
    - Vertical privilege escalation testing
    - Cross-tenant data access testing
    - Mass assignment vulnerability testing
    - Insecure direct object reference (IDOR)
    - Business logic bypass testing

  Validation_Phase:
    - Authorization mechanism verification
    - Access control rule validation
    - Session management security testing
    - Token-based authorization testing
    - API key authorization assessment
    - Rate limiting effectiveness testing
```

### 1.2 BOLA Attack Vectors
- **Direct Object References:**
  - Numeric ID manipulation
  - UUID/GUID prediction/brute-force
  - Sequential ID enumeration
  - Object reference in URL parameters
  - Object reference in request body
  - Object reference in headers

- **Indirect Object References:**
  - Mapped object references
  - Encoded object identifiers
  - Hashed object references
  - Temporary object tokens
  - Session-based object mapping
  - Cached object references

## 2 BOLA Testing Techniques

### 2.1 Horizontal Privilege Escalation Testing
```python
# Horizontal BOLA Testing Tool
import requests
import json
from typing import Dict, List, Any
from dataclasses import dataclass
import asyncio
import aiohttp

@dataclass
class BOLAResult:
    vulnerability_type: str
    endpoint: str
    technique: str
    severity: str
    evidence: str
    object_id: str
    user_context: str

class HorizontalBOLATester:
    def __init__(self, base_url: str, auth_tokens: Dict[str, str]):
        self.base_url = base_url
        self.auth_tokens = auth_tokens
        self.vulnerabilities: List[BOLAResult] = []
        
    async def test_user_object_access(self, endpoints: List[Dict]) -> List[BOLAResult]:
        """Test horizontal access control between users"""
        results = []
        
        for endpoint in endpoints:
            # Test with different user contexts
            for user_type, auth_token in self.auth_tokens.items():
                # Get accessible objects for current user
                accessible_objects = await self.get_accessible_objects(endpoint, auth_token)
                
                # Test accessing other users' objects
                for obj_id in accessible_objects:
                    for other_user, other_token in self.auth_tokens.items():
                        if other_user != user_type:
                            is_accessible = await self.test_object_access(
                                endpoint, obj_id, other_token, user_type
                            )
                            
                            if is_accessible:
                                result = BOLAResult(
                                    vulnerability_type="Horizontal BOLA",
                                    endpoint=endpoint['url'],
                                    technique="Cross-User Object Access",
                                    severity="High",
                                    evidence=f"User {other_user} accessed {user_type}'s object {obj_id}",
                                    object_id=obj_id,
                                    user_context=f"{user_type} -> {other_user}"
                                )
                                results.append(result)
        
        return results

    async def test_object_enumeration(self, endpoints: List[Dict]) -> List[BOLAResult]:
        """Test object ID enumeration vulnerabilities"""
        results = []
        
        for endpoint in endpoints:
            for user_type, auth_token in self.auth_tokens.items():
                # Test sequential ID enumeration
                sequential_results = await self.test_sequential_enumeration(endpoint, auth_token, user_type)
                results.extend(sequential_results)
                
                # Test UUID enumeration
                uuid_results = await self.test_uuid_enumeration(endpoint, auth_token, user_type)
                results.extend(uuid_results)
                
                # Test predictable ID patterns
                predictable_results = await self.test_predictable_patterns(endpoint, auth_token, user_type)
                results.extend(predictable_results)
        
        return results

    async def test_sequential_enumeration(self, endpoint: Dict, auth_token: str, user_type: str) -> List[BOLAResult]:
        """Test sequential object ID enumeration"""
        results = []
        
        # Start from known accessible object
        known_objects = await self.get_accessible_objects(endpoint, auth_token)
        
        if known_objects:
            base_id = min(known_objects) if known_objects[0].isdigit() else known_objects[0]
            
            # Test sequential IDs around known object
            for offset in range(-10, 11):
                test_id = self.generate_sequential_id(base_id, offset)
                
                is_accessible = await self.test_object_access(endpoint, test_id, auth_token, user_type)
                
                if is_accessible:
                    result = BOLAResult(
                        vulnerability_type="Object Enumeration",
                        endpoint=endpoint['url'],
                        technique="Sequential ID Prediction",
                        severity="Medium",
                        evidence=f"Accessed object {test_id} through sequential enumeration",
                        object_id=test_id,
                        user_context=user_type
                    )
                    results.append(result)
        
        return results

    async def test_uuid_enumeration(self, endpoint: Dict, auth_token: str, user_type: str) -> List[BOLAResult]:
        """Test UUID-based object enumeration"""
        results = []
        
        # Generate test UUIDs based on common patterns
        test_uuids = self.generate_test_uuids()
        
        for test_uuid in test_uuids:
            is_accessible = await self.test_object_access(endpoint, test_uuid, auth_token, user_type)
            
            if is_accessible:
                result = BOLAResult(
                    vulnerability_type="Object Enumeration",
                    endpoint=endpoint['url'],
                    technique="UUID Prediction/Brute-force",
                    severity="Low",
                    evidence=f"Accessed object {test_uuid} through UUID enumeration",
                    object_id=test_uuid,
                    user_context=user_type
                )
                results.append(result)
        
        return results

    async def get_accessible_objects(self, endpoint: Dict, auth_token: str) -> List[str]:
        """Get list of objects accessible to the user"""
        objects = []
        
        try:
            headers = {'Authorization': f'Bearer {auth_token}'}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}{endpoint['url']}",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        objects = self.extract_object_ids(data, endpoint.get('id_field', 'id'))
        
        except Exception as e:
            print(f"Error getting accessible objects: {e}")
        
        return objects

    async def test_object_access(self, endpoint: Dict, object_id: str, auth_token: str, user_type: str) -> bool:
        """Test if object is accessible with given auth token"""
        try:
            headers = {'Authorization': f'Bearer {auth_token}'}
            url = f"{self.base_url}{endpoint['url']}".replace('{id}', str(object_id))
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    return response.status == 200
        
        except Exception as e:
            print(f"Error testing object access: {e}")
            return False

    def generate_sequential_id(self, base_id: str, offset: int) -> str:
        """Generate sequential ID based on base ID"""
        if base_id.isdigit():
            return str(int(base_id) + offset)
        return base_id

    def generate_test_uuids(self) -> List[str]:
        """Generate test UUIDs for enumeration"""
        import uuid
        return [
            str(uuid.uuid4()),  # Random UUID
            "00000000-0000-0000-0000-000000000000",  # Null UUID
            "ffffffff-ffff-ffff-ffff-ffffffffffff",  # Max UUID
        ]

    def extract_object_ids(self, data: Any, id_field: str) -> List[str]:
        """Extract object IDs from API response"""
        ids = []
        
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and id_field in item:
                    ids.append(str(item[id_field]))
        elif isinstance(data, dict) and id_field in data:
            ids.append(str(data[id_field]))
        
        return ids
```

### 2.2 Vertical Privilege Escalation Testing
```python
# Vertical BOLA Testing Tool
class VerticalBOLATester:
    def __init__(self, base_url: str, role_tokens: Dict[str, str]):
        self.base_url = base_url
        self.role_tokens = role_tokens  # { 'user': token, 'admin': token, 'moderator': token }
        self.vulnerabilities: List[BOLAResult] = []
        
    async def test_privilege_escalation(self, endpoints: List[Dict]) -> List[BOLAResult]:
        """Test vertical privilege escalation"""
        results = []
        
        for endpoint in endpoints:
            # Test lower privilege accessing higher privilege objects
            for lower_role, lower_token in self.role_tokens.items():
                for higher_role, higher_token in self.role_tokens.items():
                    if self.get_privilege_level(lower_role) < self.get_privilege_level(higher_role):
                        higher_objects = await self.get_accessible_objects(endpoint, higher_token)
                        
                        for obj_id in higher_objects:
                            is_accessible = await self.test_object_access(
                                endpoint, obj_id, lower_token, lower_role
                            )
                            
                            if is_accessible:
                                result = BOLAResult(
                                    vulnerability_type="Vertical BOLA",
                                    endpoint=endpoint['url'],
                                    technique="Privilege Escalation",
                                    severity="Critical",
                                    evidence=f"{lower_role} accessed {higher_role}'s object {obj_id}",
                                    object_id=obj_id,
                                    user_context=f"{lower_role} -> {higher_role}"
                                )
                                results.append(result)
        
        return results

    async def test_admin_functionality_access(self, endpoints: List[Dict]) -> List[BOLAResult]:
        """Test access to admin-only functionality"""
        results = []
        
        admin_token = self.role_tokens.get('admin')
        if not admin_token:
            return results
        
        # Get admin-accessible endpoints and objects
        admin_objects = {}
        for endpoint in endpoints:
            if endpoint.get('admin_only', False):
                objects = await self.get_accessible_objects(endpoint, admin_token)
                admin_objects[endpoint['url']] = objects
        
        # Test non-admin access to admin objects
        for endpoint_url, objects in admin_objects.items():
            for obj_id in objects:
                for role, token in self.role_tokens.items():
                    if role != 'admin':
                        is_accessible = await self.test_object_access(
                            {'url': endpoint_url}, obj_id, token, role
                        )
                        
                        if is_accessible:
                            result = BOLAResult(
                                vulnerability_type="Vertical BOLA",
                                endpoint=endpoint_url,
                                technique="Admin Functionality Access",
                                severity="Critical",
                                evidence=f"{role} accessed admin object {obj_id}",
                                object_id=obj_id,
                                user_context=f"{role} -> admin"
                            )
                            results.append(result)
        
        return results

    def get_privilege_level(self, role: str) -> int:
        """Get numeric privilege level for role"""
        privilege_levels = {
            'user': 1,
            'moderator': 2,
            'admin': 3,
            'superadmin': 4
        }
        return privilege_levels.get(role, 0)

    async def test_role_parameter_manipulation(self, endpoints: List[Dict]) -> List[BOLAResult]:
        """Test role parameter manipulation in requests"""
        results = []
        
        for endpoint in endpoints:
            if endpoint.get('method') == 'POST' or endpoint.get('method') == 'PUT':
                for role, token in self.role_tokens.items():
                    # Test adding role parameters to requests
                    manipulated_data = await self.manipulate_role_parameters(
                        endpoint, token, role
                    )
                    
                    if manipulated_data:
                        result = BOLAResult(
                            vulnerability_type="Vertical BOLA",
                            endpoint=endpoint['url'],
                            technique="Role Parameter Manipulation",
                            severity="High",
                            evidence=f"Role escalation through parameter manipulation",
                            object_id="N/A",
                            user_context=role
                        )
                        results.append(result)
        
        return results

    async def manipulate_role_parameters(self, endpoint: Dict, auth_token: str, current_role: str) -> Dict:
        """Attempt to manipulate role parameters in request"""
        try:
            headers = {
                'Authorization': f'Bearer {auth_token}',
                'Content-Type': 'application/json'
            }
            
            # Create test data with role escalation attempts
            test_data = endpoint.get('test_data', {})
            role_attempts = [
                {'role': 'admin'},
                {'user_role': 'administrator'},
                {'privilege': 'superuser'},
                {'is_admin': True}
            ]
            
            for role_attempt in role_attempts:
                manipulated_data = {**test_data, **role_attempt}
                
                async with aiohttp.ClientSession() as session:
                    if endpoint['method'] == 'POST':
                        async with session.post(
                            f"{self.base_url}{endpoint['url']}",
                            json=manipulated_data,
                            headers=headers
                        ) as response:
                            if response.status == 200:
                                return await response.json()
            
            return None
        
        except Exception as e:
            print(f"Error manipulating role parameters: {e}")
            return None
```

### 2.3 Mass Assignment Vulnerability Testing
```python
# Mass Assignment BOLA Testing Tool
class MassAssignmentTester:
    def __init__(self, base_url: str, auth_tokens: Dict[str, str]):
        self.base_url = base_url
        self.auth_tokens = auth_tokens
        self.vulnerabilities: List[BOLAResult] = []
        
    async def test_mass_assignment(self, endpoints: List[Dict]) -> List[BOLAResult]:
        """Test mass assignment vulnerabilities"""
        results = []
        
        sensitive_fields = [
            'role', 'is_admin', 'permissions', 'privileges',
            'user_id', 'owner_id', 'created_by', 'approved',
            'balance', 'credit_limit', 'salary', 'ssn'
        ]
        
        for endpoint in endpoints:
            if endpoint.get('method') in ['POST', 'PUT', 'PATCH']:
                for user_type, auth_token in self.auth_tokens.items():
                    endpoint_results = await self.test_endpoint_mass_assignment(
                        endpoint, auth_token, user_type, sensitive_fields
                    )
                    results.extend(endpoint_results)
        
        return results

    async def test_endpoint_mass_assignment(self, endpoint: Dict, auth_token: str, 
                                          user_type: str, sensitive_fields: List[str]) -> List[BOLAResult]:
        """Test mass assignment for specific endpoint"""
        results = []
        
        base_data = endpoint.get('test_data', {})
        
        for field in sensitive_fields:
            # Test adding sensitive field to request
            test_data = base_data.copy()
            test_data[field] = self.get_test_value_for_field(field)
            
            try:
                headers = {
                    'Authorization': f'Bearer {auth_token}',
                    'Content-Type': 'application/json'
                }
                
                async with aiohttp.ClientSession() as session:
                    if endpoint['method'] == 'POST':
                        async with session.post(
                            f"{self.base_url}{endpoint['url']}",
                            json=test_data,
                            headers=headers
                        ) as response:
                            
                            if response.status in [200, 201]:
                                # Check if sensitive field was accepted
                                response_data = await response.json()
                                if self.is_sensitive_field_present(response_data, field):
                                    result = BOLAResult(
                                        vulnerability_type="Mass Assignment BOLA",
                                        endpoint=endpoint['url'],
                                        technique="Sensitive Field Injection",
                                        severity="High",
                                        evidence=f"Sensitive field '{field}' accepted in {endpoint['method']} request",
                                        object_id="N/A",
                                        user_context=user_type
                                    )
                                    results.append(result)
            
            except Exception as e:
                print(f"Error testing mass assignment: {e}")
        
        return results

    def get_test_value_for_field(self, field: str) -> Any:
        """Get appropriate test value for sensitive field"""
        test_values = {
            'role': 'admin',
            'is_admin': True,
            'permissions': ['read', 'write', 'delete'],
            'user_id': '1',
            'owner_id': '1',
            'balance': 1000000,
            'salary': 999999,
            'ssn': '123-45-6789'
        }
        return test_values.get(field, 'test_value')

    def is_sensitive_field_present(self, response_data: Dict, field: str) -> bool:
        """Check if sensitive field is present in response"""
        if isinstance(response_data, dict):
            return field in response_data
        return False

    async def test_nested_mass_assignment(self, endpoints: List[Dict]) -> List[BOLAResult]:
        """Test nested object mass assignment"""
        results = []
        
        nested_sensitive_fields = [
            'user.role', 'profile.is_admin', 'metadata.privileges',
            'settings.permissions', 'account.balance'
        ]
        
        for endpoint in endpoints:
            if endpoint.get('method') in ['POST', 'PUT', 'PATCH']:
                for user_type, auth_token in self.auth_tokens.items():
                    for nested_field in nested_sensitive_fields:
                        test_data = endpoint.get('test_data', {}).copy()
                        
                        # Create nested structure
                        current_level = test_data
                        field_parts = nested_field.split('.')
                        
                        for part in field_parts[:-1]:
                            if part not in current_level:
                                current_level[part] = {}
                            current_level = current_level[part]
                        
                        current_level[field_parts[-1]] = self.get_test_value_for_field(field_parts[-1])
                        
                        try:
                            headers = {
                                'Authorization': f'Bearer {auth_token}',
                                'Content-Type': 'application/json'
                            }
                            
                            async with aiohttp.ClientSession() as session:
                                if endpoint['method'] == 'POST':
                                    async with session.post(
                                        f"{self.base_url}{endpoint['url']}",
                                        json=test_data,
                                        headers=headers
                                    ) as response:
                                        
                                        if response.status in [200, 201]:
                                            response_data = await response.json()
                                            if self.is_nested_field_present(response_data, nested_field):
                                                result = BOLAResult(
                                                    vulnerability_type="Mass Assignment BOLA",
                                                    endpoint=endpoint['url'],
                                                    technique="Nested Sensitive Field Injection",
                                                    severity="High",
                                                    evidence=f"Nested sensitive field '{nested_field}' accepted",
                                                    object_id="N/A",
                                                    user_context=user_type
                                                )
                                                results.append(result)
                        
                        except Exception as e:
                            print(f"Error testing nested mass assignment: {e}")
        
        return results

    def is_nested_field_present(self, response_data: Dict, nested_field: str) -> bool:
        """Check if nested field is present in response"""
        current_level = response_data
        field_parts = nested_field.split('.')
        
        for part in field_parts:
            if isinstance(current_level, dict) and part in current_level:
                current_level = current_level[part]
            else:
                return False
        
        return True
```

## 3 Advanced BOLA Testing Techniques

### 3.1 Cross-Tenant Data Access Testing
```python
# Cross-Tenant BOLA Testing Tool
class CrossTenantBOLATester:
    def __init__(self, base_url: str, tenant_tokens: Dict[str, str]):
        self.base_url = base_url
        self.tenant_tokens = tenant_tokens  # { 'tenant1': token, 'tenant2': token }
        self.vulnerabilities: List[BOLAResult] = []
        
    async def test_cross_tenant_access(self, endpoints: List[Dict]) -> List[BOLAResult]:
        """Test cross-tenant data access vulnerabilities"""
        results = []
        
        for endpoint in endpoints:
            # Get objects for each tenant
            tenant_objects = {}
            for tenant, token in self.tenant_tokens.items():
                objects = await self.get_accessible_objects(endpoint, token)
                tenant_objects[tenant] = objects
            
            # Test cross-tenant access
            for source_tenant, source_token in self.tenant_tokens.items():
                for target_tenant, target_objects in tenant_objects.items():
                    if source_tenant != target_tenant:
                        for obj_id in target_objects:
                            is_accessible = await self.test_object_access(
                                endpoint, obj_id, source_token, source_tenant
                            )
                            
                            if is_accessible:
                                result = BOLAResult(
                                    vulnerability_type="Cross-Tenant BOLA",
                                    endpoint=endpoint['url'],
                                    technique="Tenant Isolation Failure",
                                    severity="Critical",
                                    evidence=f"Tenant {source_tenant} accessed {target_tenant}'s object {obj_id}",
                                    object_id=obj_id,
                                    user_context=f"{source_tenant} -> {target_tenant}"
                                )
                                results.append(result)
        
        return results

    async def test_tenant_parameter_manipulation(self, endpoints: List[Dict]) -> List[BOLAResult]:
        """Test tenant ID parameter manipulation"""
        results = []
        
        for endpoint in endpoints:
            for tenant, token in self.tenant_tokens.items():
                # Test tenant ID in URL parameters
                url_results = await self.test_url_tenant_manipulation(endpoint, token, tenant)
                results.extend(url_results)
                
                # Test tenant ID in request body
                body_results = await self.test_body_tenant_manipulation(endpoint, token, tenant)
                results.extend(body_results)
                
                # Test tenant ID in headers
                header_results = await self.test_header_tenant_manipulation(endpoint, token, tenant)
                results.extend(header_results)
        
        return results

    async def test_url_tenant_manipulation(self, endpoint: Dict, auth_token: str, tenant: str) -> List[BOLAResult]:
        """Test tenant ID manipulation in URL"""
        results = []
        
        # Get other tenants
        other_tenants = [t for t in self.tenant_tokens.keys() if t != tenant]
        
        for other_tenant in other_tenants:
            # Replace tenant ID in URL
            manipulated_url = endpoint['url'].replace(tenant, other_tenant)
            
            try:
                headers = {'Authorization': f'Bearer {auth_token}'}
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"{self.base_url}{manipulated_url}",
                        headers=headers
                    ) as response:
                        
                        if response.status == 200:
                            result = BOLAResult(
                                vulnerability_type="Cross-Tenant BOLA",
                                endpoint=endpoint['url'],
                                technique="URL Tenant ID Manipulation",
                                severity="High",
                                evidence=f"Accessed {other_tenant} data by URL manipulation",
                                object_id=other_tenant,
                                user_context=tenant
                            )
                            results.append(result)
            
            except Exception as e:
                print(f"Error testing URL tenant manipulation: {e}")
        
        return results

    async def test_shared_resource_access(self, endpoints: List[Dict]) -> List[BOLAResult]:
        """Test access to shared resources between tenants"""
        results = []
        
        shared_endpoints = [ep for ep in endpoints if ep.get('shared_resource', False)]
        
        for endpoint in shared_endpoints:
            for tenant, token in self.tenant_tokens.items():
                # Test if tenant can access shared resources they shouldn't
                is_accessible = await self.test_object_access(endpoint, 'shared', token, tenant)
                
                if is_accessible and not endpoint.get('allow_shared_access', False):
                    result = BOLAResult(
                        vulnerability_type="Cross-Tenant BOLA",
                        endpoint=endpoint['url'],
                        technique="Unauthorized Shared Resource Access",
                        severity="Medium",
                        evidence=f"Tenant {tenant} accessed restricted shared resource",
                        object_id="shared",
                        user_context=tenant
                    )
                    results.append(result)
        
        return results
```

### 3.2 Advanced Object Reference Testing
```python
# Advanced Object Reference Testing
class AdvancedObjectReferenceTester:
    def __init__(self, base_url: str, auth_tokens: Dict[str, str]):
        self.base_url = base_url
        self.auth_tokens = auth_tokens
        self.vulnerabilities: List[BOLAResult] = []
        
    async def test_encoded_references(self, endpoints: List[Dict]) -> List[BOLAResult]:
        """Test encoded/hashed object reference vulnerabilities"""
        results = []
        
        for endpoint in endpoints:
            for user_type, auth_token in self.auth_tokens.items():
                # Get accessible objects
                objects = await self.get_accessible_objects(endpoint, auth_token)
                
                for obj_id in objects:
                    # Test different encoding/decoding techniques
                    encoding_tests = [
                        self.base64_encode(obj_id),
                        self.url_encode(obj_id),
                        self.hex_encode(obj_id),
                        self.rot13_encode(obj_id)
                    ]
                    
                    for encoded_id in encoding_tests:
                        is_accessible = await self.test_object_access(
                            endpoint, encoded_id, auth_token, user_type
                        )
                        
                        if is_accessible:
                            result = BOLAResult(
                                vulnerability_type="Object Reference BOLA",
                                endpoint=endpoint['url'],
                                technique="Encoded Reference Bypass",
                                severity="Medium",
                                evidence=f"Accessed object using encoded reference: {encoded_id}",
                                object_id=obj_id,
                                user_context=user_type
                            )
                            results.append(result)
        
        return results

    async def test_temporary_references(self, endpoints: List[Dict]) -> List[BOLAResult]:
        """Test temporary object reference vulnerabilities"""
        results = []
        
        for endpoint in endpoints:
            if endpoint.get('temporary_references', False):
                for user_type, auth_token in self.auth_tokens.items():
                    # Create temporary object reference
                    temp_reference = await self.create_temporary_reference(endpoint, auth_token)
                    
                    if temp_reference:
                        # Test access with other users
                        for other_user, other_token in self.auth_tokens.items():
                            if other_user != user_type:
                                is_accessible = await self.test_object_access(
                                    endpoint, temp_reference, other_token, other_user
                                )
                                
                                if is_accessible:
                                    result = BOLAResult(
                                        vulnerability_type="Object Reference BOLA",
                                        endpoint=endpoint['url'],
                                        technique="Temporary Reference Sharing",
                                        severity="High",
                                        evidence=f"User {other_user} accessed temporary reference",
                                        object_id=temp_reference,
                                        user_context=f"{user_type} -> {other_user}"
                                    )
                                    results.append(result)
        
        return results

    def base64_encode(self, text: str) -> str:
        """Base64 encode string"""
        import base64
        return base64.b64encode(text.encode()).decode()

    def url_encode(self, text: str) -> str:
        """URL encode string"""
        from urllib.parse import quote
        return quote(text)

    def hex_encode(self, text: str) -> str:
        """Hex encode string"""
        return text.encode().hex()

    def rot13_encode(self, text: str) -> str:
        """ROT13 encode string"""
        import codecs
        return codecs.encode(text, 'rot13')

    async def create_temporary_reference(self, endpoint: Dict, auth_token: str) -> str:
        """Create a temporary object reference"""
        try:
            headers = {'Authorization': f'Bearer {auth_token}'}
            
            async with aiohttp.ClientSession() as session:
                if endpoint['method'] == 'POST':
                    async with session.post(
                        f"{self.base_url}{endpoint['url']}",
                        headers=headers,
                        json=endpoint.get('test_data', {})
                    ) as response:
                        
                        if response.status == 200:
                            data = await response.json()
                            return data.get('temp_reference') or data.get('id')
            
            return None
        
        except Exception as e:
            print(f"Error creating temporary reference: {e}")
            return None

    async def test_reference_reuse(self, endpoints: List[Dict]) -> List[BOLAResult]:
        """Test object reference reuse vulnerabilities"""
        results = []
        
        for endpoint in endpoints:
            for user_type, auth_token in self.auth_tokens.items():
                # Get used references
                used_references = await self.get_used_references(endpoint, auth_token)
                
                # Test reusing references after object deletion
                for ref in used_references:
                    # Delete the object
                    await self.delete_object(endpoint, ref, auth_token)
                    
                    # Test if reference still works
                    is_accessible = await self.test_object_access(endpoint, ref, auth_token, user_type)
                    
                    if is_accessible:
                        result = BOLAResult(
                            vulnerability_type="Object Reference BOLA",
                            endpoint=endpoint['url'],
                            technique="Reference Reuse After Deletion",
                            severity="Medium",
                            evidence=f"Reference {ref} still accessible after deletion",
                            object_id=ref,
                            user_context=user_type
                        )
                        results.append(result)
        
        return results

    async def get_used_references(self, endpoint: Dict, auth_token: str) -> List[str]:
        """Get list of used object references"""
        # Implementation depends on API structure
        return await self.get_accessible_objects(endpoint, auth_token)

    async def delete_object(self, endpoint: Dict, obj_id: str, auth_token: str) -> bool:
        """Delete an object"""
        try:
            headers = {'Authorization': f'Bearer {auth_token}'}
            delete_url = f"{self.base_url}{endpoint['url']}".replace('{id}', obj_id)
            
            async with aiohttp.ClientSession() as session:
                async with session.delete(delete_url, headers=headers) as response:
                    return response.status == 200
        
        except Exception as e:
            print(f"Error deleting object: {e}")
            return False
```

## 4 Comprehensive BOLA Testing Framework

### 4.1 Complete BOLA Testing Suite
```python
# Comprehensive BOLA Testing Framework
class ComprehensiveBOLATester:
    def __init__(self, base_url: str, test_config: Dict):
        self.base_url = base_url
        self.test_config = test_config
        self.results: List[BOLAResult] = []
        
        # Initialize testers
        self.horizontal_tester = HorizontalBOLATester(base_url, test_config['auth_tokens'])
        self.vertical_tester = VerticalBOLATester(base_url, test_config['role_tokens'])
        self.mass_assignment_tester = MassAssignmentTester(base_url, test_config['auth_tokens'])
        self.cross_tenant_tester = CrossTenantBOLATester(base_url, test_config['tenant_tokens'])
        self.object_reference_tester = AdvancedObjectReferenceTester(base_url, test_config['auth_tokens'])
        
    async def run_comprehensive_tests(self, endpoints: List[Dict]) -> Dict[str, Any]:
        """Run comprehensive BOLA testing suite"""
        test_results = {
            'horizontal_bola': [],
            'vertical_bola': [],
            'mass_assignment': [],
            'cross_tenant': [],
            'object_reference': [],
            'business_logic': []
        }
        
        # Run all test types
        print("Running Horizontal BOLA tests...")
        horizontal_results = await self.horizontal_tester.test_user_object_access(endpoints)
        test_results['horizontal_bola'].extend(horizontal_results)
        
        print("Running Vertical BOLA tests...")
        vertical_results = await self.vertical_tester.test_privilege_escalation(endpoints)
        test_results['vertical_bola'].extend(vertical_results)
        
        print("Running Mass Assignment tests...")
        mass_results = await self.mass_assignment_tester.test_mass_assignment(endpoints)
        test_results['mass_assignment'].extend(mass_results)
        
        print("Running Cross-Tenant tests...")
        cross_tenant_results = await self.cross_tenant_tester.test_cross_tenant_access(endpoints)
        test_results['cross_tenant'].extend(cross_tenant_results)
        
        print("Running Object Reference tests...")
        object_ref_results = await self.object_reference_tester.test_encoded_references(endpoints)
        test_results['object_reference'].extend(object_ref_results)
        
        print("Running Business Logic tests...")
        business_logic_results = await self.test_business_logic_bypass(endpoints)
        test_results['business_logic'].extend(business_logic_results)
        
        # Generate comprehensive report
        report = await self.generate_comprehensive_report(test_results)
        
        return report

    async def test_business_logic_bypass(self, endpoints: List[Dict]) -> List[BOLAResult]:
        """Test business logic bypass vulnerabilities"""
        results = []
        
        for endpoint in endpoints:
            if endpoint.get('business_logic_rules'):
                for user_type, auth_token in self.test_config['auth_tokens'].items():
                    logic_results = await self.test_endpoint_business_logic(endpoint, auth_token, user_type)
                    results.extend(logic_results)
        
        return results

    async def test_endpoint_business_logic(self, endpoint: Dict, auth_token: str, user_type: str) -> List[BOLAResult]:
        """Test business logic for specific endpoint"""
        results = []
        
        rules = endpoint.get('business_logic_rules', [])
        
        for rule in rules:
            if rule['type'] == 'ownership':
                ownership_results = await self.test_ownership_bypass(endpoint, auth_token, user_type, rule)
                results.extend(ownership_results)
            
            elif rule['type'] == 'workflow':
                workflow_results = await self.test_workflow_bypass(endpoint, auth_token, user_type, rule)
                results.extend(workflow_results)
            
            elif rule['type'] == 'state':
                state_results = await self.test_state_bypass(endpoint, auth_token, user_type, rule)
                results.extend(state_results)
        
        return results

    async def test_ownership_bypass(self, endpoint: Dict, auth_token: str, user_type: str, rule: Dict) -> List[BOLAResult]:
        """Test ownership validation bypass"""
        results = []
        
        # Get objects owned by other users
        other_objects = await self.get_other_users_objects(endpoint, auth_token, user_type)
        
        for obj_id in other_objects:
            # Test if current user can modify other users' objects
            can_modify = await self.test_object_modification(endpoint, obj_id, auth_token)
            
            if can_modify:
                result = BOLAResult(
                    vulnerability_type="Business Logic BOLA",
                    endpoint=endpoint['url'],
                    technique="Ownership Validation Bypass",
                    severity="High",
                    evidence=f"User {user_type} modified object {obj_id} owned by another user",
                    object_id=obj_id,
                    user_context=user_type
                )
                results.append(result)
        
        return results

    async def test_workflow_bypass(self, endpoint: Dict, auth_token: str, user_type: str, rule: Dict) -> List[BOLAResult]:
        """Test workflow bypass vulnerabilities"""
        results = []
        
        # Test skipping workflow steps
        workflow_steps = rule.get('steps', [])
        
        for i, step in enumerate(workflow_steps):
            if i > 0:  # Skip first step
                # Test accessing later steps without completing previous ones
                is_accessible = await self.test_workflow_step_access(endpoint, step, auth_token, user_type)
                
                if is_accessible:
                    result = BOLAResult(
                        vulnerability_type="Business Logic BOLA",
                        endpoint=endpoint['url'],
                        technique="Workflow Step Bypass",
                        severity="Medium",
                        evidence=f"User {user_type} accessed workflow step {step} without prerequisites",
                        object_id=step,
                        user_context=user_type
                    )
                    results.append(result)
        
        return results

    async def test_state_bypass(self, endpoint: Dict, auth_token: str, user_type: str, rule: Dict) -> List[BOLAResult]:
        """Test state validation bypass"""
        results = []
        
        valid_states = rule.get('valid_states', [])
        invalid_states = rule.get('invalid_states', [])
        
        for state in invalid_states:
            # Test setting invalid states
            can_set_state = await self.test_state_modification(endpoint, state, auth_token, user_type)
            
            if can_set_state:
                result = BOLAResult(
                    vulnerability_type="Business Logic BOLA",
                    endpoint=endpoint['url'],
                    technique="State Validation Bypass",
                    severity="Medium",
                    evidence=f"User {user_type} set invalid state: {state}",
                    object_id=state,
                    user_context=user_type
                )
                results.append(result)
        
        return results

    async def get_other_users_objects(self, endpoint: Dict, auth_token: str, current_user: str) -> List[str]:
        """Get objects owned by other users"""
        # Implementation depends on API structure
        all_objects = await self.horizontal_tester.get_accessible_objects(endpoint, auth_token)
        user_objects = await self.get_user_objects(endpoint, auth_token, current_user)
        
        return [obj for obj in all_objects if obj not in user_objects]

    async def get_user_objects(self, endpoint: Dict, auth_token: str, user: str) -> List[str]:
        """Get objects specifically owned by user"""
        # This would typically require API-specific implementation
        return await self.horizontal_tester.get_accessible_objects(endpoint, auth_token)

    async def test_object_modification(self, endpoint: Dict, obj_id: str, auth_token: str) -> bool:
        """Test if object can be modified"""
        try:
            headers = {
                'Authorization': f'Bearer {auth_token}',
                'Content-Type': 'application/json'
            }
            
            test_data = endpoint.get('test_data', {}).copy()
            
            async with aiohttp.ClientSession() as session:
                if endpoint['method'] == 'PUT':
                    url = f"{self.base_url}{endpoint['url']}".replace('{id}', obj_id)
                    async with session.put(url, json=test_data, headers=headers) as response:
                        return response.status == 200
                
                elif endpoint['method'] == 'PATCH':
                    url = f"{self.base_url}{endpoint['url']}".replace('{id}', obj_id)
                    async with session.patch(url, json=test_data, headers=headers) as response:
                        return response.status == 200
            
            return False
        
        except Exception as e:
            print(f"Error testing object modification: {e}")
            return False

    async def generate_comprehensive_report(self, test_results: Dict[str, List[BOLAResult]]) -> Dict[str, Any]:
        """Generate comprehensive BOLA testing report"""
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
            'risk_analysis': await self.perform_risk_analysis(test_results)
        }
        
        return report

    def calculate_overall_risk(self, severity_counts: Dict[str, int]) -> str:
        """Calculate overall risk level"""
        risk_score = (
            severity_counts['Critical'] * 10 +
            severity_counts['High'] * 7 +
            severity_counts['Medium'] * 4 +
            severity_counts['Low'] * 1
        )
        
        if risk_score >= 50:
            return 'Critical'
        elif risk_score >= 30:
            return 'High'
        elif risk_score >= 15:
            return 'Medium'
        else:
            return 'Low'

    def generate_recommendations(self, test_results: Dict[str, List[BOLAResult]]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if test_results['horizontal_bola']:
            recommendations.extend([
                "Implement proper user-based access controls",
                "Validate object ownership for all object operations",
                "Use user context in authorization decisions",
                "Implement row-level security in database"
            ])
        
        if test_results['vertical_bola']:
            recommendations.extend([
                "Implement role-based access control (RBAC)",
                "Validate user privileges for sensitive operations",
                "Use attribute-based access control (ABAC) for complex rules",
                "Implement proper session management"
            ])
        
        if test_results['mass_assignment']:
            recommendations.extend([
                "Use allow-lists for API input parameters",
                "Implement proper data validation and sanitization",
                "Use read-only fields for sensitive attributes",
                "Implement DTO pattern with explicit field mapping"
            ])
        
        if test_results['cross_tenant']:
            recommendations.extend([
                "Implement proper tenant isolation",
                "Use tenant context in all database queries",
                "Validate tenant ownership for cross-tenant operations",
                "Implement resource-based access control"
            ])
        
        if test_results['business_logic']:
            recommendations.extend([
                "Implement business logic validation layers",
                "Use state machines for workflow management",
                "Validate business rules server-side",
                "Implement comprehensive audit logging"
            ])
        
        return recommendations

    async def perform_risk_analysis(self, test_results: Dict[str, List[BOLAResult]]) -> Dict[str, Any]:
        """Perform detailed risk analysis"""
        risk_analysis = {
            'high_risk_endpoints': [],
            'common_vulnerability_patterns': [],
            'exploitation_complexity': {},
            'business_impact': {}
        }
        
        # Identify high-risk endpoints
        endpoint_vulnerabilities = {}
        for category, results in test_results.items():
            for result in results:
                endpoint = result.endpoint
                if endpoint not in endpoint_vulnerabilities:
                    endpoint_vulnerabilities[endpoint] = []
                endpoint_vulnerabilities[endpoint].append(result)
        
        for endpoint, vulnerabilities in endpoint_vulnerabilities.items():
            critical_count = sum(1 for v in vulnerabilities if v.severity == 'Critical')
            high_count = sum(1 for v in vulnerabilities if v.severity == 'High')
            
            if critical_count > 0 or high_count >= 2:
                risk_analysis['high_risk_endpoints'].append({
                    'endpoint': endpoint,
                    'critical_vulnerabilities': critical_count,
                    'high_vulnerabilities': high_count,
                    'total_vulnerabilities': len(vulnerabilities)
                })
        
        return risk_analysis

# Usage Example
async def main():
    # Test configuration
    test_config = {
        'auth_tokens': {
            'user1': 'token_user1',
            'user2': 'token_user2'
        },
        'role_tokens': {
            'user': 'token_user',
            'admin': 'token_admin'
        },
        'tenant_tokens': {
            'tenant1': 'token_tenant1',
            'tenant2': 'token_tenant2'
        }
    }
    
    # API endpoints to test
    endpoints = [
        {
            'url': '/api/users/{id}',
            'method': 'GET',
            'id_field': 'id'
        },
        {
            'url': '/api/orders/{id}',
            'method': 'GET',
            'id_field': 'order_id'
        },
        {
            'url': '/api/admin/users',
            'method': 'POST',
            'admin_only': True,
            'test_data': {'username': 'test', 'email': 'test@example.com'}
        }
    ]
    
    # Run comprehensive testing
    tester = ComprehensiveBOLATester('https://api.example.com', test_config)
    report = await tester.run_comprehensive_tests(endpoints)
    
    print(json.dumps(report, indent=2, default=lambda x: x.__dict__))

# Run the comprehensive BOLA tester
# asyncio.run(main())
```

## 5 BOLA Prevention and Mitigation

### 5.1 Secure Authorization Implementation
```python
# Secure Authorization Framework
class SecureAuthorization:
    def __init__(self):
        self.access_controls = {}
        
    def implement_proper_authorization(self) -> Dict[str, Any]:
        """Implement secure authorization patterns"""
        patterns = {
            'user_based_access': [
                'Always validate user context',
                'Use user ID from authenticated session',
                'Implement ownership checks for all operations',
                'Use parameterized queries with user context'
            ],
            'role_based_access': [
                'Implement RBAC with clear role definitions',
                'Validate roles for sensitive operations',
                'Use role hierarchies properly',
                'Implement least privilege principle'
            ],
            'resource_based_access': [
                'Use resource-based access control',
                'Implement attribute-based access control (ABAC)',
                'Validate resource ownership',
                'Use policy-based authorization'
            ]
        }
        return patterns

    def create_secure_object_reference(self) -> Dict[str, Any]:
        """Create secure object reference patterns"""
        secure_patterns = {
            'non_predictable_ids': [
                'Use UUIDs instead of sequential IDs',
                'Implement proper random ID generation',
                'Use cryptographically secure random generators',
                'Avoid exposing internal database IDs'
            ],
            'encoded_references': [
                'Use signed object references',
                'Implement reference expiration',
                'Use one-time use tokens for sensitive operations',
                'Implement proper reference validation'
            ],
            'access_tokens': [
                'Use short-lived access tokens',
                'Implement token scope validation',
                'Use JWT with proper claims',
                'Implement token revocation'
            ]
        }
        return secure_patterns

    def implement_access_control_checks(self) -> List[str]:
        """Implement comprehensive access control checks"""
        checks = [
            # Pre-operation checks
            "Validate user authentication",
            "Check user permissions for operation",
            "Verify object ownership",
            "Validate business rules",
            
            # During operation checks
            "Use row-level security",
            "Implement query filters",
            "Validate input parameters",
            "Check rate limits",
            
            # Post-operation checks
            "Audit all access attempts",
            "Log security events",
            "Monitor for suspicious patterns",
            "Implement alerting for violations"
        ]
        return checks
```

This comprehensive BOLA testing framework provides extensive coverage for identifying and exploiting Broken Object Level Authorization vulnerabilities in APIs. The framework includes horizontal and vertical privilege escalation testing, mass assignment vulnerability detection, cross-tenant access testing, and advanced object reference manipulation techniques. It also provides detailed reporting and security recommendations for mitigation.