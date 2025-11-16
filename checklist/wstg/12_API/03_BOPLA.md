
# 🔐 API SECURITY TESTING | BROKEN OBJECT PROPERTY LEVEL AUTHORIZATION (BOPLA)

## 1 Comprehensive BOPLA Testing Methodology

### 1.1 BOPLA Testing Framework
```yaml
BOPLA_Testing_Framework:
  Identification_Phase:
    - Object property enumeration and analysis
    - API endpoint property mapping
    - Property sensitivity classification
    - User role and property access assessment
    - Property ownership relationships mapping
    - Direct property reference identification
    - Indirect property reference discovery

  Exploitation_Phase:
    - Property-level horizontal privilege escalation
    - Property-level vertical privilege escalation
    - Sensitive property exposure testing
    - Property mass assignment vulnerability testing
    - Insecure direct property reference (IDPR)
    - Property-based business logic bypass testing

  Validation_Phase:
    - Property-level authorization verification
    - Property access control rule validation
    - Property visibility security testing
    - Property modification permission testing
    - Property-based rate limiting effectiveness
    - Property validation mechanism testing
```

### 1.2 BOPLA Attack Vectors
- **Direct Property References:**
  - Property name manipulation
  - Nested property access testing
  - Property value overwrite testing
  - Property reference in URL parameters
  - Property reference in request body
  - Property reference in headers

- **Indirect Property References:**
  - Mapped property references
  - Encoded property identifiers
  - Property alias manipulation
  - Property path traversal
  - Property name prediction
  - Property reference in responses

## 2 BOPLA Testing Techniques

### 2.1 Property-Level Horizontal Privilege Escalation Testing
```python
# Property-Level Horizontal BOPLA Testing Tool
import requests
import json
from typing import Dict, List, Any, Set
from dataclasses import dataclass
import asyncio
import aiohttp

@dataclass
class BOPLAResult:
    vulnerability_type: str
    endpoint: str
    property_name: str
    technique: str
    severity: str
    evidence: str
    user_context: str
    property_value: Any

class PropertyHorizontalTester:
    def __init__(self, base_url: str, auth_tokens: Dict[str, str]):
        self.base_url = base_url
        self.auth_tokens = auth_tokens
        self.vulnerabilities: List[BOPLAResult] = []
        self.sensitive_properties = [
            'email', 'password', 'ssn', 'credit_card', 'salary',
            'address', 'phone', 'birth_date', 'security_question',
            'api_key', 'access_token', 'private_key'
        ]
        
    async def test_property_access_control(self, endpoints: List[Dict]) -> List[BOPLAResult]:
        """Test horizontal property access control between users"""
        results = []
        
        for endpoint in endpoints:
            # Test with different user contexts
            for user_type, auth_token in self.auth_tokens.items():
                # Get accessible properties for current user
                user_properties = await self.get_user_accessible_properties(endpoint, auth_token, user_type)
                
                # Test accessing other users' sensitive properties
                for other_user, other_token in self.auth_tokens.items():
                    if other_user != user_type:
                        other_properties = await self.get_user_accessible_properties(endpoint, other_token, other_user)
                        
                        for prop_name, prop_value in other_properties.items():
                            if prop_name in self.sensitive_properties:
                                is_accessible = await self.test_property_access(
                                    endpoint, prop_name, auth_token, user_type
                                )
                                
                                if is_accessible:
                                    result = BOPLAResult(
                                        vulnerability_type="Horizontal BOPLA",
                                        endpoint=endpoint['url'],
                                        property_name=prop_name,
                                        technique="Cross-User Property Access",
                                        severity="High",
                                        evidence=f"User {user_type} accessed {other_user}'s property {prop_name}",
                                        user_context=f"{user_type} -> {other_user}",
                                        property_value=prop_value
                                    )
                                    results.append(result)
        
        return results

    async def test_property_enumeration(self, endpoints: List[Dict]) -> List[BOPLAResult]:
        """Test property name enumeration vulnerabilities"""
        results = []
        
        common_properties = [
            'id', 'uuid', 'created_at', 'updated_at', 'deleted_at',
            'user_id', 'owner_id', 'created_by', 'modified_by',
            'email', 'username', 'password_hash', 'role', 'permissions'
        ]
        
        for endpoint in endpoints:
            for user_type, auth_token in self.auth_tokens.items():
                # Test common property names
                for prop_name in common_properties:
                    exists = await self.test_property_existence(endpoint, prop_name, auth_token)
                    
                    if exists:
                        result = BOPLAResult(
                            vulnerability_type="Property Enumeration",
                            endpoint=endpoint['url'],
                            property_name=prop_name,
                            technique="Property Name Prediction",
                            severity="Medium",
                            evidence=f"Discovered property {prop_name} through enumeration",
                            user_context=user_type,
                            property_value="EXISTS"
                        )
                        results.append(result)
        
        return results

    async def test_nested_property_access(self, endpoints: List[Dict]) -> List[BOPLAResult]:
        """Test nested property access vulnerabilities"""
        results = []
        
        nested_properties = [
            'user.email', 'profile.ssn', 'account.balance',
            'metadata.private_key', 'settings.api_key',
            'personal_data.phone_number', 'financial_info.salary'
        ]
        
        for endpoint in endpoints:
            for user_type, auth_token in self.auth_tokens.items():
                for nested_prop in nested_properties:
                    is_accessible = await self.test_nested_property_read(
                        endpoint, nested_prop, auth_token
                    )
                    
                    if is_accessible:
                        result = BOPLAResult(
                            vulnerability_type="Nested Property BOPLA",
                            endpoint=endpoint['url'],
                            property_name=nested_prop,
                            technique="Nested Property Access",
                            severity="High",
                            evidence=f"Accessed nested property {nested_prop}",
                            user_context=user_type,
                            property_value="ACCESSIBLE"
                        )
                        results.append(result)
        
        return results

    async def get_user_accessible_properties(self, endpoint: Dict, auth_token: str, user_type: str) -> Dict[str, Any]:
        """Get properties accessible to the user"""
        properties = {}
        
        try:
            headers = {'Authorization': f'Bearer {auth_token}'}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}{endpoint['url']}",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        properties = self.extract_all_properties(data)
        
        except Exception as e:
            print(f"Error getting accessible properties: {e}")
        
        return properties

    async def test_property_access(self, endpoint: Dict, property_name: str, auth_token: str, user_type: str) -> bool:
        """Test if property is accessible with given auth token"""
        try:
            headers = {'Authorization': f'Bearer {auth_token}'}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}{endpoint['url']}",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self.is_property_present(data, property_name)
        
        except Exception as e:
            print(f"Error testing property access: {e}")
        
        return False

    async def test_property_existence(self, endpoint: Dict, property_name: str, auth_token: str) -> bool:
        """Test if property exists in response"""
        return await self.test_property_access(endpoint, property_name, auth_token, "tester")

    async def test_nested_property_read(self, endpoint: Dict, nested_path: str, auth_token: str) -> bool:
        """Test if nested property is accessible"""
        try:
            headers = {'Authorization': f'Bearer {auth_token}'}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}{endpoint['url']}",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self.get_nested_property(data, nested_path) is not None
        
        except Exception as e:
            print(f"Error testing nested property access: {e}")
        
        return False

    def extract_all_properties(self, data: Any, prefix: str = "") -> Dict[str, Any]:
        """Extract all properties from API response"""
        properties = {}
        
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, (dict, list)):
                    properties.update(self.extract_all_properties(value, full_key))
                else:
                    properties[full_key] = value
        elif isinstance(data, list):
            for i, item in enumerate(data):
                properties.update(self.extract_all_properties(item, f"{prefix}[{i}]"))
        
        return properties

    def is_property_present(self, data: Any, property_name: str) -> bool:
        """Check if property is present in data"""
        return self.get_nested_property(data, property_name) is not None

    def get_nested_property(self, data: Any, path: str) -> Any:
        """Get nested property value using dot notation"""
        keys = path.split('.')
        current = data
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        
        return current
```

### 2.2 Property-Level Vertical Privilege Escalation Testing
```python
# Property-Level Vertical BOPLA Testing Tool
class PropertyVerticalTester:
    def __init__(self, base_url: str, role_tokens: Dict[str, str]):
        self.base_url = base_url
        self.role_tokens = role_tokens
        self.vulnerabilities: List[BOPLAResult] = []
        self.role_specific_properties = {
            'admin': ['permissions', 'role', 'is_admin', 'system_access'],
            'moderator': ['moderation_powers', 'content_access'],
            'user': ['personal_data', 'preferences']
        }
        
    async def test_property_privilege_escalation(self, endpoints: List[Dict]) -> List[BOPLAResult]:
        """Test vertical property privilege escalation"""
        results = []
        
        for endpoint in endpoints:
            # Test lower privilege accessing higher privilege properties
            for lower_role, lower_token in self.role_tokens.items():
                for higher_role, higher_token in self.role_tokens.items():
                    if self.get_privilege_level(lower_role) < self.get_privilege_level(higher_role):
                        higher_properties = await self.get_role_specific_properties(
                            endpoint, higher_token, higher_role
                        )
                        
                        for prop_name, prop_value in higher_properties.items():
                            if prop_name in self.role_specific_properties.get(higher_role, []):
                                is_accessible = await self.test_property_access(
                                    endpoint, prop_name, lower_token, lower_role
                                )
                                
                                if is_accessible:
                                    result = BOPLAResult(
                                        vulnerability_type="Vertical BOPLA",
                                        endpoint=endpoint['url'],
                                        property_name=prop_name,
                                        technique="Property Privilege Escalation",
                                        severity="Critical",
                                        evidence=f"{lower_role} accessed {higher_role}'s property {prop_name}",
                                        user_context=f"{lower_role} -> {higher_role}",
                                        property_value=prop_value
                                    )
                                    results.append(result)
        
        return results

    async def test_admin_property_access(self, endpoints: List[Dict]) -> List[BOPLAResult]:
        """Test access to admin-only properties"""
        results = []
        
        admin_token = self.role_tokens.get('admin')
        if not admin_token:
            return results
        
        # Get admin-accessible properties
        admin_properties = {}
        for endpoint in endpoints:
            if endpoint.get('admin_only', False):
                properties = await self.get_user_accessible_properties(endpoint, admin_token, 'admin')
                admin_properties[endpoint['url']] = properties
        
        # Test non-admin access to admin properties
        for endpoint_url, properties in admin_properties.items():
            for prop_name, prop_value in properties.items():
                for role, token in self.role_tokens.items():
                    if role != 'admin':
                        is_accessible = await self.test_property_access(
                            {'url': endpoint_url}, prop_name, token, role
                        )
                        
                        if is_accessible:
                            result = BOPLAResult(
                                vulnerability_type="Vertical BOPLA",
                                endpoint=endpoint_url,
                                property_name=prop_name,
                                technique="Admin Property Access",
                                severity="Critical",
                                evidence=f"{role} accessed admin property {prop_name}",
                                user_context=f"{role} -> admin",
                                property_value=prop_value
                            )
                            results.append(result)
        
        return results

    async def test_property_write_escalation(self, endpoints: List[Dict]) -> List[BOPLAResult]:
        """Test property write privilege escalation"""
        results = []
        
        sensitive_write_properties = [
            'role', 'permissions', 'is_active', 'is_admin',
            'balance', 'credit_limit', 'access_level'
        ]
        
        for endpoint in endpoints:
            if endpoint.get('method') in ['POST', 'PUT', 'PATCH']:
                for role, token in self.role_tokens.items():
                    for prop_name in sensitive_write_properties:
                        can_write = await self.test_property_write(
                            endpoint, prop_name, token, role
                        )
                        
                        if can_write and not self.can_role_write_property(role, prop_name):
                            result = BOPLAResult(
                                vulnerability_type="Vertical BOPLA",
                                endpoint=endpoint['url'],
                                property_name=prop_name,
                                technique="Property Write Escalation",
                                severity="High",
                                evidence=f"{role} can write to restricted property {prop_name}",
                                user_context=role,
                                property_value="WRITE_ACCESS"
                            )
                            results.append(result)
        
        return results

    async def get_role_specific_properties(self, endpoint: Dict, auth_token: str, role: str) -> Dict[str, Any]:
        """Get properties specific to a role"""
        return await self.get_user_accessible_properties(endpoint, auth_token, role)

    async def test_property_write(self, endpoint: Dict, property_name: str, auth_token: str, role: str) -> bool:
        """Test if property can be written to"""
        try:
            headers = {
                'Authorization': f'Bearer {auth_token}',
                'Content-Type': 'application/json'
            }
            
            test_data = endpoint.get('test_data', {}).copy()
            test_data[property_name] = self.get_test_value_for_property(property_name)
            
            async with aiohttp.ClientSession() as session:
                if endpoint['method'] == 'POST':
                    async with session.post(
                        f"{self.base_url}{endpoint['url']}",
                        json=test_data,
                        headers=headers
                    ) as response:
                        return response.status in [200, 201]
                
                elif endpoint['method'] == 'PUT':
                    async with session.put(
                        f"{self.base_url}{endpoint['url']}",
                        json=test_data,
                        headers=headers
                    ) as response:
                        return response.status == 200
        
        except Exception as e:
            print(f"Error testing property write: {e}")
        
        return False

    def can_role_write_property(self, role: str, property_name: str) -> bool:
        """Check if role should be able to write to property"""
        role_write_permissions = {
            'admin': ['role', 'permissions', 'is_admin', 'balance'],
            'user': ['personal_data', 'preferences']
        }
        return property_name in role_write_permissions.get(role, [])

    def get_privilege_level(self, role: str) -> int:
        """Get numeric privilege level for role"""
        privilege_levels = {
            'user': 1,
            'moderator': 2,
            'admin': 3,
            'superadmin': 4
        }
        return privilege_levels.get(role, 0)

    async def get_user_accessible_properties(self, endpoint: Dict, auth_token: str, user_type: str) -> Dict[str, Any]:
        """Get properties accessible to the user"""
        properties = {}
        
        try:
            headers = {'Authorization': f'Bearer {auth_token}'}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}{endpoint['url']}",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        properties = self.extract_all_properties(data)
        
        except Exception as e:
            print(f"Error getting accessible properties: {e}")
        
        return properties

    def extract_all_properties(self, data: Any, prefix: str = "") -> Dict[str, Any]:
        """Extract all properties from API response"""
        properties = {}
        
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, (dict, list)):
                    properties.update(self.extract_all_properties(value, full_key))
                else:
                    properties[full_key] = value
        elif isinstance(data, list):
            for i, item in enumerate(data):
                properties.update(self.extract_all_properties(item, f"{prefix}[{i}]"))
        
        return properties

    def get_test_value_for_property(self, property_name: str) -> Any:
        """Get appropriate test value for property"""
        test_values = {
            'role': 'admin',
            'permissions': ['read', 'write', 'delete'],
            'is_admin': True,
            'balance': 1000000,
            'credit_limit': 50000,
            'access_level': 'superuser'
        }
        return test_values.get(property_name, 'test_value')
```

### 2.3 Property Mass Assignment Testing
```python
# Property Mass Assignment Testing Tool
class PropertyMassAssignmentTester:
    def __init__(self, base_url: str, auth_tokens: Dict[str, str]):
        self.base_url = base_url
        self.auth_tokens = auth_tokens
        self.vulnerabilities: List[BOPLAResult] = []
        
    async def test_property_mass_assignment(self, endpoints: List[Dict]) -> List[BOPLAResult]:
        """Test property mass assignment vulnerabilities"""
        results = []
        
        sensitive_properties = [
            'role', 'is_admin', 'permissions', 'privileges',
            'user_id', 'owner_id', 'created_by', 'approved',
            'balance', 'credit_limit', 'salary', 'ssn',
            'api_key', 'access_token', 'private_key'
        ]
        
        for endpoint in endpoints:
            if endpoint.get('method') in ['POST', 'PUT', 'PATCH']:
                for user_type, auth_token in self.auth_tokens.items():
                    endpoint_results = await self.test_endpoint_property_mass_assignment(
                        endpoint, auth_token, user_type, sensitive_properties
                    )
                    results.extend(endpoint_results)
        
        return results

    async def test_endpoint_property_mass_assignment(self, endpoint: Dict, auth_token: str, 
                                                   user_type: str, sensitive_properties: List[str]) -> List[BOPLAResult]:
        """Test property mass assignment for specific endpoint"""
        results = []
        
        base_data = endpoint.get('test_data', {}).copy()
        
        for property_name in sensitive_properties:
            # Test adding sensitive property to request
            test_data = base_data.copy()
            test_data[property_name] = self.get_test_value_for_property(property_name)
            
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
                                # Check if sensitive property was accepted
                                response_data = await response.json()
                                if self.is_property_accepted(response_data, property_name, test_data[property_name]):
                                    result = BOPLAResult(
                                        vulnerability_type="Property Mass Assignment",
                                        endpoint=endpoint['url'],
                                        property_name=property_name,
                                        technique="Sensitive Property Injection",
                                        severity="High",
                                        evidence=f"Sensitive property '{property_name}' accepted in {endpoint['method']} request",
                                        user_context=user_type,
                                        property_value=test_data[property_name]
                                    )
                                    results.append(result)
            
            except Exception as e:
                print(f"Error testing property mass assignment: {e}")
        
        return results

    async def test_nested_property_mass_assignment(self, endpoints: List[Dict]) -> List[BOPLAResult]:
        """Test nested property mass assignment"""
        results = []
        
        nested_sensitive_properties = [
            'user.role', 'profile.is_admin', 'metadata.privileges',
            'settings.permissions', 'account.balance',
            'security.api_key', 'tokens.access_token'
        ]
        
        for endpoint in endpoints:
            if endpoint.get('method') in ['POST', 'PUT', 'PATCH']:
                for user_type, auth_token in self.auth_tokens.items():
                    for nested_property in nested_sensitive_properties:
                        test_data = endpoint.get('test_data', {}).copy()
                        
                        # Create nested structure
                        self.set_nested_property(test_data, nested_property, 
                                               self.get_test_value_for_nested_property(nested_property))
                        
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
                                            if self.is_nested_property_accepted(response_data, nested_property):
                                                result = BOPLAResult(
                                                    vulnerability_type="Property Mass Assignment",
                                                    endpoint=endpoint['url'],
                                                    property_name=nested_property,
                                                    technique="Nested Sensitive Property Injection",
                                                    severity="High",
                                                    evidence=f"Nested sensitive property '{nested_property}' accepted",
                                                    user_context=user_type,
                                                    property_value="INJECTED"
                                                )
                                                results.append(result)
                        
                        except Exception as e:
                            print(f"Error testing nested property mass assignment: {e}")
        
        return results

    def is_property_accepted(self, response_data: Dict, property_name: str, expected_value: Any) -> bool:
        """Check if property was accepted in response"""
        if isinstance(response_data, dict):
            return property_name in response_data and response_data[property_name] == expected_value
        return False

    def is_nested_property_accepted(self, response_data: Dict, nested_path: str) -> bool:
        """Check if nested property was accepted"""
        return self.get_nested_property(response_data, nested_path) is not None

    def set_nested_property(self, data: Dict, path: str, value: Any):
        """Set nested property value using dot notation"""
        keys = path.split('.')
        current = data
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value

    def get_nested_property(self, data: Any, path: str) -> Any:
        """Get nested property value using dot notation"""
        keys = path.split('.')
        current = data
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        
        return current

    def get_test_value_for_property(self, property_name: str) -> Any:
        """Get appropriate test value for property"""
        test_values = {
            'role': 'admin',
            'is_admin': True,
            'permissions': ['read', 'write', 'delete'],
            'balance': 1000000,
            'salary': 999999,
            'ssn': '123-45-6789',
            'api_key': 'test_api_key_12345',
            'access_token': 'test_access_token_67890'
        }
        return test_values.get(property_name, 'test_value')

    def get_test_value_for_nested_property(self, nested_path: str) -> Any:
        """Get test value for nested property"""
        return self.get_test_value_for_property(nested_path.split('.')[-1])
```

## 3 Advanced BOPLA Testing Techniques

### 3.1 Property Visibility Testing
```python
# Property Visibility Testing Tool
class PropertyVisibilityTester:
    def __init__(self, base_url: str, auth_tokens: Dict[str, str]):
        self.base_url = base_url
        self.auth_tokens = auth_tokens
        self.vulnerabilities: List[BOPLAResult] = []
        
    async def test_property_visibility(self, endpoints: List[Dict]) -> List[BOPLAResult]:
        """Test property visibility vulnerabilities"""
        results = []
        
        for endpoint in endpoints:
            # Compare property visibility across different user contexts
            all_properties = {}
            
            for user_type, auth_token in self.auth_tokens.items():
                properties = await self.get_user_accessible_properties(endpoint, auth_token, user_type)
                all_properties[user_type] = set(properties.keys())
            
            # Find properties visible to higher privileges but not lower
            for higher_user, higher_props in all_properties.items():
                for lower_user, lower_props in all_properties.items():
                    if self.get_privilege_level(lower_user) < self.get_privilege_level(higher_user):
                        extra_props = higher_props - lower_props
                        
                        for prop_name in extra_props:
                            # Test if lower privilege can access these properties
                            is_accessible = await self.test_property_access(
                                endpoint, prop_name, self.auth_tokens[lower_user], lower_user
                            )
                            
                            if is_accessible:
                                result = BOPLAResult(
                                    vulnerability_type="Property Visibility BOPLA",
                                    endpoint=endpoint['url'],
                                    property_name=prop_name,
                                    technique="Property Visibility Escalation",
                                    severity="Medium",
                                    evidence=f"User {lower_user} can see {higher_user}'s property {prop_name}",
                                    user_context=f"{lower_user} -> {higher_user}",
                                    property_value="VISIBLE"
                                )
                                results.append(result)
        
        return results

    async def test_property_leakage(self, endpoints: List[Dict]) -> List[BOPLAResult]:
        """Test property information leakage"""
        results = []
        
        for endpoint in endpoints:
            for user_type, auth_token in self.auth_tokens.items():
                properties = await self.get_user_accessible_properties(endpoint, auth_token, user_type)
                
                for prop_name, prop_value in properties.items():
                    if self.is_sensitive_property(prop_name, prop_value):
                        result = BOPLAResult(
                            vulnerability_type="Property Information Leakage",
                            endpoint=endpoint['url'],
                            property_name=prop_name,
                            technique="Sensitive Property Exposure",
                            severity="High",
                            evidence=f"Sensitive property {prop_name} exposed to {user_type}",
                            user_context=user_type,
                            property_value=str(prop_value)[:100]  # Truncate for display
                        )
                        results.append(result)
        
        return results

    def is_sensitive_property(self, prop_name: str, prop_value: Any) -> bool:
        """Check if property is sensitive"""
        sensitive_patterns = [
            'password', 'token', 'key', 'secret', 'ssn',
            'credit', 'card', 'salary', 'address', 'phone'
        ]
        
        prop_name_lower = prop_name.lower()
        return any(pattern in prop_name_lower for pattern in sensitive_patterns)

    def get_privilege_level(self, role: str) -> int:
        """Get numeric privilege level for role"""
        privilege_levels = {
            'user': 1,
            'moderator': 2,
            'admin': 3
        }
        return privilege_levels.get(role, 0)

    async def get_user_accessible_properties(self, endpoint: Dict, auth_token: str, user_type: str) -> Dict[str, Any]:
        """Get properties accessible to the user"""
        properties = {}
        
        try:
            headers = {'Authorization': f'Bearer {auth_token}'}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}{endpoint['url']}",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        properties = self.extract_all_properties(data)
        
        except Exception as e:
            print(f"Error getting accessible properties: {e}")
        
        return properties

    def extract_all_properties(self, data: Any, prefix: str = "") -> Dict[str, Any]:
        """Extract all properties from API response"""
        properties = {}
        
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, (dict, list)):
                    properties.update(self.extract_all_properties(value, full_key))
                else:
                    properties[full_key] = value
        elif isinstance(data, list):
            for i, item in enumerate(data):
                properties.update(self.extract_all_properties(item, f"{prefix}[{i}]"))
        
        return properties

    async def test_property_access(self, endpoint: Dict, property_name: str, auth_token: str, user_type: str) -> bool:
        """Test if property is accessible with given auth token"""
        try:
            headers = {'Authorization': f'Bearer {auth_token}'}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}{endpoint['url']}",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self.is_property_present(data, property_name)
        
        except Exception as e:
            print(f"Error testing property access: {e}")
        
        return False

    def is_property_present(self, data: Any, property_name: str) -> bool:
        """Check if property is present in data"""
        return self.get_nested_property(data, property_name) is not None

    def get_nested_property(self, data: Any, path: str) -> Any:
        """Get nested property value using dot notation"""
        keys = path.split('.')
        current = data
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        
        return current
```

### 3.2 Property Validation Testing
```python
# Property Validation Testing Tool
class PropertyValidationTester:
    def __init__(self, base_url: str, auth_tokens: Dict[str, str]):
        self.base_url = base_url
        self.auth_tokens = auth_tokens
        self.vulnerabilities: List[BOPLAResult] = []
        
    async def test_property_validation(self, endpoints: List[Dict]) -> List[BOPLAResult]:
        """Test property validation vulnerabilities"""
        results = []
        
        validation_tests = [
            ('email', 'invalid-email', 'Email validation'),
            ('phone', 'invalid-phone', 'Phone validation'),
            ('age', -5, 'Negative age validation'),
            ('salary', 'invalid-salary', 'Salary validation'),
            ('balance', '9999999999', 'Large number validation'),
            ('username', 'a' * 1000, 'Length validation'),
            ('permissions', ['invalid_permission'], 'Array validation')
        ]
        
        for endpoint in endpoints:
            if endpoint.get('method') in ['POST', 'PUT', 'PATCH']:
                for user_type, auth_token in self.auth_tokens.items():
                    for prop_name, invalid_value, test_type in validation_tests:
                        is_accepted = await self.test_invalid_property_value(
                            endpoint, prop_name, invalid_value, auth_token, user_type
                        )
                        
                        if is_accepted:
                            result = BOPLAResult(
                                vulnerability_type="Property Validation BOPLA",
                                endpoint=endpoint['url'],
                                property_name=prop_name,
                                technique=f"Invalid {test_type}",
                                severity="Medium",
                                evidence=f"Invalid value for {prop_name} was accepted: {invalid_value}",
                                user_context=user_type,
                                property_value=str(invalid_value)
                            )
                            results.append(result)
        
        return results

    async def test_invalid_property_value(self, endpoint: Dict, property_name: str, 
                                        invalid_value: Any, auth_token: str, user_type: str) -> bool:
        """Test if invalid property value is accepted"""
        try:
            headers = {
                'Authorization': f'Bearer {auth_token}',
                'Content-Type': 'application/json'
            }
            
            test_data = endpoint.get('test_data', {}).copy()
            test_data[property_name] = invalid_value
            
            async with aiohttp.ClientSession() as session:
                if endpoint['method'] == 'POST':
                    async with session.post(
                        f"{self.base_url}{endpoint['url']}",
                        json=test_data,
                        headers=headers
                    ) as response:
                        return response.status in [200, 201]
        
        except Exception as e:
            print(f"Error testing invalid property value: {e}")
        
        return False

    async def test_property_type_manipulation(self, endpoints: List[Dict]) -> List[BOPLAResult]:
        """Test property type manipulation vulnerabilities"""
        results = []
        
        type_manipulation_tests = [
            ('integer_property', '123', 'string_to_integer'),
            ('boolean_property', 'true', 'string_to_boolean'),
            ('array_property', 'single_value', 'string_to_array'),
            ('object_property', 'string_value', 'string_to_object')
        ]
        
        for endpoint in endpoints:
            if endpoint.get('method') in ['POST', 'PUT', 'PATCH']:
                for user_type, auth_token in self.auth_tokens.items():
                    for prop_name, wrong_type_value, manipulation_type in type_manipulation_tests:
                        is_accepted = await self.test_property_type_manipulation(
                            endpoint, prop_name, wrong_type_value, auth_token, user_type
                        )
                        
                        if is_accepted:
                            result = BOPLAResult(
                                vulnerability_type="Property Type Manipulation",
                                endpoint=endpoint['url'],
                                property_name=prop_name,
                                technique=f"Type {manipulation_type}",
                                severity="Low",
                                evidence=f"Wrong type value for {prop_name} was accepted: {wrong_type_value}",
                                user_context=user_type,
                                property_value=wrong_type_value
                            )
                            results.append(result)
        
        return results

    async def test_property_type_manipulation(self, endpoint: Dict, property_name: str, 
                                            wrong_type_value: Any, auth_token: str, user_type: str) -> bool:
        """Test if wrong type property value is accepted"""
        return await self.test_invalid_property_value(endpoint, property_name, wrong_type_value, auth_token, user_type)
```

## 4 Comprehensive BOPLA Testing Framework

### 4.1 Complete BOPLA Testing Suite
```python
# Comprehensive BOPLA Testing Framework
class ComprehensiveBOPLATester:
    def __init__(self, base_url: str, test_config: Dict):
        self.base_url = base_url
        self.test_config = test_config
        self.results: List[BOPLAResult] = []
        
        # Initialize testers
        self.horizontal_tester = PropertyHorizontalTester(base_url, test_config['auth_tokens'])
        self.vertical_tester = PropertyVerticalTester(base_url, test_config['role_tokens'])
        self.mass_assignment_tester = PropertyMassAssignmentTester(base_url, test_config['auth_tokens'])
        self.visibility_tester = PropertyVisibilityTester(base_url, test_config['auth_tokens'])
        self.validation_tester = PropertyValidationTester(base_url, test_config['auth_tokens'])
        
    async def run_comprehensive_tests(self, endpoints: List[Dict]) -> Dict[str, Any]:
        """Run comprehensive BOPLA testing suite"""
        test_results = {
            'horizontal_bopla': [],
            'vertical_bopla': [],
            'property_mass_assignment': [],
            'property_visibility': [],
            'property_validation': [],
            'property_leakage': []
        }
        
        # Run all test types
        print("Running Horizontal BOPLA tests...")
        horizontal_results = await self.horizontal_tester.test_property_access_control(endpoints)
        test_results['horizontal_bopla'].extend(horizontal_results)
        
        print("Running Vertical BOPLA tests...")
        vertical_results = await self.vertical_tester.test_property_privilege_escalation(endpoints)
        test_results['vertical_bopla'].extend(vertical_results)
        
        print("Running Property Mass Assignment tests...")
        mass_results = await self.mass_assignment_tester.test_property_mass_assignment(endpoints)
        test_results['property_mass_assignment'].extend(mass_results)
        
        print("Running Property Visibility tests...")
        visibility_results = await self.visibility_tester.test_property_visibility(endpoints)
        test_results['property_visibility'].extend(visibility_results)
        
        print("Running Property Validation tests...")
        validation_results = await self.validation_tester.test_property_validation(endpoints)
        test_results['property_validation'].extend(validation_results)
        
        print("Running Property Leakage tests...")
        leakage_results = await self.visibility_tester.test_property_leakage(endpoints)
        test_results['property_leakage'].extend(leakage_results)
        
        # Generate comprehensive report
        report = await self.generate_comprehensive_report(test_results)
        
        return report

    async def generate_comprehensive_report(self, test_results: Dict[str, List[BOPLAResult]]) -> Dict[str, Any]:
        """Generate comprehensive BOPLA testing report"""
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

    def generate_recommendations(self, test_results: Dict[str, List[BOPLAResult]]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if test_results['horizontal_bopla']:
            recommendations.extend([
                "Implement property-level access controls",
                "Validate property ownership for all property operations",
                "Use user context in property authorization decisions",
                "Implement field-level security in API responses"
            ])
        
        if test_results['vertical_bopla']:
            recommendations.extend([
                "Implement role-based property access control",
                "Validate user privileges for sensitive property operations",
                "Use attribute-based access control for property-level rules",
                "Implement proper property-level session management"
            ])
        
        if test_results['property_mass_assignment']:
            recommendations.extend([
                "Use allow-lists for API property input parameters",
                "Implement proper property validation and sanitization",
                "Use read-only fields for sensitive properties",
                "Implement property mapping with explicit field definitions"
            ])
        
        if test_results['property_visibility']:
            recommendations.extend([
                "Implement property visibility controls",
                "Use different response schemas for different user roles",
                "Validate property visibility rules server-side",
                "Implement comprehensive property audit logging"
            ])
        
        if test_results['property_validation']:
            recommendations.extend([
                "Implement strong property validation",
                "Use schema validation for all API inputs",
                "Validate property types and formats",
                "Implement input sanitization for all properties"
            ])
        
        return list(set(recommendations))  # Remove duplicates

    async def perform_risk_analysis(self, test_results: Dict[str, List[BOPLAResult]]) -> Dict[str, Any]:
        """Perform detailed risk analysis"""
        risk_analysis = {
            'high_risk_properties': [],
            'common_vulnerability_patterns': [],
            'sensitive_property_exposure': [],
            'property_level_impact': {}
        }
        
        # Identify high-risk properties
        property_vulnerabilities = {}
        for category, results in test_results.items():
            for result in results:
                prop_name = result.property_name
                if prop_name not in property_vulnerabilities:
                    property_vulnerabilities[prop_name] = []
                property_vulnerabilities[prop_name].append(result)
        
        for prop_name, vulnerabilities in property_vulnerabilities.items():
            critical_count = sum(1 for v in vulnerabilities if v.severity == 'Critical')
            high_count = sum(1 for v in vulnerabilities if v.severity == 'High')
            
            if critical_count > 0 or high_count >= 2:
                risk_analysis['high_risk_properties'].append({
                    'property': prop_name,
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
        }
    }
    
    # API endpoints to test
    endpoints = [
        {
            'url': '/api/users/{id}',
            'method': 'GET'
        },
        {
            'url': '/api/profiles/{id}',
            'method': 'GET'
        },
        {
            'url': '/api/users',
            'method': 'POST',
            'test_data': {'username': 'test', 'email': 'test@example.com'}
        }
    ]
    
    # Run comprehensive testing
    tester = ComprehensiveBOPLATester('https://api.example.com', test_config)
    report = await tester.run_comprehensive_tests(endpoints)
    
    print(json.dumps(report, indent=2, default=lambda x: x.__dict__))

# Run the comprehensive BOPLA tester
# asyncio.run(main())
```

## 5 BOPLA Prevention and Mitigation

### 5.1 Secure Property Authorization Implementation
```python
# Secure Property Authorization Framework
class SecurePropertyAuthorization:
    def __init__(self):
        self.property_access_controls = {}
        
    def implement_property_authorization(self) -> Dict[str, Any]:
        """Implement secure property authorization patterns"""
        patterns = {
            'property_based_access': [
                'Validate property-level permissions',
                'Use property ownership checks',
                'Implement property visibility rules',
                'Use property-based query filtering'
            ],
            'role_based_property_access': [
                'Implement RBAC with property-level granularity',
                'Validate roles for sensitive property operations',
                'Use role-based property visibility',
                'Implement least privilege for properties'
            ],
            'dynamic_property_filtering': [
                'Use dynamic response filtering',
                'Implement property-level data masking',
                'Use context-aware property serialization',
                'Implement conditional property inclusion'
            ]
        }
        return patterns

    def create_secure_property_handling(self) -> Dict[str, Any]:
        """Create secure property handling patterns"""
        secure_patterns = {
            'input_validation': [
                'Validate all property inputs',
                'Use schema validation for properties',
                'Implement property type checking',
                'Use allow-lists for property names'
            ],
            'output_filtering': [
                'Filter sensitive properties from responses',
                'Use different serializers for different contexts',
                'Implement property-level data redaction',
                'Use response transformers with security rules'
            ],
            'property_mapping': [
                'Use explicit property mapping',
                'Implement input/output DTO patterns',
                'Use separate models for internal and external',
                'Implement property aliasing with security'
            ]
        }
        return secure_patterns

    def implement_property_security_checks(self) -> List[str]:
        """Implement comprehensive property security checks"""
        checks = [
            # Pre-operation checks
            "Validate property-level permissions",
            "Check property ownership",
            "Verify property visibility rules",
            "Validate property input formats",
            
            # During operation checks
            "Use property-level data filtering",
            "Implement property validation middleware",
            "Apply property transformation rules",
            "Enforce property access policies",
            
            # Post-operation checks
            "Audit all property access attempts",
            "Log property-level security events",
            "Monitor for property abuse patterns",
            "Implement alerts for property violations"
        ]
        return checks
```

This comprehensive BOPLA testing framework provides extensive coverage for identifying and exploiting Broken Object Property Level Authorization vulnerabilities in APIs. The framework includes property-level horizontal and vertical privilege escalation testing, property mass assignment vulnerability detection, property visibility testing, and advanced property validation techniques. It also provides detailed reporting and security recommendations for mitigation.
