# ULTIMATE BROKEN ACCESS CONTROL CHECKLIST (v1.0)

### Comprehensive Methodology for Access Control Vulnerability Testing

### 🌐 RECONNAISSANCE PHASE

    - Identify all user roles and privilege levels
    - Map all API endpoints requiring authentication
    - Document all sensitive operations (CRUD)
    - Identify IDOR (Insecure Direct Object Reference) candidates
    - Locate administrative interfaces
    - Find UUIDs/GUIDs in requests
    - Identify sequential IDs
    - Document all user-accessible parameters
    - Find hidden API endpoints via fuzzing
    - Identify JWT/access token usage

### 🔍 BASIC TESTING VECTORS

#### Horizontal Privilege Escalation

    - Test user ID swapping in requests
    - Verify account number manipulation
    - Check email/username parameter tampering
    - Test session token reuse across accounts
    - Verify access to other users' resources
    - Check UUID prediction
    - Test incrementing/decrementing IDs
    - Verify parameter pollution in auth flows
    - Check cached authorization responses
    - Test concurrent request race conditions

#### Vertical Privilege Escalation

    - Test forced browsing to admin endpoints
    - Verify role parameter tampering
    - Check JWT role claims manipulation
    - Test cookie modification for admin access
    - Verify hidden admin functionality
    - Check API version privilege differences
    - Test mobile/desktop privilege differences
    - Verify user-type switching
    - Check referral header manipulation
    - Test user-agent based privilege changes

### 🛠️ TESTING METHODOLOGIES

#### IDOR Techniques

    - Test numeric ID replacement
    - Verify UUID replacement
    - Check filename access
    - Test hash cracking (if used as IDs)
    - Verify encoded/encrypted ID prediction
    - Check time-based ID prediction
    - Test parameter substitution
    - Verify batch ID requests
    - Check GraphQL node fields
    - Test RESTful endpoint manipulation

#### Session Testing

    - Test session fixation
    - Verify concurrent sessions
    - Check session expiration
    - Test cookie attributes (Secure/HttpOnly)
    - Verify session invalidation on logout
    - Check JWT expiration validation
    - Test JWT signature verification
    - Verify refresh token abuse
    - Check CSRF token validation
    - Test OAuth token hijacking

### ⚙️ FUNCTIONAL TESTING

#### UI/Workflow Testing

    - Test hidden UI elements (enable disabled buttons)
    - Verify disabled functionality activation
    - Check client-side authorization bypass
    - Test direct API access bypassing UI
    - Verify multi-step workflow skipping
    - Check "returnUrl" parameter abuse
    - Test deep link access
    - Verify mobile/desktop view differences
    - Check cached view access
    - Test offline functionality access

#### API Testing

    - Test HTTP method override (POST->PUT/DELETE)
    - Verify endpoint guessing (admin/v1 vs user/v1)
    - Check GraphQL introspection
    - Test REST endpoint fuzzing
    - Verify bulk operations access
    - Check mass assignment vulnerabilities
    - Test parameter pollution in APIs
    - Verify WebSocket authorization
    - Check gRPC service authorization
    - Test serverless function triggers

### 🛡️ DEFENSE BYPASS TECHNIQUES

#### Request Manipulation

    - Test header injection (X-Original-URL)
    - Verify HTTP verb tampering
    - Check path normalization bypass
    - Test encoded path traversal
    - Verify host header manipulation
    - Check referrer header abuse
    - Test origin header spoofing
    - Verify CORS misconfiguration
    - Check HTTP request smuggling
    - Test chunked encoding abuse

#### Token Manipulation

    - Test JWT alg:none attack
    - Verify JWT kid injection
    - Check JWT expired token reuse
    - Test JWT claim deletion
    - Verify JWT signature stripping
    - Check OAuth token reuse
    - Test OAuth implicit flow issues
    - Verify OAuth scope escalation
    - Check SAML assertion manipulation
    - Test OpenID connect flaws

### 📊 IMPACT ANALYSIS

#### Data Exposure

    - Verify PII access
    - Check financial data access
    - Test health record access
    - Verify credential access
    - Check intellectual property access
    - Test audit log access
    - Verify configuration access
    - Check backup file access
    - Test encryption key access
    -  Verify source code access

#### System Impact

    - Test account takeover
    - Verify data modification
    - Check data deletion
    - Test service disruption
    - Verify privilege persistence
    - Check billing manipulation
    - Test quota bypass
    - Verify rate limit bypass
    - Check automated process abuse
    - Test infrastructure access

### 🧠 MITIGATION STRATEGIES

#### Prevention

    - Implement proper role-based access control
    - Use attribute-based access control where needed
    - Enforce mandatory access control for sensitive operations
    - Implement resource-based permissions
    - Apply principle of least privilege
    - Use centralized authorization logic
    - Implement proper session management
    - Enforce strong token validation
    - Apply access control at multiple layers
    - Implement proper error handling

#### Detection

    - Monitor for abnormal access patterns
    - Implement user behavior analytics
    - Detect horizontal privilege escalation attempts
    - Monitor for vertical privilege escalation
    - Detect brute force ID guessing
    - Monitor for abnormal parameter values
    - Implement sensitive operation logging
    - Detect session anomalies
    - Monitor token reuse
    - Detect authorization bypass patterns

### 📝 REPORTING

    - Document vulnerable endpoints
    - Record successful escalation paths
    - Note sensitive data accessed
    - Document business impact
    - Record bypass techniques
    - Note detection avoidance methods
    - Document potential attack chains
    - Record remediation difficulty
    - Note compliance implications
    - Provide prioritized remediation steps
