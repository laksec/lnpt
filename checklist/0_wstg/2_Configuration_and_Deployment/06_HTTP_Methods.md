# 🔍 HTTP METHODS TESTING CHECKLIST

## 2.1 Comprehensive HTTP Methods Testing

### 2.1.1 Standard HTTP Methods Testing
    - Safe Methods Testing (Should Not Change State):
      * GET: Retrieve resource representation
        - Test with sensitive operations
        - Check for side effects
        - Verify caching behavior
      * HEAD: Retrieve headers only
        - Test for information disclosure
        - Verify same headers as GET
        - Check for resource consumption

    - Unsafe Methods Testing (Can Change State):
      * POST: Create new resource
        - Test with different Content-Types
        - Verify input validation
        - Check for CSRF protection
      * PUT: Update/replace existing resource
        - Test with full resource replacement
        - Verify idempotency
        - Check for access controls
      * PATCH: Partial resource update
        - Test with JSON Patch (RFC 6902)
        - Test with JSON Merge Patch (RFC 7396)
        - Verify partial update security
      * DELETE: Remove resource
        - Test resource deletion
        - Verify authorization checks
        - Check for soft vs hard deletion

    - Other Standard Methods:
      * OPTIONS: Discover available methods
        - Test for information disclosure
        - Verify CORS preflight responses
        - Check for allowed methods listing
      * TRACE: Echo back request
        - Test for XST (Cross-Site Tracing) vulnerabilities
        - Verify TRACE method disabling
        - Check for header reflection

### 2.1.2 Extended HTTP Methods Testing
    - WebDAV Methods:
      * PROPFIND: Retrieve properties
        - Test for file system enumeration
        - Verify property exposure
      * PROPPATCH: Set properties
        - Test for unauthorized property modification
      * MKCOL: Create collection
        - Test for directory creation
      * COPY: Copy resource
        - Test for unauthorized copying
      * MOVE: Move resource
        - Test for unauthorized moving
      * LOCK: Lock resource
        - Test for denial of service
      * UNLOCK: Unlock resource
        - Test for unauthorized unlocking

    - Custom Methods:
      * SEARCH: Extended search functionality
      * BCOPY, BMOVE: Batch operations
      * SUBSCRIBE, NOTIFY: Notification methods
      * POLL: Long polling operations

### 2.1.3 HTTP Method Security Testing
    - Authentication Bypass Testing:
      * Test methods without authentication
      * Check for method-specific authentication
      * Verify authentication consistency across methods
      * Test for anonymous access to safe methods

    - Authorization Bypass Testing:
      * Test privilege escalation via different methods
      * Check for method-based access control
      * Verify role-based method restrictions
      * Test for horizontal privilege escalation

    - Input Validation Testing:
      * Test each method with malicious inputs
      * Verify validation consistency across methods
      * Check for method-specific validation rules
      * Test for parser differential attacks

### 2.1.4 Idempotency and Safety Testing
    - Idempotent Methods Verification:
      * PUT: Multiple identical requests should have same effect
      * DELETE: Multiple deletions should have same effect
      * GET, HEAD, OPTIONS: Naturally idempotent
      * Test for non-idempotent behavior in PUT/DELETE

    - Safe Methods Verification:
      * GET, HEAD, OPTIONS, TRACE should not change state
      * Test for side effects in safe methods
      * Verify read-only behavior
      * Check for state modification through safe methods

### 2.1.5 Cross-Origin Resource Sharing (CORS) Testing
    - Preflight Request Testing:
      * OPTIONS method behavior
      * Access-Control-Request-Method handling
      * Access-Control-Request-Headers validation
      * Preflight cache duration

    - CORS Method Restrictions:
      * Test allowed methods in CORS responses
      * Verify method restrictions in Access-Control-Allow-Methods
      * Check for overly permissive method allowances
      * Test complex method scenarios

### 2.1.6 HTTP Method Override Testing
    - Header-Based Override:
      * X-HTTP-Method-Override header
      * X-HTTP-Method header
      * X-METHOD-OVERRIDE header
      * Test for override functionality

    - Parameter-Based Override:
      * _method parameter (common in frameworks)
      * _http_method parameter
      * method parameter
      * Test override in GET/POST parameters

    - Override Security Implications:
      * Test for bypassing method restrictions
      * Check for WAF/security control evasion
      * Verify override authentication
      * Test for privilege escalation via override

### 2.1.7 Error Handling Testing
    - Method Not Allowed (405):
      * Test response for disallowed methods
      * Verify Allow header presence and accuracy
      * Check for information disclosure in errors
      * Test for inconsistent error handling

    - Not Implemented (501):
      * Test for unimplemented methods
      * Verify proper status code usage
      * Check for method-specific error messages
      * Test for custom method handling

    - Authentication/Authorization Errors:
      * Test method-specific error responses
      * Verify consistent error handling
      * Check for information leakage
      * Test for error message differences

### 2.1.8 Performance and Resource Testing
    - Resource Consumption:
      * Test expensive methods for DoS potential
      * Verify rate limiting per method
      * Check for method-specific resource limits
      * Test for memory exhaustion via large requests

    - Caching Behavior:
      * Test cacheability of method responses
      * Verify Cache-Control headers per method
      * Check for inappropriate caching of unsafe methods
      * Test for cache poisoning via methods

### 2.1.9 Framework-Specific Method Testing
    - REST API Method Testing:
      * Test proper RESTful method usage
      * Verify resource-oriented method mapping
      * Check for RPC-style method abuse
      * Test for overridden method behavior

    - GraphQL Method Testing:
      * POST method for queries and mutations
      * GET method for queries with parameters
      * Test for method-based access control
      * Verify GraphQL-specific method handling

    - SOAP Web Services:
      * POST method for SOAP actions
      * Test for SOAPAction header handling
      * Verify method dispatching
      * Check for WS-I compliance

### 2.1.10 Security Control Testing
    - Web Application Firewall (WAF) Testing:
      * Test WAF method filtering
      * Check for method-based rule bypass
      * Verify WAF method understanding
      * Test for false positives/negatives

    - Intrusion Detection System (IDS) Testing:
      * Test IDS method detection
      * Check for method-based evasion
      * Verify anomaly detection for unusual methods
      * Test for method rate limiting

    - API Gateway Testing:
      * Test method routing and transformation
      * Verify method-based rate limiting
      * Check for method-specific policies
      * Test for gateway method restrictions

#### Testing Methodology:
    Phase 1: Discovery
    1. OPTIONS method to discover allowed methods
    2. Test standard methods (GET, POST, PUT, DELETE, etc.)
    3. Test extended methods (WebDAV, custom)
    4. Document all available methods

    Phase 2: Security Testing
    1. Test authentication and authorization per method
    2. Check for method-based vulnerabilities
    3. Test input validation consistency
    4. Verify error handling security

    Phase 3: Advanced Testing
    1. Test method override functionality
    2. Check for parser differentials
    3. Test for security control bypass
    4. Verify business logic consistency

#### Automated Testing Tools:
    Manual Testing Tools:
    - curl: `curl -X METHOD http://target.com/resource`
    - Burp Suite Repeater with method changes
    - Postman with method selection
    - Browser developer tools

    Automated Scanners:
    - OWASP ZAP with method scanning
    - Nikto for method enumeration
    - Nmap http-methods script
    - Custom Python scripts with requests

    Specialized Tools:
    - httpx for method discovery
    - ffuf for method fuzzing
    - httpie for manual testing
    - custom method enumeration scripts

#### Common Test Cases:
    Basic Method Testing:
    curl -X OPTIONS http://target.com/api/users
    curl -X GET http://target.com/api/users/1
    curl -X POST http://target.com/api/users -d '{"name":"test"}'
    curl -X PUT http://target.com/api/users/1 -d '{"name":"updated"}'
    curl -X DELETE http://target.com/api/users/1
    curl -X TRACE http://target.com/api/users

    WebDAV Testing:
    curl -X PROPFIND http://target.com/webdav/
    curl -X MKCOL http://target.com/webdav/newfolder
    curl -X COPY http://target.com/webdav/file1 http://target.com/webdav/file2

    Method Override Testing:
    curl -X POST http://target.com/api/users -H "X-HTTP-Method-Override: DELETE"
    curl -X POST http://target.com/api/users?_method=DELETE

#### Security Headers to Check:
    - Allow: Lists allowed methods (from OPTIONS response)
    - Access-Control-Allow-Methods: CORS allowed methods
    - X-HTTP-Method-Override: Support for method overriding
    - Cache-Control: Method-specific caching directives

#### Risk Assessment Framework:
    Critical Risk:
    - TRACE method enabled with sensitive header reflection
    - PUT/DELETE methods without authentication/authorization
    - Method override allowing security control bypass
    - Administrative methods exposed publicly

    High Risk:
    - Inconsistent authentication across methods
    - Authorization bypass via different methods
    - Unsafe methods (PUT, DELETE) accepting GET parameters
    - Information disclosure through OPTIONS method

    Medium Risk:
    - Missing input validation on certain methods
    - Inconsistent error handling
    - Lack of rate limiting on expensive methods
    - Overly permissive CORS method allowances

    Low Risk:
    - Minor information disclosure in error messages
    - Missing security headers on certain methods
    - Non-standard method support without security issues

#### Protection and Hardening:
    - Method Restrictions:
      * Disable unnecessary methods (TRACE, OPTIONS, WebDAV)
      * Implement strict method whitelisting
      * Use framework security configurations
      * Configure web server method restrictions

    - Security Controls:
      * Consistent authentication across all methods
      * Proper authorization checks for unsafe methods
      * Input validation for all methods
      * Rate limiting based on method criticality

    - Monitoring and Detection:
      * Log all unsafe method usage
      * Monitor for unusual method patterns
      * Alert on administrative method usage
      * Track method-based attack attempts

#### Testing Execution Framework:
    Step 1: Method Discovery
    - Use OPTIONS to find allowed methods
    - Test common and extended methods
    - Check for method override support
    - Document method availability

    Step 2: Security Validation
    - Test authentication for each method
    - Verify authorization checks
    - Check input validation consistency
    - Test error handling security

    Step 3: Functional Testing
    - Verify method behavior matches specification
    - Test idempotency and safety
    - Check for side effects
    - Validate business logic

    Step 4: Advanced Testing
    - Test security control bypass
    - Check for parser differentials
    - Verify WAF/IDS evasion
    - Test performance implications

#### Documentation Template:
    HTTP Methods Security Assessment:
    - Target Application and Scope
    - Methodology and Tools Used
    - Discovered Methods and Functionality
    - Security Vulnerabilities Identified
    - Risk Assessment and Scoring
    - Remediation Recommendations
    - Evidence and Test Cases
    - Compliance Impact Analysis

This comprehensive HTTP methods testing checklist provides systematic testing of all HTTP method functionality, security controls, and potential vulnerabilities, ensuring thorough assessment of method handling across web applications and APIs.