# 🔍 HTTP STRICT TRANSPORT SECURITY (HSTS) TESTING CHECKLIST

## 2.2 Comprehensive HSTS Security Testing

### 2.2.1 HSTS Header Presence and Syntax Testing
    - Header Presence Testing:
      * Check for Strict-Transport-Security header in HTTPS responses
      * Verify header is only sent over HTTPS, never HTTP
      * Test all domains and subdomains for HSTS implementation
      * Check API endpoints and microservices

    - Header Syntax Validation:
      * max-age directive testing (required)
        - Test values: 0, 31536000 (1 year), 63072000 (2 years)
        - Verify max-age is present and valid
      * includeSubDomains directive testing (optional)
        - Test subdomain coverage
        - Verify wildcard and specific subdomains
      * preload directive testing (optional)
        - Check for preload readiness
        - Verify prelist requirements compliance

    - Multiple Header Testing:
      * Test for duplicate HSTS headers
      * Verify header concatenation behavior
      * Check for conflicting directives
      * Test header order and precedence

### 2.2.2 HSTS Policy Enforcement Testing
    - HTTP to HTTPS Redirection Testing:
      * Test HTTP requests are redirected to HTTPS
      * Verify redirect occurs before any data transmission
      * Check redirect status codes (301, 302, 307)
      * Test redirect chain security

    - Protocol Downgrade Prevention:
      * Test SSL stripping attacks prevention
      * Verify mixed content warnings
      * Check for HTTP links that should be HTTPS
      * Test form submission over HTTP

    - HSTS Preload List Testing:
      * Check domain presence in HSTS preload list
      * Verify preload list requirements are met
      * Test preload removal implications
      * Check for preload list propagation

### 2.2.3 Browser HSTS Behavior Testing
    - First Visit Security:
      * Test initial HTTP request behavior
      * Verify redirect efficiency
      * Check for HSTS header on first HTTPS response
      * Test initial max-age=0 scenarios

    - Subsequent Visit Security:
      * Test browser HSTS cache behavior
      * Verify automatic HTTPS upgrade
      * Check for HSTS persistence across sessions
      * Test max-age expiration behavior

    - HSTS Clear Testing:
      * Test browser HSTS clearance methods
      * Verify max-age=0 header functionality
      * Check for HSTS reset mechanisms
      * Test development environment implications

### 2.2.4 Subdomain and Scope Testing
    - includeSubDomains Directive Testing:
      * Test root domain HSTS applies to all subdomains
      * Verify www subdomain coverage
      * Check API subdomains (api., rest., graphql.)
      * Test development subdomains (dev., test., staging.)

    - Wildcard and Multi-level Subdomain Testing:
      * Test deep subdomains (a.b.example.com)
      * Verify wildcard certificate compatibility
      * Check for subdomain enumeration prevention
      * Test internationalized domain names (IDN)

    - Excluded Subdomain Testing:
      * Identify subdomains that shouldn't use HTTPS
      * Test HSTS breakage scenarios
      * Verify no-HTTPS subdomain isolation
      * Check for mixed content issues

### 2.2.5 Certificate and TLS Configuration Testing
    - Certificate Validity Testing:
      * Test with valid, trusted certificates
      * Verify certificate chain completeness
      * Check for certificate transparency
      * Test certificate revocation (OCSP, CRL)

    - TLS Configuration Compatibility:
      * Test with various TLS versions (1.2, 1.3)
      * Verify cipher suite compatibility
      * Check for weak cipher detection
      * Test with intermediate CA certificates

    - Certificate Error Handling:
      * Test browser behavior with expired certificates
      * Verify self-signed certificate rejection
      * Check for domain name mismatch errors
      * Test certificate pinning interactions

### 2.2.6 Application Integration Testing
    - Content Security Policy Integration:
      * Test CSP with HSTS compatibility
      * Verify mixed content policies
      * Check upgrade-insecure-requests directive
      * Test block-all-mixed-content directive

    - Cookie Security Integration:
      * Test Secure flag enforcement
      * Verify SameSite attribute compatibility
      * Check HttpOnly flag consistency
      * Test cookie scope with HSTS

    - Redirect Chain Testing:
      * Test multiple redirect scenarios
      * Verify HSTS header preservation
      * Check for redirect loops
      * Test cross-domain redirect security

### 2.2.7 Mobile and API Testing
    - Mobile Application Testing:
      * Test native app HSTS compliance
      * Verify WebView HSTS support
      * Check mobile browser behavior
      * Test offline application scenarios

    - API and Microservice Testing:
      * Test REST API HSTS implementation
      * Verify GraphQL endpoint security
      * Check WebSocket connections (wss://)
      * Test gRPC and other protocol endpoints

    - Third-Party Integration Testing:
      * Test CDN HSTS compatibility
      * Verify external service redirects
      * Check OAuth/OpenID Connect flows
      * Test payment gateway integrations

### 2.2.8 Security Header Integration Testing
    - Complementary Security Headers:
      * Content-Security-Policy with upgrade-insecure-requests
      * X-Content-Type-Options: nosniff
      * X-Frame-Options: DENY/SAMEORIGIN
      * X-XSS-Protection: 1; mode=block

    - Modern Security Headers:
      * Feature-Policy / Permissions-Policy
      * Referrer-Policy
      * Expect-CT
      * Report-To / Reporting-Endpoints

### 2.2.9 HSTS Deployment and Management Testing
    - Gradual Deployment Testing:
      * Test short max-age values initially
      * Verify monitoring during rollout
      * Check for breakage detection
      * Test rollback procedures

    - Policy Update Testing:
      * Test max-age extension procedures
      * Verify includeSubDomains addition
      * Check preload directive addition
      * Test policy reduction scenarios

    - Monitoring and Reporting Testing:
      * Test HSTS preload list status
      * Verify certificate transparency monitoring
      * Check for HSTS error reporting
      * Test security header monitoring tools

### 2.2.10 Advanced HSTS Attack Scenarios
    - HSTS Bypass Testing:
      * Test certificate validation bypass
      * Verify MITM attack prevention
      * Check for protocol confusion attacks
      * Test HSTS stripping techniques

    - Timing Attack Testing:
      * Test HSTS first-visit vulnerabilities
      * Verify max-age expiration attacks
      * Check for clock skew exploitation
      * Test cache poisoning scenarios

    - Domain Hijacking Testing:
      * Test HSTS preload hijack scenarios
      * Verify domain expiration implications
      * Check for registrar security requirements
      * Test DNS hijacking prevention

#### Testing Methodology:
    Phase 1: Header Validation
    1. Check HSTS header presence and syntax
    2. Verify directive correctness
    3. Test header consistency across endpoints
    4. Validate HTTPS-only header transmission

    Phase 2: Policy Enforcement
    1. Test HTTP to HTTPS redirection
    2. Verify protocol upgrade behavior
    3. Check subdomain coverage
    4. Validate browser compliance

    Phase 3: Integration Testing
    1. Test with other security headers
    2. Verify application functionality
    3. Check third-party integrations
    4. Validate mobile and API support

    Phase 4: Advanced Security
    1. Test attack scenarios
    2. Verify certificate security
    3. Check deployment safety
    4. Validate monitoring capabilities

#### Automated Testing Tools:
    Command Line Tools:
    - curl: `curl -I https://example.com`
    - hsts: Dedicated HSTS testing tools
    - testssl.sh: Comprehensive TLS/SSL testing
    - sslyze: SSL configuration analysis

    Online Testing Services:
    - SecurityHeaders.com
    - HSTS Preload List Submission
    - SSL Labs SSL Test
    - Observatory.mozilla.org

    Browser Testing:
    - Developer Tools Network tab
    - Security panel in browser devtools
    - HSTS testing browser extensions
    - Manual browser behavior testing

#### Common Test Commands:
    Basic HSTS Header Check:
    curl -I https://example.com
    curl -H "Host: example.com" https://IP_ADDRESS/

    Redirect Chain Testing:
    curl -L http://example.com
    curl -I http://example.com

    Subdomain Testing:
    curl -I https://www.example.com
    curl -I https://api.example.com
    curl -I https://sub.example.com

    Certificate Testing:
    openssl s_client -connect example.com:443
    testssl.sh example.com

#### HSTS Header Examples:
    Basic HSTS:
    Strict-Transport-Security: max-age=31536000

    With Subdomains:
    Strict-Transport-Security: max-age=31536000; includeSubDomains

    Preload Ready:
    Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

    Temporary Policy:
    Strict-Transport-Security: max-age=300

#### Risk Assessment Framework:
    Critical Risk:
    - No HSTS implementation on sensitive domains
    - HSTS with extremely short max-age
    - Missing includeSubDomains on multi-subdomain sites
    - HSTS header sent over HTTP

    High Risk:
    - Inconsistent HSTS across subdomains
    - Missing HTTP to HTTPS redirects
    - HSTS without includeSubDomains
    - Weak certificate configurations

    Medium Risk:
    - Short max-age values
    - Missing preload directive for eligible sites
    - Inconsistent security headers
    - Limited subdomain coverage

    Low Risk:
    - Minor configuration issues
    - Missing reporting endpoints
    - Non-critical subdomains excluded
    - Development environment configurations

#### Protection and Hardening:
    - HSTS Deployment Best Practices:
      * Start with short max-age and monitor
      * Gradually increase max-age to 1-2 years
      * Include all subdomains when possible
      * Submit to preload list for maximum protection

    - Certificate Management:
      * Maintain valid, trusted certificates
      * Implement certificate transparency monitoring
      * Use robust certificate revocation
      * Maintain certificate backup and recovery

    - Monitoring and Maintenance:
      * Regular HSTS header validation
      * Certificate expiration monitoring
      * HSTS preload list status checking
      * Security header compliance monitoring

#### Testing Execution Framework:
    Step 1: Discovery and Enumeration
    - Identify all domains and subdomains
    - Map application endpoints
    - Document current security headers
    - Check preload list status

    Step 2: Header Analysis
    - Test HSTS header presence
    - Validate header syntax and directives
    - Check consistency across endpoints
    - Verify HTTPS-only transmission

    Step 3: Functional Testing
    - Test HTTP to HTTPS redirects
    - Verify browser HSTS behavior
    - Check subdomain coverage
    - Validate certificate security

    Step 4: Security Validation
    - Test attack scenarios
    - Verify integration security
    - Check monitoring capabilities
    - Validate deployment procedures

#### Documentation Template:
    HSTS Security Assessment Report:
    - Assessment Scope and Methodology
    - HSTS Implementation Status
    - Header Configuration Analysis
    - Security Vulnerabilities Identified
    - Risk Assessment and Scoring
    - Remediation Recommendations
    - Preload List Eligibility
    - Compliance Status

This comprehensive HSTS testing checklist ensures thorough evaluation of HTTP Strict Transport Security implementation, helping organizations achieve maximum protection against protocol downgrade attacks and cookie hijacking while maintaining application compatibility and security.