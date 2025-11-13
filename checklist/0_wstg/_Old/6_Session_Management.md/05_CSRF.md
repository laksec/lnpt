# 🔍 CROSS-SITE REQUEST FORGERY (CSRF) TESTING CHECKLIST

## 6.5 Comprehensive Cross-Site Request Forgery Testing

### 6.5.1 CSRF Token Implementation Testing
    - Token Presence Testing:
      * CSRF token existence in sensitive forms
      * Token inclusion in state-changing requests
      * AJAX request token validation
      * API endpoint token requirements
      * Mobile app token handling

    - Token Security Testing:
      * Token randomness and unpredictability
      * Token length and entropy analysis
      * Token binding to user session
      * Token expiration and rotation
      * Token uniqueness per request

    - Token Validation Testing:
      * Server-side token verification
      * Missing token request rejection
      * Invalid token error handling
      * Token replay attack prevention
      * Concurrent token usage issues

### 6.5.2 SameSite Cookie Testing
    - SameSite Attribute Testing:
      * SameSite=Strict implementation verification
      * SameSite=Lax configuration testing
      * SameSite=None with Secure requirement
      * Cross-browser SameSite compatibility
      * Legacy browser fallback behavior

    - Cross-Origin Request Testing:
      * Top-level navigation request testing
      * Cross-origin form submission blocking
      * Third-party iframe cookie restrictions
      * External link cookie transmission
      * CORS and SameSite interaction

    - Browser Compatibility Testing:
      * Chrome SameSite enforcement
      * Firefox SameSite implementation
      * Safari Intelligent Tracking Prevention
      * Edge Chromium behavior
      * Mobile browser support

### 6.5.3 Referrer Header Validation Testing
    - Referrer Policy Testing:
      * Referrer-Policy header implementation
      * Strict-Origin-When-Cross-Origin validation
      * No-Referrer policy effectiveness
      * Origin-Only referrer restrictions
      * Custom referrer validation logic

    - Header Manipulation Testing:
      * Referrer header spoofing attempts
      * Header removal vulnerabilities
      * Proxy referrer manipulation
      * Browser referrer override
      * Mobile app referrer handling

    - Origin Validation Testing:
      * Origin header verification
      * Host header validation
      * Custom origin checking
      * Cross-domain origin issues
      * Null origin handling

### 6.5.4 State-Changing Operation Testing
    - GET Request Testing:
      * State-changing GET request vulnerabilities
      * Idempotent operation misclassification
      * Bookmarkable destructive actions
      * Image tag CSRF exploitation
      * Link-based state changes

    - POST Request Testing:
      * Form-based CSRF attacks
      * JSON POST request vulnerabilities
      * XMLHttpRequest CSRF
      * Fetch API CSRF issues
      * Multipart form data CSRF

    - Other HTTP Method Testing:
      * PUT method CSRF vulnerabilities
      * DELETE method exploitation
      * PATCH request CSRF
      * Custom method attacks
      * RESTful API CSRF

### 6.5.5 Authentication Context Testing
    - Session Dependency Testing:
      * Cookie-based authentication CSRF
      * Token-based authentication issues
      * JWT CSRF vulnerabilities
      * OAuth token CSRF
      * SSO integration CSRF

    - Re-authentication Testing:
      * Critical operation re-authentication
      * Password confirmation requirements
      * Step-up authentication
      * Biometric re-verification
      * Multi-factor CSRF protection

    - Stateless Authentication Testing:
      * API key CSRF vulnerabilities
      * Bearer token CSRF issues
      * Stateless session CSRF
      * Mobile app authentication CSRF
      * Microservice authentication

### 6.5.6 Form-Based CSRF Testing
    - Hidden Field Testing:
      * CSRF token in hidden fields
      * Token field name predictability
      * Multiple form token handling
      * Dynamic form token generation
      * Form token binding

    - Auto-Submit Testing:
      * JavaScript auto-submit forms
      * Timer-based form submission
      * Onload event form submission
      * Hidden iframe form attacks
      * Pop-under form submission

    - Multi-Step Form Testing:
      * Wizard form CSRF vulnerabilities
      * Progressive form state CSRF
      * Partial form submission
      * Form token persistence
      * Step validation CSRF

### 6.5.7 AJAX and API CSRF Testing
    - JavaScript Framework Testing:
      * React CSRF protection
      * Angular CSRF token handling
      * Vue.js CSRF implementation
      * jQuery AJAX CSRF
      * Fetch API CSRF protection

    - Custom Header Testing:
      * X-CSRF-Token header validation
      * X-Requested-With header checking
      * Custom header verification
      * Header injection vulnerabilities
      * Preflight request handling

    - JSON API Testing:
      * JSON POST CSRF vulnerabilities
      * Content-Type validation
      * JSON hijacking prevention
      * CORS and CSRF interaction
      * API token CSRF issues

### 6.5.8 File Upload CSRF Testing
    - Upload Form Testing:
      * File upload CSRF vulnerabilities
      * Malicious file upload via CSRF
      * Upload path manipulation
      * File type validation bypass
      * Upload quota exhaustion

    - Cross-Origin Upload Testing:
      * Third-party file upload CSRF
      * CDN upload form issues
      * External service upload CSRF
      * Cloud storage upload vulnerabilities
      * Avatar upload CSRF

    - Content-Type Testing:
      * MIME type spoofing via CSRF
      * Content-Type manipulation
      * Multipart form boundary issues
      * File metadata tampering
      * File name injection

### 6.5.9 Social Engineering CSRF Testing
    - Clickjacking Integration:
      * CSRF with clickjacking attacks
      * Invisible form overlays
      * Cursor manipulation techniques
      * UI redressing with CSRF
      * Touchjacking on mobile

    - Phishing Combination Testing:
      * Fake form submission pages
      * Email-triggered CSRF
      * SMS-initiated CSRF
      * Social media CSRF attacks
      * QR code CSRF exploitation

    - User Interaction Testing:
      * Single-click CSRF attacks
      * Mouse movement triggers
      * Keyboard event CSRF
      * Drag-and-drop CSRF
      * Touch event CSRF

### 6.5.10 Advanced CSRF Techniques
    - DNS Rebinding Testing:
      * DNS rebinding CSRF attacks
      * Same-IP different domain issues
      * Local network CSRF
      * Internal service exploitation
      * Router configuration CSRF

    - Cache Poisoning Testing:
      * Cache-based CSRF attacks
      * CDN cache poisoning CSRF
      * Browser cache exploitation
      * Proxy cache manipulation
      * Cache key CSRF issues

    - HTTP Request Smuggling:
      * Request smuggling CSRF
      * CL.TE smuggling attacks
      * TE.CL smuggling vulnerabilities
      * HTTP/2 downgrade CSRF
      * Header smuggling CSRF

### 6.5.11 Mobile App CSRF Testing
    - Mobile Browser Testing:
      * Mobile browser CSRF vulnerabilities
      * Touch interface CSRF issues
      * Mobile form handling
      * App-specific browser CSRF
      * Deep link CSRF

    - Native App Testing:
      * WebView CSRF vulnerabilities
      * Hybrid app CSRF issues
      * Native form CSRF
      * Mobile API CSRF
      * Push notification CSRF

    - Cross-Platform Testing:
      * Mobile to web CSRF
      * Web to mobile CSRF
      * Cross-device CSRF attacks
      * Synchronization CSRF
      * Shared session CSRF

### 6.5.12 Prevention Bypass Testing
    - Token Bypass Testing:
      * Token prediction attacks
      * Token leakage exploitation
      * Token reuse vulnerabilities
      * Weak token generation
      * Missing token validation

    - Header Bypass Testing:
      * Header spoofing attempts
      * Header removal attacks
      * Proxy header manipulation
      * Browser header override
      * Mobile header issues

    - Logic Bypass Testing:
      * Race condition exploitation
      * Timing attack CSRF
      * Cache poisoning bypass
      * Parser differential attacks
      * Protocol confusion

#### Testing Methodology:
    Phase 1: CSRF Protection Analysis
    1. Identify state-changing operations and endpoints
    2. Analyze CSRF protection mechanisms
    3. Map authentication and session dependencies
    4. Document token and validation implementations

    Phase 2: Basic CSRF Testing
    1. Test form-based CSRF vulnerabilities
    2. Validate token implementation security
    3. Check SameSite cookie effectiveness
    4. Verify referrer and origin validation

    Phase 3: Advanced Attack Testing
    1. Test AJAX and API CSRF issues
    2. Validate mobile and cross-platform CSRF
    3. Check advanced technique vulnerabilities
    4. Verify prevention bypass possibilities

    Phase 4: Impact Assessment
    1. Measure account compromise risk
    2. Assess data modification impact
    3. Validate monitoring and detection
    4. Document business impact

#### Automated Testing Tools:
    CSRF Testing Tools:
    - Burp Suite CSRF scanner
    - OWASP ZAP CSRF testing
    - Custom CSRF PoC generators
    - Browser automation tools
    - API testing frameworks

    Token Analysis Tools:
    - Token entropy analyzers
    - Randomness testing tools
    - Pattern recognition scripts
    - Custom validation testers
    - Security header checkers

    Browser Testing Tools:
    - Selenium for automated form testing
    - Puppeteer for Chrome automation
    - Playwright for cross-browser testing
    - Custom browser extension tools
    - Mobile browser emulators

#### Common Test Commands:
    Basic CSRF Testing:
    # Test form without CSRF token
    curl -X POST https://example.com/change-email \
      -d "email=attacker@example.com" \
      -b "sessionid=VALID_SESSION"

    SameSite Testing:
    # Test cross-origin request with cookies
    curl -H "Origin: https://evil.com" \
      -H "Cookie: sessionid=VALID_SESSION" \
      -X POST https://example.com/sensitive-action

    Token Analysis:
    # Analyze token patterns
    for i in {1..10}; do
      curl -s https://example.com/form | grep csrf_token
    done

#### Risk Assessment Framework:
    Critical Risk:
    - No CSRF protection on sensitive operations
    - Predictable or reusable CSRF tokens
    - State-changing GET requests without protection
    - Account takeover via CSRF

    High Risk:
    - Weak token implementation
    - Missing SameSite cookie protection
    - Incomplete token validation
    - API endpoints without CSRF protection

    Medium Risk:
    - Suboptimal token entropy
    - Limited SameSite coverage
    - Minor validation flaws
    - Non-critical operation vulnerabilities

    Low Risk:
    - Theoretical CSRF vectors
    - Properly protected endpoints
    - Non-sensitive data exposure
    - Documentation and logging improvements

#### Protection and Hardening:
    - CSRF Prevention Best Practices:
      * Use synchronizer token pattern for all state-changing requests
      * Implement SameSite=Strict cookies for sensitive operations
      * Validate Origin and Referer headers for additional protection
      * Require re-authentication for critical operations

    - Technical Controls:
      * Framework-level CSRF protection
      * Comprehensive input validation
      * Security header implementation
      * Regular security testing

    - Operational Security:
      * Developer security training
      * Code review processes
      * Incident response planning
      * Continuous security monitoring

#### Testing Execution Framework:
    Step 1: Application Analysis
    - Identify state-changing endpoints
    - Analyze CSRF protection mechanisms
    - Map authentication flows
    - Document session dependencies

    Step 2: Protection Validation
    - Test token implementation security
    - Validate SameSite cookie configuration
    - Check header validation effectiveness
    - Verify form protection coverage

    Step 3: Advanced Vulnerability Assessment
    - Test AJAX and API vulnerabilities
    - Validate mobile app protection
    - Check advanced attack techniques
    - Verify monitoring and detection

    Step 4: Risk and Compliance Evaluation
    - Measure business impact
    - Validate regulatory compliance
    - Assess detection capabilities
    - Document improvement recommendations

#### Documentation Template:
    Cross-Site Request Forgery Assessment Report:
    - Executive Summary and Risk Overview
    - CSRF Protection Analysis
    - Vulnerability Details and Evidence
    - Attack Scenarios and Impact
    - Protection Mechanism Evaluation
    - Business Risk Assessment
    - Compliance Gap Analysis
    - Risk Assessment and Scoring
    - Remediation Recommendations
    - Security Hardening Guidelines

This comprehensive Cross-Site Request Forgery testing checklist ensures thorough evaluation of CSRF protection mechanisms, helping organizations prevent unauthorized state changes, account takeover, and data manipulation through robust CSRF protection and continuous security assessment.