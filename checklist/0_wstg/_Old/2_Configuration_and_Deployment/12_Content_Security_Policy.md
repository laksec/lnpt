# 🔍 CONTENT SECURITY POLICY (CSP) TESTING CHECKLIST

## 2.7 Comprehensive Content Security Policy Testing

### 2.7.1 CSP Header Discovery & Analysis
    - Header Presence Testing:
      * `Content-Security-Policy` (current standard)
      * `Content-Security-Policy-Report-Only` (reporting mode)
      * `X-Content-Security-Policy` (legacy Firefox)
      * `X-WebKit-CSP` (legacy WebKit)

    - Header Configuration Analysis:
      * Multiple CSP header detection
      * Header concatenation behavior
      * Directive ordering and precedence
      * Case sensitivity and formatting

    - Policy Delivery Testing:
      * Meta tag CSP vs HTTP header CSP
      * Multiple policy enforcement
      * Frame-ancestors in meta tag (not supported)
      * Report-URI in meta tag (not supported)

### 2.7.2 Core Directive Security Testing
    - default-src Directive Testing:
      * Fallback behavior for unspecified directives
      * Inheritance and cascade testing
      * Wildcard usage and security implications
      * 'none' keyword effectiveness

    - script-src Directive Testing:
      * 'unsafe-inline' usage and risks
      * 'unsafe-eval' usage and risks
      * Nonce and hash-based whitelisting
      * Strict-dynamic compatibility

    - style-src Directive Testing:
      * Inline style protection
      * CSS injection prevention
      * Style attribute restrictions
      * CSS expression blocking

### 2.7.3 Source Whitelist Validation
    - Scheme Source Testing:
      * `https:` scheme restriction effectiveness
      * `http:` scheme blocking
      * `data:` URI scheme risks
      * `blob:` and `filesystem:` scheme security

    - Host Source Testing:
      * Wildcard host patterns (`*.example.com`)
      * Subdomain inheritance and security
      * IP address restrictions
      * Port number specifications

    - Keyword Source Testing:
      * `'self'` keyword scope validation
      * `'none'` keyword enforcement
      * `'unsafe-inline'` usage analysis
      * `'unsafe-eval'` usage analysis

### 2.7.4 Nonce and Hash Implementation Testing
    - Nonce-based CSP Testing:
      * Nonce randomness and predictability
      * Nonce regeneration frequency
      * Nonce exposure in external resources
      * Nonce reuse across pages

    - Hash-based CSP Testing:
      * Hash algorithm support (sha256, sha384, sha512)
      * Hash calculation accuracy
      * Dynamic content hash compatibility
      * Hash maintenance and updates

    - strict-dynamic Testing:
      * `'strict-dynamic'` compatibility
      * Nonce/hash propagation to child scripts
      * Legacy browser fallback handling
      * Third-party script loading

### 2.7.5 Frame and Object Security Testing
    - frame-ancestors Directive Testing:
      * X-Frame-Options compatibility and override
      * Parent frame restrictions
      * Multiple origin specifications
      * `'self'` and `'none'` keyword testing

    - child-src and frame-src Testing:
      * Embedded content restrictions
      * IFrame source validation
      * Object and embed tag restrictions
      * Web worker source controls

    - object-src Directive Testing:
      * Flash object restrictions
      * Java applet blocking
      * PDF viewer embedding
      * Custom plugin controls

### 2.7.6 Connection and Network Security
    - connect-src Directive Testing:
      * XMLHttpRequest (XHR) restrictions
      * Fetch API source controls
      * WebSocket connection limits
      * EventSource (SSE) restrictions

    - form-action Directive Testing:
      * Form submission target validation
      * Open redirect prevention
      * Cross-origin form submission blocking
      * Login CSRF protection

    - navigate-to Directive Testing:
      * Top-level navigation restrictions
      * Window.location changes
      * Meta refresh limitations
      * Link target controls

### 2.7.7 Media and Font Security
    - media-src Directive Testing:
      * Audio and video source restrictions
      * Streaming media controls
      * Track element limitations
      * Source element validation

    - font-src Directive Testing:
      * Web font loading restrictions
      * Google Fonts, Typekit integration
      * Custom font hosting
      * Data URI font loading

    - image-src Directive Testing:
      * Image source validation
      * Favicon loading restrictions
      * SVG image security
      * EXIF data leakage prevention

### 2.7.8 Reporting and Monitoring Testing
    - report-uri Directive Testing:
      * Reporting endpoint availability
      * Report delivery verification
      * Report format analysis
      * Report volume and filtering

    - report-to Directive Testing:
      * Reporting API implementation
      * Endpoint group configuration
      * Network error reporting
      * Deprecation reporting

    - Reporting Behavior Testing:
      * Violation report content analysis
      * Blocked-uri and violated-directive accuracy
      * Script sample in reports
      * Report-only mode effectiveness

### 2.7.9 CSP Bypass Techniques Testing
    - JSONP Endpoint Bypass:
      * JSONP callback execution testing
      * AngularJS CSP bypass techniques
      * Polyglot script injection
      * MIME type confusion attacks

    - Code Injection Vectors:
      * Dynamic code evaluation testing
      * `setTimeout`/`setInterval` with strings
      * `Function` constructor bypass attempts
      * `eval` equivalents testing

    - Third-party Service Risks:
      * CDN script integrity verification
      * Third-party widget security
      * Analytics script risks
      * Social media plugin security

### 2.7.10 Browser Compatibility Testing
    - Legacy Browser Support:
      * Internet Explorer CSP 1.0 compatibility
      * Safari specific behaviors
      * Mobile browser CSP support
      * Feature detection mechanisms

    - CSP Level 2/3 Feature Testing:
      * Workers and worker-src directive
      * Manifest-src for web app manifests
      * Prefetch-src for resource hints
      * Script-src-attr and script-src-elem

    - Browser-Specific Behaviors:
      * Chrome CSP implementation quirks
      * Firefox security preferences
      * Edge Chromium compatibility
      * Mobile browser enforcement

### 2.7.11 Application Framework CSP Testing
    - JavaScript Framework Testing:
      * React CSP compatibility
      * Angular CSP configuration
      * Vue.js security integration
      * jQuery and legacy library support

    - CMS CSP Integration:
      * WordPress CSP plugins and configurations
      * Drupal security kit module
      * Joomla content security
      * Custom CMS implementations

    - Server-Side Framework Testing:
      * Express.js helmet configuration
      * Django CSP middleware
      * Ruby on Rails security headers
      * ASP.NET CSP configuration

### 2.7.12 CSP Deployment and Maintenance
    - Policy Deployment Testing:
      * Report-Only mode rollout
      * Gradual policy enforcement
      * Policy versioning and updates
      * Rollback procedures

    - Monitoring and Analytics:
      * Violation monitoring setup
      * Alert configuration for critical violations
      * Performance impact analysis
      * User impact assessment

    - Maintenance Procedures:
      * Regular policy reviews
      * Third-party source updates
      * Nonce rotation procedures
      * Hash management processes

### 2.7.13 Advanced CSP Security Testing
    - Policy Injection Testing:
      * Header injection vulnerability testing
      * CRLF injection in CSP headers
      * Multiple policy manipulation
      * Meta tag injection attempts

    - CORS and CSP Integration:
      * Cross-origin resource loading with CSP
      * CORS and CSP conflict resolution
      * Preflight request handling
      * Credentialed requests with CSP

    - Service Worker CSP Testing:
      * Service worker registration restrictions
      * Worker-src directive enforcement
      * Cache storage with CSP
      * Background sync security

#### Testing Methodology:
    Phase 1: Discovery & Analysis
    1. Identify all CSP headers and policies
    2. Analyze policy structure and directives
    3. Map allowed sources and restrictions
    4. Document reporting configurations

    Phase 2: Security Validation
    1. Test for common bypass techniques
    2. Validate nonce/hash implementation
    3. Check for unsafe directives
    4. Verify frame and object security

    Phase 3: Functional Testing
    1. Test application functionality with CSP
    2. Validate third-party integrations
    3. Check browser compatibility
    4. Verify reporting mechanisms

    Phase 4: Advanced Testing
    1. Test advanced attack scenarios
    2. Validate deployment procedures
    3. Check maintenance processes
    4. Verify monitoring effectiveness

#### Automated Testing Tools:
    CSP Analysis Tools:
    - CSP Evaluator (Google)
    - Laboratory (Mozilla)
    - CSP Scanner
    - SecurityHeaders.io

    Browser Developer Tools:
    - Chrome DevTools Security panel
    - Firefox Developer Tools Network panel
    - Safari Web Inspector
    - Edge DevTools

    Command Line Tools:
    - curl: `curl -I https://example.com`
    - HTTPie: `http headers https://example.com`
    - Custom parsing scripts

    Specialized Scanners:
    - OWASP ZAP with CSP scanner
    - Burp Suite CSP extension
    - Custom policy analysis tools

#### Common Test Commands:
    Header Extraction:
    curl -I https://example.com | grep -i content-security-policy
    http headers https://example.com

    Policy Analysis:
    # Check for unsafe directives
    echo "policy" | grep -E "unsafe-inline|unsafe-eval"
    # Check for wildcards
    echo "policy" | grep "\*"

    Reporting Testing:
    # Test report-uri endpoint
    curl -X POST -H "Content-Type: application/csp-report" -d '{}' https://report-uri.example.com

#### Risk Assessment Framework:
    Critical Risk:
    - Missing CSP entirely on sensitive applications
    - CSP with 'unsafe-inline' and 'unsafe-eval' enabled
    - Wildcard sources in script-src or object-src
    - No frame-ancestors protection

    High Risk:
    - Insecure nonce implementation (predictable/reused)
    - Missing object-src or script-src directives
    - Overly permissive connect-src
    - No form-action restrictions

    Medium Risk:
    - Limited use of unsafe directives
    - Missing reporting mechanisms
    - Incomplete directive coverage
    - Legacy browser incompatibilities

    Low Risk:
    - Minor configuration issues
    - Missing optimization opportunities
    - Informational reporting problems
    - Non-critical directive omissions

#### Protection and Hardening:
    - CSP Best Practices:
      * Start with report-only mode
      * Use nonces/hashes instead of unsafe-inline
      * Implement strict-dynamic where possible
      * Regularly review and update policies

    - Deployment Strategy:
      * Gradual policy enforcement
      * Comprehensive testing in staging
      * User impact monitoring
      * Rollback planning

    - Monitoring and Maintenance:
      * Real-time violation monitoring
      * Automated policy testing
      * Regular security reviews
      * Third-party source management

#### Testing Execution Framework:
    Step 1: Policy Discovery
    - Identify all CSP headers and configurations
    - Document policy structure and directives
    - Map allowed sources and restrictions
    - Analyze reporting configurations

    Step 2: Security Analysis
    - Test for common bypass techniques
    - Validate security controls
    - Check for unsafe directives
    - Verify implementation security

    Step 3: Functional Validation
    - Test application functionality
    - Validate integrations
    - Check compatibility
    - Verify reporting

    Step 4: Advanced Assessment
    - Test attack scenarios
    - Validate deployment
    - Check maintenance
    - Verify monitoring

#### Documentation Template:
    Content Security Policy Assessment:
    - Executive Summary and Risk Overview
    - CSP Configuration Analysis
    - Security Vulnerabilities Identified
    - Bypass Techniques Tested
    - Risk Assessment and Scoring
    - Remediation Recommendations
    - Policy Optimization Suggestions
    - Monitoring and Maintenance Guidance

This comprehensive Content Security Policy testing checklist ensures thorough evaluation of CSP implementations, helping organizations prevent XSS attacks, data injection, and other content-based security threats through proper CSP configuration and management.