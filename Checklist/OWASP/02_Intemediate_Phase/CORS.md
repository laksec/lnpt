# ULTIMATE CORS MISCONFIGURATION TESTING CHECKLIST (v1.0)

### Comprehensive Methodology for Cross-Origin Resource Sharing Vulnerabilities

### 🌐 RECONNAISSANCE PHASE

    - Identify all API endpoints accepting cross-origin requests
    - Map AJAX/XHR calls in application JavaScript
    - Document fetch() API usage patterns
    - Find WebSocket connections with CORS
    - Locate third-party integrations using CORS
    - Identify endpoints with Access-Control-Allow-Origin headers
    - Discover preflight request endpoints (OPTIONS)
    - Note custom headers requiring CORS
    - Find credentialed requests (withCredentials)
    - Identify error handling for CORS failures

### 🔍 BASIC TESTING TECHNIQUES

#### Origin Header Manipulation

    - Test with null origin
    - Verify reflected origin values
    - Check subdomain wildcard acceptance
    - Test sibling domain inheritance
    - Verify port number handling
    - Check scheme flipping (http↔https)
    - Test internationalized domain names
    - Verify case sensitivity
    - Check IP address origins
    - Test overlong origin values

#### Header Analysis

    - Verify Access-Control-Allow-Origin values
    - Check Access-Control-Allow-Credentials
    - Test Access-Control-Expose-Headers
    - Verify Access-Control-Max-Age
    - Check Access-Control-Allow-Methods
    - Test Access-Control-Allow-Headers
    - Verify Vary header presence
    - Check timing differences for allowed origins
    - Test error message leakage
    - Verify CORS preflight caching

### 🛠️ EXPLOITATION METHODS

#### Simple Misconfigurations

    - Test wildcard (\*) in ACAO
    - Verify null origin acceptance
    - Check reflected origin in ACAO
    - Test prefix/suffix matching flaws
    - Verify regex implementation errors
    - Check subdomain wildcard abuse
    - Test sibling domain inheritance
    - Verify port number ignored
    - Check scheme validation missing
    - Test case sensitivity issues

#### Advanced Bypasses

    - Test header injection in Origin
    - Verify CRLF injection in CORS headers
    - Check header order manipulation
    - Test HTTP method overriding
    - Verify HTTP version downgrade
    - Check request smuggling
    - Test chunked encoding abuse
    - Verify connection state attacks
    - Check cache poisoning
    - Test race conditions

### ⚙️ PREFLIGHT TESTING

    - Verify OPTIONS method handling
    - Check preflight caching duration
    - Test missing preflight requirements
    - Verify header whitelist bypass
    - Check method whitelist bypass
    - Test preflight response tampering
    - Verify timing attacks on preflight
    - Check error state differences
    - Test cache control manipulation
    - Verify CORS-safe method abuse

### 🛡️ CREDENTIALED REQUEST TESTS

    - Test withCredentials=true
    - Verify cookie inclusion
    - Check Authorization header handling
    - Test client certificate impact
    - Verify TLS session ticket reuse
    - Check cache isolation
    - Test credentialed wildcard requests
    - Verify same-site cookie impact
    - Check partitioned storage access
    - Test storage isolation bypass

### 🔗 PROTECTION BYPASSES

#### Same-Origin Policy Bypasses

    - Test DNS rebinding
    - Verify postMessage exploitation
    - Check relaxed CORB policies
    - Test relaxed CORP policies
    - Verify COEP bypasses
    - Check COOP weaknesses
    - Test WebSocket hijacking
    - Verify EventSource abuse
    - Check WebRTC exploitation
    - Test Service Worker abuse

#### Browser-Specific Issues

    - Test legacy browser handling
    - Verify mobile browser quirks
    - Check embedded browser contexts
    - Test extension interactions
    - Verify cached responses
    - Check prefetch behavior
    - Test back/forward cache
    - Verify bfcache interactions
    - Check prerender states
    - Test speculative loading

### 📊 IMPACT ANALYSIS

#### Data Exfiltration

    - Test sensitive API access
    - Verify user data leakage
    - Check admin functionality access
    - Test internal service discovery
    - Verify credential theft
    - Check token extraction
    - Test metadata exposure
    - Verify configuration access
    - Check backup retrieval
    -  Test log file access

#### State Modification

    - Verify CSRF via CORS
    - Test privilege escalation
    - Check user settings modification
    - Test payment manipulation
    - Verify content injection
    - Check data deletion
    - Test approval bypass
    - Verify workflow hijacking
    - Check audit log tampering
    - Test notification abuse

### 🧩 CHAINING OPPORTUNITIES

    - Combine with XSS
    - Chain with CSRF
    - Link to SSRF
    - Combine with XXE
    - Chain with open redirects
    - Link to auth bypass
    - Combine with info disclosure
    - Chain to DoS
    - Link to business logic flaws
    - Combine with cache poisoning

### 📝 REPORTING STANDARDS

    - Document vulnerable endpoints
    - Record exact request/response headers
    - Note all bypass techniques
    - Document data exposure
    - Provide risk assessment
    - Include proof-of-concept
    - Note business impacts
    - Document security header conflicts
    - Provide clear remediation
    - Highlight critical chains

### 🛠️ REMEDIATION STRATEGIES

#### Configuration Fixes

    - Recommend exact origin matching
    - Suggest Vary: Origin header
    - Advocate for proper preflight
    - Propose credentialed request validation
    - Suggest wildcard avoidance
    - Recommend method whitelisting
    - Advocate for header whitelisting
    - Propose cache control
    - Suggest CORS middleware audits
    - Recommend security header scans

#### Architectural Solutions

    - Implement origin verification
    - Enforce same-site cookies
    - Use CSRF tokens
    - Apply request signing
    - Implement rate limiting
    - Deploy WAF protections
    - Enable CORS logging
    - Conduct regular audits
    - Implement automated testing
    - Continuous monitoring
