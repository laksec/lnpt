# 🔍 CROSS-SITE REQUEST FORGERY (CSRF) TESTING CHECKLIST

 ## Comprehensive CSRF Testing

### 1 CSRF Vulnerability Detection
    - State-Changing Operation Identification:
      * Password change functionality
      * Email address modification
      * User profile updates
      * Financial transactions
      * Administrative actions

    - Authentication Mechanism Analysis:
      * Session cookie-based authentication
      * Token-based authentication
      * OAuth/SSO integrations
      * API key authentication

    - Request Method Testing:
      * GET requests with side effects
      * POST form submissions
      * PUT/PATCH/DELETE API calls
      * JSON API endpoints

### 2 CSRF Token Testing
    - Token Presence Validation:
      * Check for CSRF tokens in forms
      * Verify token in hidden fields
      * Confirm token in request headers
      * Validate token in JSON payloads

    - Token Validation Testing:
      * Submit requests without tokens
      * Submit requests with invalid tokens
      * Reuse tokens across sessions
      * Use tokens from other users

    - Token Generation Flaws:
      * Predictable token patterns
      * Weak random number generation
      * Token reuse across sessions
      * Missing token expiration

### 3 SameSite Cookie Testing
    - SameSite Attribute Testing:
      * Check for SameSite=None (without Secure)
      * Verify SameSite=Lax enforcement
      * Test SameSite=Strict implementation
      * Assess cross-site cookie transmission

    - Browser Compatibility Testing:
      * Chrome SameSite behavior
      * Firefox SameSite implementation
      * Safari Intelligent Tracking Prevention
      * Legacy browser support

    - SameSite Bypass Techniques:
      * GET request exploitation (Lax)
      * Top-level navigation attacks
      * Form submission timing attacks
      * 302 redirect exploitation

### 4 Referer Header Validation Testing
    - Referer Header Presence:
      * Check for Referer header validation
      * Test requests without Referer header
      * Verify empty Referer header handling
      * Assess Referer header stripping

    - Referer Validation Bypass:
      * HTTPS to HTTP referer leakage
      * Meta refresh referer spoofing
      * 302 redirect referer manipulation
      * Browser extension referer modification

    - Domain Validation Testing:
      * Exact domain matching
      * Subdomain validation
      * Partial domain matching
      * Regex-based validation

### 5 Custom Header Validation
    - Origin Header Testing:
      * Check Origin header presence
      * Verify Origin header validation
      * Test missing Origin header
      * Assess Origin vs Referer usage

    - Custom Header Implementation:
      * X-Requested-With header checking
      * X-CSRF-Token header validation
      * Custom anti-CSRF headers
      * Header presence/absence validation

### 6 State-Changing Operation Testing
    - Authentication Operations:
      * Password change requests
      * Email address modification
      * Two-factor authentication setup
      * Account recovery settings

    - Financial Operations:
      * Fund transfers
      * Payment processing
      * Billing information updates
      * Subscription modifications

    - Data Modification Operations:
      * User profile updates
      * Content creation/deletion
      * Database record modifications
      * File uploads and deletions

### 7 Request Method Testing
    - GET Request CSRF:
      * State-changing GET requests
      * URL parameter manipulation
      * Image tag exploitation (<img src>)
      * Link-based CSRF attacks

    - POST Request CSRF:
      * Auto-submitting forms
      * XMLHttpRequest POST requests
      * Fetch API POST requests
      * JSON POST endpoints

    - Other HTTP Methods:
      * PUT method CSRF
      * PATCH method CSRF
      * DELETE method CSRF
      * Custom method exploitation

### 8 Multi-Step Process Testing
    - Workflow CSRF Testing:
      * Multi-form processes
      * Wizard-style interfaces
      * Confirmation dialogs
      * Token propagation across steps

    - Session State Testing:
      * Token regeneration between steps
      * State parameter validation
      * Nonce reuse across steps
      * Race conditions in multi-step flows

### 9 JSON API CSRF Testing
    - Simple Request Testing:
      * GET, HEAD, POST methods
      * Content-Type: text/plain
      * Content-Type: application/x-www-form-urlencoded
      * Content-Type: multipart/form-data

    - Preflight Request Testing:
      * OPTIONS request handling
      * CORS header validation
      * Custom header requirements
      * Content-Type restrictions

    - JSON CSRF Techniques:
      * Form-based JSON submission
      * Flash-based requests
      * 307 redirect exploitation
      * Content-Type manipulation

### 10 File Upload CSRF Testing
    - File Upload Endpoints:
      * Avatar/image uploads
      * Document upload functionality
      * Bulk import features
      * Attachment uploads

    - Malicious File Upload:
      * HTML file upload via CSRF
      * JavaScript file upload
      * Malicious document uploads
      * Cross-domain file uploads

### 11 Social Media Integration Testing
    - Social Sharing Buttons:
      * Like/Share button CSRF
      * Social media posting
      * OAuth authorization flows
      * Social login integrations

    - Webhook Integrations:
      * Social media webhooks
      * Payment provider callbacks
      * Third-party service integrations
      * Cross-domain callback handling

### 12 Administrative Function Testing
    - User Management:
      * User role modifications
      * Account creation/deletion
      * Permission changes
      * Bulk user operations

    - System Configuration:
      * Settings modification
      * Feature flag changes
      * Security configuration
      * Database operations

### 13 Advanced CSRF Techniques
    - DNS Rebinding Attacks:
      * Same-origin policy bypass
      * Internal service access
      * Network topology discovery
      * Router configuration modification

    - Clickjacking Integration:
      * CSRF + clickjacking combos
      * Hidden form overlays
      * Cursor position spoofing
      * Touch event manipulation

    - Flash-Based CSRF:
      * Flash cross-domain policies
      * crossdomain.xml misconfiguration
      * URLRequest method override
      * Flash object embedding

### 14 CSRF Protection Bypass
    - Token Bypass Techniques:
      * Cross-site token leakage
      * Token prediction algorithms
      * Token replay attacks
      * Token extraction via XSS

    - Header Bypass Methods:
      * Origin header spoofing
      * Referer header manipulation
      * Custom header removal
      * Header order attacks

    - SameSite Bypass Methods:
      * Top-level navigation GET
      * Form submission timing
      * 302 redirect chains
      * Browser version-specific exploits

### 15 Mobile Application CSRF
    - Mobile API Testing:
      * Mobile app to web service calls
      * OAuth token handling
      * Push notification actions
      * Deep link exploitation

    - Hybrid App Testing:
      * WebView CSRF vulnerabilities
      * Bridge interface exploitation
      * Local storage token leakage
      * Cross-protocol requests

### 16 Single Page Application Testing
    - SPA Framework Testing:
      * Vue.js/React/Angular CSRF
      * Client-side routing protection
      * State management security
      * API client configuration

    - Token Management:
      * JWT token CSRF protection
      * Refresh token security
      * Local storage vs cookies
      * Token auto-inclusion

#### Testing Tools and Methodologies:
    Manual Testing Tools:
    - Burp Suite CSRF PoC generator
    - OWASP ZAP CSRF testing tools
    - Browser developer tools
    - Custom HTML form generators

    Automated Testing Tools:
    - CSRF scanner extensions
    - Custom Python/Ruby scripts
    - Automated form submission tools
    - Token analysis utilities

    Specialized Testing Tools:
    - CSRF token analyzers
    - SameSite testing tools
    - Referer header manipulators
    - CORS configuration testers

    Test Case Examples:
    - Basic form: <form action="https://target.com/change-email" method="POST">
    - Auto-submit: <body onload="document.forms[0].submit()">
    - Image tag: <img src="https://target.com/delete-account">
    - JSON endpoint: <form enctype="text/plain" action="https://target.com/api">

    Testing Methodology:
    1. Identify all state-changing endpoints
    2. Check for CSRF protection mechanisms
    3. Test protection bypass techniques
    4. Verify token validation robustness
    5. Assess SameSite cookie implementation
    6. Test Referer/Origin header validation
    7. Validate multi-step process security
    8. Document exploitation scenarios

    Protection Mechanisms Testing:
    - CSRF token implementation review
    - SameSite cookie attribute verification
    - Referer/Origin header validation testing
    - Custom header security assessment
    - CORS configuration security review

    Business Impact Assessment:
    - Account takeover risk assessment
    - Financial impact evaluation
    - Data integrity impact analysis
    - Regulatory compliance implications
    - Reputational damage assessment

    Remediation Verification:
    - Token-based protection verification
    - SameSite cookie implementation check
    - Double-submit cookie pattern validation
    - Custom header requirement confirmation
    - State parameter usage verification