
# 🔍 REQUEST FORGERY TESTING CHECKLIST

## Comprehensive Request Forgery Testing

### 1 Request Parameter Manipulation Testing
    - Query Parameter Testing:
      * Parameter addition/modification
      * Parameter deletion attempts
      * Parameter order manipulation
      * Duplicate parameter testing
      * Parameter pollution attacks

    - POST Data Testing:
      * Form field manipulation
      * JSON payload modification
      * XML data tampering
      * Multipart form-data manipulation
      * Hidden field modification

    - Header Manipulation Testing:
      * Custom header injection
      * Standard header modification
      * Referrer header spoofing
      * User-Agent manipulation
      * Cookie header tampering

### 2 HTTP Method Manipulation Testing
    - Method Override Testing:
      * POST to GET conversion attempts
      * PUT/PATCH method testing
      * DELETE method exploitation
      * HEAD/OPTIONS method abuse
      * TRACE method vulnerabilities

    - Custom Method Testing:
      * Non-standard HTTP methods
      * Method override headers
      * RESTful API method manipulation
      * WebDAV method exploitation
      * Custom action parameters

    - Verb Tampering Testing:
      * Case variation attempts (get vs GET)
      * Whitespace injection in methods
      * Null byte injection in methods
      * Unicode method name manipulation
      * Method name truncation

### 3 URL and Path Manipulation Testing
    - Path Traversal Testing:
      * Directory traversal attempts
      * Absolute path injection
      * Relative path manipulation
      * URL encoding bypass attempts
      * Double encoding attacks

    - Endpoint Discovery Testing:
      * Common endpoint guessing
      * Administrative path discovery
      * API endpoint enumeration
      * Hidden functionality discovery
      * Backup file location testing

    - RESTful URL Testing:
      * ID manipulation in URLs
      * Resource enumeration attempts
      * Collection endpoint testing
      * Nested resource manipulation
      * URL pattern prediction

### 4 Authentication Bypass via Request Forgery
    - Session Manipulation Testing:
      * Session ID prediction
      * Cookie parameter manipulation
      * Token replay attacks
      * JWT token tampering
      * OAuth token theft

    - Credential Bypass Testing:
      * Hardcoded credential testing
      * Default credential attempts
      * Parameter-based authentication
      * Header-based authentication bypass
      * IP-based authentication spoofing

    - Privilege Escalation Testing:
      * User ID parameter manipulation
      * Role parameter modification
      * Permission flag tampering
      * Access level parameter forging
      * Tenant ID manipulation

### 5 Business Logic Bypass Testing
    - Workflow Bypass Testing:
      * Step skipping via direct access
      * Approval process circumvention
      * Status parameter manipulation
      * Progress state modification
      * Completion flag forging

    - Validation Bypass Testing:
      * Client-side validation circumvention
      * Checksum/hash bypass attempts
      * Signature verification bypass
      * Timestamp manipulation
      * Nonce reuse attacks

    - Process Manipulation Testing:
      * Order status modification
      * Payment status tampering
      * Shipping status manipulation
      * Approval state forging
      * Review status modification

### 6 CSRF and State Modification Testing
    - CSRF Token Testing:
      * CSRF token removal attempts
      * CSRF token prediction
      * CSRF token replay
      * Weak token generation testing
      * Token validation bypass

    - State Change Testing:
      * Unauthenticated state changes
      * Indirect reference manipulation
      * Forced browsing to state changes
      * Cross-user state modification
      * Administrative state changes

    - One-Click Attack Testing:
      * Forged form submission testing
      * Image tag CSRF exploitation
      * Link-based state changes
      * Auto-submit form testing
      * Flash-based CSRF attacks

### 7 API Request Forgery Testing
    - Endpoint Manipulation Testing:
      * Unpublished API endpoint testing
      * Version parameter manipulation
      * Action parameter modification
      * Resource ID manipulation
      * Bulk operation exploitation

    - Request Replay Testing:
      * Identical request replay
      * Parameter-modified replay
      * Timestamp-adjusted replay
      * Sequence number manipulation
      * Nonce replay attacks

    - Batch Request Testing:
      * Batch operation manipulation
      * Atomicity violation testing
      * Order-dependent operations
      * Bulk action authorization
      * Mass assignment vulnerabilities

### 8 File and Resource Manipulation
    - File Reference Testing:
      * File ID manipulation
      * File path modification
      * File ownership tampering
      * Access control list bypass
      * Shared resource exploitation

    - Upload Manipulation Testing:
      * File type parameter forging
      * File size limit bypass
      * File name injection
      * Metadata manipulation
      * Upload location control

    - Download Manipulation Testing:
      * Direct object reference manipulation
      * Download parameter tampering
      * Access-controlled file downloading
      * Path traversal in downloads
      * Signed URL exploitation

### 9 Financial Transaction Forgery
    - Amount Manipulation Testing:
      * Negative amount submission
      * Zero amount transactions
      * Decimal point manipulation
      * Maximum limit bypass
      * Currency conversion abuse

    - Payment Parameter Testing:
      * Payment method manipulation
      * Billing address tampering
      * Shipping cost modification
      * Tax calculation bypass
      * Discount code exploitation

    - Transaction State Testing:
      * Payment status manipulation
      * Order confirmation bypass
      * Refund request forging
      * Chargeback state modification
      * Settlement status tampering

### 10 Timing and Race Condition Testing
    - Time-Based Testing:
      * Timestamp manipulation
      * Expiration date modification
      * Timezone exploitation
      * Clock skew attacks
      * Time-limited offer extension

    - Race Condition Testing:
      * TOCTOU vulnerabilities
      * Concurrent balance updates
      * Simultaneous inventory claims
      * Parallel order processing
      * Multiple vote submission

    - Sequence Testing:
      * Request order manipulation
      * Step sequence bypass
      * Process flow alteration
      * Dependency chain breaking
      * State machine exploitation

### 11 Mobile and API-Specific Forgery
    - Mobile API Testing:
      * Mobile header manipulation
      * Device ID spoofing
      * App version tampering
      * Platform parameter forging
      * Push token manipulation

    - Web Service Testing:
      * SOAP action manipulation
      * WSDL enumeration
      * REST parameter tampering
      * GraphQL query manipulation
      * Webhook endpoint forging

    - Third-Party Integration Testing:
      * Callback URL manipulation
      * Webhook data tampering
      * Integration token theft
      * Partner ID spoofing
      * External reference manipulation

### 12 Advanced Forgery Techniques
    - Encoding and Obfuscation Testing:
      * Base64 encoding manipulation
      * URL encoding attacks
      * Hex encoding bypass
      * Unicode normalization issues
      * Character set exploitation

    - Parser Differential Testing:
      * Browser vs server parsing differences
      * Library-specific parsing issues
      * Content-type manipulation
      * Charset parameter tampering
      * Boundary condition exploitation

    - Protocol-Level Testing:
      * HTTP/1.1 vs HTTP/2 differences
      * Chunked encoding manipulation
      * Keep-alive connection abuse
      * Pipeline request exploitation
      * Compression bomb attacks

#### Testing Methodology:
    Phase 1: Request Analysis
    1. Map all application endpoints and parameters
    2. Analyze request/response patterns
    3. Identify authentication and authorization mechanisms
    4. Document business logic flows

    Phase 2: Basic Forgery Testing
    1. Test parameter manipulation
    2. Validate authentication bypass attempts
    3. Check authorization controls
    4. Verify business logic enforcement

    Phase 3: Advanced Manipulation Testing
    1. Test complex forgery scenarios
    2. Validate race condition exploitation
    3. Check protocol-level vulnerabilities
    4. Verify integration security

    Phase 4: Impact Assessment
    1. Evaluate business impact of forgeries
    2. Assess security control effectiveness
    3. Determine detection capabilities
    4. Document prevention recommendations

#### Testing Tools and Techniques:
    Manual Testing Tools:
    - Burp Suite Repeater and Intruder
    - OWASP ZAP Manual Request Editor
    - Postman for API manipulation
    - Browser Developer Tools
    - Custom curl scripts

    Automated Testing Support:
    - Burp Suite extensions (Autorize, etc.)
    - Custom parameter fuzzing scripts
    - API security testing frameworks
    - CSRF testing tools
    - Race condition detectors

    Specialized Testing Tools:
    - ffuf for endpoint discovery
    - sqlmap for parameter-based SQLi
    - Commix for command injection
    - CSRF token analysis tools
    - JWT manipulation utilities

#### Common Test Scenarios:
    Parameter Manipulation Tests:
    - Change user_id parameter to access other accounts
    - Modify price parameters in shopping cart
    - Tamper with quantity fields for inventory
    - Manipulate status parameters in workflows
    - Forge approval flags in processes

    Authentication Bypass Tests:
    - Remove authentication headers
    - Modify session tokens
    - Spoof IP addresses for access
    - Manipulate API keys
    - Forge OAuth tokens

    Business Logic Tests:
    - Skip payment steps in checkout
    - Modify order totals before submission
    - Bypass approval workflows
    - Change user roles via parameters
    - Manipulate voting/rating systems

#### Risk Assessment Framework:
    Critical Risk:
    - Complete authentication bypass via request forgery
    - Administrative functionality access through parameter manipulation
    - Financial transaction manipulation leading to direct loss
    - Mass data exposure through endpoint manipulation

    High Risk:
    - Privilege escalation through parameter tampering
    - Significant business logic bypass
    - Data integrity compromise
    - Unauthorized state changes

    Medium Risk:
    - Limited parameter manipulation vulnerabilities
    - Minor business logic issues
    - Information disclosure through error messages
    - Partial workflow bypass

    Low Risk:
    - Theoretical attack vectors
    - Limited impact parameter issues
    - UI-level manipulation only
    - Documentation and logging gaps

#### Protection and Prevention:
    - Request Forgery Prevention Best Practices:
      * Implement proper authentication and authorization checks
      * Use anti-CSRF tokens for state-changing operations
      * Validate all input parameters server-side
      * Implement proper session management
      * Use cryptographic signatures for critical parameters

    - Technical Controls:
      * Input validation and sanitization
      * Business logic validation at multiple layers
      * Request signing and verification
      * Rate limiting and anomaly detection
      * Comprehensive logging and monitoring

    - Process Controls:
      * Security-aware development practices
      * Regular security testing and code review
      * Threat modeling for request handling
      * Security training for developers
      * Incident response planning

#### Testing Execution Framework:
    Step 1: Endpoint and Parameter Mapping
    - Document all application endpoints
    - Identify all request parameters
    - Analyze authentication requirements
    - Map business logic flows

    Step 2: Basic Manipulation Testing
    - Test parameter addition/modification/deletion
    - Validate authentication bypass attempts
    - Check authorization enforcement
    - Verify business rule validation

    Step 3: Advanced Forgery Testing
    - Test complex manipulation scenarios
    - Validate race condition vulnerabilities
    - Check protocol-level issues
    - Verify integration security

    Step 4: Security Control Assessment
    - Evaluate prevention mechanism effectiveness
    - Assess detection and monitoring capabilities
    - Validate incident response procedures
    - Document improvement recommendations

#### Documentation Template:
    Request Forgery Assessment Report:
    - Executive Summary and Risk Overview
    - Testing Methodology and Scope
    - Endpoint and Parameter Analysis
    - Vulnerability Details and Evidence
    - Business Impact Assessment
    - Authentication Bypass Findings
    - Authorization Control Evaluation
    - Business Logic Bypass Results
    - Risk Assessment and Scoring
    - Remediation Recommendations
    - Security Hardening Guidelines

This comprehensive request forgery testing checklist ensures thorough evaluation of application request handling security, helping organizations prevent unauthorized access, data manipulation, and business logic bypass through robust request validation and security controls.
