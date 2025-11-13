# 🔍 PATH CONFUSION TESTING CHECKLIST

## 2.8 Comprehensive Path Confusion Testing

### 2.8.1 Path Traversal Testing
    - Directory Traversal Testing:
      * `../` sequence injection attempts
      * `..\` Windows path traversal
      * URL-encoded variations (`%2e%2e%2f`)
      * Double URL encoding (`%252e%252e%252f`)
      * Unicode encoding variations

    - Absolute Path Testing:
      * Absolute path injection (`/etc/passwd`)
      * Windows absolute paths (`C:\Windows\System32\`)
      * Network paths (`\\server\share`)
      * Device namespace paths (`\\.\PhysicalDrive0`)

    - Path Truncation Testing:
      * Null byte injection (`../../etc/passwd%00`)
      * Path length overflow attacks
      * Dot truncation techniques
      * File extension manipulation

### 2.8.2 URL Path Manipulation Testing
    - URL Parsing Testing:
      * Multiple slash confusion (`////etc/passwd`)
      * Mixed slash types (`/.\\././etc/passwd`)
      * Directory separator confusion
      * URL parser differential testing

    - Query Parameter Path Testing:
      * Path through parameters (`?file=../../../config`)
      * Multiple parameter techniques
      * Array parameter manipulation
      * JSON/XML path injection

    - Fragment and Anchor Testing:
      * Path confusion using fragments
      * Anchor tag manipulation
      * Hash-based path confusion
      * URL reconstruction attacks

### 2.8.3 Web Server Path Testing
    - Web Root Escalation Testing:
      * Web root directory escape
      * Virtual directory traversal
      * Alias and symlink following
      * Document root misconfiguration

    - Server-Specific Testing:
      * Apache path traversal techniques
      * IIS specific path confusion
      * Nginx path normalization
      * Tomcat/JBoss path handling

    - HTTP Method Testing:
      * PUT method path traversal
      * DELETE method path manipulation
      * MOVE/COPY method attacks
      * PROPFIND WebDAV exploitation

### 2.8.4 Application Framework Path Testing
    - Framework-Specific Testing:
      * Spring path variable confusion
      * Express.js static path traversal
      * Django MEDIA_ROOT/MEDIA_URL confusion
      * Rails public directory traversal

    - Template Engine Testing:
      * Template path injection
      * Include/import path manipulation
      * Layout file path confusion
      * Partial template traversal

    - Route Configuration Testing:
      * Route parameter path confusion
      * Wildcard route exploitation
      * Route precedence manipulation
      * Custom route handler testing

### 2.8.5 File Operation Path Testing
    - File Upload Path Testing:
      * Upload directory traversal
      * Filename path injection
      * Temporary file path confusion
      * Archive extraction path traversal

    - File Download Testing:
      * Download path manipulation
      * File stream path confusion
      * Attachment filename injection
      * Content-Disposition header manipulation

    - File Include Testing:
      * Local File Inclusion (LFI) testing
      * Remote File Inclusion (RFI) testing
      * PHP include/require path traversal
      * File wrapper protocol abuse

### 2.8.6 Operating System Path Testing
    - Windows Path Testing:
      * DOS device namespace (`CON`, `PRN`, `AUX`)
      * Short filename (8.3) exploitation
      * UNC path injection (`\\?\C:\`)
      * Volume GUID path manipulation

    - Linux/Unix Path Testing:
      * Proc filesystem access (`/proc/self/environ`)
      * Symbolic link exploitation
      * Hard link attacks
      * Special device file access

    - Cross-Platform Testing:
      * Mixed OS path separator confusion
      * Case sensitivity differentials
      * Path normalization differences
      * Environment variable path injection

### 2.8.7 Cloud Storage Path Testing
    - Cloud Bucket Testing:
      * AWS S3 key traversal
      * Azure Blob Storage path confusion
      * Google Cloud Storage object traversal
      * Pre-signed URL path manipulation

    - Container Path Testing:
      * Docker container path confusion
      * Kubernetes volume path traversal
      * Container escape through paths
      * Bind mount path manipulation

    - Serverless Path Testing:
      * Lambda function path traversal
      * Cloud Function file system access
      * Temporary directory confusion
      * Layer path manipulation

### 2.8.8 API Path Testing
    - REST API Path Testing:
      * API endpoint path traversal (`/api/../admin`)
      * Resource ID path confusion
      * Nested resource path manipulation
      * GraphQL path query abuse

    - Parameter Pollution Testing:
      * Path parameter pollution
      * Query string path confusion
      * Header injection path manipulation
      * Cookie-based path traversal

    - Web Service Testing:
      * SOAP attachment path traversal
      * XML external entity path injection
      * JSON API path confusion
      * GraphQL introspection path abuse

### 2.8.9 Configuration File Path Testing
    - Config File Access Testing:
      * Web application config traversal
      * Database configuration access
      * Environment file disclosure (`.env`)
      * Secret storage path confusion

    - Source Code Disclosure:
      * Backup file path discovery (`.bak`, `.old`)
      * Version control path traversal (`.git`, `.svn`)
      * Temporary file path access
      * Log file path confusion

    - Metadata File Testing:
      * DS_Store file access
      * Thumbs.db path traversal
      * Metadata property confusion
      * Package manager path traversal

### 2.8.10 Authentication Bypass Path Testing
    - Protected Resource Testing:
      * Authentication bypass via path manipulation
      * Authorization circumvention
      * Admin panel path confusion
      * API gateway path traversal

    - Session Path Testing:
      * Session file path confusion
      * Cookie path attribute manipulation
      * Token storage path traversal
      * OAuth callback path confusion

    - SSO Integration Testing:
      * Single Sign-On path manipulation
      * SAML assertion path confusion
      * OIDC endpoint path traversal
      * JWT storage path access

### 2.8.11 Encoding and Obfuscation Testing
    - Encoding Technique Testing:
      * URL encoding variations
      * Double URL encoding
      * UTF-8 encoding confusion
      * HTML entity encoding

    - Obfuscation Testing:
      * Mixed case path confusion
      * Whitespace injection (`/etc/passwd `)
      * Tab character manipulation
      * Line break injection

    - Special Character Testing:
      * Null byte injection testing
      * Newline confusion (`/etc/passwd\n`)
      * Carriage return manipulation
      * Unicode normalization attacks

### 2.8.12 Defense Bypass Testing
    - Filter Evasion Testing:
      * Blacklist bypass techniques
      * Filter recursion evasion
      * Pattern matching bypass
      * WAF rule evasion

    - Normalization Bypass:
      * Path normalization confusion
      * Canonicalization attacks
      * Realpath function bypass
      * Directory separator confusion

    - Chained Technique Testing:
      * Multiple encoding layers
      * Mixed attack vectors
      * Progressive path manipulation
      * Time-based path confusion

#### Testing Methodology:
    Phase 1: Discovery & Mapping
    1. Map application directory structure
    2. Identify file operations and endpoints
    3. Analyze path handling mechanisms
    4. Document input vectors for path manipulation

    Phase 2: Basic Traversal Testing
    1. Test common traversal patterns
    2. Verify encoding variations
    3. Check operating system specific paths
    4. Validate filter effectiveness

    Phase 3: Advanced Technique Testing
    1. Test framework-specific path handling
    2. Verify cloud storage path security
    3. Check API path validation
    4. Test authentication bypass attempts

    Phase 4: Defense Evasion Testing
    1. Test WAF and filter evasion
    2. Verify normalization bypasses
    3. Check chained attack techniques
    4. Validate comprehensive protection

#### Automated Testing Tools:
    Path Traversal Scanners:
    - Burp Suite Scanner with path traversal extensions
    - OWASP ZAP path traversal scripts
    - Nikto web server scanner
    - DirBuster with traversal payloads

    Custom Testing Tools:
    - Path traversal fuzzing wordlists
    - Custom encoding manipulation scripts
    - Framework-specific testing tools
    - Cloud storage testing utilities

    Developer Tools:
    - Browser developer console for URL manipulation
    - Postman for API path testing
    - curl for manual path confusion testing
    - Custom HTTP clients for encoding tests

#### Common Test Commands:
    Basic Traversal Testing:
    curl "http://example.com/files?name=../../../etc/passwd"
    wget "http://example.com/../../config.php"

    Encoding Testing:
    curl "http://example.com/files?name=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    curl "http://example.com/files?name=..%252f..%252f..%252fetc%252fpasswd"

    Advanced Technique Testing:
    curl "http://example.com/files?name=....//....//....//etc/passwd"
    curl "http://example.com/files?name=/etc/passwd%00"

#### Risk Assessment Framework:
    Critical Risk:
    - Unrestricted file system access through path traversal
    - Ability to read sensitive system files (/etc/passwd, /etc/shadow)
    - Web application source code disclosure
    - Configuration file exposure with credentials

    High Risk:
    - Limited path traversal with directory restrictions
    - Access to application configuration files
    - User data file exposure
    - Log file access through path confusion

    Medium Risk:
    - Partial path traversal with filtering
    - Limited file type access
    - Information disclosure through backup files
    - Temporary file access

    Low Risk:
    - Path confusion with no security impact
    - Error message information leakage
    - Denial of service through path manipulation
    - Non-sensitive file disclosure

#### Protection and Hardening:
    - Input Validation Best Practices:
      * Whitelist allowed path characters
      * Validate and sanitize all user input
      * Implement proper path normalization
      * Use built-in security functions

    - Server Configuration:
      * Configure web server security settings
      * Set proper directory permissions
      * Use chroot jails where appropriate
      * Implement file system access controls

    - Application Security:
      * Use framework-specific security features
      * Implement proper error handling
      * Validate file operations rigorously
      * Use secure file access APIs

    - Defense in Depth:
      * Implement WAF rules for path traversal
      * Monitor for suspicious file access patterns
      * Regular security testing and code review
      * Security headers and controls

#### Testing Execution Framework:
    Step 1: Environment Analysis
    - Identify target platform and technologies
    - Map file operations and endpoints
    - Analyze path handling mechanisms
    - Document security controls

    Step 2: Basic Vector Testing
    - Test common traversal patterns
    - Verify encoding variations
    - Check platform-specific paths
    - Validate initial security posture

    Step 3: Advanced Attack Testing
    - Test framework-specific vulnerabilities
    - Verify cloud and container security
    - Check API path validation
    - Test authentication bypasses

    Step 4: Defense Evaluation
    - Test security control effectiveness
    - Verify monitoring and detection
    - Check comprehensive protection
    - Validate incident response

#### Documentation Template:
    Path Confusion Assessment Report:
    - Executive Summary and Risk Overview
    - Path Handling Mechanism Analysis
    - Vulnerabilities Identified
    - Successful Exploitation Techniques
    - Risk Assessment and Scoring
    - Remediation Recommendations
    - Input Validation Improvements
    - Monitoring and Detection Guidance

This comprehensive Path Confusion testing checklist ensures thorough evaluation of path handling mechanisms, helping organizations prevent unauthorized file access, information disclosure, and system compromise through proper path validation and security controls.