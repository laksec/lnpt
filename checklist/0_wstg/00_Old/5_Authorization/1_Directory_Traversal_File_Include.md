# 🔍 DIRECTORY TRAVERSAL & FILE INCLUDE TESTING CHECKLIST

## 5.1 Comprehensive Directory Traversal & File Include Testing

### 5.1.1 Basic Directory Traversal Testing
    - Path Traversal Testing:
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

### 5.1.2 Local File Inclusion (LFI) Testing
    - File Inclusion Testing:
      * PHP include/require functions
      * Server-side include (SSI) injection
      * File wrapper protocol usage
      * Local file disclosure
      * Configuration file access

    - Sensitive File Access Testing:
      * `/etc/passwd` and `/etc/shadow`
      * Windows SAM database
      * Application configuration files
      * Log file access
      * Source code disclosure

    - File Extension Testing:
      * File extension bypass techniques
      * Null byte termination
      * Path traversal with extensions
      * MIME type confusion
      * Content-type manipulation

### 5.1.3 Remote File Inclusion (RFI) Testing
    - Remote URL Testing:
      * HTTP/HTTPS URL inclusion
      * FTP URL inclusion
      * SMB share inclusion
      * Remote code execution via RFI
      * Web shell upload via RFI

    - Protocol Wrapper Testing:
      * `http://` and `https://` wrappers
      * `ftp://` wrapper exploitation
      * `php://` input/output streams
      * `data://` URI scheme
      * `expect://` command execution

    - Payload Delivery Testing:
      * Malicious script hosting
      * Cross-site scripting via RFI
      * Remote code execution
      * Web shell deployment
      * Backdoor installation

### 5.1.4 Input Vector Testing
    - URL Parameter Testing:
      * GET parameter manipulation
      * POST data injection
      * Cookie value tampering
      * HTTP header injection
      * Upload filename manipulation

    - Form Field Testing:
      * File upload field traversal
      * Search functionality abuse
      * Contact form exploitation
      * User profile field manipulation
      * Comment field injection

    - API Endpoint Testing:
      * REST API parameter injection
      * GraphQL query manipulation
      * SOAP XML injection
      * JSON parameter tampering
      * File upload API exploitation

### 5.1.5 Encoding and Obfuscation Testing
    - URL Encoding Testing:
      * Single URL encoding
      * Double URL encoding
      * Mixed encoding techniques
      * UTF-8 encoding variations
      * HTML entity encoding

    - Unicode Testing:
      * Unicode normalization attacks
      * UTF-8 encoding exploitation
      * Character set confusion
      * Homoglyph attacks
      * Right-to-left override

    - Special Character Testing:
      * Null byte injection (`%00`)
      * Newline characters (`%0a`, `%0d`)
      * Tab characters (`%09`)
      * Space variations (`%20`, `+`)
      * Case manipulation

### 5.1.6 Web Server Specific Testing
    - Apache Testing:
      * Apache path traversal techniques
      *  htaccess bypass methods
      * Mod_rewrite rule exploitation
      * Virtual host traversal
      * Alias directive abuse

    - IIS Testing:
      * IIS short filename exploitation
      * Web.config access attempts
      * ASP.NET path traversal
      * UNC path injection
      * IIS specific encoding

    - Nginx Testing:
      * Nginx path normalization
      * Location directive bypass
      * Proxy_pass misconfiguration
      * Alias directive traversal
      * Root directive exploitation

### 5.1.7 Application Framework Testing
    - PHP Application Testing:
      * `include()` and `require()` exploitation
      * `file_get_contents()` abuse
      * PHP wrapper protocols
      * `$_GET`/`$_POST` parameter injection
      * PHP filter chain exploitation

    - Java Application Testing:
      * JSP include directive
      * Servlet file operations
      * Spring framework file access
      * JSTL file operations
      * FileInputStream exploitation

    -  NET Application Testing:
      * ASP.NET file inclusion
      * Server.MapPath traversal
      * File.ReadAllText exploitation
      * Response.WriteFile abuse
      * WebResource.axd access

### 5.1.8 File Upload Functionality Testing
    - Filename Manipulation Testing:
      * Filename path traversal
      * Double extension attacks
      * Case modification attacks
      * Space padding techniques
      * Special character injection

    - Content-Type Testing:
      * MIME type spoofing
      * Content-Type header manipulation
      * Magic byte modification
      * File signature forgery
      * Extension-content mismatch

    - Upload Directory Testing:
      * Upload path prediction
      * Directory listing enabled
      * Direct URL access to uploads
      * Execution permissions testing
      * Symlink creation attempts

### 5.1.9 Advanced Bypass Techniques
    - Filter Bypass Testing:
      * Blacklist circumvention
      * Case variation bypass
      * Encoding bypass techniques
      * Nested traversal sequences
      * Mixed separator attacks

    - WAF Evasion Testing:
      * Signature evasion techniques
      * Obfuscation methods
      * Protocol-level evasion
      * Request splitting attacks
      * Encoding layer attacks

    - Application Logic Testing:
      * Conditional path traversal
      * Time-based detection bypass
      * Race condition exploitation
      * Cache poisoning attacks
      * Parser differentials

### 5.1.10 Source Code Disclosure Testing
    - Backup File Testing:
      * Common backup extensions (.bak,  old,  tmp)
      * Version control files (.git,  svn,  hg)
      * IDE project files (.idea,  project)
      * Temporary file access
      * Copy file detection

    - Configuration File Testing:
      * Web server config files
      * Application config files
      * Database configuration
      * Environment files (.env)
      * Log files access

    - Source Code Testing:
      * Direct source file access
      * Parsed vs unparsed file access
      * Template file disclosure
      * Library source exposure
      * API documentation access

### 5.1.11 Impact Assessment Testing
    - Information Disclosure Testing:
      * System information leakage
      * User credentials exposure
      * Database connection strings
      * API keys and tokens
      * Personal data access

    - Remote Code Execution Testing:
      * Web shell upload via LFI/RFI
      * Log file injection for RCE
      * PHP input stream exploitation
      * Server-side template injection
      * Configuration file modification

    - Privilege Escalation Testing:
      * Sensitive file access for privilege escalation
      * Password file access
      * SSH key disclosure
      * Session file manipulation
      * Database credential theft

### 5.1.12 Prevention Bypass Testing
    - Input Validation Testing:
      * Client-side validation bypass
      * Server-side validation weaknesses
      * Regular expression bypass
      * Filter circumvention
      * Whitelist bypass techniques

    - Security Control Testing:
      * Web Application Firewall (WAF) bypass
      * Input sanitization evasion
      * Output encoding bypass
      * Access control circumvention
      * Logging evasion techniques

    - Environment Testing:
      * Development vs production differences
      * Staging environment access
      * Backup server traversal
      * Load balancer bypass
      * CDN configuration issues

#### Testing Methodology:
    Phase 1: Discovery and Reconnaissance
    1. Identify file inclusion points and parameters
    2. Map application architecture and technologies
    3. Analyze input validation mechanisms
    4. Document file operations and endpoints

    Phase 2: Basic Traversal Testing
    1. Test common traversal patterns
    2. Validate encoding variations
    3. Check different input vectors
    4. Verify server-specific techniques

    Phase 3: Advanced Exploitation
    1. Test LFI to RCE conversion
    2. Validate filter and WAF bypass
    3. Check source code disclosure
    4. Verify impact and privilege escalation

    Phase 4: Prevention and Detection
    1. Test security control effectiveness
    2. Validate monitoring and logging
    3. Check incident response procedures
    4. Assess business impact

#### Automated Testing Tools:
    Directory Traversal Tools:
    - Burp Suite with traversal extensions
    - OWASP ZAP path traversal scanner
    - DirBuster with traversal payloads
    - Gobuster for directory discovery
    - WFuzz for parameter fuzzing

    File Inclusion Tools:
    - LFI suite tools
    - RFI exploitation frameworks
    - Custom file inclusion scripts
    - Vulnerability scanners with LFI/RFI modules
    - Web shell management tools

    Manual Testing Tools:
    - Browser developer tools
    - curl for manual request testing
    - Postman for API testing
    - Custom encoding/decoding tools
    - File analysis utilities

#### Common Test Commands:
    Basic Traversal Testing:
    # Test basic path traversal
    curl "http://example.com/file?path=../../../etc/passwd"
    curl "http://example.com/include?file=../../config.php"

    Encoding Testing:
    # Test URL encoding variations
    curl "http://example.com/file?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    curl "http://example.com/file?path=..%252f..%252f..%252fetc%252fpasswd"

    Advanced Testing:
    # Test null byte injection
    curl "http://example.com/file?path=../../../etc/passwd%00"
    # Test protocol wrappers
    curl "http://example.com/include?file=php://filter/convert.base64-encode/resource=index.php"

#### Risk Assessment Framework:
    Critical Risk:
    - Remote code execution via RFI
    - System file disclosure (passwd, shadow, SAM)
    - Source code disclosure with credentials
    - Web shell upload and persistence

    High Risk:
    - Configuration file disclosure
    - Database credential exposure
    - Log file access with sensitive data
    - Limited remote file inclusion

    Medium Risk:
    - Partial file disclosure
    - Limited directory traversal
    - Non-sensitive file access
    - Information leakage without credentials

    Low Risk:
    - Theoretical traversal vectors
    - Limited impact file access
    - Properly filtered inputs
    - Non-executable file access

#### Protection and Hardening:
    - Input Validation Best Practices:
      * Implement whitelist-based input validation
      * Use proper path normalization
      * Validate file extensions and types
      * Implement file permission restrictions
      * Regular security testing and code review

    - Server Configuration:
      * Configure web server security settings
      * Set proper directory permissions
      * Use chroot jails where appropriate
      * Implement file system access controls
      * Regular security updates

    - Application Security:
      * Use framework-specific security features
      * Implement proper error handling
      * Validate file operations rigorously
      * Use secure file access APIs
      * Implement WAF rules for traversal protection

#### Testing Execution Framework:
    Step 1: Application Analysis
    - Map file operations and endpoints
    - Identify input vectors and parameters
    - Analyze technology stack and frameworks
    - Document security controls and filters

    Step 2: Basic Vulnerability Testing
    - Test common traversal patterns
    - Validate encoding and obfuscation
    - Check different input vectors
    - Verify server-specific techniques

    Step 3: Advanced Exploitation
    - Test LFI to RCE conversion
    - Validate source code disclosure
    - Check privilege escalation possibilities
    - Verify business impact

    Step 4: Security Control Assessment
    - Test prevention mechanisms effectiveness
    - Validate monitoring and detection
    - Check incident response procedures
    - Document improvement recommendations

#### Documentation Template:
    Directory Traversal & File Include Assessment Report:
    - Executive Summary and Risk Overview
    - Vulnerability Details and Evidence
    - Attack Vectors and Exploitation Paths
    - Business Impact Analysis
    - Technical Impact Assessment
    - Risk Assessment and Scoring
    - Remediation Recommendations
    - Security Hardening Guidelines
    - Monitoring and Detection Procedures

This comprehensive Directory Traversal & File Include testing checklist ensures thorough evaluation of file access controls, helping organizations prevent unauthorized file access, source code disclosure, and remote code execution through proper input validation and security controls.