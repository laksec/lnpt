# ULTIMATE FILE INCLUSION TESTING CHECKLIST (v1.0)

### Comprehensive Methodology for LFI/RFI Vulnerabilities

### 🌐 RECONNAISSANCE PHASE

    - Identify all file path parameters in URLs and forms
    - Map file upload/download functionality
    - Locate template rendering endpoints
    - Find language/locale selection features
    - Document all import/export functionality
    - Identify configuration management interfaces
    - Locate log viewing features
    - Find document processing systems
    - Identify server-side file operations
    - Discover XML/XSLT processing points

### 📂 LOCAL FILE INCLUSION (LFI)

#### Basic Techniques

    - Test with basic path traversal (../../etc/passwd)
    - Verify null byte termination (%00)
    - Check absolute path inclusion (/etc/passwd)
    - Test Windows path variations (..\..\windows\win.ini)
    - Verify case sensitivity in paths
    - Check encoded slash variations (%2f, %5c)
    - Test double encoding attempts
    - Verify UTF-8/Unicode bypasses
    - Check file protocol handling (file://)
    - Test PHP wrappers (php://filter)

#### Advanced LFI

    - Test PHP expect wrapper
    - Verify data URI exploitation
    - Check ZIP wrapper inclusion
    - Test PHAR deserialization
    - Verify SSH key retrieval
    - Check AWS credential files
    - Test database configuration files
    - Verify source code disclosure
    - Check htaccess retrieval
    - Test environment file access

### 🌍 REMOTE FILE INCLUSION (RFI)

#### Basic Techniques

    - Test with http:// URLs
    - Verify https:// handling
    - Check FTP protocol support
    - Test SMB path inclusion
    - Verify WebDAV exploitation
    - Check allow_url_fopen behavior
    - Test allow_url_include behavior
    - Verify DNS resolution timing
    - Check IPv6 address handling
    - Test domain blacklist bypasses

#### Advanced RFI

    - Test with evil.com?x.php trick
    - Verify query string appending
    - Check fragment bypass (#)
    - Test parameter pollution
    - Verify null byte in URLs
    - Check double question mark
    - Test path truncation
    - Verify case variation
    - Check mixed encoding
    - Test domain redirection

### 🧩 WRAPPER EXPLOITATION

    - Test php://input for POST data
    - Verify php://filter for encoding
    - Check data:// for code execution
    - Test expect:// for command exec
    - Verify zip:// for archive access
    - Check phar:// for deserialization
    - Test glob:// for pattern matching
    - Verify ogg:// for audio parsing
    - Check rar:// for compressed files
    - Test zlib:// for compression

### 🖥️ SERVER-SPECIFIC FILES

#### Linux/Unix

    - Retrieve /etc/passwd
    - Access /etc/shadow
    - Check /proc/self/environ
    - Verify /var/log/auth.log
    - Test /etc/hosts
    - Check ~/.bash_history
    - Verify /etc/issue
    - Test /etc/motd
    - Check /etc/group
    - Verify SSH keys (~/.ssh/)

#### Windows

    - Retrieve \windows\win.ini
    - Access \windows\system.ini
    - Check \boot.ini
    - Verify \windows\repair\sam
    - Test \windows\Panther\Unattend.xml
    - Check \inetpub\logs
    - Verify \Program Files\ directory
    - Test \Documents and Settings\
    - Check \windows\Temp\
    - Verify IIS config files

### 🛡️ DEFENSE BYPASS

#### Filter Evasion

    - Test nested traversal (....//)
    - Verify URL encoding (%2e%2e%2f)
    - Check double encoding (%252e%252e%252f)
    - Test UTF-8 overlong encoding
    - Verify unicode point bypass
    - Check mixed encoding
    - Test path truncation
    - Verify null byte in middle
    - Check case variation
    - Test file extension stripping

#### WAF Bypass

    - Test parameter fragmentation
    - Verify header injection
    - Check HTTP parameter pollution
    - Test multipart/form-data
    - Verify JSON/XML encapsulation
    - Check boundary scanning
    - Test protocol-level tricks
    - Verify request smuggling
    - Check verb tampering
    -  Test chunked encoding

### 📝 LOG POISONING

    - Identify writable log files
    - Test User-Agent injection
    - Verify Referer header injection
    - Check X-Forwarded-For
    - Test authentication logs
    - Verify error log injection
    - Check mail server logs
    - Test FTP server logs
    - Verify database query logs
    - Check application-specific logs

### 🔗 CHAINING OPPORTUNITIES

    - Combine with XSS
    - Chain with SSRF
    - Link to RCE
    - Combine with XXE
    - Chain with CSRF
    - Link to auth bypass
    - Combine with deserialization
    - Chain to DoS
    - Link to info disclosure
    - Combine with business logic flaws

### ☁️ CLOUD TARGETS

    - Test AWS metadata access
    - Verify Azure metadata
    - Check GCP metadata
    - Test Kubernetes configs
    - Verify Docker socket access
    - Check env files
    - Test CI/CD configurations
    - Verify Terraform state
    - Check cloud credentials
    - Test backup files

### 🧠 SECOND-ORDER

    - Identify file write locations
    - Verify temp file handling
    - Check cache poisoning
    - Test config file writes
    - Verify session file injection
    - Check upload processing
    - Test import/export files
    - Verify report generation
    - Check template rendering
    - Test localization files

### 📊 IMPACT ASSESSMENT

    - Document readable files
    - Record writeable locations
    - Note execution contexts
    - Document sensitive data
    - Report configuration access
    - Note privilege escalation
    - Document chain possibilities
    - Record bypass methods
    - Note detection triggers
    - Document remediation advice

### 🛠️ REMEDIATION

    - Recommend input validation
    - Suggest allowlisting
    - Advocate for sandboxing
    - Propose file permission review
    - Suggest logging hardening
    - Recommend WAF rules
    - Advocate for disable_functions
    - Propose open_basedir
    - Suggest file integrity monitoring
    - Recommend security headers
