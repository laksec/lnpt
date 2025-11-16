# ULTIMATE URL MANIPULATION TESTING CHECKLIST (v1.0)

### Comprehensive Methodology for URL Parameter Attacks

### 🔠 ENCODING TECHNIQUES

    - Test double URL encoding (%252F for /)
    - Verify UTF-8 encoding (%C3%BC for ü)
    - Check HTML entity encoding (& #x2f;)
    - Test Unicode normalization (℀ vs @)
    - Verify hex encoding (\x2f)
    - Check octal encoding (\057)
    - Test Base64 encoding of parameters
    - Verify quoted-printable encoding
    - Check punycode for international domains
    - Test overlong UTF-8 sequences (%C0%AF)

### ✂️ PARAMETER FRAGMENTATION

    - Test parameter splitting (cmd=who&cmd=ami)
    - Verify duplicate parameters (?id=1&id=2)
    - Check parameter wrapping (JSON/XML)
    - Test array parameters (user[]=admin)
    - Verify parameter pollution (id=1&id=2)
    - Check parameter hiding in fragments (#)
    - Test parameter nesting (param={malicious})
    - Verify parameter concatenation
    - Check mixed parameter cases (Id vs id)
    - Test parameter order manipulation

### 🕵️ OBFUSCATION METHODS

    - Test null byte injection (%00)
    - Verify whitespace padding (%20)
    - Check tab/newline injection (%09/%0A)
    - Test comment injection (/\*\*/)
    - Verify case variation (AdMiN)
    - Check special delimiter abuse (;, |)
    - Test right-to-left override (RLO)
    - Verify invisible Unicode characters
    - Check homoglyph attacks (ⅿ vs m)
    - Test regex bypass patterns

### 🔀 PROTOCOL MANIPULATION

    - Test scheme switching (http:// → https://)
    - Verify port manipulation (:8080)
    - Check @ symbol injection (user@host)
    - Test :// bypass variations
    - Verify host header injection
    - Check DNS rebinding techniques
    - Test IPv4 vs IPv6 differences
    - Verify subdomain manipulation
    - Check wildcard DNS abuse
    - Test TLD impersonation (.com vs co)

### 📁 PATH TRAVERSAL

    - Test basic  / sequences
    - Verify encoded traversal (%2e%2e%2f)
    - Check absolute path injection (/etc/passwd)
    - Test Windows path variations (..\)
    - Verify path truncation
    - Check null byte termination (file.php%00.jpg)
    - Test nested traversal (....//)
    - Verify mixed slashes (/.\)
    - Check UNC path injection (\\host\share)
    - Test zip/jar protocol abuse

### 🧩 PARAMETER CONTEXT

    - Test JSON parameter wrapping
    - Verify XML entity injection
    - Check serialized object manipulation
    - Test template injection
    - Verify GraphQL query abuse
    - Check SOAP action manipulation
    - Test REST parameter injection
    - Verify OData query tampering
    - Check WebSocket URL abuse
    - Test Webhook URL manipulation

### 🛡️ DEFENSE BYPASS

    - Test WAF fingerprinting
    - Verify boundary scan evasion
    - Check filter bypass via overlong URLs
    - Test HPP (HTTP Parameter Pollution)
    - Verify method override (POST→PUT)
    - Check header injection (X-Original-URL)
    - Test chunked encoding abuse
    - Verify multipart form-data injection
    - Check boundary manipulation
    - Test mime type confusion

### ⚠️ DANGEROUS PAYLOADS

    - Test JavaScript URI schemes
    - Verify data: URL injection
    - Check vbscript: protocol execution
    - Test file: protocol access
    - Verify telnet: protocol abuse
    - Check LDAP URL injection
    - Test SSRF via URL parameters
    - Verify XSS through URL fragments
    - Check CRLF injection via URLs
    - Test open redirect abuse

### 📝 REPORTING

    - Document encoding bypasses
    - Record parameter vulnerabilities
    - Note traversal possibilities
    - Document protocol abuses
    - Report defense evasion
    - Note business impact
    - Document attack scenarios
    - Record bypass methods
    - Note detection gaps
    - Provide remediation guidance

### 🛠️ REMEDIATION

    - Recommend input normalization
    - Suggest strict allowlisting
    - Advocate for URL canonicalization
    - Propose parameter validation
    - Suggest WAF rule tuning
    - Recommend logging all manipulations
    - Advocate for security headers
    - Propose regular audits
    - Suggest fuzz testing
    -  Recommend threat modeling
