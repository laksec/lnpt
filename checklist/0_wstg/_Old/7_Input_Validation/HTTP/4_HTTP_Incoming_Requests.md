# 🔍 INCOMING HTTP REQUEST TESTING CHECKLIST

 ## Comprehensive Incoming HTTP Request Testing

### 1 Request Line Testing
    - HTTP Method Testing:
      * Standard methods: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH
      * Extended methods: COPY, MOVE, MKCOL, PROPFIND, LOCK, UNLOCK
      * Custom method testing
      * Invalid method handling
      * Case sensitivity in methods

    - Request URI Testing:
      * Path traversal attempts
      * URL encoding variations
      * Double encoding attacks
      * Maximum path length testing
      * Special character handling in paths

    - HTTP Version Testing:
      * HTTP/0.9, HTTP/1.0, HTTP/1.1, HTTP/2
      * Invalid version numbers
      * Version downgrade attacks
      * Case sensitivity in version strings

### 2 Request Header Testing
    - Standard Header Manipulation:
      * Host header: overflows, injection, spoofing
      * User-Agent: SQLi, XSS, command injection
      * Accept headers: MIME type confusion, encoding issues
      * Content-Type: type confusion, boundary manipulation
      * Content-Length: overflow, underflow, negative values

    - Security Header Testing:
      * Origin header manipulation
      * Referer header: open redirect, information disclosure
      * Authorization header: token injection, basic auth bypass
      * Cookie header: injection, overflow, parsing issues

    - Custom Header Testing:
      * X-Forwarded-For: IP spoofing, SSRF
      * X-Real-IP: source validation bypass
      * X-Requested-With: CSRF protection bypass
      * Custom application headers

### 3 Request Body Testing
    - Content-Type Variations:
      * application/x-www-form-urlencoded
      * multipart/form-data
      * application/json
      * application/xml
      * text/plain
      * binary/octet-stream

    - Body Structure Testing:
      * Parameter pollution in form data
      * JSON injection and parsing issues
      * XML entity expansion attacks
      * Boundary conflicts in multipart
      * Chunked encoding manipulation

    - Size and Length Testing:
      * Maximum content length bypass
      * Empty body handling
      * Extremely large body processing
      * Negative content length
      * Chunked encoding size limits

### 4 Query Parameter Testing
    - Parameter Manipulation:
      * SQL injection in parameters
      * XSS in parameter values
      * Command injection attempts
      * Path traversal via parameters
      * Local file inclusion

    - Parameter Structure Testing:
      * Duplicate parameter names
      * Array parameter exploitation
      * Nested parameter structures
      * Missing parameter handling
      * Extra parameter injection

    - Encoding and Obfuscation:
      * URL encoding variations
      * Double URL encoding
      * Unicode encoding attacks
      * HTML entity encoding
      * Base64 encoded parameters

### 5 Cookie Testing
    - Cookie Manipulation:
      * Session fixation attacks
      * Cookie injection vulnerabilities
      * Cookie overflow testing
      * HttpOnly flag bypass attempts
      * Secure flag testing

    - Cookie Structure Testing:
      * Multiple cookie with same name
      * Special characters in cookie values
      * Extremely long cookie values
      * Cookie attribute manipulation
      * Domain/path scope testing

### 6 Authentication Bypass Testing
    - Authentication Header Testing:
      * Basic auth: base64 manipulation, null bytes
      * Bearer token: JWT manipulation, signature bypass
      * Digest auth: nonce replay, parameter tampering
      * NTLM/Kerberos: token injection, relay attacks

    - Session Management Testing:
      * Session ID prediction/bruteforce
      * Session timeout manipulation
      * Concurrent session testing
      * Session invalidation issues

    - Credential Testing:
      * Default credential testing
      * Weak password policy bypass
      * Credential stuffing detection
      * Account lockout bypass

### 7 Rate Limiting Bypass Testing
    - Request Frequency Testing:
      * Burst request attacks
      * Low-and-slow attacks
      * Distributed request testing
      * IP rotation techniques

    - Resource Exhaustion:
      * Memory exhaustion via large requests
      * CPU exhaustion via complex processing
      * Connection pool exhaustion
      * File descriptor exhaustion

### 8 Protocol-Level Testing
    - HTTP/1.1 Specific Testing:
      * Keep-alive connection exploitation
      * Pipeline request attacks
      * Chunked encoding manipulation
      * Expect header handling

    - HTTP/2 Specific Testing:
      * Stream dependency manipulation
      * Header compression attacks (HPACK)
      * Flow control window exploitation
      * Priority scheme manipulation

    - Protocol Confusion:
      * HTTP/0.9 request handling
      * HTTP/1.0 vs HTTP/1.1 differences
      * HTTP/2 to HTTP/1.1 downgrade
      * Invalid protocol versions

### 9 Request Parsing Testing
    - Parser Differential Testing:
      * Front-end vs back-end parsing differences
      * Web server vs application parsing
      * Load balancer parsing variations
      * WAF parsing inconsistencies

    - Malformed Request Testing:
      * Invalid line endings (CR, LF, CRLF)
      * Missing required headers
      * Invalid header syntax
      * Malformed chunked encoding
      * Incomplete requests

### 10 Content Processing Testing
    - File Upload Testing:
      * File type validation bypass
      * Filename injection attacks
      * File content inspection bypass
      * Archive file extraction issues
      * Virus scanning bypass

    - Data Validation Testing:
      * Type confusion attacks
      * Boundary value testing
      * Input length restrictions
      * Character set validation
      * Business logic validation

### 11 Security Control Testing
    - WAF Bypass Testing:
      * Encoding variation attacks
      * Request fragmentation
      * HTTP method confusion
      * Parameter pollution
      * Case variation attacks

    - Input Validation Bypass:
      * Null byte injection
      * Unicode normalization
      * Whitespace obfuscation
      * Comment injection
      * Multiple encoding layers

### 12 Application-Specific Testing
    - API Endpoint Testing:
      * REST API parameter testing
      * GraphQL query manipulation
      * SOAP action exploitation
      * RPC endpoint testing

    - Web Framework Testing:
      * Framework-specific parameter handling
      * Template injection points
      * Routing manipulation
      * Middleware processing

#### Testing Tools and Methodologies:
    Manual Testing Tools:
    - Burp Suite Repeater and Intruder
    - OWASP ZAP manual request editing
    - Postman with custom scripts
    - Curl with advanced options
    - Netcat for raw HTTP requests

    Automated Testing Tools:
    - Custom fuzzing scripts
    - Security scanner custom rules
    - API testing frameworks
    - Load testing tools for rate limit testing

    Specialized Testing Tools:
    - HTTP request fuzzers
    - Protocol analysis tools
    - Custom payload generators
    - Traffic interception proxies

    Test Case Examples:
    - Method: CUSTOM / HTTP/1.1
    - Header: User-Agent: ./../etc/passwd
    - Parameter: ?id=1' OR '1'='1
    - Body: {"data": "<script>alert(1)</script>"}
    - Cookie: session=../../../etc/passwd

    Testing Methodology:
    1. Identify all request entry points
    2. Test request line manipulation
    3. Test header injection and manipulation
    4. Test body parsing and processing
    5. Test parameter handling
    6. Test authentication mechanisms
    7. Test rate limiting and resource controls
    8. Test protocol-level vulnerabilities
    9. Test security control bypasses
    10. Document findings and exploitation paths

    Protection Mechanisms Testing:
    - Input validation effectiveness
    - Authentication strength
    - Rate limiting robustness
    - Parser security
    - Error handling security
    - Logging and monitoring coverage