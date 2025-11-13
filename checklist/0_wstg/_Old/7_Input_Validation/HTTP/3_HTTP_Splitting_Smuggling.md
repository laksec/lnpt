# 🔍 HTTP SPLITTING & SMUGGLING TESTING CHECKLIST

 ## Comprehensive HTTP Splitting & Smuggling Testing

### 1 HTTP Response Splitting Testing
    - CRLF Injection Vectors:
      * Basic CRLF injection: %0d%0a
      * Encoded CRLF variations: %0a%0d, %0d, %0a
      * Double encoding: %250d%250a
      * Unicode encoding: %u000d%u000a
      * Mixed encoding techniques

    - Header Injection Testing:
      * Location header manipulation: Location: http://target.com%0d%0aInjected-Header: value
      * Set-Cookie injection: Set-Cookie: session=abc%0d%0aInjected-Header: value
      * Content-Type manipulation
      * Cache-Control header injection
      * Custom header injection

    - Response Body Splitting:
      * Multiple response creation
      * Fake response injection
      * Cross-site scripting via response splitting
      * Cookie stealing through fake responses
      * Cache poisoning via split responses

### 2 HTTP Request Smuggling Testing
    - Content-Length vs Transfer-Encoding:
      * CL.TE conflicts: Content-Length vs Transfer-Encoding: chunked
      * TE.CL conflicts: Transfer-Encoding: chunked vs Content-Length
      * TE.TE conflicts: Multiple Transfer-Encoding headers
      * CL.CL conflicts: Multiple Content-Length headers

    - Smuggling Techniques:
      * Basic CL.TE smuggling
      * Basic TE.CL smuggling
      * Header obfuscation smuggling
      * HTTP/2 to HTTP/1.1 downgrade attacks
      * Request tunneling through smuggling

### 3 CL.TE (Content-Length - Transfer-Encoding) Testing
    - Basic CL.TE Payloads:
      * Simple CL.TE smuggling structure
      * With chunk size manipulation
      * With trailing headers
      * With request pipelining

    - Advanced CL.TE Techniques:
      * Partial chunk encoding
      * Chunk extension manipulation
      * Gzip content encoding conflicts
      * Connection reuse exploitation

    - CL.TE Exploitation Scenarios:
      * Cache poisoning via CL.TE
      * Authentication bypass
      * Request hijacking
      * API endpoint access

### 4 TE.CL (Transfer-Encoding - Content-Length) Testing
    - Basic TE.CL Payloads:
      * Standard TE.CL smuggling structure
      * Chunk size calculation manipulation
      * Final chunk termination testing
      * Trailer section exploitation

    - Advanced TE.CL Methods:
      * Transfer-Encoding: chunked, chunked
      * Mixed encoding declarations
      * HTTP version-specific behaviors
      * Proxy-specific parsing differences

    - TE.CL Attack Vectors:
      * Request queue poisoning
      * Response manipulation
      * Session fixation
      * Privilege escalation

### 5 TE.TE (Transfer-Encoding - Transfer-Encoding) Testing
    - Header Obfuscation Techniques:
      * Space insertion: Transfer-Encoding : chunked
      * Tab characters in headers
      * Line wrapping in headers
      * Comment injection in headers
      * Case variation: transfer-encoding: chunked

    - Multiple TE Headers:
      * Conflicting Transfer-Encoding headers
      * Duplicate header exploitation
      * Header order manipulation
      * Empty Transfer-Encoding values

    - Parser Differential Exploitation:
      * Front-end vs back-end parser differences
      * Web server specific parsing behaviors
      * Load balancer parsing variations
      * WAF parsing inconsistencies

### 6 HTTP/2 Smuggling Testing
    - HTTP/2 Specific Vectors:
      * HTTP/2 header compression attacks
      * Stream dependency manipulation
      * Priority scheme exploitation
      * Flow control window manipulation

    - HTTP/2 to HTTP/1.1 Downgrade:
      * Request line injection in downgrade
      * Header injection during protocol conversion
      * Body processing differences
      * Connection management attacks

    - HPACK Compression Exploitation:
      * Dynamic table size manipulation
      * Header field indexing attacks
      * Huffman encoding exploitation
      * Table size update attacks

### 7 Request Tunneling Testing
    - CONNECT Method Exploitation:
      * CONNECT method smuggling
      * HTTP tunnel creation
      * Port scanning through tunnels
      * Backend service access

    - POST Method Tunneling:
      * Chunked encoding tunnels
      * Gzip compressed tunnels
      * Base64 encoded tunnels
      * Multipart form data tunnels

    - WebSocket Tunneling:
      * WebSocket upgrade smuggling
      * WebSocket frame manipulation
      * Subprotocol negotiation attacks
      * Extension header exploitation

### 8 Cache Poisoning via Smuggling
    - Cache Key Manipulation:
      * Request line poisoning
      * Header key manipulation
      * Query parameter ordering
      * Method verb tampering

    - Response Injection:
      * Fake response storage in cache
      * Cache entry corruption
      * Cache timing attacks
      * Cache hierarchy exploitation

    - Cache Deception:
      * User-specific cache poisoning
      * Session cache manipulation
      * Geographic cache poisoning
      * CDN cache exploitation

### 9 Authentication & Authorization Bypass
    - Credential Forwarding Attacks:
      * Authentication token smuggling
      * Session cookie forwarding
      * API key smuggling
      * OAuth token manipulation

    - Privilege Escalation:
      * Role-based access smuggling
      * Permission boundary bypass
      * Administrative endpoint access
      * User isolation bypass

    - SSO Integration Attacks:
      * SAML assertion smuggling
      * JWT token manipulation
      * OIDC token forwarding
      * Cross-domain authentication smuggling

### 10 Application-Specific Smuggling
    - API Gateway Testing:
      * API key validation bypass
      * Rate limiting evasion
      * Endpoint access control bypass
      * Request transformation attacks

    - Load Balancer Testing:
      * Session persistence bypass
      * Health check manipulation
      * SSL termination attacks
      * Backend server targeting

    - Web Application Firewall Testing:
      * WAF rule evasion
      * Signature detection bypass
      * Request normalization attacks
      * Protocol compliance exploitation

### 11 Advanced Smuggling Techniques
    - Timing-Based Attacks:
      * Request timing manipulation
      * Response timing analysis
      * Connection pool exhaustion
      * Server resource timing

    - Resource Poisoning:
      * Database connection poisoning
      * File handle exhaustion
      * Memory allocation attacks
      * Thread pool manipulation

    - Protocol-Level Attacks:
      * HTTP pipelining exploitation
      * Keep-alive connection attacks
      * HTTP version confusion
      * Chunked encoding corruption

### 12 Defense Bypass Testing
    - Normalization Bypass:
      * Case normalization evasion
      * Whitespace normalization attacks
      * Encoding normalization bypass
      * Header order normalization

    - Validation Evasion:
      * Request size validation bypass
      * Header count limitation evasion
      * Content-Length validation attacks
      * Transfer-Encoding validation bypass

    - Monitoring Evasion:
      * Log evasion techniques
      * SIEM detection bypass
      * Audit trail manipulation
      * Forensic obfuscation

#### Testing Tools and Methodologies:
    Manual Testing Tools:
    - Burp Suite with HTTP Smuggler extension
    - Custom Python scripts for smuggling
    - Netcat for raw HTTP requests
    - Curl with manual header manipulation

    Automated Testing Tools:
    - HTTP Request Smuggling detection scripts
    - Custom fuzzing frameworks
    - Protocol analysis tools
    - Security scanner smuggling plugins

    Specialized Testing Tools:
    - smuggler.py (dedicated smuggling tool)
    - http-request-smuggling generators
    - HTTP/2 specific testing tools
    - Proxy-specific testing utilities

    Test Case Examples:
    - CL.TE: POST / HTTP/1.1\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG
    - TE.CL: POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n1\r\nA\r\n0\r\n\r\n
    - TE.TE: POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n...
    - HTTP/2: Method override in headers

    Testing Methodology:
    1. Identify potential smuggling vectors
    2. Test basic CL.TE and TE.CL scenarios
    3. Verify TE.TE obfuscation techniques
    4. Test HTTP/2 specific vectors
    5. Attempt request tunneling
    6. Test cache poisoning scenarios
    7. Verify authentication bypass attempts
    8. Document successful smuggling paths

    Protection Mechanisms Testing:
    - Request normalization verification
    - Header validation testing
    - Protocol consistency checks
    - Web server configuration testing
    - Load balancer security settings
    - WAF smuggling protection evaluation