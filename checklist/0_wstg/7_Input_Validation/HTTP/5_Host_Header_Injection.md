# 🔍 HOST HEADER INJECTION TESTING CHECKLIST

 ## Comprehensive Host Header Injection Testing

### 1 Basic Host Header Manipulation
    - Standard Host Header Testing:
      * Original Host header preservation testing
      * Host header removal: empty Host header
      * Host header duplication: multiple Host headers
      * Case variation: host, HOST, Host
      * Whitespace injection: Host: example.com\r\n

    - Simple Injection Vectors:
      * Basic injection: Host: example.com@attacker.com
      * Port manipulation: Host: example.com:80@attacker.com
      * Subdomain injection: Host: attacker.example.com
      * IP address substitution: Host: 127.0.0.1, Host: 0.0.0.0

    - Protocol Scheme Manipulation:
      * Full URL in Host: Host: http://attacker.com
      * HTTPS forcing: Host: https://attacker.com
      * FTP and other protocols: Host: ftp://attacker.com
      * JavaScript protocol: Host: javascript:alert(1)

### 2 Password Reset Poisoning
    - Password Reset Functionality:
      * Host header in password reset links
      * Email content generation with Host header
      * SMS reset codes with poisoned URLs
      * Security question reset flows

    - Reset Link Manipulation:
      * Absolute URL generation testing
      * Relative URL with poisoned Host
      * Link expiration timing with poisoned domains
      * One-time token generation with poisoned Host

    - Email Header Injection:
      * From header manipulation via Host
      * Return-Path poisoning
      * Message-ID generation issues
      * Email template rendering with Host

### 3 Cache Poisoning via Host Header
    - Cache Key Generation Testing:
      * Host header inclusion in cache keys
      * Cache key normalization issues
      * Case sensitivity in cache keys
      * Port number handling in cache

    - Poisoned Response Storage:
      * Storing malicious responses in cache
      * Cache entry overwrite attacks
      * Cache timing for poison persistence
      * CDN cache poisoning

    - Cache Deception Attacks:
      * User-specific cache poisoning
      * Session-based cache manipulation
      * Geographic cache poisoning
      * Device-specific cache attacks

### 4 SSRF via Host Header
    - Internal Service Access:
      * Localhost access: Host: 127.0.0.1, Host: localhost
      * Internal IP ranges: Host: 192.168.1.1, Host: 10.0.0.1
      * Cloud metadata services: Host: 169.254.169.254
      * Internal domain names: Host: internal.corp

    - Protocol Handling:
      * HTTP to internal services
      * HTTPS to internal endpoints
      * Other protocol attempts (FTP, SSH)
      * Port scanning via Host header

    - Response Manipulation:
      * Response splitting in internal services
      * Header injection in internal responses
      * Content injection via internal services

### 5 Authentication Bypass
    - Domain-Based Restrictions:
      * Allowed domain bypass
      * Subdomain whitelist bypass
      * IP address restriction evasion
      * Geographic restriction bypass

    - SSO and OAuth Bypass:
      * OAuth callback URL manipulation
      * SAML assertion consumer service URL
      * OpenID Connect redirect_uri
      * Single Sign-On domain validation

    - Session Management:
      * Session cookie domain manipulation
      * Cross-domain session fixation
      * Session token generation with poisoned Host
      * Logout functionality domain issues

### 6 Business Logic Exploitation
    - Email Functionality:
      * Email sending domain validation
      * Newsletter subscription domains
      * Contact form email generation
      * Notification system domain handling

    - File Operations:
      * File download domain validation
      * Upload functionality domain checks
      * Export feature domain manipulation
      * Report generation domain issues

    - Payment Processing:
      * Payment callback URL manipulation
      * Receipt generation domains
      * Invoice domain validation
      * Refund processing domains

### 7 XSS via Host Header
    - Reflected XSS Testing:
      * Host header reflection in HTML
      * Host header in JavaScript contexts
      * Host header in attribute contexts
      * Host header in CSS contexts

    - Stored XSS Testing:
      * Host header storage in databases
      * Host header in log files
      * Host header in cached responses
      * Host header in administrative interfaces

    - DOM-Based XSS:
      * Host header usage in client-side code
      * document.location.host manipulation
      * window.location hostname usage
      * URL parsing in JavaScript

### 8 Advanced Injection Techniques
    - Header Splitting Attacks:
      * CRLF injection in Host header
      * Multiple header injection via Host
      * Response splitting via Host
      * Request smuggling via Host manipulation

    - Encoding and Obfuscation:
      * URL encoding: %2e%2e%2f
      * Unicode encoding attacks
      * Base64 encoded Host values
      * Double encoding techniques

    - Special Character Testing:
      * Null byte injection: example.com%00
      * Tab and newline characters
      * Space variations: example.com, example.com 
      * Dot manipulation: example..com

### 9 Web Server Specific Testing
    - Apache Testing:
      * Virtual host configuration issues
      * ServerName and ServerAlias manipulation
      * htaccess Host validation
      * mod_rewrite Host usage

    - Nginx Testing:
      * server_name directive testing
      * Location block Host validation
      * Proxy_pass Host manipulation
      * FastCGI Host parameter

    - IIS Testing:
      * Host header binding issues
      * Application Host config manipulation
      * ARR (Application Request Routing) testing
      * URL rewrite module Host usage

### 10 Application Framework Testing
    - PHP Applications:
      * $_SERVER['HTTP_HOST'] usage
      * $_SERVER['SERVER_NAME'] differences
      * Framework-specific Host handling
      * CMS Host header processing

    - Java Applications:
      * HttpServletRequest.getHeader("Host")
      * Spring framework Host validation
      * Servlet container Host handling
      * JSP Host header usage

    - NET Applications:
      * Request.Headers["Host"] usage
      * Request.Url.Host differences
      * MVC framework Host validation
      * Web API Host processing

    - Python Applications:
      * Django ALLOWED_HOSTS testing
      * Flask request.host usage
      * WSGI environ HTTP_HOST
      * Framework middleware Host handling

### 11 Cloud and CDN Testing
    - Load Balancer Testing:
      * X-Forwarded-Host header testing
      * X-Original-Host manipulation
      * Load balancer Host passthrough
      * Health check Host manipulation

    - CDN Testing:
      * CDN origin Host manipulation
      * Cache key Host inclusion
      * CDN configuration Host validation
      * Edge server Host processing

    - Cloud Platform Testing:
      * AWS ALB/ELB Host handling
      * Azure App Service Host validation
      * Google Cloud Load Balancer
      * CloudFlare Host header rules

### 12 Defense Bypass Testing
    - Validation Bypass Techniques:
      * Case sensitivity bypass
      * Whitespace obfuscation
      * Encoding variation attacks
      * Null byte injection
      * Multiple Host header attacks

    - WAF Evasion:
      * Token fragmentation
      * Protocol compliance attacks
      * Header order manipulation
      * Chunked encoding with Host manipulation

    - Parser Differential Exploitation:
      * Front-end vs back-end parsing
      * Web server vs application parsing
      * Load balancer vs application parsing
      * Framework vs custom code parsing

#### Testing Tools and Methodologies:
    Manual Testing Tools:
    - Burp Suite with Host header manipulation
    - OWASP ZAP with custom header scripts
    - Curl with manual Host header setting
    - Browser developer tools for header modification
    - Postman with environment variables

    Automated Testing Tools:
    - Custom Host header fuzzing scripts
    - Security scanner Host header plugins
    - Nuclei templates for Host injection
    - Custom Python requests with header rotation

    Specialized Testing Tools:
    - Host header injection specific scanners
    - Header manipulation frameworks
    - Cache poisoning testing tools
    - SSRF testing with Host header

    Test Case Examples:
    - Basic: Host: evil.com
    - Port: Host: evil.com:80
    - Auth: Host: evil.com@example.com
    - IP: Host: 127.0.0.1
    - Internal: Host: 169.254.169.254

    Testing Methodology:
    1. Identify Host header usage points
    2. Test basic Host header manipulation
    3. Attempt password reset poisoning
    4. Test cache poisoning scenarios
    5. Verify SSRF possibilities
    6. Test authentication bypass attempts
    7. Check business logic vulnerabilities
    8. Attempt XSS via Host header
    9. Test defense bypass techniques
    10. Document successful exploitation paths

    Protection Mechanisms Testing:
    - Host header validation effectiveness
    - Allowed host list configuration
    - Web server security headers
    - Application framework security settings
    - Load balancer/CDN security configurations