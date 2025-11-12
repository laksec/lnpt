# 🔍 WEB SERVER FINGERPRINTING CHECKLIST

 ## Comprehensive Web Server Fingerprinting

### 1 HTTP Header Analysis
    - Server Header Examination:
      * Server: Apache, nginx, IIS, LiteSpeed, etc.
      * X-Powered-By: PHP, ASP.NET, etc.
      * X-AspNet-Version: NET framework version
      * X-Runtime: Ruby on Rails version
      * X-Generator: CMS/framework identification

    - Custom Header Identification:
      * Application-specific headers
      * Security headers (X-Frame-Options, X-Content-Type-Options)
      * CORS headers
      * Cache control headers

    - Header Order and Format:
      * Header capitalization patterns
      * Header ordering sequence
      * Date format variations
      * Cookie formatting styles

### 2 Banner Grabbing Techniques
    - Netcat Banner Grabbing:
      * nc target.com 80
      * GET / HTTP/1.0\r\n\r\n
      * HEAD / HTTP/1.0\r\n\r\n
      * OPTIONS / HTTP/1.0\r\n\r\n

    - Telnet Connection:
      * telnet target.com 80
      * Manual HTTP requests
      * Response header analysis
      * Error message examination

    - OpenSSL for HTTPS:
      * openssl s_client -connect target.com:443
      * Examine SSL certificate
      * Check for HTTP/2 support
      * Analyze encryption protocols

### 3 Response Analysis
    - Default Page Identification:
      * Apache: "It works!" page
      * IIS: "IIS Welcome" page
      * nginx: "Welcome to nginx!" page
      * Custom default page analysis

    - Error Message Patterns:
      * 404 Not Found page styling
      * 500 Internal Server Error details
      * Custom error page implementations
      * Stack trace information leakage

    - File Extension Handling:
      * php, asp, aspx, jsp processing
      * Static file handling (.html, txt)
      * Custom extension processing
      * File not found behavior

### 4 Port and Service Scanning
    - Common Web Ports:
      * 80 (HTTP), 443 (HTTPS)
      * 8080, 8443 (Alternative web ports)
      * 8000, 3000 (Development servers)
      * 7080, 7081 (Plesk admin)

    - Service Detection:
      * nmap -sV -p 80,443,8080 target.com
      * nmap -sS -sV -O target.com
      * nmap --script http-server-header.nse
      * nmap --script http-title.nse

    - SSL/TLS Service Scanning:
      * sslscan target.com:443
      * testssl.sh target.com:443
      * sslyze --regular target.com:443
      * openssl s_client -connect target.com:443

### 5 Technology Stack Identification
    - Programming Language Detection:
      * PHP: php extension, X-Powered-By: PHP
      * ASP.NET: aspx, X-AspNet-Version
      * Java: jsp, JSESSIONID cookies
      * Python: py, WSGI headers
      * Ruby: rb, Rack headers
      * Node.js: Express.js patterns

    - Framework Detection:
      * WordPress: /wp-admin/, /wp-includes/
      * Drupal: /sites/default/files
      * Joomla: /administrator/
      * Laravel: /public/, artisan patterns
      * Django: /admin/, CSRF token patterns

    - Database Backend Indicators:
      * MySQL: mysql_connect errors
      * PostgreSQL: postgresql errors
      * MongoDB: mongodb connection strings
      * SQL Server: mssql errors

### 6 Web Server Specific Fingerprinting
    - Apache HTTP Server:
      * Server: Apache/X.X.X
      * mod_* modules in headers
      * htaccess file behavior
      * mod_status page (if enabled)

    - nginx:
      * Server: nginx/X.X.X
      * X-Page-Speed header
      * FastCGI headers
      * Custom error page formats

    - Microsoft IIS:
      * Server: Microsoft-IIS/X.X
      * X-Powered-By: ASP.NET
      * X-AspNet-Version
      * W3SVC logging patterns

    - LiteSpeed:
      * Server: LiteSpeed
      * LiteSpeed-* headers
      * LSWS version in headers

### 7 Advanced Fingerprinting Techniques
    - HTTP Method Testing:
      * OPTIONS method response
      * TRACE method availability
      * PUT/DELETE method testing
      * Custom method responses

    - Timing Analysis:
      * Response time patterns
      * Keep-alive behavior
      * Connection handling
      * Load balancer detection

    - Malformed Request Testing:
      * Invalid HTTP versions
      * Extra long headers
      * Missing required headers
      * Unicode in requests

### 8 SSL/TLS Fingerprinting
    - Certificate Analysis:
      * Issuer and subject information
      * Certificate expiration
      * Subject Alternative Names (SANs)
      * Certificate transparency logs

    - Cipher Suite Analysis:
      * Supported cipher suites
      * SSL/TLS version support
      * Perfect Forward Secrecy (PFS)
      * Weak cipher detection

    - Protocol Support:
      * HTTP/2 support detection
      * SPDY protocol support
      * WebSocket support
      * QUIC protocol detection

### 9 Application-Specific Fingerprinting
    - CMS Detection:
      * WordPress: wp-json, wp-admin, readme.html
      * Joomla: administrator/, media/system/
      * Drupal: misc/drupal.js, themes/garland/
      * Magento: /js/mage/, /skin/frontend/

    - E-commerce Platforms:
      * Shopify: myshopify.com
      * WooCommerce: /wp-content/plugins/woocommerce/
      * Magento: /media/theme/, /js/varien/
      * PrestaShop: /js/tools.js, /themes/

    - Web Application Firewalls:
      * CloudFlare: cf-ray header
      * Akamai: X-Akamai-* headers
      * Imperva: X-CDN header
      * AWS WAF: X-Amz-Cf-* headers

### 10 Operating System Detection
    - TTL Value Analysis:
      * Windows: TTL ~128
      * Linux/Unix: TTL ~64
      * Network devices: TTL ~255
      * Custom TTL values

    - TCP Stack Fingerprinting:
      * TCP window size
      * TCP flags behavior
      * Initial sequence numbers
      * TCP options

    - File System Case Sensitivity:
      * Test case-sensitive paths
      * URL case sensitivity testing
      * File extension case testing

### 11 Automated Fingerprinting Tools
    - Comprehensive Scanners:
      * WhatWeb: whatweb target.com
      * Wappalyzer: Browser extension or CLI
      * BuiltWith: Online tool or API
      * Nikto: nikto -h target.com

    - Specialized Tools:
      * httprint: HTTP server fingerprinting
      * p0f: Passive OS fingerprinting
      * hping3: Advanced TCP probing
      * sslyze: SSL/TLS configuration analysis

    - Custom Scripts:
      * Python with requests library
      * Bash scripts with curl
      * PowerShell for Windows targets
      * Ruby with net-http

### 12 Passive Reconnaissance
    - Search Engine Analysis:
      * site:target.com filetype:php
      * site:target.com "powered by"
      * site:target.com intitle:"index of"
      * site:target.com "server at"

    - Certificate Transparency:
      * crt.sh for certificate history
      * Certificate Subject Alternative Names
      * Issuer information analysis
      * Certificate timeline analysis

    - Historical Data:
      * Wayback Machine (archive.org)
      * Google cached pages
      * DNS history records
      * Historical IP assignments

#### Fingerprinting Methodology:
    Initial Reconnaissance:
    1. Basic port scanning (80, 443, 8080, etc.)
    2. HTTP header analysis
    3. SSL certificate examination
    4. Default page analysis

    Detailed Analysis:
    1. Technology stack identification
    2. Web server version detection
    3. Application framework detection
    4. Security controls identification

    Advanced Techniques:
    1. Malformed request testing
    2. Timing analysis
    3. Behavioral analysis
    4. Passive intelligence gathering

#### Tools and Commands Examples:
    Basic Banner Grabbing:
    curl -I http://target.com
    nc target.com 80
    HEAD / HTTP/1.0

    Comprehensive Scanning:
    nmap -sV -sC -p 80,443,8080 target.com
    whatweb -v target.com
    wappalyzer target.com

    SSL/TLS Analysis:
    sslscan target.com
    testssl.sh target.com:443
    openssl s_client -connect target.com:443 -servername target.com

#### Documentation Template:
    Web Server Fingerprint Report:
    - Target: target.com
    - IP Address: XXX.XXX.XXX.XXX
    - Web Server: Apache/2.4.41 (Ubuntu)
    - Technologies: PHP 7.4, MySQL, WordPress 5.8
    - SSL/TLS: TLS 1.2, RSA 2048 bits
    - Security Headers: Present/Missing
    - WAF: CloudFlare detected
    - Open Ports: 80, 443, 8080

#### Defense Evasion Techniques:
    - Header Obfuscation:
      * Removing/modifying Server header
      * Custom header implementations
      * Header normalization

    - Application Masking:
      * Custom error pages
      * Modified default files
      * Framework obfuscation

    - Security Through Obscurity:
      * Non-standard ports
      * Custom file extensions
      * Modified response patterns

This comprehensive web server fingerprinting checklist helps identify the technology stack, server versions, and security configurations while maintaining thorough documentation for penetration testing and security assessment purposes.