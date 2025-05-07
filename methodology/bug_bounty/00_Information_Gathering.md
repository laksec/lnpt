# Ultimate Web Application Recon Checklist

## 1. Entry Points Enumeration
### URLs & Parameters

    | All input vectors (GET/POST params, JSON, XML, GraphQL)   | Hidden parameters (POST bodies, headers, cookies)
    | API endpoints (REST, SOAP, GraphQL, gRPC)                 | WebSocket connections
    | Server-Sent Events (SSE) channels                         | File upload handlers
    | CSRF tokens and anti-CSRF mechanisms

### Authentication Flows
    | Login/registration/reset pages    | OAuth/OpenID callback URLs        | SAML ACS endpoints
    | JWT handling endpoints            | MFA implementation endpoints      | Session management endpoints

## 2. Deep File Discovery
### Sensitive Files
    | Config files (.env, config.php, application.properties)   | Backup files (.bak, .swp, ~, .old, _v2)
    | Version control (.git/, .svn/, .hg/)                      | IDE project files (.idea/, .vscode/)
    | CI/CD configs (Jenkinsfile, .github/workflows)            | API docs (Swagger, OpenAPI, WSDL)

### Admin Interfaces
    | /admin* variants (admin, administrator, backend)          | /debug* endpoints (debug, console, phpinfo)
    | Framework-specific consoles (Django, Rails, Laravel)      | Database admin panels (phpMyAdmin, Adminer)
    | Cache management interfaces (Redis, Memcached)

## 3. API & Data Flow Analysis
### API Surface
    | Hidden GraphQL introspection      | REST parameter fuzzing        | SOAP WSDL inspection
    | gRPC service mapping              | Webhook testing endpoints     | Mobile API backends

### Data Channels
    | WebSocket message formats         | SSE event structures          | PostMessage communication
    | CORS policy analysis              | JSONP callback handlers

## 4. Security Headers & Configs
### Header Analysis
    | CORS misconfigurations            | CSP bypass opportunities      | HSTS preload status
    | X-Forwarded-* header handling     | Cache-Control directives      | Feature-Policy implementations

### Crypto Analysis
    | JWT implementation flaws          | Session cookie attributes     | TLS/SSL cipher suites
    | Certificate transparency          | HPKP implementations

## 5. JavaScript Recon
### Client-Side Analysis
    | Source-mapped code reconstruction         | API key leaks in JS bundles       | WebAssembly decompilation
    | Electron ASAR extraction                  | Service worker inspection         | localStorage/sessionStorage usage

### Framework-Specific
    | React component state analysis            | Angular template injection points     | Vue.js devtools exposure
    | Webpack chunk analysis                    | jQuery selector patterns

## 6. Advanced Google Dorks (Web Apps Only)
    | ```sql                        | site:target.com inurl:api/v1 intext:"token"       | intitle:"index of" intext:"uploads" 
    | filetype:env DB_PASSWORD      | inurl:/wp-json/wp/v2/users                        | site:github.com "target.com" password 
    | ext:yml | yaml database_password

## 7. Specialized Web Checks
    - CMS-Specific 
        | WordPress (xmlrpc.php, wp-json)   | Drupal (rest endpoint config)         | Joomla (component parameters) 
        | Magento (adminhtml paths)         | Shopify (liquid template injection)

    - Modern Web Tech 
        | WebRTC internal IP leaks          | WebSocket protocol hijacking      | WebAuthn implementation flaws 
        | WebAssembly memory corruption     | IndexedDB data exposure           | BroadcastChannel abuse
## 8. Continuous Monitoring 
    | JavaScript changelog monitoring       | New API endpoint detection        | Third-party script changes 
    | Subresource integrity checks          | CSP policy updates


# Bug Bounty Information Gathering Checklist
 
## Google Dorking
    | Exposed config files          | Login pages               | Subdomains            | API endpoints 
    | Admin panels                  | Backup files              | Directory listings    | Sensitive documents 
    | Error logs                    | Database dumps            | Public shared files   | Test environments 
    | Email addresses               | Leaked credentials        | S3 buckets            | Cloud storage 
    | Misconfigured servers         | PHP info pages            | Robots.txt            | Sitemap.xml 
    | Tech stack                    | Job postings              | Employee names        | Forum discussions 
    | Breach data                   | Cached pages              | Historical data       | Subdomains in JS 
    | Swagger docs                  | GraphQL endpoints         | Exposed Jenkins       | Exposed Git repos 
    | SSH keys                      | AWS credentials           | API keys              | Tokens 
    | WordPress sites               | Drupal sites              | Joomla sites          | Magento sites 
    | Exposed webcams               | Exposed FTP               | Exposed SMTP          | Exposed RDP 
    | Exposed VNC                   | Exposed MongoDB           | Exposed Redis         | Exposed Elasticsearch 
    | Exposed Memcached             | Leaked source code        | Exposed env files     | Exposed Docker configs 
    | Exposed Kubernetes

## WHOIS Lookup
    | Domain registrant name                | Registrant organization               | Registrant email      
    | Registrant phone number               | Registrant address                    | Registrar name                
    | Registrar URL                         | Registrar abuse contact               | Domain creation date
    | Domain expiration date                | Domain last updated date              | Name servers
    | DNSSEC status                         | Domain status (e.g., clientTransferProhibited)
    | Administrative contact name           | Administrative contact email          | Administrative contact phone
    | Technical contact name                | Technical contact email               | Technical contact phone
    | Billing contact name                  | Billing contact email                 | Billing contact phone
    | Domain privacy protection status      | Registrar IANA ID                     | WHOIS server
    | Registry domain ID                    | Reseller information                  | Domain transfer lock status
    | Auto-renewal status                   | Associated IPv4 addresses             | Associated IPv6 addresses
    | MX records                            | TXT records                           | SPF records
    | DKIM records                          | DMARC records                         | SOA record
    | NS record details                     | A record details                      | AAAA record details
    | CNAME records                         | PTR records                           | SRV records
    | Historical WHOIS data                 | Domain age                            | Registrar reputation
    | Associated TLDs                       | Subdomain enumeration via WHOIS       | WHOIS data consistency across registrars
    | Anomalies in contact details          | Cross-reference with breach databases | WHOIS data export for analysis

## Reverse WHOIS Lookup
    - Domains without privacy protection
    - Domains hosted on same server
    - Domains linked to breach data
    - Cross-reference with public datasets

    - Domains sharing 
        |  MX records       | TXT records

    - Domains by 
        | registrant name                   | registrant email                  | registrant organization           
        | registrant phone                  | administrative contact            | technical contact 
        | billing contact                   | registrar                         | name server 
        | WHOIS server                      | IP address                        | ASN 
        | country                           | city                              | postal code 
        | creation date range               | expiration date range             | last updated date
    

    - Domains with 
        | privacy protection        | specific TLDs             | similar naming patterns       | SPF records 
        | DKIM records              | DMARC records             | identical SOA records         | matching NS records 
        | similar A records         | similar AAAA records      | matching CNAME records        | shared hosting provider 
        | common CMS                | similar tech stack        | exposed admin panels          | known vulnerabilities 
        | exposed subdomains        | test environments         | staging servers               | exposed APIs 
        | GraphQL endpoints         | Swagger docs              | exposed Git repos             | leaked credentials 
        | exposed cloud storage     | misconfigured DNS         | outdated SSL/TLS              | expired certificates 
        | weak cipher suites


## Enumeration Techniques
    | Subdomain enumeration             - Use tools like Sublist3r, Amass, or Subfinder
    | Passive subdomain discovery       - Check crt.sh for certificate transparency logs
    | Active subdomain scanning         - Bruteforce with gobuster or ffuf
    | DNS enumeration                   - Query A, AAAA, CNAME, MX, TXT, NS, SOA records
    | Zone transfer attempts            - Test for misconfigured DNS servers
    | Reverse DNS lookup                - Identify IPs associated with target domains
    | Wildcard subdomain checks         - Identify wildcard DNS responses
    | Subdomain takeover checks         - Scan for dangling DNS records
    | Port scanning                     - Use nmap for TCP/UDP port discovery
    | Service enumeration               - Identify running services (HTTP, FTP, SSH, etc.)
    | Banner grabbing                   - Capture service versions and details
    | SNMP enumeration                  - Check for exposed SNMP services
    | SMTP enumeration                  - Test for open relays or user enumeration
    | SMB enumeration                   - Identify shares, users, or misconfigurations
    | NFS enumeration                   - Check for exposed Network File Systems
    | RDP enumeration                   - Identify exposed Remote Desktop services
    | VNC enumeration                   - Check for exposed VNC servers
    | Web server enumeration            - Identify server type (Apache, Nginx, IIS)
    | Web application fingerprinting    - Detect CMS (WordPress, Drupal, etc.)
    | Directory brute-forcing           - Use dirb, gobuster, or ffuf for hidden paths
    | File extension scanning           - Search for .bak, .php, .sql, .env files
    | API endpoint enumeration          - Discover REST, SOAP, or GraphQL endpoints
    | WAF detection                     - Identify Web Application Firewalls (Cloudflare, Akamai)
    | SSL/TLS enumeration               - Check cipher suites, certificate details
    | Expired SSL certificates          - Identify outdated or invalid certificates
    | HTTP method enumeration           - Test for PUT, DELETE, or TRACE methods
    | Virtual host enumeration          - Discover hidden vhosts on same IP
    | Cloud storage enumeration         - Check S3, Azure Blob, Google Storage
    | Git repository exposure           - Search for exposed .git directories
    | SVN repository exposure           - Check for exposed .svn directories
    | Database enumeration              - Identify exposed MySQL, MongoDB, Redis
    | Elasticsearch exposure            - Check for open Elasticsearch instances
    | Memcached exposure                - Test for exposed Memcached servers
    | Jenkins exposure                  - Identify open Jenkins dashboards
    | Kubernetes enumeration            - Check for exposed K8s dashboards or APIs
    | Docker enumeration                - Identify exposed Docker APIs or containers
    | WordPress enumeration             - Scan for plugins, themes, users
    | Drupal enumeration                - Identify modules and versions
    | Joomla enumeration                - Check components and extensions
    | Magento enumeration               - Identify admin paths and modules
    | Email enumeration                 - Verify valid email addresses via SMTP
    | User enumeration                  - Test login pages for username leaks
    | Password policy enumeration       - Analyze password requirements
    | Session cookie analysis           - Check cookie attributes (Secure, HttpOnly)
    | Hidden form fields                - Inspect for sensitive data in HTML
    | JavaScript file analysis          - Extract endpoints, keys, or tokens
    | Source code comments              - Search for sensitive info in HTML/JS
    | Robots.txt analysis               - Identify disallowed paths for testing
    | Sitemap.xml analysis              - Discover additional endpoints
    | Cross-domain policy files         - Check crossdomain.xml or clientaccesspolicy.xml
    | CORS misconfiguration             - Test for overly permissive CORS headers
    | Web socket enumeration            - Identify open WebSocket endpoints
    | Server-side template injection    - Test for SSTI in input fields
    | GraphQL introspection             - Query schema for sensitive fields

## Vulnerability Scanning
    | XSS testing                   - Inject payloads in forms, URLs, headers
    | SQL injection                 - Test inputs for database errors
    | Command injection             - Inject OS commands in input fields
    | File inclusion                - Test for LFI/RFI vulnerabilities
    | CSRF testing                  - Check for missing CSRF tokens
    | SSRF testing                  - Attempt to access internal resources
    | IDOR checks                   - Manipulate object IDs in requests
    | Authentication bypass         - Test weak login mechanisms
    | Session fixation              - Check for reusable session IDs
    | Broken access control         - Test privilege escalation
    | Insecure deserialization      - Inject malicious payloads
    | XML external entity (XXE)     - Test XML parsers
    | Open redirects                - Manipulate redirect parameters
    | Directory traversal           - Test for path traversal
    | HTTP smuggling                - Test for request smuggling
    | Clickjacking                  - Check for missing X-Frame-Options
    | CORS misconfiguration         - Exploit permissive CORS
    | Subdomain takeover            - Exploit dangling DNS records
    | SSTI testing                  - Inject template payloads
    | API abuse                     - Test rate limits, unauthorized access
    | GraphQL vulnerabilities       - Test for overfetching, DoS
    | WebSocket vulnerabilities     - Test for injection, DoS
    | Misconfigured headers         - Check for missing security headers
    | Weak SSL/TLS                  - Test for outdated protocols
    | Exposed admin panels          - Test default credentials
    | WordPress vulnerabilities     - Scan for outdated plugins
    | Drupal vulnerabilities        - Check for unpatched modules
    | Joomla vulnerabilities        - Test for known exploits
    | Magento vulnerabilities       - Scan for misconfigurations
    | Default credentials           - Test common username/passwords
    | Exposed backups               - Download .bak or .sql files
    | Exposed .env files            - Check for API keys, credentials
    | Cloud storage misconfigs      - Test for public S3 buckets
    | Exposed Git repos             - Extract sensitive data from .git
    | Exposed databases             - Test for unauthenticated access
    | Redis misconfiguration        - Test for unauthenticated writes
    | Elasticsearch exposure        - Test for data leaks
    | Memcached exposure            - Test for unauthorized access
    | Jenkins vulnerabilities       - Test for unauthenticated access
    | Kubernetes misconfigs         - Test for exposed APIs
    | Docker misconfigs             - Test for exposed containers
    | SMTP open relay               - Test for email spoofing
    | SMB vulnerabilities           - Test for outdated protocols
    | NFS misconfigs                - Test for unauthorized access
    | RDP vulnerabilities           - Test for weak credentials
    | VNC vulnerabilities           - Test for default passwords
    | Weak password policies        - Test for guessable passwords
    | Credential stuffing           - Test with leaked credentials
    | Business logic flaws          - Test for workflow bypasses
    | Rate limit bypass             - Test for unlimited requests
    | Cache poisoning               - Test for cache manipulation
    | Host header injection         - Test for header manipulation
    | Parameter tampering           - Manipulate query parameters
    | OAuth misconfigs              - Test for token leaks
