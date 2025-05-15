# 🔧 CONFIGURATION & DEPLOYMENT TESTING CHECKLIST

## 2.1 Network Infrastructure Configuration
    -  Verify firewall rules and port filtering
    -  Test for open management ports (SSH, RDP, SNMP)
    -  Check for TLS/SSL misconfigurations (SSLv3, weak ciphers)
    -  Test for DNS/Email security (SPF, DKIM, DMARC)
    -  Verify load balancer/WAF configuration
    -  Check for exposed database ports

## 2.2 Application Platform Configuration
    -  Verify default credentials on admin interfaces
    -  Test for verbose error messages
    -  Check unnecessary services/features enabled
    -  Verify secure cookie settings (HttpOnly, Secure flags)
    -  Test for debug mode enabled in production
    -  Check for outdated middleware/components

## 2.3 File Extensions Handling
    -  Test for sensitive files (.env, config.json)
    -  Check source code exposure (.php, .jsp)
    -  Verify proper handling of double extensions
    -  Test for directory listing vulnerabilities
    -  Check for exposed git/version control files

## 2.4 Backup and Unreferenced Files
    -  Search for common backup patterns (.bak, ~, .old)
    -  Check for temporary files (.tmp, .swp)
    -  Verify IDE/editor artifacts (.idea, .vscode)
    -  Test for compiled file exposure (.class, .pyc)
    -  Check for database dumps (.sql, .mdb)

## 2.5 Admin Interfaces Enumeration
    -  Scan for common admin paths (/admin, /manager)
    -  Test default credentials on found interfaces
    -  Verify IP-based restrictions
    -  Check for exposed API documentation
    -  Test for privilege escalation in admin panels

## 2.6 HTTP Methods Testing
    -  Test OPTIONS method for allowed verbs
    -  Verify TRACE method disabled
    -  Test PUT/DELETE method vulnerabilities
    -  Check for WebDAV misconfigurations
    -  Verify HEAD method behavior

## 2.7 HTTP Strict Transport Security
    -  Verify HSTS header presence
    -  Check max-age directive (≥6 months)
    -  Test includeSubDomains implementation
    -  Verify preload directive usage
    -  Check for HSTS bypass techniques

## 2.8 RIA Cross Domain Policy
    -  Check crossdomain.xml policy files
    -  Verify clientaccesspolicy.xml restrictions
    -  Test for overly permissive policies
    -  Check for domain wildcard misuse
    -  Verify same-origin policy enforcement

## 2.9 File Permissions
    -  Test world-writable files/directories
    -  Verify proper ownership of sensitive files
    -  Check umask settings
    -  Test for race conditions
    -  Verify configuration file permissions

## 2.10 Subdomain Takeover
    -  Check dangling DNS records
    -  Test expired cloud service instances
    -  Verify GitHub Pages/Azure takeover potential
    -  Check for abandoned AWS S3 buckets
    -  Test Heroku/Azure app subdomains

## 2.11 Cloud Storage Testing
    -  Test for open S3/GCS/Azure buckets
    -  Verify bucket permission settings
    -  Check for sensitive data in cloud storage
    -  Test signed URL expiration
    -  Verify encryption-at-rest implementation

## 2.12 Content Security Policy
    -  Verify CSP header presence
    -  Test for unsafe directives (unsafe-inline)
    -  Check script-src restrictions
    -  Verify report-uri functionality
    -  Test CSP bypass techniques

## 2.13 Path Confusion
    -  Test path traversal vulnerabilities
    -  Check for path normalization issues
    -  Verify URL encoding handling
    -  Test for open redirects
    -  Check for symlink attacks

## 2.14 Other HTTP Security Headers
    -  Verify X-Frame-Options
    -  Check X-Content-Type-Options
    -  Test X-XSS-Protection
    -  Verify Referrer-Policy
    -  Check Feature-Policy
    -  Test Permissions-Policy
    -  Verify Expect-CT header
    -  Check Cache-Control directives