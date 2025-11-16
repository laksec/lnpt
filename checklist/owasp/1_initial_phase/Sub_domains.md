# ULTIMATE SUBDOMAINS, LIVE URLs & SUBDIRECTORIES CHECKLIST (v1.0)

### Comprehensive Methodology for Surface Discovery

### 🌐 SUBDOMAIN ENUMERATION TECHNIQUES

    - Perform DNS zone transfers (AXFR) if allowed
    - Check certificate transparency logs (crt.sh)
    - Query VirusTotal for related domains
    - Search GitHub/GitLab for domain references
    - Check historical DNS records (DNSDumpster)
    - Examine SSL certificates for alternate names
    - Search web archives (Wayback Machine)
    - Check domain brute-forcing (wordlists)
    - Verify subdomains in robots.txt/sitemap.xml
    - Examine JS files for hidden API endpoints
    - Check cloud provider metadata (AWS/Azure/GCP)
    - Search for organization ASNs
    - Verify DNS CNAME records
    - Check subdomain takeovers (canary tokens)
    - Examine email headers (MX records)
    - Search SPF/DMARC records
    - Check CDN configurations
    - Verify domain parking pages
    - Examine analytics/tracking codes
    - Search for domain acquisitions

### 🚀 LIVE URL DISCOVERY METHODS

    - Perform recursive directory brute-forcing
    - Check common admin paths (/admin, /backup)
    - Verify API documentation endpoints
    - Search for config files (.env, config.php)
    - Examine backup files (.bak, old, zip)
    - Check for exposed git repositories (.git)
    - Verify temporary files (/tmp, /uploads)
    - Search for log files (access.log, error.log)
    - Examine installation directories (/install)
    - Check CMS-specific paths (wp-admin, /umbraco)
    - Verify development/staging environments
    - Search for test files (test.php, debug.html)
    - Examine old version paths (/v1, /legacy)
    - Check mobile app API endpoints
    - Verify web service paths (/api, /rest)
    - Search for exposed database interfaces
    - Examine monitoring paths (/grafana, /prometheus)
    - Check CI/CD interfaces (/jenkins, /gitlab)
    - Verify cloud management consoles
    - Search for documentation portals (/docs)

### 📂 SUBDIRECTORY TESTING APPROACH

    - Check for directory listing enabled
    - Verify sensitive file exposure
    - Test path traversal vulnerabilities
    - Examine symbolic link possibilities
    - Search for hardcoded credentials
    - Check for htaccess misconfigurations
    - Verify web server type (Apache/Nginx/IIS)
    - Examine server status pages (/server-status)
    - Search for phpinfo() exposure
    - Check for exposed source code
    - Verify file upload directories
    - Examine cache directories
    - Search for session storage paths
    - Check for temporary file storage
    - Verify media directories (/images, /media)
    - Examine language/locale directories
    - Search for plugin/module paths
    - Check for theme/template directories
    - Verify static resource directories
    - Examine vendor/library paths

### 🛠️ VERIFICATION TECHNIQUES

    - Check HTTP vs HTTPS availability
    - Verify default credentials
    - Test for HTTP methods (OPTIONS, TRACE)
    - Examine response headers
    - Check for open ports (80, 443, 8080)
    - Verify web server version disclosure
    - Test for WAF presence
    - Examine CORS policies
    - Check for HSTS implementation
    - Verify security headers
    - Test for clickjacking protection
    - Examine cookie attributes
    - Check for CSRF tokens
    - Verify session management
    - Test for directory traversal
    - Examine input validation
    - Check for error messages
    - Verify authentication mechanisms
    - Test for parameter pollution
    - Examine cache control headers

### 🔍 CONTENT ANALYSIS METHODS

    - Check for exposed API documentation
    - Verify exposed developer comments
    - Examine JavaScript source maps
    - Search for hardcoded API keys
    - Check for exposed credentials
    - Verify version control exposure
    - Examine build/config files
    - Search for test data
    - Check for PII exposure
    - Verify intellectual property leaks

### 🛡️ SECURITY CHECKS

    - Test for subdomain takeovers
    - Verify domain hijacking possibilities
    - Check for typosquatting domains
    - Examine domain expiration dates
    - Verify DNS record integrity
    - Check for domain spoofing
    - Examine email configurations
    - Verify SPF/DKIM/DMARC
    - Check for certificate validity
    - Verify TLS configurations

### 📝 REPORTING & DOCUMENTATION

    - Document all discovered subdomains
    - Record live URL findings
    - Note sensitive file exposures
    - Document configuration issues
    - Report security misconfigurations
    - Note credential exposures
    - Document PII findings
    - Record intellectual property leaks
    - Note potential attack vectors
    - Provide remediation guidance

### 🛠️ REMEDIATION STRATEGIES

    - Recommend subdomain inventory
    - Suggest regular DNS audits
    - Advocate for certificate monitoring
    - Propose web application firewalls
    - Suggest directory listing disablement
    - Recommend sensitive file removal
    - Advocate for credential rotation
    - Propose security header implementation
    - Suggest continuous monitoring
    - Recommend penetration testing

### 🔄 MAINTENANCE PRACTICES

    - Implement automated subdomain monitoring
    - Enforce certificate transparency checks
    - Regular DNS configuration reviews
    - Continuous web directory scanning
    - Periodic credential scanning
    - Regular backup file audits
    - Continuous security header checks
    - Periodic WAF rule reviews
    - Regular vulnerability scanning
    - Continuous threat intelligence feeds

### 🧠 ADVANCED TECHNIQUES

    - Perform domain permutation analysis
    - Verify domain generation algorithms
    - Check for shadow IT infrastructure
    - Examine acquired company domains
    - Search for legacy system domains
    - Verify M&A transition domains
    - Check for regional domain variants
    - Examine brand-protection domains
    - Search for phishing lookalikes
    - Verify domain parking risks

### ☁️ CLOUD-SPECIFIC CHECKS

    - Check cloud storage buckets
    - Verify serverless function URLs
    - Examine cloud API gateways
    - Search for container registry URLs
    - Check Kubernetes dashboard exposure
    - Verify cloud database interfaces
    - Examine CI/CD pipeline URLs
    - Search for infrastructure-as-code leaks
    - Check cloud monitoring interfaces
    - Verify SaaS configuration portals
