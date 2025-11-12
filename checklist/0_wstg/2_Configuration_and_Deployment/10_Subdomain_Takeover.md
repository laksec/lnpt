# 🔍 SUBDOMAIN TAKEOVER TESTING CHECKLIST

## 2.5 Comprehensive Subdomain Takeover Testing

### 2.5.1 Subdomain Enumeration & Discovery
    - Comprehensive Subdomain Discovery:
      * DNS enumeration: `subfinder -d example.com`, `amass enum -d example.com`
      * Certificate transparency logs: `crt.sh`, `censys.io`, `shodan.io`
      * Search engine dorking: `site:*.example.com`
      * DNS brute forcing: `gobuster dns -d example.com -w subdomains.txt`
      * Passive DNS replication data

    - Subdomain Verification:
      * Active DNS resolution of discovered subdomains
      * HTTP/HTTPS service detection on resolved IPs
      * Port scanning for web services (80, 443, 8080, 8443)
      * Verify subdomain accessibility and content

### 2.5.2 CNAME Record Analysis
    - CNAME Record Discovery:
      * DNS queries: `dig CNAME subdomain.example.com`
      * Bulk CNAME extraction: `dig -f subdomains.txt CNAME +short`
      * Third-party service identification in CNAME records
      * Historical CNAME record analysis

    - Third-Party Service Mapping:
      * Cloud services: AWS, Azure, Google Cloud, Heroku
      * CDN providers: CloudFlare, Akamai, Fastly, CloudFront
      * SaaS platforms: GitHub Pages, Shopify, Zendesk, Statuspage
      * Development platforms: Netlify, Vercel, Heroku, Firebase

### 2.5.3 Cloud Service Takeover Testing
    - AWS S3 Bucket Takeover:
      * CNAME to *.s3.amazonaws.com, *.s3-website-*.amazonaws.com
      * Test for "NoSuchBucket" errors
      * Check for bucket policy misconfigurations
      * Verify bucket ownership availability

    - Azure Blob Storage:
      * CNAME to *.blob.core.windows.net
      * Test for "ResourceNotFound" errors
      * Check storage account availability
      * Verify custom domain configuration

    - Google Cloud Storage:
      * CNAME to *.storage.googleapis.com
      * Test for "NoSuchBucket" errors
      * Check bucket naming availability
      * Verify domain verification status

### 2.5.4 CDN & Edge Service Takeover
    - CloudFlare Takeover:
      * CNAME to *.cloudflare.net, *.pages.dev
      * Test for "404 Not Found" on CloudFlare Pages
      * Check for orphaned CloudFlare Spectrum applications
      * Verify CloudFlare Workers subdomain availability

    - Fastly Takeover:
      * CNAME to *.fastly.net, *.global.prod.fastly.net
      * Test for "Fastly error: unknown domain" messages
      * Check for unclaimed Fastly services
      * Verify service configuration

    - Akamai Edge Hostname:
      * CNAME to *.akamaized.net, *.edgekey.net
      * Test for "Invalid URL" or Akamai error pages
      * Check for unconfigured edge hostnames
      * Verify property activation status

### 5.5 Development Platform Takeover
    - GitHub Pages Takeover:
      * CNAME to *.github.io, *.githubusercontent.com
      * Test for "There isn't a GitHub Pages site here"
      * Check for available GitHub usernames/organizations
      * Verify custom domain configuration

    - Heroku App Takeover:
      * CNAME to *.herokuapp.com
      * Test for "No such app" errors
      * Check for available Heroku subdomain names
      * Verify Heroku custom domain settings

    - Netlify Takeover:
      * CNAME to *.netlify.app, *.netlify.com
      * Test for "Not Found - Request ID" errors
      * Check for available Netlify subdomains
      * Verify custom domain configuration

### 2.5.6 SaaS Platform Takeover
    - Shopify Store Takeover:
      * CNAME to *.myshopify.com
      * Test for "Sorry, this shop is currently unavailable"
      * Check for expired Shopify stores
      * Verify custom domain availability

    - Zendesk Guide Takeover:
      * CNAME to *.zendesk.com
      * Test for "Help Center no longer available"
      * Check for unclaimed Zendesk instances
      * Verify help center configuration

    - Statuspage Takeover:
      * CNAME to *.statuspage.io
      * Test for "This statuspage does not exist"
      * Check for available status page subdomains
      * Verify custom domain settings

### 2.5.7 Email & Communication Service Takeover
    - Help Scout Takeover:
      * CNAME to *.helpscoutdocs.com, *.helpscout.net
      * Test for "No Site Found" errors
      * Check for documentation site availability
      * Verify custom domain configuration

    - Intercom Takeover:
      * CNAME to *.intercom.help, *.intercom.io
      * Test for "This page is not available" messages
      * Check for unclaimed Intercom resources
      * Verify help center settings

    - Freshdesk Takeover:
      * CNAME to *.freshdesk.com
      * Test for "Account Suspended" or "No such account"
      * Check for available Freshdesk instances
      * Verify domain configuration

### 2.5.8 Modern Development Platform Takeover
    - Vercel/Zeit Takeover:
      * CNAME to *.vercel.app, *.now.sh
      * Test for "404: NOT_FOUND" errors
      * Check for available deployment slots
      * Verify project domain settings

    - Firebase Hosting Takeover:
      * CNAME to *.web.app, *.firebaseapp.com
      * Test for "Site Not Found" errors
      * Check for available Firebase projects
      * Verify custom domain configuration

    - GitLab Pages Takeover:
      * CNAME to *.gitlab.io
      * Test for "The page could not be found or is private"
      * Check for available GitLab namespaces
      * Verify custom domain settings

### 2.5.9 Advanced Takeover Techniques
    - Wildcard Subdomain Takeover:
      * Test for *.example.com pointing to vulnerable services
      * Check for wildcard CNAME records
      * Verify all possible subdomain combinations
      * Test for recursive takeover possibilities

    - DNS Record Chain Analysis:
      * Multiple CNAME record chains
      * ALIAS and ANAME record analysis
      * DNAME record redirection testing
      * NS record delegation vulnerabilities

    - Historical Takeover Analysis:
      * DNS history analysis
      * Certificate transparency log history
      * Wayback Machine analysis
      * Historical IP address assignments

### 2.5.10 Automated Takeover Detection
    - Subdomain Takeover Tools:
      * Subjack: `subjack -w subdomains.txt -t 100 -ssl`
      * Takeover: `takeover -l subdomains.txt -v`
      * SubOver: `subover -l subdomains.txt`
      * AutoSubTakeover: Automated detection framework

    - Custom Detection Scripts:
      * Python with dnspython and requests
      * Bash scripts with dig and curl
      * Go-based high-performance scanners
      * Integration with bug bounty platforms

### 2.5.11 Proof-of-Concept Validation
    - Safe PoC Creation:
      * Create harmless test content
      * Use non-malicious verification files
      * Temporary PoC deployment
      * Immediate cleanup after validation

    - Service-Specific PoC:
      * AWS S3: Upload simple HTML file
      * GitHub Pages: Create minimal Jekyll site
      * Heroku: Deploy basic Node.js application
      * Netlify: Deploy static HTML page

### 2.5.12 Impact Assessment
    - Security Impact Analysis:
      * Cookie stealing via controlled subdomain
      * Phishing attacks from legitimate-looking domain
      * Content spoofing and defacement
      * SSL certificate issuance for subdomain

    - Business Impact Assessment:
      * Brand reputation damage
      * Customer trust impact
      * SEO and search ranking implications
      * Legal and compliance consequences

#### Testing Methodology:
    Phase 1: Discovery
    1. Comprehensive subdomain enumeration
    2. DNS record analysis (CNAME, A, AAAA)
    3. Service fingerprinting and identification
    4. Historical data analysis

    Phase 2: Vulnerability Detection
    1. Test for service-specific error patterns
    2. Verify service availability for registration
    3. Check for dangling DNS records
    4. Identify wildcard subdomain vulnerabilities

    Phase 3: Validation
    1. Safe PoC creation and testing
    2. Impact verification without harm
    3. Service reclamation prevention
    4. Documentation and evidence collection

    Phase 4: Reporting
    1. Risk assessment and scoring
    2. Remediation recommendations
    3. Evidence documentation
    4. Follow-up verification

#### Common Vulnerable Patterns:
    AWS S3:
    CNAME: static.example.com → bucket.s3.amazonaws.com
    Error: NoSuchBucket, AccessDenied

    GitHub Pages:
    CNAME: docs.example.com → org.github.io
    Error: "There isn't a GitHub Pages site here"

    Heroku:
    CNAME: app.example.com → app.herokuapp.com
    Error: "No such app"

    CloudFlare:
    CNAME: cdn.example.com → custom.cloudflare.net
    Error: "404 Not Found"

#### Risk Assessment Framework:
    Critical Risk:
    - Wildcard subdomain takeover
    - High-traffic subdomains (www, api, cdn)
    - Authentication-related subdomains (auth, login)
    - Financial transaction subdomains

    High Risk:
    - Main application subdomains
    - Customer-facing subdomains
    - API endpoints
    - Marketing and documentation sites

    Medium Risk:
    - Development/staging subdomains
    - Legacy application subdomains
    - Internal tool subdomains
    - Archive subdomains

    Low Risk:
    - Unused test subdomains
    - Non-public internal subdomains
    - Legacy redirect subdomains
    - Temporary project subdomains

#### Prevention and Remediation:
    - DNS Management Best Practices:
      * Regular DNS record audits
      * Monitor for dangling CNAME records
      * Implement DNS change controls
      * Use DNS monitoring and alerting

    - Cloud Service Management:
      * Maintain active service subscriptions
      * Monitor cloud resource lifecycle
      * Implement resource tagging and ownership
      * Regular cloud infrastructure audits

    - Development Process Integration:
      * Include DNS checks in CI/CD pipelines
      * Automated subdomain monitoring
      * Pre-deployment DNS validation
      * Post-decommission DNS cleanup

#### Testing Execution Framework:
    Step 1: Reconnaissance
    - Subdomain enumeration
    - DNS record collection
    - Service identification
    - Historical analysis

    Step 2: Vulnerability Scanning
    - Automated takeover detection
    - Manual verification of findings
    - Service availability checking
    - PoC feasibility assessment

    Step 3: Validation
    - Safe PoC implementation
    - Impact verification
    - Evidence collection
    - Cleanup and restoration

    Step 4: Reporting
    - Vulnerability documentation
    - Risk assessment
    - Remediation guidance
    - Prevention recommendations

#### Documentation Template:
    Subdomain Takeover Assessment Report:
    - Assessment Scope and Methodology
    - Vulnerable Subdomains Identified
    - Service Types and Risk Levels
    - Evidence and Proof of Concept
    - Impact Analysis
    - Remediation Recommendations
    - Prevention Strategies
    - Ongoing Monitoring Recommendations

This comprehensive subdomain takeover testing checklist provides systematic identification of vulnerable subdomains, helping organizations prevent domain hijacking, phishing attacks, and brand reputation damage through proper DNS and cloud service management.