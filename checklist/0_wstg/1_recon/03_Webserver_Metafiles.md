# 🔍 WEBSERVER METAFILES INFORMATION LEAKAGE TESTING CHECKLIST

 ## Comprehensive Webserver Metafiles Analysis

### 1 robots.txt Analysis
    - Standard Robots.txt Examination:
      * Location: http://target.com/robots.txt
      * User-agent directives analysis
      * Disallowed directory enumeration
      * Allowed path verification
      * Crawl-delay directives

    - Sensitive Path Discovery:
      * Admin interfaces: Disallow: /admin/, /administrator/
      * Configuration files: Disallow: /config/, /includes/
      * Backup directories: Disallow: /backup/, /backups/
      * Database files: Disallow: /db/, /database/
      * Log files: Disallow: /logs/, /temp/

    - Advanced Robots.txt Techniques:
      * Case-sensitive path testing
      * URL encoding variations
      * Wildcard pattern analysis
      * Comment analysis in robots.txt

### 2 sitemap.xml Analysis
    - Sitemap Structure Examination:
      * Location: http://target.com/sitemap.xml
      * Sitemap index files analysis
      * URL entry examination
      * Last modification dates
      * Change frequency patterns

    - Hidden Content Discovery:
      * Unlinked page identification
      * Development/staging URLs
      * Administrative interfaces
      * API endpoints in sitemaps

    - Sitemap Security Analysis:
      * Password-protected areas in sitemap
      * Internal network URLs exposure
      * Backup file references
      * Configuration file locations

### 3 well-known Directory Analysis
    - Security Policy Files:
      * security.txt: /.well-known/security.txt
      * keybase.txt: /.well-known/keybase.txt
      * gpc.json: /.well-known/gpc.json (Global Privacy Control)

    - Authentication and Verification:
      * acme-challenge: /.well-known/acme-challenge/ (Let's Encrypt)
      * apple-developer-merchantid-domain-association
      * assetlinks.json: /.well-known/assetlinks.json (Android App Links)
      * apple-app-site-association

    - Protocol Handlers:
      * openid-configuration: /.well-known/openid-configuration
      * oauth-authorization-server
      * webfinger: /.well-known/webfinger
      * nodeinfo: /.well-known/nodeinfo

### 4 Cross-Domain Policy Files
    - crossdomain.xml Analysis:
      * Location: http://target.com/crossdomain.xml
      * Domain whitelist examination
      * allow-access-from domain directives
      * allow-http-request-headers-from
      * Site control policies

    - clientaccesspolicy.xml (Silverlight):
      * Location: http://target.com/clientaccesspolicy.xml
      * Domain access rules
      * Resource path permissions
      * HTTP method allowances

### 5 Configuration File Discovery
    - Web Server Configuration:
      * htaccess (Apache): Sensitive directives, auth configurations
      * web.config (IIS): Application settings, connection strings
      * nginx.conf: Server block configurations
      * httpd.conf: Main server configuration

    - Application Configuration:
      * env: Environment variables, API keys, database credentials
      * config.php, settings.py, config.json
      * application.properties (Java Spring)
      * appsettings.json (.NET Core)

    - IDE and Editor Files:
      * idea/ (JetBrains IDE)
      * vscode/ (Visual Studio Code)
      * project, classpath (Eclipse)
      * Thumbs.db (Windows)

### 6 Version Control System Files
    - Git Repository Exposure:
      * /.git/HEAD
      * /.git/config
      * /.git/logs/HEAD
      * /.git/refs/heads/master
      * /.git/index

    - SVN Repository Files:
      * /.svn/entries
      * /.svn/wc.db
      * /.svn/pristine/
      * /.svn/prop-base/

    - Mercurial Files:
      * /.hg/requires
      * /.hg/branch
      * /.hg/cache/
      * /.hg/dirstate

### 7 Backup and Temporary Files
    - Common Backup Extensions:
      * bak, backup, old, tmp
      * save, orig, previous
      * ~ (tilde backup files)
      * _ (underscore backups)

    - Database Backup Files:
      * sql, dump, export
      * mdb, accdb (Access databases)
      * db, sqlite, sqlite3

    - Compressed Backups:
      * zip, tar, tar.gz, tgz
      * rar, 7z, gz
      * backup.zip, site.tar.gz

### 8 Log File Discovery
    - Access Logs:
      * /logs/access.log
      * /var/log/apache2/access.log
      * /var/log/nginx/access.log
      * /inetpub/logs/LogFiles/

    - Error Logs:
      * /logs/error.log
      * /var/log/apache2/error.log
      * /var/log/nginx/error.log
      * application error logs

    - Application Specific Logs:
      * debug.log, system.log
      * audit.log, security.log
      * Custom application logs

### 9 CMS and Framework Specific Files
    - WordPress:
      * /wp-config.php
      * /wp-content/debug.log
      * /wp-content/backup-*
      * /wp-admin/install.php

    - Drupal:
      * /sites/default/settings.php
      * /sites/default/default.settings.php
      * /sites/default/files/

    - Joomla:
      * /configuration.php
      * /administrator/logs/
      * /tmp/ directory

    - Laravel:
      * /.env
      * /storage/logs/laravel.log
      * /bootstrap/cache/

### 10 DNS and SSL Meta Files
    - DNS Record Files:
      * zone files exposure
      * DNS configuration files
      * BIND configuration files

    - SSL Certificate Files:
      * Private key exposure (.key files)
      * Certificate signing requests (.csr)
      * Certificate bundles (.pem, crt)
      * Keystore files (.jks, keystore)

### 11 Cloud Configuration Files
    - AWS Configuration:
      * aws/credentials
      * aws/config
      * cloudformation templates
      * terraform.tfstate

    - Azure Configuration:
      * azure/config
      * arm templates
      * app service configurations

    - Google Cloud:
      * gcloud/configuration
      * deployment manager configurations
      * service account keys

### 12 Automated Discovery Tools
    - Metafile Scanners:
      * dirb, dirbuster, gobuster
      * ffuf, wfuzz for pattern matching
      * Metasploit auxiliary modules
      * Custom Python scripts

    - Specialized Tools:
      * GitHacker: Git repository recovery
      * DVCS-Pillage: Version control system pillaging
      * truffleHog: Secret scanning in files
      * git-secrets: AWS key detection

    - Browser Extensions:
      * Wappalyzer for technology detection
      * BuiltWith for infrastructure analysis
      * FoxyProxy for request interception

#### Testing Methodology:
    Initial Discovery Phase:
    1. Check standard metafiles (robots.txt, sitemap.xml)
    2. Examine well-known directory contents
    3. Look for cross-domain policy files
    4. Search for configuration files

    Deep Analysis Phase:
    1. Version control system file discovery
    2. Backup file identification
    3. Log file location testing
    4. CMS-specific file examination

    Advanced Techniques:
    1. Pattern-based file discovery
    2. Historical file analysis
    3. Backup file recovery attempts
    4. Source code reconstruction

#### Common Metafile Locations:
    Standard Locations:
    - /robots.txt
    - /sitemap.xml
    - /.well-known/security.txt
    - /crossdomain.xml
    - /clientaccesspolicy.xml

    Configuration Files:
    - /.htaccess
    - /web.config
    - /.env
    - /config.php

    Version Control:
    - /.git/HEAD
    - /.svn/entries
    - /.hg/requires

#### Tools and Commands Examples:
    Basic File Discovery:
    curl -s http://target.com/robots.txt
    wget http://target.com/sitemap.xml
    curl -s http://target.com/.well-known/security.txt

    Automated Scanning:
    gobuster dir -u http://target.com -w common-metafiles.txt
    ffuf -u http://target.com/FUZZ -w metafiles-wordlist.txt
    dirb http://target.com /usr/share/dirb/wordlists/common.txt

    Git Repository Analysis:
    git-dumper http://target.com/.git/ /output-dir
    DVCS-Pillage target.com

#### Security Headers to Check:
    Information Disclosure Prevention:
    - X-Robots-Tag: none
    - Secure metafile access controls
    - Proper file permissions
    - Regular security scans

#### Documentation Template:
    Metafiles Analysis Report:
    - Target: target.com
    - Robots.txt: Found, X disallowed paths
    - Sitemap.xml: Found, X URLs discovered
    - Configuration Files: X sensitive files exposed
    - Version Control: Git/SVN exposure detected
    - Backup Files: X backup files accessible
    - Recommendations: [List of security improvements]

#### Protection Mechanisms:
    - Access Control:
      * Restrict metafile access via web server configuration
      * Implement authentication for sensitive files
      * Use proper file permissions

    - Content Management:
      * Regular security audits of exposed files
      * Remove unnecessary metafiles
      * Implement monitoring for sensitive file access

    - Security Headers:
      * X-Robots-Tag for search engine control
      * Proper cache-control headers
      * Security.txt implementation

This comprehensive webserver metafiles testing checklist helps identify information leakage through exposed configuration files, backup files, and other metadata while providing methodology for thorough security assessment.