# 🔍 SEARCH ENGINE DISCOVERY & RECONNAISSANCE FOR INFORMATION LEAKAGE

 ## Comprehensive Search Engine Reconnaissance Checklist

### 1 Google Dorking Techniques
    - Basic Search Operators:
      * site: - Restrict to specific domain
      * filetype: - Search for specific file types
      * ext: - File extension search
      * inurl: - Search within URLs
      * intitle: - Search in page titles
      * intext: - Search in page content
      * cache: - View cached versions
      * link: - Find pages linking to target

    - Sensitive File Discovery:
      * Configuration files: ext:env OR ext:yml OR ext:yaml OR ext:config
      * Database dumps: ext:sql OR ext:db OR ext:dbf OR ext:mdb
      * Backup files: ext:bak OR ext:backup OR ext:old OR ext:tmp
      * Log files: ext:log OR ext:logs OR ext:txt "password"
      * SSH keys: "BEGIN RSA PRIVATE KEY" OR "BEGIN DSA PRIVATE KEY"

    - Administrative Interfaces:
      * intitle:"admin" OR intitle:"login" OR intitle:"dashboard"
      * inurl:"admin" OR inurl:"login" OR inurl:"dashboard"
      * inurl:"phpmyadmin" OR inurl:"adminer" OR inurl:"webmin"

### 2 Information Leakage Patterns
    - Credential Exposure:
      * "password" filetype:txt OR filetype:log
      * "api_key" OR "apikey" OR "secret" site:github.com
      * "aws_access_key" OR "aws_secret_key"
      * "database_password" OR "db_password"
      * "ftp://" "password" OR "username"

    - Developer Information:
      * "TODO" OR "FIXME" OR "HACK" site:target.com
      * "debug" OR "console.log" filetype:js
      * "test" OR "staging" OR "dev" site:target.com
      * ".git" (directory listing exposure)

    - Error Messages:
      * "stack trace" OR "error occurred" site:target.com
      * "warning" OR "notice" filetype:php
      * "exception" OR "throw" site:target.com
      * "sql syntax" OR "mysql error"

### 3 Document and File Discovery
    - Office Documents:
      * filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls
      * filetype:ppt OR filetype:pptx OR filetype:odt
      * "confidential" OR "internal" OR "restricted" filetype:pdf

    - Source Code Exposure:
      * filetype:java OR filetype:py OR filetype:php OR filetype:js
      * filetype:cpp OR filetype:c OR filetype:html
      * "index of" ".git" (Git repository exposure)
      * "index of" ".svn" (SVN repository exposure)

    - Database and Backup Files:
      * filetype:sql "INSERT INTO" OR "CREATE TABLE"
      * filetype:dump OR filetype:sql.gz OR filetype:backup
      * "backup" OR "dump" inurl:sql OR inurl:bak

### 4 Directory Listings and Exposed Directories
    - Web Server Listings:
      * "index of" "/uploads"
      * "index of" "/images"
      * "index of" "/backup"
      * "index of" "/database"
      * "index of" "/admin"

    - Application Directories:
      * "index of" "/wp-content" (WordPress)
      * "index of" "/sites/default/files" (Drupal)
      * "index of" "/media" OR "/images"
      * "index of" "/tmp" OR "/temp"

### 5 API and Endpoint Discovery
    - API Documentation:
      * "swagger" OR "openapi" site:target.com
      * "api documentation" OR "api reference"
      * inurl:"api/v1" OR inurl:"/v1/api"
      * filetype:json OR filetype:yaml "swagger"

    - API Keys and Tokens:
      * "api_key=" OR "apikey=" OR "access_token="
      * "secret=" OR "token=" site:target.com
      * "oauth_token" OR "bearer token"
      * "x-api-key" OR "authorization: bearer"

### 6 Cloud Service Discovery
    - AWS Information:
      * "bucket.s3.amazonaws.com" OR "s3.amazonaws.com"
      * "amazonaws.com" "target.com"
      * "AWS_ACCESS_KEY" OR "AWS_SECRET_KEY"
      * "cloudfront.net" site:target.com

    - Azure Information:
      * "blob.core.windows.net" 
      * "azurewebsites.net" site:target.com
      * "AZURE_STORAGE_KEY" OR "AZURE_SECRET"

    - Google Cloud:
      * "storage.googleapis.com"
      * "appspot.com" site:target.com
      * "googleapis.com" "key="

### 7 Email and Contact Information
    - Email Address Discovery:
      * "@target.com" filetype:txt OR filetype:pdf
      * "contact" OR "email" site:target.com
      * "mailto:" site:target.com
      * "username@target.com"

    - Employee Information:
      * "team" OR "staff" OR "employees" site:target.com
      * "linkedin.com/company/target"
      * "about us" site:target.com

### 8 Subdomain and Infrastructure Discovery
    - Subdomain Enumeration:
      * site:*.target.com
      * -site:www.target.com site:target.com
      * "target.com" -site:www.target.com

    - Related Domains:
      * related:target.com
      * link:target.com
      * "target" "copyright" (footer discovery)

### 9 Technology Stack Identification
    - Framework Detection:
      * "powered by wordpress" site:target.com
      * "drupal" OR "joomla" site:target.com
      * "laravel" OR "django" OR "ruby on rails"
      * "react" OR "angular" OR "vue" filetype:js

    - Server Information:
      * "server: apache" OR "server: nginx" OR "server: iis"
      * "x-powered-by" site:target.com
      * "x-aspnet-version" OR "x-aspnetmvc-version"

### 10 Advanced Search Techniques
    - Date Range Searching:
      * daterange: - Search within specific date ranges
      * after: - Find content after specific date
      * before: - Find content before specific date

    - Numeric Range Searching:
      * numrange: - Search within numeric ranges
      * . (double dot) for range searches

    - Combined Operators:
      * site:target.com (filetype:pdf OR filetype:doc) "confidential"
      * inurl:admin (intitle:"login" OR intitle:"admin")

### 11 Alternative Search Engines
    - Bing Search Techniques:
      * Use similar operators as Google
      * ip: - Find sites hosted on specific IP
      * contains: - Similar to filetype:

    - Shodan.io Reconnaissance:
      * hostname:target.com
      * net: (CIDR range search)
      * port: (specific port search)
      * product: (software/product search)
      * country: (geographic search)

    - Other Specialized Engines:
      * Censys.io - Certificate and host discovery
      * ZoomEye - Network device discovery
      * BinaryEdge - Internet-wide scanning data

### 12 Automated Reconnaissance Tools
    - Google Dorking Automation:
      * GooDork - Automated Google dorking
      * DorkBot - Command-line dorking tool
      * GoogleHacking - Database of dorks

    - Subdomain Discovery Tools:
      * Sublist3r - Subdomain enumeration
      * Amass - In-depth DNS enumeration
      * SubFinder - Subdomain discovery tool

    - Comprehensive Recon Tools:
      * theHarvester - Email, subdomain, and name discovery
      * Recon-ng - Full-featured reconnaissance framework
      * OSINT Framework - Comprehensive OSINT resource

#### Search Engine Monitoring:
    - Google Alerts Setup:
      * Monitor for target domain mentions
      * Track specific keywords related to target
      * Set up alerts for data breaches

    - Continuous Monitoring:
      * Regular search engine reconnaissance
      * Automated scanning with custom scripts
      * Monitor paste sites for leaked data
      * Set up RSS feeds for target mentions

#### Legal and Ethical Considerations:
    - Scope Verification:
      * Ensure target is within authorized scope
      * Verify bug bounty program rules
      * Check penetration testing agreement terms

    - Responsible Disclosure:
      * Document findings appropriately
      * Follow responsible disclosure procedures
      * Avoid accessing or downloading sensitive data

#### Documentation and Reporting:
    - Finding Documentation:
      * Capture screenshots of exposed information
      * Record search queries used
      * Document potential impact of findings
      * Categorize by severity and exposure level

    - Report Generation:
      * Executive summary of findings
      * Detailed technical documentation
      * Risk assessment and recommendations
      * Evidence collection and preservation

#### Advanced Techniques:
    - Search Engine Cache Analysis:
      * Review historical versions of pages
      * Identify removed sensitive content
      * Track changes over time

    - Language-Specific Searches:
      * Search in multiple languages
      * Regional domain variations
      * International site versions

    - Metadata Analysis:
      * Document metadata examination
      * EXIF data from images
      * PDF metadata analysis
