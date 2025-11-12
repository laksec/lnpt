# 🔍 FILE EXTENSIONS HANDLING TESTING CHECKLIST

## 8.13 Comprehensive File Extensions Handling Testing for Sensitive Information

### 8.13.1 Common Sensitive File Extension Testing
    - Configuration Files:
      * .env, .config, .conf, .ini, .properties
      * .xml, .json, .yml, .yaml configuration files
      * .settings, .preferences, .options
      * web.config, app.config, application.properties

    - Backup and Temporary Files:
      * .bak, .backup, .old, .tmp, .temp
      * .save, .sav, .previous, .orig
      * ~ (tilde backup files), .# (emacs backup)
      * .swp, .swo (vim swap files)

    - Version Control Files:
      * .git/ directory and contents
      * .svn/ directory and entries files
      * .hg/ directory (Mercurial)
      * .gitignore, .svnignore, .hgignore

### 8.13.2 Development and Source Code Files
    - Source Code Exposure:
      * .java, .py, .php, .js, .cpp, .c, .cs
      * .rb, .go, .rs, .swift, .kt
      * .html, .css, .scss, .less
      * .vue, .jsx, .tsx, .ts

    - Build and Dependency Files:
      * package.json, package-lock.json
      * requirements.txt, Pipfile, poetry.lock
      * pom.xml, build.gradle, build.xml
      * Dockerfile, docker-compose.yml

    - IDE and Editor Files:
      * .idea/, .vscode/, .project, .classpath
      * .settings/, .metadata/, .factorypath
      * Thumbs.db, Desktop.ini, .DS_Store

### 8.13.3 Database and Data Files
    - Database Files:
      * .db, .sqlite, .sqlite3, .mdb, .accdb
      * .sql, .dump, .export, .backup
      * .frm, .myd, .myi (MySQL)
      * .dbf, .mdf, .ldf (SQL Server)

    - Data Export Files:
      * .csv, .tsv, .xls, .xlsx
      * .json, .xml, .yaml, .yml data dumps
      * .pdf, .doc, .docx reports
      * .log, .txt, .out output files

### 8.13.4 Security and Credential Files
    - Certificate and Key Files:
      * .pem, .key, .crt, .cer, .der
      * .pfx, .p12, .p7b, .p7c
      * .jks, .keystore, .truststore
      * .csr, .crl, .ocsp

    - Credential and Secret Files:
      * .pwd, .pass, .password, .cred
      * .secret, .token, .key, .auth
      * .gnupg/, .ssh/ directories
      * .aws/credentials, .azure/config

### 8.13.5 Application-Specific File Extensions
    - CMS Configuration Files:
      * wp-config.php (WordPress)
      * settings.php (Drupal)
      * configuration.php (Joomla)
      * local.xml (Magento)

    - Framework-Specific Files:
      * .env (Laravel, Node.js)
      * application.yml (Spring Boot)
      * appsettings.json (.NET Core)
      * config.ru (Ruby on Rails)

### 8.13.6 Archive and Compressed Files
    - Common Archive Formats:
      * .zip, .tar, .gz, .tgz, .bz2
      * .rar, .7z, .iso, .img
      * .jar, .war, .ear (Java archives)
      * .whl, .egg (Python packages)

### 8.13.7 Log and Audit Files
    - Application Logs:
      * .log, .logs, .out, .err
      * .audit, .trace, .debug
      * access.log, error.log
      * application.log, system.log

### 8.13.8 File Extension Handling Security Testing
    - Direct File Access Testing:
      * Attempt to access files with double extensions: file.php.txt
      * Test case variations: .PHP, .Php, .pHp
      * URL encoded extensions: %2ephp, %2ephp
      * Null byte injection: file.php%00.txt

    - MIME Type Confusion:
      * Files with incorrect MIME types
      * Content-Type vs file extension mismatch
      * File content vs extension validation
      * Browser MIME sniffing behavior

    - File Upload Bypass Testing:
      * Extension blacklist bypass attempts
      * Whitelist validation flaws
      * Magic byte verification testing
      * Content-Type header manipulation

### 8.13.9 Information Disclosure Testing
    - Directory Listing:
      * Check for enabled directory browsing
      * Test for partial directory listings
      * Verify .htaccess restrictions
      * Check for exposed file metadata

    - Source Code Disclosure:
      * Test for source code backup files
      * Check for exposed configuration snippets
      * Verify commented code exposure
      * Test for exposed API keys in files

### 8.13.10 Backup File Discovery
    - Automated Backup Patterns:
      * Date-based backups: backup-2024-01-01.sql
      * Version-based backups: v1.2.3-backup.zip
      * Incremental backups: backup.1, backup.2
      * Automated system backups

    - Manual Backup Files:
      * Developer backup files
      * Temporary migration files
      * Database export files
      * Configuration backup files

### 8.13.11 Hidden File Exposure
    - Dot Files Testing:
      * .htaccess, .htpasswd
      * .gitconfig, .bashrc, .profile
      * .npmrc, .yarnrc, .pypirc
      * .dockerignore, .gitattributes

    - System Hidden Files:
      * Thumbs.db (Windows)
      * .DS_Store (macOS)
      * desktop.ini (Windows)
      * .localized (macOS)

### 8.13.12 Cloud Storage Files
    - Cloud Configuration:
      * .s3cfg, .boto (AWS)
      * .azure, .gcloud
      * cloudformation templates
      * terraform.tfstate files

### 8.13.13 Development Environment Files
    - Local Development Files:
      * Local configuration overrides
      * Development database files
      * Test data and fixtures
      * Debug configuration files

### 8.13.14 Database and Cache Files
    - Database Related:
      * SQL dump files
      * Database transaction logs
      * Cache dump files
      * Session storage files

### 8.13.15 Custom Application Files
    - Application-Specific Extensions:
      * Custom configuration formats
      * Proprietary data files
      * Application backup formats
      * Export/import file formats

#### Testing Methodology:
    Phase 1: Automated Discovery
    1. Use automated scanners with comprehensive file extension wordlists
    2. Perform directory brute-forcing with extension fuzzing
    3. Search for common backup and temporary file patterns
    4. Check version control system exposures

    Phase 2: Manual Testing
    1. Test application-specific file patterns
    2. Verify file extension handling security
    3. Check for MIME type confusion vulnerabilities
    4. Test file upload security controls

    Phase 3: Deep Analysis
    1. Analyze found files for sensitive information
    2. Test file permission and access controls
    3. Verify backup file security
    4. Check for information leakage in error messages

#### Automated Testing Tools:
    Directory Brute-Forcing:
    - Gobuster: `gobuster dir -u http://target.com -w extensions_wordlist.txt`
    - FFuF: `ffuf -u http://target.com/FUZZ -w file_extensions.txt`
    - Dirsearch: `dirsearch -u http://target.com -e php,html,bak,old,tmp`
    - Burp Suite Intruder with file extension payloads

    Specialized Scanners:
    - GitTools for .git exposure testing
    - DVCS-Ripper for version control systems
    - TruffleHog for secret scanning in files
    - GitRob for GitHub repository scanning

    Custom Scripts:
    - Python scripts with requests library
    - Bash scripts with curl and wget
    - Extension fuzzing scripts
    - Pattern matching scripts

#### Common File Extension Wordlists:
    Configuration Files:
    env, config, conf, ini, properties, xml, json, yml, yaml, settings

    Backup Files:
    bak, backup, old, tmp, temp, save, sav, previous, orig, ~

    Source Code:
    php, java, py, js, html, css, cpp, c, cs, rb, go, rs, swift

    Database Files:
    db, sqlite, sql, dump, mdb, accdb, frm, myd, myi

    Security Files:
    pem, key, crt, cer, pfx, p12, jks, keystore, pwd, cred

#### Risk Assessment Framework:
    Critical Risk:
    - Exposed credential files (.env, .pem, .key)
    - Database backup files with sensitive data
    - Configuration files with secrets
    - Source code with hardcoded credentials

    High Risk:
    - Application configuration files
    - Log files with sensitive information
    - Backup files with partial data
    - Version control system exposures

    Medium Risk:
    - Temporary files with limited information
    - Development environment files
    - Build configuration files
    - Documentation with internal information

    Low Risk:
    - Static assets without sensitive data
    - Public documentation files
    - Test files without real data
    - Cache files without sensitive content

#### Protection and Prevention:
    - Web Server Configuration:
      * Disable directory browsing
      * Restrict access to sensitive file extensions
      * Implement proper MIME type handling
      * Use security headers (X-Content-Type-Options)

    - Application Security:
      * Implement proper file upload validation
      * Use secure file storage practices
      * Regular security scanning for exposed files
      * Automated backup file cleanup

    - Development Practices:
      * Include sensitive files in .gitignore
      * Use environment variables for configuration
      * Implement secure backup procedures
      * Regular security awareness training

#### Documentation Template:
    File Extensions Handling Test Report:
    - Target Application: [Application Name]
    - Testing Period: [Date Range]
    - Files Discovered: [Number and types]
    - Sensitive Information Exposed: [Details]
    - Risk Assessment: [Critical/High/Medium/Low]
    - Recommendations: [Remediation steps]
    - Evidence: [Screenshots and file contents]

This comprehensive file extensions handling testing checklist provides a systematic approach to identifying sensitive information exposure through various file types, helping organizations secure their applications and prevent data leakage through improper file handling.