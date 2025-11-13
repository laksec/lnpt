# 🔍 FILE PERMISSIONS TESTING CHECKLIST

## 2.4 Comprehensive File Permissions Security Testing

### 2.4.1 Web Root Directory Permissions Testing
    - Directory Structure Permission Analysis:
      * Web root directory (/, /var/www, /htdocs, /public_html)
      * Subdirectory permission inheritance
      * Parent directory traversal permissions
      * Symbolic link and junction point security

    - Critical Directory Permission Testing:
      * Configuration directories (/config, /settings, /conf)
      * Upload directories (/uploads, /files, /media)
      * Temporary directories (/tmp, /temp, /cache)
      * Log directories (/logs, /var/log)

    - Permission Model Analysis:
      * User ownership (www-data, apache, nginx, iusr)
      * Group ownership and access rights
      * Other/world permissions
      * Special permissions (SUID, SGID, sticky bit)

### 2.4.2 Configuration File Permissions Testing
    - Web Server Configuration Files:
      * Apache: httpd.conf, apache2.conf, .htaccess
      * Nginx: nginx.conf, sites-available/, sites-enabled/
      * IIS: web.config, applicationHost.config
      * PHP: php.ini, .user.ini

    - Application Configuration Files:
      * Environment files: .env, .env.production, .env.local
      * Framework config: config.php, settings.py, app.config
      * Database configuration files
      * API key and secret storage files

    - Permission Validation:
      * World-readable configuration files
      * Write permissions on configuration directories
      * Ownership by non-privileged users
      * Backup file permissions (.bak, .old, .orig)

### 2.4.3 Source Code File Permissions Testing
    - Application Source Code:
      * PHP files (.php, .phtml, .php3, .php4, .php5, .php7)
      * Python files (.py, .pyc, .pyo)
      * Java files (.jsp, .java, .class)
      * .NET files (.aspx, .ascx, .asmx)
      * Node.js files (.js, .ts)

    - Template and View Files:
      * HTML templates with server-side code
      * Template engine files (.twig, .blade.php, .erb)
      * View components and partials
      * Static template files

    - Library and Dependency Files:
      * Vendor directories (vendor/, node_modules/)
      * Composer, npm, pip package files
      * Custom library directories
      * Plugin and extension files

### 2.4.4 Upload Directory Security Testing
    - File Upload Area Permissions:
      * Write permissions for web server user
      * Read permissions for web server user
      * Execute permissions (should be disabled)
      * Directory listing permissions

    - Upload File Permission Validation:
      * Uploaded file ownership and permissions
      * File type validation effectiveness
      * Quarantine directory permissions
      * Temporary upload file handling

    - Secure Upload Configuration:
      * Outside web root upload directories
      * Proper file extension handling
      * MIME type validation
      * Virus scanning integration

### 2.4.5 Database and Data File Permissions
    - Database File Security:
      * Database file locations and permissions
      * Database connection strings security
      * Backup file permissions and locations
      * Transaction log file security

    - Session File Permissions:
      * Session storage directory permissions
      * Session file ownership and access
      * Session data isolation
      * Temporary session files

### 2.4.6 Log File Permissions Testing
    - Application Log Security:
      * Log file directory permissions
      * Log file ownership and rotation
      * Log file read/write permissions
      * Log file backup security

    - System Log Integration:
      * syslog integration permissions
      * Log forwarding security
      * Log aggregation permissions
      * Audit log protection

### 2.4.7 Backup File Permissions Testing
    - Automated Backup Security:
      * Backup script permissions
      * Backup file storage permissions
      * Backup encryption verification
      * Backup retention policy enforcement

    - Manual Backup Files:
      * Developer backup file permissions
      * Temporary backup file security
      * Migration backup files
      * Version control backup files

### 2.4.8 Special Permission Testing
    - SUID/SGID Binary Analysis:
      * SUID root binaries in web directories
      * SGID binaries and directory permissions
      * Custom executable permissions
      * Script execution permissions

    - Sticky Bit Directories:
      * /tmp directory sticky bit verification
      * Upload directory sticky bit usage
      * Temporary file directory security
      * Shared directory permissions

### 2.4.9 Symbolic Link and Hard Link Testing
    - Symbolic Link Security:
      * Symbolic link following permissions
      * Directory traversal via symlinks
      * External file system access
      * Privilege escalation via symlinks

    - Hard Link Vulnerabilities:
      * Hard link creation permissions
      * File system race conditions
      * Permission bypass via hard links
      * Backup file manipulation

### 2.4.10 File Inclusion Vulnerability Testing
    - Local File Inclusion (LFI):
      * Directory traversal attempts
      * Null byte injection testing
      * Path truncation attacks
      * Filter bypass techniques

    - Remote File Inclusion (RFI):
      * URL-based file inclusion
      * Protocol wrapper testing
      * Input validation bypass
      * Code execution via inclusion

### 2.4.11 Operating System Specific Testing
    - Linux/Unix File Permissions:
      * Octal permission analysis (755, 644, 777)
      * umask configuration and inheritance
      * SELinux/AppArmor context verification
      * Extended attributes and ACLs

    - Windows File Permissions:
      * NTFS permissions analysis
      * Share permissions vs NTFS permissions
      * Inheritance and propagation
      * Service account permissions

    - Cloud Storage Permissions:
      * S3 bucket policies and ACLs
      * Azure Blob storage permissions
      * Google Cloud Storage IAM
      * Cross-account access permissions

### 2.4.12 Framework-Specific File Permissions
    - CMS File Permissions:
      * WordPress: wp-content/uploads, wp-config.php
      * Drupal: sites/default/files, settings.php
      * Joomla: images/, configuration.php
      * Magento: var/, media/

    - Framework Directory Structures:
      * Laravel: storage/, bootstrap/cache/
      * Django: static/, media/, __pycache__/
      * Ruby on Rails: tmp/, log/, storage/
      * Spring Boot: /tmp, logs/

### 2.4.13 Container and Virtualization Permissions
    - Docker Container Permissions:
      * Volume mount permissions
      * Container user privileges
      * Host file system access
      * Secret file permissions

    - Kubernetes File Security:
      * ConfigMap and Secret permissions
      * Persistent volume claims
      * Pod security contexts
      * Service account tokens

### 2.4.14 API and Microservice File Permissions
    - API Configuration Files:
      * API key storage permissions
      * Certificate and key files
      * Configuration endpoint security
      * Service discovery files

    - Microservice File Security:
      * Inter-service communication files
      * Shared configuration permissions
      * Service mesh certificate files
      * Distributed tracing files

#### Testing Methodology:
    Phase 1: Discovery and Enumeration
    1. Map file system structure
    2. Identify sensitive files and directories
    3. Document current permission schemes
    4. Identify file ownership patterns

    Phase 2: Permission Analysis
    1. Analyze file and directory permissions
    2. Check for insecure permission patterns
    3. Verify ownership and group assignments
    4. Test special permission flags

    Phase 3: Security Validation
    1. Test file inclusion vulnerabilities
    2. Verify access control effectiveness
    3. Check for privilege escalation paths
    4. Validate backup file security

    Phase 4: Remediation Verification
    1. Verify permission fixes
    2. Test updated configurations
    3. Validate security controls
    4. Confirm risk reduction

#### Automated Testing Tools:
    Command Line Tools:
    - find: `find /var/www -type f -perm 777`
    - ls: `ls -la /path/to/directory`
    - stat: `stat /path/to/file`
    - getfacl: `getfacl /path/to/file` (for ACLs)

    Specialized Scanners:
    - Lynis: System and security auditing
    - OpenSCAP: Compliance checking
    - Tripwire: File integrity monitoring
    - AIDE: Advanced intrusion detection

    Custom Scripts:
    - Python with os and stat modules
    - Bash scripts with find and grep
    - PowerShell for Windows systems
    - Ansible for configuration auditing

#### Common Permission Test Commands:
    Linux/Unix Permissions:
    find /var/www -type f -perm -o=w -ls
    find /var/www -name "*.php" -perm 644
    ls -la /var/www/html/
    stat -c "%a %n" /path/to/file

    Windows Permissions:
    icacls C:\inetpub\wwwroot\
    Get-Acl C:\inetpub\wwwroot\web.config | Format-List
    dir /q C:\inetpub\wwwroot\

    Dangerous Permission Patterns:
    find / -perm -4000 2>/dev/null  # SUID files
    find / -perm -2000 2>/dev/null  # SGID files
    find /var/www -perm 777 -ls     # World writable
    find /var/www -name "*.env" -ls # Environment files

#### Risk Assessment Framework:
    Critical Risk:
    - World-writable configuration files with secrets
    - SUID binaries in web directories
    - Database files accessible to web server
    - Backup files with plaintext credentials

    High Risk:
    - World-readable .env files
    - Write permissions on system directories
    - Insecure upload directory permissions
    - Log files containing sensitive data

    Medium Risk:
    - Excessive read permissions on source code
    - Insecure temporary file handling
    - Directory listing enabled
    - Outdated file permissions

    Low Risk:
    - Minor permission misconfigurations
    - Development file leftovers
    - Non-sensitive file permissions
    - Temporary file permissions

#### Protection and Hardening:
    - Principle of Least Privilege:
      * Web server should run as non-privileged user
      * Files should have minimum required permissions
      * Directories should restrict listing where possible
      * Regular permission audits

    - Secure Default Configurations:
      * Default file permissions: 644 for files, 755 for directories
      * Secure umask settings (0022, 0027)
      * Regular security scanning
      * Automated permission enforcement

    - Monitoring and Detection:
      * File integrity monitoring
      * Permission change detection
      * Suspicious file access monitoring
      * Regular security audits

#### Testing Execution Framework:
    Step 1: Environment Discovery
    - Identify web server user and group
    - Map application directory structure
    - Document current permission schemes
    - Identify sensitive data locations

    Step 2: Permission Analysis
    - Check file and directory permissions
    - Verify ownership and group assignments
    - Test special permission flags
    - Analyze permission inheritance

    Step 3: Security Testing
    - Test file inclusion vulnerabilities
    - Verify access control bypass attempts
    - Check for privilege escalation
    - Validate backup file security

    Step 4: Compliance Verification
    - Check against security benchmarks (CIS, STIG)
    - Verify regulatory compliance (PCI DSS, HIPAA)
    - Validate organizational policies
    - Document findings and recommendations

#### Documentation Template:
    File Permissions Security Assessment:
    - Assessment Scope and Methodology
    - File System Structure Analysis
    - Permission Configuration Findings
    - Security Vulnerabilities Identified
    - Risk Assessment and Scoring
    - Remediation Recommendations
    - Compliance Status
    - Ongoing Monitoring Recommendations

This comprehensive file permissions testing checklist ensures thorough evaluation of file system security configurations, helping organizations prevent unauthorized access, data leakage, and system compromise through proper file permission management.