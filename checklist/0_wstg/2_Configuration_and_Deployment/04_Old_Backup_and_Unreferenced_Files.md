# 🔍 OLD BACKUP & UNREFERENCED FILES SENSITIVE INFORMATION TESTING CHECKLIST

## 8.14 Comprehensive Backup and Unreferenced Files Security Testing

### 8.14.1 Backup File Discovery and Analysis
    - Automated Backup File Patterns:
      * Date-based backups: backup_2024-01-01, backup_010124, backup_240101
      * Timestamp backups: backup_1701234567, backup_20240101120000
      * Sequential backups: backup_001, backup_v1, backup_final, backup_final_final
      * Incremental backups: backup_inc_1, backup_diff_20240101

    - Manual Backup Files:
      * Developer backups: mybackup, temp_backup, test_backup
      * Emergency backups: emergency_backup, quick_backup, urgent_backup
      * Migration backups: pre_migration, post_migration, migration_backup
      * Version-specific backups: v2_backup, old_version_backup

    - System-Generated Backups:
      * Auto-save files: ~file.docx, .~lock.file#
      * Temporary backups: file.tmp, file.bak, file.old
      * Crash recovery files: file.recovery, file.sav

### 8.14.2 Unreferenced File Discovery Techniques
    - Web Root Unreferenced Files:
      * Files not linked from any page
      * Orphaned functionality endpoints
      * Legacy API versions (v1, v2 when current is v3)
      * Deprecated feature files

    - Content Management System Orphans:
      * Unused themes and templates
      * Deactivated plugin/extension files
      * Old media library files
      * Unpublished content files

    - Development and Staging Files:
      * Leftover development files in production
      * Testing data and mock files
      * Debug and profiling output files
      * Build artifacts and distribution files

### 8.14.3 Archive and Compression File Analysis
    - Common Archive Formats:
      * ZIP files: .zip, .zipx, .jar, .war, .ear
      * TAR files: .tar, .tar.gz, .tgz, .tar.bz2, .tbz2
      * RAR files: .rar, .r00, .r01
      * 7-Zip files: .7z, .7z.001

    - Application-Specific Archives:
      * Database dumps: .sql.gz, .dump.tar, .backup.zip
      * Log archives: logs.zip, error_logs.tar.gz
      * Configuration backups: config_backup.tar
      * Full site backups: site_backup_2024.zip

### 8.14.4 Database Backup Security Analysis
    - Database Dump Files:
      * MySQL dumps: .sql, .mysqldump
      * PostgreSQL dumps: .pgdump, .backup
      * MongoDB dumps: .bson, .mongodump
      * SQL Server backups: .bak, .mdf, .ldf

    - Database Export Files:
      * CSV exports: data_export.csv, users.csv
      * JSON exports: db_export.json, data.json
      * XML exports: database.xml, export.xml
      * Excel exports: report.xlsx, data_export.xls

### 8.14.5 Version Control System Leftovers
    - Git Repository Artifacts:
      * .git directory exposure
      * Git backup files: .git.bak, git_backup
      * Git configuration backups
      * Patch files and diff outputs

    - SVN Repository Remnants:
      * .svn directory exposure
      * SVN backup files
      * Working copy leftovers
      * Repository dump files

    - Other VCS Files:
      * Mercurial .hg directories
      * CVS CVS directories
      * Perforce depot files

### 8.14.6 Configuration Backup Analysis
    - Application Configuration Backups:
      * web.config.bak, web.config.old
      * app.config.backup, settings.php.bak
      * .env.backup, config.yml.old
      * database.yml.backup

    - Server Configuration Backups:
      * httpd.conf.bak, nginx.conf.old
      * php.ini.backup, my.cnf.old
      * sshd_config.backup

    - Environment Configuration Backups:
      * .env.production.backup
      * environment.config.old
      * deployment.config.bak

### 8.14.7 Log File Archive Analysis
    - Application Log Archives:
      * access.log.1, access.log.2.gz
      * error.log.old, debug.log.backup
      * application.log.2024-01.tar
      * security.log.archive

    - System Log Backups:
      * syslog.1, syslog.2.gz
      * auth.log.old, secure.log.backup
      * kernel.log.archive

    - Audit Log Archives:
      * audit.log.2024-01.gz
      * compliance.log.backup
      * security_audit.log.old

### 8.14.8 Media and Content Backups
    - Image and Media Backups:
      * Original image backups (before compression)
      * Video file backups
      * Audio file archives
      * Document backups

    - Content Management Backups:
      * Article and post backups
      * Page revision backups
      * Media library backups
      * User content archives

### 8.14.9 User Data and Export Backups
    - User Data Exports:
      * User profile data exports
      * Personal data backup files
      * GDPR/data subject access request exports
      * User account archives

    - Business Data Backups:
      * Customer data exports
      * Transaction history backups
      * Financial data archives
      * Inventory and product backups

### 8.14.10 Email and Communication Backups
    - Email Archive Files:
      * PST files (Outlook)
      * EML files (individual emails)
      * MBOX files (Unix mail)
      * Email server backups

    - Communication Backups:
      * Chat log exports
      * Message history backups
      * Support ticket archives
      * Notification logs

### 8.14.11 Development and Build Backups
    - Source Code Backups:
      * Old version source code
      * Feature branch backups
      * Hotfix backups
      * Legacy code archives

    - Build Artifact Backups:
      * Old build outputs
      * Deployment package backups
      * Compilation output archives
      * Dependency snapshots

### 8.14.12 Security-Specific Backup Analysis
    - Security Configuration Backups:
      * Firewall rule backups
      * Security policy exports
      * Access control list backups
      * Certificate and key backups

    - Security Log Archives:
      * Intrusion detection logs
      * Firewall log backups
      * Security incident archives
      * Compliance audit backups

### 8.14.13 Cloud Storage and Sync Leftovers
    - Cloud Sync Artifacts:
      * Dropbox .dropbox.cache files
      * Google Drive sync conflicts
      * OneDrive temporary files
      * iCloud sync leftovers

    - Cloud Backup Remnants:
      * AWS S3 backup artifacts
      * Azure Blob storage backups
      * Google Cloud Storage archives
      * Cloud sync backup files

### 8.14.14 Mobile and Device Backups
    - Mobile App Backups:
      * Mobile database backups
      * App configuration backups
      * User session backups
      * Cache and temporary files

    - Device Sync Files:
      * Mobile device backups
      * Tablet application data
      * Wearable device sync files

### 8.14.15 Third-Party Integration Backups
    - API and Integration Backups:
      * Third-party API data exports
      * Integration configuration backups
      * Webhook log archives
      * External service data backups

    - Payment and E-commerce Backups:
      * Payment gateway exports
      * Order history backups
      * Customer data exports
      * Subscription management backups

#### Discovery Methodology:
    Phase 1: Automated Scanning
    1. Use comprehensive backup file wordlists
    2. Perform pattern-based file discovery
    3. Scan for version control remnants
    4. Search for archive and compressed files

    Phase 2: Manual Investigation
    1. Check common backup locations
    2. Review file modification timestamps
    3. Analyze file naming patterns
    4. Investigate directory structures

    Phase 3: Content Analysis
    1. Extract and examine archive contents
    2. Search for sensitive information patterns
    3. Analyze database dump files
    4. Review configuration file backups

#### Automated Discovery Tools:
    Backup File Scanners:
    - Dirsearch with backup file wordlists
    - Gobuster with custom backup patterns
    - FFuF with extension fuzzing
    - Burp Suite with backup file payloads

    Content Analysis Tools:
    - TruffleHog for secret scanning
    - GitRob for repository analysis
    - DVCS-Ripper for version control
    - Binwalk for archive analysis

    Custom Scripts:
    - Python scripts for pattern matching
    - Bash scripts for file analysis
    - Regex patterns for sensitive data
    - Archive extraction and analysis scripts

#### Common Backup File Patterns:
    Date-Based Patterns:
    backup_YYYY-MM-DD, backup_DDMMYYYY, backup_YYMMDD
    backup_YYYYMMDD, backup_epoch_timestamp

    Sequential Patterns:
    backup_001, backup_v1, backup_final, backup_new
    backup_old, backup_previous, backup_archive

    System Patterns:
    ~filename, filename.old, filename.bak, filename.tmp
    filename.autosave, filename.recovery

#### Sensitive Information Patterns:
    Credentials and Secrets:
    API keys, database passwords, encryption keys
    OAuth tokens, SSH keys, certificate private keys

    Personal Data:
    Email addresses, phone numbers, physical addresses
    Government IDs, financial information, health data

    Business Information:
    Customer data, financial records, trade secrets
    Internal communications, strategic plans

#### Risk Assessment Framework:
    Critical Risk:
    - Database dumps with user credentials
    - Configuration files with API keys and secrets
    - Financial data exports
    - Encryption key backups

    High Risk:
    - User personal data exports
    - Internal communication archives
    - Business intelligence backups
    - Security log files with sensitive data

    Medium Risk:
    - Application logs with partial data
    - Development backups with test data
    - Configuration backups without secrets
    - Old version source code

    Low Risk:
    - Static asset backups
    - Public content archives
    - Build artifacts without sensitive data
    - Cache and temporary files

#### Protection and Remediation:
    - Backup Management Policies:
      * Implement automated backup cleanup
      * Use secure backup storage locations
      * Encrypt sensitive backup files
      * Implement access controls for backups

    - Development Practices:
      * Include backup files in .gitignore
      * Implement secure file deletion procedures
      * Use environment variables for sensitive data
      * Regular security scanning for exposed files

    - Monitoring and Detection:
      * Implement file integrity monitoring
      * Set up alerts for backup file access
      * Regular security audits of file systems
      * Automated scanning for sensitive data

#### Testing Execution Framework:
    Step 1: Discovery
    - Identify backup file patterns
    - Scan for unreferenced files
    - Locate archive and compressed files
    - Find version control remnants

    Step 2: Analysis
    - Extract and examine backup contents
    - Search for sensitive information
    - Analyze file permissions and access
    - Review file metadata

    Step 3: Validation
    - Verify information exposure risk
    - Test access control effectiveness
    - Validate cleanup procedures
    - Confirm remediation effectiveness

#### Documentation Template:
    Backup File Security Assessment Report:
    - Assessment Scope and Methodology
    - Backup Files Discovered
    - Sensitive Information Identified
    - Risk Assessment and Scoring
    - Remediation Recommendations
    - Evidence and Findings
    - Compliance Impact Analysis
    - Follow-up Actions Required

This comprehensive checklist provides a systematic approach to identifying and assessing security risks associated with old backup and unreferenced files, helping organizations prevent sensitive information leakage through forgotten or improperly secured backup files.