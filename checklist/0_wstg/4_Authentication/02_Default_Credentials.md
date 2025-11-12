# 🔍 DEFAULT CREDENTIALS TESTING CHECKLIST

## 4.2 Comprehensive Default Credentials Testing

### 4.2.1 System and Platform Testing
    - Operating System Testing:
      * Windows default accounts (Administrator, Guest)
      * Linux/Unix root and system accounts
      * macOS default administrative accounts
      * Virtual machine template accounts
      * Cloud platform default accounts

    - Database System Testing:
      * MySQL/MariaDB (root, admin)
      * PostgreSQL (postgres, admin)
      * Oracle (SYS, SYSTEM, DBSNMP)
      * Microsoft SQL Server (sa, admin)
      * MongoDB (admin, root)

    - Network Device Testing:
      * Routers (admin, cisco, root)
      * Switches (admin, cisco)
      * Firewalls (admin, cisco, firewall)
      * Wireless APs (admin, root)
      * Network storage devices

### 4.2.2 Web Application Testing
    - CMS Platform Testing:
      * WordPress (admin, administrator)
      * Joomla (admin, superuser)
      * Drupal (admin, administrator)
      * Magento (admin, administrator)
      * Shopify (admin, storeowner)

    - Web Server Testing:
      * Apache Tomcat (tomcat, admin)
      * IBM WebSphere (admin, wasadmin)
      * Oracle WebLogic (weblogic, admin)
      * Microsoft IIS (IUSR, IWAM)
      * Nginx (admin, root)

    - Application Framework Testing:
      * Spring Boot (admin, user)
      * Django (admin, root)
      * Ruby on Rails (admin, administrator)
      * Laravel (admin, root)
      * Express.js (admin, user)

### 4.2.3 Cloud Service Testing
    - IaaS Platform Testing:
      * AWS (admin, root, ec2-user)
      * Azure (azureuser, admin)
      * Google Cloud (gcpadmin, user)
      * Oracle Cloud (opc, admin)
      * IBM Cloud (admin, user)

    - SaaS Application Testing:
      * Salesforce (admin, administrator)
      * Office 365 (admin, administrator)
      * Google Workspace (admin, superadmin)
      * Slack (admin, owner)
      * Zoom (admin, host)

    - Container Platform Testing:
      * Docker (root, docker)
      * Kubernetes (admin, kubernetes)
      * OpenShift (admin, developer)
      * Rancher (admin, rancher)
      * Portainer (admin, portainer)

### 4.2.4 IoT and Embedded Device Testing
    - Smart Home Devices:
      * Routers and modems (admin, root)
      * IP cameras (admin, root)
      * Smart TVs (admin, root)
      * Home automation hubs
      * IoT sensors and controllers

    - Industrial Control Systems:
      * SCADA systems (admin, engineer)
      * PLCs (admin, technician)
      * HMIs (admin, operator)
      * RTUs (admin, user)
      * Industrial network devices

    - Medical Devices:
      * Medical imaging systems
      * Patient monitoring devices
      * Hospital network equipment
      * Medical database systems
      * Healthcare IoT devices

### 4.2.5 API and Service Testing
    - REST API Testing:
      * Default API keys and tokens
      * Test environment credentials
      * Development API endpoints
      * Webhook default authentication
      * Microservice default accounts

    - Middleware Testing:
      * Message queues (admin, guest)
      * Cache systems (admin, default)
      * ESB platforms (admin, esbuser)
      * API gateways (admin, gateway)
      * Service mesh control planes

    - Monitoring System Testing:
      * Prometheus (admin, prometheus)
      * Grafana (admin, grafana)
      * Nagios (nagiosadmin, admin)
      * Zabbix (Admin, guest)
      * Datadog (admin, datadog)

### 4.2.6 Development and DevOps Testing
    - Development Tool Testing:
      * Git repositories (admin, git)
      * CI/CD systems (admin, jenkins)
      * Container registries (admin, registry)
      * Package managers (admin, npm)
      * Code quality tools

    - DevOps Platform Testing:
      * Jenkins (admin, jenkins)
      * GitLab (root, admin)
      * GitHub Enterprise (admin, administrator)
      * Bitbucket (admin, bitbucket)
      * Jira/Confluence (admin, administrator)

    - Infrastructure as Code Testing:
      * Terraform state files
      * Ansible vault defaults
      * CloudFormation templates
      * Helm chart defaults
      * Dockerfile base images

### 4.2.7 Vendor-Specific Testing
    - Hardware Vendor Testing:
      * Cisco (cisco, admin)
      * HP (admin, root)
      * Dell (root, admin)
      * IBM (admin, ibm)
      * Juniper (root, admin)

    - Software Vendor Testing:
      * Microsoft (Administrator, sa)
      * Oracle (system, sys)
      * SAP (DDIC, SAP*)
      * Adobe (admin, administrator)
      * VMware (root, admin)

    - Security Vendor Testing:
      * Firewall appliances (admin, firewall)
      * VPN concentrators (admin, vpn)
      * SIEM systems (admin, siem)
      * IDS/IPS systems (admin, snort)
      * Antivirus management consoles

### 4.2.8 Default Password Pattern Testing
    - Common Password Patterns:
      * "admin/admin" combinations
      * "password" and variations
      * "1234" and sequential numbers
      * "changeme" and similar prompts
      * Blank or null passwords

    - Vendor-Specific Patterns:
      * Company name as password
      * Product name variations
      * Model number passwords
      * Serial number patterns
      * MAC address-based passwords

    - Industry-Specific Patterns:
      * Healthcare default credentials
      * Financial system defaults
      * Government system defaults
      * Education institution defaults
      * Manufacturing system defaults

### 4.2.9 Configuration File Testing
    - File System Scanning:
      * Configuration files with credentials
      * Environment files (.env, .bashrc)
      * Property files (.properties, .yml, .json)
      * Script files with hardcoded credentials
      * Backup files with configuration data

    - Source Code Analysis:
      * Hardcoded credentials in source
      * Test configuration files
      * Deployment scripts
      * Database connection strings
      * API key storage

    - Log File Analysis:
      * Application logs with credentials
      * Database query logs
      * Network device logs
      * Audit logs with authentication data
      * Error logs with sensitive information

### 4.2.10 Network Service Testing
    - Remote Access Testing:
      * SSH default credentials
      * Telnet default logins
      * RDP default accounts
      * VNC default passwords
      * Web-based management interfaces

    - File Service Testing:
      * FTP default credentials
      * SMB/CIFS default shares
      * NFS default exports
      * SFTP default configurations
      * WebDAV default access

    - Directory Service Testing:
      * LDAP anonymous binding
      * Active Directory default accounts
      * OpenLDAP default configurations
      * RADIUS default shared secrets
      * Kerberos default principals

### 4.2.11 Protocol-Specific Testing
    - Database Protocol Testing:
      * MySQL default on port 3306
      * PostgreSQL default on port 5432
      * Redis default on port 6379
      * MongoDB default on port 27017
      * Oracle default on port 1521

    - Management Protocol Testing:
      * SNMP default community strings
      * IPMI default credentials
      * SMTP default configurations
      * HTTP/HTTPS management interfaces
      * Custom management protocols

    - Industrial Protocol Testing:
      * Modbus default configurations
      * PROFINET default settings
      * OPC UA default security
      * DNP3 default parameters
      * IEC 61850 default configurations

### 4.2.12 Automated Discovery Testing
    - Network Scanning:
      * Port scanning for management interfaces
      * Service version detection
      * Banner grabbing analysis
      * Automated credential testing
      * Vulnerability scanning integration

    - Credential Database Testing:
      * Common default credential databases
      * Vendor-specific password lists
      * Industry-specific credential patterns
      * Custom wordlist generation
      * Password mutation testing

    - Brute Force Protection Testing:
      * Account lockout mechanisms
      * Rate limiting effectiveness
      * CAPTCHA implementation
      * IP blocking capabilities
      * Behavioral analysis detection

#### Testing Methodology:
    Phase 1: Discovery and Enumeration
    1. Identify all systems, services, and applications
    2. Map network services and management interfaces
    3. Gather vendor and version information
    4. Document potential default credential targets

    Phase 2: Credential Testing
    1. Test common default username/password combinations
    2. Use vendor-specific default credentials
    3. Test industry-specific default patterns
    4. Validate blank and null credential attempts

    Phase 3: Configuration Analysis
    1. Scan for configuration files with credentials
    2. Analyze source code and deployment artifacts
    3. Check log files for credential exposure
    4. Review backup and snapshot data

    Phase 4: Impact Assessment
    1. Evaluate access level gained with default credentials
    2. Assess potential damage and data exposure
    3. Validate privilege escalation possibilities
    4. Document business impact findings

#### Automated Testing Tools:
    Network Scanning Tools:
    - Nmap with NSE scripts for default credentials
    - Masscan for rapid service discovery
    - Nessus for vulnerability scanning
    - OpenVAS for comprehensive testing
    - Nikto for web application scanning

    Credential Testing Tools:
    - Hydra for network service brute forcing
    - Medusa for parallelized attacks
    - Ncrack for network authentication
    - Patator for multi-protocol testing
    - Metasploit for exploit-based testing

    Custom Testing Tools:
    - Default credential wordlist generators
    - Vendor-specific testing scripts
    - Configuration file scanners
    - Log analysis automation
    - API credential testers

#### Common Test Commands:
    Network Service Testing:
    # Test SSH default credentials
    hydra -L users.txt -P passwords.txt ssh://target.com
    # Test web application defaults
    hydra -L users.txt -P passwords.txt https://target.com/login

    Service Discovery:
    # Scan for services with default credentials
    nmap -sV --script default-credentials target.com
    # Check for common web interfaces
    nmap -p 80,443,8080,8443 --script http-default-accounts target.com

    Configuration Analysis:
    # Search for configuration files
    find / -name "*.config" -o -name "*.xml" -o -name "*.properties" 2>/dev/null
    # Check for environment files
    find / -name ".env" -o -name ".bashrc" -o -name ".profile" 2>/dev/null

#### Risk Assessment Framework:
    Critical Risk:
    - Default administrative credentials on internet-facing systems
    - Default credentials providing full system control
    - Multiple systems using same default credentials
    - No credential change enforcement mechanisms

    High Risk:
    - Default credentials on internal critical systems
    - Service accounts with default passwords
    - Database systems with default administrative access
    - Network devices with default configurations

    Medium Risk:
    - Default credentials on non-critical systems
    - Read-only access with default credentials
    - Development/test environments with defaults
    - Legacy systems with unchanged defaults

    Low Risk:
    - Default credentials on isolated systems
    - Systems with limited access and functionality
    - Monitoring-only default accounts
    - Systems scheduled for decommissioning

#### Protection and Hardening:
    - Credential Management Best Practices:
      * Change all default credentials before deployment
      * Implement strong password policies
      * Use unique credentials for each system
      * Regular credential rotation and auditing

    - System Hardening:
      * Disable or rename default accounts where possible
      * Implement account lockout policies
      * Use multi-factor authentication
      * Regular security patching and updates

    - Monitoring and Detection:
      * Monitor for default credential usage attempts
      * Implement SIEM alerts for authentication anomalies
      * Regular vulnerability scanning
      * Continuous security assessment

#### Testing Execution Framework:
    Step 1: Asset Discovery and Inventory
    - Identify all systems and services in scope
    - Map network architecture and access points
    - Document vendor and version information
    - Prioritize critical systems for testing

    Step 2: Default Credential Testing
    - Test common default credentials
    - Use vendor-specific credential databases
    - Validate configuration file security
    - Check for hardcoded credentials

    Step 3: Impact Analysis
    - Assess access levels gained
    - Evaluate potential privilege escalation
    - Document data exposure risks
    - Calculate business impact

    Step 4: Remediation Validation
    - Verify credential changes
    - Test security controls effectiveness
    - Validate monitoring and detection
    - Document ongoing maintenance procedures

#### Documentation Template:
    Default Credentials Assessment Report:
    - Executive Summary and Risk Overview
    - Systems and Services Tested
    - Default Credentials Found
    - Access Levels and Privileges Obtained
    - Business Impact Analysis
    - Vulnerability Details and Evidence
    - Risk Assessment and Scoring
    - Remediation Recommendations
    - Credential Management Guidelines
    - Ongoing Monitoring Procedures

This comprehensive Default Credentials testing checklist ensures thorough evaluation of systems and applications for unchanged default authentication, helping organizations prevent unauthorized access, system compromise, and data breaches through proper credential management and security controls.