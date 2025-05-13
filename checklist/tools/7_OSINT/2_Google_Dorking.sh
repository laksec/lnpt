#!/bin/bash
# =====================================================================
# ULTIMATE GOOGLE DORKING MASTER FILE
# =====================================================================
# [Version 3.0] | [Updated: 2024] | [Author: Your Name]
# =====================================================================

# ==============================================
# TABLE OF CONTENTS
# ==============================================
# 1. Credentials & Secrets
# 2. Database Exposures
# 3. Admin Interfaces
# 4. Sensitive Documents
# 5. Cloud & Infrastructure Leaks
# 6. Network Devices
# 7. Source Code & Configs
# 8. Industrial Systems
# 9. Financial Data
# 10. Healthcare Leaks
# 11. Government & Military
# 12. Educational Institutions
# 13. Automation & Scripts
# 14. Defensive Dorking
# 15. Legal & Compliance
# ==============================================

# ==============================================
# 1. CREDENTIALS & SECRETS
# ==============================================
intext:"password" filetype:log after:2023                         # Log files with passwords
"api_key" ext:env OR ext:yml -git                                  # API keys in config files
intitle:"index of" "credentials.json"                              # Exposed credential files
site:github.com "BEGIN RSA PRIVATE KEY"                            # SSH private keys
"DB_USERNAME=" ext:env OR ext:ini                                  # Database credentials
inurl:/config.php "mysql_connect"                                  # PHP config files
filetype:sql "INSERT INTO `users`"                                 # SQL user dumps
"secret_key_base" ext:rb OR ext:env                                # Rails secrets

# ==============================================
# 2. DATABASE EXPOSURES
# ==============================================
ext:sql "DROP TABLE" -git                                          # SQL database dumps
intitle:"index of" "backup" site:target.com                        # Database backups
filetype:mdb OR filetype:accdb "user"                              # MS Access databases
inurl:/phpmyadmin/index.php "server="                              # phpMyAdmin interfaces
"mongodb://" ext:txt OR ext:env                                    # MongoDB connections
"redis://" ext:env OR ext:conf                                     # Redis connections
"jdbc:" ext:properties OR ext:yml                                  # JDBC connection strings

# ==============================================
# 3. ADMIN INTERFACES
# ==============================================
inurl:/admin/login.php "username"                                  # CMS admin logins
intitle:"tomcat manager" "user roles"                              # Tomcat manager
inurl:":8080/manager/html"                                         # Java manager apps
site:target.com intitle:"dashboard" -inurl:help                    # Custom dashboards
inurl:/wp-admin "WordPress"                                        # WordPress admin
inurl:/administrator "Joomla"                                      # Joomla admin
inurl:/admin/config "Drupal"                                       # Drupal admin

# ==============================================
# 4. SENSITIVE DOCUMENTS
# ==============================================
filetype:pdf "confidential" site:target.com                        # Confidential PDFs
ext:xls "salary" OR "employee"                                     # HR spreadsheets
filetype:docx "proprietary" before:2023                            # Proprietary docs
ext:csv "transaction" OR "payment"                                 # Financial records
filetype:pptx "roadmap" OR "strategy"                              # Strategy decks
filetype:txt "credentials" OR "passwords"                          # Password lists
filetype:rtf "internal memo"                                       # Internal memos

# ==============================================
# 5. CLOUD & INFRASTRUCTURE LEAKS
# ==============================================
site:s3.amazonaws.com "target-"                                    # AWS S3 buckets
"storage.googleapis.com" "secret_"                                 # GCP storage
inurl:.blob.core.windows.net "AccountKey="                         # Azure blobs
filetype:tfstate "access_key"                                      # Terraform state
"AKIA[0-9A-Z]{16}" ext:txt OR ext:env                              # AWS keys
"herokuapp.com" "DATABASE_URL"                                     # Heroku configs
"docker-compose.yml" "MYSQL_ROOT_PASSWORD"                         # Docker secrets

# ==============================================
# 6. NETWORK DEVICES
# ==============================================
intitle:"router login" "admin"                                     # Router logins
inurl:"/cgi-bin/luci" "OpenWrt"                                    # OpenWRT interfaces
intitle:"webcam" OR "camera login"                                 # Camera logins
"HP iLO Login" OR "Dell iDRAC"                                     # Server management
inurl:/cgi-bin/login.cgi "QNAP"                                    # NAS devices
intitle:"firewall" "login" "Cisco"                                 # Firewall interfaces
inurl:":10000" "Webmin"                                            # Webmin interfaces

# ==============================================
# 7. SOURCE CODE & CONFIGS
# ==============================================
inurl:/.git/config "[remote]"                                      # Git configs
filetype:yaml "apiVersion:" "kind: Secret"                         # Kubernetes secrets
inurl:jenkins/ "Manage Jenkins"                                    # Jenkins interfaces
filetype:sh "chmod +x" "curl http"                                 # Suspicious scripts
".npmrc" "_authToken="                                             # NPM tokens
".env" "DB_PASSWORD"                                               # Environment files
"pom.xml" "password"                                               # Maven configs

# ==============================================
# 8. INDUSTRIAL SYSTEMS
# ==============================================
intitle:"SCADA Login" OR intitle:"WinCC login"                     # SCADA systems
inurl:"/awp/Logon.html" intitle:"Allen-Bradley"                   # PLC interfaces
"HMI" "login" filetype:aspx                                        # HMIs
"MODBUS" "TCP" inurl:/                                             # MODBUS interfaces
"SIEMENS" "S7" inurl:/Portal/                                      # Siemens portals
"Wonderware" intitle:"Login"                                       # Wonderware systems

# ==============================================
# 9. FINANCIAL DATA
# ==============================================
filetype:xls "credit card"                                         # Credit card data
"invoice" ext:csv "total"                                          # Invoice records
"bank statement" site:target.com                                   # Bank statements
"transaction history" filetype:pdf                                 # Transaction PDFs
"swift code" OR "iban" ext:txt                                     # Banking details
"tax return" "2023" filetype:pdf                                   # Tax documents

# ==============================================
# 10. HEALTHCARE LEAKS
# ==============================================
"patient records" ext:csv                                          # Patient data
"PHI" OR "ePHI" filetype:xls                                       # Protected health info
"medical report" site:target.com                                   # Medical reports
"HIPAA" "compliance" filetype:pdf                                  # Compliance docs
"prescription" ext:pdf "doctor"                                    # Prescriptions
"lab results" filetype:csv                                         # Lab test results

# ==============================================
# 11. GOVERNMENT & MILITARY
# ==============================================
site:.gov "confidential" filetype:pdf                              # Gov confidential docs
site:.mil "operation" ext:doc                                      # Military operations
"for official use only" site:.gov                                  # FOUO documents
"classified" filetype:pdf site:.gov                                # Classified docs
"security clearance" ext:xls                                       # Clearance lists
"intelligence report" site:.gov                                    # Intel reports

# ==============================================
# 12. EDUCATIONAL INSTITUTIONS
# ==============================================
site:.edu "student records"                                        # Student records
"gradebook" filetype:xls site:.edu                                 # Gradebooks
"financial aid" ext:pdf site:.edu                                  # Financial aid docs
"research data" ext:csv site:.edu                                  # Research data
"thesis" filetype:pdf "confidential" site:.edu                     # Theses
"faculty salaries" ext:xls site:.edu                               # Salary info

# ==============================================
# 13. AUTOMATION & SCRIPTS
# ==============================================
parallel -j 5 'curl -s "https://google.com/search?q={}"' ::: \     # Parallel scanning
  "site:target.com ext:sql" \                                      # SQL files
  "intitle:'index of' 'backup'" \                                  # Backups
  "filetype:env 'DB_PASSWORD'"                                     # Env files

# Bulk domain scanning
while read domain; do
  curl -s "https://google.com/search?q=site:$domain+filetype:pdf"
done < domains.txt

# Scheduled monitoring
watch -n 3600 "curl -s 'https://google.com/search?q=site:target.com+after:$(date +%Y-%m-%d)'"

# ==============================================
# 14. DEFENSIVE DORKING
# ==============================================
site:target.com intext:"copyright" -github                         # IP protection
"security@" site:target.com ext:contact                            # Abuse contacts
filetype:pdf "responsible disclosure policy"                       # Bug bounty
"dmca@" OR "legal@" site:target.com                                # Legal contacts
"privacy policy" "data protection" site:target.com                 # Privacy docs

# ==============================================
# 15. LEGAL & COMPLIANCE
# ==============================================
# US Computer Fraud and Abuse Act (CFAA) applies
# GDPR compliance required for EU targets
# Always obtain written permission
# Document all testing activities

# ==============================================
# PRO TIPS
# ==============================================
# 1. Chain operators: intitle:"index of" "backup" ext:sql
# 2. Use date ranges: after:2023-01 before:2023-12
# 3. Exclude results: -site:github.com
# 4. For precise matches: allintext:"username password"
# 5. Use proxies: curl -x socks5h://localhost:9050

# ==============================================
# LEGAL DISCLAIMER
# ==============================================
# This file is for educational purposes only.
# Unauthorized scanning is illegal.
# Use only with explicit permission.
# ==============================================

# 1. Quick Credential Search
curl "https://google.com/search?q=intext:'password' filetype:log site:target.com"

# 2. Full Domain Audit
grep -A5 "CREDENTIALS" dorkfile.sh | while read dork; do curl -s "https://google.com/search?q=$dork site:yourdomain.com"; done

# 3. Cloud Security Check
awk '/CLOUD/{flag=1;next}/NETWORK/{flag=0}flag' dorkfile.sh | \ parallel -j 3 'curl -s "https://google.com/search?q={}"'