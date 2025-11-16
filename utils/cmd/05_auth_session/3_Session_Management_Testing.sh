#!/bin/bash
# ==============================================
# SESSION MANAGEMENT SECURITY TESTING CHEAT SHEET
# ==============================================

# 1. COOKIE INSPECTION
# --------------------

# View cookies from response
curl -Iks https://target.com | grep -i 'set-cookie'

# Detailed cookie inspection
curl -ks https://target.com -o /dev/null -w "Cookies: %{cookie_parse}\n"

# Common tests:
# - Secure flag missing
# - HttpOnly flag missing
# - SameSite attribute
# - Overly long expiration

# 2. SESSION FIXATION
# -------------------

# Test session fixation vulnerability
# Step 1: Get a fixed session ID
curl -ks https://target.com/login -c fixated_cookie.txt

# Step 2: Authenticate with fixed session
curl -ks https://target.com/login -d "user=admin&pass=password" -b fixated_cookie.txt

# Step 3: Verify session remains same
curl -ks https://target.com/dashboard -b fixated_cookie.txt

# 3. SESSION TIMEOUT
# ------------------

# Test session timeout (adjust sleep time)
curl -ks https://target.com/login -d "user=admin&pass=password" -c auth_cookie.txt
sleep 1210 # Default timeout often 20 minutes
curl -ks https://target.com/dashboard -b auth_cookie.txt

# 4. CONCURRENT SESSION TESTING
# -----------------------------

# Test multiple concurrent sessions
curl -ks https://target.com/login -d "user=admin&pass=password" -c session1.txt
curl -ks https://target.com/login -d "user=admin&pass=password" -c session2.txt

# Verify both sessions work
curl -ks https://target.com/dashboard -b session1.txt
curl -ks https://target.com/dashboard -b session2.txt

# 5. SESSION INVALIDATION
# ----------------------

# Test logout functionality
curl -ks https://target.com/login -d "user=admin&pass=password" -c auth_cookie.txt
curl -ks https://target.com/logout -b auth_cookie.txt
curl -ks https://target.com/dashboard -b auth_cookie.txt

# 6. TOKEN ANALYSIS
# ----------------

# Decode JWT sessions (if used)
echo "SESSION_TOKEN" | cut -d '.' -f 2 | base64 -d 2>/dev/null | jq

# Test for weak tokens
crunch 10 10 0123456789 | while read token; do
  curl -ks https://target.com/dashboard -H "Authorization: Bearer $token" | grep -q "Welcome" && echo "Valid token: $token" && break
done

# 7. TOOLS
# --------

# Burp Suite:
# - Use Session Handling Rules
# - Test with Sequencer
# - Check with Active Scan

# OWASP ZAP:
# - Session Management Scripts
# - Authentication Testing

# Custom Scripts:
python3 session_tester.py -u https://target.com -w wordlist.txt

# 8. AUTOMATED CHECKS
# ------------------

# Nuclei Templates
nuclei -t ~/nuclei-templates/session/ -u https://target.com -o session_scan.txt

# ==============================================
# TIPS:
# 1. Always check for session regeneration after login
# 2. Verify cookies have proper security flags
# 3. Test with different browsers/devices
# 4. Check for session sharing across users
# ==============================================

# COMMON VULNERABILITIES:
# -----------------------
# 1. Session fixation
# 2. Missing Secure/HttpOnly flags
# 3. Weak session tokens
# 4. No proper timeout
# 5. Concurrent sessions allowed
# 6. Session not invalidated on logout
# 7. Session tokens in URLs

# RECOMMENDED WORDLISTS:
# ----------------------
# /usr/share/wordlists/session/common_cookies.txt
# /usr/share/wordlists/session/tokens.txt

# Manual Testing Checklist:
# Cookie Attributes:
# - Secure flag (HTTPS only)
# - HttpOnly flag (anti-XSS)
# - SameSite attribute (CSRF protection)
# - Domain/path restrictions

# Session Lifecycle:
# - Generation (randomness, strength)
# - Timeout (inactivity timeout)
# - Destruction (logout functionality)
# - Renewal (after privilege changes)

# Session Tokens:
# - Predictability testing
# - Entropy analysis
# - Information leakage

# Advanced Techniques:
# - Session Puzzle Attacks: Testing for session confusion vulnerabilities
# - Session Riding: Testing for CSRF with valid sessions
# - Subdomain Attacks: Testing cookie scope across subdomains
# - Browser Cache Effects: Testing back/forward cache behavior