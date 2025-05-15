# 🔑 AUTHENTICATION TESTING MASTER CHECKLIST

## 4.1 Credential Transmission Security
    - Verify all authentication requests use HTTPS
    - Test for mixed content during auth flows
    - Check for credentials in URL parameters
    - Verify no credentials cached in browser history
    - Test for HTTP downgrade attacks
    - Check HSTS implementation on auth endpoints

## 4.2 Default Credentials Testing
    - Test common admin:admin combinations
    - Check vendor-specific default credentials
    - Verify default service accounts are changed
    - Test application installer defaults
    - Check IoT/device default credentials
    - Verify cloud service default passwords

## 4.3 Account Lockout Mechanisms
    - Test lockout threshold (3-5 attempts recommended)
    - Verify lockout duration (15-30 minutes recommended)
    - Check for lockout bypass via parameter tampering
    - Test different IP/user agent combinations
    - Verify lockout state persists after logout
    - Check for username enumeration via lockout messages

## 4.4 Authentication Bypass
    - Test SQLi in login forms
    - Check for JWT manipulation
    - Verify session fixation vulnerabilities
    - Test for magic/hardcoded tokens
    - Check cookie manipulation attacks
    - Verify CSRF protection on auth endpoints
    - Test for header injection (X-Original-URL)

## 4.5 "Remember Me" Functionality
    - Verify persistent tokens are random
    - Check token expiration (max 30 days)
    - Test for token prediction
    - Verify logout invalidates remember tokens
    - Check cookie security flags (HttpOnly, Secure)

## 4.6 Browser Cache Testing
    - Verify auth pages have no-cache headers
    - Test back button after logout
    - Check for sensitive data in browser cache
    - Verify autocomplete=off on password fields
    - Test page cache in CDN/proxies

## 4.7 Weak Authentication Methods
    - Test for basic auth over HTTPS
    - Verify no fallback to weaker protocols
    - Check for insecure LDAP binds
    - Test for NTLM/Windows auth vulnerabilities
    - Verify OAuth implementation security

## 4.8 Security Questions
    - Verify questions aren't easily guessable
    - Test for unlimited answer attempts
    - Check answers are case-sensitive
    - Verify questions can't be bypassed
    - Test for answers in social media

## 4.9 Password Reset Weaknesses
    - Test token expiration (max 1 hour)
    - Verify token single-use
    - Check for token prediction
    - Test account enumeration via reset
    - Verify old password requirement for changes
    - Check for weak new password requirements

## 4.10 Alternative Channel Auth
    - Test SMS/email auth code security
    - Verify equal security across channels
    - Check for OTP reuse
    - Test voice callback vulnerabilities
    - Verify mobile app auth consistency

## 4.11 Multi-Factor Authentication
    - Test MFA bypass via API endpoints
    - Verify backup codes are secure
    - Check MFA fatigue attacks
    - Test time sync for TOTP
    - Verify MFA re-enrollment requires auth
    - Check for MFA code leakage in logs
    - Test recovery process security

## Advanced Authentication Tests
    - Verify password hashing strength (bcrypt, Argon2)
    - Test for timing attacks in auth flows
    - Check for BREACH/CRIME vulnerabilities
    - Verify session invalidation after password change
    - Test concurrent session limitations
    - Check for authentication in iframes

#### Recommended Tools:
    Burp Suite for manual testing
    OWASP ZAP for automated scans
    JWT Toolkit for token testing
    Hashcat for password hash testing
    Custom scripts for timing attacks