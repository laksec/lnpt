# 🔐 AUTHORIZATION TESTING MASTER CHECKLIST

## 5.1 Testing Directory Traversal/File Include
    - Test path traversal using ../ sequences
    - Verify absolute path blocking (e.g., /etc/passwd)
    - Check for null byte injection (%00)
    - Test encoded traversal attempts (URL, double URL, UTF-8)
    - Verify file inclusion with remote URLs
    - Check for restricted file extensions bypass
    - Test Windows-specific paths (C:\Windows\system.ini)
    - Verify web server configuration files inaccessible

## 5.2 Testing for Bypassing Authorization Schema
    - Test forced browsing to privileged pages
    - Verify horizontal privilege separation
    - Check for missing authorization headers
    - Test parameter manipulation for role changes
    - Verify API endpoints enforce authorization
    - Check for admin functionality in client-side code
    - Test state-changing actions without CSRF tokens
    - Verify JWT claims are properly validated

## 5.3 Testing for Privilege Escalation
    - Test user role parameter tampering
    - Verify UUID/userID can't be guessed
    - Check for admin cookies in normal user flows
    - Test concurrent sessions with different roles
    - Verify password change requires current password
    - Check for privilege inheritance vulnerabilities
    - Test API endpoints with elevated privileges
    - Verify admin interfaces require re-authentication

## 5.4 Testing for Insecure Direct Object References (IDOR)
    - Test sequential object IDs (1, 2, 3...)
    - Verify UUIDs are truly random
    - Check for direct database references
    - Test file references with different extensions
    - Verify indirect reference maps are used
    - Check for IDOR in POST/PUT requests
    - Test mass assignment vulnerabilities
    - Verify object ownership checks

## 5.5 Testing for OAuth Weaknesses
### 5.5.1 Testing OAuth Authorization Server
    - Verify PKCE implementation
    - Test for open redirect vulnerabilities
    - Check refresh token rotation
    - Verify scope restrictions are enforced
    - Test for token leakage in URLs
    - Check token expiration times (max 10 min)
    - Verify client secrets aren't exposed
    - Test for SSRF in OAuth callbacks

### 5.5.2 Testing OAuth Client
    - Verify state parameter is random and validated
    - Test for CSRF in OAuth flows
    - Check proper token storage (not localStorage)
    - Verify token validation on server-side
    - Test for token replay attacks
    - Check for implicit flow vulnerabilities
    - Verify logout terminates OAuth sessions
    - Test for mixed OAuth versions

#### Recommended Tools:
    Burp Suite with Autorize extension
    OWASP ZAP with Access Control add-on
    Postman for API authorization testing
    OAuth Tester tools (oxd, etc.)
    Custom scripts for IDOR detection
    JWT tools for token analysis