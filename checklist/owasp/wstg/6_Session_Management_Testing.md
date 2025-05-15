# 🔒 SESSION MANAGEMENT TESTING MASTER CHECKLIST  

## 6.1 Testing for Session Management Schema  
    - Verify session tokens are randomly generated (no predictable patterns)  
    - Test for session token length (minimum 128 bits entropy)  
    - Check if session tokens expire after inactivity/timeout  
    - Verify no sensitive data stored in session tokens  
    - Test for session regeneration after login/logout  
    - Check if sessions are invalidated server-side when expired  
    - Test for session fixation (see 6.3)  

## 6.2 Testing for Cookies Attributes  
    - Verify Secure flag (HTTPS-only cookies)  
    - Check HttpOnly flag (prevent JavaScript access)  
    - Test SameSite attribute (`Strict` or `Lax` for CSRF protection)  
    - Verify Domain and Path restrictions (no overly permissive settings)  
    - Check Expires/Max-Age (not excessively long-lived)  
    - Test for cookie tampering (modify `sessionID` or `JWT`)  
    - Verify no sensitive data stored in cookies  

## 6.3 Testing for Session Fixation  
    - Test if session token changes after login  
    - Verify old session tokens cannot be reused  
    - Check if URL-based session tokens are avoided  
    - Test if session ID rotation occurs on privilege changes  

## 6.4 Testing for Exposed Session Variables  
    - Check URL parameters for session tokens (`?sessionid=123`)  
    - Test hidden form fields for session data  
    - Verify no session tokens in logs (server/application logs)  
    - Check browser storage (localStorage, sessionStorage) for sensitive data  
    - Test autocomplete on sensitive fields  

## 6.5 Testing for Cross-Site Request Forgery (CSRF)  
    - Verify CSRF tokens are required for state-changing actions  
    - Test if CSRF tokens are unique per session/request  
    - Check if SameSite cookie attribute mitigates CSRF  
    - Test header-based CSRF protection (`X-Requested-With`, `Origin`)  
    - Verify no GET requests for state changes  

## 6.6 Testing for Logout Functionality  
    - Verify session is invalidated server-side on logout  
    - Test if cookies are cleared/deleted on logout  
    - Check if back button allows access after logout  
    - Verify session timeout still applies post-logout  
    - Test concurrent session termination (if enabled)  

## 6.7 Testing Session Timeout  
    - Verify inactivity timeout (15-30 mins recommended)  
    - Test if absolute timeout exists (max session duration)  
    - Check if session persists after browser close  
    - Verify re-authentication required for sensitive actions  
    - Test if extending sessions is allowed (e.g., "Keep me logged in")  

## 6.8 Testing for Session Puzzling  
    - Verify no session confusion between different roles  
    - Test if session variables are isolated per user  
    - Check for session mixing in shared environments  
    - Verify no session parameter overrides (e.g., `?lang=en` affecting auth state)  

## 6.9 Testing for Session Hijacking  
    - Test session replay attacks (reusing old tokens)  
    - Verify IP/User-Agent binding (optional but recommended)  
    - Check if session tokens are exposed in network traffic  
    - Test man-in-the-middle (MITM) attacks (unencrypted sessions)  

## 6.10 Testing JSON Web Tokens (JWT)  
    - Verify signature validation (none algorithm disabled)  
    - Test for JWT tampering (modifying claims)  
    - Check expiration (`exp`) and not-before (`nbf`) claims  
    - Verify issuer (`iss`) and audience (`aud`) validation  
    - Test for weak HMAC keys (if used)  
    - Check if sensitive data is stored in JWT payload  
    - Verify token revocation mechanism (if applicable)  

## 6.11 Testing for Concurrent Sessions  
    - Verify if multiple sessions per user are allowed  
    - Test if old sessions are terminated on new login  
    - Check for session limits (max concurrent sessions)  
    - Verify admin alerts for suspicious concurrent logins  

## 6.12 Testing for Session Token Predictability  
    - Check if session tokens follow sequential patterns (e.g., `sessionID=1001`, `1002`)  
    - Verify tokens use cryptographically secure RNG (not timestamps or usernames)  
    - Test if token entropy is sufficient (prevent brute-force guessing)  
    - Check for weak hash algorithms (MD5, SHA-1) in token generation  

## 6.13 Testing for Session Token Leakage in Referer Headers  
    - Verify no session tokens are passed in `Referer` headers  
    - Test if external links expose session data  
    - Check redirects for token leakage  

## 6.14 Testing for Session Token Binding  
    - Verify if tokens are bound to IP address (optional, but useful for high-security apps)  
    - Test if User-Agent changes invalidate sessions  
    - Check for device fingerprinting to detect session hijacking  

## 6.15 Testing for CORS and Session Security  
    - Verify CORS headers don’t allow arbitrary origins (`Access-Control-Allow-Origin: *`)  
    - Test if credentials mode (`withCredentials`) is abused  
    - Check if cross-origin requests can steal session tokens  

## 6.16 Testing for Session Replay Attacks  
    - Verify one-time-use tokens for critical actions (e.g., password reset)  
    - Test if old JWTs are rejected after logout  
    - Check if timestamp-based nonces prevent replay  

## 6.17 Testing for Mixed HTTP/HTTPS Session Issues  
    - Verify no mixed content during session handshake  
    - Test if cookies set via HTTP can be stolen (force HTTPS-only)  
    - Check if HSTS is enforced for session-related pages  

## 6.18 Testing for Session Storage Security  
    - Verify no sensitive data stored in `localStorage`/`sessionStorage`  
    - Test if XSS can steal session tokens from client storage  
    - Check if session data is encrypted in client-side storage  

## 6.19 Testing for Session Management in Microservices  
    - Verify stateless sessions (JWT/OAuth) are properly validated  
    - Test if shared session stores (Redis, DB) are secured  
    - Check if session stickiness in load balancers introduces risks  

## 6.20 Testing for Session Attacks via WebSockets  
    - Verify WebSocket connections enforce session checks  
    - Test if session tokens in WebSocket URLs are exposed  
    - Check if real-time updates leak session data  


### 🔍 Advanced Session Testing Techniques  
    ✅ Time-based attacks: Check if token generation is predictable based on time.  
    ✅ Race conditions: Test if rapid session requests cause conflicts.  
    ✅ Cluster environments: Verify session sync across multiple servers.  
    ✅ Browser cache poisoning: Test if cached responses contain session data.  

### 🛡️ Mitigation Strategies Checklist  
    ✔ Always use `Secure`, `HttpOnly`, and `SameSite` cookies.  
    ✔ Implement short-lived sessions with re-authentication for sensitive actions.  
    ✔ Rotate session tokens after login/logout.  
    ✔ Log and monitor abnormal session activity (e.g., multiple IPs).  
    ✔ Use JWTs with strong signatures (`RS256`) instead of client-side storage.  

### 🔧 Recommended Tools:  
    ✅ Burp Suite (Session handling, CSRF testing)  
    ✅ OWASP ZAP (Automated session checks)  
    ✅ JWT.io / jwt_tool (JWT manipulation testing)  
    ✅ Browser DevTools (Cookie inspection, storage checks)  
    ✅ Postman/curl (API session testing)  
    ✅ Custom scripts (for session fixation, replay attacks)  

### 🚀 Final Recommendations  
- For high-security apps, consider IP binding and device fingerprinting.  
- For APIs, enforce short-lived JWTs with refresh token rotation.  
- For legacy systems, audit session management for predictable tokens.  

