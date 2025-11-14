
# 🔍 JSON WEB TOKENS (JWT) TESTING CHECKLIST

## 6.10 Comprehensive JWT Security Testing

### 6.10.1 JWT Structure and Validation Testing
    - Token Format Testing:
      * Header parsing vulnerabilities
      * Payload structure analysis
      * Signature validation testing
      * Base64URL encoding issues
      * Token segmentation flaws

    - Algorithm Validation Testing:
      * "alg: none" vulnerability testing
      * Algorithm confusion attacks
      * Weak algorithm exploitation (HS256 vs RS256)
      * Unsupported algorithm handling
      * Algorithm downgrade attacks

    - Signature Verification Testing:
      * Missing signature validation
      * Signature bypass techniques
      * Key confusion attacks
      * Public key extraction attempts
      * Symmetric key brute force

### 6.10.2 JWT Claims Testing
    - Standard Claims Testing:
      * "exp" (expiration) claim manipulation
      * "nbf" (not before) claim bypass
      * "iat" (issued at) claim forgery
      * "iss" (issuer) claim spoofing
      * "aud" (audience) claim manipulation

    - Custom Claims Testing:
      * Privilege escalation via custom claims
      * Claim injection vulnerabilities
      * Claim tampering attacks
      * Business logic bypass via claims
      * Role modification testing

    - Claim Validation Testing:
      * Missing claim validation
      * Type confusion attacks
      * Claim order manipulation
      * Duplicate claim exploitation
      * Case sensitivity issues

### 6.10.3 JWT Storage and Transmission Testing
    - Client-Side Storage Testing:
      * LocalStorage JWT exposure
      * SessionStorage security issues
      * Cookie storage configuration
      * IndexedDB token storage
      * Memory storage analysis

    - Transmission Security Testing:
      * HTTPS enforcement validation
      * Token transmission in URLs
      * Authorization header testing
      * Cross-origin token leakage
      * Referrer header exposure

    - Browser Security Testing:
      * HttpOnly flag implementation
      * Secure cookie flag testing
      * SameSite attribute validation
      * Domain and path scope testing
      * Cookie prefix security

### 6.10.4 JWT Cryptography Testing
    - Key Management Testing:
      * Weak secret key testing
      * Key rotation vulnerabilities
      * Key storage security assessment
      * Key generation weaknesses
      * Hardcoded key detection

    - Encryption Testing:
      * JWE encryption bypass
      * Weak encryption algorithms
      * Encryption key brute force
      * CBC mode attacks
      * Padding oracle vulnerabilities

    - Signature Security Testing:
      * HMAC key strength testing
      * RSA key size validation
      * ECDSA curve security
      * Signature forgery attempts
      * Key injection attacks

### 6.10.5 JWT Implementation Flaw Testing
    - Library Vulnerabilities Testing:
      * Known JWT library vulnerabilities
      * Version-specific exploits
      * Library misconfiguration
      * Default settings exploitation
      * Dependency chain attacks

    - Parser Testing:
      * Parser differential attacks
      * Header parameter injection
      * JSON parser vulnerabilities
      * Type confusion attacks
      * Parser error handling

    - Validation Bypass Testing:
      * Missing signature verification
      * Partial validation attacks
      * Case sensitivity bypass
      * Whitespace manipulation
      * Encoding/decoding issues

### 6.10.6 JWT Revocation and Expiration Testing
    - Token Expiration Testing:
      * Expired token acceptance
      * Clock skew exploitation
      * Timezone manipulation
      * Token lifetime extension
      * "exp" claim bypass

    - Revocation Mechanism Testing:
      * Blacklist implementation testing
      * Token revocation effectiveness
      * Logout functionality security
      * Session invalidation testing
      * Forceful token expiration

    - Refresh Token Testing:
      * Refresh token theft testing
      * Refresh token replay attacks
      * Unlimited refresh token usage
      * Refresh token scope escalation
      * Refresh token expiration bypass

### 6.10.7 JWT in OAuth/OIDC Flows Testing
    - Authorization Code Flow Testing:
      * JWT in authorization code
      * ID token validation testing
      * Access token security
      * Token endpoint security
      * Redirect URI validation

    - Implicit Flow Testing:
      * JWT exposure in URL fragments
      * Token interception in browser
      * Implicit flow security issues
      * Token leakage to third parties
      * Client authentication bypass

    - Hybrid Flow Testing:
      * Mixed flow JWT security
      * Multiple token handling
      * Token binding validation
      * Cross-flow contamination
      * Scope escalation attacks

### 6.10.8 Advanced JWT Attacks Testing
    - JWT Injection Testing:
      * Header injection attacks
      * Payload injection testing
      * JSON injection vulnerabilities
      * SQL injection via JWT claims
      * Command injection through tokens

    - JWT Spoofing Testing:
      * Token forgery attempts
      * Signature spoofing attacks
      * Claim spoofing testing
      * Issuer spoofing attempts
      * Audience spoofing attacks

    - JWT Replay Testing:
      * Token replay attacks
      * Replay protection bypass
      * Time-based replay attacks
      * Cross-user replay testing
      * Cross-service replay attacks

### 6.10.9 JWT in Microservices Testing
    - Service-to-Service Testing:
      * Inter-service JWT validation
      * API gateway token handling
      * Service mesh JWT security
      * Cross-service claim propagation
      * Trust boundary validation

    - Token Propagation Testing:
      * Token forwarding vulnerabilities
      * Claim modification during propagation
      * Token scope expansion attacks
      * Service chain security issues
      * Delegation token security

    - Distributed Validation Testing:
      * Centralized vs decentralized validation
      * Cache poisoning attacks
      * Validation service security
      * Key distribution vulnerabilities
      * Service discovery attacks

### 6.10.10 Mobile JWT Security Testing
    - Mobile Storage Testing:
      * Keychain/Keystore security
      * Shared preferences exposure
      * Mobile backup vulnerabilities
      * App sandbox bypass attempts
      * Inter-app communication security

    - Mobile Transmission Testing:
      * Cellular network interception
      * Mobile VPN security testing
      * Certificate pinning bypass
      * Mobile proxy interception
      * Certificate validation testing

    - Mobile Application Testing:
      * JWT caching vulnerabilities
      * Background app token access
      * Mobile browser JWT handling
      * Deep link token exposure
      * Push notification token security

### 6.10.11 JWT Best Practices Validation
    - Security Headers Testing:
      * JWT-related security headers
      * CORS configuration testing
      * CSP header validation
      * HSTS implementation testing
      * Security header completeness

    - Development Practices Testing:
      * Secure coding practices
      * Error handling security
      * Logging and monitoring
      * Security testing integration
      * Code review effectiveness

    - Operational Security Testing:
      * Key rotation procedures
      * Incident response planning
      * Monitoring and alerting
      * Backup and recovery security
      * Disaster recovery testing

### 6.10.12 JWT Detection and Response Testing
    - Anomaly Detection Testing:
      * Unusual token usage patterns
      * Geographic anomaly detection
      * Device fingerprint validation
      * Behavioral analysis testing
      * Rate limiting effectiveness

    - Response Mechanism Testing:
      * Token revocation procedures
      * User notification systems
      * Session termination testing
      * Forensic evidence collection
      * Recovery process validation

    - Monitoring Testing:
      * Real-time token monitoring
      * Security event correlation
      * Audit log completeness
      * Alerting system effectiveness
      * Reporting capabilities

#### Testing Methodology:
    Phase 1: JWT Architecture Analysis
    1. Map JWT implementation architecture
    2. Identify token generation and validation points
    3. Analyze cryptographic implementation
    4. Document token flow and storage

    Phase 2: Core JWT Security Testing
    1. Test token structure and validation
    2. Validate cryptographic security
    3. Check claim validation integrity
    4. Verify storage and transmission security

    Phase 3: Advanced Attack Simulation
    1. Test implementation-specific vulnerabilities
    2. Validate advanced cryptographic attacks
    3. Check microservice and distributed issues
    4. Verify mobile and cross-platform security

    Phase 4: Protection and Response Assessment
    1. Measure detection system effectiveness
    2. Assess prevention mechanism strength
    3. Validate incident response procedures
    4. Document business impact

#### Automated Testing Tools:
    JWT-Specific Tools:
    - jwt_tool: JWT security testing toolkit
    - jwt-heartbreaker: JWT vulnerability scanner
    - jwt-cracker: JWT secret brute forcer
    - Burp Suite JWT extensions
    - OWASP ZAP JWT add-ons

    Cryptographic Testing Tools:
    - John the Ripper with JWT rules
    - Hashcat for JWT secret cracking
    - Custom JWT manipulation scripts
    - Algorithm confusion testing tools
    - Signature verification testers

    Development Testing Tools:
    - JWT linting and validation tools
    - Security scanning in CI/CD pipelines
    - Code analysis tools with JWT rules
    - Dependency vulnerability scanners
    - Automated security testing frameworks

#### Common Test Commands:
    JWT Manipulation:
    # Decode JWT without verification
    echo "JWT_TOKEN" | jq -R 'split(".") |  [0],.[1] | @base64d | fromjson'
    
    # Test "none" algorithm
    jwt encode --alg none --secret "" "payload"
    
    # Brute force secret
    jwt-cracker "JWT_TOKEN" "alphabet" max-length

    Algorithm Confusion:
    # Convert RSA public key to HMAC secret
    openssl rsa -pubin -in public.pem -text -noout
    
    # Test HS256 with RSA public key
    jwt encode --alg HS256 --secret "$(cat public.pem)" "payload"

    Token Analysis:
    # Analyze JWT structure
    jwt debug "JWT_TOKEN"
    
    # Validate token claims
    jwt verify "JWT_TOKEN" --secret "your-secret"

#### Risk Assessment Framework:
    Critical Risk:
    - "alg: none" vulnerability present
    - No signature verification implemented
    - Weak symmetric keys (HS256 with short secrets)
    - Tokens transmitted over HTTP
    - No token expiration implemented

    High Risk:
    - Algorithm confusion vulnerabilities
    - Weak RSA keys (<2048 bits)
    - Missing claim validation
    - Tokens stored in insecure locations
    - No HTTPS enforcement

    Medium Risk:
    - Insensitive token expiration
    - Weak key rotation procedures
    - Limited validation of claims
    - Suboptimal storage mechanisms
    - Incomplete monitoring

    Low Risk:
    - Theoretical attack vectors
    - Minor information leakage in claims
    - Documentation issues
    - Logging improvements needed

#### Protection and Hardening:
    - JWT Security Best Practices:
      * Always validate token signatures
      * Use strong algorithms (RS256, ES256)
      * Implement proper claim validation
      * Store tokens securely (HttpOnly cookies)
      * Use short expiration times

    - Technical Controls:
      * Implement token blacklisting/revocation
      * Use appropriate key sizes and rotation
      * Enable comprehensive monitoring
      * Implement proper error handling
      * Regular security testing and code review

    - Operational Security:
      * Secure key management procedures
      * Regular security assessments
      * Incident response planning
      * Developer security training
      * Continuous security monitoring

#### Testing Execution Framework:
    Step 1: JWT Implementation Review
    - Document JWT architecture and flow
    - Analyze token generation and validation
    - Identify cryptographic implementation
    - Review storage and transmission mechanisms

    Step 2: Core Security Testing
    - Test token validation vulnerabilities
    - Validate cryptographic security
    - Check claim validation integrity
    - Verify transmission and storage security

    Step 3: Advanced Security Assessment
    - Test implementation-specific issues
    - Validate advanced attack scenarios
    - Check distributed system vulnerabilities
    - Verify mobile and API security

    Step 4: Protection and Response Evaluation
    - Measure protection mechanism effectiveness
    - Assess detection and response capabilities
    - Validate monitoring and logging
    - Document improvement recommendations

#### Documentation Template:
    JWT Security Assessment Report:
    - Executive Summary and Risk Overview
    - JWT Architecture Analysis
    - Vulnerability Details and Evidence
    - Cryptographic Security Assessment
    - Implementation Flaw Analysis
    - Business Impact Assessment
    - Protection Mechanism Evaluation
    - Detection and Response Assessment
    - Risk Assessment and Scoring
    - Remediation Recommendations
    - Security Hardening Guidelines

This comprehensive JWT testing checklist ensures thorough evaluation of JSON Web Token security controls, helping organizations prevent unauthorized access, privilege escalation, and data compromise through robust token security and continuous security assessment.
