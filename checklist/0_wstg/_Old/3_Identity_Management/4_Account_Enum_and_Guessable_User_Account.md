
# 🔍 ACCOUNT ENUMERATION & GUESSABLE USER ACCOUNT TESTING CHECKLIST

## 3.4 Comprehensive Account Enumeration and Guessable User Account Testing

### 3.4.1 Authentication Interface Enumeration Testing
    - Login Response Testing:
      * Distinct error messages for invalid username vs invalid password
      * Response time differential analysis
      * HTTP status code variations
      * Redirect behavior differences
      * Session cookie setting on valid/invalid users

    - Error Message Analysis:
      * Verbose error message information leakage
      * Custom error page content analysis
      * Password strength feedback timing
      * Account status disclosure (locked, disabled, pending)
      * Email-based username disclosure

    - Timing Attack Testing:
      * Response time analysis for valid vs invalid users
      * Database query timing exploitation
      * Network latency manipulation
      * Resource-intensive operations timing
      * Cryptographic operation timing

### 3.4.2 Registration Process Enumeration Testing
    - Duplicate Account Detection Testing:
      * Real-time username availability checking
      * Email existence verification
      * Phone number validation responses
      * Social security number verification
      * Employee ID validation

    - Registration Error Messages:
      * "Username already exists" disclosure
      * "Email already registered" messages
      * "Account pending approval" status
      * "Invitation required" responses
      * Domain-specific account validation

    - Progressive Disclosure Testing:
      * Step-by-step registration information leakage
      * Pre-populated field analysis
      * Auto-complete behavior
      * Social registration integration leaks

### 3.4.3 Password Reset Enumeration Testing
    - Password Reset Flow Testing:
      * "Username/email not found" vs "reset email sent" responses
      * Password reset token predictability
      * Reset link expiration timing analysis
      * Account lockout during reset process
      * Multi-factor reset bypass

    - Security Question Testing:
      * Security question disclosure for valid accounts
      * Question answer timing attacks
      * Common security question predictability
      * Custom question information leakage
      * Question skipping for non-existent accounts

    - SMS/Email Verification Testing:
      * OTP code delivery confirmation
      * Phone number/email existence confirmation
      * Rate limiting bypass techniques
      * OTP code predictability
      * Verification code reuse testing

### 3.4.4 Account Recovery Enumeration Testing
    - Recovery Option Testing:
      * Available recovery methods disclosure
      * Backup email/phone exposure
      * Recovery question revelation
      * Trusted device information leakage
      * Recovery code distribution

    - Recovery Response Analysis:
      * Success/failure message differentiation
      * Recovery method availability based on account existence
      * Time-based recovery option disclosure
      * Geographic recovery restrictions
      * Device-based recovery limitations

    - Social Engineering Vector Testing:
      * Customer support information disclosure
      * Help desk verification procedures
      * Knowledge-based authentication weaknesses
      * Personal information verification exposure
      * Administrative override procedures

### 3.4.5 API Endpoint Enumeration Testing
    - REST API Testing:
      * API response differentiation
      * Error object structure analysis
      * Rate limiting implementation gaps
      * Bulk account validation endpoints
      * GraphQL introspection attacks

    - Mobile API Testing:
      * Mobile-specific endpoint behavior
      * Different authentication flows
      * Offline account validation
      * Cached account information
      * Biometric authentication leaks

    - Third-Party Integration Testing:
      * OAuth authorization endpoint leaks
      * SAML identity provider responses
      * SCIM user provisioning endpoints
      * Webhook account validation
      * Federated identity leaks

### 3.4.6 Guessable Username Testing
    - Common Username Patterns:
      * Default administrator accounts (admin, administrator, root)
      * Email-based usernames (first.last@company.com)
      * Employee ID patterns (E12345, 100001)
      * Sequential numbering schemes
      * Department-based naming (hr001, finance001)

    - Organizational Structure Analysis:
      * Executive team username guessing
      * IT department account patterns
      * Developer account naming conventions
      * Service account identification
      * Vendor account patterns

    - Industry-Specific Patterns:
      * Healthcare: doctor IDs, patient codes
      * Education: student IDs, faculty codes
      * Finance: trader IDs, analyst codes
      * Government: employee badge numbers
      * Military: rank-based usernames

### 3.4.7 User Directory Enumeration Testing
    - LDAP/Active Directory Testing:
      * Anonymous LDAP binding
      * LDAP query injection
      * Directory information tree exposure
      * User attribute disclosure
      * Group membership enumeration

    - Web Directory Testing:
      * User profile page accessibility
      * Author page enumeration
      * Commenter identification
      * File upload attribution
      * Activity stream analysis

    - Search Functionality Testing:
      * User search feature exploitation
      * Wildcard search capabilities
      * Advanced search operator abuse
      * Search result limitation bypass
      * Auto-suggest feature analysis

### 3.4.8 Information Disclosure Testing
    - Public Information Correlation:
      * Social media profile matching
      * Professional network analysis
      * Company directory information
      * Conference attendee lists
      * GitHub/LinkedIn username patterns

    - Technical Information Leakage:
      * Error stack traces
      * Log file exposure
      * Backup file disclosure
      * Version control exposure
      * Configuration file leaks

    - Metadata Analysis:
      * Document metadata examination
      * Image EXIF data extraction
      * Email header analysis
      * Network packet inspection
      * Browser cache examination

### 3.4.9 Rate Limiting Bypass Testing
    - IP Rotation Testing:
      * Multiple IP address rotation
      * Proxy server utilization
      * VPN service switching
      * Tor network exploitation
      * Cloud platform IP diversity

    - Request Variation Testing:
      * HTTP method alternation (GET/POST/PUT)
      * Parameter permutation
      * Header manipulation
      * Encoding variation
      * Protocol switching

    - Timing Bypass Testing:
      * Request timing randomization
      * Low-and-slow attack patterns
      * Distributed enumeration attempts
      * Application-level bypasses
      * Cache poisoning techniques

### 3.4.10 Authentication Bypass Testing
    - Credential Stuffing Testing:
      * Breached credential database testing
      * Password spray attacks
      * Default credential testing
      * Weak password pattern exploitation
      * Season-based password guessing

    - Session Manipulation Testing:
      * Session prediction attacks
      * Cookie manipulation
      * Token replay attacks
      * JWT token tampering
      * Single Sign-On exploitation

    - Multi-Factor Bypass Testing:
      * MFA fatigue attacks
      * SIM swapping techniques
      * Biometric spoofing
      * Backup code prediction
      * Trusted device manipulation

### 3.4.11 Application-Specific Enumeration Testing
    - E-commerce Applications:
      * Order history enumeration
      * Wishlist accessibility
      * Review author identification
      * Loyalty program account discovery
      * Payment method attribution

    - Social Media Platforms:
      * Profile URL guessing
      * Friend list enumeration
      * Group membership discovery
      * Activity feed analysis
      * Direct message recipient validation

    - Enterprise Applications:
      * Employee directory exploitation
      * Organization chart analysis
      * Project team identification
      * Departmental account patterns
      * Vendor portal access

### 3.4.12 Defense Evasion Testing
    - WAF Bypass Testing:
      * Signature evasion techniques
      * Obfuscation methods
      * Encoding variations
      * Protocol-level evasion
      * Behavioral mimicry

    - Detection Avoidance Testing:
      * Human-like interaction patterns
      * Randomized timing intervals
      * Geographic consistency maintenance
      * User agent rotation
      * Referrer header manipulation

    - Countermeasure Testing:
      * CAPTCHA bypass techniques
      * Behavioral analysis evasion
      * Device fingerprinting spoofing
      * IP reputation manipulation
      * Browser automation detection evasion

#### Testing Methodology:
    Phase 1: Reconnaissance and Discovery
    1. Identify all authentication-related endpoints
    2. Map user interaction points
    3. Analyze application architecture
    4. Document information disclosure vectors

    Phase 2: Enumeration Technique Testing
    1. Test login/registration/reset flows for information leakage
    2. Analyze API endpoints for user existence disclosure
    3. Test timing and error-based enumeration
    4. Validate guessable username patterns

    Phase 3: Advanced Attack Testing
    1. Test rate limiting bypass techniques
    2. Validate defense evasion methods
    3. Test application-specific enumeration
    4. Verify correlation attack effectiveness

    Phase 4: Impact Assessment
    1. Measure enumeration success rates
    2. Assess business impact of account discovery
    3. Validate detection and prevention controls
    4. Document risk assessment findings

#### Automated Testing Tools:
    Enumeration Tools:
    - Burp Suite Intruder with custom payloads
    - OWASP ZAP with enumeration scripts
    - Custom Python enumeration scripts
    - Hydra for brute-force testing
    - Patator for multi-protocol attacks

    OSINT Tools:
    - Recon-ng for information gathering
    - theHarvester for email/username discovery
    - Sherlock for social media username enumeration
    - LinkedInt for LinkedIn data extraction
    - GHunt for Google account analysis

    Custom Testing Tools:
    - Timing attack measurement scripts
    - Response differential analysis tools
    - Pattern recognition algorithms
    - Bulk validation automation
    - Defense evasion testing frameworks

#### Common Test Commands:
    Basic Enumeration:
    # Test login responses with common usernames
    curl -X POST https://example.com/login \
      -d "username=admin&password=wrong" \
      -H "Content-Type: application/x-www-form-urlencoded"

    # Timing attack measurement
    time curl -s -o /dev/null -w "%{http_code}" https://api.example.com/user/exists?email=test@example.com

    Advanced Enumeration:
    # Bulk username validation with Burp
    java -jar burpsuite.jar --project-file=enumeration-project.burp

    # Pattern-based username generation
    for i in {100000..100100}; do
      curl -s "https://example.com/reset-password?username=user$i" | grep -q "exists" && echo "Found: user$i"
    done

#### Risk Assessment Framework:
    Critical Risk:
    - Reliable user enumeration via login responses
    - Predictable username patterns allowing mass account discovery
    - No rate limiting on authentication endpoints
    - Administrative account enumeration

    High Risk:
    - Timing attacks revealing valid accounts
    - Password reset flow information leakage
    - API endpoints disclosing account existence
    - Weak username/email validation

    Medium Risk:
    - Partial information disclosure in error messages
    - Limited enumeration via secondary features
    - Inconsistent rate limiting implementation
    - Predictable account recovery tokens

    Low Risk:
    - Theoretical enumeration requiring extensive resources
    - Limited impact information disclosure
    - Well-protected endpoints with strong controls
    - Non-sensitive account enumeration

#### Protection and Hardening:
    - Authentication Security Best Practices:
      * Use identical generic error messages for all authentication failures
      * Implement consistent response timing regardless of account existence
      * Apply comprehensive rate limiting with IP and account-based restrictions
      * Use CAPTCHA or other bot protection mechanisms

    - Account Management Controls:
      * Implement account lockout policies after repeated failures
      * Use strong, unpredictable usernames/IDs
      * Monitor for suspicious enumeration patterns
      * Regular security awareness training

    - Technical Defenses:
      * Web Application Firewall (WAF) with enumeration detection rules
      * Behavioral analysis for detection of automated attacks
      * Multi-factor authentication for sensitive accounts
      * Regular security testing and code review

#### Testing Execution Framework:
    Step 1: Enumeration Vector Identification
    - Map all user-facing authentication interfaces
    - Identify API endpoints and hidden functionality
    - Analyze application architecture and data flows
    - Document potential information leakage points

    Step 2: Basic Enumeration Testing
    - Test standard authentication flows
    - Validate error message consistency
    - Check timing attack susceptibility
    - Test guessable username patterns

    Step 3: Advanced Technique Testing
    - Test rate limiting bypass methods
    - Validate defense evasion techniques
    - Test application-specific enumeration
    - Check correlation attack effectiveness

    Step 4: Impact and Mitigation Assessment
    - Measure enumeration success rates
    - Assess business impact
    - Validate existing controls
    - Document remediation recommendations

#### Documentation Template:
    Account Enumeration Assessment Report:
    - Executive Summary and Risk Overview
    - Enumeration Vectors Identified
    - Testing Methodology and Tools Used
    - Vulnerability Details and Evidence
    - Business Impact Analysis
    - Attack Scenarios and Exploitation Paths
    - Risk Assessment and Scoring
    - Remediation Recommendations
    - Detection and Monitoring Guidance
    - Ongoing Assessment Procedures

This comprehensive Account Enumeration and Guessable User Account testing checklist ensures thorough evaluation of user discovery vulnerabilities, helping organizations prevent unauthorized account identification, credential stuffing attacks, and targeted account compromise through proper authentication security controls.
