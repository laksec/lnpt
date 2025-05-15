# 🧠 BUSINESS LOGIC TESTING MASTER CHECKLIST

## 10.0 Introduction to Business Logic
### Pre-Assessment
    - Document all key business workflows
    - Identify sensitive operations (payments, admin functions)
    - Map trust boundaries between components
    - Review rate limiting and fraud detection mechanisms

## 10.1 Test Business Logic Data Validation
### Input Validation
    - Test negative values in financial transactions
    - Verify decimal handling (0.999 vs 1.00)
    - Check maximum quantity limits (e.g., order 999999 items)
    - Test special characters in all fields
    - Verify coupon stacking logic

### State Validation
    - Test out-of-sequence workflow access
    - Verify cart/checkout state consistency
    - Check time-limited offer expiration

## 10.2 Test Ability to Forge Requests
### Request Manipulation
    - Modify hidden form fields (e.g., price, userID)
    - Tamper with API parameters via Burp
    - Replay requests with altered timestamps
    - Test parameter pollution in critical actions

### Privilege Testing
    - Change role IDs in requests
    - Test UUID prediction/bruteforcing
    - Verify JWT claims enforcement

## 10.3 Test Integrity Checks
### Tamper Detection
    - Test checksum/hash validation
    - Verify digital signature enforcement
    - Check audit log generation for sensitive actions
    - Test replay attack prevention

## 10.4 Test for Process Timing
### Timing Attacks
    - Measure response times for:
    - Valid/invalid credentials
    - Existing/non-existing accounts
    - Correct/incorrect MFA codes
    - Verify async processing of sensitive operations

## 10.5 Test Function Usage Limits
### Rate Limiting
    - Test API endpoint throttling
    - Verify free trial restrictions
    - Check coupon code usage limits
    - Test password reset flood protection

## 10.6 Testing Workflow Circumvention
### Flow Bypass
    - Skip required steps in multi-step processes
    - Access "completed" workflows post-modification
    - Test direct URL access to restricted steps
    - Verify parallel session restrictions

## 10.7 Test Defenses Against Application Misuse
### Abuse Scenarios
    - Test scalping/bot protections
    - Verify geo-fencing enforcement
    - Check referral program abuse
    - Test loyalty point exploitation

## 10.8 Test Upload of Unexpected File Types
### File Validation
    - Upload disguised files (e.g., .exe as .jpg)
    - Test oversized files (> defined limits)
    - Verify metadata stripping (EXIF, macros)
    - Check virus scanning implementation

## 10.9 Test Upload of Malicious Files
### Malware Testing
    - Upload EICAR test file
    - Test polyglot files
    - Verify HTML/JS file sanitization
    - Check archive bomb protection

## 10.10 Test Payment Functionality
### Transaction Testing
    - Test negative/zero-value transactions
    - Verify currency conversion rounding
    - Check partial refund exploitation
    - Test duplicate transaction detection
    - Verify CVV/CSC validation

## 10.11 Additional Critical Tests
### Price Manipulation
    - Modify prices via HTTP parameter tampering
    - Test loyalty point exchange rates
    - Verify server-side total recalculation

### Inventory Management
    - Test negative inventory values
    - Verify concurrent purchase handling
    - Check overselling protections


### 🛡️ DEFENSE VERIFICATION CHECKLIST
    ✔ Server-side validation for all business rules  
    ✔ Non-repudiation mechanisms for critical actions  
    ✔ Real-time monitoring for anomalous patterns  
    ✔ Fraud scoring for high-risk transactions  

### 🔧 TESTING TOOLS
    - Burp Suite (Request manipulation)
    - Postman (API workflow testing)
    - OWASP ZAP (Automated business logic scans)
    - Custom scripts (Race condition testing)
    - Selenium (Multi-step workflow automation)

### ⚠️ COMMON BUSINESS LOGIC FLAWS
    - Negative balance exploitation
    - Coupon code brute-forcing
    - Time-of-check vs time-of-use (TOCTOU) issues
    - Unlimited free trial extensions
    - Workflow step skipping

#### Would you like me to add:
    1. Specific exploit examples for e-commerce systems?
    2. Compliance mappings (PCI DSS 4.0 requirements)?
    3. Industry-specific test cases (banking/healthcare)?
    4. Sample fraud detection rule configurations?