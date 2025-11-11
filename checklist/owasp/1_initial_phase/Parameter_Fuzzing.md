# ULTIMATE PARAMETER FUZZING CHECKLIST (v1.0)

### Comprehensive Methodology for Input Validation Testing

### 🌐 RECONNAISSANCE PHASE

    - Identify all query parameters in URLs
    - Map POST/PUT request body parameters
    - Locate JSON/XML input fields in APIs
    - Document cookie parameters
    - Find hidden form fields
    - Identify HTTP headers used as parameters
    - Locate file upload metadata fields
    - Discover API versioning parameters
    - Find localization/language parameters
    - Identify caching-related parameters

### 🔍 BASIC FUZZING VECTORS

#### Data Type Testing

    - Test integer overflow/underflow
    - Verify negative number handling
    - Check large number values
    - Test floating-point precision
    - Verify string length limits
    - Check empty string handling
    - Test whitespace variations
    - Verify null byte injection
    - Check data type confusion
    - Test array vs single value

#### Special Characters

    - Test SQL meta-characters (', ", ;)
    - Verify HTML/XML tags (<, >, /)
    - Check JavaScript syntax ((), {}, [])
    - Test path traversal sequences (../)
    - Verify command injection chars (|, &, ||)
    - Check regex special chars (.\*, $, ^)
    - Test encoding variations (%00, \x00)
    - Verify Unicode characters (non-ASCII)
    - Check right-to-left override chars
    - Test delimiter variations (,, :, |)

### 🛠️ FUZZING METHODOLOGIES

#### Value Manipulation

    - Test boundary values
    - Verify out-of-range inputs
    - Check default value overrides
    - Test type juggling
    - Verify parameter deletion
    - Check duplicate parameters
    - Test parameter order variation
    - Verify case sensitivity
    - Check encoding/decoding
    - Test time-based values

#### Structural Testing

    - Test JSON/XML structure breaking
    - Verify deep nesting
    - Check malformed data structures
    - Test array index manipulation
    - Verify object key overrides
    - Check circular references
    - Test schema validation bypass
    - Verify omitted required fields
    - Check extra unexpected fields
    - Test content-type switching

### ⚙️ PROTOCOL-LEVEL FUZZING

    - Test HTTP method overriding
    - Verify header injection
    - Check chunked encoding
    - Test HTTP version manipulation
    - Verify keep-alive abuse
    - Check pipeline flooding
    - Test request smuggling
    - Verify parameter pollution
    - Check cookie jar overflow
    - Test session fixation

### 🛡️ DEFENSE BYPASS TECHNIQUES

#### Filter Evasion

    - Test mixed encoding
    - Verify case variation
    - Check null byte positioning
    - Test comment injection
    - Verify whitespace padding
    - Check alternative delimiters
    - Test nested expressions
    - Verify function chaining
    - Check variable variables
    - Test indirect evaluation

#### WAF Bypass

    - Test parameter fragmentation
    - Verify overlong UTF-8
    - Check multipart/form-data
    - Test JSON/XML encapsulation
    - Verify boundary scanning
    - Check protocol-level tricks
    - Test request splitting
    - Verify header smuggling
    - Check verb tampering
    - Test chunked encoding

### 📊 RESPONSE ANALYSIS

#### Error Detection

    - Monitor for 500 errors
    - Verify stack traces
    - Check debug information
    - Test timeout behavior
    - Verify memory leaks
    - Check error message changes
    - Test content-type switching
    - Verify encoding differences
    - Check header variations
    - Test redirect behavior

#### Behavioral Analysis

    - Monitor response times
    - Verify resource consumption
    - Check session changes
    - Test privilege escalation
    - Verify data leakage
    - Check caching behavior
    - Test CSRF token generation
    - Verify CORS changes
    - Check HSTS behavior
    -  Test cookie modifications

### 🔗 CHAINING OPPORTUNITIES

    - Combine with XSS
    - Chain with SQLi
    - Link to RCE
    - Combine with SSRF
    - Chain with XXE
    - Link to LFI/RFI
    - Combine with auth bypass
    - Chain to DoS
    - Link to info disclosure
    - Combine with business logic flaws

### 🧠 CONTEXT-AWARE FUZZING

#### Web Application

    - Test authentication params
    - Verify session handling
    - Check authorization params
    - Test user management
    - Verify password reset
    - Check CAPTCHA bypass
    - Test 2FA parameters
    - Verify OAuth flows
    - Check API keys
    - Test rate limiting

#### API Specific

    - Test pagination params
    - Verify sorting/filtering
    - Check field selection
    - Test batch operations
    - Verify webhook configs
    - Check callback URLs
    - Test version params
    - Verify deprecation headers
    - Check expansion params
    - Test embedding options

### ☁️ CLOUD-NATIVE FUZZING

    - Test AWS parameter store
    - Verify Azure app configs
    - Check GCP metadata
    - Test Kubernetes annotations
    - Verify Docker env vars
    - Check serverless triggers
    - Test IaC parameters
    - Verify CDN configs
    - Check WAF rulesets
    - Test API gateway params

### 📝 REPORTING & ANALYSIS

    - Document vulnerable params
    - Record payload triggers
    - Note error conditions
    - Document data exposure
    - Report performance impact
    - Note security controls bypassed
    - Document chain possibilities
    - Record bypass methods
    - Note detection signatures
    - Document remediation advice

### 🛠️ REMEDIATION STRATEGIES

    - Recommend input validation
    - Suggest allowlisting
    - Advocate for type checking
    - Propose parameter sanitization
    - Suggest schema validation
    - Recommend WAF tuning
    - Advocate for rate limiting
    - Propose monitoring rules
    - Suggest security headers
    - Recommend fuzz testing
