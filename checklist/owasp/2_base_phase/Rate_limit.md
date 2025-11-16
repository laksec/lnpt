# ULTIMATE RATE LIMIT PROBING CHECKLIST (v1.0)

### Comprehensive Methodology for Testing Rate Limiting Protections

### 🔍 DETECTION PHASE

    - Identify rate-limited endpoints (auth, API, forms)
    - Check for `X-RateLimit-*` headers in responses
    - Verify `Retry-After` header presence
    - Detect 429 (Too Many Requests) responses
    - Identify different rate limit tiers (IP, user, API key)

### ⏱ TIMING ANALYSIS

    - Test request timing windows (per second/minute/hour)
    - Verify sliding vs fixed window implementations
    - Check for burst allowance patterns
    - Test warm-up periods after limits
    - Verify limit reset mechanisms

### 🧩 BYPASS TECHNIQUES

    - Test IP rotation (proxies/VPN/Tor)
    - Verify User-Agent randomization
    - Check header permutations
    - Test parameter fuzzing variations
    - Verify cookie cycling
    - Check HTTP/2 multiplexing
    - Test HTTP vs HTTPS differences
    - Verify case-sensitive endpoint variations
    - Check path normalization bypasses (/v1/ vs /v1//)
    - Test API version switching

### 🛠 TOOLING

    - Use Burp Intruder with timing settings
    - Verify with OWASP ZAP Fuzzer
    - Test with custom Python scripts (aiohttp)
    - Check with vegeta load testing
    - Verify with JMeter distributed testing

### ⚠️ DANGEROUS SCENARIOS

    - Test auth endpoint brute forcing
    - Verify OTP bypass via limits
    - Check password reset flooding
    - Test gift card/balance checking
    - Verify promo code abuse
    - Check search/export function abuse
    - Test comment spam mechanisms
    - Verify contact form flooding
    - Check inventory reservation abuse
    - Test free tier API quota bypass

### 📊 METRICS

    - Record exact request thresholds
    - Document response variations
    - Track lockout durations
    - Note recovery mechanisms
    - Identify server-side vs client-side enforcement

### 🛡 DEFENSE EVASION

    - Test gradual ramp-up patterns
    - Verify randomized delay bypasses
    - Check JWT token rotation
    - Test OAuth refresh token abuse
    - Verify session cycling

### 📝 REPORTING

    - Document exact limit thresholds
    - Record bypass techniques
    - Note business impact scenarios
    - Provide reproduction steps
    - Include timing diagrams

### 🛠 REMEDIATION

    - Recommend multi-factor rate limiting
    - Suggest IP + behavior analysis
    - Advocate for exponential backoff
    - Propose account-level limits
    - Suggest CAPTCHA fallbacks
    - Recommend anomaly detection
    - Advocate for cost-based limits
    - Propose request fingerprinting
    - Suggest cloud WAF integration
    - Recommend regular load testing
