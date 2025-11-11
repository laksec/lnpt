# ULTIMATE CACHE POISONING TESTING CHECKLIST (v1.0)

### Comprehensive Methodology for Web Cache Deception and Poisoning Attacks

### 🔍 CACHE DETECTION

    - Identify caching mechanisms (CDN, reverse proxies, etc.)
    - Check for Cache-Control headers (public, private, no-store)
    - Verify presence of Vary header
    - Detect Age and X-Cache headers
    - Test for keyed/non-keyed cache parameters

### 🧪 BASIC TESTING

    - Test unkeyed input injection (headers, cookies)
    - Verify cacheable responses for sensitive data
    - Check for GET parameter caching
    - Test HEAD method for cache poisoning
    - Verify cache duration/TTL settings

### ⚔️ REQUEST SMUGGLING VECTORS

    - Test HTTP/1.1 vs HTTP/2 cache poisoning
    - Verify chunked encoding attacks
    - Check CL.TE/TE.CL smuggling variants
    - Test header injection via newlines
    - Verify whitespace smuggling techniques

### 🌐 DOMAIN-WIDE POISONING

    - Test Host header injection
    - Verify X-Forwarded-Host manipulation
    - Check for open redirect caching
    - Test subdomain takeover -> cache poisoning
    - Verify DNS rebinding attacks

### 📦 HEADER INJECTION

    - Test X-Forwarded-For poisoning
    - Verify User-Agent based caching
    - Check Accept-Language manipulation
    - Test Referer header poisoning
    - Verify Cookie header injection

### 🎯 RESPONSE MANIPULATION

    - Test stored XSS via cached responses
    - Verify JavaScript resource poisoning
    - Check CSS injection via cache
    - Test HTML import poisoning
    - Verify JSONP callback poisoning

### 🛠️ TOOLS & TECHNIQUES

    - Use Param Miner (Burp extension)
    - Test with Web Cache Vulnerability Scanner
    - Verify with curl -H attacks
    - Check using browser dev tools
    - Test with automated cache poisoning tools

### ⚠️ DANGEROUS SCENARIOS

    - Test authentication bypass via caching
    - Verify session fixation via cache
    - Check JWT token leakage
    - Test OAuth flow poisoning
    - Verify API response poisoning

### 📝 REPORTING

    - Document cacheable sensitive endpoints
    - Record unkeyed input vectors
    - Note cache TTL durations
    - Document poisoning impact scenarios
    - Provide reproducible steps
    - Include HTTP request/response samples
    - Note CDN/provider specifics
    - Document cache hierarchy findings
    - Report cache purge capabilities
    - Provide remediation guidance

### 🛠️ REMEDIATION

    - Recommend proper Cache-Control headers
    - Suggest Vary header implementation
    - Advocate for sensitive data no-store
    - Propose cache key normalization
    - Suggest request validation
    - Recommend header sanitization
    - Advocate for cache partitioning
    - Propose regular cache purges
    - Suggest cache poisoning monitoring
    - Recommend security headers

### 🔮 ADVANCED PROTECTIONS

    - Test cache busting techniques
    - Verify cache fingerprinting
    - Check for cache key flaws
    - Test cache timing attacks
    - Verify cache invalidation methods
