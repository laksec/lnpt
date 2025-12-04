### 2.7 HTTP Analysis
#### 2.7.1 HTTP Method Testing
    # 1. BASIC METHOD DISCOVERY
    # OPTIONS request (standard)
    curl -X OPTIONS https://target.com/api/ -i \
    -H "Origin: https://example.com" \
    -H "Access-Control-Request-Method: POST"

    # Batch testing with httpx
    httpx -l live_endpoints.txt \
    -methods \
    -timeout 5 \
    -threads 50 \
    -o allowed_methods.json \
    -json

    # 2. METHOD FUZZING
    # FFUF method testing
    ffuf -w /usr/share/seclists/Discovery/Web-Content/http-methods.txt:METHOD \
    -u https://target.com/FUZZ \
    -X METHOD \
    -t 100 \
    -mc 200,405 \
    -o methods_fuzz.json

    # WFuzz method testing
    wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/http-methods.txt \
    -X FUZZ \
    --hc 404 \
    https://target.com/api/

    # 3. COMPREHENSIVE TESTING
    # Nuclei verb tampering
    nuclei -l live_urls.txt \
    -t exposures/http-verb-tampering/ \
    -severity medium,high,critical \
    -o verb_tampering_results.json

    # Custom method testing
    for method in PUT DELETE PATCH TRACE; do
    echo -n "$method: "
    curl -X $method https://target.com/admin -I | grep "HTTP/"
    done > custom_methods.txt

    # 4. ADVANCED TECHNIQUES
    # Test with arbitrary methods
    ffuf -w /usr/share/seclists/Discovery/Web-Content/custom-methods.txt:METHOD \
    -u https://target.com/ \
    -X METHOD \
    -H "X-Custom-Header: test" \
    -o exotic_methods.json

    # Test method override headers
    curl -X POST https://target.com/api/ \
    -H "X-HTTP-Method-Override: DELETE" \
    -d "param=value"

    # ======================
    # PRO TIPS:
    # 1. Always test both standard and exotic methods
    # 2. Check for method overriding headers:
    #  - X-HTTP-Method
    #  - X-HTTP-Method-Override
    #  - X-Method-Override
    # 3. Test with/without authentication
    # 4. Look for inconsistent behavior
    # 5. Combine with CORS testing
    # ======================

    # RECOMMENDED WORDLISTS:
    #  - /usr/share/seclists/Discovery/Web-Content/http-methods.txt
    #  - /usr/share/seclists/Discovery/Web-Content/custom-methods.txt
    #  - Custom lists for target technology

    # EXAMPLE WORKFLOW:
    # 1. OPTIONS request to discover allowed methods
    # 2. httpx scan for quick verification
    # 3. FFUF/WFuzz for exhaustive testing
    # 4. Nuclei for vulnerability detection
    # 5. Manual verification of interesting findings

    # SAMPLE OUTPUT PROCESSING:
    jq -r '.results[] | select(.status == 200) | "\(.url) allows \(.method)"' methods_fuzz.json

#### 2.7.2 Response Header Analysis
    # 1. BASIC HEADER INSPECTION
    # Simple header fetch (HEAD)
    curl -I https://target.com \
    -H "User-Agent: SecurityScan/1.0" \
    -H "X-Forwarded-For: 127.0.0.1" \
    --connect-timeout 5

    # Full header inspection (GET)
    curl -s -D headers.txt https://target.com -o /dev/null

    # 2. COMPREHENSIVE HEADER ANALYSIS (httpx)
    httpx -l live_urls.txt \
    -title \
    -status-code \
    -tech-detect \
    -csp \
    -hsts \
    -server \
    -jarm \
    -json \
    -o headers_analysis.json

    # 3. SECURITY HEADER CHECKS
    # Check common security headers
    nuclei -l live_urls.txt \
    -t vulnerabilities/misconfiguration/security-misconfig/ \
    -o security_headers_report.txt

    # 4. SPECIALIZED CHECKS
    # Cookie analysis
    cat headers.txt | grep -i 'set-cookie' | analyze-cookies

    # CORS misconfiguration testing
    curl -H "Origin: https://evil.com" -I https://target.com/api

    # 5. BATCH PROCESSING
    # Analyze headers from multiple targets
    cat urls.txt | while read url; do
    echo -n "$url: "
    curl -s -I $url | grep -E 'Server|X-Powered-By'
    done > server_versions.txt

    # ======================
    # KEY HEADERS TO ANALYZE
    # ======================

    # 1. SERVER TECHNOLOGY
    # Server: Apache/2.4.41 (Ubuntu)
    # X-Powered-By: PHP/7.4.3
    # X-AspNet-Version: 4.0.30319

    # 2. SECURITY HEADERS
    # Content-Security-Policy: default-src 'self'
    # Strict-Transport-Security: max-age=31536000
    # X-Frame-Options: DENY
    # X-Content-Type-Options: nosniff
    # Referrer-Policy: no-referrer

    # 3. CORS CONFIGURATION
    # Access-Control-Allow-Origin: *
    # Access-Control-Allow-Credentials: true

    # 4. COOKIE SETTINGS
    # Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict

    # ======================
    # PRO TIPS:
    # 1. Always check for missing security headers
    # 2. Look for version disclosures (Server, X-Powered-By)
    # 3. Test with different HTTP methods (HEAD vs GET)
    # 4. Verify cookie flags (Secure, HttpOnly, SameSite)
    # 5. Check for CORS misconfigurations
    # 6. Compare headers across endpoints
    # ======================

    # EXAMPLE WORKFLOW:
    # 1. Fetch headers from all endpoints
    # 2. Identify technology versions
    # 3. Check security headers
    # 4. Test for CORS issues
    # 5. Verify cookie settings
    # 6. Report findings

    # RECOMMENDED TOOLS:
    #  - curl (manual inspection)
    #  - httpx (batch analysis)
    #  - nuclei (vulnerability scanning)
    #  - analyze-cookies (cookie testing)
    #  - test-cors.sh (CORS testing)

    # SAMPLE ANALYZE-COOKIES SCRIPT:
    """
    #!/bin/bash
    grep -i 'set-cookie' | while read line; do
    echo -n "Cookie: "
    echo $line | grep -q 'Secure' || echo -n "Missing Secure! "
    echo $line | grep -q 'HttpOnly' || echo -n "Missing HttpOnly! "
    echo $line | grep -q 'SameSite' || echo "Missing SameSite!"
    done
    """

    # Test with different user agents
    # Check header consistency across environments
    # Monitor for header changes over time
    # Test with various HTTP versions (1.0, 1.1, 2)
    # Analyze JARM fingerprints for server identification

    [✓] Content-Security-Policy
    [✓] Strict-Transport-Security 
    [✓] X-Frame-Options
    [✓] X-Content-Type-Options
    [✓] Referrer-Policy
    [✓] Permissions-Policy
    [✓] Cross-Origin-Opener-Policy

#### 2.7.3 Status Code & Content Analysis
    # 1. INTERESTING STATUS CODE DISCOVERY (FFUF)
    # Comprehensive status code scan
    ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -u https://target.com/FUZZ \
    -mc 200,201,202,301,302,307,401,403,404,405,500,501,502 \
    -t 150 \
    -o ffuf_interesting_codes.json \
    -of json

    # 2. STATUS CODE + CONTENT ANALYSIS (HTTPX)
    # Detailed response analysis
    httpx -l live_urls.txt \
    -status-code \
    -content-length \
    -title \
    -location \
    -content-type \
    -web-server \
    -tech-detect \
    -json \
    -o detailed_response_analysis.json

    # 3. SPECIALIZED STATUS CODE CHECKS
    # 401/403 Bypass Testing
    ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -u https://target.com/restricted/FUZZ=bypass \
    -mc 200 \
    -t 100

    # 302 Redirect Analysis
    httpx -l redirect_urls.txt \
    -location \
    -match-string "admin" \
    -o suspicious_redirects.txt

    # 4. CONTENT LENGTH ANALYSIS
    # Find similar-length responses
    cat status_length.txt | awk '{print $2,$1}' | sort -n | uniq -d -f1

    # 5. ADVANCED TECHNIQUES
    # Header-based status code differences
    curl -I https://target.com/admin -H "X-Forwarded-For: 127.0.0.1" | grep HTTP

    # Method-based status code differences
    for method in GET POST PUT DELETE; do
    echo -n "$method: "
    curl -X $method -s -o /dev/null -w "%{http_code}" https://target.com/api/
    done

    # ======================
    # INTERESTING STATUS CODES
    # ======================
    # 200 OK - Standard success
    # 201 Created - Resource creation
    # 301/302 Redirect - Check location header
    # 307 Temporary Redirect - Often used for auth
    # 401 Unauthorized - Authentication required
    # 403 Forbidden - Potential bypass opportunities
    # 405 Method Not Allowed - Try other methods
    # 500 Internal Error - Potential info leaks
    # 502 Bad Gateway - Proxy issues

    # ======================
    # PRO TIPS:
    # 1. Always check for:
    #  - Inconsistent status codes across similar endpoints
    #  - Status code differences with/without authentication
    #  - Header-based status code changes
    # 2. Compare content lengths for:
    #  - Error messages vs normal responses
    #  - Authenticated vs unauthenticated views
    # 3. Look for:
    #  - Stack traces in 500 errors
    #  - Debug information in 400-series errors
    #  - Redirects to unexpected locations
    # 4. Test with:
    #  - Different HTTP methods
    #  - Various headers (X-Forwarded-For, Referer)
    #  - Modified cookies
    # ======================

    # EXAMPLE WORKFLOW:
    # 1. Scan for interesting status codes
    # 2. Analyze response headers and content
    # 3. Test for bypass opportunities
    # 4. Check for information leaks
    # 5. Document findings

    # RECOMMENDED TOOLS:
    #  - ffuf (status code fuzzing)
    #  - httpx (detailed response analysis)
    #  - curl (manual testing)
    #  - jq (JSON processing)
    #  - awk/sort (content length analysis)

    # SAMPLE JSON PROCESSING:
    jq -r '.results[] | select(.status == 403) | "\(.url) - \(.content_length)"' ffuf_results.json

    # Advanced Techniques:
    # Use -match-string in httpx to find specific error messages
    # Combine with nuclei templates for vulnerability detection
    # Test with -H "X-Original-URL: /admin" header for 403 bypass
    # Check for -H "X-Rewrite-URL: /admin" variations
    # Monitor for status code changes over time

    # Security Considerations:
    # 500 errors may contain stack traces
    # 400 errors might reveal input validation rules
    # 302 redirects could expose internal endpoints
    # 401 responses might differ between valid/invalid auth
    # 403 responses may vary based on headers

#### 2.7.4 Content Similarity Analysis
    # 1. SETUP (Install required tools)
    pip install ssdeep tlsh similarityhash

    # 2. BASELINE CREATION
    # Get baseline 404 response
    curl -s https://target.com/nonexistent_page > baseline_404.html

    # Generate similarity hashes
    ssdeep -b baseline_404.html > baseline_404.ssdeep
    tlsh -f baseline_404.html > baseline_404.tlsh
    simhash baseline_404.html > baseline_404.simhash

    # 3. FUZZING WITH HASH CAPTURE
    # Run ffuf with full response capture
    ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -u https://target.com/FUZZ \
    -t 150 \
    -of json \
    -o ffuf_results.json \
    -sr baseline_404.ssdeep \
    -recursion

    # 4. AUTOMATED ANALYSIS SCRIPT (process_ffuf_output.py)
    """
    #!/usr/bin/env python3
    import ssdeep, json, sys

    def analyze_results(ffuf_file, baseline_hash):
        with open(ffuf_file) as f:
            data = json.load(f)
        
        for result in data['results']:
            if result['content']:
                current_hash = ssdeep.hash(result['content'])
                similarity = ssdeep.compare(baseline_hash, current_hash)
                if similarity < 85:  # Adjust threshold as needed
                    print(f"{result['url']} - Similarity: {similarity}%")

    if __name__ == "__main__":
        if len(sys.argv) != 3:
            print("Usage: process_ffuf_output.py ffuf_results.json baseline_hash.txt")
            sys.exit(1)
        
        with open(sys.argv[2]) as f:
            baseline_hash = f.read().strip()
        
        analyze_results(sys.argv[1], baseline_hash)
    """

    # 5. ADVANCED TECHNIQUES
    # Multi-hash comparison
    compare_hashes() {
        for file in responses/*; do
            ssdeep -b -m baseline_404.ssdeep "$file" | grep -v "matches"
            tlsh -c baseline_404.tlsh "$file"
        done > similarity_results.txt
    }

    # Cluster similar responses
    simhash-cluster responses/* -t 0.9 -o clusters.txt

    # ======================
    # PRO TIPS:
    # 1. Use multiple hashing algorithms for better accuracy:
    #  - ssdeep (fuzzy hashing)
    #  - tlsh (trend micro locality-sensitive)
    #  - simhash (Google's approach)
    # 2. Adjust similarity thresholds based on site:
    #  - 90-100%: Likely identical
    #  - 70-89%: Similar template
    #  - <70%: Different content
    # 3. Store raw responses for manual review
    # 4. Compare with different baseline pages:
    #  - 404 pages
    #  - Login redirects
    #  - Empty responses
    # 5. Combine with status code analysis
    # ======================

    # EXAMPLE WORKFLOW:
    # 1. Establish baseline hashes
    # 2. Run ffuf with response capture
    # 3. Analyze similarity scores
    # 4. Manually review interesting responses
    # 5. Document unique pages

    # RECOMMENDED TOOLS:
    #  - ssdeep (fuzzy hashing)
    #  - tlsh (locality-sensitive)
    #  - simhash (bitwise comparison)
    #  - jq (JSON processing)
    #  - curl (manual verification)

    # SAMPLE ANALYSIS COMMANDS:
    # Find similar responses:
    jq -r '.results[] | select(.similarity < 85) | "\(.url) - \(.status) - \(.content_length)"' ffuf_results.json

    # Find unique responses:
    jq -r '.results[] | select(.similarity < 60) | url' ffuf_results.json | sort -u

    # Advanced Techniques:
    # Create baseline hashes for different error types
    # Monitor similarity changes over time
    # Combine with screenshot analysis
    # Build custom hash databases for target
    # Use machine learning for anomaly detection
    # Security Considerations:
    # Low similarity scores may indicate:

    # Hidden pages
    # Debug information
    # Error messages
    # Authentication differences
    # Parameter-dependent content

#### 2.7.5 Error Message Extraction & Analysis
# ======================
# ULTIMATE ERROR MESSAGE DETECTION CHEATSHEET
# ======================

# 1. COMPREHENSIVE ERROR DISCOVERY
# Crawl and find error pages
katana -u https://target.com \
  -d 3 \
  -jc \ # JavaScript crawling
  -kf \ # Known files
  -o katana_crawl.txt

# Extract error pages
cat katana_crawl.txt | httpx \
  -status-code 400,500 \
  -content-length \
  -title \
  -o error_pages.txt

# 2. ERROR MESSAGE ANALYSIS
# Search for common error patterns
cat error_pages.txt | while read url; do
  echo "=== $url ==="
  curl -s "$url" | grep -E -i \
    'exception|error|warning|traceback|stack trace|sqlstate|ora-|path|microsoft ole db|at line|syntax error|uncaught'
done > detailed_errors.txt

# 3. NUCLEI TEMPLATES
# Scan for stack traces and debug info
nuclei -l live_urls.txt \
  -t exposures/stacktrace-disclosure/ \
  -severity medium,high,critical \
  -o nuclei_errors.json \
  -json

# 4. ADVANCED TECHNIQUES
# Find file paths in errors
grep -E -i '/[a-z0-9_/-]+(/[a-z0-9_/-]+)+\.(php|asp|aspx|jsp)' detailed_errors.txt

# Find database errors
grep -E -i '(sqlstate|ora-|mysql_error|postgresql|mssql)' detailed_errors.txt

# Find API keys/secrets in errors
grep -E -i '(api[_-]?key|secret|token|password)' detailed_errors.txt

# ======================
# COMMON ERROR PATTERNS
# ======================
# Java: Exception in thread "main" java.lang.NullPointerException
# PHP: Fatal error: Uncaught Error: Call to undefined function
# Python: Traceback (most recent call last):
# NET: System.NullReferenceException: Object reference not set
# Database: SQLSTATE[42S22]: Column not found
# File paths: /var/www/html/config.php on line 42
# API keys: "api_key": "12345-abcdef"

# ======================
# PRO TIPS:
# 1. Look for different error types:
#  - 500 Internal Server Error
#  - 400 Bad Request
#  - 403 Forbidden (sometimes leaks info)
# 2. Check with different input:
#  - Malformed parameters
#  - Special characters
#  - Long strings
# 3. Compare authenticated vs unauthenticated
# 4. Monitor for intermittent errors
# 5. Archive findings for historical comparison
# ======================

# EXAMPLE WORKFLOW:
# 1. Crawl site to discover endpoints
# 2. Identify error pages (400/500 status)
# 3. Extract error messages
# 4. Analyze for sensitive info
# 5. Document findings

# RECOMMENDED TOOLS:
#  - katana (crawling)
#  - httpx (error page detection)
#  - nuclei (vulnerability scanning)
#  - curl (manual inspection)
#  - jq (JSON processing)

# SAMPLE ERROR ANALYSIS SCRIPT:
"""
#!/bin/bash
# error_analyzer.sh
input_file=$1
output_file="error_report_$(date +%Y%m%d).txt"

echo "Error Analysis Report - $(date)" > $output_file
echo "=================================" >> $output_file

patterns=(
  "Exception"
  "Error"
  "Warning"
  "Traceback"
  "SQLSTATE"
  "ORA-"
  "path"
  "Microsoft OLE DB"
  "at line"
  "api.?key"
  "secret"
  "token"
)

for url in $(cat $input_file); do
  echo -n "Checking $url... "
  response=$(curl -s "$url")
  
  for pattern in "${patterns[@]}"; do
    if echo "$response" | grep -qE -i "$pattern"; then
      echo "$url: Found $pattern" >> $output_file
      echo "$pattern "
    fi
  done
  echo "done"
done
"""

    # Advanced Techniques:
    # - Use -H "Accept: application/json" to trigger API errors
    # - Test with malformed UTF-8 sequences
    # - Try parameter pollution to trigger edge cases
    # - Compare error responses across environments
    # - Monitor for intermittent errors with scheduled scans
    
    # Security Considerations:
    # Error messages may reveal:
    #  - System architecture
    #  - Database credentials
    #  - File system paths
    #  - API keys
    #  - Framework versions
    #  - Business logic