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
    #    - X-HTTP-Method
    #    - X-HTTP-Method-Override
    #    - X-Method-Override
    # 3. Test with/without authentication
    # 4. Look for inconsistent behavior
    # 5. Combine with CORS testing
    # ======================

    # RECOMMENDED WORDLISTS:
    # - /usr/share/seclists/Discovery/Web-Content/http-methods.txt
    # - /usr/share/seclists/Discovery/Web-Content/custom-methods.txt
    # - Custom lists for target technology

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
    # - curl (manual inspection)
    # - httpx (batch analysis)
    # - nuclei (vulnerability scanning)
    # - analyze-cookies (cookie testing)
    # - test-cors.sh (CORS testing)

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

    :- Test with different user agents
    :- Check header consistency across environments
    :- Monitor for header changes over time
    :- Test with various HTTP versions (1.0, 1.1, 2)
    :- Analyze JARM fingerprints for server identification

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
    #    - Inconsistent status codes across similar endpoints
    #    - Status code differences with/without authentication
    #    - Header-based status code changes
    # 2. Compare content lengths for:
    #    - Error messages vs normal responses
    #    - Authenticated vs unauthenticated views
    # 3. Look for:
    #    - Stack traces in 500 errors
    #    - Debug information in 400-series errors
    #    - Redirects to unexpected locations
    # 4. Test with:
    #    - Different HTTP methods
    #    - Various headers (X-Forwarded-For, Referer)
    #    - Modified cookies
    # ======================

    # EXAMPLE WORKFLOW:
    # 1. Scan for interesting status codes
    # 2. Analyze response headers and content
    # 3. Test for bypass opportunities
    # 4. Check for information leaks
    # 5. Document findings

    # RECOMMENDED TOOLS:
    # - ffuf (status code fuzzing)
    # - httpx (detailed response analysis)
    # - curl (manual testing)
    # - jq (JSON processing)
    # - awk/sort (content length analysis)

    # SAMPLE JSON PROCESSING:
    jq -r '.results[] | select(.status == 403) | "\(.url) - \(.content_length)"' ffuf_results.json

    ::- Advanced Techniques:
    :- Use -match-string in httpx to find specific error messages
    :- Combine with nuclei templates for vulnerability detection
    :- Test with -H "X-Original-URL: /admin" header for 403 bypass
    :- Check for -H "X-Rewrite-URL: /admin" variations
    :- Monitor for status code changes over time

    ::- Security Considerations:
    :- 500 errors may contain stack traces
    :- 400 errors might reveal input validation rules
    :- 302 redirects could expose internal endpoints
    :- 401 responses might differ between valid/invalid auth
    :- 403 responses may vary based on headers

#### 2.7.4 Content Similarity Analysis
    :- Requires tools that can calculate perceptual hashes or similarity scores

    pip install ssdeep tlsh
    
    :- Conceptual Workflow:
    :- 1. Get response body for a known non-existent page: curl https://target.com/nonexistent_page > baseline_404.html
    :- 2. Calculate hash: ssdeep baseline_404.html > baseline_hash.txt
    :- 3. During fuzzing, hash responses and compare:
    
    ffuf -w wordlist.txt -u https://target.com/FUZZ -of json -o ffuf_results.json
    python process_ffuf_output.py ffuf_results.json baseline_hash.txt 
    :- Custom script to hash results and compare

#### 2.7.5 Error Message Extraction & Analysis
    :- Looking for stack traces, database errors, file paths in error messages
    
    :- Combine crawling/fuzzing with grep:

    katana -u https://target.com -d 3 -o crawl.txt && cat crawl.txt | httpx -silent -status-code 500 -o error_pages.txt

    cat error_pages.txt | xargs -I{} curl -s {} | grep -E 'Exception|Error|Warning|Traceback|SQLSTATE| ORA-|path|Microsoft OLE DB|at line' > errors_found.txt
    
    nuclei -l live_urls.txt -t exposures/stacktrace-disclosure.yaml -o nuclei_stacktraces.txt 
    :- Use Nuclei templates for error detection