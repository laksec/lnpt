```
# HTTP ANALYSIS - COMMAND LINE TOOLS (FOR FILES)

## 1. HTTP HEADER ANALYSIS

# Extract headers from URLs in file
while read url; do
    echo "=== $url ==="
    curl -I -s "$url" | head -20
    echo ""
done < urls.txt > http_headers.txt

# Extract specific headers
while read url; do
    echo -n "$url: "
    curl -I -s "$url" | grep -i "server:\|x-powered-by:\|x-aspnet-version:" | head -3
done < urls.txt > specific_headers.txt


## 2. HTTP RESPONSE ANALYSIS

# Analyze HTTP responses
httpx -l urls.txt -title -status-code -content-length -web-server -tech-detect -o http_analysis.txt

# Detailed response analysis
httpx -l urls.txt -json -o http_analysis.json


## 3. SECURITY HEADER ANALYSIS

# Check security headers
while read url; do
    echo "=== $url ==="
    curl -I -s "$url" | grep -i "content-security-policy\|x-frame-options\|x-content-type-options\|x-xss-protection\|strict-transport-security"
    echo ""
done < urls.txt > security_headers.txt

# Missing security headers check
while read url; do
    echo -n "$url: "
    headers=$(curl -I -s "$url")
    missing=""
    for header in "Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options" "Strict-Transport-Security"; do
        echo "$headers" | grep -qi "$header" || missing="$missing $header"
    done
    [ -n "$missing" ] && echo "Missing:$missing" || echo "All good"
done < urls.txt > missing_security_headers.txt


## 4. HTTP METHOD TESTING

# Test HTTP methods
while read url; do
    echo "=== $url ==="
    for method in GET POST PUT DELETE HEAD OPTIONS PATCH TRACE; do
        echo -n "$method: "
        curl -X $method -s -o /dev/null -w "%{http_code}" "$url"
        echo ""
    done
    echo ""
done < urls.txt > http_methods.txt


## 5. REDIRECTION ANALYSIS

# Analyze redirects
while read url; do
    echo -n "$url -> "
    curl -s -L -I -o /dev/null -w "%{url_effective} (%{http_code})" "$url"
    echo ""
done < urls.txt > redirect_analysis.txt

# Follow redirect chain
while read url; do
    echo "=== Redirect chain for $url ==="
    curl -s -L -I "$url" 2>&1 | grep -i "http\|location:" | head -10
    echo ""
done < urls.txt > redirect_chains.txt


## 6. CORS ANALYSIS

# Check CORS headers
while read url; do
    echo "=== $url ==="
    curl -I -s "$url" -H "Origin: https://evil.com" | grep -i "access-control"
    echo ""
done < urls.txt > cors_headers.txt


## 7. COOKIE ANALYSIS

# Analyze cookies
while read url; do
    echo "=== $url ==="
    curl -I -s "$url" | grep -i "set-cookie" | head -5
    echo ""
done < urls.txt > cookie_analysis.txt

# Check secure cookie flags
while read url; do
    echo -n "$url: "
    cookies=$(curl -I -s "$url" | grep -i "set-cookie")
    if echo "$cookies" | grep -q "Secure\|HttpOnly"; then
        echo "$cookies" | head -1
    else
        echo "No secure cookies"
    fi
done < urls.txt > cookie_security.txt


## 8. HTTP VERSION TESTING

# Test HTTP versions
while read url; do
    echo "=== $url ==="
    for version in 1.0 1.1 2 3; do
        echo -n "HTTP/$version: "
        curl --http$version -s -o /dev/null -w "%{http_code} %{time_total}s" "$url" 2>/dev/null || echo "Not supported"
        echo ""
    done
    echo ""
done < urls.txt > http_versions.txt


## 9. RESPONSE TIME ANALYSIS

# Measure response times
while read url; do
    echo -n "$url: "
    curl -s -o /dev/null -w "Time: %{time_total}s Size: %{size_download} bytes Code: %{http_code}" "$url"
    echo ""
done < urls.txt > response_times.txt


## 10. CONTENT TYPE ANALYSIS

# Analyze content types
while read url; do
    echo -n "$url: "
    curl -I -s "$url" | grep -i "content-type:" | head -1
done < urls.txt > content_types.txt


## 11. COMPRESSION ANALYSIS

# Check compression
while read url; do
    echo "=== $url ==="
    echo -n "No compression: "
    curl -s -o /dev/null -w "%{size_download}" "$url"
    echo " bytes"
    
    echo -n "With gzip: "
    curl -H "Accept-Encoding: gzip" -s -o /dev/null -w "%{size_download}" "$url"
    echo " bytes"
    echo ""
done < urls.txt > compression_analysis.txt


## 12. CACHE HEADER ANALYSIS

# Analyze cache headers
while read url; do
    echo "=== $url ==="
    curl -I -s "$url" | grep -i "cache-control\|expires\|etag\|last-modified"
    echo ""
done < urls.txt > cache_headers.txt


## 13. HSTS ANALYSIS

# Check HSTS
while read url; do
    echo -n "$url: "
    curl -I -s "$url" | grep -i "strict-transport-security" || echo "No HSTS"
done < urls.txt > hsts_check.txt


## 14. OPEN REDIRECT TESTING

# Test for open redirects
while read url; do
    for param in url redirect r uri u link next; do
        test_url="${url}?${param}=https://evil.com"
        location=$(curl -s -I "$test_url" | grep -i "location:" | head -1)
        if echo "$location" | grep -qi "evil.com"; then
            echo "$url: Possible open redirect via $param"
        fi
    done
done < urls.txt > open_redirect_test.txt


## 15. HTTP REQUEST SMUGGLING DETECTION

# Basic smuggling detection
while read url; do
    echo "=== Testing $url ==="
    # Test CL.TE
    curl -X POST -H "Transfer-Encoding: chunked" -H "Content-Length: 4" -d "1\r\nA\r\n0\r\n\r\n" "$url" -v 2>&1 | grep -i "smuggle\|timeout\|error"
    echo ""
done < urls.txt > smuggling_test.txt


## 16. HTTP PARAMETER POLLUTION

# Test parameter pollution
while read url; do
    if echo "$url" | grep -q "?"; then
        polluted="${url}&test=1&test=2"
        echo "Testing: $polluted"
        curl -s "$polluted" | grep -q "test=1.*test=2" && echo "Possible parameter pollution"
    fi
done < urls.txt > parameter_pollution.txt


## 17. NUCLEI HTTP TEMPLATES

# Scan with HTTP-related nuclei templates
nuclei -l urls.txt -t ~/nuclei-templates/http/ -o nuclei_http_scan.txt

# Specific security headers check
nuclei -l urls.txt -t ~/nuclei-templates/http/missing-security-headers.yaml -o nuclei_missing_headers.txt


## 18. WEB CACHE POISONING TESTS

# Test cache poisoning vectors
while read url; do
    echo "=== $url ==="
    # Test X-Forwarded-Host
    curl -H "X-Forwarded-Host: evil.com" -s -I "$url" | grep -i "location\|host"
    echo ""
done < urls.txt > cache_poison_test.txt


## 19. HTTP DESYNC ATTACK VECTORS

# Test desync vectors
while read url; do
    echo "Testing: $url"
    curl -H "Transfer-Encoding: chunked" -H "Content-Length: 0" -X POST "$url" -v 2>&1 | grep -i "timeout\|error\|desync"
done < urls.txt > desync_test.txt


## 20. OUTPUT PROCESSING

# Create HTTP analysis report
echo "HTTP Analysis Report" > http_report.txt
echo "===================" >> http_report.txt
echo "" >> http_report.txt
echo "Total URLs analyzed: $(wc -l < urls.txt)" >> http_report.txt
echo "" >> http_report.txt

# Summary statistics
echo "HTTP Status Codes:" >> http_report.txt
httpx -l urls.txt -status-code -silent | awk '{print $2}' | sort | uniq -c | sort -rn >> http_report.txt
echo "" >> http_report.txt

echo "Web Servers:" >> http_report.txt
httpx -l urls.txt -web-server -silent | awk '{print $2}' | sort | uniq -c | sort -rn >> http_report.txt
echo "" >> http_report.txt


## 21. COMBINATION PIPELINES

# Header extraction → Security analysis pipeline
while read url; do
    headers=$(curl -I -s "$url")
    echo "$url" >> headers_analysis.txt
    echo "$headers" >> headers_analysis.txt
    
    # Check for specific issues
    if ! echo "$headers" | grep -qi "x-frame-options"; then
        echo "$url: Missing X-Frame-Options" >> missing_headers.txt
    fi
done < urls.txt


## 22. BATCH PROCESSING

# Batch HTTP analysis
split -l 50 urls.txt batch_
for batch in batch_*; do
    httpx -l "$batch" -title -status-code -web-server -o "analysis_$batch.txt"
done
cat analysis_batch_*.txt > combined_analysis.txt


## 23. VALIDATION

# Validate HTTP responses
cat urls.txt | httpx -silent -status-code -title -content-length -o validated_responses.txt

# Filter interesting responses
cat validated_responses.txt | grep -E " 200 .*admin\| 200 .*login\| 403\| 401" > interesting_responses.txt


## 24. MONITORING FOR CHANGES

# Diff-based monitoring
old="old_responses.txt"; new="new_responses.txt"

# Get current responses
httpx -l urls.txt -title -status-code -silent > $new

# Find changes
if [ -f "$old" ]; then
    echo "=== Changed Responses ===" > http_changes.txt
    diff "$old" "$new" | grep "^[<>]" >> http_changes.txt
fi

# Update tracking
mv "$new" "$old"


## 25. SPECIALIZED ANALYSIS

# Analyze AJAX endpoints
while read url; do
    echo "=== $url ==="
    curl -s "$url" | grep -o "['\"]url['\"]:['\"][^'\"]*['\"]" | cut -d\" -f4 | head -5
done < urls.txt > ajax_endpoints.txt


## 26. QUICK CHECKS

# Quick header check
while read url; do
    echo -n "$url: "
    server=$(curl -I -s "$url" | grep -i "server:" | head -1 | cut -d: -f2 | xargs)
    [ -n "$server" ] && echo "$server" || echo "No server header"
done < urls.txt | head -20 > quick_server_check.txt

# Check for admin panels
cat validated_responses.txt | grep -i "admin\|login\|dashboard" | head -10


## 27. PERFORMANCE ANALYSIS

# Load time analysis
echo "URL,Load Time(ms),Size(bytes),Status" > performance.csv
while read url; do
    load_time=$(curl -s -o /dev/null -w "%{time_total}" "$url" | awk '{print $1*1000}')
    size=$(curl -s -o /dev/null -w "%{size_download}" "$url")
    status=$(curl -s -o /dev/null -w "%{http_code}" "$url")
    echo "$url,$load_time,$size,$status" >> performance.csv
done < urls.txt


## 28. INTEGRATION WITH OTHER TOOLS

# HTTP analysis → Nuclei scanning
cat urls.txt | httpx -silent | nuclei -t ~/nuclei-templates/ -o http_nuclei_scan.txt

# Header analysis → WAF detection
while read url; do
    headers=$(curl -I -s "$url")
    echo "$headers" | grep -qi "cloudflare\|akamai\|sucuri" && echo "$url: WAF detected"
done < urls.txt > waf_detection.txt


## 29. OUTPUT FORMATTING

# JSON formatted analysis
httpx -l urls.txt -json -o http_analysis_full.json

# Markdown report
echo "# HTTP Security Analysis" > security_report.md
echo "" >> security_report.md
echo "## Missing Security Headers" >> security_report.md
echo "" >> security_report.md
cat missing_security_headers.txt | while read line; do
    echo "- $line" >> security_report.md
done
echo "" >> security_report.md

echo "## Server Technologies" >> security_report.md
echo "" >> security_report.md
httpx -l urls.txt -web-server -silent | awk '{print $2}' | sort | uniq -c | sort -rn | while read count server; do
    echo "- $server: $count" >> security_report.md
done
```