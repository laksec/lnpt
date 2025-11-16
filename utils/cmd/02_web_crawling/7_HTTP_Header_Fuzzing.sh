### 2.10 HTTP Header Fuzzing
     # 1. HEADER INJECTION TESTING
     # X-Forwarded-Host fuzzing (cache poisoning)
     ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u https://target.com \
     -H "X-Forwarded-Host: FUZZ" \
     -fs $(curl -s -o /dev/null -w "%{size_download}" https://target.com) \
     -o xfh_fuzz.json \
     -of json

     # 2. HEADER NAME FUZZING
     # Discover custom/special headers
     ffuf -w /usr/share/seclists/Discovery/Web-Content/HTTP-Headers.txt:HEADER \
     -u https://target.com/api \
     -H "HEADER: vulnerable" \
     -mc 200,302,400 \
     -t 100 \
     -o header_fuzz.json

     # 3. HTTP METHOD TESTING
     # Non-standard method fuzzing
     ffuf -w /usr/share/seclists/Discovery/Web-Content/http-methods.txt:METHOD \
     -u https://target.com/admin \
     -X METHOD \
     -mc 200,403 \
     -fc 405,404 \
     -o method_fuzz.json

     # 4. CACHE POISONING CHECKS
     # Multi-header injection
     curl -v https://target.com \
     -H "X-Forwarded-Host: evil.com" \
     -H "X-Forwarded-Scheme: http" \
     -H "X-Forwarded-Port: 80"

     # 5. ADVANCED TECHNIQUES
     # Request smuggling probe
     curl https://target.com \
     -H "Transfer-Encoding: chunked" \
     -H "Content-Length: 3" \
     -X POST \
     -d "1\r\nA\r\n0\r\n\r\n"

     # CRLF injection test
     ffuf -w /usr/share/seclists/Fuzzing/CRLF-Injection.txt:INJECT \
     -u https://target.com \
     -H "User-Agent: Mozilla/5.0\r\nINJECT" \
     -o crlf_test.json

     # ======================
     # PRO TIPS:
     # 1. Always test with:
     #  - Multiple header variations
     #  - Different HTTP versions
     #  - Various target endpoints
     # 2. Look for:
     #  - Reflection in responses
     #  - Header parsing differences
     #  - Cache control behaviors
     # 3. Special headers to test:
     #  - X-Forwarded-*
     #  - X-Rewrite-URL
     #  - X-Original-URL
     #  - X-Custom-*
     # 4. Monitor for:
     #  - Response time differences
     #  - Header order effects
     #  - Case sensitivity
     # ======================

     # EXAMPLE WORKFLOW:
     # 1. Identify target endpoints
     # 2. Establish baseline responses
     # 3. Fuzz standard headers
     # 4. Test custom headers
     # 5. Verify potential findings

     # RECOMMENDED WORDLISTS:
     #  - /usr/share/seclists/Discovery/Web-Content/HTTP-Headers.txt
     #  - /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
     #  - /usr/share/seclists/Fuzzing/CRLF-Injection.txt
     #  - Custom lists based on target tech

     # SAMPLE HEADER ANALYSIS SCRIPT:
     """
     #!/bin/bash
     # header_analyzer.sh
     url=$1
     headers_file=$2

     echo "Header Analysis Report - $(date)"
     echo "==============================="

     while read header; do
     echo -n "Testing $header: "
     response=$(curl -s -I -H "$header: TEST" $url)
     if [[ "$response" != *"400"* && "$response" != *"403"* ]]; then
     echo "POSSIBLE INJECTION"
     echo "$response" | grep -E "^HTTP|^Location|^Set-Cookie"
     else
     echo "filtered"
     fi
     done < $headers_file
     """

     # Advanced Techniques:
     #  - Test with -H "X-Original-URL: /admin" for path override
     #  - Try -H "X-Rewrite-URL: /admin" variations
     #  - Check for header order dependencies
     #  - Test with duplicate headers
     #  - Monitor for cache timestamp changes

     # Security Considerations:
     # Header fuzzing may reveal:
     #  - Cache poisoning opportunities
     #  - Access control bypasses
     #  - Server software leaks
     #  - Injection vulnerabilities
     #  - Business logic flaws
