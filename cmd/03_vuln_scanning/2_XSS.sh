### 3.2 XSS Testing
    # 1. DALFOX (Modern XSS Scanner)
    # Basic reflected XSS test
    dalfox url 'https://target.com/search?q=FUZZ' \
    -b your.burpcollaborator.net \
    -o dalfox_results.json \
    -w /usr/share/seclists/Fuzzing/XSS/XSS-Payloads-L5.txt

    # Comprehensive DOM XSS scan
    dalfox url 'https://target.com/app' \
    --mining-dom \
    --deep-domxss \
    --waf-evasion \
    --skip-bav \
    -o dom_xss.json

    # 2. XSSTRIKE (Advanced Fuzzing)
    # Crawl and test with polyglots
    xsstrike -u "https://target.com" \
    --crawl \
    -t 20 \
    -l 3 \
    --fuzzer all \
    --encode \
    -o xsstrike_report.html

    # JSON input testing
    xsstrike -u "https://target.com/api" \
    --json \
    --path \
    -d '{"search":"FUZZ"}' \
    --headers "Content-Type: application/json"

    # 3. KXSS (Quick Reflection Checks)
    # Fast parameter testing
    echo 'https://target.com/search?q=FUZZ' | kxss \
    -p 'Cookie: session=123' \
    --user-agent "Mozilla/5.0" \
    --proxy http://127.0.0.1:8080

    # 4. BRUTEXSS (Brute-force Approach)
    # Multi-parameter testing
    brutexss -u https://target.com/contact \
    -p "name,email,message" \
    -w /usr/share/seclists/Fuzzing/XSS/XSS-Event-Attributes.txt \
    -t 30 \
    -cookies "session=abc123"

    # 5. ADVANCED TECHNIQUES
    # WAF Bypass Testing
    dalfox url 'https://target.com/search?q=FUZZ' \
    --waf-evasion \
    --custom-payload xss-waf-bypasses.txt \
    --blind-timeout 30

    # Hidden Parameter Discovery
    arjun -u https://target.com/api \
    | dalfox pipe \
    -b your.burpcollaborator.net

    # ======================
    # PRO TIPS:
    # 1. Always test:
    #  - Reflected parameters
    #  - DOM sinks (document.write, innerHTML)
    #  - JSON inputs
    #  - Form submissions
    # 2. Use multiple scanners for coverage
    # 3. Test with different contexts:
    #  - HTML, JavaScript, attributes
    #  - Single vs double quotes
    # 4. Check for WAF bypasses
    # 5. Monitor blind XSS callbacks
    # ======================

    # EXAMPLE WORKFLOW:
    # 1. Discover parameters with Arjun/ParamSpider
    # 2. Test for reflections with kxss
    # 3. Full scan with Dalfox/XSStrike
    # 4. Verify manually in browser
    # 5. Document all findings

    # RECOMMENDED PAYLOADS:
    #  - /usr/share/seclists/Fuzzing/XSS/XSS-Payloads-L5.txt
    #  - /usr/share/seclists/Fuzzing/XSS/XSS-Polyglots.txt
    #  - /usr/share/seclists/Fuzzing/XSS/XSS-Event-Attributes.txt
    #  - Custom lists for target tech

    
    # Advanced Techniques:
    # - Test with different content types
    # - Try browser-specific payloads
    # - Check for XSS in dynamic imports
    # - Test WebSocket connections
    # - Monitor for delayed XSS triggers

    # Security Considerations:
    # - XSS may lead to:
    # - Session hijacking
    # - Credential theft
    # - UI redressing
    # - CSRF escalation
    # - Complete account takeover

    # SAMPLE XSS TESTING SCRIPT:
    """
    #!/bin/bash
    # xss_tester.sh
    url=$1
    params_file=$2

    echo "XSS Testing Report - $(date)"
    echo "==========================="

    while read param; do
    # Test basic reflection
    echo -n "Testing $param: "
    curl -s "https://$url?$param=<test>" | grep -q "<test>" && echo "REFLECTED" || echo "filtered"
    
    # Test with DOM scanner
    dalfox url "https://$url?$param=1" --mining-dom --silence | tee -a dom_xss.txt
    done < $params_file
    """

    # 6. SPECIALIZED TESTING
    # AngularJS injection
    curl "https://target.com/search?q={{7*7}}" 

    # SVG XSS testing
    curl -X POST https://target.com/upload \
    -F "file=@xss.svg" \
    -H "Content-Type: multipart/form-data"

    # Template injection
    curl "https://target.com/profile?name=<%= 7*7 %>"

