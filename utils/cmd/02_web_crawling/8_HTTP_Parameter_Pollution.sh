### 2.11 HTTP Parameter Pollution (HPP)
    # 1. MANUAL PARAMETER POLLUTION TESTING
    # GET request testing
    curl -v "https://target.com/search?q=test1&q=test2"

    # POST request testing
    curl -X POST https://target.com/search -d "q=test1&q=test2" -H "Content-Type: application/x-www-form-urlencoded"

    # 2. AUTOMATED PARAMETER DISCOVERY
    # Comprehensive parameter discovery (Arjun)
    arjun -u https://target.com/api \
    -m GET,POST,JSON \
    -t 30 \
    -o discovered_params.json \
    --passive

    # Historical parameter mining (ParamSpider)
    paramspider -d target.com \
    -l high \
    -s \ # Include subdomains
    -w /usr/share/seclists/Fuzzing/predictable-parameters.txt \
    -o paramspider_results.txt

    # 3. WAYBACK PARAMETER EXTRACTION
    waybackparam -u target.com \
    -o wayback_params.txt \
    -dedupe \
    -filter "api|token|id|session"

    # 4. PARAMETER FUZZING
    # GET parameter fuzzing (Parameth)
    parameth -u https://target.com/search \
    -f /usr/share/seclists/Fuzzing/param-names/extended.txt \
    -b "404,400" \
    -t 25 \
    -o parameth_results.txt

    # POST parameter fuzzing (Qsreplace)
    qsreplace -a api_endpoints.txt \
    -p /usr/share/seclists/Fuzzing/POST-params.txt \
    -m POST \
    -threads 30 \
    -o post_params_fuzzed.txt

    # 5. NUCLEI TEMPLATES
    # Test for parameter pollution vulnerabilities
    nuclei -l target_urls.txt \
    -t exposures/parameter-pollution/ \
    -severity medium,high,critical \
    -o hpp_results.json

    # ======================
    # PRO TIPS:
    # 1. Always test:
    #  - Duplicate parameters (q=1&q=2)
    #  - Parameter override techniques
    #  - Different HTTP methods
    #  - Various content types (JSON, XML)
    # 2. Look for:
    #  - Response differences
    #  - Parameter precedence
    #  - Error messages
    #  - Business logic changes
    # 3. Special cases:
    #  - JSON parameter pollution
    #  - XML attribute injection
    #  - Array parameters (q[]=1&q[]=2)
    # ======================

    # EXAMPLE WORKFLOW:
    # 1. Discover parameters with Arjun/ParamSpider
    # 2. Mine historical parameters with WaybackParam
    # 3. Test for pollution vulnerabilities
    # 4. Verify findings manually
    # 5. Document all parameter behaviors

    # RECOMMENDED WORDLISTS:
    #  - /usr/share/seclists/Fuzzing/param-names/
    #  - /usr/share/seclists/Fuzzing/predictable-parameters.txt
    #  - /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
    #  - Custom lists based on target tech


    # Advanced Techniques:
    # - Test with different parameter encodings
    # - Check for parameter name case sensitivity
    # - Try parameter hiding techniques (;param=value)
    # - Test with null bytes in parameters
    # - Monitor for parameter-dependent behavior changes

    # Security Considerations:
    # Parameter pollution may lead to:
    # - Access control bypass
    # - Business logic flaws
    # - Cache poisoning
    # - Authentication issues
    # - Information disclosure

    # SAMPLE PARAMETER TESTING SCRIPT:    
    ```
        #!/bin/bash
        # param_tester.sh
        url=$1
        params_file=$2

        echo "Parameter Testing Report - $(date)"
        echo "================================"

        while read param; do
        # Test GET pollution
        echo -n "Testing GET $param: "
        curl -s "https://$url?$param=1&$param=2" | grep -q "unexpected" && echo "VULNERABLE" || echo "safe"

        # Test POST pollution
        echo -n "Testing POST $param: "
        curl -s -X POST -d "$param=1&$param=2" "https://$url" | grep -q "unexpected" && echo "VULNERABLE" || echo "safe"
        done < $params_file
    ```

    # 6. ADVANCED TECHNIQUES
    # JSON parameter pollution
    curl -X POST https://target.com/api \
    -H "Content-Type: application/json" \
    -d '{"q":"test1","q":"test2"}'

    # Array parameter testing
    curl "https://target.com/search?q[]=1&q[]=2"

    # XML attribute injection
    curl -X POST https://target.com/xml \
    -H "Content-Type: application/xml" \
    -d '<root param="test1" param="test2"/>'

