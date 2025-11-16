
### 2.3 Parameter Discovery
    # 1. ARJUN (Smart Parameter Discovery)
    # Comprehensive parameter scan (all methods)
    arjun -u https://target.com/api/endpoint \
    --include-get --include-post --include-json \
    -o arjun_all_params.json \
    --passive

    # Targeted GET parameter discovery
    arjun -u https://target.com/search \
    -m GET \
    -t 50 \
    -o arjun_get_params.json

    # JSON API parameter discovery
    arjun -u https://target.com/api/v1/user \
    -m JSON \
    --headers 'Content-Type: application/json' \
    -o arjun_json_params.json

    # Batch processing from URL list
    arjun -i endpoints.txt \
    --stable \
    -o arjun_batch_results.json

    # 2. PARAMSPIDER (Archive Mining)
    # Aggressive parameter mining
    paramspider -d target.com \
    -l high \
    -s \
    --exclude jpg,png,css \
    -o paramspider_aggressive.txt

    # Focused parameter mining
    paramspider -d target.com \
    -p /path/to/custom_params.txt \
    --level low \
    -o paramspider_targeted.txt

    # 3. COMBINED WORKFLOW
    # Step 1: Mine parameters from archives
    paramspider -d target.com -o initial_params.txt

    # Step 2: Validate parameters with Arjun
    cat initial_params.txt | while read url; do
    arjun -u "$url" --stable -o $(echo $url | md5sum | cut -d' ' -f1).json
    done

    # ADVANCED TECHNIQUES

    # 1. PARAMETER PATTERN ANALYSIS
    # Find numeric ID parameters
    cat discovered_params.txt | grep -E 'id=[0-9]+'

    # 2. JQ PROCESSING FOR ARJUN RESULTS
    jq -r '.results[] | url + "?" + (.params | join("&"))' arjun_results.json

    # 3. WAYBACK PARAMETER MINING
    waybackurls target.com | grep -E '\?.+=' | unfurl keys | sort -u

    # 4. PARAMETER FUZZING WITH FFUF
    cat discovered_params.txt | while read param; do
    ffuf -w values.txt -u "https://target.com/api?$param=FUZZ" -o fuzzed_$param.json
    done

    # PRO TIPS:
    # 1. Always test parameters with different HTTP methods
    # 2. Look for API documentation leaks (/swagger.json, /openapi.json)
    # 3. Check for parameter pollution (same param multiple times)
    # 4. Try parameter name variations (user_id, userId, user-id)
    # 5. Combine with nuclei for automatic vulnerability testing

    # RECOMMENDED WORDLISTS:
    # /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
    # /usr/share/seclists/Discovery/Web-Content/raft-medium-parameters.txt
    # Custom lists based on target technology

    # EXAMPLE WORKFLOW:
    # 1. Mine parameters from archives with ParamSpider
    # 2. Validate with Arjun
    # 3. Analyze parameter patterns
    # 4. Fuzz interesting parameters
    # 5. Test for vulnerabilities

#### 2.3.1 Hidden Input Field Discovery
    # 1. KATANA (Built-in hidden input detection)
    katana -u https://target.com \
    -f hidden \
    -jc \  # JavaScript crawling
    -d 3 \ # Depth
    -o katana_hidden_inputs.txt \
    -em "login,admin,auth" # Focus on auth-related pages

    # 2. COMPREHENSIVE CRAWL & GREP APPROACH
    # Step 1: Crawl with Gospider
    gospider -s https://target.com \
    --other-source \
    --include-subs \
    -t 50 \
    -d 3 \
    -o gospider_crawl.json

    # Step 2: Extract hidden inputs
    cat gospider_crawl.json | jq -r '.output?' | httpx -silent -sr -srd responses
    grep -r '<input[^>]*type=[" ]*hidden[" ]' responses/ > all_hidden_inputs.txt

    # 3. ADVANCED HTML PARSING
    # Using pup (HTML parser)
    curl -s https://target.com/login | pup 'input[type=hidden] json{}' | jq

    # 4. NUCLEI TEMPLATES
    nuclei -u https://target.com \
    -t exposures/hidden-inputs/ \
    -o nuclei_hidden_inputs.json

    # ADVANCED TECHNIQUES

    # 1. HIDDEN INPUT ANALYSIS
    # Extract names and values
    grep -o 'name=["'\''][^"'\'']*["'\''][^>]*value=["'\''][^"'\'']*["'\'']' all_hidden_inputs.txt \
    | sed -E 's/name=["'\'']([^"'\'']*)["'\''].*value=["'\'']([^"'\'']*)["'\'']/\1=\2/' \
    > hidden_input_values.txt

    # 2. CSRF TOKEN DETECTION
    grep -i 'csrf\|token\|nonce' hidden_input_values.txt > potential_csrf_tokens.txt

    # 3. SESSION ID DETECTION
    grep -i 'session\|sessid\|phpsessid' hidden_input_values.txt > potential_session_ids.txt

    # 4. AUTOMATED TAMPERING TEST
    cat hidden_input_values.txt | while read line; do
    param=$(echo $line | cut -d'=' -f1)
    orig_value=$(echo $line | cut -d'=' -f2)
    ffuf -w test_values.txt -u "https://target.com/login?$param=FUZZ" -mr "error"
    done

    # Combine with sed to modify hidden values in requests:
    curl -s https://target.com/login | sed 's/<input type="hidden" name="admin" value="0"/<input type="hidden" name="admin" value="1"/' | curl -X POST https://target.com/login -d @-

    #Use trufflehog to search for secrets in hidden values:
    grep -o 'value=["'\''][^"'\'']*["'\'']' all_hidden_inputs.txt | trufflehog --stdin

    # Monitor hidden values across sessions with diff:
    diff <(curl -s https://target.com/login | grep 'type="hidden"') <(curl -s -b "session=cookie2" https://target.com/login | grep 'type="hidden"')

    # PRO TIPS:
    # 1. Focus on authentication forms first
    # 2. Look for CSRF tokens and session identifiers
    # 3. Check for hidden admin flags (admin=false, role=user)
    # 4. Test modifying values (true/false, 0/1, etc.)
    # 5. Compare across users/sessions for sensitive values

    # RECOMMENDED TEST VALUES:
    # true/false
    # 1/0
    # admin/user
    # /../ (path traversal)
    # <script>alert(1)</script> (XSS test)

    # EXAMPLE WORKFLOW:
    # 1. Crawl site for all pages
    # 2. Extract hidden inputs
    # 3. Analyze for sensitive parameters
    # 4. Test parameter tampering
    # 5. Verify impact of modified values