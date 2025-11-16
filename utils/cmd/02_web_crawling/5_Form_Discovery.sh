
### 2.8 Form Discovery
    # 1. TARGETED FORM DISCOVERY (Katana)
    # Comprehensive form extraction
    katana -u https://target.com \
    -f form \
    -d 3 \
    -jc \ # JavaScript crawling
    -kf \ # Known files
    -o katana_forms.json \
    -json

    # 2. CRAWL AND GREP APPROACH
    # Crawl with Gospider
    gospider -s https://target.com \
    -d 3 \
    -t 50 \
    -o gospider_crawl \
    --other-source

    # Extract forms from crawled pages
    grep -r -E -l '<form[^>]*>' gospider_crawl/ > form_pages.txt

    # 3. ADVANCED FORM ANALYSIS
    # Extract form details with pup (HTML parser)
    cat form_pages.txt | while read file; do
    echo "=== $file ==="
    pup -f $file 'form json{}' | jq
    done > form_details.json

    # 4. NUCLEI TEMPLATES
    # Scan for vulnerable forms
    nuclei -l form_pages.txt \
    -t vulnerabilities/csrf/ \
    -t vulnerabilities/xss/ \
    -t vulnerabilities/sqli/ \
    -o form_vulnerabilities.json \
    -json

    # ======================
    # FORM ANALYSIS TECHNIQUES
    # ======================

    # 1. CSRF DETECTION
    # Check for anti-CSRF tokens
    grep -r -E -l 'name="csrf|name="token' gospider_crawl/

    # 2. XSS TESTING
    # Find reflected parameters
    cat form_details.json | jq -r '.[] | select(.method == "GET") | action + "?" + (.inputs[] | select(.type != "hidden") | name + "=XSS")'

    # 3. SQLi TESTING
    # Identify potential injection points
    cat form_details.json | jq -r '.[] | select(.method == "POST") | action + " (params: " + (.inputs | map(.name) | join(",")) + ")"'

    # ======================
    # PRO TIPS:
    # 1. Look for:
    #  - Authentication forms (login, registration)
    #  - Admin interfaces
    #  - Search functionality
    #  - File uploads
    # 2. Check both GET and POST forms
    # 3. Analyze hidden fields for sensitive data
    # 4. Test with different user roles
    # 5. Monitor for new forms/changes
    # ======================

    # EXAMPLE WORKFLOW:
    # 1. Crawl site to discover forms
    # 2. Extract form details (action, method, inputs)
    # 3. Identify interesting forms
    # 4. Test for vulnerabilities
    # 5. Document findings

    # RECOMMENDED TOOLS:
    #  - katana (form extraction)
    #  - gospider (crawling)
    #  - pup+jq (form analysis)
    #  - nuclei (vulnerability scanning)
    #  - curl (manual testing)

    # SAMPLE FORM TESTING SCRIPT:
    """
    #!/bin/bash
    # form_tester.sh
    input_file=$1
    output_file="form_test_report_$(date +%Y%m%d).txt"

    echo "Form Test Report - $(date)" > $output_file
    echo "==========================" >> $output_file

    while read form_url; do
    echo -n "Testing $form_url... "
    
    # Extract form details
    form_html=$(curl -s "$form_url")
    action=$(echo "$form_html" | pup 'form attr{action}')
    method=$(echo "$form_html" | pup 'form attr{method}')
    inputs=$(echo "$form_html" | pup 'input attr{name}' | tr '\n' ',')

    # Test for CSRF
    if [[ ! "$form_html" =~ csrf|token ]]; then
        echo "Potential CSRF (missing token)" >> $output_file
    fi

    # Test for XSS
    if [[ "$method" == "GET" ]]; then
        echo "Test XSS at: $action?${inputs//,/=XSS&}" >> $output_file
    fi

    echo "done"
    done < $input_file
"""

    # Advanced Techniques:
    # - Test with modified hidden fields
    # - Compare forms across user roles
    # - Monitor for form changes over time
    # - Check for DOM-based forms in JavaScript
    # - Analyze form submission endpoints

    # Security Considerations:
    # Forms may expose:
    #  - Authentication mechanisms
    #  - Business logic flaws
    #  - Sensitive parameters
    #  - Missing security controls
    #  - Debug functionality