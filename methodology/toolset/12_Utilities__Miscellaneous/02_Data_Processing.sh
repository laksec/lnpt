### 12.2 Data Processing
    gf xss urls.txt | tee xss_urls.txt
    anew old.txt new.txt > combined.txt
    urldedupe -s urls.txt > unique_urls.txt
    ------
    gf xss urls.txt | grep -v "logout\|redirect" | tee xss_filtered.txt
    anew old.txt new1.txt new2.txt > combined_all.txt
    urldedupe -s urls_large.txt -o unique_large.txt -threads 20
    sed -i 's/http:/https:/g' urls_http.txt # Replace http with https
    awk '/param=/ {print $0}' urls_with_params.txt > params_only.txt
    ------
    gf xss urls.txt | grep -Po '([\'"]).*?\1' | tee xss_quotes.txt
    anew old1.txt old2.txt new1.txt new2.txt > combined_mega.txt
    urldedupe -s massive_urls.txt -o unique_massive.txt -threads 100 -buffer-size 100000
    sed -i 's/https:\/\/www\./https:\/\//g' urls_no_www.txt
    awk -F'=' '{print $2}' urls_with_equals.txt > values_only.txt
    cut -d '/' -f 3 urls_hostname_only.txt | sort -u | tee hostnames.txt

    #### 12.2.1 Data Processing & Manipulation
    # Combine and unique subdomain lists
    cat *.txt | sort -u > all_unique_subdomains.txt
    
    # Append new unique lines
    anew old_urls.txt new_discovered_urls.txt > combined_urls.txt
    
    # Deduplicate URLs (another tool example)
    urldedupe -s urls_with_duplicates.txt > unique_urls.txt
    
    # Filter URLs with gf patterns for XSS
    gf xss urls_to_check.txt | tee xss_potential_urls.txt
    
    # Filter for SQLi patterns
    gf sqli urls_to_check.txt | tee sqli_potential_urls.txt
    
    # Extract unique parameter names from URLs
    cat urls.txt | unfurl --unique keys > unique_params.txt
    
    # Extract scheme and path
    cat urls.txt | unfurl format %s%p > scheme_path.txt
    
    # Probe live hosts and get info
    cat subdomains.txt | httpx -silent -status-code -title -o live_hosts_info.txt 

#### 12.2.2 JSON Processing with jq
    # Pretty print JSON
    cat data.json | jq .
    
    # Extract all user names
    cat data.json | jq '.users[].name'
    
    # Filter objects with status active
    cat data.json | jq 'select(.status=="active")'
    
    # Wrap multiple JSON objects into an array
    cat file_with_json_lines.txt | jq -s

#### 12.2.3 Encoding/Decoding
    # Base64 encode
    echo -n "string" | base64
    
    # Base64 decode
    echo "c3RyaW5n" | base64 -d
    
    # For Basic Auth header generation
    echo -n "admin:password" | base64 
    
    # URL encode
    python3 -c "import urllib.parse; print(urllib.parse.quote_plus('test value?&='))" 
    
    # URL decode
    python3 -c "import urllib.parse; print(urllib.parse.unquote_plus('test+value%3F%26%3D'))" 
    
    # Hex encode HTML for some bypasses
    echo "<h1>test</h1>" | xxd -p | tr -d '\n'