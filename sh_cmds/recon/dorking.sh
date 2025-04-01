#!/bin/bash

# Ultimate Google Dorking Script
# Version: 2.0
# Usage: ./google_dorking.sh <domains.txt> <output_directory>

# Configuration
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
DELAY=3  # seconds between requests to avoid rate limiting
PAGES=3  # number of search result pages to scrape per dork
MAX_THREADS=5

# Initialize
init() {
    if [ $# -ne 2 ]; then
        echo "Usage: $0 <domains.txt> <output_directory>"
        exit 1
    fi

    INPUT_FILE="$1"
    OUTPUT_BASE="$2"

    if [ ! -f "$INPUT_FILE" ]; then
        echo "Error: Input file not found"
        exit 1
    fi

    mkdir -p "$OUTPUT_BASE" || {
        echo "Error: Failed to create output directory"
        exit 1
    }

    # Create dork patterns file if not exists
    DORK_FILE="$OUTPUT_BASE/dork_patterns.txt"
    [ -f "$DORK_FILE" ] || generate_dork_patterns "$DORK_FILE"
}

generate_dork_patterns() {
    local dork_file="$1"
    cat <<EOF > "$dork_file"
site:DOMAIN ext:php | ext:asp | ext:aspx | ext:jsp | ext:py
site:DOMAIN intitle:"index of" | intitle:"directory listing"
site:DOMAIN inurl:/admin/ | inurl:/login/ | inurl:/dashboard/
site:DOMAIN filetype:pdf | filetype:doc | filetype:xls | filetype:csv
site:DOMAIN intext:"password" | intext:"username" | intext:"credentials"
site:DOMAIN ext:env | ext:yml | ext:config | ext:conf
site:DOMAIN inurl:"/wp-content/" | inurl:"/wp-admin/"
site:DOMAIN "error" | "warning" | "debug" | "exception"
site:DOMACH ext:sql | ext:dbf | ext:mdb | ext:bak
site:DOMAIN "api" | "swagger" | "graphql" | "rest"
EOF
}

# Perform Google search
google_search() {
    local query="$1"
    local output_file="$2"
    local results=()

    for ((page=0; page<PAGES; page++)); do
        start=$((page * 10))
        url="https://www.google.com/search?q=${query}&start=${start}&num=100"
        
        html=$(curl -s -A "$USER_AGENT" "$url" 2>/dev/null)
        if [[ $? -ne 0 ]]; then
            echo "Error: Request failed for $query"
            return 1
        fi

        # Extract clean URLs from search results
        urls=$(echo "$html" | grep -oP 'href="\K\/url\?q=[^"]+' | cut -d'&' -f1 | sed 's/\/url?q=//')
        for url in $urls; do
            results+=("$url")
        done

        sleep "$DELAY"
    done

    # Save unique results
    printf "%s\n" "${results[@]}" | sort -u > "$output_file"
}

# Process domain with all dorks
process_domain() {
    local domain="$1"
    local domain_dir="$OUTPUT_BASE/$(echo "$domain" | tr '.' '_')"
    mkdir -p "$domain_dir"

    echo "[*] Processing domain: $domain"
    
    while IFS= read -r dork_pattern; do
        dork_name=$(echo "$dork_pattern" | cut -d' ' -f1 | tr -d ':')
        output_file="$domain_dir/${dork_name}_results.txt"
        query=$(echo "$dork_pattern" | sed "s/DOMAIN/$domain/g")
        
        echo "  [+] Dork: $query"
        google_search "$query" "$output_file" &
        
        # Limit concurrent processes
        while [ $(jobs -r -p | wc -l) -ge "$MAX_THREADS" ]; do
            sleep 1
        done
        
        sleep "$DELAY"
    done < "$DORK_FILE"
    
    wait
}

# Main execution
init "$@"

echo "[*] Starting Google Dorking scan"
echo "[*] Input file: $INPUT_FILE"
echo "[*] Output directory: $OUTPUT_BASE"
echo "[*] Using $MAX_THREADS threads with $DELAY second delay"

while IFS= read -r domain || [[ -n "$domain" ]]; do
    domain=$(echo "$domain" | tr -d '\r\n' | sed 's/^[[:blank:]]*//;s/[[:blank:]]*$//')
    [[ -z "$domain" ]] && continue
    [[ "$domain" =~ ^# ]] && continue
    
    process_domain "$domain"
done < "$INPUT_FILE"

echo "[*] Google Dorking completed. Results saved to $OUTPUT_BASE"