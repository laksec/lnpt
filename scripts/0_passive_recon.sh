#!/bin/bash

# Check arguments
[[ -z "$1" ]] || [[ -z "$2" ]] && { 
    echo "Usage: $0 <output_prefix> <domains_file>"; 
    echo "Example: $0 project_name domains_in_scope.txt"; 
    exit 1; 
}

# Global variables
OUTPUT_DIR="0_${1}"
TARGET_FILE="$2"
DATE_TAG=$(date +%Y%m%d_%H%M%S)

# Create directory structure
for vl in 1_raw 2_filtered 3_dns 4_resolved 5_live 8_reports; do
    mkdir -p ${OUTPUT_DIR}/$vl
done

# Setup log file
LOG_FILE="${OUTPUT_DIR}/enum_${DATE_TAG}.log"
exec 2>"${OUTPUT_DIR}/errors.log"

log() {
    echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# ============================================
# FUNCTION 1: PASSIVE SUBDOMAIN ENUMERATION
# ============================================
passive_subdomain_enum() {
    local domains_file="$1"
    local output_dir="$2"
    
    log "Starting passive subdomain enumeration"
    
    # 1. Subfinder (passive mode)
    if command -v subfinder &>/dev/null; then
        log "Running subfinder..."
        subfinder -dL "$domains_file" -silent -o "${output_dir}/1_raw/subfinder.txt" 2>/dev/null
        [[ $? -eq 0 ]] && log "Subfinder completed" || log "Subfinder failed, skipping..."
    else
        log "Subfinder not found, skipping..."
    fi
    
    # 2. Assetfinder (passive - online APIs)
    if command -v assetfinder &>/dev/null; then
        log "Running assetfinder..."
        while read -r domain; do 
            assetfinder --subs-only "$domain" 2>/dev/null; 
        done < "$domains_file" > "${output_dir}/1_raw/assetfinder.txt" 2>&1
        [[ $? -eq 0 ]] && log "Assetfinder completed" || log "Assetfinder failed, skipping..."
    else
        log "Assetfinder not found, skipping..."
    fi
    
    # # 3. Chaos (requires API key - passive)
    # if command -v chaos-client &>/dev/null && [[ -n "$CHAOS_API_KEY" ]]; then
    #     log "Running chaos-client..."
    #     # Changed 'chaos' to 'chaos-client' in the execution line
    #     chaos-client -dL "$domains_file" -silent -o "${output_dir}/1_raw/chaos.txt" 2>/dev/null
    #     [[ $? -eq 0 ]] && log "Chaos-client completed" || log "Chaos-client failed, skipping..."
    # else
    #     # Updated log message to reflect the new tool name
    #     log "Chaos-client not available (missing API key or tool), skipping..."
    # fi
    
    # 4. crt.sh queries (passive - public API)
    log "Querying crt.sh..."
    while read -r domain; do 
        curl -s --max-time 10 "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null | \
        jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' 2>/dev/null || true
    done < "$domains_file" | sort -u > "${output_dir}/1_raw/crtsh.txt" 2>&1
    [[ -s "${output_dir}/1_raw/crtsh.txt" ]] && log "crt.sh completed" || log "crt.sh failed or no results"
    
    # 5. CertSpotter API (passive - public API)
    log "Querying CertSpotter..."
    while read -r domain; do 
        curl -s --max-time 10 "https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names" 2>/dev/null | \
        jq -r '.[].dns_names[]' 2>/dev/null || true
    done < "$domains_file" | sort -u > "${output_dir}/1_raw/certspotter.txt" 2>&1
    [[ -s "${output_dir}/1_raw/certspotter.txt" ]] && log "CertSpotter completed" || log "CertSpotter failed or no results"
    
    # 6. Wayback URLs (passive - historical data)
    if command -v waybackurls &>/dev/null; then
        log "Querying Wayback Machine..."
        while read -r domain; do 
            waybackurls "$domain" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.${domain}" 2>/dev/null || true
        done < "$domains_file" | sort -u > "${output_dir}/1_raw/wayback.txt" 2>&1
        [[ $? -eq 0 ]] && log "Wayback completed" || log "Wayback failed, skipping..."
    else
        log "Waybackurls not found, skipping..."
    fi
    
    # 7. Bufferover API (passive - public API)
    log "Querying Bufferover..."
    while read -r domain; do 
        curl -s --max-time 10 "https://dns.bufferover.run/dns?q=.${domain}" 2>/dev/null | \
        jq -r '.FDNS_A[],.RDNS[]' 2>/dev/null | cut -d',' -f2 2>/dev/null || true
    done < "$domains_file" | sort -u > "${output_dir}/1_raw/bufferover.txt" 2>&1
    [[ -s "${output_dir}/1_raw/bufferover.txt" ]] && log "Bufferover completed" || log "Bufferover failed or no results"
    
    # 8. Sublist3r (passive mode)
    if command -v sublist3r &>/dev/null; then
        log "Running Sublist3r..."
        while read -r domain; do 
            sublist3r -d "$domain" -b -o "${output_dir}/1_raw/sublist3r_${domain}.txt" 2>/dev/null
            [[ -f "${output_dir}/1_raw/sublist3r_${domain}.txt" ]] && cat "${output_dir}/1_raw/sublist3r_${domain}.txt" 2>/dev/null
        done < "$domains_file" > "${output_dir}/1_raw/sublist3r_combined.txt" 2>&1
        [[ $? -eq 0 ]] && log "Sublist3r completed" || log "Sublist3r failed, skipping..."
    else
        log "Sublist3r not found, skipping..."
    fi
    
    # 9. Findomain (fast and passive)
    if command -v findomain &>/dev/null; then
        log "Running Findomain..."
        findomain -f "$domains_file" -u "${output_dir}/1_raw/findomain.txt" 2>/dev/null
        [[ $? -eq 0 ]] && log "Findomain completed" || log "Findomain failed, skipping..."
    else
        log "Findomain not found, skipping..."
    fi
    
    # 10. Amass (passive mode only)
    if command -v amass &>/dev/null; then
        log "Running Amass (passive mode)..."
        amass enum -passive -df "$domains_file" -o "${output_dir}/1_raw/amass.txt" 2>/dev/null
        [[ $? -eq 0 ]] && log "Amass completed" || log "Amass failed, skipping..."
    else
        log "Amass not found, skipping..."
    fi
    
    # # 11. Shodan (if API key available - passive)
    # if command -v shodan &>/dev/null && [[ -n "$SHODAN_API_KEY" ]]; then
    #     log "Querying Shodan..."
    #     while read -r domain; do
    #         shodan domain "$domain" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.${domain}" 2>/dev/null || true
    #     done < "$domains_file" > "${output_dir}/1_raw/shodan.txt" 2>&1
    #     [[ -s "${output_dir}/1_raw/shodan.txt" ]] && log "Shodan completed" || log "Shodan failed or no results"
    # else
    #     log "Shodan not available (missing API key or tool), skipping..."
    # fi
    
    # Combine all results
    cat "${output_dir}/1_raw/"*.txt 2>/dev/null | sort -u | grep -v "^\*\." | \
    grep -E '^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+$' > "${output_dir}/2_filtered/all_subdomains.txt"
    
    local count=$(wc -l < "${output_dir}/2_filtered/all_subdomains.txt" 2>/dev/null || echo 0)
    log "Passive enumeration completed: ${count} unique subdomains found"
    
    # Show which tools succeeded
    log "Successful tools:"
    for tool_file in "${output_dir}/1_raw/"*.txt; do
        if [[ -s "$tool_file" ]]; then
            tool_name=$(basename "$tool_file" .txt)
            tool_count=$(wc -l < "$tool_file" 2>/dev/null || echo 0)
            log "  - ${tool_name}: ${tool_count}"
        fi
    done
}

# ============================================
# FUNCTION 2: PASSIVE DNS RESOLUTION
# ============================================
passive_dns_resolution() {
    local subdomains_file="$1"
    local output_dir="$2"
    
    log "Starting passive DNS resolution"
    
    # Create output dirs
    mkdir -p "${output_dir}/3_dns" "${output_dir}/4_resolved"
    
    # Try multiple passive DNS sources
    local resolved_count=0
    
    # 1. Try using system's DNS (passive lookup)
    log "Attempting passive DNS lookups..."
    while read -r domain; do
        host "$domain" 2>/dev/null | grep "has address" | awk '{print $1 " A " $4}' 2>/dev/null || true
    done < "$subdomains_file" > "${output_dir}/3_dns/system_dns.txt" 2>&1
    
    # 2. Try using dig (still passive - just queries)
    if command -v dig &>/dev/null; then
        log "Using dig for DNS lookups..."
        while read -r domain; do
            dig +short A "$domain" 2>/dev/null | xargs -r -I{} echo "$domain A {}" 2>/dev/null || true
        done < "$subdomains_file" >> "${output_dir}/3_dns/system_dns.txt" 2>&1
    fi
    
    # Extract A records
    grep " A " "${output_dir}/3_dns/system_dns.txt" 2>/dev/null | sort -u > "${output_dir}/3_dns/a_records.txt"
    
    # Extract unique IPs
    awk '{print $3}' "${output_dir}/3_dns/a_records.txt" 2>/dev/null | sort -u > "${output_dir}/4_resolved/ips.txt"
    
    # Count results
    resolved_count=$(wc -l < "${output_dir}/4_resolved/ips.txt" 2>/dev/null || echo 0)
    log "Passive DNS resolution completed: ${resolved_count} unique IPs found"
    
    # Note about active resolution being skipped
    echo "# NOTE: Active DNS resolution (massdns, puredns) skipped for passive recon" > "${output_dir}/3_dns/note.txt"
    echo "# To enable active resolution, uncomment the relevant functions in the script" >> "${output_dir}/3_dns/note.txt"
}

# ============================================
# FUNCTION 3: PASSIVE LIVE HOST DETECTION
# ============================================
passive_live_detection() {
    local subdomains_file="$1"
    local output_dir="$2"
    local live_dir="${output_dir}/5_live"
    
    log "Starting passive live host detection"
    mkdir -p "$live_dir"
    
    # Note: True passive live detection is limited
    # We can only check what we already know from our passive sources
    
    # Create a placeholder - in true passive recon, we don't actually probe hosts
    echo "# Passive Reconnaissance Results" > "${live_dir}/README.md"
    echo "" >> "${live_dir}/README.md"
    echo "In passive reconnaissance mode, we do not actively probe hosts." >> "${live_dir}/README.md"
    echo "The following subdomains were found through passive sources:" >> "${live_dir}/README.md"
    echo "" >> "${live_dir}/README.md"
    
    cat "$subdomains_file" 2>/dev/null | while read -r domain; do
        echo "- $domain" >> "${live_dir}/README.md"
    done
    
    # We can't determine if hosts are actually live without probing
    # So we'll just copy the subdomains as "potentially live"
    cp "$subdomains_file" "${live_dir}/potential_hosts.txt" 2>/dev/null
    
    log "Passive live detection completed"
    log "Note: Active probing (httpx, nmap, etc.) skipped in passive mode"
}

# ============================================
# FUNCTION 4: PASSIVE TAKEOVER DETECTION
# ============================================
passive_takeover_detection() {
    local subdomains_file="$1"
    local output_dir="$2"
    
    log "Starting passive takeover detection"
    mkdir -p "${output_dir}/7_takeover"
    
    # Check for potentially vulnerable services in subdomain names
    # This is completely passive - just pattern matching
    local patterns=(
        'github\.io'
        '\.?s3[\.-]'
        'cloudfront\.net'
        'azurewebsites\.net'
        'herokuapp\.com'
        '\.firebaseapp\.com'
        '\.surge\.sh'
        'readme\.io'
        'uservoice\.com'
        'statuspage\.io'
        '\.aws\.'
        '\.cloudapp\.'
        '\.appspot\.com'
        '\.netlify\.com'
        '\.zeit\.co'
    )
    
    local pattern_string=$(IFS='|'; echo "${patterns[*]}")
    
    grep -hiE "($pattern_string)" "$subdomains_file" 2>/dev/null | \
    awk '!a[tolower($0)]++' | sort > "${output_dir}/7_takeover/potential_takeovers.txt"
    
    local count=$(wc -l < "${output_dir}/7_takeover/potential_takeovers.txt" 2>/dev/null || echo 0)
    
    if [[ $count -gt 0 ]]; then
        log "Found ${count} potential takeover targets (based on naming patterns)"
        log "These require manual verification"
    else
        log "No obvious takeover targets found"
    fi
    
    # Add explanatory note
    echo "# Passive Takeover Detection Results" > "${output_dir}/7_takeover/README.md"
    echo "" >> "${output_dir}/7_takeover/README.md"
    echo "This is a PASSIVE check only - looking for subdomain naming patterns" >> "${output_dir}/7_takeover/README.md"
    echo "that commonly indicate third-party services that could be vulnerable" >> "${output_dir}/7_takeover/README.md"
    echo "to subdomain takeover." >> "${output_dir}/7_takeover/README.md"
    echo "" >> "${output_dir}/7_takeover/README.md"
    echo "For active takeover testing, use tools like:" >> "${output_dir}/7_takeover/README.md"
    echo "- subjack" >> "${output_dir}/7_takeover/README.md"
    echo "- SubOver" >> "${output_dir}/7_takeover/README.md"
    echo "- nuclei (with takeover templates)" >> "${output_dir}/7_takeover/README.md"
}

# ============================================
# FUNCTION 5: GENERATE PASSIVE REPORTS
# ============================================
generate_passive_reports() {
    local output_dir="$1"
    
    log "Generating passive reconnaissance reports"
    
    # Summary report
    echo "# Passive Reconnaissance Report" > "${output_dir}/8_reports/summary.md"
    echo "Generated: $(date)" >> "${output_dir}/8_reports/summary.md"
    echo "Mode: PASSIVE ONLY (no active scanning)" >> "${output_dir}/8_reports/summary.md"
    echo "" >> "${output_dir}/8_reports/summary.md"
    echo "## Statistics" >> "${output_dir}/8_reports/summary.md"
    echo "- Total domains input: $(wc -l < "$TARGET_FILE" 2>/dev/null || echo 0)" >> "${output_dir}/8_reports/summary.md"
    echo "- Unique subdomains found: $(wc -l < "${output_dir}/2_filtered/all_subdomains.txt" 2>/dev/null || echo 0)" >> "${output_dir}/8_reports/summary.md"
    echo "- IP addresses resolved: $(wc -l < "${output_dir}/4_resolved/ips.txt" 2>/dev/null || echo 0)" >> "${output_dir}/8_reports/summary.md"
    echo "- Potential takeover targets: $(wc -l < "${output_dir}/7_takeover/potential_takeovers.txt" 2>/dev/null || echo 0)" >> "${output_dir}/8_reports/summary.md"
    echo "" >> "${output_dir}/8_reports/summary.md"
    
    # Tools used section
    echo "## Tools/Sources Used" >> "${output_dir}/8_reports/summary.md"
    for raw_file in "${output_dir}/1_raw/"*.txt; do
        if [[ -f "$raw_file" ]] && [[ -s "$raw_file" ]]; then
            tool_name=$(basename "$raw_file" .txt)
            count=$(wc -l < "$raw_file" 2>/dev/null || echo 0)
            echo "- **${tool_name}**: ${count} results" >> "${output_dir}/8_reports/summary.md"
        fi
    done
    echo "" >> "${output_dir}/8_reports/summary.md"
    
    # List of subdomains by base domain
    echo "## Subdomains by Base Domain" >> "${output_dir}/8_reports/summary.md"
    while read -r domain; do
        echo "### ${domain}" >> "${output_dir}/8_reports/summary.md"
        grep "\.${domain}$" "${output_dir}/2_filtered/all_subdomains.txt" 2>/dev/null | \
        sed 's/^/- /' >> "${output_dir}/8_reports/summary.md"
        echo "" >> "${output_dir}/8_reports/summary.md"
    done < "$TARGET_FILE"
    
    # CSV export
    echo "domain,source_tools" > "${output_dir}/8_reports/subdomains.csv"
    while read -r subdomain; do
        # Find which tools found this subdomain
        sources=""
        for raw_file in "${output_dir}/1_raw/"*.txt; do
            if [[ -f "$raw_file" ]] && grep -q "^${subdomain}$" "$raw_file" 2>/dev/null; then
                tool_name=$(basename "$raw_file" .txt)
                sources="${sources}${tool_name},"
            fi
        done
        sources="${sources%,}"  # Remove trailing comma
        echo "\"$subdomain\",\"$sources\"" >> "${output_dir}/8_reports/subdomains.csv"
    done < "${output_dir}/2_filtered/all_subdomains.txt"
    
    # Generate simple wordlist for future use
    cp "${output_dir}/2_filtered/all_subdomains.txt" "${output_dir}/8_reports/subdomains_wordlist.txt"
    
    log "Reports generated in ${output_dir}/8_reports/"
}

# ============================================
# FUNCTION 6: CLEAN AND VALIDATE RESULTS
# ============================================
clean_and_validate() {
    local input_file="$1"
    local output_file="$2"
    
    log "Cleaning and validating subdomains"
    
    # Remove wildcards, invalid chars, and sort
    if [[ -f "$input_file" ]]; then
        cat "$input_file" 2>/dev/null | \
        grep -v "^\*\." | \
        grep -E '^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+$' | \
        sed 's/^\.//;s/\.$//' | \
        sort -u > "$output_file"
        
        local count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
        log "Cleaned: ${count} valid subdomains"
    else
        log "No input file to clean"
        touch "$output_file"
    fi
}


# ============================================
# MAIN EXECUTION - PASSIVE ONLY
# ============================================
main() {
    log "========================================"
    log "STARTING PASSIVE RECONNAISSANCE ONLY"
    log "Output directory: $OUTPUT_DIR"
    log "Target domains: $(wc -l < "$TARGET_FILE" 2>/dev/null || echo 0)"
    log "========================================"
    log "NOTE: All active techniques are disabled"
    log "========================================"
    
    # Clean target file
    dos2unix "$TARGET_FILE" 2>/dev/null
    
    # Step 1: Passive subdomain enumeration
    passive_subdomain_enum "$TARGET_FILE" "$OUTPUT_DIR"
    
    # Step 2: Clean results
    clean_and_validate "${OUTPUT_DIR}/2_filtered/all_subdomains.txt" "${OUTPUT_DIR}/2_filtered/clean_subdomains.txt"
    mv "${OUTPUT_DIR}/2_filtered/clean_subdomains.txt" "${OUTPUT_DIR}/2_filtered/all_subdomains.txt"
    
    # Step 3: Passive DNS resolution
    passive_dns_resolution "${OUTPUT_DIR}/2_filtered/all_subdomains.txt" "$OUTPUT_DIR"
    
    # Step 4: Passive live host detection (limited)
    passive_live_detection "${OUTPUT_DIR}/2_filtered/all_subdomains.txt" "$OUTPUT_DIR"
    
    # Step 5: Passive takeover detection
    passive_takeover_detection "${OUTPUT_DIR}/2_filtered/all_subdomains.txt" "$OUTPUT_DIR"
    
    # Step 6: Generate reports
    generate_passive_reports "$OUTPUT_DIR"
    
    # Final summary
    log "========================================"
    log "PASSIVE RECONNAISSANCE COMPLETE"
    log "========================================"
    log "Total subdomains: $(wc -l < "${OUTPUT_DIR}/2_filtered/all_subdomains.txt" 2>/dev/null || echo 0)"
    log "Resolved IPs: $(wc -l < "${OUTPUT_DIR}/4_resolved/ips.txt" 2>/dev/null || echo 0)"
    log "Potential takeovers: $(wc -l < "${output_dir}/7_takeover/potential_takeovers.txt" 2>/dev/null || echo 0)"
    log "========================================"
    log "Reports: ${OUTPUT_DIR}/8_reports/"
    log "Raw data: ${OUTPUT_DIR}/1_raw/"
    log "========================================"
    log "Next steps for active reconnaissance:"
    log "1. Review subdomains in ${OUTPUT_DIR}/2_filtered/all_subdomains.txt"
    log "2. Use httpx/nmap for active scanning"
    log "3. Run subjack for takeover testing"
    log "4. Use massdns for thorough DNS resolution"
    log "========================================"
}

# Run main function
main