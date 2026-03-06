#!/bin/bash

# Check arguments
[[ -z "$1" ]] || [[ -z "$2" ]] && { 
    echo "Usage: $0 <output_prefix> <domains_file> [wordlist]"; 
    echo "Example: $0 project_name domains_in_scope.txt /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"; 
    exit 1; 
}

# Global variables
OUTPUT_DIR="0_${1}"
TARGET_FILE="$2"
WORDLIST="${3:-/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt}"
THREADS=50
DATE_TAG=$(date +%Y%m%d_%H%M%S)

# Create directory structure
for dir in 1_subdomains 2_resolved 3_live 4_urls 5_reports; do
    mkdir -p "${OUTPUT_DIR}/$dir"
done

# Setup logging
LOG_FILE="${OUTPUT_DIR}/enum_${DATE_TAG}.log"
ERROR_LOG="${OUTPUT_DIR}/errors_${DATE_TAG}.log"
exec 2>"$ERROR_LOG"

# Helper functions
log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
check_tool() { command -v "$1" &>/dev/null || { log "WARNING: $1 not installed, skipping related tasks"; return 1; } }
clean_subdomains() { grep -v "^\*\." | grep -E '^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+$' | sort -u; }

# ============================================
# PHASE 1: SUBDOMAIN DISCOVERY
# ============================================

phase_subdomain_discovery() {
    local domains_file="$1"
    local output_dir="$2"
    local combined_file="${output_dir}/1_subdomains/all_discovered.txt"
    
    log "Starting Phase 1: Subdomain Discovery"
    
    # Clear previous results
    > "$combined_file"
    
    # Subfinder (most comprehensive)
    if check_tool "subfinder"; then
        log "Running subfinder..."
        subfinder -dL "$domains_file" -all -silent -o "${output_dir}/1_subdomains/subfinder.txt" 2>/dev/null
        cat "${output_dir}/1_subdomains/subfinder.txt" >> "$combined_file"
    fi
    
    # Assetfinder (good for ASN/related domains)
    if check_tool "assetfinder"; then
        log "Running assetfinder..."
        while read -r dm; do
            assetfinder --subs-only "$dm" 2>/dev/null
        done < "$domains_file" > "${output_dir}/1_subdomains/assetfinder.txt"
        cat "${output_dir}/1_subdomains/assetfinder.txt" >> "$combined_file"
    fi
    
    # crt.sh (certificate transparency - valuable source)
    log "Querying crt.sh..."
    while read -r dm; do
        curl -s "https://crt.sh/?q=%25.${dm}&output=json" 2>/dev/null | \
            jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g'
    done < "$domains_file" | sort -u > "${output_dir}/1_subdomains/crtsh.txt"
    cat "${output_dir}/1_subdomains/crtsh.txt" >> "$combined_file"
    
    # Clean and deduplicate
    cat "$combined_file" | clean_subdomains | sort -u > "${combined_file}.tmp"
    mv "${combined_file}.tmp" "$combined_file"
    
    local count=$(wc -l < "$combined_file" 2>/dev/null || echo 0)
    log "Phase 1 completed: $count subdomains discovered"
}

# ============================================
# PHASE 2: SUBDOMAIN BRUTEFORCE + RESOLUTION
# ============================================

phase_bruteforce_resolution() {
    local domains_file="$1"
    local wordlist="$2"
    local output_dir="$3"
    local discovered_file="${output_dir}/1_subdomains/all_discovered.txt"
    local final_file="${output_dir}/1_subdomains/all_subdomains.txt"
    
    log "Starting Phase 2: Subdomain Bruteforce & Resolution"
    
    # Check prerequisites
    [[ ! -f "$wordlist" ]] && { log "Wordlist not found: $wordlist"; return 1; }
    
    local resolver_file="/etc/resolv.conf"  # Use system resolvers
    local bruteforce_file="${output_dir}/1_subdomains/bruteforce.txt"
    
    # PureDNS is preferred as it handles both bruteforce and resolution
    if check_tool "puredns"; then
        # Step 1: Bruteforce with wildcard handling
        log "Running puredns bruteforce (with wildcard detection)..."
        puredns bruteforce "$wordlist" "$domains_file" \
            -r "$resolver_file" \
            --wildcard-batch \
            --wildcard-tests 10 \
            -l 1000 \
            -o "$bruteforce_file" 2>/dev/null
        
        # Step 2: Resolve all domains (discovered + bruteforced)
        log "Resolving all domains with puredns..."
        cat "$discovered_file" "$bruteforce_file" 2>/dev/null | \
            clean_subdomains | sort -u > "${output_dir}/1_subdomains/to_resolve.txt"
        
        puredns resolve "${output_dir}/1_subdomains/to_resolve.txt" \
            -r "$resolver_file" \
            --wildcard-batch \
            --write "${output_dir}/2_resolved/resolved.txt" 2>/dev/null
        
        # Extract IPs and create clean subdomain list
        if [[ -f "${output_dir}/2_resolved/resolved.txt" ]]; then
            cut -d' ' -f1 "${output_dir}/2_resolved/resolved.txt" | sort -u > "$final_file"
            awk '{print $2}' "${output_dir}/2_resolved/resolved.txt" | sort -u > "${output_dir}/2_resolved/ips.txt"
        fi
    
    # Fallback: Use massdns for resolution only
    elif check_tool "massdns"; then
        log "PureDNS not found, using massdns for resolution (bruteforce only)"
        
        # Basic bruteforce with sed+massdns
        while read -r dm; do
            sed "s/$/.${dm}/" "$wordlist" 
        done < "$domains_file" | sort -u > "${output_dir}/1_subdomains/bruteforce_candidates.txt"
        
        massdns -r "$resolver_file" \
            -t A \
            -o S \
            -w "${output_dir}/2_resolved/massdns.txt" \
            "${output_dir}/1_subdomains/bruteforce_candidates.txt" 2>/dev/null
        
        # Parse resolved domains
        grep " A " "${output_dir}/2_resolved/massdns.txt" | \
            awk '{print $1}' | sed 's/\.$//' | sort -u > "$bruteforce_file"
        
        # Combine with discovered and parse
        cat "$discovered_file" "$bruteforce_file" | clean_subdomains | sort -u > "$final_file"
        grep " A " "${output_dir}/2_resolved/massdns.txt" | \
            awk '{print $1" "$3}' | sed 's/\.$//' | sort -u > "${output_dir}/2_resolved/a_records.txt"
        awk '{print $2}' "${output_dir}/2_resolved/a_records.txt" | sort -u > "${output_dir}/2_resolved/ips.txt"
    fi
    
    local final_count=$(wc -l < "$final_file" 2>/dev/null || echo 0)
    local ip_count=$(wc -l < "${output_dir}/2_resolved/ips.txt" 2>/dev/null || echo 0)
    log "Phase 2 completed: $final_count resolved subdomains, $ip_count unique IPs"
}

# ============================================
# PHASE 3: LIVE HOSTS DETECTION
# ============================================

phase_live_hosts() {
    local subdomains_file="$1"
    local output_dir="$2"
    
    log "Starting Phase 3: Live Hosts Detection"
    
    [[ ! -f "$subdomains_file" ]] && { log "No subdomains file found"; return 1; }
    
    if check_tool "httpx"; then
        httpx -l "$subdomains_file" \
            -silent \
            -sc \
            -title \
            -td \
            -ip \
            -cname \
            -threads "$THREADS" \
            -timeout 5 \
            -ports 80,443,8080,8443 \
            -o "${output_dir}/3_live/httpx.txt" 2>/dev/null
        
        # Extract live URLs
        awk '{print $1}' "${output_dir}/3_live/httpx.txt" 2>/dev/null | sort -u > "${output_dir}/3_live/live_urls.txt"
    fi
    
    local live_count=$(wc -l < "${output_dir}/3_live/live_urls.txt" 2>/dev/null || echo 0)
    log "Phase 3 completed: $live_count live hosts found"
}

# ============================================
# PHASE 4: URL DISCOVERY
# ============================================

phase_url_discovery() {
    local live_urls_file="$1"
    local output_dir="$2"
    
    log "Starting Phase 4: URL Discovery"
    
    [[ ! -f "$live_urls_file" ]] && { log "No live URLs file found"; return 1; }
    
    local urls_file="${output_dir}/4_urls/all_urls.txt"
    > "$urls_file"
    
    # Wayback Machine (most comprehensive)
    if check_tool "waybackurls"; then
        log "Fetching Wayback Machine URLs..."
        cat "$live_urls_file" | waybackurls 2>/dev/null | sort -u > "${output_dir}/4_urls/wayback.txt"
        cat "${output_dir}/4_urls/wayback.txt" >> "$urls_file"
    fi
    
    # Gau (good supplement)
    if check_tool "gau"; then
        log "Running gau..."
        cat "$live_urls_file" | gau --threads 20 2>/dev/null | sort -u > "${output_dir}/4_urls/gau.txt"
        cat "${output_dir}/4_urls/gau.txt" >> "$urls_file"
    fi
    
    # Clean and deduplicate
    sort -u "$urls_file" -o "$urls_file"
    
    # Extract interesting endpoints
    grep -E "\.js$|\.json$|\.xml$|\.yaml$|\.conf$|\.config$|\.bak$|\.old$|\.sql$|\.db$" "$urls_file" \
        > "${output_dir}/4_urls/sensitive_files.txt" 2>/dev/null
    
    grep -E "api|v1|v2|v3|graphql|rest|swagger|docs|redoc" "$urls_file" \
        > "${output_dir}/4_urls/api_endpoints.txt" 2>/dev/null
    
    local url_count=$(wc -l < "$urls_file" 2>/dev/null || echo 0)
    log "Phase 4 completed: $url_count URLs discovered"
}

# ============================================
# PHASE 5: REPORT GENERATION
# ============================================

phase_report_generation() {
    local output_dir="$1"
    
    log "Starting Phase 5: Report Generation"
    
    local report_dir="${output_dir}/5_reports"
    mkdir -p "$report_dir"
    
    # Generate summary
    {
        echo "# DNS Enumeration Report"
        echo "Generated: $(date)"
        echo ""
        echo "## Targets"
        echo "- Domains: $(wc -l < "$TARGET_FILE" | tr -d ' ')"
        echo ""
        echo "## Results Summary"
        echo "- **Subdomains (resolved)**: $(wc -l < "${output_dir}/1_subdomains/all_subdomains.txt" 2>/dev/null || echo 0)"
        echo "- **Unique IPs**: $(wc -l < "${output_dir}/2_resolved/ips.txt" 2>/dev/null || echo 0)"
        echo "- **Live Hosts (HTTP/HTTPS)**: $(wc -l < "${output_dir}/3_live/live_urls.txt" 2>/dev/null || echo 0)"
        echo "- **Total URLs**: $(wc -l < "${output_dir}/4_urls/all_urls.txt" 2>/dev/null || echo 0)"
        echo "- **Sensitive Files**: $(wc -l < "${output_dir}/4_urls/sensitive_files.txt" 2>/dev/null || echo 0)"
        echo "- **API Endpoints**: $(wc -l < "${output_dir}/4_urls/api_endpoints.txt" 2>/dev/null || echo 0)"
        
        # Top 10 subdomains by length (potential interesting ones)
        echo ""
        echo "## Sample Subdomains (Top 10)"
        head -10 "${output_dir}/1_subdomains/all_subdomains.txt" 2>/dev/null | sed 's/^/  - /'
        
        # Sample live hosts
        echo ""
        echo "## Sample Live Hosts (Top 10)"
        head -10 "${output_dir}/3_live/live_urls.txt" 2>/dev/null | sed 's/^/  - /'
        
    } > "${report_dir}/summary.md"
    
    # Create commands file for next steps
    {
        echo "# Next Steps Commands"
        echo ""
        echo "## Port Scanning (if needed)"
        echo "naabu -list ${output_dir}/2_resolved/ips.txt -top-ports 1000 -o ${output_dir}/naabu_ports.txt"
        echo ""
        echo "## Subdirectory Bruteforce (if needed)"
        echo "ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -u https://example.com/FUZZ"
        echo ""
        echo "## Screenshots"
        echo "gowitness file -f ${output_dir}/3_live/live_urls.txt --destination ${output_dir}/screenshots/"
        echo ""
        echo "## Vulnerability Scanning"
        echo "nuclei -list ${output_dir}/3_live/live_urls.txt -t ~/nuclei-templates/ -o ${output_dir}/nuclei_results.txt"
        
    } > "${report_dir}/next_steps.txt"
    
    # Create file tree
    find "$output_dir" -type f -name "*.txt" -o -name "*.md" | sort > "${report_dir}/files.txt"
    
    log "Phase 5 completed: Reports generated in ${report_dir}/"
}

# ============================================
# MAIN EXECUTION
# ============================================

main() {
    log "========================================="
    log "Starting DNS Enumeration Pipeline"
    log "Output directory: $OUTPUT_DIR"
    log "========================================="
    
    # Validate target file
    [[ ! -f "$TARGET_FILE" ]] && { log "Error: Target file '$TARGET_FILE' not found"; exit 1; }
    
    # Convert line endings just in case
    dos2unix "$TARGET_FILE" 2>/dev/null
    
    # Remove comments and empty lines from target file
    grep -v '^#' "$TARGET_FILE" | grep -v '^$' > "${OUTPUT_DIR}/domains_clean.txt"
    local target_count=$(wc -l < "${OUTPUT_DIR}/domains_clean.txt")
    log "Target domains: $target_count"
    
    # Phase 1: Passive subdomain discovery
    phase_subdomain_discovery "${OUTPUT_DIR}/domains_clean.txt" "$OUTPUT_DIR"
    
    # Phase 2: Bruteforce + Resolution (combined)
    [[ -f "$WORDLIST" ]] && phase_bruteforce_resolution "${OUTPUT_DIR}/domains_clean.txt" "$WORDLIST" "$OUTPUT_DIR"
    
    # Phase 3: Live hosts detection
    [[ -f "${OUTPUT_DIR}/1_subdomains/all_subdomains.txt" ]] && \
        phase_live_hosts "${OUTPUT_DIR}/1_subdomains/all_subdomains.txt" "$OUTPUT_DIR"
    
    # Phase 4: URL discovery
    [[ -f "${OUTPUT_DIR}/3_live/live_urls.txt" ]] && \
        phase_url_discovery "${OUTPUT_DIR}/3_live/live_urls.txt" "$OUTPUT_DIR"
    
    # Phase 5: Report generation
    phase_report_generation "$OUTPUT_DIR"
    
    # Final summary
    log "========================================="
    log "ENUMERATION COMPLETE"
    log "Resolved subdomains: $(wc -l < "${OUTPUT_DIR}/1_subdomains/all_subdomains.txt" 2>/dev/null || echo 0)"
    log "Live hosts: $(wc -l < "${OUTPUT_DIR}/3_live/live_urls.txt" 2>/dev/null || echo 0)"
    log "URLs found: $(wc -l < "${OUTPUT_DIR}/4_urls/all_urls.txt" 2>/dev/null || echo 0)"
    log "Reports: ${OUTPUT_DIR}/5_reports/"
    log "========================================="
}

# Run main function
main