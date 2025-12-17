#!/bin/bash

# Check arguments
[[ -z "$1" ]] || [[ -z "$2" ]] && { 
    echo "Usage: $0 <output_prefix> <domains_file> [wordlist]"; 
    echo "Example: $0 project_name domains_in_scope.txt subdomains.txt"; 
    exit 1; 
}

# Global variables
OUTPUT_DIR="0_${1}"
TARGET_FILE="$2"
WORDLIST="${3:-/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt}"
THREADS=50
DATE_TAG=$(date +%Y%m%d_%H%M%S)

# Create directory structure
for dir in 1_subdomains 2_dns 3_live 4_scans 5_urls 6_reports; do
    mkdir -p "${OUTPUT_DIR}/$dir"
done

# Setup logging
LOG_FILE="${OUTPUT_DIR}/enum_${DATE_TAG}.log"
exec 2>"${OUTPUT_DIR}/errors.log"

# Helper functions
log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
run_tool() { local cmd="$1"; local log_msg="$2"; log "$log_msg"; eval "$cmd" 2>/dev/null; }
clean_subdomains() { grep -v "^\*\." | grep -E '^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+$' | sort -u; }

# ============================================
# PHASE 1: SUBDOMAIN DISCOVERY
# ============================================

phase_subdomain_discovery() {
    local domains_file="$1"
    local output_dir="$2"
    
    log "Starting Phase 1: Subdomain Discovery"
    
    # Subfinder
    run_tool "subfinder -dL '$domains_file' -all -silent -o '${output_dir}/1_subdomains/subfinder.txt'" "Running subfinder"
    
    # Assetfinder
    run_tool "while read -r dm; do assetfinder --subs-only \"\$dm\" 2>/dev/null; done < '$domains_file' > '${output_dir}/1_subdomains/assetfinder.txt'" "Running assetfinder"
    
    # Chaos (if available)
    [[ -x "$(command -v chaos-client)" ]] && run_tool "chaos-client -dL '$domains_file' -silent -o '${output_dir}/1_subdomains/chaos.txt'" "Running chaos"
    
    # crt.sh
    run_tool "while read -r dm; do curl -s 'https://crt.sh/?q=%25.\${dm}&output=json' | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g'; done < '$domains_file' | sort -u > '${output_dir}/1_subdomains/crtsh.txt'" "Querying crt.sh"
    
    # Bufferover API
    run_tool "while read -r dm; do curl -s 'https://dns.bufferover.run/dns?q=.\${dm}' | jq -r '.FDNS_A[],.RDNS[]' 2>/dev/null | cut -d',' -f2; done < '$domains_file' | sort -u > '${output_dir}/1_subdomains/bufferover.txt'" "Querying Bufferover"
    
    # Findomain
    [[ -x "$(command -v findomain)" ]] && run_tool "findomain -f '$domains_file' -u '${output_dir}/1_subdomains/findomain.txt' 2>/dev/null" "Running Findomain"
    
    # Combine and clean results
    cat "${output_dir}/1_subdomains/"*.txt 2>/dev/null | uniq |clean_subdomains > "${output_dir}/1_subdomains/all_discovered.txt"
    
    local count=$(wc -l < "${output_dir}/1_subdomains/all_discovered.txt" 2>/dev/null || echo 0)
    log "Phase 1 completed: $count subdomains discovered"
}

# ============================================
# PHASE 2: SUBDOMAIN BRUTEFORCE
# ============================================

phase_subdomain_bruteforce() {
    local domains_file="$1"
    local wordlist="$2"
    local output_dir="$3"
    
    log "Starting Phase 2: Subdomain Bruteforce"
    [[ ! -f "$wordlist" ]] && { log "Wordlist not found: $wordlist"; return 1; }
    
    local resolver_file="/usr/share/massdns/lists/resolvers.txt"
    
    # PureDNS bruteforce (preferred)
    if [[ -x "$(command -v puredns)" ]] && [[ -f "$resolver_file" ]]; then
        run_tool "puredns bruteforce '$wordlist' '$domains_file' -r '$resolver_file' -o '${output_dir}/1_subdomains/bruteforce.txt' 2>/dev/null" "Running PureDNS bruteforce"
    
    # MassDNS bruteforce (fallback)
    elif [[ -x "$(command -v massdns)" ]] && [[ -f "$resolver_file" ]]; then
        run_tool "while read -r dm; do cat '$wordlist' | sed \"s/\$/.${dm}/\" | massdns -r '${resolver_file}' -t A -o S -w '${output_dir}/1_subdomains/massdns_\${dm}.txt' 2>/dev/null; done < '$domains_file'" "Running MassDNS bruteforce"
        cat "${output_dir}/1_subdomains/massdns_"*.txt 2>/dev/null | grep -E " A " | awk '{print $1}' | sed 's/\.$//' | sort -u > "${output_dir}/1_subdomains/bruteforce.txt"
    fi
    
    # Merge with discovered subdomains
    cat "${output_dir}/1_subdomains/all_discovered.txt" "${output_dir}/1_subdomains/bruteforce.txt" 2>/dev/null | clean_subdomains | sort -u > "${output_dir}/1_subdomains/all_subdomains.txt"
    
    local final_count=$(wc -l < "${output_dir}/1_subdomains/all_subdomains.txt" 2>/dev/null || echo 0)
    log "Phase 2 completed: $final_count total subdomains"
}

# ============================================
# PHASE 3: DNS RESOLUTION
# ============================================

phase_dns_resolution() {
    local subdomains_file="$1"
    local output_dir="$2"
    
    log "Starting Phase 3: DNS Resolution"
    
    local resolver_file="/usr/share/massdns/lists/resolvers.txt"
    [[ ! -f "$resolver_file" ]] && { log "Resolver file not found"; return 1; }
    
    # MassDNS resolution
    if [[ -x "$(command -v massdns)" ]]; then
        run_tool "massdns -r '$resolver_file' -t A -o S -w '${output_dir}/2_dns/massdns_raw.txt' '$subdomains_file' 2>/dev/null" "Running MassDNS resolution"
        
        # Parse records
        grep " A " "${output_dir}/2_dns/massdns_raw.txt" 2>/dev/null | awk '{print $1" "$3}' | sed 's/\.$//' | sort -u > "${output_dir}/2_dns/a_records.txt"
        grep " CNAME " "${output_dir}/2_dns/massdns_raw.txt" 2>/dev/null | awk '{print $1" "$3}' | sed 's/\.$//' | sort -u > "${output_dir}/2_dns/cname_records.txt"
        grep " AAAA " "${output_dir}/2_dns/massdns_raw.txt" 2>/dev/null | awk '{print $1" "$3}' | sed 's/\.$//' | sort -u > "${output_dir}/2_dns/aaaa_records.txt"
    
    # PureDNS resolution (fallback)
    elif [[ -x "$(command -v puredns)" ]]; then
        run_tool "puredns resolve '$subdomains_file' -r '$resolver_file' --write '${output_dir}/2_dns/resolved.txt' 2>/dev/null" "Running PureDNS resolution"
    fi
    
    # Extract unique IPs
    awk '{print $2}' "${output_dir}/2_dns/a_records.txt" 2>/dev/null | sort -u > "${output_dir}/2_dns/ips.txt"
    
    local ip_count=$(wc -l < "${output_dir}/2_dns/ips.txt" 2>/dev/null || echo 0)
    log "Phase 3 completed: $ip_count unique IPs resolved"
}

# ============================================
# PHASE 4: LIVE HOSTS DETECTION
# ============================================

phase_live_hosts() {
    local subdomains_file="$1"
    local output_dir="$2"
    
    log "Starting Phase 4: Live Hosts Detection"
    
    if command -v httpx &>/dev/null; then
        run_tool "httpx -l '$subdomains_file' -silent -sc -title -tech-detect -threads '$THREADS' -timeout 5 -ports 80,443,8080,8443,3000,8000,8888,9000,9001 -json -o '${output_dir}/3_live/scan.json' 2>/dev/null" "Running httpx scan"
        
        if [[ -f "${output_dir}/3_live/scan.json" ]]; then
            # Extract live URLs
            jq -r 'select(.status_code|tostring|match("^[2345]")) | .url' "${output_dir}/3_live/scan.json" 2>/dev/null | sort -u > "${output_dir}/3_live/live_urls.txt"
            
            # Extract status codes
            jq -r 'select(.status_code) | "\(.url) \(.status_code)"' "${output_dir}/3_live/scan.json" 2>/dev/null | sort > "${output_dir}/3_live/status_codes.txt"
            
            # Extract technologies
            jq -r 'select(.tech) | "\(.url) : \(.tech | join(\", \"))"' "${output_dir}/3_live/scan.json" 2>/dev/null > "${output_dir}/3_live/technologies.txt"
        fi
    fi
    
    local live_count=$(wc -l < "${output_dir}/3_live/live_urls.txt" 2>/dev/null || echo 0)
    log "Phase 4 completed: $live_count live hosts found"
}

# ============================================
# PHASE 5: PORT SCANNING
# ============================================

phase_port_scanning() {
    local ips_file="$1"
    local output_dir="$2"
    
    log "Starting Phase 5: Port Scanning"
    
    if [[ ! -f "$ips_file" ]] || [[ ! -s "$ips_file" ]]; then
        log "No IPs to scan"
        return 1
    fi
    
    mkdir -p "${output_dir}/4_scans/ports"
    
    # Naabu scanning
    if command -v naabu &>/dev/null; then
        run_tool "naabu -list '$ips_file' -silent -top-ports 100 -rate 1000 -o '${output_dir}/4_scans/ports/naabu_top100.txt' 2>/dev/null" "Running Naabu (top 100 ports)"
        run_tool "naabu -list '$ips_file' -silent -p 80,443,8080,8443,8888 -rate 2000 -o '${output_dir}/4_scans/ports/naabu_web.txt' 2>/dev/null" "Running Naabu (web ports)"
    fi
    
    # Nmap quick scan
    if command -v nmap &>/dev/null; then
        run_tool "nmap -iL '$ips_file' -T4 --open -p 21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,6379,8080,8443,27017 -oG '${output_dir}/4_scans/ports/nmap_quick.gnmap' 2>/dev/null" "Running Nmap quick scan"
        
        # Parse open ports
        grep "Ports:" "${output_dir}/4_scans/ports/nmap_quick.gnmap" 2>/dev/null | awk '{ip=$2; ports=$4; gsub(/Ports:/,"",ports); print ip ":" ports}' > "${output_dir}/4_scans/ports/open_ports.txt"
    fi
    
    local port_count=$(grep -c ":" "${output_dir}/4_scans/ports/open_ports.txt" 2>/dev/null || echo 0)
    
    log "Phase 5 completed: $port_count IPs with open ports"
}

# ============================================
# PHASE 6: URL DISCOVERY
# ============================================

phase_url_discovery() {
    local live_urls_file="$1"
    local output_dir="$2"
    
    log "Starting Phase 6: URL Discovery"
    
    if [[ ! -f "$live_urls_file" ]] || [[ ! -s "$live_urls_file" ]]; then
        log "No live URLs for discovery"
        return 1
    fi
    
    mkdir -p "${output_dir}/5_urls"
    
    # Wayback URLs
    if command -v waybackurls &>/dev/null; then
        run_tool "cat '$live_urls_file' | waybackurls 2>/dev/null | sort -u > '${output_dir}/5_urls/wayback.txt'" "Fetching Wayback URLs"
    fi
    
    # Gau (fetch known URLs)
    if command -v gau &>/dev/null; then
        run_tool "cat '$live_urls_file' | gau --threads 20 2>/dev/null | sort -u > '${output_dir}/5_urls/gau.txt'" "Running gau"
    fi
    
    # Combine and deduplicate
    cat "${output_dir}/5_urls/"*.txt 2>/dev/null | sort -u > "${output_dir}/5_urls/all_urls.txt"
    
    local url_count=$(wc -l < "${output_dir}/5_urls/all_urls.txt" 2>/dev/null || echo 0)
    log "Phase 6 completed: $url_count URLs discovered"
}

# ============================================
# PHASE 7: SUBDIRECTORY BRUTEFORCE
# ============================================

phase_subdirectory_bruteforce() {
    local live_urls_file="$1"
    local output_dir="$2"
    
    log "Starting Phase 7: Subdirectory Bruteforce"
    
    if [[ ! -f "$live_urls_file" ]] || [[ ! -s "$live_urls_file" ]]; then
        log "No live URLs for subdirectory bruteforce"
        return 1
    fi
    
    local wordlist="/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"
    [[ ! -f "$wordlist" ]] && { log "Directory wordlist not found"; return 1; }
    
    # FFuF for subdirectory discovery
    if command -v ffuf &>/dev/null; then
        mkdir -p "${output_dir}/5_urls/directories"
        
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            local domain=$(echo "$url" | sed 's|^https*://||' | sed 's|/.*$||')
            local output_file="${output_dir}/5_urls/directories/$(echo $domain | tr '.' '_').txt"
            
            run_tool "ffuf -u '${url}/FUZZ' -w '$wordlist' -t 20 -ac -c -mc 200,301,302,307,401,403 -o '$output_file' -of csv 2>/dev/null" "Scanning $domain for directories"
        done < "$live_urls_file"
    fi
    
    log "Phase 7 completed: Subdirectory bruteforce finished"
}

# ============================================
# PHASE 8: REVERSE DNS LOOKUP
# ============================================

phase_reverse_dns() {
    local ips_file="$1"
    local output_dir="$2"
    
    log "Starting Phase 8: Reverse DNS Lookup"
    
    if [[ ! -f "$ips_file" ]] || [[ ! -s "$ips_file" ]]; then
        log "No IPs for reverse DNS"
        return 1
    fi
    
    local output_file="${output_dir}/2_dns/reverse_dns.txt"
    
    # Use dig for reverse DNS
    run_tool "xargs -P '$THREADS' -a '$ips_file' -I{} bash -c 'ptr=\$(dig +short -x {} 2>/dev/null); [[ -n \"\$ptr\" ]] && echo \"{} -> \$ptr\"' > '$output_file' 2>/dev/null" "Running reverse DNS lookups"
    
    # Clean empty lines and sort
    sed -i '/^$/d' "$output_file" 2>/dev/null
    sort -u "$output_file" -o "$output_file" 2>/dev/null
    
    local ptr_count=$(wc -l < "$output_file" 2>/dev/null | tr -d ' ')
    log "Phase 8 completed: $ptr_count PTR records found"
}

# ============================================
# PHASE 9: DNS ZONE TRANSFER
# ============================================

phase_zone_transfer() {
    local domains_file="$1"
    local output_dir="$2"
    
    log "Starting Phase 9: DNS Zone Transfer Testing"
    
    mkdir -p "${output_dir}/2_dns/zone_transfers"
    
    while IFS= read -r dm; do
        [[ -z "$dm" ]] && continue
        
        # Get nameservers
        ns_list=$(dig +short NS "$dm" 2>/dev/null | sort -u)
        [[ -z "$ns_list" ]] && continue
        
        local output_file="${output_dir}/2_dns/zone_transfers/${dm//./_}.txt"
        
        # Try zone transfer on each nameserver
        while read -r ns; do
            dig @"$ns" "$dm" AXFR +noall +answer 2>/dev/null | grep -E "^[a-zA-Z0-9]" | sed "s/$/ # NS: $ns/"
        done <<< "$ns_list" > "$output_file"
        
        # Remove empty files
        [[ ! -s "$output_file" ]] && rm -f "$output_file" 2>/dev/null
        
    done < "$domains_file"
    
    local success_count=$(find "${output_dir}/2_dns/zone_transfers" -type f -size +0 2>/dev/null | wc -l)
    log "Phase 9 completed: $success_count successful zone transfers"
}

# ============================================
# PHASE 10: REPORT GENERATION
# ============================================

phase_report_generation() {
    local output_dir="$1"
    
    log "Starting Phase 10: Report Generation"
    
    # Create summary report
    {
        echo "# Enumeration Report"
        echo "Generated: $(date)"
        echo ""
        echo "## Summary"
        echo "- Total subdomains: $(wc -l < "${output_dir}/1_subdomains/all_subdomains.txt" 2>/dev/null || echo 0)"
        echo "- Resolved IPs: $(wc -l < "${output_dir}/2_dns/ips.txt" 2>/dev/null || echo 0)"
        echo "- Live hosts: $(wc -l < "${output_dir}/3_live/live_urls.txt" 2>/dev/null || echo 0)"
        echo "- Discovered URLs: $(wc -l < "${output_dir}/5_urls/all_urls.txt" 2>/dev/null || echo 0)"
        echo ""
        echo "## Files"
        find "$output_dir" -type f -name "*.txt" -o -name "*.json" -o -name "*.gnmap" | sed 's|^| - |'
    } > "${output_dir}/6_reports/summary.md"
    
    log "Phase 10 completed: Reports generated in ${output_dir}/6_reports/"
}

# ============================================
# MAIN EXECUTION
# ============================================

main() {
    log "Starting enumeration pipeline"
    log "Output directory: $OUTPUT_DIR"
    
    # Validate target file
    [[ ! -f "$TARGET_FILE" ]] && { log "Error: Target file '$TARGET_FILE' not found"; exit 1; }
    dos2unix "$TARGET_FILE" 2>/dev/null
    local target_count=$(wc -l < "$TARGET_FILE" 2>/dev/null || echo 0)
    log "Target domains: $target_count"
    
    # Phase 1: Subdomain discovery
    phase_subdomain_discovery "$TARGET_FILE" "$OUTPUT_DIR"
    
    # Phase 2: Subdomain bruteforce
    [[ -f "$WORDLIST" ]] && phase_subdomain_bruteforce "$TARGET_FILE" "$WORDLIST" "$OUTPUT_DIR"
    
    # Phase 3: DNS resolution
    phase_dns_resolution "${OUTPUT_DIR}/1_subdomains/all_subdomains.txt" "$OUTPUT_DIR"
    
    # Phase 4: Live hosts detection
    phase_live_hosts "${OUTPUT_DIR}/1_subdomains/all_subdomains.txt" "$OUTPUT_DIR"
    
    # Phase 5: Port scanning (if IPs found)
    [[ -f "${OUTPUT_DIR}/2_dns/ips.txt" ]] && [[ -s "${OUTPUT_DIR}/2_dns/ips.txt" ]] && phase_port_scanning "${OUTPUT_DIR}/2_dns/ips.txt" "$OUTPUT_DIR"
    
    # Phase 6: URL discovery
    [[ -f "${OUTPUT_DIR}/3_live/live_urls.txt" ]] && [[ -s "${OUTPUT_DIR}/3_live/live_urls.txt" ]] && phase_url_discovery "${OUTPUT_DIR}/3_live/live_urls.txt" "$OUTPUT_DIR"
    
    # Phase 7: Subdirectory bruteforce
    [[ -f "${OUTPUT_DIR}/3_live/live_urls.txt" ]] && [[ -s "${OUTPUT_DIR}/3_live/live_urls.txt" ]] && phase_subdirectory_bruteforce "${OUTPUT_DIR}/3_live/live_urls.txt" "$OUTPUT_DIR"
    
    # Phase 8: Reverse DNS lookup
    [[ -f "${OUTPUT_DIR}/2_dns/ips.txt" ]] && [[ -s "${OUTPUT_DIR}/2_dns/ips.txt" ]] && phase_reverse_dns "${OUTPUT_DIR}/2_dns/ips.txt" "$OUTPUT_DIR"
    
    # Phase 9: DNS zone transfer
    phase_zone_transfer "$TARGET_FILE" "$OUTPUT_DIR"
    
    # Phase 10: Report generation
    phase_report_generation "$OUTPUT_DIR"
    
    # Final summary
    log "========================================"
    log "ENUMERATION COMPLETE"
    log "Subdomains: $(wc -l < "${OUTPUT_DIR}/1_subdomains/all_subdomains.txt" 2>/dev/null || echo 0)"
    log "Live hosts: $(wc -l < "${OUTPUT_DIR}/3_live/live_urls.txt" 2>/dev/null || echo 0)"
    log "Unique IPs: $(wc -l < "${OUTPUT_DIR}/2_dns/ips.txt" 2>/dev/null || echo 0)"
    log "Reports: ${OUTPUT_DIR}/6_reports/"
    log "========================================"
}

# Run main function
main